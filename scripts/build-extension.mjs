#!/usr/bin/env node
/**
 * OmniShield X — extension builder.
 *
 * Why this exists: the shipped ZIP used to be built by hand, which made it
 * unreproducible and let it drift from the bundled feed. It also carried 50,000
 * static declarativeNetRequest rules; Chrome only *guarantees* 30,000 static
 * rules per extension (GUARANTEED_MINIMUM_STATIC_RULES) and shares anything above
 * that with every other installed blocker. Exceeding it makes rulesets fail to
 * enable on crowded profiles, which looks exactly like "the extension does
 * nothing".
 *
 * This script:
 *   - extracts `||domain^` rules from the bundled feeds (supplement first, then
 *     the light list, in feed order),
 *   - drops anything on the app's system safety allowlist (captive portals,
 *     connectivity checks, DoH endpoints) so the extension cannot break networking,
 *   - dedupes, caps at MAX_STATIC_RULES, and splits into rulesets,
 *   - copies the reviewed sources in extension/src/,
 *   - writes a deterministic ZIP (fixed timestamps, sorted entries).
 *
 * Run: `npm run build:extension` · Check only: `node scripts/build-extension.mjs --check`
 */
import { readFileSync, writeFileSync, statSync, existsSync, mkdirSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { deflateRawSync, inflateRawSync } from 'node:zlib';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const abs = (p) => resolve(ROOT, p);

/** Chrome's guaranteed static-rule allowance. Never exceed it silently. */
export const MAX_STATIC_RULES = 30000;
/** Rules per ruleset file. Two files stay well inside the ruleset-count limit. */
export const RULES_PER_FILE = 15000;
/** Feed order is preserved; the supplement is curated and goes first. */
export const FEED_FILES = [
  'assets/core_supplement_ads.txt',
  'assets/core_lite_ads.txt'
];

const SAFETY_ALLOWLIST = [
  'connectivitycheck.gstatic.com', 'connectivitycheck.android.com', 'clients3.google.com',
  'clients4.google.com', 'captive.apple.com', 'captive.g.aaplimg.com', 'play.googleapis.com',
  'android.clients.google.com', 'time.android.com', 'time.google.com', 'msftconnecttest.com',
  'msftncsi.com', 'dns.msftncsi.com', 'www.msftconnecttest.com', 'detectportal.firefox.com',
  'nmcheck.gnome.org', 'connectivity-check.ubuntu.com', 'network-test.debian.org',
  'cloudflare-dns.com', 'one.one.one.one', 'dns.google', 'dns.quad9.net', 'doh.opendns.com',
  'dns.nextdns.io', 'dns.adguard-dns.com', 'ipv4only.arpa', 'localhost'
];

const STATIC_FILES = [
  ['background.js', 'application/javascript'],
  ['popup.html', 'text/html'],
  ['popup.js', 'application/javascript'],
  ['content.js', 'application/javascript'],
  ['icon.png', 'image/png']
];

/** `||ads.example.com^` → `ads.example.com`; anything else is ignored. */
function domainOf(line) {
  const match = /^\|\|([a-z0-9.*_-]+)\^?\s*$/i.exec(line.trim());
  return match ? match[1].toLowerCase() : null;
}

/**
 * Selects the rules the extension ships.
 * @returns {{rules:string[], skipped:Record<string,number>, total:number, capped:boolean}}
 */
export function selectRules({ files = FEED_FILES, root = ROOT, maxRules = MAX_STATIC_RULES } = {}) {
  const safety = new Set(SAFETY_ALLOWLIST);
  const seen = new Set();
  const rules = [];
  const skipped = { safety: 0, duplicate: 0, malformed: 0, overCap: 0, tooShort: 0 };
  let total = 0;

  for (const file of files) {
    const text = readFileSync(resolve(root, file), 'utf8');
    for (const rawLine of text.split('\n')) {
      const line = rawLine.trim();
      if (!line || line.startsWith('!') || line.startsWith('#')) continue;
      total++;
      const domain = domainOf(line);
      if (!domain) { skipped.malformed++; continue; }
      // A single-label or wildcard-only rule is useless in a DNR requestDomains
      // condition and risks over-blocking.
      if (!domain.includes('.') || domain.includes('*')) { skipped.tooShort++; continue; }
      if (safety.has(domain) || [...safety].some((s) => domain.endsWith(`.${s}`))) { skipped.safety++; continue; }
      if (seen.has(domain)) { skipped.duplicate++; continue; }
      if (rules.length >= maxRules) { skipped.overCap++; continue; }
      seen.add(domain);
      rules.push(domain);
    }
  }
  return { rules, skipped, total, capped: skipped.overCap > 0 };
}

/** Builds DNR rule objects (ids restart per ruleset, which DNR allows). */
export function toDnrRules(domains) {
  return domains.map((domain, index) => ({
    id: index + 1,
    priority: 1,
    action: { type: 'block' },
    condition: { requestDomains: [domain], domainType: 'thirdParty' }
  }));
}

/** Splits selected domains into ruleset chunks. */
export function splitRules(domains, perFile = RULES_PER_FILE) {
  const files = [];
  for (let i = 0; i < domains.length; i += perFile) files.push(domains.slice(i, i + perFile));
  return files;
}

/** Manifest generated from measured data, not hand-maintained. */
export function buildManifest({ version, rulesetCount }) {
  return {
    manifest_version: 3,
    name: 'OmniShield X — Ad & Tracker Shield',
    version,
    description: 'Blocks third-party ads and trackers with static rules generated from the same feeds as OmniShield X. Local-only: no servers, no analytics.',
    permissions: ['declarativeNetRequest', 'declarativeNetRequestFeedback', 'storage'],
    background: { service_worker: 'background.js' },
    icons: { 128: 'icon.png' },
    action: { default_popup: 'popup.html', default_title: 'OmniShield X' },
    declarative_net_request: {
      rule_resources: Array.from({ length: rulesetCount }, (_, i) => ({
        id: `ads_${i + 1}`,
        enabled: true,
        path: `rules-${i + 1}.json`
      }))
    },
    content_scripts: [{
      matches: ['http://*/*', 'https://*/*'],
      js: ['content.js'],
      run_at: 'document_end'
    }]
  };
}

/* ---------------------------------------------------------------- */
/* Minimal deterministic ZIP writer/reader (no dependencies)         */
/* ---------------------------------------------------------------- */

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[i] = c >>> 0;
  }
  return table;
})();

export function crc32(buf) {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) crc = CRC_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

/** Fixed 1980-01-01 timestamp keeps the archive byte-identical across builds. */
const DOS_TIME = 0;
const DOS_DATE = (1 << 5) | 1; // 1980-01-01

export function createZip(entries) {
  const local = [];
  const central = [];
  let offset = 0;
  const sorted = [...entries].sort((a, b) => a.name.localeCompare(b.name));
  for (const entry of sorted) {
    const name = Buffer.from(entry.name, 'utf8');
    const data = Buffer.isBuffer(entry.data) ? entry.data : Buffer.from(entry.data, 'utf8');
    const deflated = deflateRawSync(data, { level: 9 });
    const useDeflate = deflated.length < data.length;
    const payload = useDeflate ? deflated : data;
    const method = useDeflate ? 8 : 0;
    const crc = crc32(data);

    const header = Buffer.alloc(30);
    header.writeUInt32LE(0x04034b50, 0);
    header.writeUInt16LE(20, 4);
    header.writeUInt16LE(0x0800, 6); // UTF-8 names
    header.writeUInt16LE(method, 8);
    header.writeUInt16LE(DOS_TIME, 10);
    header.writeUInt16LE(DOS_DATE, 12);
    header.writeUInt32LE(crc, 14);
    header.writeUInt32LE(payload.length, 18);
    header.writeUInt32LE(data.length, 22);
    header.writeUInt16LE(name.length, 26);
    header.writeUInt16LE(0, 28);
    local.push(header, name, payload);

    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(20, 4);
    cd.writeUInt16LE(20, 6);
    cd.writeUInt16LE(0x0800, 8);
    cd.writeUInt16LE(method, 10);
    cd.writeUInt16LE(DOS_TIME, 12);
    cd.writeUInt16LE(DOS_DATE, 14);
    cd.writeUInt32LE(crc, 16);
    cd.writeUInt32LE(payload.length, 20);
    cd.writeUInt32LE(data.length, 24);
    cd.writeUInt16LE(name.length, 28);
    cd.writeUInt16LE(0, 30);
    cd.writeUInt16LE(0, 32);
    cd.writeUInt16LE(0, 34);
    cd.writeUInt16LE(0, 36);
    cd.writeUInt32LE(0, 38);
    cd.writeUInt32LE(offset, 42);
    central.push(cd, name);

    offset += header.length + name.length + payload.length;
  }
  const centralBuf = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(sorted.length, 8);
  end.writeUInt16LE(sorted.length, 10);
  end.writeUInt32LE(centralBuf.length, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(0, 20);
  return Buffer.concat([...local, centralBuf, end]);
}

/** Reads a ZIP produced by createZip (stored or deflated entries). */
export function readZip(buffer) {
  const entries = [];
  let offset = 0;
  while (offset + 4 <= buffer.length && buffer.readUInt32LE(offset) === 0x04034b50) {
    const method = buffer.readUInt16LE(offset + 8);
    const crc = buffer.readUInt32LE(offset + 14);
    const compressed = buffer.readUInt32LE(offset + 18);
    const size = buffer.readUInt32LE(offset + 22);
    const nameLength = buffer.readUInt16LE(offset + 26);
    const extraLength = buffer.readUInt16LE(offset + 28);
    const name = buffer.toString('utf8', offset + 30, offset + 30 + nameLength);
    const dataStart = offset + 30 + nameLength + extraLength;
    const raw = buffer.subarray(dataStart, dataStart + compressed);
    const data = method === 8 ? inflateRawSync(raw) : Buffer.from(raw);
    if (data.length !== size) throw new Error(`${name}: size mismatch (${data.length} != ${size})`);
    if (crc32(data) !== crc) throw new Error(`${name}: CRC mismatch`);
    entries.push({ name, data });
    offset = dataStart + compressed;
  }
  return entries;
}

/* ---------------------------------------------------------------- */
/* Build                                                             */
/* ---------------------------------------------------------------- */

export function build({ root = ROOT, outFile = 'omnishield-x-extension.zip', files = FEED_FILES, maxRules = MAX_STATIC_RULES } = {}) {
  const pkg = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'));
  const { rules, skipped, total, capped } = selectRules({ root, files, maxRules });
  if (!rules.length) throw new Error('no usable rules found in the bundled feeds');
  if (rules.length > MAX_STATIC_RULES) {
    throw new Error(`refusing to ship ${rules.length} static rules (Chrome guarantees ${MAX_STATIC_RULES})`);
  }
  const chunks = splitRules(rules);
  const manifest = buildManifest({ version: pkg.version, rulesetCount: chunks.length });

  const entries = [{ name: 'manifest.json', data: JSON.stringify(manifest, null, 2) + '\n' }];
  chunks.forEach((chunk, index) => {
    entries.push({ name: `rules-${index + 1}.json`, data: JSON.stringify(toDnrRules(chunk)) });
  });
  for (const [file, mime] of STATIC_FILES) {
    const source = readFileSync(resolve(root, 'extension/src', file));
    entries.push({ name: file, data: source, mime });
  }

  const zip = createZip(entries);
  const target = resolve(root, outFile);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, zip);

  // Facts about the shipped artifact, so the UI can show measured numbers
  // instead of hand-written copy that drifts from the ZIP.
  const facts = {
    artifact: outFile,
    version: pkg.version,
    rules: rules.length,
    uniqueDomains: new Set(rules).size,
    rulesets: chunks.length,
    bytes: zip.length,
    maxStaticRules: MAX_STATIC_RULES,
    feedLinesConsidered: total,
    skipped,
    source: 'generated by scripts/build-extension.mjs — do not edit by hand'
  };
  mkdirSync(dirname(resolve(root, 'assets/extension-facts.json')), { recursive: true });
  writeFileSync(resolve(root, 'assets/extension-facts.json'), JSON.stringify(facts, null, 2) + '\n');

  return {
    outFile: target,
    bytes: zip.length,
    rules: rules.length,
    rulesets: chunks.length,
    feedLines: total,
    skipped,
    capped,
    version: pkg.version,
    maxStaticRules: MAX_STATIC_RULES
  };
}

/** Validates the shipped ZIP without rebuilding it. */
export function inspect({ root = ROOT, outFile = 'omnishield-x-extension.zip' } = {}) {
  const file = resolve(root, outFile);
  if (!existsSync(file)) return { ok: false, error: 'extension archive is missing' };
  const zip = readFileSync(file);
  let entries;
  try { entries = readZip(zip); } catch (err) { return { ok: false, error: `unreadable archive: ${err.message}` }; }
  const byName = new Map(entries.map((e) => [e.name, e]));
  const manifestEntry = byName.get('manifest.json');
  if (!manifestEntry) return { ok: false, error: 'manifest.json missing' };
  let manifest;
  try { manifest = JSON.parse(manifestEntry.data.toString('utf8')); } catch (err) {
    return { ok: false, error: `manifest is not JSON: ${err.message}` };
  }
  const resources = manifest.declarative_net_request?.rule_resources || [];
  let ruleCount = 0;
  const ids = new Set();
  for (const resource of resources) {
    const entry = byName.get(resource.path);
    if (!entry) return { ok: false, error: `ruleset file ${resource.path} missing` };
    let parsed;
    try { parsed = JSON.parse(entry.data.toString('utf8')); } catch (err) {
      return { ok: false, error: `${resource.path} is not JSON: ${err.message}` };
    }
    if (!Array.isArray(parsed)) return { ok: false, error: `${resource.path} is not an array` };
    for (const rule of parsed) {
      if (!rule?.condition?.requestDomains?.length) return { ok: false, error: `${resource.path} has a rule without requestDomains` };
      ids.add(rule.condition.requestDomains[0]);
    }
    ruleCount += parsed.length;
  }
  const files = ['background.js', 'popup.html', 'popup.js', 'content.js', 'icon.png'];
  const missing = files.filter((f) => !byName.has(f));
  return {
    ok: missing.length === 0 && ruleCount > 0,
    error: missing.length ? `missing files: ${missing.join(', ')}` : null,
    ruleCount,
    uniqueDomains: ids.size,
    rulesets: resources.length,
    version: manifest.version,
    manifestVersion: manifest.manifest_version,
    overLimit: ruleCount > MAX_STATIC_RULES,
    bytes: statSync(file).size,
    files: entries.map((e) => e.name).sort()
  };
}

/* CLI */
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const check = process.argv.includes('--check');
  if (check) {
    const result = inspect();
    console.log(JSON.stringify(result, null, 2));
    if (!result.ok || result.overLimit) process.exit(1);
  } else {
    const result = build();
    console.log(`wrote ${result.outFile}`);
    console.log(`${result.rules} static rules in ${result.rulesets} rulesets (limit ${result.maxStaticRules}) · ${result.bytes} bytes`);
    if (result.capped) console.log('note: feed exceeded the static-rule limit; selection was capped by feed order');
    console.log('skipped', JSON.stringify(result.skipped));
  }
}
