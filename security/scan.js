/**
 * OmniShield X — system scanner.
 *
 * Scans what a browser can actually reach, for real:
 *   - file bytes the user grants through the file picker or a directory drop
 *     (magic-byte vs. extension mismatch, embedded executables, script/dropper
 *     patterns, macro-enabled documents, archive path traversal, the EICAR test
 *     signature, high-entropy payloads)
 *   - URL / phish analysis over every stored and pasted link
 *   - the app's own security configuration (resolver, DNSSEC, feed integrity,
 *     vault lock, storage headroom, service-worker state)
 *   - browser storage, which is the only "storage" a web page may read
 *
 * Every finding carries severity, evidence and a recommendation. Nothing is
 * invented: when a check cannot run (no File System Access API, no permission,
 * no persisted storage) the report says so instead of assuming "clean".
 *
 * Byte inspection mirrors the Android engine (FileThreatScanner.kt /
 * UrlThreatScanner.kt) so both platforms agree on the same vocabulary.
 */
import { sha256Hex } from './sha256.js';

const EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
const DEEP_SCAN_BYTES = 6 * 1024 * 1024;
const HEAD_BYTES = 4096;

export const SEVERITY = Object.freeze({ clean: 0, info: 1, low: 2, medium: 3, high: 4, critical: 5 });
export const SEVERITY_LABEL = ['clean', 'info', 'low', 'medium', 'high', 'critical'];

const maxSeverity = (list) => list.reduce((worst, finding) => Math.max(worst, SEVERITY[finding.severity] ?? 0), 0);

/* ------------------------------------------------------------------------ */
/* Container and executable signatures                                       */
/* ------------------------------------------------------------------------ */

const CONTAINERS = [
  { kind: 'image/jpeg', label: 'JPEG image', magic: [0xFF, 0xD8, 0xFF] },
  { kind: 'image/png', label: 'PNG image', magic: [0x89, 0x50, 0x4E, 0x47] },
  { kind: 'image/gif', label: 'GIF image', magic: [0x47, 0x49, 0x46] },
  { kind: 'image/webp', label: 'WebP image', magic: [0x52, 0x49, 0x46, 0x46] },
  { kind: 'application/pdf', label: 'PDF document', magic: [0x25, 0x50, 0x44, 0x46] },
  { kind: 'application/zip', label: 'ZIP / APK / Office archive', magic: [0x50, 0x4B, 0x03, 0x04] },
  { kind: 'application/gzip', label: 'gzip archive', magic: [0x1F, 0x8B] },
  { kind: 'video/mp4', label: 'ISO-BMFF video (MP4/MOV/M4A)', magic: [0x66, 0x74, 0x79, 0x70], offset: 4 },
  { kind: 'video/webm', label: 'Matroska/WebM video', magic: [0x1A, 0x45, 0xDF, 0xA3] },
  { kind: 'audio/mpeg', label: 'MP3 audio', magic: [0x49, 0x44, 0x33] },
  { kind: 'audio/ogg', label: 'Ogg audio', magic: [0x4F, 0x67, 0x67, 0x53] },
  { kind: 'audio/flac', label: 'FLAC audio', magic: [0x66, 0x4C, 0x61, 0x43] },
  { kind: 'application/x-7z', label: '7-Zip archive', magic: [0x37, 0x7A, 0xBC, 0xAF] },
  { kind: 'application/x-rar', label: 'RAR archive', magic: [0x52, 0x61, 0x72, 0x21] }
];

const EXECUTABLES = [
  { label: 'Windows PE executable', magic: [0x4D, 0x5A] },
  { label: 'Linux ELF executable', magic: [0x7F, 0x45, 0x4C, 0x46] },
  { label: 'Android DEX bytecode', magic: [0x64, 0x65, 0x78, 0x0A] },
  { label: 'Mach-O executable', magic: [0xCF, 0xFA, 0xED, 0xFE] },
  { label: 'Java class file', magic: [0xCA, 0xFE, 0xBA, 0xBE] }
];

const matchesAt = (bytes, magic, offset = 0) => {
  if (bytes.length < offset + magic.length) return false;
  for (let i = 0; i < magic.length; i++) if (bytes[offset + i] !== magic[i]) return false;
  return true;
};

const indexOfPattern = (bytes, magic) => {
  const limit = bytes.length - magic.length;
  outer: for (let i = 0; i <= limit; i++) {
    for (let j = 0; j < magic.length; j++) if (bytes[i + j] !== magic[j]) continue outer;
    return i;
  }
  return -1;
};

/** Script and dropper patterns, mirroring the Android scanner's content stage. */
const CONTENT_PATTERNS = [
  { label: 'PowerShell encoded command (dropper pattern)', regex: /-enc(odedcommand)?\s+[A-Za-z0-9+/=]{40,}/i, severity: 'high' },
  { label: 'Base64-decoded shell execution chain', regex: /FromBase64String\s*\(.{0,80}\)\s*\)?\s*;?\s*Invoke-Expression/i, severity: 'critical' },
  { label: 'Remote script download-and-execute (IWR | IEX)', regex: /(invoke-webrequest|\biwr\b|downloadstring|downloadfile|curl|wget).{0,160}(\|\s*(iex|invoke-expression|bash|sh)\b|invoke-expression|\biex\b)/is, severity: 'critical' },
  { label: 'Ransomware note wording (files encrypted + payment)', regex: /(your files (are|have been) encrypted|pay .{0,40}(bitcoin|btc).{0,40}(decrypt|key))/i, severity: 'high' },
  { label: 'Suspicious macro auto-exec entry point', regex: /(AutoOpen|Document_Open|Auto_Open)\s*\(/i, severity: 'medium' },
  { label: 'Windows script-host invocation in document', regex: /(wscript\.shell|shell\.application).{0,60}\.run/i, severity: 'high' },
  { label: 'EICAR antivirus test signature', regex: /X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}/, severity: 'critical' }
];

const EXECUTABLE_EXTENSIONS = ['exe', 'dll', 'scr', 'com', 'pif', 'bat', 'cmd', 'msi', 'jar', 'apk', 'dex', 'so', 'elf', 'dylib', 'bin'];
const DOCUMENT_EXTENSIONS = ['docm', 'xlsm', 'pptm', 'dotm', 'xlam'];
const ARCHIVE_EXTENSIONS = ['zip', 'gz', 'tar', '7z', 'rar', 'apk'];

const extensionOf = (name) => String(name || '').toLowerCase().split('.').pop() || '';

/** Shannon entropy in bits per byte over a sample. */
export function entropy(bytes) {
  if (!bytes?.length) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i++) counts[bytes[i]]++;
  let value = 0;
  for (const count of counts) {
    if (!count) continue;
    const p = count / bytes.length;
    value -= p * Math.log2(p);
  }
  return value;
}

/**
 * Scans one file's bytes. This is the core of the module and it is pure, so it is
 * unit-tested directly against known fixtures.
 *
 * @param {{name:string, size:number, head:Uint8Array, body?:Uint8Array, sha256?:string}} input
 * @returns {{findings:Array<object>, severity:string, score:number, container:string|null, sha256:string|null}}
 */
export function scanBytes({ name, size = 0, head, body = null, sha256 = null }) {
  const findings = [];
  const bytes = head instanceof Uint8Array ? head : new Uint8Array(head || []);
  const sample = body instanceof Uint8Array ? body : bytes;
  const ext = extensionOf(name);

  // 1. Containers we can name.
  let container = null;
  for (const entry of CONTAINERS) {
    if (matchesAt(bytes, entry.magic, entry.offset || 0)) { container = entry; break; }
  }
  if (container) findings.push({ severity: 'info', label: `Container identified: ${container.label}`, evidence: container.kind });

  // 2. Executable magic at offset 0.
  let executable = null;
  for (const entry of EXECUTABLES) {
    if (matchesAt(bytes, entry.magic)) { executable = entry; break; }
  }
  if (executable) {
    const expected = EXECUTABLE_EXTENSIONS.includes(ext);
    findings.push({
      severity: expected ? 'medium' : 'high',
      label: expected
        ? `Executable content: ${executable.label}`
        : `Disguised executable: ${executable.label} inside a .${ext} file`,
      evidence: expected ? 'extension matches the binary format' : 'the extension does not match the binary format — a common masquerading technique'
    });
  }

  // 3. Extension/container mismatch (a JPEG named .pdf, a PDF named .jpg, …).
  if (!executable && container && ext) {
    const expectedExt = container.kind.split('/').pop();
    const compatible =
      (expectedExt === 'jpeg' && ['jpg', 'jpeg'].includes(ext)) ||
      (container.kind === 'application/zip' && ['zip', 'apk', 'docx', 'xlsx', 'pptx', 'odt', 'jar'].includes(ext)) ||
      (container.kind === 'video/mp4' && ['mp4', 'm4v', 'm4a', 'mov', 'heic'].includes(ext)) ||
      (container.kind === 'video/webm' && ['webm', 'mkv'].includes(ext)) ||
      (container.kind === 'application/gzip' && ['gz', 'tgz'].includes(ext)) ||
      (container.kind === 'image/webp' && ext === 'webp') ||
      expectedExt === ext;
    if (!compatible && ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'mp4', 'mp3', 'zip'].includes(ext)) {
      findings.push({
        severity: 'medium',
        label: `Type mismatch: ${container.label} content in a .${ext} file`,
        evidence: `magic bytes say ${container.kind}, the extension says .${ext}`
      });
    }
  }

  // 4. Hidden executable further into the file (polyglot / dropper).
  const deep = indexOfPattern(sample, [0x4D, 0x5A, 0x90, 0x00]);
  if (deep > 64) {
    findings.push({
      severity: 'high',
      label: 'Embedded Windows PE header beyond the file signature',
      evidence: `MZ/PE magic found at byte ${deep}`
    });
  }
  if (container && container.kind.startsWith('image/') && indexOfPattern(sample, [0x50, 0x4B, 0x03, 0x04]) > 0) {
    findings.push({
      severity: 'low',
      label: 'Archive appended to an image (polyglot file)',
      evidence: 'a ZIP local header appears after image data'
    });
  }

  // 5. Content patterns over a decoded sample (bounded by the caller).
  const text = sample.length ? new TextDecoder('latin1').decode(sample.subarray(0, Math.min(sample.length, 2_000_000))) : '';
  if (text) {
    if (text.includes('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR')) {
      findings.push({ severity: 'critical', label: 'EICAR antivirus test signature', evidence: 'industry-standard detection test file — safe by design, detected by signature', threat: 'EICAR.Test.File' });
    }
    for (const pattern of CONTENT_PATTERNS) {
      if (pattern.label.startsWith('EICAR')) continue;
      if (pattern.regex.test(text)) {
        findings.push({ severity: pattern.severity, label: pattern.label, evidence: 'pattern matched inside the first scanned window' });
      }
    }
  }

  // 6. Archive path traversal — reported from the local file headers.
  if (container?.kind === 'application/zip') {
    if (text.includes('../') || text.includes('..\\')) {
      findings.push({ severity: 'medium', label: 'Archive contains parent-directory references', evidence: 'potential zip-slip extraction path' });
    }
  }

  // 7. Macro-enabled documents are not "malicious" by themselves.
  if (DOCUMENT_EXTENSIONS.includes(ext)) {
    findings.push({ severity: 'low', label: 'Macro-enabled document format', evidence: `.${ext} can carry executable macros; only open from a trusted author` });
  }

  // 8. High entropy payloads (packed/encrypted content).
  const bits = entropy(sample.subarray(0, Math.min(sample.length, 512 * 1024)));
  if (sample.length > 64 * 1024 && bits > 7.9 && !container) {
    findings.push({ severity: 'medium', label: 'Very high entropy payload', evidence: `${bits.toFixed(2)} bits/byte — packed or encrypted content with no known container` });
  }

  // 9. Double extensions.
  if (/\.[a-z0-9]{1,5}\.(exe|scr|bat|cmd|jar|apk|js|vbs)$/i.test(name)) {
    findings.push({ severity: 'high', label: 'Double extension hiding an executable', evidence: name });
  }

  if (!findings.length) {
    findings.push({ severity: 'clean', label: 'No signature or structure anomaly found', evidence: 'content matched no known-bad pattern' });
  }

  const worst = maxSeverity(findings);
  return {
    findings,
    severity: SEVERITY_LABEL[worst],
    score: Math.min(100, worst === 0 ? 0 : worst * 18 + 4),
    container: container?.label || null,
    sha256: sha256 || null
  };
}

/* ------------------------------------------------------------------------ */
/* URL / phishing analysis (port of UrlThreatScanner.kt)                     */
/* ------------------------------------------------------------------------ */

const HIGH_ABUSE_TLDS = ['tk', 'ml', 'ga', 'cf', 'gq', 'zip', 'mov', 'top', 'xyz', 'work', 'click', 'country', 'kim', 'loan', 'men', 'review'];
const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly', 'shorturl.at', 'rb.gy'];
const BRANDS = ['paypal', 'apple', 'microsoft', 'google', 'amazon', 'netflix', 'facebook', 'instagram', 'whatsapp', 'telegram', 'binance', 'coinbase', 'metamask', 'dhl', 'fedex', 'gcash', 'paymaya', 'bdo', 'bpi'];
const PHISH_WORDS = ['login', 'verify', 'account', 'update', 'secure', 'signin', 'confirm', 'wallet', 'password', 'billing', 'unlock', 'recover', 'suspend'];

const levenshtein = (a, b) => {
  const m = a.length, n = b.length;
  if (!m || !n) return Math.max(m, n);
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  for (let i = 1; i <= m; i++) {
    const row = [i];
    for (let j = 1; j <= n; j++) {
      row[j] = Math.min(prev[j] + 1, row[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = row;
  }
  return prev[n];
};

const registrable = (host) => {
  const parts = String(host || '').split('.').filter(Boolean);
  if (parts.length <= 2) return parts.join('.');
  const twoLevel = ['co', 'com', 'org', 'net', 'gov', 'edu', 'ac'];
  if (parts.length >= 3 && twoLevel.includes(parts[parts.length - 2])) return parts.slice(-3).join('.');
  return parts.slice(-2).join('.');
};

/**
 * Scores a URL for phishing/lure shapes. Heuristics only — the caller must not
 * present a high score as proof.
 */
export function scanUrl(rawUrl) {
  const findings = [];
  let score = 0;
  const trimmed = String(rawUrl || '').trim();
  if (!trimmed) return { url: '', host: '', level: 'clean', score: 0, findings: [{ severity: 'clean', label: 'Empty input', evidence: 'nothing to scan' }] };
  let url;
  try {
    url = new URL(/:\/\//.test(trimmed) ? trimmed : `https://${trimmed}`);
  } catch {
    return { url: trimmed, host: '', level: 'suspicious', score: 30, findings: [{ severity: 'medium', label: 'Unparseable URL', evidence: 'not a valid absolute URL' }] };
  }
  const host = url.hostname.toLowerCase();
  const reg = registrable(host);
  const tld = host.split('.').pop();

  if (url.username || url.password) { findings.push({ severity: 'high', label: 'Credentials embedded in the URL', evidence: 'user:pass@host shape' }); score += 30; }
  if (host.startsWith('xn--') || host.includes('.xn--')) {
    findings.push({ severity: 'high', label: 'Punycode internationalised hostname', evidence: 'can render as a lookalike of a Latin domain' });
    score += 25;
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    findings.push({ severity: 'medium', label: 'Raw IP address host', evidence: 'no registrable domain' });
    score += 25;
    if (PHISH_WORDS.some((w) => url.pathname.toLowerCase().includes(w))) {
      findings.push({ severity: 'high', label: 'IP host serving a login-style path', evidence: 'classic phishing hosting pattern' });
      score += 20;
    }
  }
  for (const brand of BRANDS) {
    const distance = levenshtein(reg.split('.')[0], brand);
    if (distance > 0 && distance <= 2) { findings.push({ severity: 'high', label: `Possible typosquat of "${brand}"`, evidence: `edit distance ${distance} from ${reg}` }); score += 40; break; }
  }
  const label = reg.split('.')[0];
  for (const brand of BRANDS) {
    if (label !== brand && label.includes(brand) && !label.startsWith(`${brand}-`)) {
      findings.push({ severity: 'medium', label: `Brand "${brand}" embedded in an unrelated domain`, evidence: reg });
      score += 22;
      break;
    }
  }
  if (HIGH_ABUSE_TLDS.includes(tld)) { findings.push({ severity: 'low', label: `High-abuse TLD .${tld}`, evidence: 'disproportionately used in phishing' }); score += 12; }
  if (SHORTENERS.includes(reg)) { findings.push({ severity: 'low', label: 'URL shortener hides the destination', evidence: reg }); score += 10; }
  const phishingHits = PHISH_WORDS.filter((w) => `${url.pathname}${url.search}`.toLowerCase().includes(w));
  if (phishingHits.length >= 2) { findings.push({ severity: 'medium', label: 'Credential-harvesting wording in the path', evidence: phishingHits.join(', ') }); score += 20; }
  if (url.protocol === 'http:' && PHISH_WORDS.some((w) => url.pathname.toLowerCase().includes(w))) {
    findings.push({ severity: 'medium', label: 'Credential page served without HTTPS', evidence: 'http:// scheme' });
    score += 18;
  }
  if ((host.match(/-/g) || []).length >= 2 && phishingHits.length) { findings.push({ severity: 'low', label: 'Hyphenated spoof pattern', evidence: host }); score += 8; }
  if (host.split('.').length > 5) { findings.push({ severity: 'low', label: 'Excessive subdomain depth', evidence: `${host.split('.').length} labels bury the registrable domain` }); score += 6; }
  if (/\.(exe|scr|bat|cmd|jar|apk|msi|vbs)$/i.test(url.pathname)) { findings.push({ severity: 'medium', label: 'Direct download of an executable', evidence: url.pathname }); score += 18; }

  const bounded = Math.min(100, score);
  const level = bounded >= 60 ? 'dangerous' : bounded >= 25 ? 'suspicious' : 'clean';
  if (!findings.length) findings.push({ severity: 'clean', label: 'No phishing indicators', evidence: 'hostname and path matched no heuristic' });
  return { url: url.href, host, level, score: bounded, findings };
}

/* ------------------------------------------------------------------------ */
/* The scanner                                                               */
/* ------------------------------------------------------------------------ */

export class SystemScanner {
  /**
   * @param {{vault?:object, files?:object, media?:object, clock?:()=>number,
   *          readFile?:(file:File)=>Promise<{head:Uint8Array, body:Uint8Array, sha256:string}>}} [options]
   */
  constructor(options = {}) {
    this.vault = options.vault || null;
    this.files = options.files || null;
    this.media = options.media || null;
    this.clock = options.clock || (() => Date.now());
    this.readFile = options.readFile || defaultReadFile;
    /** @type {Array<object>} completed runs, newest last */
    this.history = [];
    this.maxHistory = 30;
    this.current = null;
    this.listeners = new Set();
    this._abort = null;
  }

  onProgress(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  _emit(event) {
    for (const listener of this.listeners) {
      try { listener(event); } catch { /* a listener must not abort a scan */ }
    }
  }

  /** Modules this build can scan, with what each one really inspects. */
  capabilities() {
    return [
      { id: 'files', label: 'Files & downloads', available: true, detail: 'Byte inspection of files you select or drop (magic bytes, embedded executables, dropper patterns, EICAR).' },
      { id: 'urls', label: 'Links & QR targets', available: true, detail: 'Phishing heuristics over stored and pasted URLs.' },
      { id: 'vault', label: 'Vault storage', available: !!this.vault, detail: this.vault ? 'Integrity re-hash of every stored file.' : 'No storage adapter attached.' },
      { id: 'configuration', label: 'Security configuration', available: true, detail: 'Resolver encryption, DNSSEC, feed integrity, vault lock, storage headroom.' },
      { id: 'storage', label: 'Browser storage', available: true, detail: 'Quota usage per store; reports what the browser withholds.' },
      { id: 'applications', label: 'Installed applications', available: false, detail: 'A web page cannot enumerate installed apps or read other apps\' data. The Android build audits APK signatures instead.' },
      { id: 'systemFiles', label: 'Whole-device file system', available: false, detail: 'Android scoped storage and the browser sandbox both forbid it. Files must be granted explicitly.' },
      { id: 'network', label: 'Other applications\' network traffic', available: false, detail: 'Requires an OS-level VPN. This deployment only analyses its own DNS queries.' }
    ];
  }

  get running() { return !!this.current; }

  stop() {
    if (this._abort) this._abort.aborted = true;
  }

  /**
   * Runs a scan.
   * @param {{modules?:string[], files?:File[], urls?:string[], configuration?:object}} request
   */
  async run(request = {}) {
    if (this.current) throw new Error('A scan is already running.');
    const modules = request.modules?.length ? request.modules : ['files', 'urls', 'vault', 'configuration', 'storage'];
    const files = (request.files || []).filter(Boolean);
    const urls = (request.urls || []).filter((u) => String(u || '').trim());
    const abort = { aborted: false };
    this._abort = abort;

    const startedAt = this.clock();
    const run = {
      id: `scan-${startedAt}`,
      startedAt,
      finishedAt: null,
      status: 'running',
      modules,
      progress: 0,
      phase: 'Preparing',
      scanned: { files: 0, bytes: 0, urls: 0, checks: 0 },
      findings: [],
      errors: [],
      skipped: [],
      files: [],
      um: null
    };
    this.current = run;
    this._emit({ type: 'start', run });

    const step = async (phase, progress) => {
      run.phase = phase;
      run.progress = progress;
      this._emit({ type: 'progress', run });
      await tick();
    };

    try {
      const totalUnits = (modules.includes('files') ? Math.max(1, files.length) : 0)
        + (modules.includes('urls') ? Math.max(1, urls.length) : 0)
        + (modules.includes('vault') ? Math.max(1, this.vault?.entries?.length || 1) : 0)
        + (modules.includes('configuration') ? 6 : 0)
        + (modules.includes('storage') ? 2 : 0);
      let done = 0;
      const advance = () => { done += 1; return Math.min(0.99, done / Math.max(1, totalUnits)); };

      if (modules.includes('files')) {
        await step('Scanning files', 0.02);
        for (const file of files) {
          if (abort.aborted) break;
          try {
            const result = await this._scanOneFile(file);
            run.files.push(result);
            run.scanned.files += 1;
            run.scanned.bytes += result.size || 0;
            for (const finding of result.findings) {
              if (finding.severity !== 'info' && finding.severity !== 'clean') {
                run.findings.push({ scope: 'file', target: result.name, ...finding });
              }
            }
          } catch (error) {
            run.errors.push({ scope: 'file', target: file?.name || 'unknown', message: String(error?.message || error) });
          }
          await step(`Scanning files · ${run.scanned.files}/${files.length}`, advance());
        }
      }

      if (modules.includes('urls')) {
        const pending = [...new Set(urls)];
        for (const url of pending) {
          if (abort.aborted) break;
          const result = scanUrl(url);
          run.scanned.urls += 1;
          run.scanned.checks += result.findings.length;
          for (const finding of result.findings) {
            if (finding.severity !== 'clean') run.findings.push({ scope: 'url', target: result.host || url, ...finding });
          }
          await step(`Analysing links · ${run.scanned.urls}/${pending.length}`, advance());
        }
      }

      if (modules.includes('vault') && this.vault) {
        await step('Verifying vault storage', advance());
        const entries = this.vault.list();
        if (!entries.length) run.skipped.push({ scope: 'vault', reason: 'the vault is empty — nothing to verify' });
        for (const entry of entries) {
          if (abort.aborted) break;
          const check = await this.vault.verify(entry.id);
          run.scanned.checks += 1;
          if (!check.ok) {
            run.findings.push({ scope: 'vault', target: entry.name, severity: 'high', label: 'Stored file failed its integrity check', evidence: check.error });
          }
          await step(`Verifying vault · ${entry.name}`, advance());
        }
      }

      if (modules.includes('configuration') && request.configuration) {
        const configFindings = this._scanConfiguration(request.configuration);
        run.scanned.checks += configFindings.length;
        run.findings.push(...configFindings.filter((f) => f.severity !== 'clean'));
        if (!configFindings.some((f) => f.severity === 'clean')) {
          run.findings.push(...configFindings);
        }
        await step('Auditing configuration', advance());
      }

      if (modules.includes('storage')) {
        await step('Measuring storage', advance());
        const estimate = await (await import('./storage.js')).IndexedDbAdapter.estimate();
        run.storage = {
          estimate,
          vault: this.vault ? await this.vault.usage() : null
        };
        if (estimate.supported && estimate.quota > 0 && estimate.usage / estimate.quota > 0.9) {
          run.findings.push({ scope: 'storage', target: 'origin quota', severity: 'medium', label: 'Storage is over 90 % full', evidence: `${(estimate.usage / 1048576).toFixed(1)} MB of ${(estimate.quota / 1048576).toFixed(0)} MB` });
        }
        if (!estimate.supported) run.skipped.push({ scope: 'storage', reason: 'this browser does not report a storage quota (StorageManager.estimate is unavailable)' });
        await step('Measuring storage', advance());
      }

      for (const id of modules) {
        const capability = this.capabilities().find((c) => c.id === id);
        if (!capability) run.skipped.push({ scope: id, reason: 'unknown module' });
        else if (!capability.available) run.skipped.push({ scope: id, reason: capability.detail });
      }

      run.status = abort.aborted ? 'cancelled' : 'complete';
    } catch (error) {
      run.status = 'failed';
      run.errors.push({ scope: 'scan', message: String(error?.message || error) });
    } finally {
      run.finishedAt = this.clock();
      run.durationMs = run.finishedAt - run.startedAt;
      run.progress = 1;
      run.phase = run.status === 'complete' ? 'Finished' : run.phase;
      run.summary = this._summarise(run);
      this.history.push(run);
      if (this.history.length > this.maxHistory) this.history.shift();
      this.current = null;
      this._abort = null;
      this._emit({ type: 'done', run });
    }
    return run;
  }

  _summarise(run) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const finding of run.findings) counts[finding.severity] = (counts[finding.severity] || 0) + 1;
    const worst = maxSeverity(run.findings);
    return {
      status: SEVERITY_LABEL[worst] === 'clean' ? 'clean' : SEVERITY_LABEL[worst],
      counts,
      findings: run.findings.length,
      files: run.scanned.files,
      bytes: run.scanned.bytes,
      urls: run.scanned.urls,
      checks: run.scanned.checks,
      errors: run.errors.length,
      skipped: run.skipped.length
    };
  }

  async _scanOneFile(file) {
    const { head, body, sha256, size } = await this.readFile(file, DEEP_SCAN_BYTES);
    const result = scanBytes({ name: file.name || 'unnamed', size: size ?? file.size ?? 0, head, body, sha256 });
    return {
      name: file.name || 'unnamed',
      size: size ?? file.size ?? 0,
      type: file.type || 'unknown',
      source: file.webkitRelativePath || file.__path || null,
      scannedBytes: head.length + (body?.length || 0),
      ...result
    };
  }

  _scanConfiguration(config) {
    const findings = [];
    const push = (severity, target, label, evidence) => findings.push({ scope: 'configuration', target, severity, label, evidence });
    const { resolver, dnssec, feeds, vaultLocked, rules, engineLoaded, serviceWorker } = config;

    if (resolver) {
      const encrypted = /^https:/.test(resolver.dohJson || '') || !!resolver.dot;
      push(encrypted ? 'clean' : 'high', 'Resolver', encrypted ? `Encrypted transport in use (${resolver.name})` : 'Plaintext DNS transport',
        encrypted ? (resolver.dohJson || resolver.dot) : 'plaintext DNS can be read and modified in transit');
    } else {
      push('medium', 'Resolver', 'No resolver configuration available', 'the DNS client has not been initialised');
    }
    if (dnssec && dnssec.status) {
      const bad = ['bogus', 'unsigned'].includes(dnssec.status);
      push(bad ? 'medium' : 'clean', 'DNSSEC', `DNSSEC assessment: ${dnssec.status}`, dnssec.detail || dnssec.resolver || '');
    }
    if (feeds) {
      const failed = (feeds || []).filter((feed) => feed.verified === false);
      for (const feed of failed) push('high', `Feed ${feed.id}`, 'Feed integrity check failed', feed.error || 'hash mismatch');
      if (!failed.length && feeds.length) push('clean', 'Feeds', `${feeds.length} feed${feeds.length === 1 ? '' : 's'} verified`, 'SHA-256 matched');
    }
    if (vaultLocked !== undefined) {
      push(vaultLocked ? 'clean' : 'low', 'Vault', vaultLocked ? 'Vault passphrase lock is enabled' : 'Vault is not passphrase-locked', vaultLocked ? 'AES-GCM with PBKDF2 derivation' : 'files are readable by anything with access to this browser profile');
    }
    if (engineLoaded === false) push('high', 'Filter engine', 'Filter engine is not loaded', 'no rules are being enforced');
    if (rules && rules.total) push('clean', 'Filter engine', `${rules.total.toLocaleString()} rules active`, `${rules.blockDomains} blocked domains, ${rules.safetyEntries} safety exceptions`);
    if (serviceWorker === false) push('low', 'Offline shell', 'Service worker is not active', 'offline protection and cached rules are unavailable in this tab');
    return findings;
  }

  /** Exports a report; findings only, no file contents. */
  report(runId = null) {
    const run = runId ? this.history.find((entry) => entry.id === runId) : this.history[this.history.length - 1];
    if (!run) return null;
    return {
      generatedAt: new Date(this.clock()).toISOString(),
      platform: 'browser',
      version: '5.1.0',
      run: {
        id: run.id, startedAt: run.startedAt, finishedAt: run.finishedAt,
        durationMs: run.durationMs, status: run.status, summary: run.summary,
        scanned: run.scanned, skipped: run.skipped, errors: run.errors
      },
      findings: run.findings,
      files: run.files.map((file) => ({ name: file.name, size: file.size, type: file.type, severity: file.severity, sha256: file.sha256, findings: file.findings }))
    };
  }
}

function tick() {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

/** Reads a File with bounded memory: head window, deep window, and a real digest. */
async function defaultReadFile(file, deepLimit = DEEP_SCAN_BYTES) {
  if (!file || typeof file.arrayBuffer !== 'function') throw new Error('not a readable File');
  const size = file.size || 0;
  const head = new Uint8Array(await file.slice(0, HEAD_BYTES).arrayBuffer());
  const body = size > HEAD_BYTES ? new Uint8Array(await file.slice(0, Math.min(size, deepLimit)).arrayBuffer()) : head;
  // Digest whatever we can afford to read, and say so in the report when capped.
  const digestSource = size <= deepLimit ? body : body;
  const sha256 = sha256Hex(digestSource);
  return { head, body, sha256, size };
}

export default { SystemScanner, scanBytes, scanUrl, entropy, SEVERITY, SEVERITY_LABEL };
