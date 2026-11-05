#!/usr/bin/env node
/**
 * AdShield Pro — staged-site verification.
 *
 * Runs against the tree that scripts/stage-site.mjs produced, i.e. the exact bytes GitHub
 * Pages will serve. `npm run verify` checks the source repository; this checks the deployment,
 * because those are different failure modes:
 *
 *   - a link that works from docs/index.html locally but 404s once the app lives at /app/
 *   - a social-preview tag pointing at an image that was never staged
 *   - the 404 page quietly depending on an asset that does not exist
 *   - robots.txt / sitemap.xml advertising an origin the site is not published from
 *   - an oversized artifact (Pages rejects files over 100 MB)
 *
 * Usage:
 *   node scripts/verify-site.mjs [dir=_site]            # human-readable, exits 1 on failure
 *   node scripts/verify-site.mjs [dir=_site] --summary   # GitHub step summary (markdown)
 *
 * Also importable: `verifySite(dir)` returns { ok, checks, summary }.
 */
import { readFileSync, existsSync, statSync, readdirSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { readOrigin } from './stage-site.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
export const MAX_PAGES_FILE_BYTES = 100 * 1024 * 1024;

const read = (file) => readFileSync(file, 'utf8');

/** Parses attributes out of a start tag well enough for site-wide link auditing. */
function attrs(tag) {
  const out = {};
  for (const m of tag.matchAll(/([a-zA-Z@:-]+)\s*=\s*"([^"]*)"/g)) out[m[1].toLowerCase()] = m[2];
  return out;
}

/** Every href/src/action/posters value in a document, in source order. */
function references(html) {
  const refs = [];
  for (const m of html.matchAll(/<(a|link|script|img|source|use|form|iframe|video|audio|image)\b[^>]*>/gi)) {
    const a = attrs(m[0]);
    for (const key of ['href', 'src', 'action', 'poster', 'xlink:href']) {
      if (a[key]) refs.push({ tag: m[1].toLowerCase(), attr: key, url: a[key] });
    }
    // <source srcset="…"> and srcset on images: audit the first candidate only.
    if (a.srcset) refs.push({ tag: m[1].toLowerCase(), attr: 'srcset', url: a.srcset.split(',')[0].trim().split(/\s+/)[0] });
  }
  return refs;
}

/**
 * Classifies a URL from a staged page.
 * @param {string} url raw attribute value
 * @param {string} pagePath absolute path of the page doing the linking
 * @param {string} [origin] published origin; absolute URLs under it are audited like local ones
 * @param {{siteRoot?: string}} [options] staged tree; enables root-relative URL resolution
 * @returns {{kind: 'external'|'anchor'|'data'|'empty'|'local', path?: string, why?: string}}
 */
export function classify(url, pagePath, origin = '', { siteRoot = '' } = {}) {
  const value = url.trim();
  if (!value) return { kind: 'empty' };
  if (value.startsWith('#')) return { kind: 'anchor', why: value };
  if (/^(data|blob|mailto|tel|javascript):/i.test(value) || value.startsWith('?')) return { kind: 'data' };
  if (/^[a-z][a-z0-9+.-]*:/i.test(value) && !/^https?:/i.test(value)) return { kind: 'external' };
  if (/^https?:\/\//i.test(value)) {
    // A link written as https://<origin>/x is the same file as /x, so audit it the same way.
    if (origin && value.startsWith(`${origin}/`)) {
      return { kind: 'local', path: resolve(dirname(pagePath), `.${value.slice(origin.length)}`) };
    }
    return { kind: 'external' };
  }
  if (value.startsWith('//')) return { kind: 'external' };
  // Relative or root-relative. Strip query and fragment, then resolve against the page.
  const clean = value.split('#')[0].split('?')[0];
  // GitHub Pages project sites are served from /<repo>/, so "/" means the site root only when
  // we know where the site root is. Without it, a root-relative link cannot be audited.
  if (clean.startsWith('/')) {
    return siteRoot ? { kind: 'local', path: resolve(siteRoot, `.${clean}`) } : { kind: 'local', path: '' };
  }
  return { kind: 'local', path: resolve(dirname(pagePath), clean) };
}

function isFile(file) {
  try { return statSync(file).isFile(); } catch { return false; }
}

/** A directory URL ("app/") is satisfied by app/index.html and by the directory itself. */
function resolvesTo(target) {
  if (isFile(target)) return true;
  try { if (statSync(target).isDirectory()) return true; } catch { /* not a directory */ }
  return isFile(resolve(target, 'index.html'));
}

/**
 * @param {string} dir staged site directory
 * @param {{root?: string}} [options] root of the source repository (for origin + 404 source)
 */
export function verifySite(dir, { root = resolve(HERE, '..') } = {}) {
  const site = resolve(dir);
  const checks = [];
  const add = (name, ok, detail = '') => checks.push({ name, ok: !!ok, detail: String(detail) });

  const fail = (name, detail) => add(name, false, detail);

  /* 1. The staged tree exists and holds both halves of the site. */
  const pages = { 'index.html': resolve(site, 'index.html'), 'app/index.html': resolve(site, 'app/index.html') };
  for (const [label, file] of Object.entries(pages)) {
    if (!isFile(file)) { fail(`page exists: ${label}`, file); continue; }
    add(`page exists: ${label}`, statSync(file).size > 500, `${statSync(file).size} bytes`);
  }
  if (!checks.every((c) => c.ok)) return finish(checks, site);

  const home = read(pages['index.html']);

  /* 2. Social/SEO metadata: absolute, complete, and pointing at files that were staged. */
  const meta = (attr, value) => {
    const re = new RegExp(`<meta[^>]*${attr}=["']${value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}["'][^>]*content=["']([^"']*)["']`, 'i');
    return home.match(re)?.[1] || '';
  };
  let origin = '';
  try {
    origin = readOrigin(root);
    add('origin declared', true, origin);
  } catch (err) {
    fail('origin declared', err.message);
  }

  const ogImage = meta('property', 'og:image');
  add('og:image is an absolute URL', /^https:\/\/[^/]+\/.*\.(png|jpg|jpeg|webp|gif)$/i.test(ogImage), ogImage || 'missing');
  add('twitter:card is summary_large_image', meta('name', 'twitter:card') === 'summary_large_image', meta('name', 'twitter:card') || 'missing');
  add('og:title is set', !!meta('property', 'og:title'), meta('property', 'og:title'));
  add('og:description is set', !!meta('property', 'og:description'), meta('property', 'og:description'));
  add('canonical link is absolute', /<link[^>]*rel="canonical"[^>]*href="https:\/\//i.test(home));

  // og:image must be a file this deployment actually serves, at the same path.
  if (origin && ogImage.startsWith(`${origin}/`)) {
    const staged = resolve(site, ogImage.slice(origin.length + 1));
    add('og:image is published', isFile(staged), staged);
    if (isFile(staged)) {
      const size = statSync(staged).size;
      add('og:image is under 1 MB (scrapers skip larger previews)', size <= 1024 * 1024, `${(size / 1024).toFixed(0)} KB`);
    }
  } else if (ogImage) {
    fail('og:image matches the published origin', `${ogImage} is not under ${origin || '(unknown origin)'}`);
  }

  /* 3. Every same-site link from the two public pages resolves inside the staged tree. */
  const broken = [];
  const unaudited = [];
  let localLinks = 0;
  for (const [label, file] of Object.entries(pages)) {
    for (const ref of references(read(file))) {
      const c = classify(ref.url, file, origin, { siteRoot: site });
      if (c.kind !== 'local') continue;
      if (!c.path) { unaudited.push(ref.url); continue; }
      localLinks += 1;
      if (c.path.startsWith(site)) {
        if (!resolvesTo(c.path)) broken.push(`${label} → ${ref.url}`);
      } else if (c.path === resolve(root, 'docs/PRIVACY_POLICY.md') || ref.url.includes('/AdShieldPro/blob/')) {
        // Cross-origin links into the GitHub repository are external by definition.
        continue;
      } else if (!resolvesTo(c.path)) {
        broken.push(`${label} → ${ref.url} (outside the staged site)`);
      }
    }
  }
  add('every published internal link resolves', broken.length === 0, broken.join('; '));
  add('internal links were actually found', localLinks > 0, `${localLinks} links`);
  add('no unevaluated root-relative link', unaudited.length === 0, unaudited.join(', '));

  /* 4. The 404 page is self-contained and routes back into the site. */
  const notFound = resolve(site, '404.html');
  if (!isFile(notFound)) {
    fail('404.html is published', 'missing from the staged tree');
  } else {
    const html404 = read(notFound);
    const external = references(html404).filter((r) => {
      const c = classify(r.url, notFound, origin, { siteRoot: site });
      return c.kind === 'local' && c.path && !resolvesTo(c.path);
    });
    add('404.html references only what it ships', external.length === 0, external.map((r) => r.url).join(', '));
    add('404.html links home', /href="\/"/.test(html404));
    add('404.html is noindex', metaFrom(html404, 'name', 'robots') === 'noindex');
  }

  /* 5. Crawler files agree with the declared origin. */
  const robots = resolve(site, 'robots.txt');
  const sitemap = resolve(site, 'sitemap.xml');
  add('robots.txt is published', isFile(robots), isFile(robots) ? `${statSync(robots).size} bytes` : 'missing');
  add('sitemap.xml is published', isFile(sitemap), isFile(sitemap) ? `${statSync(sitemap).size} bytes` : 'missing');
  if (origin && isFile(robots) && isFile(sitemap)) {
    const text = read(robots);
    add('robots.txt points at the published sitemap', text.includes(`Sitemap: ${origin}/sitemap.xml`), text.split('\n').find((l) => l.startsWith('Sitemap:')) || 'no Sitemap line');
    const xml = read(sitemap);
    const locs = [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]);
    add('sitemap lists the site root and the web app', locs.includes(`${origin}/`) && locs.includes(`${origin}/app/`), locs.join(', '));
    const stale = locs.filter((l) => !l.startsWith(`${origin}/`));
    add('sitemap has only the declared origin', stale.length === 0, stale.join(', '));
    add('sitemap urls are all reachable', locs.every((loc) => {
      const rel = loc.slice(origin.length + 1) || '.';
      return resolvesTo(resolve(site, rel));
    }), locs.join(', '));
    // The canonical tag and og:url must match too, or search engines see two homes.
    add('canonical matches the declared origin', home.includes(`href="${origin}/"`));
    add('og:url matches the declared origin', home.includes(`property="og:url" content="${origin}/"`));
  }

  /* 6. Deployment size limits and the things that must never be published. */
  const oversized = [];
  let biggest = { file: '', size: 0 };
  let total = 0;
  let files = 0;
  (function walk(directory) {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const full = resolve(directory, entry.name);
      if (entry.isDirectory()) { walk(full); continue; }
      const size = statSync(full).size;
      total += size;
      files += 1;
      if (size > biggest.size) biggest = { file: full.slice(site.length + 1), size };
      if (size > MAX_PAGES_FILE_BYTES) oversized.push(`${full.slice(site.length + 1)} (${(size / 1048576).toFixed(1)} MB)`);
    }
  })(site);
  add('no file exceeds the 100 MB Pages limit', oversized.length === 0, oversized.join(', '));
  add('artifact is under 1 GB (Pages limit)', total < 1024 ** 3, `${(total / 1048576).toFixed(1)} MB in ${files} files`);

  for (const forbidden of ['node_modules', 'tests', 'scripts', 'package.json', '.git', 'app/tests', 'app/node_modules']) {
    add(`not published: ${forbidden}`, !existsSync(resolve(site, forbidden)), resolve(site, forbidden));
  }
  add('no source map is published', !hasExtension(site, '.map'));
  add('largest published file', biggest.size > 0, `${biggest.file} — ${(biggest.size / 1048576).toFixed(2)} MB`);

  return finish(checks, site, { origin, total, files, biggest });
}

/** Reads a meta tag by attribute name and value. */
function metaFrom(html, attr, value) {
  const re = new RegExp(`<meta[^>]*${attr}=["']${value}["'][^>]*content=["']([^"']*)["']`, 'i');
  return html.match(re)?.[1] || '';
}

function hasExtension(directory, extension) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const full = resolve(directory, entry.name);
    if (entry.isDirectory()) { if (hasExtension(full, extension)) return true; }
    else if (entry.name.endsWith(extension)) return true;
  }
  return false;
}

function finish(checks, site, extra = {}) {
  return {
    ok: checks.every((c) => c.ok),
    checks,
    site,
    ...extra,
    summary: {
      passed: checks.filter((c) => c.ok).length,
      failed: checks.filter((c) => !c.ok).length
    }
  };
}

/* CLI */
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = process.argv.slice(2).filter((a) => !a.startsWith('--'));
  const html = process.argv.includes('--html');
  const dir = args[0] || '_site';
  let result;
  try {
    result = verifySite(dir);
  } catch (err) {
    console.error(`site verification could not run: ${err.message}`);
    process.exit(1);
  }

  if (process.argv.includes('--summary')) {
    const lines = [
      '### Staged site',
      '',
      `| Check | Result | Detail |`,
      `|---|---|---|`,
      ...result.checks.map((c) => `| ${c.name} | ${c.ok ? '✅' : '❌'} | ${c.detail ? c.detail.replace(/\|/g, '\\|').slice(0, 160) : ''} |`),
      ''
    ];
    console.log(`${result.summary.passed} passed · ${result.summary.failed} failed${result.origin ? ` · ${result.origin}` : ''}`);
    console.log(lines.join('\n'));
  } else {
    for (const check of result.checks) {
      const mark = check.ok ? 'ok  ' : 'FAIL';
      console.log(`${mark} ${check.name}${check.detail ? ` — ${check.detail}` : ''}`);
    }
    console.log(`\n${result.summary.passed} passed, ${result.summary.failed} failed${result.total ? ` · ${(result.total / 1048576).toFixed(1)} MB in ${result.files} files` : ''}`);
  }
  if (!result.ok) process.exit(1);
}
