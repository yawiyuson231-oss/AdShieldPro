#!/usr/bin/env node
/**
 * OmniShield X — site assembler.
 *
 * The GitHub Pages deployment hosts two things on one domain:
 *
 *   /        ← public web files in docs/   marketing site, privacy policy, 404, icons, feeds
 *   /app/    ← the web platform            index.html, modules, feeds, extension zip
 *
 * Keeping the assembly in a script (rather than inline in the workflow) means the
 * exact same layout can be produced and checked locally, service-worker precache
 * entries are verified against the staged tree, and every relative link and anchor
 * across all published HTML pages is verified before upload.
 *
 * Usage: `node scripts/stage-site.mjs [--out _site] [--check-only]`
 */
import {
  cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync,
  readdirSync, rmSync, statSync, writeFileSync
} from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, relative } from 'node:path';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** Public entries copied from docs/ into the root of the deployed site. */
export const SITE_ROOT_FILES = [
  'index.html',
  'privacy.html',
  '404.html',
  '.nojekyll',
  'robots.txt',
  'sitemap.xml',
  'app-icon-512.png',
  'PRIVACY_POLICY.md'
];
export const SITE_ROOT_DIRS = ['images', 'intel'];

/** Files the browser needs at the root of /app/. */
export const APP_ROOT_FILES = [
  'index.html', 'app.js', 'engine.js', 'sw.js', 'manifest.webmanifest', 'omnishield-x-extension.zip'
];
/** Directories copied wholesale (they contain only runtime assets). */
export const APP_DIRS = ['ui', 'dns', 'aether', 'security', 'guard', 'assets'];

/** Parses the service worker's precache list and reports which entries are missing. */
export function checkPrecache(appDir) {
  const swPath = resolve(appDir, 'sw.js');
  if (!existsSync(swPath)) return { ok: false, error: 'sw.js missing from the staged app', listed: [], missing: [] };
  const source = readFileSync(swPath, 'utf8');
  const listed = [...new Set([...source.matchAll(/'(\.\/[^']+)'/g)].map((m) => m[1]))];
  const missing = listed
    .filter((url) => url !== './')
    .map((url) => url.slice(2))
    .filter((rel) => !existsSync(resolve(appDir, rel)));
  return { ok: missing.length === 0, listed, missing, error: missing.length ? `missing: ${missing.join(', ')}` : null };
}

/** Verifies every relative href/src and #anchor across staged HTML pages. */
export function checkSiteLinks(siteDir) {
  const htmlFiles = collectHtmlFiles(siteDir);
  const idCache = new Map();
  const idsFor = (filePath) => {
    if (!idCache.has(filePath)) {
      const clean = stripNonMarkup(readFileSync(filePath, 'utf8'));
      idCache.set(filePath, new Set([...clean.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1])));
    }
    return idCache.get(filePath);
  };

  const broken = [];
  let checked = 0;

  for (const htmlFile of htmlFiles) {
    const relPage = relative(siteDir, htmlFile);
    const clean = stripNonMarkup(readFileSync(htmlFile, 'utf8'));
    for (const match of clean.matchAll(/\b(?:href|src)="([^"]*)"/g)) {
      const raw = match[1].trim();
      if (!raw) continue;
      if (/^(?:https?:|data:|mailto:|tel:|javascript:|blob:|about:|chrome:)/i.test(raw)) continue;
      checked++;

      const hashIdx = raw.indexOf('#');
      const pathPart = (hashIdx === -1 ? raw : raw.slice(0, hashIdx)).split('?')[0];
      const fragment = hashIdx === -1 ? '' : raw.slice(hashIdx + 1);

      if (!pathPart) {
        if (fragment && !idsFor(htmlFile).has(fragment)) {
          broken.push(`${relPage}: missing #${fragment}`);
        }
        continue;
      }

      const candidate = pathPart.startsWith('/')
        ? resolve(siteDir, `.${pathPart}`)
        : resolve(dirname(htmlFile), pathPart);

      // Refuse paths that escape the deployed site root.
      if (candidate !== siteDir && !candidate.startsWith(`${siteDir}/`)) {
        broken.push(`${relPage}: ${raw} escapes site root`);
        continue;
      }

      let targetFile = candidate;
      if (existsSync(candidate) && statSync(candidate).isDirectory()) {
        targetFile = resolve(candidate, 'index.html');
      }
      if (!existsSync(targetFile) || !statSync(targetFile).isFile()) {
        broken.push(`${relPage}: ${raw} -> missing (${relative(siteDir, targetFile)})`);
        continue;
      }

      if (fragment && targetFile.endsWith('.html') && !idsFor(targetFile).has(fragment)) {
        broken.push(`${relPage}: ${raw} -> missing #${fragment} in ${relative(siteDir, targetFile)}`);
      }
    }
  }

  return {
    ok: broken.length === 0,
    pages: htmlFiles.length,
    checked,
    broken,
    error: broken.length ? broken.join('; ') : null
  };
}

function stripNonMarkup(html) {
  return html
    .replace(/<script\b[\s\S]*?<\/script>/gi, '')
    .replace(/<style\b[\s\S]*?<\/style>/gi, '')
    .replace(/<!--[\s\S]*?-->/g, '');
}

function collectHtmlFiles(dir) {
  const found = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = resolve(dir, entry.name);
    if (entry.isDirectory()) found.push(...collectHtmlFiles(full));
    else if (entry.name.endsWith('.html')) found.push(full);
  }
  return found;
}

/**
 * Builds the deployable tree.
 * @param {{out?: string, root?: string}} [options]
 */
export function stageSite({ out = '_site', root = ROOT } = {}) {
  const target = resolve(root, out);
  rmSync(target, { recursive: true, force: true });
  mkdirSync(target, { recursive: true });

  // 1. Public marketing site files at the domain root.
  const docs = resolve(root, 'docs');
  if (!existsSync(resolve(docs, 'index.html'))) throw new Error('docs/index.html is missing');
  const rootCopied = [];
  for (const file of SITE_ROOT_FILES) {
    const from = resolve(docs, file);
    if (!existsSync(from)) continue;
    cpSync(from, resolve(target, file));
    rootCopied.push(file);
  }
  for (const dir of SITE_ROOT_DIRS) {
    const from = resolve(docs, dir);
    if (!existsSync(from)) continue;
    cpSync(from, resolve(target, dir), { recursive: true });
    rootCopied.push(`${dir}/`);
  }
  // Always include .nojekyll so GitHub Pages serves every asset verbatim.
  if (!existsSync(resolve(target, '.nojekyll'))) {
    writeFileSync(resolve(target, '.nojekyll'), '');
    rootCopied.push('.nojekyll');
  }

  // 2. The web platform under /app/.
  const appDir = resolve(target, 'app');
  mkdirSync(appDir, { recursive: true });
  const copied = [];
  for (const file of APP_ROOT_FILES) {
    const from = resolve(root, file);
    if (!existsSync(from)) {
      // Allow miniature test fixtures without the generated extension ZIP.
      if (file === 'omnishield-x-extension.zip' && root !== ROOT) continue;
      throw new Error(`${file} is missing from the repository root`);
    }
    cpSync(from, resolve(appDir, file));
    copied.push(file);
  }
  for (const dir of APP_DIRS) {
    const from = resolve(root, dir);
    if (!existsSync(from)) throw new Error(`${dir}/ is missing from the repository root`);
    cpSync(from, resolve(appDir, dir), { recursive: true });
    copied.push(`${dir}/`);
  }

  // 3. Nothing that only exists for development may leak into the artifact.
  for (const forbidden of ['node_modules', 'tests', 'scripts', 'package.json', '.git', 'design']) {
    if (existsSync(resolve(target, forbidden))) throw new Error(`${forbidden} must not be published at /`);
    if (existsSync(resolve(appDir, forbidden))) throw new Error(`${forbidden} must not be published under /app/`);
  }

  // 4. Service-worker precache and HTML link integrity gates.
  const precache = checkPrecache(appDir);
  if (!precache.ok) throw new Error(`staged app is not self-sufficient — ${precache.error}`);

  const links = checkSiteLinks(target);
  if (!links.ok) throw new Error(`staged site has broken internal links — ${links.error}`);

  return {
    out: target,
    appDir,
    rootCopied,
    copied,
    precache: precache.listed.length,
    linksChecked: links.checked,
    pagesChecked: links.pages,
    siteBytes: directorySize(target),
    appBytes: directorySize(appDir),
    files: countFiles(appDir)
  };
}

function directorySize(dir) {
  let total = 0;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = resolve(dir, entry.name);
    total += entry.isDirectory() ? directorySize(full) : statSync(full).size;
  }
  return total;
}

function countFiles(dir) {
  let total = 0;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    total += entry.isDirectory() ? countFiles(resolve(dir, entry.name)) : 1;
  }
  return total;
}

/* CLI */
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const checkOnly = process.argv.includes('--check-only');
  const outIndex = process.argv.indexOf('--out');
  const tempRoot = checkOnly ? mkdtempSync(resolve(tmpdir(), 'adshield-stage-check-')) : null;
  const out = checkOnly ? resolve(tempRoot, 'site') : (outIndex !== -1 ? process.argv[outIndex + 1] : '_site');
  try {
    const result = stageSite({ out });
    const where = checkOnly ? '(check-only)' : (relative(ROOT, result.out) || result.out);
    console.log(`staged ${where} — site ${(result.siteBytes / 1048576).toFixed(2)} MB · app ${(result.appBytes / 1048576).toFixed(2)} MB in ${result.files} files`);
    console.log(`${result.precache} precached assets verified · ${result.linksChecked} internal links verified across ${result.pagesChecked} pages`);
  } catch (err) {
    console.error(`staging failed: ${err.message}`);
    process.exitCode = 1;
  } finally {
    if (tempRoot) rmSync(tempRoot, { recursive: true, force: true });
  }
}
