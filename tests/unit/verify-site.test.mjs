/**
 * Unit tests — staged-site verification (scripts/verify-site.mjs).
 *
 * `verify` audits the source repository; this audits the tree GitHub Pages actually serves.
 * Each test stages the real repository once, breaks one thing that would only show up after
 * deployment, and asserts the check catches it. Without these, a green `npm run verify` and a
 * broken live site can ship together.
 */
import test from 'node:test';
import { strict as assert } from 'node:assert';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, cpSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { stageSite, readOrigin, sitemapUrls } from '../../scripts/stage-site.mjs';
import { verifySite, classify } from '../../scripts/verify-site.mjs';

/** Stages the real repository into a throwaway directory. */
function staged() {
  const dir = mkdtempSync(join(tmpdir(), 'adshield-site-'));
  const site = join(dir, 'site');
  stageSite({ out: site });
  return { dir, site, dispose: () => rmSync(dir, { recursive: true, force: true }) };
}

const failed = (result) => result.checks.filter((c) => !c.ok).map((c) => c.name);

test('the real deployment passes every staged-site gate', () => {
  const { site, dispose } = staged();
  try {
    const result = verifySite(site);
    assert.equal(result.ok, true, failed(result).join(', '));
    assert.ok(result.summary.passed >= 30, `expected a full audit, got ${result.summary.passed} checks`);
    assert.match(result.origin, /^https:\/\/[^/]+\//);
  } finally {
    dispose();
  }
});

test('a same-site link to a file that was never staged fails the deployment', () => {
  const { site, dispose } = staged();
  try {
    const home = join(site, 'index.html');
    writeFileSync(home, readFileSync(home, 'utf8').replace('<main', '<a href="images/not-there.png">x</a><main'));
    const result = verifySite(site);
    assert.equal(result.ok, false);
    assert.ok(failed(result).includes('every published internal link resolves'), failed(result).join(', '));
  } finally {
    dispose();
  }
});

test('the og:image in the preview tags must be a published file', () => {
  const { site, dispose } = staged();
  try {
    unlinkSync(join(site, 'og-image.png'));
    const result = verifySite(site);
    assert.equal(result.ok, false);
    assert.ok(failed(result).includes('og:image is published'), failed(result).join(', '));
  } finally {
    dispose();
  }
});

test('robots.txt and the sitemap must agree with the declared origin', () => {
  const { site, dispose } = staged();
  try {
    writeFileSync(join(site, 'robots.txt'), 'User-agent: *\nAllow: /\nSitemap: https://someone-else.example/sitemap.xml\n');
    const result = verifySite(site);
    assert.equal(result.ok, false);
    assert.ok(failed(result).includes('robots.txt points at the published sitemap'), failed(result).join(', '));
  } finally {
    dispose();
  }
});

test('the 404 page may only link to pages the deployment actually serves', () => {
  const { site, dispose } = staged();
  try {
    const page = join(site, '404.html');
    writeFileSync(page, readFileSync(page, 'utf8').replace('href="/app/"', 'href="/app-moved/"'));
    const result = verifySite(site);
    assert.equal(result.ok, false);
    assert.ok(failed(result).includes('404.html references only what it ships'), failed(result).join(', '));
  } finally {
    dispose();
  }
});

test('a staged tree without the 404 page is rejected', () => {
  const { site, dispose } = staged();
  try {
    unlinkSync(join(site, '404.html'));
    const result = verifySite(site);
    assert.equal(result.ok, false);
    assert.ok(failed(result).includes('404.html is published'));
  } finally {
    dispose();
  }
});

test('root-relative links resolve against the site root, not the filesystem', () => {
  const ctx = { siteRoot: '/tmp/site' };
  assert.equal(classify('/app/', '/tmp/site/404.html', '', ctx).path, '/tmp/site/app');
  assert.equal(classify('/missing/', '/tmp/site/404.html', '', ctx).path, '/tmp/site/missing');
  // Same-site absolute links are audited like relative ones; other hosts stay external.
  assert.equal(classify('https://u.github.io/r/app/', '/tmp/site/index.html', 'https://u.github.io/r').path, '/tmp/site/app');
  assert.equal(classify('https://github.com/x/y', '/tmp/site/index.html', 'https://u.github.io/r').kind, 'external');
  assert.equal(classify('#top', '/tmp/site/index.html').kind, 'anchor');
  assert.equal(classify('data:image/svg+xml,<svg/>', '/tmp/site/index.html').kind, 'data');
});

test('the origin is read from one file and the sitemap is derived from it', () => {
  const origin = readOrigin();
  assert.match(origin, /^https:\/\/[^/]+(\/[^/]+)?$/, origin);
  assert.ok(!origin.endsWith('/'), 'the origin is stored without a trailing slash');
  assert.deepEqual(sitemapUrls(origin), [`${origin}/`, `${origin}/app/`]);
});

test('a canonical.txt without a usable URL stops the build instead of shipping a bad sitemap', () => {
  const dir = mkdtempSync(join(tmpdir(), 'adshield-origin-'));
  try {
    cpSync(join(process.cwd(), 'docs/canonical.txt'), join(dir, 'docs/canonical.txt'), { recursive: true });
    writeFileSync(join(dir, 'docs/canonical.txt'), '# no url here\nnot-a-url\n');
    assert.throws(() => readOrigin(dir), /one https URL/);
    rmSync(join(dir, 'docs/canonical.txt'));
    assert.throws(() => readOrigin(dir), /canonical\.txt is missing/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
