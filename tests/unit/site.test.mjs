/**
 * Unit tests — the published website (marketing site + web platform shell + deploy wiring).
 *
 * Each test pins a defect that reached the live site and that no other suite could see,
 * because the pages rendered "successfully" in jsdom and every workflow was green:
 *
 *  - the deploy trigger did not cover every published directory, so a change there
 *    never redeployed;
 *  - branch pushes started deploys the github-pages environment always rejects;
 *  - a stray Markdown fence after </html> was rendered as text under the footer;
 *  - the desktop header showed the download button twice (a specificity tie);
 *  - on phones the web platform was wider than the screen and half of it was sticky chrome.
 */
import test from 'node:test';
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { APP_ROOT_FILES, APP_DIRS } from '../../scripts/stage-site.mjs';

const read = (path) => readFileSync(new URL(`../../${path}`, import.meta.url), 'utf8');

const workflow = read('.github/workflows/deploy-website.yml');
const marketing = read('docs/index.html');
const platform = read('index.html');

/** The `on:` block of the workflow, comments stripped. */
function triggerBlock(text) {
  const start = text.indexOf('\non:\n');
  const end = text.indexOf('\nconcurrency:', start);
  assert.ok(start !== -1 && end !== -1, 'the workflow must have an on: block followed by concurrency:');
  return text.slice(start, end).split('\n').filter((line) => !line.trim().startsWith('#')).join('\n');
}

/** The first <style> block of a page. */
function styles(html) {
  const match = /<style>([\s\S]*?)<\/style>/.exec(html);
  assert.ok(match, 'page must carry an inline stylesheet');
  return match[1];
}

test('every published file and directory triggers a redeploy', () => {
  const on = triggerBlock(workflow);
  for (const file of APP_ROOT_FILES) {
    assert.ok(on.includes(`- '${file}'`), `${file} is published under /app/ but does not trigger the deploy`);
  }
  for (const dir of APP_DIRS) {
    assert.ok(on.includes(`- '${dir}/**'`), `${dir}/ is published under /app/ but does not trigger the deploy`);
  }
  assert.ok(on.includes("- 'docs/**'"), 'the marketing site must trigger the deploy');
  assert.ok(on.includes("- 'scripts/stage-site.mjs'"), 'changing the assembler must trigger the deploy');
});

test('only main deploys to the live site', () => {
  const on = triggerBlock(workflow);
  const branches = /branches:\n((?:\s+- .+\n)+)/.exec(on);
  assert.ok(branches, 'the push trigger must list its branches');
  const listed = branches[1].trim().split('\n').map((line) => line.replace(/^\s*-\s*/, '').replace(/['"]/g, ''));
  assert.deepEqual(listed, ['main']);
});

test('the deploy reports a Pages source that would overwrite it', () => {
  assert.match(workflow, /build_type/);
  assert.match(workflow, /"legacy"/);
  assert.match(workflow, /GITHUB_STEP_SUMMARY/);
  // ...and puts the real site back after GitHub's branch build has replaced it.
  assert.match(triggerBlock(workflow), /workflow_run:\n\s+workflows: \['pages-build-deployment'\]/);
});

test('both pages end at </html> with nothing rendered after it', () => {
  for (const [name, html] of [['docs/index.html', marketing], ['index.html', platform]]) {
    assert.match(html, /<\/html>\s*$/, `${name} has content after </html>`);
    assert.ok(!html.includes('```'), `${name} contains a Markdown code fence`);
  }
});

test('the marketing header shows one download button per breakpoint', () => {
  const css = styles(marketing);
  // `.btn { display: inline-flex }` comes later in the sheet; the hide rule must out-rank it.
  assert.match(css, /\.nav \.nav-mobile-cta\s*\{\s*display:\s*none;?\s*\}/);
  assert.ok(!/(^|\n)\s*\.nav-mobile-cta\s*\{/.test(css), 'a bare .nav-mobile-cta rule loses to .btn');
  // The desktop button is hidden exactly where the menu (and its own button) takes over.
  const collapse = /@media \(max-width: (\d+)px\) \{\s*:root \{ --header-h: 66px; \}\s*\.header-cta \{ display: none; \}/.exec(css);
  assert.ok(collapse, 'the header must collapse to the menu in one media query');
  assert.ok(Number(collapse[1]) >= 1100, 'the full link row does not fit below ~1100px');
  assert.ok(marketing.includes(`window.innerWidth > ${collapse[1]} &&`),
    'the resize handler must close the menu at the same width the CSS collapses it');
});

test('marketing links to the web platform resolve inside the deployed tree', () => {
  const links = [...marketing.matchAll(/href="([^"#][^"]*)"/g)].map((m) => m[1])
    .filter((href) => !/^(https?:|data:|mailto:)/.test(href));
  assert.ok(links.length > 0);
  for (const href of links) assert.equal(href, 'app/', `unexpected relative link ${href}`);
});

test('the web platform cannot be wider than a phone screen', () => {
  const css = styles(platform);
  assert.match(css, /\.page\s*\{[^}]*grid-template-columns:\s*minmax\(0, 1fr\)/,
    'page sections must let their content shrink');
  for (const kind of ['k4', 'k3', 'k2']) {
    assert.match(css, new RegExp(`\\.grid\\.${kind}\\s*\\{[^}]*minmax\\(min\\(\\d+px, 100%\\), 1fr\\)`),
      `.grid.${kind} must cap its column minimum at the container width`);
  }
});

test('the web platform header and tabs stick as one unit', () => {
  const css = styles(platform);
  assert.match(platform, /<div class="chrome">\s*<header class="top">[\s\S]*?<\/nav>\s*<\/div>/);
  assert.match(css, /\.chrome\s*\{[^}]*position:\s*sticky/);
  // No magic header height: that offset was only right for one header height.
  assert.ok(!/top:\s*(77|69)px/.test(css), 'tabs must not be offset by a hard-coded header height');
  const phone = /@media \(max-width: 700px\) \{([\s\S]*?)\n  \}/.exec(css);
  assert.ok(phone, 'a phone breakpoint must exist');
  assert.match(phone[1], /nav\.tabs\s*\{[^}]*flex-wrap:\s*nowrap[^}]*overflow-x:\s*auto/,
    'tabs must stay on one swipeable row on phones');
});

test('the web platform draws its logo instead of relying on an emoji font', () => {
  const shield = /<div class="shield"[^>]*>([\s\S]*?)<\/div>/.exec(platform);
  assert.ok(shield);
  assert.match(shield[1], /<svg[\s\S]*<\/svg>/);
  assert.match(platform, /<link rel="icon"[^>]*href="assets\/icon\.svg"/);
});
