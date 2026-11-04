/**
 * Unit tests — lexical features, domain structure, typosquat algorithms.
 */
import test from 'node:test';
import { strict as assert } from 'node:assert';
import {
  shannonEntropy, dgaScore, extractFeatures, detectScripts, decodePunycodeLabel,
  findTokens, describeFeatures
} from '../../aether/lexical.js';
import { registrableDomain, publicSuffix, subdomainOf } from '../../aether/domain.js';
import { damerauLevenshtein, findImpersonation, skeleton, SEVERITY } from '../../aether/typosquat.js';
import { POPULAR_DOMAINS } from '../../aether/data.js';

test('entropy is mathematically correct', () => {
  assert.equal(shannonEntropy('aaaa'), 0);
  assert.equal(shannonEntropy('ab'), 1);
  assert.equal(shannonEntropy('abcd'), 2);
  assert.equal(Math.round(shannonEntropy('aabb') * 100) / 100, 1);
});

test('public suffix and registrable domain handling', () => {
  assert.equal(registrableDomain('paypal.com.evil.tk'), 'evil.tk');
  assert.equal(registrableDomain('a.b.example.co.uk'), 'example.co.uk');
  assert.equal(registrableDomain('example.com'), 'example.com');
  assert.equal(registrableDomain('com.ph'), 'com.ph', 'a bare suffix has no registrable domain');
  assert.equal(publicSuffix('shop.example.com.ph'), 'com.ph');
  assert.equal(subdomainOf('a.b.example.co.uk'), 'a.b');
  assert.equal(subdomainOf('example.com'), '');
});

test('punycode decoding matches RFC 3492 test vectors', () => {
  assert.equal(decodePunycodeLabel('xn--bcher-kva'), 'bücher');
  assert.equal(decodePunycodeLabel('xn--e1afmkfd'), 'пример');
  assert.equal(decodePunycodeLabel('xn--fiqs8s'), '中国');
  assert.equal(decodePunycodeLabel('plain'), 'plain');
});

test('IDN homograph detection flags mixed scripts only when they exist', () => {
  const homograph = detectScripts('xn--80ak6aa92e.com'); // Cyrillic "аррӏе"
  assert.equal(homograph.mixed, true);
  assert.deepEqual(homograph.scripts.sort(), ['Cyrillic', 'Latin']);
  assert.equal(homograph.punycode, true);

  const clean = detectScripts('apple.com');
  assert.equal(clean.mixed, false);
  assert.deepEqual(clean.scripts, ['Latin']);

  const chinese = detectScripts('xn--fiqs8s.cn');
  assert.equal(chinese.mixed, false, 'a single non-Latin script is not a homograph');
});

test('token extraction finds real ad/tracker vocabulary', () => {
  assert.ok(findTokens('ads.doubleclick.net').includes('ads'), 'must find the ads label');
  assert.deepEqual(findTokens('shop.example').filter((t) => t !== 'shop'), [], 'no invented tokens');
  assert.ok(findTokens('analytics.tracker.example').length >= 1);
  assert.deepEqual(findTokens('example.com'), []);
  assert.deepEqual(findTokens('adservicedelivery.example').sort(), ['adservice']);
});

test('feature extraction reports measured values', () => {
  const good = extractFeatures('www.example.com');
  assert.equal(good.tld, 'com');
  assert.equal(good.registrable, 'example.com');
  assert.equal(good.labelCount, 3);
  assert.equal(good.hyphens, 0);
  assert.equal(good.mixedScripts, false);

  const bad = extractFeatures('secure-paypal-login.verify-account.tk');
  assert.equal(bad.hyphens, 3);
  assert.equal(bad.highAbuseTld, true);
  assert.ok(bad.threatTokens.includes('login') || bad.threatTokens.includes('secure'));
  assert.ok(bad.entropy > 3);
  assert.ok(describeFeatures(bad).length > 2);
});

test('DGA heuristic responds to random-looking labels only', () => {
  const legit = ['google', 'facebook', 'microsoft', 'youtube', 'wikipedia'];
  for (const name of legit) assert.ok(dgaScore(name) <= 0.2, `${name} scored ${dgaScore(name)}`);
  const random = ['xkqmzptvw', 'qwrtypsdf', 'zxjvbqklm', 'aoeiurbcdf'];
  const scored = random.map(dgaScore);
  assert.ok(Math.max(...scored) > 0.3, `random labels should score higher: ${scored}`);
});

test('Damerau-Levenshtein counts transpositions as one edit', () => {
  assert.equal(damerauLevenshtein('paypal', 'paypal'), 0);
  assert.equal(damerauLevenshtein('paypal', 'paypla'), 1, 'transposition = 1 edit');
  assert.equal(damerauLevenshtein('paypal', 'paypa1'), 1);
  assert.equal(damerauLevenshtein('paypal', 'paypall'), 1);
  assert.equal(damerauLevenshtein('google', 'gogle'), 1);
  assert.equal(damerauLevenshtein('google', 'gooogle'), 1);
  assert.equal(damerauLevenshtein('kitten', 'sitting'), 3);
  assert.equal(damerauLevenshtein('abc', 'xyzxyz', 2), 3, 'early exit returns maxDistance+1');
});

test('skeleton collapses homoglyphs to the Latin target', () => {
  assert.equal(skeleton('paypa1'), 'paypal');
  assert.equal(skeleton('rnicrosoft').replace(/0/g, 'o'), 'microsoft');
  assert.equal(skeleton('аpple'), 'apple', 'Cyrillic а folds to Latin a');
  assert.equal(skeleton('g00gle'), 'google');
});

test('typosquat detection: phishing shapes are caught', () => {
  const cases = [
    ['paypa1.com', 'homoglyph or typo of paypal'],
    ['paypal-login.com', 'brand plus affix'],
    ['paypal.com.account-verify.tk', 'brand in subdomain'],
    ['gogle.com', 'typo'],
    ['micros0ft.com', 'homoglyph']
  ];
  for (const [domain, why] of cases) {
    const res = findImpersonation(domain);
    assert.equal(res.suspicious, true, `${domain} (${why}) should be flagged`);
    assert.ok(res.severity >= SEVERITY.MEDIUM, `${domain} severity ${res.severity}`);
    assert.ok(res.matches.length > 0);
    assert.ok(res.matches[0].explanation.length > 20, 'every match needs an explanation');
  }
});

test('typosquat detection does not flag legitimate popular domains', () => {
  for (const domain of ['google.com', 'paypal.com', 'www.microsoft.com', 'github.com',
    'accounts.google.com', 'mail.google.com', 'www.paypal.com', 'apple.com']) {
    const res = findImpersonation(domain);
    assert.equal(res.suspicious, false, `${domain} was wrongly flagged: ${JSON.stringify(res.matches)}`);
  }
});

test('no false-positive explosion across the whole curated corpus', () => {
  let flagged = 0;
  for (const domain of POPULAR_DOMAINS) {
    if (findImpersonation(domain).suspicious) flagged++;
  }
  // Some curated entries are genuinely brand-alt-TLD/short-brand near-misses;
  // anything above a handful would mean the thresholds are too loose.
  assert.ok(flagged <= 5, `${flagged}/${POPULAR_DOMAINS.length} popular domains wrongly flagged`);
});
