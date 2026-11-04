import { OmniShieldFilterEngine } from './engine.js';
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';

/**
 * OmniShield X — Web engine CI test.
 * Runs the REAL JS engine against a synthetic list and the REAL bundled assets,
 * enforcing the same compatibility guarantees as the Android CI gate:
 * ads/trackers blocked, video/auth/play domains NEVER blocked.
 */

const engine = new OmniShieldFilterEngine();

// --- Synthetic ladder checks ---
engine.loadFilterList('! test\n||doubleclick.net^\n||tracker.example^\n@@||safe.tracker.example^\n', 'ADS', 'Synthetic');
assert.equal(engine.evaluate('https://ad.doubleclick.net/pcm?x=1').blocked, true);
assert.equal(engine.evaluate('http://www.doubleclick.net:8080/path').blocked, true);
assert.equal(engine.evaluate('safe.tracker.example').blocked, false);
assert.equal(engine.evaluate('safe.tracker.example').source, 'List Exception');
assert.equal(engine.evaluate('connectivitycheck.gstatic.com').source, 'System Safety Allowlist');
assert.equal(engine.evaluate('not-blocked.example.org').blocked, false);

// Normalization: scheme, creds, port, path, www, uppercase
assert.equal(OmniShieldFilterEngine.normalizeDomain('HTTPS://User:Pass@WWW.DoubleClick.NET:443/adx/test?q=1'), 'doubleclick.net');

// User rules outrank lists (allow wins)
engine.addUserRule('||tracker.example^', true);
assert.equal(engine.evaluate('sub.tracker.example').blocked, false);
assert.equal(engine.evaluate('sub.tracker.example').source, 'User Allowlist');

// --- Real bundled production lists (same files as the Android APK) ---
const lite = readFileSync(new URL('../app/src/main/assets/core_lite_ads.txt', import.meta.url), 'utf8');
engine.loadFilterList(lite, 'ADS', 'core_lite_ads');

const mustWork = [
  'www.youtube.com', 'r1---sn-ab5l6ne7.googlevideo.com', 'i.ytimg.com',
  'www.netflix.com', 'www.tiktok.com', 'www.facebook.com', 'www.instagram.com',
  'accounts.google.com', 'play.google.com', 'www.paypal.com', 'aena.ms',
  'web.whatsapp.com', 'discord.com'
];
for (const host of mustWork) {
  const v = engine.evaluate(host);
  assert.equal(v.blocked, false, `COMPATIBILITY BREAK: ${host} blocked via ${v.source}`);
}

const mustBlock = ['doubleclick.net', 'adnxs.com', 'scorecardresearch.com'];
let protectionOk = 0;
for (const host of mustBlock) {
  if (engine.evaluate(host).blocked) protectionOk++;
}
assert.ok(protectionOk >= 2, `Protection regression: only ${protectionOk}/3 classic ad domains blocked in lite list`);

console.log(`Web engine OK: ${engine.totalRules()} rules from real assets, ${engine.stats.duplicates} dups, ${engine.stats.wildcards} wildcards (reported, not evaluated)`);
console.log(`Compatibility: all ${mustWork.length} must-work domains pass; protection ${protectionOk}/${mustBlock.length} verified`);
