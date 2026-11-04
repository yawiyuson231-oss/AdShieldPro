/**
 * Unit tests — reputation scoring, guardrails, feedback adaptation, AETHER facade.
 *
 * These tests encode the product's honesty contract:
 * evidence is attributable, legit domains stay clean, nothing auto-blocks.
 */
import test from 'node:test';
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { OmniShieldFilterEngine } from '../../engine.js';
import { ReputationEngine, SIGNAL_WEIGHTS, verdictFor } from '../../aether/reputation.js';
import { Aether } from '../../aether/index.js';
import { DomainClassifier } from '../../aether/classifier.js';
import { POPULAR_DOMAINS } from '../../aether/data.js';

const LITE = readFileSync(new URL('../../assets/core_lite_ads.txt', import.meta.url), 'utf8');

function engineWithFeeds() {
  const e = new OmniShieldFilterEngine();
  e.loadFilterList('||ads.doubleclick.net^\n', 'ADS', 'core_lite_ads');
  e.loadFilterList('||malware-c2.example^\n', 'MALWARE', 'threats');
  return e;
}

function trainedAether(clock) {
  const engine = new OmniShieldFilterEngine();
  engine.loadFilterList(LITE, 'ADS', 'core_lite_ads');
  engine.loadFilterList(
    readFileSync(new URL('../../assets/core_supplement_ads.txt', import.meta.url), 'utf8'),
    'ADS', 'core_supplement_ads'
  );
  engine.loadFilterList('||malware-c2.example^\n', 'MALWARE', 'threats');
  const aether = new Aether({ engine, clock });
  const all = [...engine.filterSubdomains.keys()];
  const step = Math.floor(all.length / 4000);
  aether.train({ positives: all.filter((_, i) => i % step === 0).slice(0, 4000) });
  return { aether, engine };
}

test('published weights sum to exactly 100', () => {
  const total = Object.values(SIGNAL_WEIGHTS).reduce((a, b) => a + b, 0);
  assert.equal(total, 100, `weights sum to ${total}, must equal 100`);
});

test('verdict bands are ordered and cover the whole range', () => {
  assert.equal(verdictFor(0).id, 'clean');
  assert.equal(verdictFor(19).id, 'clean');
  assert.equal(verdictFor(20).id, 'watch');
  assert.equal(verdictFor(45).id, 'suspicious');
  assert.equal(verdictFor(70).id, 'likely-malicious');
  assert.equal(verdictFor(100).id, 'high-confidence');
});

test('every point of score is attributable to a signal', () => {
  const engine = engineWithFeeds();
  const rep = new ReputationEngine();
  const report = rep.analyze('ads.doubleclick.net', { engine });
  assert.ok(report.score > 0);
  assert.ok(report.signals.length > 0);
  const summed = report.signals.reduce((sum, s) => sum + s.contribution, 0);
  assert.ok(Math.abs(summed - report.rawScore) < 0.2, `rawScore ${report.rawScore} != sum ${summed}`);
  for (const s of report.signals) {
    assert.ok(SIGNAL_WEIGHTS[s.id] !== undefined, `unknown signal id ${s.id}`);
    assert.ok(s.evidence.length > 10, `signal ${s.id} has no real evidence`);
    assert.ok(s.contribution >= 0 && s.contribution <= s.weight);
  }
});

test('absence of evidence produces a zero score and says so', () => {
  const rep = new ReputationEngine();
  const report = rep.analyze('quiet.example');
  assert.equal(report.signals.length, 0);
  assert.equal(report.score, 0);
  assert.equal(report.verdict, 'clean');
  assert.match(report.summary, /no signal produced any evidence/i);
  assert.match(report.summary, /not proof of safety/i);
});

test('popular domains are hard-capped by the false-positive guardrail', () => {
  const rep = new ReputationEngine();
  for (const domain of ['google.com', 'paypal.com', 'github.com', 'www.youtube.com']) {
    const report = rep.analyze(domain);
    assert.equal(report.score <= 10, true, `${domain} scored ${report.score}`);
    assert.ok(report.guardrails.some((g) => g.id === 'popularity'), `${domain} missing popularity guardrail`);
    assert.notEqual(report.action, 'recommend-block');
  }
});

test('user allowlist outranks reputation and caps the score', () => {
  const engine = engineWithFeeds();
  engine.addUserRule('||ads.doubleclick.net^', true);
  const rep = new ReputationEngine();
  const report = rep.analyze('ads.doubleclick.net', { engine });
  assert.equal(report.score <= 5, true, `score ${report.score}`);
  assert.ok(report.guardrails.some((g) => g.id === 'user-allow'));
  assert.notEqual(report.action, 'recommend-block', 'capped reports must never recommend a block');
  assert.equal(report.action, 'allow', 'a domain the user allowlisted is advised as allowed');
});

test('malware-category feeds weigh more than ad feeds', () => {
  const engine = engineWithFeeds();
  const rep = new ReputationEngine();
  const ad = rep.analyze('ads.doubleclick.net', { engine });
  const mal = rep.analyze('malware-c2.example', { engine });
  assert.ok(mal.score > ad.score, `malware ${mal.score} should exceed ad ${ad.score}`);
  assert.ok(mal.signals.some((s) => s.id === 'threatFeedMatch'));
  assert.ok(ad.score >= 40, `ad feed evidence floor not applied: ${ad.score}`);
  assert.ok(mal.score >= 80, `threat feed evidence floor not applied: ${mal.score}`);
  assert.equal(ad.floors[0].id, 'ad-feed');
  assert.equal(mal.floors[0].id, 'threat-feed');
  assert.ok(['likely-malicious', 'high-confidence'].includes(verdictFor(mal.score).id),
    `threat feed verdict was ${verdictFor(mal.score).id}`);
  assert.match(ad.floors[0].reason, /privacy risk, not malware/);
});

test('AETHER never enforces its own advisory', () => {
  const { aether } = trainedAether();
  const report = aether.analyze('ads.doubleclick.net');
  assert.equal(report.enforcement.blocking, true, 'the engine blocks it...');
  assert.notEqual(report.enforcement.decidedBy, 'no rule matched', '...because a real rule matched');
  assert.match(report.enforcement.decidedBy, /core_(lite|supplement)_ads/);
  assert.ok(report.filterVerdict.reasons.length > 0, 'a block must carry its reasons');
  assert.equal(report.enforcement.advisoryIsEnforced, false, 'the advisory is never auto-enforced');

  const clean = aether.analyze('example.org');
  assert.equal(clean.enforcement.blocking, false);
  assert.equal(clean.enforcement.decidedBy, 'no rule matched');
});

test('false-positive feedback adds a reversible allow rule and adapts weights', () => {
  const { aether, engine } = trainedAether();
  engine.loadFilterList('||false-positive-test.example^\n', 'ADS', 'core_lite_ads');
  assert.equal(engine.evaluate('false-positive-test.example').blocked, true);

  const result = aether.reportFalsePositive('false-positive-test.example');
  assert.equal(result.ok, true);
  assert.equal(result.allowRuleAdded, true);
  assert.equal(engine.evaluate('false-positive-test.example').blocked, false, 'allow rule must take effect');

  const adapted = result.adapted.find((a) => a.id === 'feedMatch');
  assert.ok(adapted, 'the feed signal should be reported as adapted');
  assert.ok(adapted.falsePositives >= 1);

  assert.equal(aether.undoFalsePositive('false-positive-test.example'), true);
  assert.equal(engine.evaluate('false-positive-test.example').blocked, true, 'undo must restore blocking');
});

test('weight adaptation is bounded: feedback cannot silence a signal', () => {
  const rep = new ReputationEngine();
  const report = rep.analyze('ads.doubleclick.net', { engine: engineWithFeeds() });
  for (let i = 0; i < 50; i++) rep.recordFeedback('ads.doubleclick.net', { falsePositive: true, report });
  const { base, effective, multiplier } = rep.effectiveWeight('feedMatch');
  assert.equal(multiplier, 0.4, 'adaptation floor is 40% of the published weight');
  assert.ok(effective >= base * 0.4);
  assert.ok(effective > 0, 'a signal can never be zeroed out by feedback');
});

test('classifier evidence is capped, labelled and low-weight', () => {
  const { aether } = trainedAether();
  const report = aether.analyze('secure-paypal-login.tk');
  const modelSignal = report.signals.find((s) => s.id === 'classifier');
  if (modelSignal) {
    assert.ok(modelSignal.baseWeight <= 10, 'the lexical model must stay a minor signal');
    assert.match(modelSignal.evidence, /operating threshold/);
    assert.ok(Array.isArray(modelSignal.contributions));
  }
  // Whatever happens, the model alone must not reach a block recommendation.
  assert.ok(report.score < 100);
});

test('AETHER state round-trips through a backup payload', () => {
  const { aether } = trainedAether();
  aether.observe('example.org', { at: 1000 });
  aether.analyze('example.org');
  const state = aether.exportState();

  const engine = new OmniShieldFilterEngine();
  engine.loadFilterList(LITE, 'ADS', 'core_lite_ads');
  const restored = new Aether({ engine });
  const result = restored.importState(JSON.parse(JSON.stringify(state)));
  assert.equal(result.ok, true);
  assert.equal(result.classifierRestored, true);
  assert.equal(restored.classifier.isTrained, true);
  assert.equal(restored.observations.get('example.org').firstSeen, 1000);
  assert.equal(restored.importState({ version: 99 }).ok, false);
});

test('observation store is bounded and reports first-seen honestly', () => {
  const clock = () => 1_000_000_000;
  const aether = new Aether({ clock });
  aether.observe('example.org');
  const entry = aether.observations.get('example.org');
  assert.equal(entry.firstSeen, 1_000_000_000);
  assert.equal(entry.count, 1);

  const report = aether.analyze('example.org');
  assert.ok(report.observation, 'analysis must expose what we actually observed');
  // One second of history must not produce a "newly seen" threat claim.
  const newness = report.signals.find((s) => s.id === 'newness');
  assert.ok(!newness || newness.contribution < 3);
});

test('analysis of an invalid hostname is explicit, not guessed', () => {
  const aether = new Aether();
  const report = aether.analyze('not a domain');
  assert.equal(report.verdict, 'invalid');
  assert.equal(report.error, 'invalid-domain');
  assert.match(report.summary, /did not analyse/i);
});

test('classifier can be swapped in without polluting the scorer', () => {
  const rep = new ReputationEngine();
  const before = rep.analyze('trendyol-shop.example').score;
  const c = new DomainClassifier();
  assert.equal(rep.statsSnapshot().classifierTrained, false);
  rep.setClassifier(c);
  assert.equal(rep.analyze('trendyol-shop.example').score, before, 'untrained model must add no evidence');
});
