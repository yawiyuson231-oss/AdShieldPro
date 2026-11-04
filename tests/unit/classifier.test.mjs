/**
 * Unit + statistical tests — AETHER lexical classifier.
 *
 * The thresholds asserted here are the *measured* behaviour of the shipped
 * model. If a change makes the model worse, these tests fail — that is the
 * point. Numbers are not cosmetic: the UI displays exactly these metrics.
 */
import test from 'node:test';
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import {
  DomainClassifier, tokenizeDomain, computeAuc, classificationMetrics, mulberry32,
  precisionAtPrevalence
} from '../../aether/classifier.js';
import { POPULAR_DOMAINS } from '../../aether/data.js';
import { OmniShieldFilterEngine } from '../../engine.js';

const LITE = readFileSync(new URL('../../assets/core_lite_ads.txt', import.meta.url), 'utf8');

function samplePositives(count = 8000) {
  const engine = new OmniShieldFilterEngine();
  engine.loadFilterList(LITE, 'ADS', 'core_lite_ads');
  const all = [...engine.filterSubdomains.keys()];
  const step = Math.max(1, Math.floor(all.length / count));
  return all.filter((_, i) => i % step === 0).slice(0, count);
}

test('AUC arithmetic is correct on known cases', () => {
  assert.equal(computeAuc([0.1, 0.2, 0.8, 0.9], [0, 0, 1, 1]), 1, 'perfect separation');
  assert.equal(computeAuc([0.9, 0.8, 0.2, 0.1], [0, 0, 1, 1]), 0, 'inverted ranking');
  assert.equal(computeAuc([0.5, 0.5, 0.5, 0.5], [0, 0, 1, 1]), 0.5, 'all ties');
  assert.equal(computeAuc([0.5], [1]), null, 'single class has no AUC');
});

test('confusion-matrix metrics are computed from the counts', () => {
  const m = classificationMetrics([0.9, 0.8, 0.2, 0.1], [1, 1, 0, 1]);
  assert.equal(m.tp, 2);
  assert.equal(m.fn, 1);
  assert.equal(m.tn, 1);
  assert.equal(m.fp, 0);
  assert.equal(m.precision, 1);
  assert.equal(Math.round(m.recall * 1000) / 1000, 0.667);
  assert.equal(m.specificity, 1);
});

test('tokenizer produces bounded, labelled features', () => {
  const tokens = tokenizeDomain('ads.tracker-example.co.uk');
  assert.ok(tokens.includes('T:uk'));
  assert.ok(tokens.includes('L:tracker-example'));
  assert.ok(tokens.includes('W:tracker'));
  assert.ok(tokens.some((t) => t.startsWith('C:')));
  assert.ok(tokens.length < 60, `too many tokens: ${tokens.length}`);
  assert.deepEqual(tokenizeDomain(''), []);
  // www is stripped so it cannot dominate the model.
  assert.deepEqual(tokenizeDomain('www.a.com'), tokenizeDomain('a.com'));
});

test('seeded PRNG is reproducible', () => {
  const a = mulberry32(7); const b = mulberry32(7);
  const seqA = Array.from({ length: 5 }, () => a());
  const seqB = Array.from({ length: 5 }, () => b());
  assert.deepEqual(seqA, seqB);
  assert.ok(seqA.every((x) => x >= 0 && x < 1));
});

test('untrained classifier refuses to fake a score', () => {
  const c = new DomainClassifier();
  assert.equal(c.isTrained, false);
  const p = c.predict('example.com');
  assert.equal(p.trained, false);
  assert.equal(p.score, 0);
  assert.deepEqual(p.contributions, []);
  assert.equal(c.toJSON(), null);
});

test('training is deterministic and reports real holdout metrics', () => {
  const positives = samplePositives(6000);
  const negatives = [...POPULAR_DOMAINS];

  const a = new DomainClassifier();
  const metricsA = a.train({ positives, negatives });
  const b = new DomainClassifier();
  const metricsB = b.train({ positives, negatives });
  const withoutTiming = ({ trainMs, ...rest }) => rest;
  assert.deepEqual(withoutTiming(metricsA), withoutTiming(metricsB),
    'same seed and data must give identical metrics (timing excluded)');

  // The model must actually beat chance, and stay conservative on legit names.
  assert.ok(metricsA.auc >= 0.85, `AUC regressed to ${metricsA.auc}`);
  assert.ok(metricsA.atThreshold.precision >= 0.95, `precision regressed to ${metricsA.atThreshold.precision}`);
  assert.ok(metricsA.atThreshold.specificity >= 0.85, `specificity regressed to ${metricsA.atThreshold.specificity}`);
  assert.ok(metricsA.atThreshold.recall >= 0.6, `recall regressed to ${metricsA.atThreshold.recall}`);
  assert.equal(metricsA.fitSize + metricsA.tuneSize + metricsA.holdoutSize, 6000 + negatives.length,
    'fit, tuning and holdout splits must together account for every example (no leakage by omission)');
  assert.equal(metricsA.tuningSize, metricsA.tuneSize, 'tuning split size must be reported consistently');
  assert.equal(metricsA.atThreshold.calibratedOn, 'tuning-split',
    'the operating point must be chosen on the tuning split, never on the holdout');
  assert.notEqual(metricsA.atThreshold.threshold, 0.5,
    'a calibrated threshold must come from the sweep');
  assert.ok(metricsA.trainMs >= 0, 'training time is measured, not estimated');
  assert.equal(metricsA.featureMode, 'hybrid');
});

test('precision is reported at realistic base rates, not just the corpus ratio', () => {
  // Perfect ranking on a positive-heavy corpus produces a flattering precision.
  // Converting through recall/specificity at a realistic prevalence is honest.
  const atOnePercent = precisionAtPrevalence(0.66, 0.9, 0.01);
  const atTenPercent = precisionAtPrevalence(0.66, 0.9, 0.1);
  assert.ok(atOnePercent < 0.1, `precision at 1% base rate should be low, got ${atOnePercent}`);
  assert.ok(atTenPercent > atOnePercent, 'precision must improve as prevalence rises');
  assert.ok(precisionAtPrevalence(1, 1, 0.5) === 1, 'a perfect model is perfect at any base rate');
  assert.throws(() => precisionAtPrevalence(0.5, 0.5, 0), /prevalence/);
  assert.throws(() => precisionAtPrevalence(0.5, 0.5, 1), /prevalence/);

  const metrics = new DomainClassifier().train({ positives: samplePositives(6000), negatives: [...POPULAR_DOMAINS] });
  const at = metrics.atThreshold;
  assert.ok(at.precisionAtPrevalence, 'operating point must carry base-rate precision');
  assert.ok(at.precisionAtPrevalence[0.01] < at.precision,
    'base-rate precision must be lower than the corpus-ratio precision (honesty gate)');
  assert.ok(at.balancedAccuracy <= 1 && at.balancedAccuracy > 0.5, 'balanced accuracy must be measured');
});

test('known legitimate domains stay below the operating threshold', () => {
  const c = new DomainClassifier();
  c.train({ positives: samplePositives(6000), negatives: [...POPULAR_DOMAINS] });
  const legit = ['paypal.com', 'google.com', 'github.com', 'weather.com', 'amazon.co.uk',
    'outlook.office365.com', 'cdn.jsdelivr.net', 'bbc.co.uk'];
  const flagged = legit.filter((d) => c.predict(d).score >= c.operatingThreshold);
  assert.deepEqual(flagged, [], `false positives on known-good domains: ${flagged.join(', ')}`);
  assert.ok(c.operatingThreshold > 0.5, 'operating point must be calibrated above the naive 0.5');
});

test('ad and phishing-shaped names score high, with explainable tokens', () => {
  const c = new DomainClassifier();
  c.train({ positives: samplePositives(6000), negatives: [...POPULAR_DOMAINS] });
  for (const domain of ['ads.doubleclick.net', 'analytics.tracker.example', 'secure-paypal-login.tk']) {
    const p = c.predict(domain);
    assert.ok(p.score >= c.operatingThreshold, `${domain} scored only ${p.score}`);
    assert.ok(p.contributions.length > 0, `${domain} produced a score with no contributing tokens`);
    assert.ok(p.contributions.every((t) => typeof t.token === 'string' && 'weight' in t));
  }
});

test('model survives a JSON round-trip with identical predictions', () => {
  const c = new DomainClassifier();
  c.train({ positives: samplePositives(3000), negatives: [...POPULAR_DOMAINS] });
  const clone = DomainClassifier.fromJSON(JSON.parse(JSON.stringify(c.toJSON())));
  assert.ok(clone, 'fromJSON must accept a serialized model');
  assert.equal(clone.operatingThreshold, c.operatingThreshold);
  for (const d of ['paypal.com', 'ads.doubleclick.net', 'random.example']) {
    assert.equal(clone.predict(d).score, c.predict(d).score, `prediction drifted for ${d}`);
  }
  assert.equal(DomainClassifier.fromJSON({ version: 99 }), null, 'unknown versions are rejected');
});

test('refuses to train on an unusably small corpus', () => {
  const c = new DomainClassifier();
  assert.throws(
    () => c.train({ positives: ['a.example', 'b.example'], negatives: [...POPULAR_DOMAINS] }),
    /not enough training data/
  );
  assert.equal(c.isTrained, false);
});

test('serialized model stays within a sane size budget', () => {
  const c = new DomainClassifier();
  c.train({ positives: samplePositives(6000), negatives: [...POPULAR_DOMAINS] });
  const kb = JSON.stringify(c.toJSON()).length / 1024;
  assert.ok(kb < 900, `model is ${Math.round(kb)} KB — too large to cache in localStorage`);
});
