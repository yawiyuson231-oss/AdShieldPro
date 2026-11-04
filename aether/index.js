/**
 * OmniShield X — AETHER: the decision engine facade.
 *
 * AETHER is the platform's threat-intelligence layer. It owns:
 *   - the filter engine reference (deterministic rules → the only thing that blocks),
 *   - the reputation scorer (explainable 0-100 evidence score),
 *   - the on-device lexical classifier (trained from the bundled feeds),
 *   - the observation store (first-seen times, per-domain counters),
 *   - false-positive handling with real, reversible user feedback.
 *
 * AETHER does not silently block. Its `analyze()` output carries an advisory
 * action and full evidence; enforcement stays with the filter engine and the
 * user's explicit choices.
 */
import { OmniShieldFilterEngine } from '../engine.js';
import { ReputationEngine, SIGNAL_WEIGHTS, verdictFor } from './reputation.js';
import { DomainClassifier, precisionAtPrevalence } from './classifier.js';
import { POPULAR_DOMAINS } from './data.js';

const MAX_OBSERVATIONS = 50000;

export class Aether {
  /**
   * @param {{engine?:OmniShieldFilterEngine, classifier?:DomainClassifier,
   *          reputation?:ReputationEngine, clock?:()=>number, onEvent?:Function}} [options]
   */
  constructor(options = {}) {
    this.clock = options.clock ?? (() => Date.now());
    this.engine = options.engine ?? new OmniShieldFilterEngine();
    this.classifier = options.classifier ?? new DomainClassifier();
    this.reputation = options.reputation ?? new ReputationEngine({ classifier: this.classifier, clock: this.clock });
    this.reputation.setClassifier(this.classifier);
    this.onEvent = options.onEvent ?? null;
    /** domain -> {firstSeen, lastSeen, count, allowed, blocked} */
    this.observations = new Map();
    this.stats = {
      analyses: 0, blocksObserved: 0, falsePositivesReported: 0,
      classifierTrainings: 0, lastTrainingAt: null
    };
  }

  _emit(event) {
    if (this.onEvent) { try { this.onEvent(event); } catch { /* observers must not break analysis */ } }
  }

  attachEngine(engine) {
    this.engine = engine;
    this.reputation.cache.clear();
    return this;
  }

  /** Records an observation (used for first-seen recency and traffic history). */
  observe(domain, { blocked = false, at = this.clock() } = {}) {
    const name = OmniShieldFilterEngine.normalizeDomain(domain);
    if (!name) return null;
    let entry = this.observations.get(name);
    if (!entry) {
      entry = { firstSeen: at, lastSeen: at, count: 0, allowed: 0, blocked: 0 };
      if (this.observations.size >= MAX_OBSERVATIONS) {
        // Bounded memory: forget the least recently seen observation.
        let oldestKey = null; let oldest = Infinity;
        for (const [k, v] of this.observations) if (v.lastSeen < oldest) { oldest = v.lastSeen; oldestKey = k; }
        if (oldestKey) this.observations.delete(oldestKey);
      }
      this.observations.set(name, entry);
    }
    entry.lastSeen = at;
    entry.count++;
    if (blocked) entry.blocked++; else entry.allowed++;
    return entry;
  }

  /**
   * Full analysis for one domain.
   * @param {string} input
   * @param {{explain?:boolean}} [options]
   */
  analyze(input, options = {}) {
    const name = OmniShieldFilterEngine.normalizeDomain(input);
    if (!name) {
      return {
        domain: input, score: 0, verdict: 'invalid', action: 'allow',
        summary: 'Not a valid hostname; AETHER did not analyse it.', signals: [], guardrails: [], error: 'invalid-domain'
      };
    }
    const observation = this.observations.get(name);
    const report = this.reputation.analyze(name, {
      engine: this.engine,
      firstSeenAt: observation?.firstSeen
    });
    this.stats.analyses++;
    if (report.signals.some((s) => s.id === 'feedMatch' || s.id === 'threatFeedMatch')) this.stats.blocksObserved++;

    const verdict = this.engine.evaluate(name);
    const result = {
      ...report,
      filterVerdict: {
        blocked: verdict.blocked, source: verdict.source,
        matched: verdict.matched, category: verdict.category, reasons: verdict.reasons
      },
      enforcement: {
        // Enforcement is the engine's job; AETHER only advises.
        blocking: verdict.blocked,
        decidedBy: verdict.blocked ? verdict.source : 'no rule matched',
        advisory: report.action,
        advisoryIsEnforced: false
      },
      observation: observation ? { ...observation } : null
    };
    this._emit({ kind: 'analysis', domain: name, score: report.score, verdict: report.verdict, at: this.clock() });
    return options.explain ? result : result;
  }

  analyzeMany(domains) {
    return domains.map((d) => this.analyze(d));
  }

  /**
   * Trains the lexical classifier from the loaded feeds plus the curated list.
   * Real training, real holdout metrics — safe to call again after feed updates.
   */
  train({ positives, negatives = POPULAR_DOMAINS, maxPositives = 6000 } = {}) {
    const corpus = positives ?? [...this.engine.filterSubdomains.keys()];
    if (!corpus.length) throw new Error('cannot train: no positive samples in the loaded feeds');
    const step = Math.max(1, Math.floor(corpus.length / maxPositives));
    const sample = corpus.filter((_, i) => i % step === 0).slice(0, maxPositives);
    const metrics = this.classifier.train({ positives: sample, negatives: [...negatives], now: this.clock });
    this.reputation.setClassifier(this.classifier);
    this.stats.classifierTrainings++;
    this.stats.lastTrainingAt = new Date(this.clock()).toISOString();
    this._emit({ kind: 'training', metrics, at: this.clock() });
    return metrics;
  }

  /**
   * Marks a domain as a false positive: allowlists it (reversible) and adapts
   * the signals that fired, so the same coincidence is less likely to fire again.
   */
  reportFalsePositive(input, { allowlist = true } = {}) {
    const name = OmniShieldFilterEngine.normalizeDomain(input);
    if (!name) return { ok: false, error: 'invalid-domain' };
    const report = this.reputation.analyze(name, { engine: this.engine });
    const adaptation = this.reputation.recordFeedback(name, { falsePositive: true, report });
    let allowRuleAdded = false;
    if (allowlist) {
      allowRuleAdded = this.engine.addUserRule(`||${name}^`, true);
      this.reputation.cache.clear();
    }
    this.stats.falsePositivesReported++;
    this._emit({ kind: 'false-positive', domain: name, adaptation, allowRuleAdded, at: this.clock() });
    return {
      ok: true, domain: name, allowRuleAdded,
      adapted: adaptation.adapted,
      note: allowRuleAdded
        ? `${name} is now on your allowlist and its subdomains are no longer filtered. You can undo this from Custom rules.`
        : 'Allow rule was not added, but signal weights were adjusted.'
    };
  }

  /** Reverses a false-positive allow-rule (keeps the learned weighting). */
  undoFalsePositive(input) {
    const name = OmniShieldFilterEngine.normalizeDomain(input);
    if (!name) return false;
    const removed = this.engine.removeUserRule(`||${name}^`, true);
    this.reputation.cache.clear();
    return removed;
  }

  verdictBands() { return { verdictFor, weights: SIGNAL_WEIGHTS }; }

  snapshot() {
    const metrics = this.classifier.metrics;
    return {
      engine: this.engine.breakdown(),
      observations: this.observations.size,
      analyses: this.stats.analyses,
      falsePositivesReported: this.stats.falsePositivesReported,
      classifier: {
        trained: this.classifier.isTrained,
        metrics,
        operatingThreshold: this.classifier.operatingThreshold,
        trainings: this.stats.classifierTrainings,
        lastTrainingAt: this.stats.lastTrainingAt
      },
      reputation: this.reputation.statsSnapshot()
    };
  }

  /** State persisted in configuration backups. */
  exportState() {
    return {
      version: 1,
      reputation: this.reputation.toJSON(),
      classifier: this.classifier.toJSON(),
      observations: [...this.observations.entries()].slice(-5000).map(([domain, o]) => ({ domain, ...o }))
    };
  }

  importState(state) {
    if (!state || state.version !== 1) return { ok: false, error: 'unsupported-state-version' };
    let classifierRestored = false;
    if (state.reputation) this.reputation.loadJSON(state.reputation);
    if (state.classifier) {
      const restored = DomainClassifier.fromJSON(state.classifier);
      if (restored) {
        this.classifier = restored;
        this.reputation.setClassifier(restored);
        classifierRestored = true;
      }
    }
    if (Array.isArray(state.observations)) {
      this.observations.clear();
      for (const o of state.observations.slice(-MAX_OBSERVATIONS)) {
        if (o?.domain) this.observations.set(o.domain, {
          firstSeen: o.firstSeen, lastSeen: o.lastSeen, count: o.count || 0,
          allowed: o.allowed || 0, blocked: o.blocked || 0
        });
      }
    }
    return { ok: true, classifierRestored };
  }
}

export { ReputationEngine, DomainClassifier, SIGNAL_WEIGHTS, precisionAtPrevalence };
export default Aether;
