/**
 * OmniShield X — AETHER domain reputation scoring.
 *
 * DESIGN RULES (these are the product's honesty contract)
 * ------------------------------------------------------
 *  1. Every point of score is attributable to a named signal with evidence.
 *  2. Weights are explicit, published and sum to 100 — no black box.
 *  3. The score NEVER blocks anything on its own. Safe default is allow+monitor;
 *     only the deterministic filter engine can block, and only on a real rule.
 *  4. False-positive guardrails (popularity, user allowlist, feed exception)
 *     hard-cap the score, so a legit domain can never be driven to "malicious"
 *     by lexical coincidences.
 *  5. User feedback on false positives shrinks the offending signal's weight,
 *     bounded so a signal can never be tuned to zero and evidence can never be
 *     fully silenced.
 */
import { POPULAR_SET, HIGH_ABUSE_TLDS } from './data.js';
import { extractFeatures, describeFeatures } from './lexical.js';
import { findImpersonation, SEVERITY } from './typosquat.js';
import { registrableDomain } from './domain.js';

/**
 * Base weights. They sum to exactly 100 (asserted by the test suite).
 *
 * Rationale: crowd-reviewed threat feeds are the strongest evidence available,
 * so they carry the most weight; heuristics are deliberately small so no single
 * lexical coincidence can drive a verdict.
 */
export const SIGNAL_WEIGHTS = Object.freeze({
  threatFeedMatch: 38,
  feedMatch: 18,
  typosquat: 16,
  classifier: 7,
  homoglyph: 6,
  threatTokens: 6,
  dga: 3,
  lexical: 2,
  highAbuseTld: 2,
  altTld: 1,
  newness: 1
});

/**
 * Evidence floors. Some evidence is stronger than any weighted sum of weak
 * signals, so a confirmed feed match establishes a minimum score:
 *
 *   - malware/phishing feed  -> 80 ("high confidence"): these lists are curated
 *     and false positives are rare, and the user can still allowlist.
 *   - ad/tracker feed        -> 40: confirmed monitoring/advertising
 *     infrastructure, which is a privacy issue, not a security incident.
 *
 * Floors are published here, shown in the UI, and overridden by guardrails.
 */
export const EVIDENCE_FLOORS = Object.freeze({
  threatFeed: { score: 80, reason: 'Domain is listed in a curated malware/phishing threat feed.' },
  adFeed: { score: 40, reason: 'Domain is listed in a curated advertising/tracking feed. This is a privacy risk, not malware.' },
  homoglyphImpersonation: {
    score: 55,
    reason: 'The registrable name is a look-alike spelling of a well-known brand (homoglyph/substitution).'
  },
  brandInForeignDomain: {
    score: 55,
    reason: "A well-known brand appears in the subdomain of a registrable domain that brand does not own."
  },
  brandAffix: {
    score: 45,
    reason: 'The registrable name combines a well-known brand with an account-security word.'
  },
  typosquatNearMiss: {
    score: 30,
    reason: 'The registrable name is one edit away from a well-known brand. That is a common squatting pattern, but also a plausible independent registration — treat as "unusual", not proven malicious.'
  }
});

export const SIGNAL_LABELS = Object.freeze({
  feedMatch: 'Listed in an ad/tracker feed',
  threatFeedMatch: 'Listed in a malware/phishing feed',
  typosquat: 'Typosquat of a well-known brand',
  classifier: 'Lexical model flags advertising/malware naming style',
  homoglyph: 'Look-alike (homograph) characters',
  dga: 'Generated-looking label (DGA heuristic)',
  lexical: 'Suspicious hostname structure',
  threatTokens: 'Credential/malware vocabulary in the name',
  highAbuseTld: 'High-abuse top-level domain',
  altTld: 'Brand name on a different TLD',
  newness: 'Domain first seen very recently'
});

export const VERDICTS = Object.freeze([
  { min: 90, id: 'high-confidence', label: 'High confidence threat', action: 'recommend-block' },
  { min: 70, id: 'likely-malicious', label: 'Likely malicious', action: 'recommend-block' },
  { min: 45, id: 'suspicious', label: 'Suspicious', action: 'monitor' },
  { min: 20, id: 'watch', label: 'Unusual', action: 'monitor' },
  // Any non-zero score means *something* fired, so the label must not claim
  // "no evidence" (it previously did for scores 1-19, contradicting itself).
  { min: 1, id: 'minimal', label: 'Minimal evidence', action: 'allow' },
  { min: 0, id: 'clean', label: 'No evidence of risk', action: 'allow' }
]);

export function verdictFor(score) {
  return VERDICTS.find((v) => score >= v.min) ?? VERDICTS[VERDICTS.length - 1];
}

const THREAT_CATEGORIES = new Set(['MALWARE', 'PHISHING', 'THREAT', 'FRAUD', 'CRYPTO', 'SCAM', 'BOTNET', 'C2']);

export class ReputationEngine {
  /**
   * @param {{classifier?:object, clock?:()=>number, weights?:object}} [options]
   */
  constructor(options = {}) {
    this.classifier = options.classifier ?? null;
    this.clock = options.clock ?? (() => Date.now());
    this.weights = { ...SIGNAL_WEIGHTS, ...(options.weights || {}) };
    /** False-positive counts per signal, used to shrink noisy signals. */
    this.feedback = {};
    for (const id of Object.keys(this.weights)) this.feedback[id] = { falsePositives: 0, confirmations: 0 };
    this.cache = new Map();
    this.cacheLimit = options.cacheLimit ?? 2000;
    this.stats = { analysed: 0, byVerdict: {}, feedbackEvents: 0 };
  }

  setClassifier(classifier) { this.classifier = classifier; this.cache.clear(); }

  /**
   * Effective weight after feedback adaptation, bounded to [40%, 100%] of base.
   * A signal can lose confidence, but never be switched off by a few clicks.
   */
  effectiveWeight(id) {
    const base = this.weights[id] ?? 0;
    const f = this.feedback[id] || { falsePositives: 0, confirmations: 0 };
    const total = f.falsePositives + f.confirmations;
    if (total < 3) return { base, effective: base, multiplier: 1 };
    const errorRate = f.falsePositives / total;
    const multiplier = Math.max(0.4, 1 - errorRate * 0.6);
    return { base, effective: base * multiplier, multiplier: Math.round(multiplier * 100) / 100 };
  }

  /**
   * Full reputation analysis.
   *
   * @param {string} domain normalized hostname
   * @param {{engine?:object, firstSeenAt?:number, now?:number, allowlist?:Iterable<string>}} [context]
   */
  analyze(domain, context = {}) {
    const name = String(domain || '').toLowerCase();
    const cacheKey = `${name}|${context.engine ? context.engine._generation : 0}|${this.classifier?.operatingThreshold ?? ''}`;
    if (this.cache.has(cacheKey)) {
      const cached = this.cache.get(cacheKey);
      return { ...cached, cached: true };
    }

    const signals = [];
    const features = extractFeatures(name);

    // ---- Guardrails first: they can cap the final score ---------------
    const guardrails = [];
    const registrable = registrableDomain(name);
    if (POPULAR_SET.has(name) || POPULAR_SET.has(registrable)) {
      guardrails.push({
        id: 'popularity',
        label: 'Curated popular domain',
        detail: `${POPULAR_SET.has(name) ? name : registrable} is on the curated popular-domain list, which exists specifically to prevent false positives.`
      });
    }

    let feedVerdict = null;
    if (context.engine) {
      feedVerdict = context.engine.evaluate(name);
      if (feedVerdict.source === 'User Allowlist') {
        guardrails.push({ id: 'user-allow', label: 'User allowlist', detail: 'You explicitly allowed this domain; reputation cannot override that.' });
      } else if (feedVerdict.source === 'List Exception') {
        guardrails.push({ id: 'feed-exception', label: 'Feed exception', detail: 'The upstream feed explicitly exempts this domain.' });
      } else if (feedVerdict.source === 'System Safety Allowlist') {
        guardrails.push({ id: 'system-allow', label: 'System safety allowlist', detail: 'Required for network connectivity checks.' });
      }
    }

    const add = (id, strength, evidence, extra = {}) => {
      const { base, effective, multiplier } = this.effectiveWeight(id);
      const contribution = Math.round(effective * clamp01(strength) * 10) / 10;
      signals.push({
        id, label: SIGNAL_LABELS[id], baseWeight: base, weight: Math.round(effective * 10) / 10,
        weightMultiplier: multiplier, strength: Math.round(clamp01(strength) * 100) / 100,
        contribution, evidence, ...extra
      });
    };

    // ---- Feed evidence -------------------------------------------------
    let matchedThreatFeed = false;
    let matchedAdFeed = false;
    if (feedVerdict?.blocked && !['User Allowlist', 'List Exception', 'System Safety Allowlist'].includes(feedVerdict.source)) {
      const isThreat = THREAT_CATEGORIES.has(String(feedVerdict.category || '').toUpperCase());
      if (isThreat) matchedThreatFeed = true; else matchedAdFeed = true;
      add(isThreat ? 'threatFeedMatch' : 'feedMatch', 1,
        `Rule "${feedVerdict.matched}" in ${feedVerdict.source} (category ${feedVerdict.category || 'unspecified'}).`,
        { matched: feedVerdict.matched, category: feedVerdict.category, source: feedVerdict.source });
    }

    // ---- Typosquat ------------------------------------------------------
    const squat = findImpersonation(name);
    let impersonationKind = null;
    if (squat.matches.length) {
      const strongest = squat.matches[0];
      impersonationKind = strongest.kind;
      add('typosquat', strongest.severity / SEVERITY.HIGH,
        strongest.explanation, { matches: squat.matches.slice(0, 3) });
      if (strongest.kind === 'homoglyph') {
        add('homoglyph', 1, `Look-alike characters detected in "${features.mainLabel}".`);
      }
      if (strongest.kind === 'brand-alt-tld') {
        add('altTld', 1, strongest.explanation);
      }
    }

    // ---- Lexical model --------------------------------------------------
    if (this.classifier?.isTrained) {
      const prediction = this.classifier.predict(name);
      const threshold = this.classifier.operatingThreshold ?? 0.9;
      if (prediction.score >= threshold) {
        // Strength scales with how far past the calibrated threshold it sits.
        const strength = clamp01((prediction.score - threshold) / Math.max(0.001, 1 - threshold));
        // Token weights travel in `contributions` and are rendered once by the UI;
        // repeating them in the prose produced a duplicated, noisy line.
        add('classifier', strength,
          `Lexical model score ${prediction.score.toFixed(3)} is at or above the calibrated threshold ${threshold}. This is a naming-style signal only: it cannot see page content, certificates or traffic.`,
          { modelScore: prediction.score, threshold, contributions: prediction.contributions.slice(0, 5) });
      }
    }

    // ---- Structural heuristics -----------------------------------------
    if (features.dgaScore >= 0.5) {
      add('dga', (features.dgaScore - 0.4) / 0.6,
        `Generator-like label "${features.mainLabel}" (heuristic score ${features.dgaScore}).`);
    }
    const structural = describeFeatures(features);
    if (structural.length) {
      add('lexical', Math.min(1, structural.length / 4), structural.join('; ') + '.');
    }
    if (features.threatTokens.length) {
      add('threatTokens', Math.min(1, features.threatTokens.length / 2),
        `Name contains account-security vocabulary: ${features.threatTokens.join(', ')}.`);
    }
    if (features.highAbuseTld) {
      add('highAbuseTld', 0.6,
        `.${features.tld} is frequently abused according to public reporting — a weak signal only, many legitimate services use it.`);
    }

    // ---- Recency --------------------------------------------------------
    if (Number.isFinite(context.firstSeenAt)) {
      const ageHours = (this.clock() - context.firstSeenAt) / 36e5;
      if (ageHours >= 0 && ageHours < 24) {
        add('newness', 1 - ageHours / 24,
          `First observed by OmniShield X ${ageHours.toFixed(1)}h ago. Recency is not evidence of malice by itself.`);
      }
    }

    // ---- Aggregate ------------------------------------------------------
    let rawScore = signals.reduce((sum, s) => sum + s.contribution, 0);
    rawScore = Math.min(100, Math.round(rawScore * 10) / 10);

    const floors = [];
    if (matchedThreatFeed) floors.push({ id: 'threat-feed', ...EVIDENCE_FLOORS.threatFeed });
    if (matchedAdFeed) floors.push({ id: 'ad-feed', ...EVIDENCE_FLOORS.adFeed });
    if (impersonationKind === 'homoglyph') floors.push({ id: 'homoglyph-impersonation', ...EVIDENCE_FLOORS.homoglyphImpersonation });
    if (impersonationKind === 'brand-in-subdomain') floors.push({ id: 'brand-in-foreign-domain', ...EVIDENCE_FLOORS.brandInForeignDomain });
    if (impersonationKind === 'brand-affix') floors.push({ id: 'brand-affix', ...EVIDENCE_FLOORS.brandAffix });
    if (impersonationKind === 'typosquat' || impersonationKind === 'keyboard-typo') {
      floors.push({ id: 'typosquat-near-miss', ...EVIDENCE_FLOORS.typosquatNearMiss });
    }

    let score = rawScore;
    for (const floor of floors) score = Math.max(score, floor.score);
    score = Math.round(score * 10) / 10;

    let capped = false;
    if (guardrails.length) {
      const cap = guardrails.some((g) => g.id === 'user-allow') ? 5 : 10;
      if (score > cap) { score = cap; capped = true; }
    }
    const verdict = verdictFor(score);
    const report = {
      domain: name,
      registrable,
      score,
      rawScore,
      capped,
      verdict: verdict.id,
      verdictLabel: verdict.label,
      action: guardrails.length && verdict.action === 'recommend-block' ? 'monitor' : verdict.action,
      signals,
      guardrails,
      floors,
      features,
      evidenceCount: signals.length,
      summary: buildSummary({ score, verdict, signals, guardrails, floors, capped, rawScore }),
      analysedAt: new Date(this.clock()).toISOString()
    };

    this.stats.analysed++;
    this.stats.byVerdict[verdict.id] = (this.stats.byVerdict[verdict.id] || 0) + 1;

    if (this.cache.size >= this.cacheLimit) this.cache.delete(this.cache.keys().next().value);
    this.cache.set(cacheKey, report);
    return report;
  }

  /**
   * Records user feedback and adapts signal weights.
   * @param {string} domain
   * @param {{falsePositive:boolean, report?:object}} input
   */
  recordFeedback(domain, { falsePositive = true, report = null } = {}) {
    const target = report ?? this.cache.get([...this.cache.keys()].find((k) => k.startsWith(`${domain}|`)));
    this.stats.feedbackEvents++;
    if (!target?.signals?.length) {
      return { adapted: [], reason: 'No signal evidence recorded for this domain; nothing to adapt.' };
    }
    const adapted = [];
    for (const signal of target.signals) {
      const entry = this.feedback[signal.id];
      if (!entry) continue;
      if (falsePositive) entry.falsePositives++;
      else entry.confirmations++;
      const { base, effective, multiplier } = this.effectiveWeight(signal.id);
      adapted.push({ id: signal.id, falsePositives: entry.falsePositives, confirmations: entry.confirmations, base, effective: Math.round(effective * 10) / 10, multiplier });
    }
    this.cache.clear();
    return { adapted, reason: falsePositive ? 'Signal weights reduced for the signals that fired.' : 'Signal weights reinforced.' };
  }

  statsSnapshot() {
    return {
      ...this.stats,
      feedback: JSON.parse(JSON.stringify(this.feedback)),
      weights: Object.fromEntries(Object.keys(this.weights).map((id) => [id, this.effectiveWeight(id)])),
      cacheSize: this.cache.size,
      classifierTrained: !!this.classifier?.isTrained,
      classifierMetrics: this.classifier?.metrics ?? null
    };
  }

  toJSON() {
    return { version: 1, weights: this.weights, feedback: this.feedback, stats: this.stats };
  }

  loadJSON(json) {
    if (!json || json.version !== 1) return false;
    if (json.weights) this.weights = { ...this.weights, ...json.weights };
    if (json.feedback) {
      for (const [id, v] of Object.entries(json.feedback)) {
        this.feedback[id] = { falsePositives: v.falsePositives || 0, confirmations: v.confirmations || 0 };
      }
    }
    if (json.stats) this.stats = { ...this.stats, ...json.stats };
    this.cache.clear();
    return true;
  }
}

function clamp01(x) {
  if (!Number.isFinite(x)) return 0;
  return Math.min(1, Math.max(0, x));
}

function buildSummary({ score, verdict, signals, guardrails, floors, capped, rawScore }) {
  if (guardrails.length) {
    const g = guardrails[0];
    return `Score ${score}/100 (${verdict.label}). Guardrail applied: ${g.label}. ${capped ? `Raw heuristic score ${rawScore} was capped to prevent a false positive.` : ''}`.trim();
  }
  if (floors.length) {
    const f = floors[0];
    return `Score ${score}/100 (${verdict.label}). ${f.reason} Weighted heuristics alone produced ${rawScore}.`;
  }
  if (!signals.length) {
    return `Score 0/100: no signal produced any evidence for this domain. Absence of evidence is not proof of safety.`;
  }
  const top = [...signals].sort((a, b) => b.contribution - a.contribution).slice(0, 2)
    .map((s) => `${s.label.toLowerCase()} (+${s.contribution})`);
  return `Score ${score}/100 (${verdict.label}) based on ${signals.length} signal${signals.length === 1 ? '' : 's'}; largest contributors: ${top.join(' and ')}.`;
}

export default ReputationEngine;
