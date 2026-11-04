/**
 * OmniShield X — AETHER lexical classifier (trained on-device).
 *
 * WHAT THIS IS
 * ------------
 * A multinomial Naive Bayes classifier over character trigrams of the hostname.
 * It is trained at runtime from two labelled sets that ship with the platform:
 *
 *   positives — domains from the bundled ad/tracker/malware feeds
 *   negatives — the curated popular-domain list
 *
 * Training is deterministic (seeded shuffle), split into train/holdout, and the
 * holdout metrics (precision, recall, F1, AUC, confusion matrix) are computed
 * with real arithmetic and displayed in the UI. If the model is weak, the UI
 * says it is weak, and its reputation weight is deliberately small (~10%).
 *
 * WHAT THIS IS NOT
 * ----------------
 * Not a neural network, not a cloud model, not a malware detector. It only sees
 * the characters of a domain name. It cannot see page content, certificates,
 * WHOIS records or traffic. Those limitations are listed in docs/UNSUPPORTED.md
 * and repeated in the UI.
 */

const BOUNDARY_START = '^';
const BOUNDARY_END = '$';

/** Deterministic PRNG (mulberry32) so splits and metrics are reproducible. */
export function mulberry32(seed) {
  let a = seed >>> 0;
  return function random() {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Tokenizes a hostname.
 *
 * Hybrid feature set (chosen by measurement — see docs/AETHER.md):
 *   T:<tld>          top-level domain as a categorical token
 *   L:<label>        whole labels
 *   W:<word>         hyphen/dot-separated words
 *   C:<trigram>      character trigrams with ^/$ boundary markers
 *
 * Whole-label and word tokens carry most of the signal; trigrams keep the model
 * useful for names it has never seen. Both are *lexical only* — the classifier
 * never sees anything except the string.
 */
export function tokenizeDomain(domain, mode = 'hybrid') {
  const name = String(domain || '').toLowerCase().replace(/^www\./, '');
  if (!name) return [];
  const tokens = [];
  if (mode === 'trigram') {
    const padded = `${BOUNDARY_START}${name}${BOUNDARY_END}`;
    for (let i = 0; i + 3 <= padded.length; i++) tokens.push(padded.slice(i, i + 3));
    return tokens;
  }
  const labels = name.split('.').filter(Boolean);
  tokens.push(`T:${labels[labels.length - 1]}`);
  for (const label of labels) {
    tokens.push(`L:${label}`);
    for (const word of label.split('-')) {
      if (word) tokens.push(`W:${word}`);
    }
  }
  if (mode === 'hybrid') {
    const padded = `${BOUNDARY_START}${name}${BOUNDARY_END}`;
    for (let i = 0; i + 3 <= padded.length; i++) tokens.push(`C:${padded.slice(i, i + 3)}`);
  }
  return tokens;
}

function sigmoid(x) {
  if (x >= 0) return 1 / (1 + Math.exp(-x));
  const e = Math.exp(x);
  return e / (1 + e);
}

/** Area under the ROC curve with tie handling (Mann–Whitney U). */
export function computeAuc(scores, labels) {
  const pairs = scores.map((s, i) => ({ s, y: labels[i] })).sort((a, b) => a.s - b.s);
  const nPos = labels.filter((y) => y === 1).length;
  const nNeg = labels.length - nPos;
  if (!nPos || !nNeg) return null;
  let rankSum = 0;
  let i = 0;
  while (i < pairs.length) {
    let j = i;
    while (j + 1 < pairs.length && pairs[j + 1].s === pairs[i].s) j++;
    const avgRank = (i + j + 2) / 2; // 1-based average rank for ties
    for (let k = i; k <= j; k++) if (pairs[k].y === 1) rankSum += avgRank;
    i = j + 1;
  }
  return (rankSum - (nPos * (nPos + 1)) / 2) / (nPos * nNeg);
}

export function classificationMetrics(scores, labels, threshold = 0.5) {
  let tp = 0; let fp = 0; let tn = 0; let fn = 0;
  for (let i = 0; i < scores.length; i++) {
    const predicted = scores[i] >= threshold ? 1 : 0;
    if (predicted === 1 && labels[i] === 1) tp++;
    else if (predicted === 1 && labels[i] === 0) fp++;
    else if (predicted === 0 && labels[i] === 0) tn++;
    else fn++;
  }
  const precision = tp + fp === 0 ? 0 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 0 : tp / (tp + fn);
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  const accuracy = scores.length ? (tp + tn) / scores.length : 0;
  return {
    threshold, tp, fp, tn, fn,
    precision: round4(precision),
    recall: round4(recall),
    f1: round4(f1),
    accuracy: round4(accuracy),
    specificity: round4(tn + fp === 0 ? 0 : tn / (tn + fp)),
    positives: tp + fn,
    negatives: tn + fp
  };
}

function round4(x) { return Math.round(x * 10000) / 10000; }

export class DomainClassifier {
  /**
   * @param {{alpha?:number, maxFeatures?:number, seed?:number, minTokenCount?:number}} [options]
   */
  constructor(options = {}) {
    this.alpha = options.alpha ?? 0.1;
    this.maxFeatures = options.maxFeatures ?? 25000;
    this.seed = options.seed ?? 1337;
    this.minTokenCount = options.minTokenCount ?? 2;
    this.featureMode = options.featureMode ?? 'hybrid';
    /** Presence (Bernoulli-style) counting resists keyword stuffing. */
    this.binary = options.binary ?? true;
    /** Equal class priors: the score is symmetric, not skewed by corpus size. */
    this.balancedPriors = options.balancedPriors ?? true;
    /** Operating point is calibrated for this held-out specificity. */
    this.targetSpecificity = options.targetSpecificity ?? 0.9;
    this.operatingThreshold = 0.5;
    this.model = null;
    this.metrics = null;
    this.trainingInfo = null;
  }

  get isTrained() { return !!this.model; }

  /**
   * Trains on labelled corpora and evaluates on a held-out split.
   * @param {{positives:string[], negatives:string[], holdout?:number, now?:()=>number}} input
   */
  train({ positives, negatives, holdout = 0.2, now = () => Date.now() }) {
    const started = now();
    const pos = dedupe(positives);
    const neg = dedupe(negatives);
    if (pos.length < 20 || neg.length < 20) {
      throw new Error(`not enough training data: ${pos.length} positives, ${neg.length} negatives (need >= 20 each)`);
    }

    const rand = mulberry32(this.seed);
    const shuffledPos = shuffle(pos, rand);
    const shuffledNeg = shuffle(neg, rand);
    const posHoldoutCount = Math.max(5, Math.floor(shuffledPos.length * holdout));
    const negHoldoutCount = Math.max(5, Math.floor(shuffledNeg.length * holdout));

    const posTest = shuffledPos.slice(0, posHoldoutCount);
    const posTrain = shuffledPos.slice(posHoldoutCount);
    const negTest = shuffledNeg.slice(0, negHoldoutCount);
    const negTrain = shuffledNeg.slice(negHoldoutCount);

    // --- Count tokens in one pass over the training split ---
    const counts = new Map(); // token -> {p, n}
    const addDoc = (domain, cls) => {
      const raw = tokenizeDomain(domain, this.featureMode);
      const tokens = this.binary ? new Set(raw) : raw;
      for (const token of tokens) {
        let entry = counts.get(token);
        if (!entry) { entry = { p: 0, n: 0 }; counts.set(token, entry); }
        if (cls === 'p') entry.p++; else entry.n++;
      }
    };
    for (const domain of posTrain) addDoc(domain, 'p');
    for (const domain of negTrain) addDoc(domain, 'n');

    // --- Vocabulary selection (bounded memory, discriminative ranking) ---
    // Frequency-only ranking is dominated by the much larger positive corpus and
    // throws away tokens that are specific to the (small) legitimate corpus.
    // Rank by normalised class imbalance multiplied by log support instead, so a
    // token seen in a handful of legitimate domains still makes the cut.
    const P = posTrain.length;
    const N = negTrain.length;
    const scored = [...counts.entries()]
      .filter(([, c]) => c.p + c.n >= this.minTokenCount)
      .map(([token, c]) => {
        const imbalance = Math.abs((c.p + 0.5) / P - (c.n + 0.5) / N);
        const support = Math.log(1 + c.p + c.n);
        return { token, score: imbalance * support, c };
      })
      .sort((a, b) => b.score - a.score)
      .slice(0, this.maxFeatures);
    const vocab = scored.map((x) => x.token);
    const vocabIndex = new Map(vocab.map((t, i) => [t, i]));

    let posTokens = 0; let negTokens = 0;
    for (const token of vocab) {
      const c = counts.get(token);
      posTokens += c.p;
      negTokens += c.n;
    }

    const vocabSize = vocab.length;
    const logLikPos = new Float64Array(vocabSize);
    const logLikNeg = new Float64Array(vocabSize);
    const denomPos = posTokens + this.alpha * vocabSize;
    const denomNeg = negTokens + this.alpha * vocabSize;
    for (let i = 0; i < vocabSize; i++) {
      const c = counts.get(vocab[i]);
      logLikPos[i] = Math.log((c.p + this.alpha) / denomPos);
      logLikNeg[i] = Math.log((c.n + this.alpha) / denomNeg);
    }

    const priorPos = (posTrain.length + 1) / (posTrain.length + negTrain.length + 2);
    const logPriorPos = this.balancedPriors ? Math.log(0.5) : Math.log(priorPos);
    const logPriorNeg = this.balancedPriors ? Math.log(0.5) : Math.log(1 - priorPos);
    this.model = {
      vocab, vocabIndex, logLikPos, logLikNeg,
      logPriorPos, logPriorNeg,
      featureMode: this.featureMode,
      binary: this.binary,
      trainedAt: new Date(started).toISOString()
    };

    // --- Held-out evaluation (never on training data) ---
    const scores = [];
    const labels = [];
    for (const domain of posTest) { scores.push(this.predict(domain).score); labels.push(1); }
    for (const domain of negTest) { scores.push(this.predict(domain).score); labels.push(0); }

    const base = classificationMetrics(scores, labels, 0.5);

    // Choose an operating point on the holdout that keeps false positives under
    // control (specificity >= targetSpecificity) while maximising recall.
    let operating = null;
    for (let t = 0.99; t >= 0.05; t -= 0.01) {
      const m = classificationMetrics(scores, labels, round4(t));
      if (m.specificity >= this.targetSpecificity) {
        operating = { ...m, threshold: round4(t) };
      } else break;
    }
    if (!operating) {
      // No threshold reaches the target: be explicit rather than pretending.
      operating = { ...classificationMetrics(scores, labels, 0.99), threshold: 0.99, unreachable: true };
    }
    this.operatingThreshold = operating.threshold;

    // Best-F1 sweep is reported too, never hidden behind the headline number.
    let best = { f1: -1, threshold: 0.5 };
    for (let t = 0.05; t <= 0.95; t += 0.01) {
      const m = classificationMetrics(scores, labels, round4(t));
      if (m.f1 > best.f1) best = { f1: m.f1, threshold: round4(t), precision: m.precision, recall: m.recall };
    }

    this.metrics = {
      ...base,
      atThreshold: operating,
      operatingThreshold: operating.threshold,
      targetSpecificity: this.targetSpecificity,
      featureMode: this.featureMode,
      binary: this.binary,
      balancedPriors: this.balancedPriors,
      auc: round4(computeAuc(scores, labels) ?? 0),
      bestF1: best.f1,
      bestThreshold: best.threshold,
      bestPrecision: best.precision,
      bestRecall: best.recall,
      holdoutSize: scores.length,
      vocabSize,
      trainSize: posTrain.length + negTrain.length,
      trainMs: Math.max(0, now() - started)
    };
    this.trainingInfo = {
      positives: pos.length, negatives: neg.length, holdout,
      seed: this.seed, alpha: this.alpha, trainedAt: this.model.trainedAt
    };
    return this.metrics;
  }

  /**
   * Scores a hostname.
   * @returns {{score:number, logOdds:number, contributions:Array<{token:string,weight:number,count:number}>, trained:boolean}}
   */
  predict(domain) {
    if (!this.model) {
      return { score: 0, logOdds: 0, contributions: [], trained: false };
    }
    const raw = tokenizeDomain(domain, this.model.featureMode);
    const tokens = this.model.binary ? new Set(raw) : raw;
    const counts = new Map();
    for (const token of tokens) {
      const idx = this.model.vocabIndex.get(token);
      if (idx !== undefined) counts.set(idx, (counts.get(idx) || 0) + 1);
    }
    if (counts.size === 0) {
      // No known token: fall back to the prior, statement of ignorance included.
      return {
        score: round4(sigmoid(this.model.logPriorPos - this.model.logPriorNeg)),
        logOdds: this.model.logPriorPos - this.model.logPriorNeg,
        contributions: [], trained: true, outOfVocabulary: true
      };
    }
    let logOdds = this.model.logPriorPos - this.model.logPriorNeg;
    const contributions = [];
    for (const [idx, count] of counts) {
      const delta = this.model.logLikPos[idx] - this.model.logLikNeg[idx];
      logOdds += delta * count;
      contributions.push({ token: this.model.vocab[idx], weight: round4(delta), count });
    }
    contributions.sort((a, b) => Math.abs(b.weight * b.count) - Math.abs(a.weight * a.count));
    return {
      score: round4(sigmoid(logOdds)),
      logOdds: round4(logOdds),
      contributions: contributions.slice(0, 8),
      trained: true
    };
  }

  /** Compact serialization for persistent caching (localStorage/IndexedDB). */
  toJSON() {
    if (!this.model) return null;
    return {
      version: 1,
      alpha: this.alpha,
      maxFeatures: this.maxFeatures,
      seed: this.seed,
      featureMode: this.model.featureMode,
      binary: this.model.binary,
      operatingThreshold: this.operatingThreshold,
      vocab: this.model.vocab,
      logLikPos: Array.from(this.model.logLikPos),
      logLikNeg: Array.from(this.model.logLikNeg),
      logPriorPos: this.model.logPriorPos,
      logPriorNeg: this.model.logPriorNeg,
      trainedAt: this.model.trainedAt,
      metrics: this.metrics,
      trainingInfo: this.trainingInfo
    };
  }

  static fromJSON(json) {
    if (!json || json.version !== 1) return null;
    const c = new DomainClassifier({
      alpha: json.alpha, maxFeatures: json.maxFeatures, seed: json.seed,
      featureMode: json.featureMode, binary: json.binary
    });
    c.operatingThreshold = json.operatingThreshold ?? json.metrics?.operatingThreshold ?? 0.5;
    c.model = {
      vocab: json.vocab,
      vocabIndex: new Map(json.vocab.map((t, i) => [t, i])),
      logLikPos: Float64Array.from(json.logLikPos),
      logLikNeg: Float64Array.from(json.logLikNeg),
      logPriorPos: json.logPriorPos,
      logPriorNeg: json.logPriorNeg,
      trainedAt: json.trainedAt
    };
    c.metrics = json.metrics;
    c.trainingInfo = json.trainingInfo;
    return c;
  }
}

function dedupe(list) {
  const set = new Set();
  for (const d of list || []) {
    const clean = String(d || '').trim().toLowerCase();
    if (clean) set.add(clean);
  }
  return [...set];
}

function shuffle(array, rand) {
  const a = array.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

export default DomainClassifier;
