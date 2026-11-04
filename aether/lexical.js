/**
 * OmniShield X — lexical analysis of hostnames.
 *
 * Every function here is a deterministic, testable computation over the string
 * itself. None of them "detect malware": they measure properties (entropy,
 * label shape, token matches, script mixing) that the reputation scorer later
 * weighs together with feed evidence.
 */
import { AD_TRACKER_TOKENS, THREAT_TOKENS, HIGH_ABUSE_TLDS, CONFUSABLE_SCRIPTS } from './data.js';
import { labelsOf, publicSuffix, registrableDomain, subdomainOf } from './domain.js';

/** Shannon entropy in bits per character. */
export function shannonEntropy(text) {
  const str = String(text || '');
  if (!str) return 0;
  const counts = new Map();
  for (const ch of str) counts.set(ch, (counts.get(ch) || 0) + 1);
  let bits = 0;
  for (const count of counts.values()) {
    const p = count / str.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

/** Length of the longest run of consonants (random strings are consonant-heavy). */
export function longestConsonantRun(text) {
  let best = 0; let run = 0;
  for (const ch of String(text || '')) {
    if (/[bcdfghjklmnpqrstvwxz]/.test(ch)) { run++; best = Math.max(best, run); } else run = 0;
  }
  return best;
}

export function digitRatio(text) {
  const str = String(text || '');
  if (!str) return 0;
  const digits = (str.match(/\d/g) || []).length;
  return digits / str.length;
}

export function vowelRatio(text) {
  const str = String(text || '');
  if (!str) return 0;
  return (str.match(/[aeiouy]/g) || []).length / str.length;
}

/** True when a label looks like a random hex chunk (common in DGA and CDNs). */
export function isHexLike(label) {
  return /^[0-9a-f]{8,}$/.test(label) && /\d/.test(label) && /[a-f]/.test(label);
}

export function isNumericLabel(label) {
  return /^\d+$/.test(label);
}

/** Detects punycode (IDN) labels. */
export function hasPunycode(domain) {
  return labelsOf(domain).some((l) => l.startsWith('xn--'));
}

/**
 * Decodes punycode labels where possible and reports mixed-script names.
 * Browsers expose `URL` which converts IDN to punycode; we reverse it through
 * the punycode algorithm implemented below so detection works offline.
 */
export function decodePunycodeLabel(label) {
  if (!label.startsWith('xn--')) return label;
  const input = label.slice(4);
  const base = 36; const tMin = 1; const tMax = 26; const skew = 38; const damp = 700;
  const output = [];
  let n = 128; // 0x80
  let i = 0; let bias = 72;
  // RFC 3492: text before the last delimiter is literal; decoding starts after it.
  const delimiter = input.lastIndexOf('-');
  let pos = 0;
  if (delimiter > 0) {
    for (let j = 0; j < delimiter; j++) output.push(input.charCodeAt(j));
    pos = delimiter + 1;
  }
  const adapt = (delta, numPoints, firstTime) => {
    let d = firstTime ? Math.floor(delta / damp) : Math.floor(delta / 2);
    d += Math.floor(d / numPoints);
    let k = 0;
    while (d > ((base - tMin) * tMax) / 2) { d = Math.floor(d / (base - tMin)); k += base; }
    return k + Math.floor(((base - tMin + 1) * d) / (d + skew));
  };
  let guard = 0;
  while (pos < input.length) {
    if (++guard > 1024) return label;
    if (pos >= input.length) return label;
    const oldi = i; let w = 1;
    for (let k = base; ; k += base) {
      if (pos >= input.length) return label;
      const c = input.charCodeAt(pos++);
      const digit = c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : base;
      if (digit < 0 || digit >= base) return label;
      i += digit * w;
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (digit < t) break;
      w *= base - t;
    }
    const out = output.length + 1;
    bias = adapt(i - oldi, out, oldi === 0);
    n += Math.floor(i / out);
    i %= out;
    output.splice(i, 0, n);
    i++;
  }
  return String.fromCodePoint(...output);
}

/**
 * Reports which writing systems appear in a (decoded) name.
 * Mixed Latin + Cyrillic is the classic IDN homograph phishing pattern.
 */
export function detectScripts(domain) {
  const decoded = labelsOf(domain).map(decodePunycodeLabel).join('.');
  const found = [{
    name: 'Latin', re: /[a-z]/i, examples: 'a b c'
  }, ...CONFUSABLE_SCRIPTS]
    .filter((s) => s.re.test(decoded))
    .map((s) => ({ name: s.name, examples: s.examples }));
  return {
    scripts: found.map((s) => s.name),
    mixed: found.some((s) => s.name === 'Latin') && found.length > 1,
    decoded,
    punycode: hasPunycode(domain)
  };
}

/** Tokens from the ad/tracker vocabulary present in the name. */
export function findTokens(domain, vocabulary = AD_TRACKER_TOKENS) {
  const labels = labelsOf(domain);
  const hits = new Set();
  for (const label of labels) {
    const parts = label.split(/[-_.]/).filter(Boolean);
    for (const part of parts) {
      if (vocabulary.includes(part)) hits.add(part);
      else {
        // substring match for compound names such as "adservicedelivery"
        for (const token of vocabulary) {
          if (token.length >= 4 && part.includes(token)) { hits.add(token); break; }
        }
      }
    }
  }
  return [...hits];
}

/**
 * A coarse DGA heuristic score in [0,1].
 * Combines entropy, consonant runs, digit ratio and label repetition.
 * Documented as a heuristic: modern DGAs defeat it, and we never claim more.
 */
export function dgaScore(label) {
  const l = String(label || '').toLowerCase();
  if (l.length < 8) return 0;
  const entropy = shannonEntropy(l);
  const entropyNorm = Math.min(1, Math.max(0, (entropy - 2.6) / 1.4));      // 2.6..4.0 bits
  const consonant = Math.min(1, Math.max(0, (longestConsonantRun(l) - 3) / 4));
  const digits = Math.min(1, digitRatio(l) * 2.5);
  const vowels = vowelRatio(l);
  const noVowels = vowels < 0.15 ? 1 : 0;
  return Math.round((0.35 * entropyNorm + 0.3 * consonant + 0.2 * digits + 0.15 * noVowels) * 100) / 100;
}

/**
 * Extracts the complete lexical feature vector for a hostname.
 * @param {string} domain normalized hostname
 */
export function extractFeatures(domain) {
  const labels = labelsOf(domain);
  const suffix = publicSuffix(domain);
  const registrable = registrableDomain(domain);
  const sub = subdomainOf(domain);
  const main = labels[labels.length - (suffix ? suffix.split('.').length + 1 : 2)] || labels[0] || '';
  const longest = labels.reduce((a, b) => (b.length > a.length ? b : a), '');
  const scripts = detectScripts(domain);

  return {
    domain,
    length: domain.length,
    labelCount: labels.length,
    depth: Math.max(0, labels.length - 1),
    longestLabel: longest.length,
    hyphens: (domain.match(/-/g) || []).length,
    digits: (domain.match(/\d/g) || []).length,
    digitRatio: Math.round(digitRatio(main) * 100) / 100,
    entropy: Math.round(shannonEntropy(main) * 100) / 100,
    entropyDomain: Math.round(shannonEntropy(domain.replace(/\./g, '')) * 100) / 100,
    consonantRun: longestConsonantRun(main),
    vowelRatio: Math.round(vowelRatio(main) * 100) / 100,
    hexLabel: isHexLike(main),
    numericSubdomains: labels.slice(0, -2).filter(isNumericLabel).length,
    tld: suffix,
    registrable,
    subdomain: sub,
    mainLabel: main,
    adTokens: findTokens(domain, AD_TRACKER_TOKENS),
    threatTokens: findTokens(sub ? sub.split('.').join('-') : '', THREAT_TOKENS)
      .concat(findTokens(main, THREAT_TOKENS)),
    highAbuseTld: HIGH_ABUSE_TLDS.includes(publicSuffix(domain)),
    punycode: scripts.punycode,
    scripts: scripts.scripts,
    mixedScripts: scripts.mixed,
    decoded: scripts.decoded,
    dgaScore: dgaScore(main)
  };
}

/** Human-readable description of a feature vector (used in explanations). */
export function describeFeatures(features) {
  const notes = [];
  if (features.hyphens >= 3) notes.push(`${features.hyphens} hyphens`);
  if (features.labelCount >= 4) notes.push(`${features.labelCount} labels (deep nesting)`);
  if (features.longestLabel > 30) notes.push(`long label (${features.longestLabel} chars)`);
  if (features.digitRatio > 0.3) notes.push('digit-heavy main label');
  if (features.entropy >= 3.5) notes.push(`high entropy (${features.entropy} bits/char)`);
  if (features.consonantRun >= 5) notes.push(`consonant run of ${features.consonantRun}`);
  if (features.mixedScripts) notes.push(`mixed scripts: ${features.scripts.join(' + ')}`);
  if (features.punycode) notes.push('punycode (IDN) label');
  if (features.highAbuseTld) notes.push(`high-abuse TLD .${features.tld}`);
  if (features.adTokens.length) notes.push(`ad/tracker tokens: ${features.adTokens.join(', ')}`);
  return notes;
}

export default { extractFeatures, shannonEntropy, dgaScore, detectScripts, describeFeatures, findTokens };
