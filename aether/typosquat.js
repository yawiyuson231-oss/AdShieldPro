/**
 * OmniShield X — typosquat / brand-impersonation detection.
 *
 * Real algorithms, no black boxes:
 *  - optimal-string-alignment distance (Damerau–Levenshtein with transpositions),
 *    with an early-exit band so only near-misses are computed,
 *  - homoglyph "skeleton" normalization (paypa1 -> paypal, rn -> m, Cyrillic а -> a),
 *  - brand placement analysis against the *registrable* domain, which is the
 *    unit an attacker actually has to register,
 *  - keyboard-adjacency typos.
 *
 * Severity is expressed as a small, documented scale. Matching a brand's name is
 * NOT proof of malice: 'apples.com' and 'target.com' exist legitimately, which is
 * why a match alone can never produce a block (see reputation.js weights).
 */
import { BRANDS, HOMOGLYPHS, KEYBOARD_NEIGHBOURS, POPULAR_SET, POPULAR_DOMAINS } from './data.js';
import { registrableDomain, subdomainOf, labelsOf, publicSuffix } from './domain.js';
import { decodePunycodeLabel } from './lexical.js';

export const SEVERITY = Object.freeze({ NONE: 0, LOW: 1, MEDIUM: 2, HIGH: 3 });
export const SEVERITY_LABELS = Object.freeze({ 0: 'none', 1: 'low', 2: 'medium', 3: 'high' });

/** Canonical TLD for each brand, taken from the curated popular-domain list. */
const BRAND_CANONICAL_TLD = new Map();
for (const domain of POPULAR_DOMAINS) {
  const label = domain.split('.').slice(-2)[0];
  const tld = domain.split('.').pop();
  if (!label || !/^[a-z]+$/.test(label)) continue;
  if (!BRAND_CANONICAL_TLD.has(label)) BRAND_CANONICAL_TLD.set(label, tld);
}

const BRAND_SET = new Set(BRANDS);

/**
 * Optimal string alignment distance, with an optional early exit.
 * @returns {number} distance, or maxDistance + 1 when it certainly exceeds it
 */
export function damerauLevenshtein(a, b, maxDistance = Infinity) {
  const s = String(a); const t = String(b);
  if (s === t) return 0;
  if (Math.abs(s.length - t.length) > maxDistance) return maxDistance + 1;

  const rows = s.length + 1;
  const cols = t.length + 1;
  // Two rolling rows are enough except for transpositions, which need three.
  let prev2 = new Array(cols).fill(0);
  let prev = new Array(cols);
  let curr = new Array(cols);
  for (let j = 0; j < cols; j++) prev[j] = j;

  for (let i = 1; i < rows; i++) {
    curr[0] = i;
    let rowMin = curr[0];
    for (let j = 1; j < cols; j++) {
      const cost = s[i - 1] === t[j - 1] ? 0 : 1;
      let value = Math.min(
        prev[j] + 1,          // deletion
        curr[j - 1] + 1,      // insertion
        prev[j - 1] + cost    // substitution
      );
      if (i > 1 && j > 1 && s[i - 1] === t[j - 2] && s[i - 2] === t[j - 1]) {
        value = Math.min(value, prev2[j - 2] + 1); // transposition
      }
      curr[j] = value;
      if (value < rowMin) rowMin = value;
    }
    if (rowMin > maxDistance) return maxDistance + 1;
    const tmp = prev2; prev2 = prev; prev = curr; curr = tmp;
  }
  return prev[t.length];
}

/** Normalizes look-alike characters so 'paypa1' and 'pаypal' (Cyrillic а) collapse. */
export function skeleton(label) {
  let s = String(label || '').toLowerCase();
  // Decode punycode first so homograph attacks are visible to the matcher.
  s = s.split('-').map((part) => (part.startsWith('xn--') ? decodePunycodeLabel(part) : part)).join('-');
  // Fold common Cyrillic/Greek look-alikes to Latin.
  s = s.replace(/[\u0430\u03b1]/g, 'a').replace(/[\u0435\u03b5]/g, 'e')
    .replace(/[\u043e\u03bf\u03d5]/g, 'o').replace(/[\u0440\u03c1]/g, 'p')
    .replace(/[\u0441\u03f2]/g, 'c').replace(/[\u0445\u03c7]/g, 'x')
    .replace(/[\u0443\u03c5]/g, 'y').replace(/[\u0456\u04cf\u03b9]/g, 'i')
    .replace(/[\u0455]/g, 's').replace(/[\u04bb]/g, 'h')
    .replace(/[\u0501]/g, 'd').replace(/[\u0261\u0262]/g, 'g')
    .replace(/[\u04af]/g, 'y');
  // Multi-character and single-character homoglyphs.
  s = s.replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/cl(?=[aeiou])/g, 'd');
  s = s.replace(/[01345789$@!|]/g, (ch) => HOMOGLYPHS[ch] ?? ch);
  return s;
}

function stripSeparators(s) { return s.replace(/[^a-z0-9]/g, ''); }

function isKeyboardTypo(a, b) {
  if (a.length !== b.length) return false;
  let diffs = 0;
  for (let i = 0; i < a.length; i++) {
    if (a[i] === b[i]) continue;
    diffs++;
    if (diffs > 1) return false;
    const neighbours = KEYBOARD_NEIGHBOURS[a[i]] || '';
    if (!neighbours.includes(b[i])) return false;
  }
  return diffs === 1;
}

/** Affix tokens often used in phishing hostnames: login-paypal, paypalverify. */
const AFFIX_TOKENS = [
  'login', 'signin', 'secure', 'security', 'verify', 'verification', 'account',
  'update', 'confirm', 'support', 'help', 'service', 'official', 'auth',
  'wallet', 'billing', 'payment', 'recovery', 'unlock', 'reset', 'portal',
  'customer', 'team', 'alert', 'notice', 'invoice', 'center', 'online'
];

/**
 * Analyses a hostname for brand impersonation.
 *
 * @param {string} domain normalized hostname
 * @param {{brands?:string[]}} [options]
 * @returns {{suspicious:boolean, severity:number, severityLabel:string,
 *            matches:Array, registrable:string, subdomain:string}}
 */
export function findImpersonation(domain, options = {}) {
  const brands = options.brands ?? BRANDS;
  const normalized = String(domain || '').toLowerCase();
  const registrable = registrableDomain(normalized);
  const sub = subdomainOf(normalized);
  const regLabel = registrable.split('.')[0] || '';
  const tld = publicSuffix(normalized);

  const result = {
    suspicious: false, severity: SEVERITY.NONE, severityLabel: 'none',
    matches: [], registrable, subdomain: sub
  };

  // A domain that is itself in the curated popular list is never a squat.
  if (POPULAR_SET.has(registrable) || POPULAR_SET.has(normalized)) return result;

  const skelReg = stripSeparators(skeleton(regLabel));
  const skelSub = stripSeparators(skeleton(sub));
  const subLabels = labelsOf(sub);

  for (const brand of brands) {
    if (brand.length < 5) continue;
    const skelBrand = stripSeparators(skeleton(brand));

    // 1. Brand hidden in the subdomain, unknown registrable domain.
    if (sub && subLabels.some((l) => {
      const s = stripSeparators(skeleton(l));
      return s === skelBrand && stripSeparators(regLabel) !== skelBrand;
    })) {
      result.matches.push({
        brand, kind: 'brand-in-subdomain', severity: SEVERITY.HIGH,
        explanation: `The name "${brand}" appears in the subdomain of ${registrable}, which is not ${brand}'s own domain.`
      });
      continue;
    }

    // 2. Brand plus a phishing affix: paypal-login, secure-apple, verify-paypal.
    const brandWithAffix = skelReg.includes(skelBrand)
      && skelReg !== skelBrand
      && AFFIX_TOKENS.some((t) => skelReg.includes(t));
    if (brandWithAffix && skelBrand.length >= 5) {
      result.matches.push({
        brand, kind: 'brand-affix', severity: SEVERITY.HIGH,
        explanation: `The registrable name ${regLabel} combines "${brand}" with an account-security word, a classic credential-phishing pattern.`
      });
      continue;
    }

    // 3. Homoglyph or typo within edit distance 1 (2 for long brands).
    const maxDistance = brand.length >= 10 ? 2 : 1;
    if (skelReg !== skelBrand) {
      const distance = damerauLevenshtein(skelReg, skelBrand, maxDistance);
      if (distance <= maxDistance && distance > 0) {
        const sameTld = tld === BRAND_CANONICAL_TLD.get(brand);
        result.matches.push({
          brand, kind: 'typosquat', severity: sameTld ? SEVERITY.MEDIUM : SEVERITY.HIGH,
          distance,
          explanation: `${regLabel} is ${distance} edit${distance === 1 ? '' : 's'} away from "${brand}"${sameTld ? ` on a .${tld} name those organisations do not control` : ''}.`
        });
        continue;
      }
    }

    // 4. Skeleton matches exactly, but the registered label differs from the
    // brand: this is a look-alike spelling (paypa1, micros0ft, Cyrillic аpple).
    if (skelReg === skelBrand && regLabel !== brand) {
      result.matches.push({
        brand, kind: 'homoglyph', severity: SEVERITY.HIGH,
        explanation: `${regLabel} uses look-alike characters to imitate "${brand}".`
      });
      continue;
    }
    if (regLabel === brand && tld !== BRAND_CANONICAL_TLD.get(brand)) {
      result.matches.push({
        brand, kind: 'brand-alt-tld', severity: SEVERITY.LOW,
        explanation: `${brand} normally uses .${BRAND_CANONICAL_TLD.get(brand) || 'com'}; this is the .${tld} name. Large brands do own several TLDs, so this is a weak signal on its own.`
      });
      continue;
    }

    // 5. Adjacent-key typo (gogle.com).
    if (isKeyboardTypo(skelReg, skelBrand)) {
      result.matches.push({
        brand, kind: 'keyboard-typo', severity: SEVERITY.MEDIUM,
        explanation: `${regLabel} differs from "${brand}" by one adjacent key — a common fat-finger registration used for traffic theft.`
      });
    }
  }

  if (result.matches.length) {
    result.severity = Math.max(...result.matches.map((m) => m.severity));
    result.severityLabel = SEVERITY_LABELS[result.severity];
    result.suspicious = result.severity >= SEVERITY.LOW;
    // Keep the strongest evidence first and cap the list for UI sanity.
    result.matches.sort((a, b) => b.severity - a.severity);
    result.matches = result.matches.slice(0, 5);
  }
  return result;
}

/** True when the main label is a known brand (used to avoid self-flagging). */
export function isKnownBrand(label) {
  return BRAND_SET.has(String(label || '').toLowerCase());
}

export default { findImpersonation, damerauLevenshtein, skeleton, isKnownBrand, SEVERITY };
