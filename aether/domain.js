/**
 * OmniShield X — domain structure helpers.
 *
 * Deliberately does NOT claim full Public Suffix List support. The real PSL has
 * ~9,000 entries and a 200 KB+ footprint; OmniShield X ships a focused list of
 * the multi-label suffixes that cover the overwhelming majority of real-world
 * registrations, and states the limitation in docs/UNSUPPORTED.md.
 */

/** Multi-label public suffixes handled locally (covers common ccTLD layouts). */
export const MULTI_LABEL_SUFFIXES = Object.freeze(new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'id.au',
  'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp', 'gr.jp',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'com.ph', 'net.ph', 'org.ph', 'gov.ph', 'edu.ph',
  'com.sg', 'net.sg', 'org.sg', 'gov.sg',
  'com.my', 'net.my', 'org.my', 'gov.my',
  'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in',
  'co.za', 'net.za', 'org.za', 'gov.za',
  'com.mx', 'net.mx', 'org.mx', 'gob.mx',
  'com.ar', 'net.ar', 'org.ar', 'gob.ar',
  'com.co', 'net.co', 'org.co',
  'com.pe', 'com.ve', 'com.ec', 'com.uy', 'com.py', 'com.bo',
  'com.tr', 'net.tr', 'org.tr', 'gov.tr',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn',
  'com.tw', 'net.tw', 'org.tw', 'gov.tw',
  'co.kr', 'or.kr', 'ne.kr', 'go.kr',
  'co.id', 'or.id', 'web.id', 'go.id',
  'com.vn', 'net.vn', 'org.vn',
  'com.pk', 'com.bd', 'com.np', 'com.lk',
  'com.ng', 'com.gh', 'com.eg', 'com.sa', 'com.ae', 'com.qa', 'com.kw',
  'co.ke', 'co.tz', 'co.ug', 'co.il', 'co.th', 'co.ir',
  'com.hk', 'com.mo', 'com.ua', 'com.ru', 'com.pl', 'com.pt', 'com.gr',
  'com.es', 'com.it', 'com.fr', 'com.de', 'com.se', 'com.no', 'com.dk',
  'com.fi', 'com.ie', 'com.is', 'com.hr', 'com.rs', 'com.bg', 'com.ro',
  'com.cz', 'com.sk', 'com.hu', 'com.ee', 'com.lv', 'com.lt', 'com.by',
  'com.kz', 'com.uz', 'com.ge', 'com.am', 'com.az'
]));

/** Returns the "public suffix" portion of a domain (best effort). */
export function publicSuffix(domain) {
  const parts = String(domain || '').toLowerCase().split('.').filter(Boolean);
  if (parts.length < 2) return '';
  const two = parts.slice(-2).join('.');
  return MULTI_LABEL_SUFFIXES.has(two) && parts.length >= 3 ? two : parts[parts.length - 1];
}

/**
 * Returns the registrable domain (eTLD+1) — the unit an attacker must register.
 * `paypal.com.evil.tk` => `evil.tk`, which is what makes the phishing obvious.
 */
export function registrableDomain(domain) {
  const parts = String(domain || '').toLowerCase().split('.').filter(Boolean);
  if (parts.length < 2) return parts.join('.');
  const suffix = publicSuffix(parts.join('.'));
  const suffixLabels = suffix ? suffix.split('.').length : 1;
  return parts.slice(-(suffixLabels + 1)).join('.');
}

/** Everything left of the registrable domain (may be ''). */
export function subdomainOf(domain) {
  const reg = registrableDomain(domain);
  const d = String(domain || '').toLowerCase();
  return d.endsWith(`.${reg}`) ? d.slice(0, -(reg.length + 1)) : (d === reg ? '' : d);
}

/** Splits a domain into its labels, most specific first. */
export function labelsOf(domain) {
  return String(domain || '').toLowerCase().split('.').filter(Boolean);
}

/** True when the domain equals or is a subdomain of another. */
export function isWithin(domain, parent) {
  const d = String(domain || '').toLowerCase();
  const p = String(parent || '').toLowerCase();
  return d === p || d.endsWith(`.${p}`);
}

export default { MULTI_LABEL_SUFFIXES, publicSuffix, registrableDomain, subdomainOf, labelsOf, isWithin };
