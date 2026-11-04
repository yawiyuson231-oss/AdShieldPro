/**
 * OmniShield X — DNS redirect-chain audit.
 *
 * Why this exists: a DNS filter cannot see HTTP redirects (301/302/JS). What it
 * *can* see is the CNAME chain a resolver returns, and that is where a common
 * tracking and phishing trick lives: a first-party-looking hostname
 * (`metrics.shop.example`) is a CNAME to a third-party tracker
 * (`tracker.vendor.example`), so blocking the third party by name never fires.
 *
 * This module answers three questions, with evidence and no guessing:
 *   1. What does the chain look like? (every link, in order)
 *   2. Does any link match a filter rule or a suspicious reputation score?
 *   3. Is this "CNAME cloaking" — a subdomain of the queried site pointing off-site
 *      to something we already consider blocked or risky?
 *
 * It does not block anything. It returns an advisory object that the DNS lab and
 * the monitor can display; enforcement stays with the filter engine.
 */
import { OmniShieldFilterEngine } from '../engine.js';

const SCOPE = 'DNS CNAME chain only. HTTP redirects (301/302/JavaScript) are invisible to a DNS filter.';

/** Registrable-ish domain: last two labels, with a small public-suffix allowance. */
export function registrableDomain(hostname) {
  const name = OmniShieldFilterEngine.normalizeDomain(hostname);
  if (!name) return null;
  const labels = name.split('.');
  if (labels.length <= 2) return name;
  const twoLevel = new Set(['co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'or', 'ne', 'go']);
  const last = labels[labels.length - 1];
  const penultimate = labels[labels.length - 2];
  if (last.length === 2 && twoLevel.has(penultimate) && labels.length >= 3) {
    return labels.slice(-3).join('.');
  }
  return labels.slice(-2).join('.');
}

/**
 * @param {{name:string, cname?:string[], engine?:object, reputation?:Function,
 *          maxDepth?:number}} input
 */
export function auditChain({ name, cname = [], engine = null, reputation = null, maxDepth = 12 }) {
  const queried = OmniShieldFilterEngine.normalizeDomain(name);
  const links = [];
  let depth = 0;
  for (const raw of cname || []) {
    // Resolvers return either plain strings or {from, to} link objects.
    const value = typeof raw === 'string' ? raw : raw?.to;
    const target = OmniShieldFilterEngine.normalizeDomain(value);
    if (!target) continue;
    if (++depth > maxDepth) break;
    const verdict = engine?.evaluate ? engine.evaluate(target) : null;
    const rep = typeof reputation === 'function' ? reputation(target) : null;
    links.push({
      target,
      registrable: registrableDomain(target),
      blocked: !!verdict?.blocked,
      blockedBy: verdict?.blocked ? { source: verdict.source, matched: verdict.matched, category: verdict.category } : null,
      score: rep ? rep.score : null,
      verdict: rep ? rep.verdict : null,
      risky: !!rep && rep.score >= 45
    });
  }

  if (!links.length) {
    return {
      queried, links, cloaking: false, depth: 0,
      summary: 'No CNAME indirection: the answer came back directly for the queried name.',
      evidence: [],
      scope: SCOPE
    };
  }

  const queriedSite = registrableDomain(queried);
  const offSite = links.filter((link) => link.registrable && queriedSite && link.registrable !== queriedSite);
  const offending = offSite.filter((link) => link.blocked || link.risky);

  const evidence = [];
  if (links.length) evidence.push(`Chain: ${[queried, ...links.map((l) => l.target)].join(' → ')}`);
  for (const link of links) {
    if (link.blocked) {
      evidence.push(`${link.target} is blocked by ${link.blockedBy.source}${link.blockedBy.matched ? ` (rule ${link.blockedBy.matched})` : ''}.`);
    } else if (link.risky) {
      evidence.push(`${link.target} scores ${link.score}/100 (${link.verdict}) on AETHER's evidence scale.`);
    }
  }
  if (offSite.length) evidence.push(`${offSite.length} of ${links.length} link(s) leave the queried site's registrable domain.`);

  const cloaking = offending.length > 0;
  return {
    queried,
    links,
    depth: links.length,
    offSiteLinks: offSite.length,
    cloaking,
    cloakedTargets: offending.map((l) => l.target),
    summary: cloaking
      ? `CNAME cloaking: ${queried} resolves through ${offending.length} off-site link(s) that the filter or AETHER already flags.`
      : offSite.length
        ? `The chain leaves ${queriedSite} but no link is blocked or risky — recorded, not flagged.`
        : 'The chain stays inside the queried site\'s registrable domain.',
    evidence,
    /** Explicit scope statement, shown in the UI so the limit is never implied away. */
    scope: SCOPE
  };
}
