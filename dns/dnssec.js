/**
 * OmniShield X — DNSSEC status assessment.
 *
 * HONEST SCOPE STATEMENT
 * ----------------------
 * A web page cannot perform full local DNSSEC validation: it would need to walk
 * the chain of trust from the root KSK down, fetch DNSKEY/DS records itself and
 * verify RSA/ECDSA signatures locally. That is possible in a native DNS client
 * but not something we claim to do here.
 *
 * What this module really does:
 *  1. Asks for DNSSEC records (DO bit) and verifies the response is internally
 *     coherent (RRSIG presence, signer, covered type, validity window).
 *  2. Reports the AD (Authenticated Data) bit that a *validating upstream
 *     resolver* sets — and names that resolver, so the trust is attributable.
 *  3. Distinguishes "no DNSSEC deployed", "signed but not validated by us" and
 *     "validated upstream", and never upgrades one to another.
 *
 * Verification of signatures locally is listed in docs/UNSUPPORTED.md.
 */
import { TYPE } from './codec.js';

export const DNSSEC_STATUS = Object.freeze({
  VALIDATED_UPSTREAM: 'VALIDATED_UPSTREAM',
  SIGNED_UNVERIFIED: 'SIGNED_UNVERIFIED',
  UNSIGNED: 'UNSIGNED',
  BOGUS_SUSPECTED: 'BOGUS_SUSPECTED',
  UNKNOWN: 'UNKNOWN'
});

export const DNSSEC_LABELS = Object.freeze({
  VALIDATED_UPSTREAM: 'Validated by upstream resolver (AD bit)',
  SIGNED_UNVERIFIED: 'Signed (RRSIG present) — not validated locally',
  UNSIGNED: 'Not signed (no DNSSEC records)',
  BOGUS_SUSPECTED: 'Resolution failed with DNSSEC requested — could be bogus or simply unreachable',
  UNKNOWN: 'Unknown'
});

/**
 * Inspects RRSIG records in a response against the answer set.
 * @returns {{signed:boolean, signatures:Array, problems:string[]}}
 */
export function inspectSignatures(message) {
  const problems = [];
  const signatures = [];
  const allRecords = [...message.answers, ...message.authorities];

  for (const rr of allRecords) {
    if (rr.type !== TYPE.RRSIG) continue;
    const d = rr.data || {};
    signatures.push({
      name: rr.name,
      typeCovered: d.typeCovered,
      algorithm: d.algorithm,
      keyTag: d.keyTag,
      signerName: d.signerName,
      inception: d.inception,
      expiration: d.expiration,
      labels: d.labels
    });
    if (!d.signerName) problems.push('RRSIG without signer name');
    if (!d.signature) problems.push('RRSIG without signature bytes');
    // Expired signature (algorithm-level check, not a crypto verification).
    if (d.expiration) {
      const exp = Date.parse(d.expiration);
      if (Number.isFinite(exp) && exp < Date.now()) problems.push(`signature expired at ${d.expiration}`);
    }
    if (d.inception) {
      const inc = Date.parse(d.inception);
      if (Number.isFinite(inc) && inc > Date.now() + 120000) problems.push(`signature not yet valid (${d.inception})`);
    }
  }

  const answerTypes = new Set(message.answers.map((r) => r.type));
  if (signatures.length) {
    for (const sig of signatures) {
      if (sig.typeCovered && !answerTypes.has(sig.typeCovered)) {
        // Normal for NSEC/denial proofs — informational only.
        problems.push(`signature covers ${sig.typeCovered} which is not in the answer set`);
      }
    }
  }
  return { signed: signatures.length > 0, signatures, problems };
}

/**
 * Assesses the DNSSEC posture of a resolution result.
 *
 * @param {{message:object, requested:boolean, resolverName?:string,
 *          transportFailed?:boolean, rcode?:number}} input
 */
export function assessDnssec(input) {
  const { message, requested, resolverName = 'upstream resolver', transportFailed = false } = input;

  if (transportFailed) {
    return {
      status: DNSSEC_STATUS.UNKNOWN,
      label: DNSSEC_LABELS.UNKNOWN,
      validatedBy: null,
      signed: false,
      detail: 'No DNSSEC conclusion: the resolver did not answer.'
    };
  }
  if (!message) {
    return {
      status: DNSSEC_STATUS.UNKNOWN, label: DNSSEC_LABELS.UNKNOWN,
      validatedBy: null, signed: false, detail: 'No response to inspect.'
    };
  }

  const { signed, signatures, problems } = inspectSignatures(message);
  const ad = !!message.flags?.authenticatedData;

  // SERVFAIL with DNSSEC requested may be a bogus signature, but may equally be
  // an unreachable authoritative server. We never assert "bogus".
  if (message.rcode === 2 || message.rcode === 5) {
    return {
      status: DNSSEC_STATUS.BOGUS_SUSPECTED,
      label: DNSSEC_LABELS.BOGUS_SUSPECTED,
      validatedBy: null,
      signed,
      signatures: signatures.length,
      detail: requested
        ? `The resolver answered ${message.rcodeName} with DNSSEC requested. This is consistent with a validation failure, but also with an authoritative outage — OmniShield X does not claim a signature was proven invalid.`
        : `The resolver answered ${message.rcodeName}.`,
      problems
    };
  }

  if (ad) {
    return {
      status: DNSSEC_STATUS.VALIDATED_UPSTREAM,
      label: DNSSEC_LABELS.VALIDATED_UPSTREAM,
      validatedBy: resolverName,
      signed: true,
      signatures: signatures.length,
      detail: `${resolverName} set the AD bit, meaning it validated the signature chain itself. OmniShield X trusts that resolver's verdict; it did not perform local cryptographic validation.`,
      problems
    };
  }

  if (signed) {
    return {
      status: DNSSEC_STATUS.SIGNED_UNVERIFIED,
      label: DNSSEC_LABELS.SIGNED_UNVERIFIED,
      validatedBy: null,
      signed: true,
      signatures: signatures.length,
      detail: `${signatures.length} signature record(s) were returned but the resolver did not set the AD bit, so the chain is not proven valid.`,
      problems
    };
  }

  return {
    status: DNSSEC_STATUS.UNSIGNED,
    label: DNSSEC_LABELS.UNSIGNED,
    validatedBy: null,
    signed: false,
    signatures: 0,
    detail: 'The zone returned no DNSSEC signature records. Unsigned zones are not automatically unsafe, but their answers cannot be authenticated.',
    problems
  };
}
