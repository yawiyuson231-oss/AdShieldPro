/**
 * OmniShield X — DNS wire-format codec (RFC 1035 / RFC 6891).
 *
 * Real encoder/decoder used by the DoH wire transport, the DNSSEC inspector and
 * the DNS test lab. No dependencies, works in browsers and Node.
 *
 * Supported record types: A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, SRV, CAA,
 * OPT (EDNS0), DS, RRSIG, DNSKEY, NSEC, NSEC3, TLSA.
 * Unknown types are preserved as `{type, data: Uint8Array}` so nothing is lost.
 *
 * Safety: every read is bounds-checked, name compression pointers are limited
 * to 32 jumps and never allowed to move forward, so malicious packets cannot
 * trigger infinite loops or out-of-bounds reads.
 */

export const TYPE = Object.freeze({
  A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28,
  SRV: 33, OPT: 41, DS: 43, RRSIG: 46, NSEC: 47, DNSKEY: 48, NSEC3: 50, TLSA: 52,
  CAA: 257, ANY: 255
});

export const CLASS = Object.freeze({ IN: 1, CH: 3, ANY: 255 });

export const RCODE = Object.freeze({
  0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP',
  5: 'REFUSED', 6: 'YXDOMAIN', 7: 'YXRRSET', 8: 'NXRRSET', 9: 'NOTAUTH', 10: 'NOTZONE'
});

/** Pseudo-RR for the root of a DNSKEY trust chain (RFC 4034 §2). */
export const ROOT_DNSKEY_TYPE = TYPE.DNSKEY;

const NAME_LABEL_RE = /^[A-Za-z0-9_-]{1,63}$/;

export class DnsFormatError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DnsFormatError';
  }
}

const typeNameCache = new Map();
for (const [name, num] of Object.entries(TYPE)) typeNameCache.set(num, name);

export function typeToString(type) {
  return typeNameCache.get(type) || `TYPE${type}`;
}

export function typeFromString(name) {
  const upper = String(name || 'A').toUpperCase();
  return TYPE[upper] ?? (Number.isInteger(Number(name)) ? Number(name) : TYPE.A);
}

export function rcodeToString(rcode) {
  return RCODE[rcode] || `RCODE${rcode}`;
}

/* ------------------------------------------------------------------ */
/* Names                                                               */
/* ------------------------------------------------------------------ */

/** Encodes a hostname to wire format (labels + terminating zero). */
export function encodeName(name) {
  const clean = String(name || '').trim().replace(/^\.+/, '').replace(/\.+$/, '');
  if (clean === '') return new Uint8Array([0]);
  const labels = clean.split('.');
  const parts = [];
  let total = 0;
  for (const label of labels) {
    if (!NAME_LABEL_RE.test(label)) throw new DnsFormatError(`invalid label "${label}" in "${name}"`);
    parts.push(label.length, ...new TextEncoder().encode(label));
    total += label.length + 1;
  }
  if (total + 1 > 255) throw new DnsFormatError(`domain name too long: ${name}`);
  return new Uint8Array([...parts, 0]);
}

/* ------------------------------------------------------------------ */
/* Query encoding                                                      */
/* ------------------------------------------------------------------ */

/**
 * Builds a DNS query message.
 * @param {{id?:number, name:string, type?:string|number, dnssec?:boolean,
 *          edns?:boolean, ednsSize?:number, rd?:boolean, cd?:boolean}} options
 */
export function encodeQuery(options) {
  const {
    name, type = 'A', dnssec = false, edns = true,
    ednsSize = 1232, rd = true, cd = false
  } = options;
  const id = options.id ?? cryptoRandomId();
  const qname = encodeName(name);
  const arcount = edns ? 1 : 0;
  const size = 12 + qname.length + 4 + (edns ? 11 : 0);
  const buf = new Uint8Array(size);
  const view = new DataView(buf.buffer);

  view.setUint16(0, id);
  let flags = 0;
  if (rd) flags |= 0x0100;          // RD
  if (cd) flags |= 0x0010;          // CD (checking disabled)
  view.setUint16(2, flags);
  view.setUint16(4, 1);             // QDCOUNT
  view.setUint16(6, 0);             // ANCOUNT
  view.setUint16(8, 0);             // NSCOUNT
  view.setUint16(10, arcount);      // ARCOUNT

  buf.set(qname, 12);
  let offset = 12 + qname.length;
  view.setUint16(offset, typeFromString(type)); offset += 2;
  view.setUint16(offset, CLASS.IN); offset += 2;

  if (edns) {
    buf[offset] = 0;                 // root name
    view.setUint16(offset + 1, TYPE.OPT);
    view.setUint16(offset + 3, ednsSize);
    // TTL field carries extended-rcode(8) | version(8) | flags(16); DO = 0x8000
    const ttl = dnssec ? 0x00008000 : 0;
    view.setUint32(offset + 5, ttl);
    view.setUint16(offset + 9, 0);   // RDLEN
    offset += 11;
  }
  return { id, bytes: buf, name, type: typeFromString(type) };
}

export function cryptoRandomId() {
  const g = globalThis.crypto;
  if (g?.getRandomValues) {
    const arr = new Uint16Array(1);
    g.getRandomValues(arr);
    return arr[0];
  }
  return Math.floor(Math.random() * 0x10000);
}

/* ------------------------------------------------------------------ */
/* Message decoding                                                    */
/* ------------------------------------------------------------------ */

class Reader {
  constructor(bytes) {
    this.bytes = bytes;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.pos = 0;
  }
  need(n) {
    if (this.pos + n > this.bytes.length) throw new DnsFormatError('truncated message');
  }
  u8() { this.need(1); return this.bytes[this.pos++]; }
  u16() { this.need(2); const v = this.view.getUint16(this.pos); this.pos += 2; return v; }
  u32() { this.need(4); const v = this.view.getUint32(this.pos); this.pos += 4; return v; }
  slice(n) { this.need(n); const s = this.bytes.subarray(this.pos, this.pos + n); this.pos += n; return s; }

  /** Reads a (possibly compressed) name. */
  name() {
    const labels = [];
    let jumps = 0;
    let pos = this.pos;
    let advanced = false;
    let guard = 0;
    while (true) {
      if (++guard > 512) throw new DnsFormatError('name too long');
      if (pos >= this.bytes.length) throw new DnsFormatError('name out of bounds');
      const len = this.bytes[pos];
      if (len === 0) {
        pos += 1;
        if (!advanced) this.pos = pos;
        break;
      }
      if ((len & 0xc0) === 0xc0) {
        if (pos + 1 >= this.bytes.length) throw new DnsFormatError('truncated compression pointer');
        const ptr = ((len & 0x3f) << 8) | this.bytes[pos + 1];
        if (++jumps > 32) throw new DnsFormatError('compression pointer loop');
        // Pointers must move strictly backwards to prevent loops.
        if (ptr >= pos) throw new DnsFormatError('forward compression pointer');
        if (!advanced) { this.pos = pos + 2; advanced = true; }
        pos = ptr;
        continue;
      }
      if (len > 63) throw new DnsFormatError('invalid label length');
      if (pos + 1 + len > this.bytes.length) throw new DnsFormatError('truncated label');
      labels.push(new TextDecoder().decode(this.bytes.subarray(pos + 1, pos + 1 + len)));
      pos += 1 + len;
      if (labels.join('.').length > 253) throw new DnsFormatError('name too long');
    }
    if (!advanced) this.pos = pos;
    return labels.length ? labels.join('.') : '.';
  }
}

function decodeRdata(reader, type, rdlength) {
  const start = reader.pos;
  const end = start + rdlength;
  if (end > reader.bytes.length) throw new DnsFormatError('rdata out of bounds');

  switch (type) {
    case TYPE.A: {
      const b = reader.slice(4);
      return { address: `${b[0]}.${b[1]}.${b[2]}.${b[3]}` };
    }
    case TYPE.AAAA: {
      const b = reader.slice(16);
      const groups = [];
      for (let i = 0; i < 16; i += 2) groups.push(((b[i] << 8) | b[i + 1]).toString(16));
      return { address: compressIpv6(groups.join(':')) };
    }
    case TYPE.NS: case TYPE.CNAME: case TYPE.PTR:
      return { target: reader.name() };
    case TYPE.MX: {
      const preference = reader.u16();
      return { preference, target: reader.name() };
    }
    case TYPE.TXT: {
      const chunks = [];
      while (reader.pos < end) {
        const len = reader.u8();
        chunks.push(new TextDecoder().decode(reader.slice(len)));
      }
      return { text: chunks.join('') };
    }
    case TYPE.SOA: {
      const mname = reader.name();
      const rname = reader.name();
      const serial = reader.u32();
      const refresh = reader.u32();
      const retry = reader.u32();
      const expire = reader.u32();
      const minimum = reader.u32();
      return { mname, rname, serial, refresh, retry, expire, minimum };
    }
    case TYPE.SRV: {
      const priority = reader.u16();
      const weight = reader.u16();
      const port = reader.u16();
      return { priority, weight, port, target: reader.name() };
    }
    case TYPE.CAA: {
      const flags = reader.u8();
      const tagLen = reader.u8();
      const tag = new TextDecoder().decode(reader.slice(tagLen));
      const value = new TextDecoder().decode(reader.slice(end - reader.pos));
      return { flags, tag, value };
    }
    case TYPE.DS: {
      const keyTag = reader.u16();
      const algorithm = reader.u8();
      const digestType = reader.u8();
      const digest = toHex(reader.slice(end - reader.pos));
      return { keyTag, algorithm, digestType, digest };
    }
    case TYPE.DNSKEY: {
      const flags = reader.u16();
      const protocol = reader.u8();
      const algorithm = reader.u8();
      const publicKey = toHex(reader.slice(end - reader.pos));
      return { flags, protocol, algorithm, publicKey, zoneKey: (flags & 0x0100) !== 0 };
    }
    case TYPE.RRSIG: {
      const typeCovered = reader.u16();
      const algorithm = reader.u8();
      const labels = reader.u8();
      const originalTtl = reader.u32();
      const expiration = reader.u32();
      const inception = reader.u32();
      const keyTag = reader.u16();
      const signerName = reader.name();
      const signature = toHex(reader.slice(end - reader.pos));
      return {
        typeCovered, algorithm, labels, originalTtl,
        expiration: new Date(expiration * 1000).toISOString(),
        inception: new Date(inception * 1000).toISOString(),
        keyTag, signerName, signature
      };
    }
    case TYPE.NSEC:
      return { nextDomain: reader.name(), typeBitmap: toHex(reader.slice(end - reader.pos)) };
    default:
      return { raw: toHex(reader.slice(end - reader.pos)) };
  }
}

function compressIpv6(str) {
  // Collapse the longest run of zero groups to "::" (RFC 5952 §4.2).
  const groups = str.split(':');
  let bestStart = -1; let bestLen = 0; let curStart = -1; let curLen = 0;
  for (let i = 0; i < groups.length; i++) {
    if (groups[i] === '0') {
      if (curStart < 0) { curStart = i; curLen = 0; }
      curLen++;
      if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
    } else { curStart = -1; curLen = 0; }
  }
  if (bestLen < 2) return groups.join(':');
  return `${groups.slice(0, bestStart).join(':')}::${groups.slice(bestStart + bestLen).join(':')}`;
}

export function toHex(bytes) {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

export function fromHex(hex) {
  const clean = String(hex).replace(/[^0-9a-fA-F]/g, '');
  if (clean.length % 2) throw new DnsFormatError('odd hex length');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

/**
 * Decodes a DNS message.
 * @param {Uint8Array} input
 * @returns {object} parsed message
 */
export function decodeMessage(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  const reader = new Reader(bytes);
  reader.need(12);
  const id = reader.u16();
  const flagsWord = reader.u16();
  const qdcount = reader.u16();
  const ancount = reader.u16();
  const nscount = reader.u16();
  const arcount = reader.u16();

  if (qdcount > 64 || ancount > 512 || nscount > 256 || arcount > 256) {
    throw new DnsFormatError('suspiciously large record counts');
  }

  const flags = {
    qr: (flagsWord & 0x8000) !== 0,
    opcode: (flagsWord >> 11) & 0x0f,
    authoritative: (flagsWord & 0x0400) !== 0,
    truncated: (flagsWord & 0x0200) !== 0,
    recursionDesired: (flagsWord & 0x0100) !== 0,
    recursionAvailable: (flagsWord & 0x0080) !== 0,
    authenticatedData: (flagsWord & 0x0020) !== 0,   // AD
    checkingDisabled: (flagsWord & 0x0010) !== 0,    // CD
    rcode: flagsWord & 0x000f
  };

  const questions = [];
  for (let i = 0; i < qdcount; i++) {
    const name = reader.name();
    const type = reader.u16();
    const qclass = reader.u16();
    questions.push({ name, type, typeName: typeToString(type), class: qclass });
  }

  const readRecords = (count) => {
    const records = [];
    for (let i = 0; i < count; i++) {
      const name = reader.name();
      const type = reader.u16();
      const rclass = reader.u16();
      const ttl = reader.u32();
      const rdlength = reader.u16();
      if (type === TYPE.OPT) {
        // OPT: class = UDP payload size, ttl = extended rcode/version/flags
        const data = decodeRdata(reader, type, rdlength);
        records.push({
          name, type, typeName: 'OPT', udpSize: rclass, ttl,
          dnssecOk: (ttl & 0x8000) !== 0,
          extendedRcode: (ttl >>> 24) & 0xff,
          version: (ttl >>> 16) & 0xff,
          data
        });
        continue;
      }
      const data = decodeRdata(reader, type, rdlength);
      records.push({ name, type, typeName: typeToString(type), class: rclass, ttl, data });
      if (reader.pos > bytes.length) throw new DnsFormatError('record overflow');
    }
    return records;
  };

  const answers = readRecords(ancount);
  const authorities = readRecords(nscount);
  const additionals = readRecords(arcount);

  return {
    id, flags, rcode: flags.rcode, rcodeName: rcodeToString(flags.rcode),
    counts: { questions: qdcount, answers: ancount, authorities: nscount, additionals: arcount },
    questions, answers, authorities, additionals,
    edns: additionals.find((r) => r.type === TYPE.OPT) || null,
    bytesRead: reader.pos,
    size: bytes.length
  };
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

export function addressesOf(message, type = 'A') {
  const wanted = typeFromString(type);
  return message.answers
    .filter((r) => r.type === wanted && r.data?.address)
    .map((r) => ({ address: r.data.address, ttl: r.ttl }));
}

export function chainOf(message) {
  return message.answers.filter((r) => r.type === TYPE.CNAME)
    .map((r) => ({ from: r.name, to: r.data.target, ttl: r.ttl }));
}

export function minTtl(message, fallback = 60) {
  const ttls = message.answers.filter((r) => Number.isFinite(r.ttl)).map((r) => r.ttl);
  return ttls.length ? Math.min(...ttls) : fallback;
}

/** base64url helpers usable in browsers and Node. */
export function toBase64Url(bytes) {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  const b64 = typeof btoa === 'function'
    ? btoa(binary)
    : Buffer.from(bytes).toString('base64');
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64Url(str) {
  const b64 = String(str).replace(/-/g, '+').replace(/_/g, '/');
  if (typeof atob === 'function') {
    const binary = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  }
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

/**
 * Frames a DNS message for a stream transport (DoT / TCP): 2-byte length prefix.
 * Used by the tested DoT codec. Note: browsers cannot open TCP:853 — see docs.
 */
export function frameStreamMessage(bytes) {
  if (bytes.length > 0xffff) throw new DnsFormatError('message exceeds 65535 bytes');
  const out = new Uint8Array(2 + bytes.length);
  out[0] = (bytes.length >> 8) & 0xff;
  out[1] = bytes.length & 0xff;
  out.set(bytes, 2);
  return out;
}

/** Reads one length-prefixed message from a byte stream; returns null if incomplete. */
export function deframeStreamMessage(bytes) {
  if (bytes.length < 2) return null;
  const len = (bytes[0] << 8) | bytes[1];
  if (bytes.length < 2 + len) return null;
  return { message: bytes.subarray(2, 2 + len), rest: bytes.subarray(2 + len) };
}
