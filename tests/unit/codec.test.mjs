/**
 * Unit tests — DNS wire codec.
 *
 * Includes a hand-assembled reference packet (not produced by our own encoder)
 * so the decoder is validated against the RFC format itself, not against
 * itself. Malformed/hostile input must throw DnsFormatError, never hang.
 */
import test from 'node:test';
import { strict as assert } from 'node:assert';
import {
  encodeQuery, decodeMessage, fromHex, toHex, encodeName, TYPE, typeToString,
  addressesOf, chainOf, minTtl, toBase64Url, fromBase64Url, DnsFormatError,
  frameStreamMessage, deframeStreamMessage
} from '../../dns/codec.js';

/** Hand-assembled: example.com A 300 93.184.216.34, with a C0 0C name pointer. */
const REFERENCE_PACKET = fromHex(
  '1234' + '8180' + '0001' + '0001' + '0000' + '0000' +
  '07' + '6578616d706c65' + '03' + '636f6d' + '00' + '0001' + '0001' +
  'c00c' + '0001' + '0001' + '0000012c' + '0004' + '5db8d822'
);

test('decodes a hand-assembled reference packet', () => {
  const msg = decodeMessage(REFERENCE_PACKET);
  assert.equal(msg.id, 0x1234);
  assert.equal(msg.flags.qr, true);
  assert.equal(msg.flags.recursionDesired, true);
  assert.equal(msg.flags.recursionAvailable, true);
  assert.equal(msg.flags.authenticatedData, false);
  assert.equal(msg.rcodeName, 'NOERROR');
  assert.equal(msg.questions.length, 1);
  assert.equal(msg.questions[0].name, 'example.com');
  assert.equal(msg.questions[0].typeName, 'A');
  assert.equal(msg.answers.length, 1);
  assert.equal(msg.answers[0].name, 'example.com', 'compression pointer must resolve');
  assert.equal(msg.answers[0].ttl, 300);
  assert.equal(msg.answers[0].data.address, '93.184.216.34');
  assert.deepEqual(addressesOf(msg, 'A'), [{ address: '93.184.216.34', ttl: 300 }]);
  assert.equal(msg.bytesRead, REFERENCE_PACKET.length);
});

test('query encoding round-trips through the decoder', () => {
  const { bytes, id } = encodeQuery({ name: 'ads.example.co.uk', type: 'AAAA', dnssec: true });
  const msg = decodeMessage(bytes);
  assert.equal(msg.id, id);
  assert.equal(msg.flags.qr, false);
  assert.equal(msg.flags.recursionDesired, true);
  assert.equal(msg.questions[0].name, 'ads.example.co.uk');
  assert.equal(msg.questions[0].type, TYPE.AAAA);
  assert.ok(msg.edns, 'EDNS0 OPT record must be present');
  assert.equal(msg.edns.dnssecOk, true, 'DO bit must be set for DNSSEC queries');
  assert.equal(msg.edns.udpSize, 1232, 'RFC 6891 recommended buffer size');
});

test('CD flag, EDNS opt-out and type strings', () => {
  const noEdns = decodeMessage(encodeQuery({ name: 'a.b', type: 'TXT', edns: false, cd: true }).bytes);
  assert.equal(noEdns.edns, null);
  assert.equal(noEdns.flags.checkingDisabled, true);
  assert.equal(noEdns.questions[0].typeName, 'TXT');
  assert.equal(typeToString(28), 'AAAA');
  assert.equal(typeToString(999), 'TYPE999');
});

test('IPv6 addresses are compressed per RFC 5952', () => {
  const hex =
    'abcd' + '8180' + '0001' + '0001' + '0000' + '0000' +
    '03' + '697076' + '06' + '676f6f676c65' + '00' + '001c' + '0001' + // ipv.google AAAA
    'c00c' + '001c' + '0001' + '0000003c' + '0010' +
    '2607' + 'f8b0' + '4009' + '0800' + '0000' + '0000' + '0000' + '200e';
  const msg = decodeMessage(fromHex(hex));
  assert.equal(msg.answers[0].data.address, '2607:f8b0:4009:800::200e');
});

test('TXT, SOA and CNAME chains decode', () => {
  const txt = decodeMessage(fromHex(
    '0001' + '8180' + '0001' + '0001' + '0000' + '0000' +
    '01' + '78' + '03' + '636f6d' + '00' + '0010' + '0001' +
    'c00c' + '0010' + '0001' + '0000003c' + '000c' + '0b' + toHex(new TextEncoder().encode('v=spf1 -all'))
  ));
  assert.equal(txt.answers[0].data.text, 'v=spf1 -all');

  const soa = decodeMessage(fromHex(
    '0002' + '8183' + '0001' + '0000' + '0001' + '0000' +
    '07' + '6578616d706c65' + '03' + '636f6d' + '00' + '0006' + '0001' +
    'c00c' + '0006' + '0001' + '00000000' + '0024' +
    '02' + '6e73' + 'c00c' + '0a' + '686f73746d6173746572' + 'c00c' +
    '00000001' + '00000e10' + '00000258' + '00093a80' + '0000012c'
  ));
  assert.equal(soa.rcodeName, 'NXDOMAIN');
  assert.equal(soa.authorities[0].data.minimum, 300);
  assert.equal(soa.authorities[0].data.serial, 1);

  const chain = decodeMessage(fromHex(
    '0003' + '8180' + '0001' + '0002' + '0000' + '0000' +
    '03' + '777777' + '07' + '6578616d706c65' + '03' + '636f6d' + '00' + '0001' + '0001' +
    'c00c' + '0005' + '0001' + '0000003c' + '0002' + 'c010' +
    'c010' + '0001' + '0001' + '0000003c' + '0004' + 'c0a80001'
  ));
  assert.deepEqual(chainOf(chain), [{ from: 'www.example.com', to: 'example.com', ttl: 60 }]);
  assert.equal(minTtl(chain), 60);
  assert.equal(addressesOf(chain)[0].address, '192.168.0.1');
});

test('DNSSEC records decode (DS / DNSKEY / RRSIG)', () => {
  const ds = decodeMessage(fromHex(
    '0004' + '8180' + '0001' + '0001' + '0000' + '0000' +
    '07' + '6578616d706c65' + '00' + '002b' + '0001' +
    'c00c' + '002b' + '0001' + '00000e10' + '0008' + '1a2b' + '08' + '02' + 'aabbccdd'
  ));
  assert.equal(ds.answers[0].data.keyTag, 0x1a2b);
  assert.equal(ds.answers[0].data.algorithm, 8);
  assert.equal(ds.answers[0].data.digestType, 2);
  assert.equal(ds.answers[0].data.digest, 'aabbccdd');

  const dnskey = decodeMessage(fromHex(
    '0005' + '8180' + '0001' + '0001' + '0000' + '0000' +
    '00' + '0030' + '0001' +
    '00' + '0030' + '0001' + '00000e10' + '0008' + '0101' + '03' + '08' + 'deadbeef'
  ));
  assert.equal(dnskey.answers[0].data.zoneKey, true);
  assert.equal(dnskey.answers[0].data.algorithm, 8);
  assert.equal(dnskey.answers[0].name, '.', 'root zone DNSKEY');
});

test('rejects malformed and hostile packets', () => {
  assert.throws(() => decodeMessage(new Uint8Array(5)), DnsFormatError);
  // Truncated answer.
  assert.throws(() => decodeMessage(REFERENCE_PACKET.subarray(0, 20)), DnsFormatError);
  // Self-referential compression pointer (would loop forever without the guard).
  assert.throws(
    () => decodeMessage(fromHex('0001' + '0100' + '0001' + '0000' + '0000' + '0000' + 'c00c' + '0001' + '0001')),
    DnsFormatError
  );
  // Absurd record counts.
  assert.throws(
    () => decodeMessage(fromHex('0001' + '8180' + 'ffff' + 'ffff' + 'ffff' + 'ffff')),
    DnsFormatError
  );
  // Invalid label characters cannot be encoded in the first place.
  assert.throws(() => encodeName('bad name.com'), DnsFormatError);
  assert.throws(() => encodeName('a'.repeat(64) + '.com'), DnsFormatError);
  assert.throws(() => encodeName('x.'.repeat(200) + 'com'), DnsFormatError);
});

test('base64url and stream framing round-trip', () => {
  const { bytes } = encodeQuery({ name: 'example.com' });
  const b64 = toBase64Url(bytes);
  assert.match(b64, /^[A-Za-z0-9_-]+$/, 'must be URL safe with no padding');
  assert.deepEqual(Array.from(fromBase64Url(b64)), Array.from(bytes));

  const frame = frameStreamMessage(bytes);
  assert.equal(frame.length, bytes.length + 2);
  const out = deframeStreamMessage(frame);
  assert.equal(out.rest.length, 0);
  assert.deepEqual(Array.from(out.message), Array.from(bytes));
  assert.equal(deframeStreamMessage(frame.subarray(0, frame.length - 1)), null, 'partial frame returns null');
});
