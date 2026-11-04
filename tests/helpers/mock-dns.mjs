/**
 * Test helper — in-memory DoH simulator.
 *
 * Behaves like a DoH JSON endpoint: honours abort signals, records every call,
 * can be told to fail specific hosts, and returns realistic payloads (including
 * NXDOMAIN and AD bits). It is used only by tests; the app itself never imports it.
 */

const A_RECORDS = {
  'example.com': ['93.184.216.34'],
  'www.example.com': ['93.184.216.34'],
  'ads.doubleclick.net': ['151.101.2.1'],
  'cdn.example.net': ['203.0.113.10'],
  'signed.example': ['198.51.100.7']
};

const AAAA_RECORDS = {
  'example.com': ['2606:2800:220:1:248:1893:25c8:1946'],
  'cdn.example.net': ['2001:db8::10']
};

export function createMockDoh(options = {}) {
  const {
    latencyMs = 1,
    failHosts = new Set(),
    nxdomain = new Set(),
    ad = true,
    rcode = 0,
    answerOverride = null
  } = options;

  const calls = [];
  const state = { requests: 0, failures: 0 };

  const fetchImpl = async (url, init = {}) => {
    calls.push({ url: String(url), at: Date.now() });
    state.requests++;
    const u = new URL(String(url));
    const host = u.hostname;
    const name = (u.searchParams.get('name') || '').replace(/\.$/, '');
    const rawType = u.searchParams.get('type') || '1';
    const type = /^\d+$/.test(rawType)
      ? Number(rawType)
      : ({ A: 1, NS: 2, CNAME: 5, SOA: 6, TXT: 16, AAAA: 28, DS: 43, RRSIG: 46, DNSKEY: 48 }[rawType.toUpperCase()] ?? 1);

    await new Promise((resolve, reject) => {
      if (init.signal?.aborted) return reject(Object.assign(new Error('aborted'), { name: 'AbortError' }));
      const timer = setTimeout(resolve, latencyMs);
      init.signal?.addEventListener('abort', () => {
        clearTimeout(timer);
        reject(Object.assign(new Error('aborted'), { name: 'AbortError' }));
      }, { once: true });
    });

    if (failHosts.has(host) || nxdomain.has('__all__')) {
      state.failures++;
      throw new TypeError('simulated network failure');
    }

    const question = [{ name: `${name}.`, type }];
    if (nxdomain.has(name)) {
      return makeJson({ Status: 3, AD: false, Question: question, Authority: [soa(name)] });
    }
    if (rcode) {
      return makeJson({ Status: rcode, AD: false, Question: question });
    }

    if (answerOverride) {
      const custom = answerOverride(name, type);
      if (custom) return makeJson({ Status: 0, AD: ad, Question: question, Answer: custom });
    }

    const list = type === 28 ? AAAA_RECORDS : A_RECORDS;
    const data = list[name];
    if (!data) {
      return makeJson({ Status: 3, AD: false, Question: question, Authority: [soa(name)] });
    }
    return makeJson({
      Status: 0, AD: ad, Question: question,
      Answer: data.map((d) => ({ name: `${name}.`, type, TTL: 120, data: d }))
    });
  };

  return {
    fetchImpl,
    calls,
    state,
    urls: () => calls.map((c) => c.url),
    nameOf: (i) => new URL(calls[i].url).searchParams.get('name')
  };
}

function soa(name) {
  return {
    name: `${name.replace(/^[^.]+\./, '') || name}.`,
    type: 6,
    TTL: 60,
    data: 'ns1.example. hostmaster.example. 1 7200 900 1209600 300'
  };
}

function makeJson(payload) {
  return {
    ok: true,
    status: 200,
    headers: { get: () => 'application/dns-json' },
    async json() { return payload; },
    async text() { return JSON.stringify(payload); }
  };
}

/** Builds a raw DNS message for wire-transport tests. */
export function wireResponse(hex) {
  const clean = hex.replace(/[^0-9a-fA-F]/g, '');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
  return {
    ok: true,
    status: 200,
    headers: { get: () => 'application/dns-message' },
    async arrayBuffer() { return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength); }
  };
}
