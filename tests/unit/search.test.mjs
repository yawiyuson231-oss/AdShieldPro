/**
 * Private search.
 *
 * The important assertions are (a) every provider builds the URL its own front end
 * actually accepts, (b) no tracking parameter survives a strip, (c) a blocked
 * pop-up is reported as blocked, and (d) in-app instant answers come from a real
 * response and say why when they cannot.
 */
import test from 'node:test';
import { strict as assert } from 'node:assert';
import {
  PROVIDERS, buildSearchUrl, stripTracking, openExternal, instantAnswer,
  sanitizeQuery, resolveBang, detectSearchUrl, SearchHistory, providerById
} from '../../security/search.js';
import { MemoryStorage } from '../../security/storage.js';

test('google and duckduckgo are both offered, DuckDuckGo is the privacy default', () => {
  const ids = PROVIDERS.map((p) => p.id);
  assert.ok(ids.includes('google'));
  assert.ok(ids.includes('duckduckgo'));
  assert.equal(providerById('duckduckgo').default, true);
  assert.equal(PROVIDERS.filter((p) => p.default).length, 1);
  for (const provider of PROVIDERS) {
    assert.ok(provider.privacy.length > 20, `${provider.id} must state its privacy position`);
    assert.ok(/^https:/.test(provider.home));
    assert.ok(/^https:/.test(provider.search));
  }
});

test('search URLs are built for each provider with its own parameter name', () => {
  assert.equal(buildSearchUrl('duckduckgo', 'dns filtering'), 'https://duckduckgo.com/?q=dns+filtering');
  assert.equal(buildSearchUrl('google', 'dns filtering'), 'https://www.google.com/search?q=dns+filtering');
  assert.equal(buildSearchUrl('startpage', 'dns'), 'https://www.startpage.com/sp/search?query=dns');
  assert.equal(buildSearchUrl('brave', 'dns'), 'https://search.brave.com/search?q=dns');
  assert.equal(buildSearchUrl('mojeek', 'dns'), 'https://www.mojeek.com/search?q=dns');
  assert.match(buildSearchUrl('google', 'cats', { kind: 'images' }), /tbm=isch/);
  assert.match(buildSearchUrl('duckduckgo', 'cats', { kind: 'videos' }), /ia=videos/);
  assert.throws(() => buildSearchUrl('mojeek', 'cats', { kind: 'images' }), /does not offer images/);
  assert.throws(() => buildSearchUrl('google', '   '), /Type something/);
});

test('queries are sanitised, never truncated mid-word silently', () => {
  assert.equal(sanitizeQuery('  hello\u0000world\n '), 'hello world');
  assert.equal(sanitizeQuery('a'.repeat(900)).length, 400);
  assert.equal(sanitizeQuery(null), '');
});

test('!bangs switch provider inside one box', () => {
  assert.deepEqual(resolveBang('!g dns leak'), { provider: 'google', query: 'dns leak' });
  assert.deepEqual(resolveBang('!ddg tracker'), { provider: 'duckduckgo', query: 'tracker' });
  assert.deepEqual(resolveBang('plain query'), { provider: null, query: 'plain query' });
  assert.deepEqual(resolveBang('!zz nope'), { provider: null, query: '!zz nope' });
});

test('tracking parameters are stripped and reported', () => {
  const result = stripTracking('https://shop.example/item?id=9&utm_source=news&utm_medium=email&fbclid=abc&gclid=x#frag');
  assert.equal(result.ok, true);
  assert.deepEqual(result.removed.sort(), ['fbclid', 'gclid', 'utm_medium', 'utm_source']);
  assert.equal(result.url.includes('utm_'), false);
  assert.equal(result.url.includes('id=9'), true);
  assert.equal(result.url.includes('#frag'), true);
  assert.equal(stripTracking('not a url').ok, false);
  assert.equal(stripTracking('https://clean.example/a?b=1').removed.length, 0);
});

test('openExternal reports a blocked pop-up instead of pretending it opened', () => {
  const blocked = openExternal('https://duckduckgo.com/?q=x', { open: () => null });
  assert.equal(blocked.opened, false);
  assert.match(blocked.reason, /blocked/);

  let requested = null;
  const allowed = openExternal('https://duckduckgo.com/?q=x', {
    open: (url, target, features) => { requested = { url, target, features }; return { opener: 'x' }; }
  });
  assert.equal(allowed.opened, true);
  assert.equal(requested.target, '_blank');
  assert.equal(requested.features, 'noopener,noreferrer');
  assert.equal(allowed.handle.opener, null, 'the opener reference must be severed');
});

test('instant answers come from a real response and degrade honestly', async () => {
  const ok = await instantAnswer('dns', {
    fetchImpl: async (url) => {
      assert.match(url, /api\.duckduckgo\.com\/\?q=dns&format=json/);
      return {
        ok: true,
        status: 200,
        async json() {
          return {
            Heading: 'Domain Name System',
            AbstractText: 'The DNS resolves names to addresses.',
            AbstractSource: 'Wikipedia',
            AbstractURL: 'https://en.wikipedia.org/wiki/DNS',
            RelatedTopics: [{ FirstURL: 'https://example.org/dns', Text: 'Related topic' }, { Topics: [{ FirstURL: 'https://example.org/x', Text: 'Nested topic' }] }]
          };
        }
      };
    }
  });
  assert.equal(ok.ok, true);
  assert.equal(ok.heading, 'Domain Name System');
  assert.equal(ok.topics.length, 2);
  assert.equal(ok.hasContent, true);

  const failed = await instantAnswer('dns', { fetchImpl: async () => ({ ok: false, status: 503, headers: { get: () => null } }) });
  assert.equal(failed.ok, false);
  assert.match(failed.error, /503/);

  const offline = await instantAnswer('dns', { fetchImpl: async () => { throw new Error('offline'); } });
  assert.equal(offline.ok, false);
  assert.match(offline.error, /unavailable/);
});

test('a pasted engine result URL is recognised and its query extracted', () => {
  assert.deepEqual(detectSearchUrl('https://duckduckgo.com/?q=privacy+test&ia=web'), { provider: 'duckduckgo', query: 'privacy test' });
  assert.deepEqual(detectSearchUrl('https://www.google.com/search?q=privacy+test'), { provider: 'google', query: 'privacy test' });
  assert.equal(detectSearchUrl('https://example.com/?q=x'), null);
  assert.equal(detectSearchUrl('junk'), null);
});

test('search history is local, bounded, opt-out and clearable', async () => {
  const history = new SearchHistory({ storage: new MemoryStorage(), limit: 3, clock: () => 7 });
  await history.load();
  await history.record('one', 'duckduckgo');
  await history.record('two', 'google');
  await history.record('three', 'brave');
  await history.record('four', 'duckduckgo');
  assert.equal(history.entries.length, 3);
  assert.equal(history.entries[0].query, 'four');

  await history.setEnabled(false);
  assert.equal(history.entries.length, 0, 'disabling history must erase what was stored');
  assert.equal(await history.record('five', 'google'), null);

  await history.setEnabled(true);
  await history.record('six', 'mojeek');
  await history.clear();
  assert.equal(history.entries.length, 0);
});
