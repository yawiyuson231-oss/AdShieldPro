/**
 * Aura AI Assistant — unit tests for the retrieval engine and release manifest.
 *
 * These assert the properties that make Aura safe to ship: it answers from the
 * curated corpus, it declines instead of improvising, it is deterministic, and it
 * never fabricates an integrity value it was not given.
 */
import test from 'node:test';
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';

import { AuraAssistant, CONFIDENCE_FLOOR, contentTokens, normalise, stem, looksLikeHostname } from '../../aura/assistant.js';
import { AURA_TOPICS, AURA_LIMITS, AURA_PILLARS, AURA_QUICK_PROMPTS } from '../../aura/knowledge.js';
import { AURA_RELEASE, isAllowedDownloadUrl, integritySummary, releaseLine } from '../../aura/release.js';

const assistant = () => new AuraAssistant();

test('normalisation folds case, quotes and apostrophes', () => {
  assert.equal(normalise('  What   IS Aura’s  “limit”? '), 'what is auras "limit"?');
  assert.equal(normalise(null), '');
});

test('stemming lets safely/safe and installing/install meet', () => {
  assert.equal(stem('safely'), 'safe');
  assert.equal(stem('installing'), 'install');
  assert.equal(stem('rules'), 'rule');
  assert.equal(stem('dns'), 'dns');
  assert.deepEqual(contentTokens('What is the DNS cache?'), ['dns', 'cache']);
});

test('hostname detection distinguishes domains from prose', () => {
  assert.equal(looksLikeHostname('paypa1.com'), true);
  assert.equal(looksLikeHostname('ads.doubleclick.net'), true);
  assert.equal(looksLikeHostname('What is Aura?'), false);
  assert.equal(looksLikeHostname('this ends with a period.'), false);
});

test('the knowledge base is unique, answerable and non-trivial', () => {
  const ids = AURA_TOPICS.map((topic) => topic.id);
  assert.equal(new Set(ids).size, ids.length, 'topic ids must be unique');
  assert.ok(AURA_TOPICS.length >= 10, `expected 10+ entries, found ${AURA_TOPICS.length}`);
  for (const topic of AURA_TOPICS) {
    assert.ok(topic.answer.length >= 1, `${topic.id} has no answer`);
    assert.ok(topic.answer.join(' ').length > 60, `${topic.id} answer is too thin`);
    assert.ok(topic.keywords.length >= 3, `${topic.id} has too little vocabulary`);
    assert.ok(topic.phrases.length >= 1, `${topic.id} has no phrase anchors`);
    assert.ok(topic.question.endsWith('?'), `${topic.id} question must be a question`);
  }
  assert.ok(AURA_LIMITS.length >= 3);
  assert.ok(AURA_PILLARS.length >= 3);
  assert.ok(AURA_QUICK_PROMPTS.length >= 3);
});

test('every starter prompt is answerable rather than declined', () => {
  const a = assistant();
  for (const prompt of AURA_QUICK_PROMPTS) {
    const reply = a.reply(prompt);
    assert.notEqual(reply.kind, 'fallback', `starter prompt "${prompt}" was declined`);
    assert.ok(reply.confidence >= CONFIDENCE_FLOOR, `"${prompt}" scored ${reply.confidence}`);
  }
});

test('identity, download and privacy questions hit the intended entries', () => {
  const a = assistant();
  assert.equal(a.reply('What is Aura?').topicId, 'intro');
  assert.equal(a.reply('Where do I download the APK?').topicId, 'download');
  assert.equal(a.reply('Is my chat private?').topicId, 'privacy');
  assert.equal(a.reply('How does DNS filtering work?').topicId, 'dns');
  assert.equal(a.reply('What is AETHER?').topicId, 'aether');
  assert.equal(a.reply('How do I install it safely?').topicId, 'verify');
});

test('the download answer quotes the manifest, not a copy of it', () => {
  const reply = assistant().reply('Where do I download the APK?');
  const text = reply.answer.join(' ');
  assert.match(text, new RegExp(AURA_RELEASE.fileName.replace(/\./g, '\\.')));
  assert.equal(reply.link.kind, 'download');
  assert.match(reply.points.join(' '), /MediaFire/);
});

test('off-topic questions are declined with the nearest topics offered', () => {
  const a = assistant();
  for (const question of ['what is the capital of France', 'how do I bake sourdough', 'write me a poem about the sea']) {
    const reply = a.reply(question);
    assert.equal(reply.kind, 'fallback', `"${question}" should have been declined`);
    assert.equal(reply.confidence, 0);
    assert.equal(reply.topicId, null);
    assert.match(reply.answer[0], /outside the answers I carry/);
    assert.ok(reply.followUps.length >= 1, 'a decline must still offer a way forward');
  }
});

test('a hostname is routed to AETHER instead of being scored by the assistant', () => {
  const reply = assistant().reply('paypa1.com');
  assert.equal(reply.topicId, 'aether');
  assert.equal(reply.link.page, 'aether');
  assert.match(reply.answer.join(' '), /AETHER does/);
});

test('small talk is handled without pretending to be a general chatbot', () => {
  const a = assistant();
  assert.equal(a.reply('hi').kind, 'smalltalk');
  assert.equal(a.reply('thanks!').kind, 'smalltalk');
  assert.equal(a.reply('bye').kind, 'smalltalk');
  assert.ok(!/language model/i.test(a.reply('hello').answer.join(' ')));
});

test('answers are deterministic', () => {
  const first = new AuraAssistant().reply('How do I verify the download?');
  const second = new AuraAssistant().reply('How do I verify the download?');
  assert.deepEqual(first, second);
});

test('history records both sides and reset clears it', () => {
  const a = assistant();
  a.ask('What is Aura?');
  a.ask('hi');
  assert.equal(a.history.filter((entry) => entry.role === 'user').length, 2);
  assert.equal(a.history.filter((entry) => entry.role === 'aura').length, 2);
  a.reset();
  assert.equal(a.history.length, 0);
});

test('the assistant never returns fabricated facts about the APK', () => {
  const a = assistant();
  for (const topic of AURA_TOPICS) {
    const text = [...topic.answer, ...(topic.points || [])].join(' ');
    assert.ok(!/[0-9a-f]{64}/i.test(text), `${topic.id} contains something shaped like a hash`);
    assert.ok(!/\b\d+(\.\d+)? ?MB\b/.test(text), `${topic.id} invents a file size`);
  }
  // The download entry must say the hash is unpublished rather than stay silent.
  const download = AURA_TOPICS.find((topic) => topic.id === 'verify');
  assert.match(download.answer.join(' '), /No SHA-256 is published/i);
  assert.equal(a.reply('Is it safe?').topicId, 'verify');
});

test('release manifest is https, allowlisted and internally consistent', () => {
  assert.equal(isAllowedDownloadUrl(AURA_RELEASE.pageUrl), true);
  assert.equal(isAllowedDownloadUrl('http://www.mediafire.com/file/x'), false, 'http must be rejected');
  assert.equal(isAllowedDownloadUrl('https://mediafire.example.com/file/x'), false, 'lookalike host must be rejected');
  assert.equal(isAllowedDownloadUrl('javascript:alert(1)'), false);
  assert.equal(AURA_RELEASE.fileName, `aura-${AURA_RELEASE.version}.apk`);
  assert.equal(AURA_RELEASE.sha256, null);
  assert.equal(AURA_RELEASE.bytes, null);
  assert.match(integritySummary(), /not published/);
  assert.match(releaseLine(), /aura-1\.0\.582\.apk/);
});

test('Aura runtime sources contain no network or code-injection primitives', () => {
  const files = ['knowledge.js', 'release.js', 'assistant.js', 'view.js']
    .map((file) => new URL(`../../aura/${file}`, import.meta.url));
  for (const file of files) {
    const source = readFileSync(file, 'utf8');
    assert.ok(!/\bfetch\s*\(/.test(source), `${file.pathname} calls fetch`);
    assert.ok(!/XMLHttpRequest|WebSocket|sendBeacon/.test(source), `${file.pathname} opens a socket`);
    assert.ok(!/\beval\s*\(|new Function\s*\(/.test(source), `${file.pathname} evaluates code`);
    assert.ok(!/innerHTML|insertAdjacentHTML|document\.write/.test(source), `${file.pathname} writes HTML`);
  }
});
