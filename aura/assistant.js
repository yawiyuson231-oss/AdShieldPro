/**
 * Aura AI Assistant — deterministic retrieval engine.
 *
 * The contract this module is built to keep:
 *
 *   1. No network. No `fetch`, no sockets, no storage of the conversation
 *      anywhere but a plain array the caller owns.
 *   2. No invention. If the best match is weak, the reply is a fallback that
 *      names the closest topics — never a composed-sounding guess.
 *   3. Deterministic. Same question, same corpus, same answer, forever.
 *   4. Auditable. Every reply carries the topic id it came from and the
 *      confidence the matcher actually measured.
 *
 * Scoring is intentionally simple and explainable: keyword hits, phrase hits and
 * title hits, then normalised into a 0–1 confidence. A learned ranker would be
 * better at fuzzy paraphrases and worse at being inspected, and this is a
 * privacy product — the explainable one wins.
 */
import { AURA_TOPICS, AURA_QUICK_PROMPTS } from './knowledge.js';
import { AURA_RELEASE } from './release.js';

/** Below this confidence the engine declines instead of answering. */
export const CONFIDENCE_FLOOR = 0.34;

/** Score that maps to confidence 1.0. */
const SCORE_CEILING = 7;

const PHRASE_WEIGHT = 3;
const KEYWORD_WEIGHT = 1;
const TITLE_WEIGHT = 1;

const GREETINGS = /^(hi|hey|hello|yo|good (morning|afternoon|evening)|hiya|howdy)\b/;
const THANKS = /^(thanks|thank you|thx|cheers|appreciate it)\b/;
const FAREWELL = /^(bye|goodbye|see you|later|good night)\b/;

/**
 * @typedef {object} AuraReply
 * @property {'answer'|'fallback'|'smalltalk'} kind
 * @property {string} query           The question as asked.
 * @property {string|null} topicId    Knowledge entry used (citation).
 * @property {string} title           Short label for the reply header.
 * @property {number} confidence      0–1 measured match score.
 * @property {string[]} answer        Paragraphs, in order.
 * @property {string[]} points        Optional evidence bullets.
 * @property {{kind: string, page?: string, href?: string, label: string}|null} link
 * @property {string[]} followUps     Suggested next questions.
 * @property {string[]} matched       Terms that produced the match (explainability).
 */

/** Lowercase, unify quotes, drop apostrophes so `can't` matches `cant`. */
export function normalise(text) {
  return String(text ?? '')
    .toLowerCase()
    .replace(/[\u2018\u2019\u02bc]/g, "'")
    .replace(/'/g, '')
    .replace(/[\u201c\u201d]/g, '"')
    .replace(/\s+/g, ' ')
    .trim();
}

/** Word tokens; dots are kept so a hostname survives as one token. */
export function tokenize(text) {
  return normalise(text)
    .split(/[^a-z0-9.\-]+/)
    .map((token) => token.replace(/^[.\-]+|[.\-]+$/g, ''))
    .filter((token) => token.length > 1);
}

/**
 * Words that carry no retrieval signal. Without this, "what is the capital of
 * France" scores on `what` and `is` and gets answered — the exact failure mode a
 * retrieval assistant must not have.
 */
const STOPWORDS = new Set([
  'a', 'an', 'and', 'any', 'are', 'as', 'at', 'be', 'by', 'can', 'could', 'did', 'do', 'does',
  'for', 'from', 'get', 'had', 'has', 'have', 'how', 'i', 'if', 'in', 'into', 'is', 'it', 'its',
  'me', 'my', 'of', 'on', 'or', 'should', 'so', 'tell', 'than', 'that', 'the', 'their', 'them',
  'then', 'there', 'these', 'they', 'this', 'to', 'was', 'we', 'were', 'what', 'when', 'where',
  'which', 'who', 'why', 'will', 'with', 'would', 'you', 'your'
]);

/**
 * Very light stemmer: enough to let `safely`, `safe` and `safest` meet, or
 * `installing` meet `install`. Not a linguistics project — a retrieval aid.
 * @param {string} word
 */
export function stem(word) {
  let value = String(word);
  if (value.length > 5 && value.endsWith('ing')) value = value.slice(0, -3);
  else if (value.length > 4 && value.endsWith('ly')) value = value.slice(0, -2);
  else if (value.length > 4 && value.endsWith('ed')) value = value.slice(0, -2);
  if (value.length > 3 && value.endsWith('s')) value = value.slice(0, -1);
  return value;
}

/** Tokens that actually discriminate between entries. */
export function contentTokens(text) {
  return tokenize(text).filter((token) => !STOPWORDS.has(token));
}

/** True for input shaped like a hostname rather than a sentence. */
export function looksLikeHostname(text) {
  const value = String(text ?? '').trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/.test(value)) return false;
  // A question ending in a period is prose, not a domain.
  if (/\s/.test(value)) return false;
  return true;
}

/**
 * Scores one knowledge entry against a query.
 * @param {string} query   Already normalised query.
 * @param {string[]} tokens
 * @param {import('./knowledge.js').AuraTopic} topic
 */
export function scoreTopic(query, tokens, topic) {
  const matched = [];
  let score = 0;

  for (const phrase of topic.phrases || []) {
    const needle = normalise(phrase);
    if (needle && query.includes(needle)) {
      score += PHRASE_WEIGHT;
      matched.push(phrase);
    }
  }

  const tokenSet = new Set(tokens.map(stem));
  for (const keyword of topic.keywords || []) {
    const needle = normalise(keyword);
    if (!needle || STOPWORDS.has(needle)) continue;
    const hit = tokenSet.has(stem(needle)) || (needle.length > 3 && query.includes(needle));
    if (hit) {
      score += KEYWORD_WEIGHT;
      matched.push(keyword);
    }
  }

  for (const word of contentTokens(topic.title)) {
    if (tokenSet.has(stem(word)) && !matched.includes(word) && !matched.includes(stem(word))) {
      score += TITLE_WEIGHT;
      matched.push(word);
    }
  }

  return { score, matched: [...new Set(matched)] };
}

/** Explicit release facts, so the download answers cannot drift from the manifest. */
function releaseFacts() {
  return {
    file: AURA_RELEASE.fileName,
    version: AURA_RELEASE.version,
    platform: AURA_RELEASE.platform,
    channel: AURA_RELEASE.channel,
    url: AURA_RELEASE.pageUrl
  };
}

export class AuraAssistant {
  /**
   * @param {{topics?: import('./knowledge.js').AuraTopic[], quickPrompts?: string[], floor?: number}} [options]
   */
  constructor(options = {}) {
    this.topics = options.topics || AURA_TOPICS;
    this.quickPrompts = options.quickPrompts || AURA_QUICK_PROMPTS;
    this.floor = typeof options.floor === 'number' ? options.floor : CONFIDENCE_FLOOR;
    /** @type {{role: 'user'|'aura', text: string, at: number, reply?: AuraReply}[]} */
    this.history = [];
    this.release = releaseFacts();
  }

  /** Starter questions for the composer. */
  suggestions() {
    return [...this.quickPrompts];
  }

  /** Topics ranked by relevance, used by the fallback and the topic index. */
  ranked(question) {
    const query = normalise(question);
    const tokens = contentTokens(question);
    return this.topics
      .map((topic) => ({ topic, ...scoreTopic(query, tokens, topic) }))
      .sort((a, b) => b.score - a.score || a.topic.id.localeCompare(b.topic.id));
  }

  /**
   * Answers one question. Pure with respect to the world: the only state touched
   * is `this.history`, which the caller can clear.
   * @param {string} question
   * @returns {AuraReply}
   */
  ask(question) {
    const raw = String(question ?? '').trim();
    const reply = this.reply(raw);
    this.history.push({ role: 'user', text: raw, at: Date.now() });
    this.history.push({ role: 'aura', text: reply.answer.join(' '), at: Date.now(), reply });
    return reply;
  }

  /** Clears the conversation. Nothing was persisted, so nothing else is needed. */
  reset() {
    this.history = [];
  }

  /**
   * The matcher, without touching history — used by `ask` and by tests.
   * @param {string} raw
   * @returns {AuraReply}
   */
  reply(raw) {
    const query = normalise(raw);

    if (!query) {
      return {
        kind: 'fallback', query: raw, topicId: null, title: 'Ask me something',
        confidence: 0,
        answer: ['Type a question about Aura, the APK, DNS filtering or AETHER — for example, “What is Aura?”'],
        points: [], link: null, followUps: this.suggestions().slice(0, 3), matched: []
      };
    }

    if (GREETINGS.test(query)) {
      return {
        kind: 'smalltalk', query: raw, topicId: null, title: 'Hello',
        confidence: 1,
        answer: ['Hello. I answer questions about Aura, the Android build and how this platform filters DNS — locally, in this tab.'],
        points: [], link: null,
        followUps: this.suggestions().slice(0, 3), matched: ['greeting']
      };
    }

    if (THANKS.test(query)) {
      return {
        kind: 'smalltalk', query: raw, topicId: null, title: 'You are welcome',
        confidence: 1,
        answer: ['Any time. If you are about to install the APK, read the verification steps in the download card first.'],
        points: [], link: null,
        followUps: ['How do I verify the download?', 'What are your limits?'], matched: ['thanks']
      };
    }

    if (FAREWELL.test(query)) {
      return {
        kind: 'smalltalk', query: raw, topicId: null, title: 'Goodbye',
        confidence: 1,
        answer: ['Goodbye. Nothing from this conversation is stored — closing the tab clears it.'],
        points: [], link: null, followUps: ['What is Aura?'], matched: ['farewell']
      };
    }

    if (looksLikeHostname(query)) {
      return {
        kind: 'answer', query: raw, topicId: 'aether', title: 'That looks like a hostname',
        confidence: 0.9,
        answer: [
          `“${raw}” is shaped like a hostname. Aura does not score domains itself — AETHER does, with named signals and published weights.`,
          'Open AETHER AI and paste it there: you will get a risk score, the rule that matched (if any), and the evidence behind every point.'
        ],
        points: ['AETHER scores; Aura explains. Keeping them separate means an assistant can never change a verdict.'],
        link: { kind: 'page', page: 'aether', label: 'Open AETHER AI' },
        followUps: ['What is AETHER?', 'How does DNS filtering work?'], matched: ['hostname']
      };
    }

    const ranked = this.ranked(raw);
    const best = ranked[0];
    const confidence = best ? Math.min(1, best.score / SCORE_CEILING) : 0;

    if (!best || confidence < this.floor) {
      return this.fallback(raw, ranked);
    }

    return {
      kind: 'answer',
      query: raw,
      topicId: best.topic.id,
      title: best.topic.title,
      confidence: Number(confidence.toFixed(2)),
      answer: [...best.topic.answer],
      points: [...(best.topic.points || [])],
      link: best.topic.link || null,
      followUps: [...(best.topic.followUps || [])].slice(0, 3),
      matched: best.matched.slice(0, 6)
    };
  }

  /**
   * Declines honestly and hands over the nearest topics.
   * @param {string} raw
   * @param {{topic: import('./knowledge.js').AuraTopic, score: number}[]} ranked
   * @returns {AuraReply}
   */
  fallback(raw, ranked) {
    const near = ranked.slice(0, 3).map((entry) => entry.topic.question);
    return {
      kind: 'fallback',
      query: raw,
      topicId: null,
      title: 'Outside what I cover',
      confidence: 0,
      answer: [
        'That one is outside the answers I carry. I would rather say so than improvise: I answer from a reviewed knowledge base about Aura, the APK, DNS filtering and AETHER.',
        'If you were asking about something else, the Capabilities page documents exactly what this platform does — including what it does not do.'
      ],
      points: near.length ? [`Closest topics: ${near.join(' · ')}`] : [],
      link: { kind: 'page', page: 'status', label: 'Open Capabilities' },
      followUps: near.slice(0, 3),
      matched: []
    };
  }
}

export default AuraAssistant;
