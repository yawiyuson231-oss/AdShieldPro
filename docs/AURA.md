# Aura AI Assistant

Aura is the assistant surface of the OmniShield X / AdShield Pro web platform. It has its own
page (`app/#aura`), its own modules (`aura/`) and its own test file (`tests/unit/aura.test.mjs`),
and it is reachable in one click from every page through the **✦ Aura** launcher.

Two things share the name and must not be confused:

| | What it is | Where |
|---|---|---|
| **Aura preview** (this repository) | A deterministic, offline retrieval assistant over a curated knowledge base, running entirely in the browser tab | `aura/` + `index.html#page-aura` |
| **Aura Android build** | `aura-1.0.582.apk`, distributed as a sideloaded APK through MediaFire | `aura/release.js` (manifest), download card on the page |

This document covers both, and states plainly what the repository can and cannot vouch for.

---

## 1. Why retrieval instead of a language model

The rest of the platform earns trust by being inspectable: every AETHER score names its signals,
every capability row has evidence, and `scripts/verify.mjs` fails the build if a claim drifts.
A chat bubble that streams tokens from a third-party endpoint would break that contract in one
move — the question leaves the device, the answer cannot be audited, and the failure mode (a
confident, wrong sentence) is invisible.

So Aura is built the other way around:

1. **Curated corpus.** `aura/knowledge.js` holds 13 reviewed entries. Each has an id, a canonical
   question, retrieval vocabulary, phrase anchors, an answer, optional evidence bullets, optional
   deep link and follow-up questions.
2. **Explainable matcher.** `aura/assistant.js` normalises and tokenises the question, drops
   stopwords, applies a light stemmer, then scores every entry on phrase hits (weight 3), keyword
   hits (1) and distinctive title hits (1). The top score becomes a 0–1 confidence.
3. **A floor, not a guess.** If the best confidence is under `CONFIDENCE_FLOOR` (0.34), the reply is
   a *decline* that names the closest topics — never a composed answer.
4. **Determinism.** Same question plus same corpus yields a byte-identical reply, which is what
   makes the behaviour testable at all.

The trade-off is stated rather than hidden: Aura handles paraphrase poorly compared with a model.
That is why the UI offers starter prompts and a clickable topic index, and why a
question like "what is the capital of France" is declined instead of answered.

## 2. Module map

| File | Responsibility |
|---|---|
| `aura/knowledge.js` | Introduction copy, four pillars, 13 knowledge entries, starter prompts, explicit limits |
| `aura/release.js` | Release manifest: artifact name, version, host, allowlist check, integrity summary |
| `aura/assistant.js` | Normalisation, stemming, scoring, `AuraAssistant` (`ask`, `reply`, `ranked`, `reset`) |
| `aura/view.js` | The separate UI: introduction, conversation, download card, topic index |
| `index.html#page-aura` | Section shell, static introduction, accessible landmarks |
| `app.js` → `renderAura()` | Owns the assistant instance (conversation survives navigation) and wires the jump controls |

The view builds DOM only through `ui/dom.js`, whose helpers write with `textContent`. There is no
`innerHTML`, no `eval`, no `new Function`, and no network primitive anywhere in `aura/`.

## 3. Properties enforced by CI

`scripts/verify.mjs` adds gates that fail the build if any of these regress:

- Aura has a navigation target, a labelled `<section>`, and the launcher is wired in `app.js`.
- The introduction, conversation, download and topic surfaces all exist in `index.html`.
- `aura/*.js` contains no `fetch`, `XMLHttpRequest`, `WebSocket`, `sendBeacon` or clipboard *read*.
- The download URL is `https:` on an allowlisted host (`isAllowedDownloadUrl`).
- `AURA_RELEASE.fileName` equals `aura-${AURA_RELEASE.version}.apk`.
- The manifest never carries a fabricated `sha256` or `bytes`, and no 64-hex string appears in it.
- Knowledge entries have unique ids and each is answerable (answer + ≥3 keywords + ≥1 phrase).
- The live engine answers a download question, answers a privacy question, and **declines** an
  off-topic question (`what is the capital of France`).

`tests/unit/aura.test.mjs` adds engine-level checks: determinism, history/reset, hostname routing
to AETHER, decline behaviour for three off-topic questions, every starter prompt answerable, and
"no invented hash or file size in any answer".

`tests/integration/ui.test.mjs` drives the real page in jsdom: it asserts the introduction text,
the safe `rel="noopener noreferrer"` download link, that a real question produces a citation and a
confidence badge, that clearing erases the conversation, and that the launcher hides on its own page.

## 4. Release policy for the Android build

`aura/release.js` is the single source of truth. The download card links to the MediaFire *file
page*, not to a scraped direct link, because a direct link is unauditable and expires.

Deliberate omissions:

- **`sha256: null`** — the uploader has not published a checksum. The UI says "SHA-256 not published
  for this build" and tells the visitor to verify the file themselves. Printing an invented hash
  would look identical to a correct one to anyone who is not checking.
- **`bytes: null`** — no size claim, so no false "file size mismatch" alarm.

Consequences are documented in the UI rather than glossed over: sideloading means no store review,
"install unknown apps" must be granted and then revoked, and the link on the page is the only
distribution channel this site endorses.

## 5. Adding an answer

1. Append an entry to `AURA_TOPICS` in `aura/knowledge.js` — id, canonical question, ≥3 keywords,
   ≥1 phrase, at least one paragraph, optional points/link/follow-ups.
2. Keep every sentence checkable against this repository. No marketing claims, no invented numbers.
3. Run `npm run ci`. If the entry is unreachable by any realistic phrasing, the starter-prompt and
   verify probes will tell you; add phrase anchors rather than lowering `CONFIDENCE_FLOOR`.

Nothing else needs editing: the topic index, the fallback suggestions and the UI all read the corpus.

## 6. Known limits

- Paraphrase coverage is bounded by the corpus. A model would generalise further; this does not.
- The preview explains the platform — it does not execute actions, score domains (AETHER does that)
  or inspect the device.
- The Android APK is third-party code from this publisher. This repository can describe the
  download; it cannot audit a binary it did not build.
