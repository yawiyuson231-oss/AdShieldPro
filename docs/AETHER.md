# AETHER — threat intelligence methodology

AETHER is the platform's decision layer. This document states exactly what it computes,
how each number is produced, and where it is weak. The UI displays these same facts.

## 1. Design contract

1. **Every point of score is attributable.** `analyze()` returns `signals[]`; each entry has
   `id`, published base weight, feedback-adjusted weight, strength, contribution and a
   human-readable `evidence` string. The contributions sum to `rawScore` (tested).
2. **Published weights sum to 100.** `SIGNAL_WEIGHTS` in `aether/reputation.js`; the test
   suite and `scripts/verify.mjs` both fail if they stop summing to 100.
3. **Advisory only.** `enforcement.advisoryIsEnforced === false` always. Enforcement is
   the deterministic filter engine's job.
4. **Guardrails beat scoring.** A curated-popular domain is capped at 10/100, a user
   allowlist at 5/100, a feed exception at 10/100 — no accumulation of lexical coincidences
   can turn them into "malicious".
5. **Absence of evidence is reported as absence**, not as safety.

## 2. Signals and weights

| Signal | Weight | What it measures | Weakness |
|---|---|---|---|
| `threatFeedMatch` | 40 | rule in a curated malware/phishing feed | feed quality is upstream's responsibility |
| `feedMatch` | 20 | rule in a curated ad/tracker feed | ads are not malware; classified separately |
| `typosquat` | 10 | OSA distance / homoglyph / brand-affix to a known brand | short brands and dictionary words collide |
| `classifier` | 7 | lexical Naive Bayes score | sees only the hostname string |
| `threatTokens` | 6 | account-security vocabulary in the name | legitimate login pages also match |
| `homoglyph` | 5 | mixed scripts / look-alike characters | IDN legitimately exists |
| `dga` | 4 | entropy + consonant runs + digit ratio | modern DGAs defeat it |
| `lexical` | 3 | hyphens, depth, label length, digits | CDNs use these patterns |
| `highAbuseTld` | 2 | TLD appears in public abuse rankings | many legitimate services use them |
| `newness` | 2 | first observed < 24 h ago (local observation store) | says nothing about intent |
| `altTld` | 1 | brand name on a non-canonical TLD | large brands own many TLDs |

### Evidence floors

Some evidence is stronger than a weighted sum of heuristics, so a confirmed feed match
establishes a minimum score (`EVIDENCE_FLOORS`):

- malware/phishing feed match → **80/100** ("high confidence")
- ad/tracker feed match → **40/100** (privacy risk, explicitly *not* malware)

Floors are listed in the report (`floors[]`), explained in the summary line, and overridden
by guardrails.

### Verdict bands

| Score | Verdict | Advisory action |
|---|---|---|
| 0–19 | No evidence of risk | allow |
| 20–44 | Unusual | monitor |
| 45–69 | Suspicious | monitor |
| 70–89 | Likely malicious | recommend block |
| 90–100 | High confidence threat | recommend block |

## 3. The lexical classifier

**What it is.** A multinomial Naive Bayes classifier over hybrid features:
`T:<tld>`, `L:<label>`, `W:<word>`, `C:<trigram>` (with `^`/`$` boundary markers).
Presence (Bernoulli-style) counting, Laplace smoothing α = 0.1, equal class priors.

**Training data (on-device, at runtime).**
- positives: sampled domains from the loaded feeds (ad/tracker hundreds of thousands → 6,000-sample strided subset)
- negatives: the curated 541-entry popular-domain list in `aether/data.js`

**Vocabulary selection.** Tokens are ranked by *normalised class imbalance × log support*
rather than raw frequency. Frequency ranking is dominated by the much larger positive
corpus and discards the tokens that distinguish legitimate domains — that mistake was made,
measured, and fixed (AUC 0.826 → 0.904 with α 1.0 → 0.1 + discriminative ranking).

**Evaluation.** Seeded 75/25 split; the holdout is never used for training. Reported:
confusion matrix, precision, recall, F1, specificity, accuracy, AUC (tie-aware Mann-Whitney),
and a best-F1 sweep. The **operating threshold** is chosen on the holdout as the highest
threshold whose specificity still meets the target (0.9), so the model's operating point is
a measured false-positive constraint, not a guess.

**Measured on this repository's data** (`npm test` → `tests/unit/classifier.test.mjs`):
AUC ≈ 0.90, precision ≈ 0.99, specificity ≈ 0.92 at the operating point, with recall ≈ 0.75.
Those floors are asserted by tests; a regression fails CI.

**Known weakness, stated in the UI.** The model only sees characters. Legitimate but
unfamiliar domains (`myblog.example`) can score as "ad-like". That is why its weight is 7/100,
why known-popular domains are hard-capped, and why nothing is blocked on model evidence alone.

## 4. Typosquat detection

- Optimal string alignment (Damerau–Levenshtein with transpositions), early-exit band.
- Homoglyph skeleton: Cyrillic/Greek look-alikes → Latin, `rn`→`m`, `vv`→`w`, `0`→`o`, `1`→`l`.
- Punycode decoded locally (RFC 3492) so `xn--80ak6aa92e` is seen as Cyrillic `аррӓе`.
- Placement analysis against the **registrable** domain: `paypal.com.verify.tk` is flagged
  because the brand sits in the subdomain of a domain the brand does not own.
- Brand-affix detection (`paypal-login`, `secure-apple`) using a curated affix list.
- Severity scale 0–3 with an explanation per match; the corpus test asserts ≤ 5 of 541
  popular domains are flagged (currently 0 for the exact-match guard set).

## 5. Adaptive weighting (real feedback, bounded)

Reporting a false positive:
1. adds a reversible user allow rule (`undoFalsePositive()` restores filtering — regression-tested),
2. increments that signal's false-positive counter,
3. recomputes its multiplier as `max(0.4, 1 − 0.6 × errorRate)` once ≥ 3 verdicts exist.

A signal can lose confidence but can never be silenced: the floor is 40 % of the published
weight. The current multipliers are displayed on the AETHER page.

## 6. What AETHER does not do

- No cloud model, no server-side enrichment, no WHOIS/age data (only local first-seen).
- No content inspection, no TLS interception, no certificate analysis.
- No claim that a high score *proves* malice; the copy is written accordingly.
