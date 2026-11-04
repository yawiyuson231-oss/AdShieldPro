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
| `threatFeedMatch` | 38 | rule in a curated malware/phishing feed | feed quality is upstream's responsibility |
| `feedMatch` | 18 | rule in a curated ad/tracker feed | ads are not malware; classified separately |
| `typosquat` | 16 | OSA distance / homoglyph / brand-affix to a known brand | short brands and dictionary words collide |
| `classifier` | 7 | lexical Naive Bayes score | sees only the hostname string |
| `homoglyph` | 6 | look-alike characters (paypa1, g00gle, Cyrillic аpple) | IDN legitimately exists |
| `threatTokens` | 6 | account-security vocabulary in the name | legitimate login pages also match |
| `dga` | 3 | entropy + consonant runs + digit ratio | modern DGAs defeat it |
| `lexical` | 2 | hyphens, depth, label length, digits | CDNs use these patterns |
| `highAbuseTld` | 2 | TLD appears in public abuse rankings | many legitimate services use them |
| `altTld` | 1 | brand name on a non-canonical TLD | large brands own many TLDs |
| `newness` | 1 | first observed < 24 h ago (local observation store) | says nothing about intent |

### Evidence floors

Some evidence is stronger than a weighted sum of heuristics, so a confirmed feed match
establishes a minimum score (`EVIDENCE_FLOORS`):

- malware/phishing feed match → **80/100** ("high confidence")
- ad/tracker feed match → **40/100** (privacy risk, explicitly *not* malware)
- homoglyph impersonation of a known brand → **55/100** ("suspicious")
- brand inside a subdomain of a domain it does not own → **55/100**
- brand combined with an account-security word → **45/100**
- one-edit brand typo (`gogle.com`) → **30/100** ("unusual") — deliberately *not* a block
  recommendation, because independent near-miss registrations exist

Floors are listed in the report (`floors[]`), explained in the summary line, and overridden
by guardrails.

### Verdict bands

| Score | Verdict | Advisory action |
|---|---|---|
| 0 | No evidence of risk | allow |
| 1–19 | Minimal evidence | allow |
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
measured, and fixed (α 1.0 → 0.1 plus discriminative ranking took AUC from 0.826 to 0.904
under the earlier two-way split; the numbers quoted below are the current three-way ones).

**Evaluation.** Seeded **three-way split**: fit / tuning / holdout (60 / 20 / 20). The token
counts and likelihoods are fit on the fit split, the **operating threshold is chosen on the
tuning split** (highest threshold whose specificity still meets the 0.9 target), and every
headline number — precision, recall, specificity, F1, AUC (tie-aware Mann-Whitney), the
confusion matrix and the best-F1 sweep — is measured once on the **holdout**, which never
influences selection.

Selecting the threshold on the holdout was the earlier design, and it made the reported
specificity an in-sample number (the target could be "met" while the holdout actually sat
below it). It is now impossible to report a target the holdout did not earn: when the
holdout specificity lands under the target, `atThreshold.unreachable` is set with a reason
string and the UI prints it instead of the target.

**Evidence damping.** Scores are `sigmoid(prior + ΣΔ / tokens^0.25)`. Un-damped binary NB
pins to 1.0 on long hostnames (a 12-token name multiplies every log-likelihood ratio), which
destroys any fixed threshold. The exponent 0.25 was chosen on the **tuning** AUC (0.8786 vs
0.8778 at 0.5 and 0.8693 at 1.0); the holdout was not consulted.

**Measured on this repository's data** (holdout, `tests/unit/classifier.test.mjs`):
AUC ≈ 0.857, precision ≈ 0.986, specificity 0.898, recall ≈ 0.663, F1 ≈ 0.793 at the
operating threshold 0.96. Balanced accuracy is 0.780. The 0.9 specificity target is **not** reached out-of-sample
(0.898 — one held-out legitimate domain short), and the UI says so. Recall at that operating
point is 0.66, which is exactly why the classifier carries only 7/100 of the reputation
score and never blocks on its own. Floors asserted by tests: AUC ≥ 0.85, precision ≥ 0.95,
specificity ≥ 0.85, recall ≥ 0.6; a regression fails CI.

**Base-rate honesty.** The evaluation corpus is roughly 11:1 positive-to-negative, so its
precision of 0.986 is not the precision you would see on real traffic. The engine converts
recall and specificity into precision at plausible base rates and shows both in the UI:
**0.062 at a 1% base rate** and **0.419 at a 10% base rate**. In other words, on ordinary
browsing a flagged domain is usually *not* malicious — which is precisely why this score is
7/100 of the reputation total and why it can never block, allowlist or enforce anything.

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
