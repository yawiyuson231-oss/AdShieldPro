# AdShield Pro Android Agent roadmap

**Technical and AI direction · November 2026**

Make the Agent the fastest way to answer **“Is my protection doing what I intended, and what should I
review next?”** Every important claim should say what was observed, what was merely configured, and
what Android did not let us check. Better answers and safer actions matter more than more models.
This roadmap covers the Android Agent, not the browser platform's separate AETHER system.

## Implemented

**Security → AI Agent → Review phone, DNS and apps** runs one approved workflow. The bundled intent
model can also suggest **Security review**, but can't choose targets, authorize tools, or score threats.

| Component | Input and job | Boundary |
| --- | --- | --- |
| Phone protection specialist | Local tunnel status, passive Android readings and permitted summaries; identifies protection interruptions and relevant device context. | No active network probe. Missing readings stay unknown. |
| DNS policy specialist | Saved resolver plan and filtering settings, plus the current tunnel's in-memory receipt for accepted/rejected VPN exclusions. | Setup evidence only. No lookup, observed traffic, or claimed per-query rule enforcement. |
| App-risk specialist | Android-visible package declarations and install-source evidence; counts inspected and unavailable metadata. | Not a malware verdict, proof of permission use, or access to private app data. |
| Coordinator | Runs the three readers independently, joins indicators to saved exceptions by exact package ID, and ranks evidence-linked follow-ups. | Fixed local code. No data sent, policy changes, background tasks or model-to-tool calls. |

For example, the report can flag an app with medium- or high-risk metadata indicators that also has
an **Allow all DNS** rule. That changes what to review first, not what to block. Coverage and missing
readings are part of the report. One approval covers these three reads only; a follow-up benchmark or
settings action is a separate decision. See the [usage and device checklist](PHONE_AGENT.md).

The Android CI suite now exercises the real Agent UI on an API 29 emulator, including canceled and
expired approvals, an offline report, leaving the Agent, and the real VPN's receipt across setup,
changed settings, rebuild, pause/resume and stop. A separate test uses a controlled reader to verify
in-flight cancellation. This does not validate physical handsets, all network transitions or packet
coverage. See [the test scope](TESTING.md#android-agent-device-tests).

## What to build next, in order

| Priority | Proposed delivery | Evidence required before shipping |
| --- | --- | --- |
| **P0 · Validate on handsets and protect the release channel** | Extend API 29 coverage to a low-memory handset and a current handset, including actual network switches, Android revocation, IPv6 routing and configuration changes. Keep public previews separate from private Secure signing. | Device traces for approval, cancel, VPN transitions and controlled egress. Verify fresh install and upgrade; CI test-signing is not production signing. |
| **P1 · Extend applied evidence only where measurable** | Keep setup receipts separate from per-query policy decisions. Where Android provides reliable attribution and logging is allowed, consider bounded summaries tagged with source, freshness and unknown attribution. | Verify receipt and per-query summaries on controlled fixtures; never infer packet or per-app coverage from a configuration flag. |
| **P2 · Make safe fixes reviewable** | Add a policy preview specialist that computes a before/after diff using the existing DNS policy evaluator. Start with one narrowly scoped change and show what it cannot predict. Bind approval to exact inputs, recheck the settings revision before applying, and provide undo without overwriting later changes. | Test policy precedence, no-op, stale/double approval, timeout, partial failure, undo, and app compatibility. No silent auto-block, uninstall, permission grant or rollback over a newer edit. |
| **P3 · Expand defensive evidence, then models** | Run link and file specialists only on one explicitly supplied URL or picker-selected file. Use versioned local indicators with source and age; report stale or conflicting evidence instead of hiding it. Improve English and Taglish task routing and abstention. Evaluate optional on-device summarization of the structured evidence if it measurably helps users. | Separate task-routing and threat-quality test sets, privacy/retention checks, false-positive review, and measured low-end phone cost. Generated prose must not introduce new evidence or authorize an action. Keep deterministic reports as the fallback. |

Do not restore open-ended cloud planning or add arbitrary network requests, accessibility privileges,
TLS interception, or raw log uploads to make the Agent look more capable. Fixed workflows with typed
inputs, explicit approval, bounded resources and traceable evidence are the default.

## Scorecard before making comparative claims

No market ranking has been established. Launch or unit tests establish behavior only in the scenarios
run, not threat-detection quality or protection on all devices. Publish a reproducible scorecard before
claiming AdShield is better than another app:

- **Protection correctness:** replay labeled benign and blocked DNS policy fixtures; measure missed
  blocks, false blocks, rule precedence, and failover behavior. Separately verify routing and coverage
  on Wi-Fi, mobile data, IPv4/IPv6, VPN transitions and captive portals. Label unsupported cases.
- **Recommendation quality:** have reviewers label real consented or synthetic incidents, including
  legitimate permission-heavy apps and necessary exceptions. Report precision for ranked follow-ups,
  recall on defined risks, and how often the Agent correctly says it lacks evidence. Test dated,
  source-separated link/file datasets without opening live targets or executing samples.
- **Model quality:** keep examples split by template, language and source. Report wrong suggestions,
  supported requests declined, and unsupported actions correctly declined separately. An intent
  holdout is not a malware or phishing benchmark.
- **Safety and performance:** release gates should reject unauthorized side effects, stale approvals,
  and silent DNS downgrade in tested workflows. Record p50/p95 review time, unavailable-read rate,
  DNS latency and failure rate, battery and memory with and without protection. Check egress under
  controlled conditions; don't infer privacy from airplane mode alone.
- **Fair comparisons:** pin app versions, phone, OS, network, resolver, filter coverage and scenarios;
  repeat trials and report sample sizes and uncertainty. Compare only overlapping features, disclose
  constraints and misses, and get independent verification before a superiority claim.

**Next implementation:** start with a read-only preview for restoring one saved VPN exclusion to
filtered. It should show the change, the need for a successful tunnel rebuild, and what the Agent
can't predict. Do not add automatic fixes or a new execution path before that preview is tested.
