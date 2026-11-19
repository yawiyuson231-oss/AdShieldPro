# Android AI Agent

Open **Security → AI Agent**. Type one request, such as **“Check my phone’s protection”**, then tap
**Suggest a check**. Review the proposed action and approve or cancel it. To start a combined review
without typing, tap **Review phone, DNS and apps**. **Choose a check instead** lists the other tasks.
Both entry points use the same confirmation as a model suggestion.

The small task model is bundled in the APK and classifies requests on the phone. There is no AI
account, key, model download, prompt upload or cloud inference. This is not a chatbot: it picks from
the checks below, or gives no suggestion if unsure. Ask for checks one at a time. The app's actual
checks, not the model, produce the findings.

| Request example | What approval allows |
| --- | --- |
| **Check my phone’s protection** | Read current AdShield protection, DNS activity summaries (when enabled), connection and device readings. Missing readings stay unknown. |
| **Audit my apps** | Inspect permission declarations and install sources of apps visible to AdShield. No private app-file access or uninstall. |
| **Security review** | Run the three local specialists below. No network requests, new permissions, scan-history entry or settings change from this review. |
| **Check a link** | Type or paste a single URL in the confirmation. Check it locally without opening it. The model cannot supply a URL. |
| **Scan a file** | Pick one file with Android's document picker. AdShield reads up to 24 MiB of the selected file into a temporary copy, checks it locally and removes the copy. It never launches, installs, uploads or modifies the original. A cloud document provider may fetch the file you chose. |
| **Test DNS speed** | Send a real `example.com` lookup to each built-in resolver (and your custom resolver if selected) using your configured DNS protocol. Resolver operators can see the DNS lookup and normal connection metadata. Task text and results are not sent. The benchmark never switches your provider or falls back to plaintext from an encrypted mode. |
| **Turn on DNS Alias Shield** | Change only AdShield's Alias Shield setting. Review or turn it off in DNS settings. |

## How Security review works

- **Phone protection** reads AdShield's runtime status, passive Android network and device readings,
  and local activity summaries when available. It respects the detailed DNS logging preference.
- **Saved DNS policy** checks the selected protocol, resolver plan and eligible backups, DNSSEC mode,
  Alias Shield, allowlist-only setting, and saved network and app exceptions. It doesn't probe a
  resolver or confirm which settings the live tunnel applied. DNSSEC reporting is upstream evidence,
  not local signature-chain validation.
- **App metadata** inspects declarations and install-source readings for Android-visible packages.
  It counts unreadable entries separately. A declaration is not a grant or evidence of compromise.

These are fixed read-only specialists, not three language models. They run independently with
cooperative deadlines (phone: 8 seconds; DNS: 5 seconds; apps: 30 seconds). If one fails or times out,
completed evidence remains available. Canceling the whole review discards that run; an Android system
read already in progress may need to return before cancellation completes.

The coordinator matches **exact package IDs** between all inspected apps with medium- or high-risk
indicators and saved VPN exclusions or **Allow all DNS** rules. It reports the full match count and
shows up to four examples; the separate app summary shows up to eight flagged apps. Missing app or
policy evidence is not a zero-match result. The report also flags saved **Block all DNS** rules that
overlap with VPN exclusions. An exclusion only matters if it was applied to the tunnel, and a DNS rule
only matters for a request that enters it. For those requests, allowlist-only mode can block names
before an app's **Allow all DNS** rule takes effect. Check again after changing settings or networks.

Recommendations explain the evidence and link to existing controls. They do not apply changes. Any
suggested Agent action, including a live DNS benchmark, needs its own separate approval.

Use **Cancel check** to stop an ongoing read or benchmark. A sent query cannot be recalled. The
Agent does not start scheduled work. Leaving the Agent tab dismisses pending approvals and its latest
result. The Android file picker can return only the file chosen for its approval. An earlier build's
saved AI connection is removed when this build starts; this cannot revoke keys at the original provider
or erase requests it already received. Other provider settings are not changed.

A clean result means the checks found no matching indicators, not that a device, app, link or file
is guaranteed safe. DNS benchmark latency measures a lookup, not bandwidth, privacy or geolocation.
See the [Android Agent roadmap](AETHER_AGENT_ROADMAP.md) for work that is **not** implemented yet.

## On-device smoke checklist

1. On an emulator or test phone with airplane mode on, open **Security → AI Agent**. Tap **Review
   phone, DNS and apps**, then cancel the confirmation. Confirm no review runs. Repeat and approve:
   verify all three coverage entries, check that missing Android readings are labeled, and confirm
   that saved DNS settings and scan history did not change. To verify no requests from the review
   with networking enabled, capture on an isolated test setup and distinguish existing background DNS
   and scheduled work from the confirmed review interval.
2. In a disposable test profile, choose an app with a medium- or high-risk indicator in **Security →
   Apps**. Save an **Allow all DNS** rule for its exact package in **Settings → Per-App Firewall &
   Split-Tunnel**. Rerun the review and confirm the pair is labeled **saved**, not observed. Switch
   it back to filtered and confirm the pair disappears on the next run. No permission grant or live
   connection is needed. The JVM tests use synthetic app metadata to cover this case independently.
3. Ask for **“Audit my apps, then test DNS speed”**. Confirm no plan, suggestion or network request.
   If a result offers **Run DNS benchmark**, tap it and confirm a new approval is required; cancel it.
4. Choose **Check a link**. Confirm the approval dialog starts empty and the link is not launched.
5. Choose **Scan a file**, approve and cancel Android's picker. Repeat, choose a small local file and
   check the result. Try a file over 24 MiB: it must be refused, not partially scanned.
6. Start a review, tap **Cancel check** or background the app before it completes, and confirm that
   no canceled result or stale approval can run on return. Check the report at large font sizes.
7. Enable network access and approve **Test DNS speed** separately. Check that it shows the selected
   protocol, live timings or failures, and does not change the configured resolver. With encrypted DNS
   unable to connect, it must report failures rather than silently send the probe over UDP/TCP.
