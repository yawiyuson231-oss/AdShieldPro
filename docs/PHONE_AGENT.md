# Android AI Agent

Open **Security → AI Agent**. Type one request, such as **“Check my phone’s protection”**, then tap
**Suggest a check**. Review the proposed action and approve or cancel it. You can also use **Choose
a check instead** without typing anything. Choosing a check opens the same confirmation.

The small task model is bundled in the APK and classifies requests on the phone. There is no AI
account, key, model download, prompt upload or cloud inference. This is not a chatbot: it picks from
the checks below, or gives no suggestion if unsure. Ask for checks one at a time. The app's actual
checks, not the model, produce the findings.

| Request example | What approval allows |
| --- | --- |
| **Check my phone’s protection** | Read current AdShield protection, DNS activity summaries (when enabled), connection and device readings. Missing readings stay unknown. |
| **Audit my apps** | Inspect permission declarations and install sources of apps visible to AdShield. No private app-file access or uninstall. |
| **Security review** | Run both the phone check and app audit in one read-only report. No network test or settings change. |
| **Check a link** | Type or paste a single URL in the confirmation. Check it locally without opening it. The model cannot supply a URL. |
| **Scan a file** | Pick one file with Android's document picker. AdShield reads up to 24 MiB of the selected file into a temporary copy, checks it locally and removes the copy. It never launches, installs, uploads or modifies the original. A cloud document provider may fetch the file you chose. |
| **Test DNS speed** | Send a real `example.com` lookup to each built-in resolver (and your custom resolver if selected) using your configured DNS protocol. Resolver operators can see the DNS lookup and normal connection metadata. Task text and results are not sent. The benchmark never switches your provider or falls back to plaintext from an encrypted mode. |
| **Turn on DNS Alias Shield** | Change only AdShield's Alias Shield setting. Review or turn it off in DNS settings. |

Use **Cancel check** to stop an ongoing read or benchmark. A sent query cannot be recalled. The
Agent does not start scheduled work, and leaving it dismisses pending approvals and its latest
result. The active Android file picker can return only the file chosen for that approval. An earlier
build's saved AI connection is removed when this build starts; this cannot revoke keys at the
original provider or erase requests it already received. Other provider settings are not changed.

A clean result means the checks found no matching indicators, not that a device, app, link or file
is guaranteed safe. DNS benchmark latency measures a lookup, not bandwidth, privacy or geolocation.

## On-device smoke checklist

1. Open **Security → AI Agent** with airplane mode on. Request **“Audit my apps”** and cancel the
   confirmation. Confirm no audit runs. Repeat and approve; check visible and unavailable counts.
2. Ask for **“Audit my apps, then test DNS speed”**. Confirm no plan, suggestion or network request.
   Choose **Security review** manually to see one combined read-only report.
3. Choose **Check a link**. Confirm the approval dialog starts empty and the link is not launched.
4. Choose **Scan a file**, approve and cancel Android's picker. Repeat, choose a small local file and
   check the result. Try a file over 24 MiB: it must be refused, not partially scanned.
5. Start a check, tap **Cancel check** or background the app, and check that no stale approval can
   run on return.
6. Enable network access and approve **Test DNS speed**. Check that it shows the selected protocol,
   live timings or failures, and does not change the configured resolver. With encrypted DNS unable to
   connect, it must report failures rather than silently send the probe over UDP/TCP.
