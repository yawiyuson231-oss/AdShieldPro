# AETHER Security Agent (Android)

Open **Security → Agent**.

- **Security review → Run review** checks protection and then app risks. Watch the two steps and
  tap **View latest result** to see what was checked, what was flagged, and what was unavailable.
  Tap **Review in Android Settings** on a flagged app to open its App Info page yourself.
- Type a task and tap **Find task offline**, or **Ask online AI** if you connected a provider.
  For a multi-step request, tap **Try a guided plan** or use “then” between checks and choose
  **Find task offline**. You can also choose a tool directly.
- To check a file, choose **Scan a file → Choose file**. Pick **one** file in Android’s picker.
  AdShield analyzes a temporary local copy, not the rest of your storage.

| Try typing | What runs after you approve |
| --- | --- |
| “Security review” | Two fixed local steps: phone/protection readings and Android-visible app metadata. If one step fails or times out, the other can still report its evidence. |
| “Check my phone’s protection” | A local snapshot of AdShield settings, recent aggregate activity, connection, storage, memory, and heat. **Check my phone** runs this same read directly. |
| “Audit my apps” | Reads permissions, declared component bindings and install metadata for apps Android exposes. Shows inspected and skipped counts and explains medium- or high-risk flags. |
| “Scan a file” | Inspects a user-selected file (up to **24 MiB**) for static indicators. Does not launch, install, upload, change or delete the original. |
| “Check a link” | Asks you for **one** HTTP(S) link or domain in a separate field. Checks active threat lists and local phishing indicators without visiting the link. |
| “Test DNS speed” | Sends a fixed `example.com` query to resolver presets (including a selected custom resolver) using the configured protocol. Shows lookup timings and failures, not Wi-Fi speed. Never switches resolvers. |
| “Turn on DNS Alias Shield” | The one tool that writes a setting. It enables AdShield’s existing Alias Shield and clears the resolver cache. Filtering still requires active protection. Turn it off again in DNS settings. |

### What the results mean

The model **chooses a task**; AdShield’s Android readers and scanners **supply the evidence**.
Neither model supplies targets, verdicts, or tools outside the allowlist. The on-device planner
puts individually recognized checks in the order you requested. The Agent cannot run commands,
browse links, read other apps’ private data, uninstall apps, or schedule work on its own.

- **Review:** The phone and app steps have independent, cooperative time limits of 8 and 30 seconds.
  A device reading that Android doesn't expose is not assumed healthy. Apps counted as inspected
  had readable package metadata; not every app or install source is necessarily visible.
  Declarations are not permission grants, observed behavior, or proof of malware.
- **File:** The byte limit is checked against actual reads, not the provider’s reported size. A
  larger file is rejected, not scanned as a partial copy. The Agent uses app-private cache
  storage and attempts to remove the copy on completion or cancellation. The result shows the
  copy size, matching indicators, and limits such as unavailable archive metadata. Archive checks
  cover entry metadata; `.apk` can also get static manifest and bounded code checks. This does not
  unpack nested packages, verify signatures cryptographically, or guarantee the file is safe.
  A cloud-backed picker may need its provider to make the chosen file available on the phone.
- **Stopping:** Use **Cancel check** on a running check. An in-progress Android read or network
  operation may take time to return, and DNS queries already sent cannot be recalled. Leaving the
  Agent dismisses pending local
  approvals and cancels these reads. A picker result cannot authorize a different or already-used
  task. **Stop waiting** cancels the online wait; the provider might already have received the text.
- **History:** Typed requests, separately entered links, and Agent results are not written to
  scan history. The standalone **Security → Apps / Files / Links** tools and **History** remain
  separate workflows.

The bundled on-device model is fitted to English and Taglish task examples. It ranks seven tasks
plus an unsupported class and can decline ambiguous wording. It needs no account, API key,
model download, root or new permissions. It is not a chatbot. If the model is unavailable or
doesn't match your request, choose a tool yourself.

## Guided plans

Try **Security → Agent → Try a guided plan**, or type **“Audit my apps, then test DNS speed”** and
select **Find task offline**. The planner recognizes **two or three** distinct checks in an explicit
order. Separate complete requests with `then`, `tapos`, semicolons, or new lines. For example:

- “Security review, then scan a file, then check a link”
- “Suriin ang seguridad ng cellphone ko tapos audit my installed apps”

1. Read the ordered steps and their scope. A plan does not start any check.
2. Tap **Review step 1** and confirm its exact action. Supply a file or link in that step's own
   picker or input. A DNS benchmark runs only when approved and uses `example.com`.
3. Read the receipt and choose what to do next. **Finished with limits** means a check returned
   partial evidence; **Needs retry or skip** means it didn't produce usable results. You can
   **View step … result**, retry with a fresh approval, skip the current step, or end the plan.
   The next step never runs automatically.

An unrecognized, conditional, overlapping, or setting-changing step rejects the plan instead of
silently running a subset. For example, use **Security review** or a separate **Audit installed
apps**, not both in one plan. To turn on DNS Alias Shield, make a separate request.

Planning runs on the phone with the same bundled model. Plan receipts stay in memory until you
close the plan or leave the Agent; they aren't uploaded or added to History. Putting the app in
the background cancels running checks and dismisses approval dialogs. The one Android picker
opened for an approved file step can still return its chosen file while the plan is open.
**Ask online AI** still suggests one task at a time; explicit plan requests are not sent.

## Optional: connect your own AI API

In **Security → Agent → Connect AI API**, choose a provider. Paste your key directly into the
app, not into the Agent's task field or a chat.

| Provider | What to enter |
| --- | --- |
| **Google Gemini** | A Gemini Developer API key from [Google AI Studio](https://aistudio.google.com/api-keys). Keep `gemini-3.5-flash-lite` or use a text model your project can access. AdShield uses Google's native `generateContent` endpoint with `x-goog-api-key`; no URL is needed. |
| **OpenAI** | An OpenAI API key and a text model ID that supports [Chat Completions](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create/) with `developer` messages and `max_completion_tokens`. The URL is set for you. |
| **Other compatible API** | Your gateway's HTTPS API base URL (for example, `https://api.example.com/v1`) or full `/chat/completions` URL, model ID, and bearer token. AdShield appends `/chat/completions` to a base URL as entered. Select `max_completion_tokens` instead of `max_tokens` if your provider requires it. |

A custom endpoint must accept non-streaming Chat Completions requests with `system` and `user`
messages, and return an assistant text choice. Not every API uses that format. Responses-only,
native Anthropic Messages and Vertex AI endpoints, HTTP-only servers, and routes that need keys
in the URL or extra authentication headers aren't supported directly. A compatible HTTPS gateway
can translate a different provider protocol.

1. Tap **Save & review test**. The key is saved locally. Review the provider, destination, model
   and fixed text (“Audit my installed apps”). Tap **Send test** to make one request, or **Cancel**
   to keep the settings without sending anything. You can retest from **Test API**.
2. The test passes only when the model returns the matching task ID. **No audit or other tool
   runs**, even if the model returns a different supported task.
3. To use the connection, type a task and tap **Ask online AI**. Review the exact text, model and
   destination. **Send** approves that request once. If the model suggests a task, approve the
   on-phone action separately. **Find task offline** and the direct tools don't need the API.

| If the test reports… | Check… |
| --- | --- |
| **Key or access rejected** | Paste the API key itself, not `Bearer` plus the key. Check that it belongs to the selected provider, can use the API, and has access to the model. |
| **Model or API route not found** | Copy the model ID from your provider. For a custom API, use the documented API base (including any version path) or the final Chat Completions URL. |
| **Quota, billing, or project requirement** | Check your provider's usage limits, billing, and project or region eligibility. A chat subscription alone may not include API access. |
| **Output token setting rejected** | In **AI API settings** for a custom provider, switch to the limit field it documents. Re-enter the key to save changes. |
| **No valid or finished task response** | Try a fast text model that supports the selected API, or use **Find task offline**. |
| **Connection, timeout, or certificate problem** | Check internet access and the HTTPS hostname and certificate. A timed-out request may still have reached the provider. |

A provider can charge for a test or online task request. It receives the approved text and fixed
task instructions via the reviewed endpoint, with the key sent in a header. AdShield does not
attach settings, app lists, results, activity, files, or links entered into the separate scanner.
The app rejects common web addresses, email addresses and IPs in online task text, but cannot
recognize every secret. AdShield does not follow redirects, replay the POST, display raw provider
errors, or execute provider text. Requests have a 40-second call limit and replies over 64 KiB
are rejected.

The provider, endpoint, model ID and key are stored together as Android Keystore-backed
ciphertext and aren't included in AdShield backups. Existing valid saved Chat Completions
connections remain under **Other compatible API** and keep using the `max_tokens` field. To switch
protocol settings, choose the new provider preset and re-enter your key. **AI API settings →
Disconnect** removes the saved connection locally; revoke the key with your provider if needed.
There is no bundled key or hosted AI service.
For a shared deployment, keep upstream keys on your own server and issue scoped gateway tokens.

### Phone evidence and limits

- **Protection:** AdShield’s reported VPN state and rule count, DNS transport, Alias Shield,
  exclusions, browser cookie settings, and scan and update settings.
- **Connection:** Android’s default network, validation, captive portal, and connected Wi-Fi
  security and signal when exposed. AdShield does not collect SSID or BSSID in this check or
  guess which connection lies behind a VPN.
- **DNS:** Up to 250 existing log rows from the past hour if detailed logging is enabled. p95
  requires five or more positive timings for unblocked, non-SERVFAIL queries. When logging is
  off, old detailed rows are not read.
- **Device and activity:** Android’s low-memory flag, storage available to AdShield, thermal
  status, aggregate DNS activity, and counts of retained scan records. No automatic cleanup,
  app killing, performance guarantee or assumption that past findings are current.

## Verification

```sh
python3 tools/train_aether_tasks.py --check
./gradlew :app:testDebugUnitTest \
  --tests 'com.adshield.pro.Aether*Test' \
  --tests 'com.adshield.pro.SecurityCenterTestSuite'
```

The model is reproducible from `tools/aether_agent/train.tsv` (411 authored examples, not collected
user data). On the 94-example development holdout, v2 matched **90**, made **no wrong task
suggestions**, and declined four supported requests. The holdout is not used in fitting; these are
regression results, not an independent estimate of real-world accuracy. The JVM tests exercise the
Kotlin model, guide composition and step approvals, both review deadlines, cancellation, partial
readings, byte limits, and static scanner results. Transport fixtures cover the Gemini and Chat Completions request
formats, reply parsing, legacy settings, cancellation and diagnostics. They do not test a live
API account.

### On-device smoke checklist

1. In airplane mode, type **Security review** and cancel the suggestion. Verify neither check runs.
   Approve it, verify both receipts and the current visible/inspected counts, and check that the
   review does not modify settings or add a History entry. If there is a flagged app, tap its App
   Info button and verify Android opens the matching package.
2. Cancel while a check runs. Try changing tabs and returning, and sending the app to the
   background. Verify no second review starts. Some in-progress Android reads can delay cancellation.
3. Select **Scan a file**. Back out of the picker; nothing should be scanned. Repeat with a small
   local text file, then with a file larger than 24 MiB. Verify the size or explicit rejection,
   and verify the original is unchanged. Rotate or leave during selection; a stale picker result
   should not start another scan. Check that **Security → Files** and **History** still work separately.
4. Check a harmless documentation link, such as `http://192.0.2.1/login/verify`, and verify that
   no browser opens. Approve a DNS benchmark while connected and confirm the resolver setting does
   not change. Cancel and then approve an Alias Shield change with the toggle initially off.
5. Check the phone with filtering on, paused and off. Disable detailed DNS logging; old rows
   should not appear in the report. Check that redacted readings are not presented as healthy.
6. Select **Google Gemini**, enter a key in the app and tap **Save & review test**. Cancel the
   review and check that the provider shows no request. Tap **Test API → Send test** and check
   that a pass does not open an audit or run a tool. Repeat with an invalid key or unknown model
   and verify the error, then confirm offline tasks still work.
7. Repeat with **OpenAI** or a compatible gateway. For a gateway, try its base URL as well as the
   full route and check the reviewed destination. Kill and reopen the app to check the stored
   connection, then disconnect and verify the **Ask online AI** button is gone. Approve an online
   file suggestion but dismiss the separate task approval; the picker should not launch.
8. Try a guided plan. Dismiss the first approval and verify nothing runs, then approve it and
   verify the second step waits. Open the first receipt after the second check or skip. Cancel
   a file picker in a plan and verify its step says **Needs retry or skip**. Leave and reenter
   the Agent to check that the plan and its receipts were cleared.
