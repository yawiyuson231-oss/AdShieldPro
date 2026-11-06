# Safe GPS — accurate fixes, shared on your terms

AdShield Pro 2.10 adds a **Safe GPS** tab to the Android app. It answers two questions that are
usually mixed together:

1. *How good is this location fix, really?*
2. *Is it safe to send it, in this form, to this person?*

The usual flow — tap "use my location", copy the pin, paste it into a group chat — gets both
wrong. A single `getCurrentLocation()` call often returns a cached Wi-Fi/cell position, and the
pin it produces usually identifies a doorway rather than a street.

Nothing in this feature contacts a server. Capture uses the platform `LocationManager`; the pin
is text the user sends from their own messaging app.

---

## 1. Why the first fix is usually the worst

A cold GNSS receiver needs tens of seconds to acquire satellites and converge. Android will hand
back the best it has *now*, which on a phone that just woke up is frequently a network position
from minutes ago. No app can make that better by asking once.

Safe GPS therefore, in `engine/location/SafeGpsLocator.kt`:

| Behaviour | Why it matters |
|---|---|
| `requestLocationUpdates` on every enabled provider (GNSS + network), 500 ms / 0 m | Subscribes to real fixes instead of polling |
| Keeps sampling until the device reports the target accuracy 3× , the sample budget (12) is spent, or the deadline (15/30/60 s) passes | This is the **only** honest way to improve accuracy: wait for the hardware |
| Shows the first fix alongside the best one | The improvement is measured and displayed, not claimed |
| Propagates `Location.isMock` (API 31+) / `isFromMockProvider` | A simulated fix is never presented as a real emergency position |
| Uses `elapsedRealtimeNanos` for timing | A clock or timezone change can never fake an "implausible movement" warning |
| Cancels and unregisters on `DisposableEffect`/`onCleared` | No capture continues after the screen is left |

The screen shows **"38.6 m tighter (80 %) over 4 fixes"** or, if the device did not converge,
*says that a longer wait would not help on this device*.

### What "accuracy" means

`Location.getAccuracy()` is the device's own **68 % confidence radius**. It is a claim by the
device, not a measurement the app can verify. Urban multipath, a stale cached fix, or a spoofer
all produce confident-looking numbers. So the analysis (`LocationAnalyzer.analyse`) computes:

- **consistency** — do the accuracy circles of the fixes intersect? If not, no position is
  trusted and no pin is produced;
- **movement plausibility** — an implied speed above 250 m/s between two fixes is reported as
  implausible, explicitly as a hint and *not* as tamper detection;
- **spread**, **weighted centre** (1/accuracy²), and an **outlier-resistant median** position;
- the platform's **mock flag**, which downgrades quality and blocks emergency sharing.

---

## 2. Sharing safely

Before text is generated (`LocationSafetyAdvisor.buildSharePlan`):

| Disclosed precision | What the screen says |
|---|---|
| ≤ 15 m | Very precise — identifies a building entrance. Risky for a public post |
| ≤ 60 m | Street level — the usual precision you want |
| ≤ 300 m | Neighbourhood — fine for a rider or responder |
| > 300 m | Coarse, network positioning — names the town, not the street |

**Privacy rounding** snaps the shared pin to a 250 m / 1 km / 5 km grid and states the measured
displacement and the worst case (half the cell diagonal). The disclosed radius always covers the
rounding, and the exact latitude is absent from rounded output — asserted by
`SafeGpsTestSuite.roundedShareNeverContainsTheExactLatitude`.

Two modes, different text:

- **Everyday** — coordinates, disclosed radius, time, an optional map link, and the sentence
  *"This is a fixed pin, not live tracking: it does not update after I send it."*
- **Emergency** — starts with `EMERGENCY`, states the time and radius, tells the receiver to
  search from these coordinates if you stop replying, and names **911** (PH) with a request to
  call on your behalf if you cannot.

The outputs are a copyable message, an `sms:?body=…` intent (the messaging app opens with the
text; the user still chooses the recipient and presses send), and a `geo:` URI for whichever map
app is installed. **No pin is produced at all** when the fixes contradict each other.

### Device checklist

`LocationSafetyAdvisor.deviceChecklist` turns platform facts into seven rows, each with a state
of ok / check / blocking / **cannot read**, and — where one exists — a shortcut to the exact
Settings screen that fixes it: location permission, the system location switch, precise vs
approximate permission, Wi-Fi scanning, simulated-location providers, encrypted network, and
screen lock. A value Android does not expose is shown as *cannot read*, never as healthy.

---

## 3. What this feature deliberately does not do

Registered in `CapabilityRegistry` as `UNAVAILABLE`, so the app's own Status screen says so:

| Not implemented | Why |
|---|---|
| Live tracking / shared sessions | Needs a relay server and a live session; a lost or stolen phone would keep broadcasting |
| `ACCESS_BACKGROUND_LOCATION` | Not declared in the manifest. Capture runs only while the Safe GPS screen is open |
| Proof-of-location / anti-spoof guarantee | No reliable attestation source; mock flags and plausibility are hints, never certification |
| Emergency calls or automatic contact alerts | An app cannot place a 911 call for you or guarantee an alert |
| Map tiles | No map SDK is bundled; only a `geo:`/OpenStreetMap link you choose to open |
| Reverse geocoding | Would send coordinates to a third party without being asked |

In the Philippines dial **911**; elsewhere use your local emergency number. Tell a person, not an app.

---

## 4. Verification

```bash
# JVM suite (no device needed)
./gradlew :app:testDebugUnitTest

# the capability row for each shipping behaviour must name a real @Test
python3 tools/audit_capability_tests.py --strict
python3 tools/generate_capability_matrix.py --check
```

`SafeGpsTestSuite` (28 tests) covers: validation of impossible fixes, haversine and circle
overlap, weighted centre and outlier-resistant median, best-fix selection, convergence and the
measured improvement, a single tight fix not being called converged, disagreement being refused
instead of averaged, network-only fixes being called coarse, empty windows inventing nothing,
mock fixes being flagged, implausible movement, formatters, the spoken reference, bounded
rounding (including clamping), precision language, everyday and emergency message content,
refusal to share a contradiction, rounding never leaking the exact latitude, warnings per
precision, the device checklist (including "unknown" states and the exact settings shortcut), and
URI encoding.

On a device: open **Safe GPS → Get my location** outdoors, watch the accuracy converge, then
compare the copied message with what a map app shows.

---

## 5. Remaining work

- **Fused provider.** `LocationManager` is used deliberately (no Play Services dependency). A
  fused provider could converge faster, but it would add Google Play Services to a privacy-first
  app; not planned unless a device-verified need appears.
- **Accuracy history.** Only the current session is kept; nothing is persisted, by design.
- **Contact shortcuts.** Would need a contacts permission and a stored emergency contact — not
  added, because the message is already one tap from any SMS app.
