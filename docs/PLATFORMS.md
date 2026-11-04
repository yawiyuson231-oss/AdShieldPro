# Battery monitoring on every platform

The same battery rules now run on Android, Windows, macOS, Linux, and as an iOS
library. This page states what each platform can actually measure, because the honest
answer differs a lot and the UI changes accordingly.

## What each platform exposes

| | Level | Charging | Current (mA) | Voltage | Cell temp | SoC temp |
|---|---|---|---|---|---|---|
| **Android** | ✅ | ✅ | ✅ `CURRENT_NOW` | ✅ | ✅ | ⚠️ sysfs, often restricted |
| **Linux** | ✅ | ✅ | ✅ `current_now` | ✅ | ⚠️ if the driver has `temp` | ❌ |
| **macOS** | ✅ | ✅ | ✅ `CurrentAmperage` | ✅ | ✅ `Temperature` | ❌ |
| **Windows** | ✅ | ✅ | ❌ no public API | ✅ design voltage | ❌ | ❌ |
| **iOS** | ✅ | ✅ | ❌ by design | ❌ | ❌ | ❌ |

✅ measured · ⚠️ hardware-dependent · ❌ not available to third-party apps

Where a cell is ❌, the app says **"not reported"**. It never substitutes a typical
value, and an alert that needs that value stays off with a visible reason in the
settings screen.

**Windows** has no battery current API. Tools that show mA there read vendor EC drivers
or parse `powercfg /batteryreport`, which is a snapshot of the last session rather than
a live reading. This app does neither.

**iOS** exposes level and charging state and nothing else. Current, voltage and
temperature are not available to App Store apps; the IOKit APIs that would provide them
are private. So on iOS only two of the four alerts can fire — low battery and charge
complete — and the app says so rather than shipping dead switches.

## What is shared, and how it stays shared

Three implementations of one test contract:

| Platform | Code | Verified by |
|---|---|---|
| Android | `app/src/main/java/com/adshield/pro/engine/optimizer/BatteryTelemetry.kt` | `BatteryTelemetryTest` on the JVM, in `android-build.yml` |
| Desktop | `desktop/src/core/battery.js`, `alerts.js` | `tests/unit/battery-core.test.mjs` (43 tests) |
| iOS | `ios/Sources/AdShieldBattery/` | `swift test` in `apple.yml` on macOS |

All three assert the same things: sign normalisation, withheld values, the two-sensor
heat rule, threshold clamping, and the cooldown behaviour of every alert. If one drifts,
its own build fails.

The desktop adapters (`desktop/src/adapters/`) convert each OS's raw units into the
shared ones and are tested against recorded fixtures in `tests/fixtures/battery/`, so
all three are exercised on Linux CI.

## Desktop app

No npm dependencies:

```bash
npm run battery:once    # one reading as JSON, then exit
npm run battery          # sample every 5 s, notify on alerts
npm run battery:serve    # also serve http://127.0.0.1:7317/battery
```

- Settings: `~/.config/adshield/battery-settings.json`
- Alert state: `~/.config/adshield/battery-state.json`
- Notifications use `osascript` (macOS), `notify-send` (Linux) and PowerShell
  (Windows). No native module, no build step, works on all three from one file.
- The HTTP listener binds to loopback only. It has no authentication, and battery
  telemetry is local data.

A tray/menu-bar icon would need a native dependency; the process is designed so one can
wrap it (`/battery` returns everything the icon needs) without changing the core.

## iOS

`ios/` is a Swift package, not an Xcode project, for one practical reason: a package
builds and tests with **no signing, no provisioning profile and no Apple developer
account**, which is why `apple.yml` can keep it green on a macOS runner today.

To turn it into a shipping app you need a Mac and an Apple developer account
($99/year):

1. In Xcode: *File → New → Project → iOS App*, add the local package
   `ios/` as a dependency.
2. Set the bundle identifier to one you own, choose your team for signing.
3. Add `AlertSettings` values to a settings screen and call
   `IOSBatteryAdapter.readSnapshot()` on a timer while the app is foregrounded.
4. Local notifications for low battery / charge complete:
   `UNUserNotificationCenter` with a `UNTimeIntervalNotificationTrigger`, scheduled from
   the snapshot. iOS does not allow background battery polling, so alerts fire while the
   app is running or from a scheduled notification you set up in advance.

Until those steps are done, what exists is the tested core plus the platform adapter —
not a signed app.

## Android

Unchanged in behaviour for the user, but the rules now match the other platforms
exactly, including the fix for the "first alert suppressed" timestamp bug.
