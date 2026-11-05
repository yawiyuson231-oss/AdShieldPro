# Battery Command Center

Real-time, hardware-connected battery monitoring with a cyber command-center interface.
Everything on this screen comes from Android's own battery APIs; nothing is simulated,
randomised, or drawn for decoration.

| | |
|---|---|
| Screen | `app/src/main/java/com/adshield/pro/ui/screens/BatteryScreen.kt` |
| Engine | `engine/battery/BatteryMonitoringEngine.kt` (event receiver + 1 Hz current path) |
| Pure rules | `engine/battery/BatteryMonitor.kt` (status, sensors, trends, efficiency) |
| Telemetry | `engine/battery/BatteryTelemetrySource.kt` (`BatteryManager` + `ACTION_BATTERY_CHANGED`) |
| State | `data/repository/BatteryIntelligenceRepository.kt` (`dashboard` flow) |
| Tests | `app/src/test/.../BatteryCommandCenterTestSuite.kt`, `BatteryIntelligenceTestSuite.kt` |
| Static gate | `tools/check_battery_command_center.py` (CI) |

---

## 1. Where every number comes from

| Metric | Source | Notes |
|---|---|---|
| Battery level (%) | `EXTRA_LEVEL` / `EXTRA_SCALE` | falls back to `BATTERY_PROPERTY_CAPACITY` |
| Live current (mA) | `BATTERY_PROPERTY_CURRENT_NOW` | µA → mA; re-read at 1 Hz while the screen is visible |
| Average current (mA) | `BATTERY_PROPERTY_CURRENT_AVERAGE` | separate value; never substituted for the live current |
| Voltage (mV) | `EXTRA_VOLTAGE` | reported in V, shown in both V and mV |
| Temperature (°C/°F) | `EXTRA_TEMPERATURE` | tenths of °C from the driver |
| Health | `EXTRA_HEALTH` | a vendor flag, not a capacity measurement |
| Technology | `EXTRA_TECHNOLOGY` | e.g. `Li-ion` |
| Charging state | `EXTRA_STATUS` | charging / discharging / full / not charging |
| Charging source | `EXTRA_PLUGGED` | AC, USB, wireless, dock (bit 8, API 33+) |
| Charge counter (µAh) | `BATTERY_PROPERTY_CHARGE_COUNTER` | optional; labelled unsupported when absent |
| Design / full capacity | `CHARGE_COUNTER_FULL_DESIGN` / `_FULL` | probed by field name; absent on most devices |
| Cycle count | `BatteryManager.getCycleCount()` | Android 14+ only |
| Charge ETA | `computeChargeTimeRemaining()` | Android's own estimate, labelled as such |

**Power** is computed, never read: `P (W) = V (V) × |I| (A)` on the **battery side**. No app can
read a charger's output, so charger-side wattage is never displayed. When either input is missing
the tile shows `—` and names the missing input.

---

## 2. Update paths (why it is fast, and why it does not drain the battery)

| Path | Trigger | Cost | Covers |
|---|---|---|---|
| Event | `ACTION_BATTERY_CHANGED` broadcast | one receiver, system-driven | level, temperature, health, charging state, source |
| Fast | `CURRENT_NOW` poll, 1 Hz | one `getIntProperty` per second | live mA and W |
| Watchdog | 2 s timer | reads two `Long`s | freshness (`Live` → `Delayed` → `Stale`) |

Requirements this satisfies:

- **Event-driven first.** The broadcast receiver is registered once and is the only source for
  state changes, so plugging in a charger updates the screen immediately.
- **1 Hz only when it pays off.** `BatteryMonitor.recommendedRefreshIntervalMs` returns 1 s only
  when the engine is active, the screen is on and readings are live; otherwise 3–5 s. The battery
  screen stops the poll in `onStopOrDispose`, so no background polling happens.
- **No sensors, no polling.** `BatteryMonitoringEngine.startFastPolling` returns immediately when
  `BatteryTelemetrySource.hasCurrentSensor()` is false.
- **No wake locks, no alarms, no background services.**
- **Monotonic freshness.** Snapshots carry `SystemClock.elapsedRealtime()`; wall-clock changes
  (NTP, timezone) cannot make a stale reading look live.
- **Sample throttling.** At most one history sample per ~1 s whichever path produced it; a coarse
  copy is persisted every 30 s (6 hours of history across launches), and the in-memory ring holds
  ~30 minutes at 1 Hz.

---

## 3. Sections

### Live Power Monitor
Live current, average current, voltage (V and mV), actual power, charging power, discharging power,
observed average and peak power. Each tile names its API and whether the value is measured or
computed.

### Battery Intelligence
Average observed current, power trend (first half vs second half of the window), measured drain
and charge rates, screen-on vs screen-off drain, abnormal-drain and overheating flags, plus explicit
notes about what could not be observed.

### Charging Analytics
Measured charge rate (%/h), projected time to full (estimate), projected runtime (estimate),
Android's charge ETA, charging-source label, and an efficiency **estimate** (stored watts ÷
battery-side watts) that says plainly why it is a lower bound.

### Battery Health
Composite health index (temperature, capacity, cycles — missing inputs skipped, not assumed),
Android health flag, measured capacity vs design, cycle count, cell technology. Each row carries a
`MEASURED` / `COMPUTED` / `NOT SUPPORTED` badge.

### Temperature Monitor
Current temperature in °C and °F, session average, warning thresholds, and a real history chart.

### Power Consumption History
Power, current and level series from recorded samples. Gaps in the data are drawn as gaps: a
missing sensor read is never interpolated into a smooth line.

### Sensor Diagnostics
One row per hardware input: level, voltage, current, average current, temperature, charge counter,
computed power, cycle count, design capacity, charge ETA. States are `Operational`, `Delayed`,
`Unsupported`, `Unavailable`, `Invalid reading`, `Waiting for data`.

### System Monitoring Status
Battery API, current sensor, voltage sensor, temperature sensor, power calculation, monitoring
engine and data freshness, rolled up into `Operational` / `Partial` / `Error` plus a percentage of
operational components, the measurement **reliability** (High/Medium/Low/None from freshness plus
sensor coverage) and **charging stability** (voltage spread and recorded dropouts; `NOT MEASURABLE`
when the device exposes no voltage).

### Diagnostic Engine and Charging Sessions
The pre-existing evidence-based rule chain and locally stored session history, restyled for the
command center and unchanged in behaviour.

---

## 4. Status rules

`BatteryMonitor.condition(...)` resolves the headline status, safety first:

1. `Temperature warning` — measured ≥ 40 °C (caution) or ≥ 45 °C (critical). This outranks
   charging/discharging: reporting only "discharging" at 41 °C would hide the important fact.
2. `Fully charged` — Android reports `BATTERY_STATUS_FULL`.
3. `Fast charging` — **only** with a platform signal (`BATTERY_PROPERTY_STATUS` fast-charge value or
   an unambiguous OEM protocol string) *and* a measured rate ≥ 30 %/h (or a rate still being
   measured, which the UI states).
4. `Slow charging` — measured charge rate < 8 %/h.
5. `Charging` / `Connected, not charging` / `Discharging` / `High power consumption` (measured
   average ≥ 4.5 W).
6. `Insufficient sensor information` — when neither current nor voltage is exposed. This outranks
   a benign-looking idle state, because claiming "discharging" without a current reading would be
   lying by omission.

---

## 5. Guarantees, and how they are enforced

| Guarantee | Enforced by |
|---|---|
| No fabricated measurements | `BatteryCommandCenterTestSuite` (null-in → null-out power) + `tools/check_battery_command_center.py` (no randomness/`nanoTime` in the battery package) |
| Instantaneous ≠ average current | separate fields end-to-end; tests assert they are never merged |
| Unsupported ≠ zero | `SensorState.UNSUPPORTED` renders `—` plus the reason |
| Fast charging only when provable | `FastChargeSignal` + `fastChargeSignalConfirmsRate`; four-sided test matrix |
| Projections need evidence | rate functions return `null` below 3 samples / 5 minutes |
| 1 Hz never runs in the background | `LifecycleStartEffect` / `onStopOrDispose` gate + refresh-policy test |
| No idle animation | animations stop when monitoring is not live or system animations are off |
| Per-app drain is never invented | the intelligence panel states that per-app attribution needs `BATTERY_STATS` and is therefore not attempted |
| Reliability is never a fake percentage | `MeasurementReliability` is a 4-step band from freshness + sensor coverage (tested) |

## 6. Verification

```bash
python3 tools/check_battery_command_center.py     # static: imports, members, honesty, lifecycle, docs
./gradlew :app:testDebugUnitTest                  # JVM suite (includes BatteryCommandCenterTestSuite)
./gradlew :app:assembleDebug                      # installable APK
```

### Manual acceptance checklist (physical device)

1. Open **Battery** → the header reads `LIVE` and a `1 Hz` badge appears; mA/W change every second.
2. Plug in a charger → status flips to `Charging` within a second, source names AC/USB/wireless.
3. Unplug → status returns to `Discharging`; the session card appears after ≥ 1 minute.
4. Compare temperature with `adb shell dumpsys battery` — they must match exactly.
5. Compare current with `adb shell dumpsys battery` (`current now`) — same value, same sign handling.
6. Leave the tab → `adb shell dumpsys batterystats AdShieldPro` must show no sustained wakeups.
7. Airplane mode + charger removed → the status reports `Insufficient sensor information` only if
   the device really exposes no current sensor (check `dumpsys battery` first).
8. Fast charging: verify the claim only appears on devices where `dumpsys battery` shows a fast-charge
   property. On other devices the screen must say "Fast charging is not claimed".
