# Battery telemetry: what is measured, what is not

Battery numbers are easy to fake. This document states exactly where every figure in
the Optimizer's **Battery & Temp** tab comes from, so a reading can be checked
against the device rather than trusted.

## Current (mA)

Read from `BatteryManager.BATTERY_PROPERTY_CURRENT_NOW`, with
`BATTERY_PROPERTY_CURRENT_AVERAGE` as a fallback.

| Situation | What the app shows |
|---|---|
| Device reports a plausible current | The measured value, e.g. `-812 mA` |
| Device reports `0`, `Int.MIN_VALUE`, or something outside 20–20 000 mA | `n/a` and *"Not reported by this device"* |

**Sign convention:** negative = energy leaving the battery, positive = charging. Not
every device agrees on this. The builder normalises each reading against the charging
state from `EXTRA_STATUS`, so a phone that reports positive current while discharging
still displays a negative number.

There is no fallback estimate. When the platform does not report current, the app
says so instead of showing a typical value.

## Power (W)

Derived as `voltage × current` from two measured inputs. It is **withheld entirely**
when either input is missing or implausible (voltage outside 2 000–6 000 mV). A wattage
derived from a placeholder would be worse than no wattage.

## Temperature (°C) — two different sensors

The most common mistake in battery apps is calling the battery extra "device
temperature". It is not. Two readings are reported separately:

| Reading | Source | Notes |
|---|---|---|
| **Battery cell** | `EXTRA_TEMPERATURE` (tenths of °C) | The cell, not the processor. Limits fast charging. |
| **Chip (SoC)** | `/sys/class/thermal/thermal_zone*/temp` + `type` | The processor and skin. Usually the hotter one during gaming. |

The chip reading exists because there is no public Android API for SoC temperature.
Many OEMs restrict `/sys/class/thermal` on recent Android versions; when no zone is
readable the app shows `n/a` and *"Hidden by this device"* rather than substituting
the battery temperature.

When both are readable and the chip is at least 5 °C hotter, the app says so
explicitly: *"The CPU/SoC is 24.0 °C hotter than the battery — this heat is workload,
not the cell."*

`EXTRA_TEMPERATURE` is only treated as a measurement when the extra is actually
present. A missing extra does not become "31 °C".

## Charge and energy

| Value | Source | When it appears |
|---|---|---|
| Remaining charge (mAh) | `BATTERY_PROPERTY_CHARGE_COUNTER` ÷ 1000 | Only if the device implements it and returns > 0 |
| Stored energy (mWh) | charge × voltage | Only when the charge counter exists |

Both are hidden rather than estimated on devices without charge counters.

## Notifications

All battery alerts are **off until you turn them on**, in *Optimizer → Battery & Temp →
Battery alerts*. Enabling them on Android 13+ also requests the notification permission.

| Alert | Fires when | Rate limit |
|---|---|---|
| Low battery | Not charging and at or below your threshold | Once per drop, then again every further 5% |
| Charge complete | Charging and at your full threshold | Once per charging session |
| Heat alert | Effective temperature at or above your threshold | 30 min, or +2 °C above the last alert |
| Heavy draw | Measured discharge current above your threshold | 45 min |

"Effective temperature" is the **battery cell** when it is readable, the chip otherwise
— the cell is the sensor that limits charging.

Every alert body is built from the same measured values shown on screen, so you can
verify it: `62% • -812 mA (3.2 W) • 31.4°C cell`. When a value is unavailable the text
says `current not reported` or `no temperature sensor readable` — never `0 mA`.

Two delivery paths, one evaluator:

- **While the Optimizer screen is open**, `BatteryTelemetryService` samples every 5 s
  and keeps a silent, ongoing *Battery monitor* notification in sync with the measured
  readings. It stops when you leave the screen; it holds no wake locks and schedules
  no alarms.
- **While the app is closed**, the existing Smart Maintenance worker (WorkManager)
  evaluates the same thresholds on its schedule. If maintenance is deferred because of
  low battery or heat, the battery alerts are still evaluated first — that is exactly
  when they matter.

A **Send a test alert** button posts one notification with the current measured values,
so the feature can be verified without waiting for a flat or hot battery.

## Why the app itself is not claimed to be measured

AdShield's own power draw is not reported by Android and is not invented here. What the
Optimizer does claim is structural and verifiable in the source: the DNS loop is
event-driven (blocking reads on the TUN socket) with no polling timers, so filtering
adds no periodic wakeups. The live DNS figures shown next to it are measured by the
engine.
