/**
 * AdShield battery alerts — the rules, with no I/O.
 *
 * This is the reference implementation of the four alerts that also ship on Android
 * (service/BatteryHealthNotifier.kt) and iOS (Sources/AdShieldBattery/Alerts.swift).
 * It takes a snapshot, the user's thresholds, and the state left over from the last
 * evaluation, and returns what should fire. Persisting that state, showing the
 * notification and reading the clock are the caller's job, which is what makes every
 * rule here testable without a device.
 */
import { Source } from './battery.js';

/** Defaults match the Android app so the platforms behave identically. */
export const DEFAULT_SETTINGS = Object.freeze({
  enabled: false,
  lowPercentThreshold: 20,
  fullPercentThreshold: 100,
  tempWarningCelsius: 41,
  currentAlertMilliAmps: 1800,
  notifyOnChargeComplete: true
});

/** Suppression windows, in milliseconds. */
export const COOLDOWN = Object.freeze({
  tempMs: 30 * 60 * 1000,
  currentMs: 45 * 60 * 1000
});

/** A rising temperature must clear this to re-alert before the cooldown expires. */
export const TEMP_REALERT_DELTA_C = 2;

export const AlertKind = Object.freeze({
  LOW_BATTERY: 'low-battery',
  CHARGE_COMPLETE: 'charge-complete',
  HEAT: 'heat',
  HEAVY_DRAW: 'heavy-draw'
});

/** Fresh state. Every field is what the last evaluation left behind. */
export function emptyState() {
  return {
    lastLowPercent: null,
    // null, not 0: 0 is a valid timestamp argument (tests pass it), so it cannot
    // double as "never alerted" or the first alert after it is suppressed.
    lastTempAlertMs: null,
    lastTempAlertValueC: 0,
    lastCurrentAlertMs: null,
    chargeCompleteSessionMarker: null
  };
}

/**
 * Clamps user thresholds into ranges that are actually useful.
 *
 * A low-battery warning above 50% fires constantly; a heat warning below normal
 * operating temperature fires on every device; a full-charge warning must sit above
 * the low-battery warning or the two contradict each other.
 */
export function clampSettings(settings) {
  const low = clamp(settings.lowPercentThreshold ?? DEFAULT_SETTINGS.lowPercentThreshold, 5, 50);
  return {
    enabled: !!settings.enabled,
    lowPercentThreshold: low,
    fullPercentThreshold: clamp(settings.fullPercentThreshold ?? DEFAULT_SETTINGS.fullPercentThreshold, low + 10, 100),
    tempWarningCelsius: clamp(settings.tempWarningCelsius ?? DEFAULT_SETTINGS.tempWarningCelsius, 35, 55),
    currentAlertMilliAmps: clamp(settings.currentAlertMilliAmps ?? DEFAULT_SETTINGS.currentAlertMilliAmps, 500, 5000),
    notifyOnChargeComplete: settings.notifyOnChargeComplete ?? DEFAULT_SETTINGS.notifyOnChargeComplete
  };
}

function clamp(value, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return min;
  return Math.min(max, Math.max(min, n));
}

/**
 * Evaluates one snapshot.
 *
 * @param {object} snapshot from buildSnapshot()
 * @param {object} rawSettings user thresholds (clamped here)
 * @param {object} previous state returned by the previous call
 * @param {number} nowMs current time; injected so tests do not depend on the clock
 * @param {(ms: number) => number} [sessionOf] maps a timestamp to a charging session id
 * @returns {{alerts: Array<{kind: string, title: string, body: string}>, state: object}}
 */
export function evaluate(snapshot, rawSettings, previous = emptyState(), nowMs = 0, sessionOf = defaultSession) {
  const settings = clampSettings(rawSettings);
  const state = { ...emptyState(), ...previous };
  const alerts = [];

  if (!settings.enabled) return { alerts, state };

  const charging = snapshot.current.source === Source.MEASURED
    ? snapshot.current.milliAmps > 0
    : snapshot.isCharging;

  // 1. Low battery. Once per drop below the threshold, then again every further 5%,
  //    so a slow drain does not produce a notification per sample.
  if (!charging && snapshot.percent <= settings.lowPercentThreshold) {
    if (state.lastLowPercent === null || snapshot.percent <= state.lastLowPercent - 5) {
      alerts.push({
        kind: AlertKind.LOW_BATTERY,
        title: `Battery low — ${snapshot.percent}%`,
        body: `${snapshot.percent}% • AdShield keeps filtering; consider Battery Saver mode.`
      });
      state.lastLowPercent = snapshot.percent;
    }
  } else if (charging) {
    state.lastLowPercent = null;
  }

  // 2. Charge complete. Once per charging session, not once per sample at 100%.
  if (settings.notifyOnChargeComplete && charging && snapshot.percent >= settings.fullPercentThreshold) {
    const marker = sessionOf(nowMs);
    if (state.chargeCompleteSessionMarker !== marker) {
      alerts.push({
        kind: AlertKind.CHARGE_COMPLETE,
        title: `Charge complete — ${snapshot.percent}%`,
        body: 'Unplugging near 80–90% is easier on cell life.'
      });
      state.chargeCompleteSessionMarker = marker;
    }
  }

  // 3. Heat. Uses whichever sensor is readable, preferring the cell.
  const temp = snapshot.heat.effectiveCelsius;
  if (temp !== null && temp >= settings.tempWarningCelsius) {
    const cooled = state.lastTempAlertMs === null || nowMs - state.lastTempAlertMs >= COOLDOWN.tempMs;
    const heatingUp = state.lastTempAlertMs !== null && temp >= state.lastTempAlertValueC + TEMP_REALERT_DELTA_C;
    if (state.lastTempAlertMs === null || cooled || heatingUp) {
      alerts.push({
        kind: AlertKind.HEAT,
        title: `Heat alert — ${temp.toFixed(1)}°C`,
        body: `${snapshot.heat.heatSource} ${charging
          ? `Unplug or slow-charge until it drops below ${settings.tempWarningCelsius}°C.`
          : `Close heavy apps until it drops below ${settings.tempWarningCelsius}°C.`}`
      });
      state.lastTempAlertMs = nowMs;
      state.lastTempAlertValueC = temp;
    }
  }

  // 4. Heavy draw. Only from a measured current: an unmeasured device has nothing to
  //    compare, and inventing a draw to warn about would be a fabricated alert.
  if (!charging
    && snapshot.current.source === Source.MEASURED
    && snapshot.current.milliAmps < -settings.currentAlertMilliAmps) {
    if (state.lastCurrentAlertMs === null || nowMs - state.lastCurrentAlertMs >= COOLDOWN.currentMs) {
      alerts.push({
        kind: AlertKind.HEAVY_DRAW,
        title: `Heavy battery draw — ${Math.abs(snapshot.current.milliAmps)} mA`,
        body: 'A background app may be working hard.'
      });
      state.lastCurrentAlertMs = nowMs;
    }
  }

  return { alerts, state };
}

/** Charging sessions are bucketed in 12-hour windows, matching the Android rule. */
export function defaultSession(nowMs) {
  return Math.floor(nowMs / (12 * 60 * 60 * 1000));
}

/** Explains why an alert cannot fire on this machine, for the settings screen. */
export function unavailableReasons(snapshot) {
  const reasons = [];
  if (snapshot.current.source !== Source.MEASURED) {
    reasons.push('Heavy-draw alerts need a measured current; this platform does not expose one.');
  }
  if (snapshot.heat.effectiveCelsius === null) {
    reasons.push('Heat alerts need a readable temperature sensor; none was found.');
  }
  return reasons;
}
