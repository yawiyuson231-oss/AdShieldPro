/**
 * macOS battery adapter — `ioreg -rn AppleSmartBattery`.
 *
 * macOS is the best of the three: `AppleSmartBattery` exposes `CurrentAmperage`,
 * `Voltage`, `Temperature` (centi-degrees) and `AppleRawCurrentCapacity`, so current,
 * power and cell temperature are all real measurements.
 *
 * The parser is separated from the shell-out so the recorded ioreg output below can be
 * exercised on Linux CI.
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { buildSnapshot } from '../core/battery.js';

const exec = promisify(execFile);

export const QUERY = ['-rn', 'AppleSmartBattery'];

/**
 * Parses `ioreg -rn AppleSmartBattery` text output.
 *
 * ioreg prints a plist-ish structure, one `"Key" = value` per line. It is not JSON and
 * not XML in this mode, so this reads the handful of keys we need rather than trying
 * to parse the whole thing.
 */
export function parseIoreg(text, nowMs = 0) {
  const value = (key) => {
    const match = new RegExp(`"${key}"\\s*=\\s*(-?\\d+)`).exec(text || '');
    return match ? Number(match[1]) : null;
  };

  const currentAmps = value('CurrentAmperage') ?? value('InstantAmperage');
  if (currentAmps === null) {
    return buildSnapshot({
      platform: 'macos',
      percent: 0,
      isCharging: false,
      chargingLabel: 'No battery detected',
      healthLabel: 'Not reported',
      readingAtMs: nowMs
    });
  }

  // MaxCapacity and CurrentCapacity are in mAh on Intel and a percentage on Apple
  // Silicon; AppleRawCurrentCapacity is mAh on both.
  const rawCapacity = value('AppleRawCurrentCapacity');
  const rawMax = value('AppleRawMaxCapacity');
  const percentRaw = value('CurrentCapacity');
  const percent = rawCapacity !== null && rawMax
    ? (rawCapacity / rawMax) * 100
    : percentRaw;

  // ioreg prints `"IsCharging" = Yes`, not a number, so the numeric reader returns
  // null for it; either form is accepted.
  const chargingFlag = /"IsCharging"\s*=\s*(Yes|No|1|0)/.exec(text || '');
  const chargingFlagOn = chargingFlag ? /Yes|1/.test(chargingFlag[1]) : null;
  const isCharging = chargingFlagOn ?? currentAmps > 0;

  // Temperature is in centi-degrees Celsius.
  const tempCenti = value('Temperature');
  const cellCelsius = tempCenti === null ? null : tempCenti / 100;

  // Voltage on macOS is millivolts already.
  const voltageMilliVolts = value('Voltage');

  const snapshot = buildSnapshot({
    platform: 'macos',
    percent,
    isCharging,
    chargingLabel: isCharging ? 'Charging' : ((value('ExternalConnected') === 1) ? 'On AC (not charging)' : 'Discharging'),
    currentMilliAmps: currentAmps,
    voltageMilliVolts,
    cellCelsius,
    socCelsius: null,
    chargeMilliAmpHours: rawCapacity,
    healthLabel: (value('PermanentFailureStatus') === 0) ? 'Good' : 'Reported failure flag',
    readingAtMs: nowMs
  });
  snapshot.batteryName = 'AppleSmartBattery';
  return snapshot;
}

/** Reads a live snapshot on macOS; returns an "unavailable" snapshot elsewhere. */
export async function readSnapshot({ nowMs = 0, runner = exec } = {}) {
  if (process.platform !== 'darwin' && !runner.__force) {
    return parseIoreg('', nowMs);
  }
  const { stdout } = await runner('ioreg', QUERY);
  return parseIoreg(stdout, nowMs);
}
