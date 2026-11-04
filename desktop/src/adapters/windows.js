/**
 * Windows battery adapter — `Get-CimInstance Win32_Battery`.
 *
 * Windows is the least generous of the three platforms. `Win32_Battery` exposes
 * charge, estimated runtime, voltage and chemistry, but **no current and no
 * temperature**. Battery current on Windows needs vendor EC drivers or
 * `GenerateBatteryReport`, which is asynchronous and not a live reading, so this
 * adapter reports current as unavailable rather than guessing.
 *
 * The command is injectable so this file can be tested on Linux CI by feeding it
 * recorded `ConvertTo-Json` output.
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { buildSnapshot } from '../core/battery.js';

const exec = promisify(execFile);

/** Windows reports charging state as a small enum, not a boolean. */
const STATUS = {
  1: { charging: false, label: 'Discharging' },
  2: { charging: false, label: 'On AC (not charging)' },
  3: { charging: false, label: 'Fully charged' },
  4: { charging: false, label: 'Low' },
  5: { charging: false, label: 'Critical' },
  6: { charging: true, label: 'Charging' },
  7: { charging: true, label: 'Charging (high)' },
  8: { charging: true, label: 'Charging (low)' },
  9: { charging: true, label: 'Charging (medium)' },
  11: { charging: false, label: 'Partially charged' }
};

/** The PowerShell we run. Kept as a constant so tests assert the same query. */
export const QUERY = 'Get-CimInstance -ClassName Win32_Battery | ' +
  'Select-Object Name,EstimatedChargeRemaining,BatteryStatus,DesignVoltage,Chemistry | ' +
  'ConvertTo-Json -Compress';

/**
 * Parses `ConvertTo-Json` output into a snapshot.
 *
 * Handles the single-object case (one battery) and the array case, and never throws
 * on malformed input: a monitor that crashes on a driver quirk is worse than one that
 * says "unavailable".
 */
export function parseCimJson(json, nowMs = 0) {
  let parsed;
  try {
    parsed = JSON.parse(json);
  } catch {
    parsed = null;
  }
  const record = Array.isArray(parsed) ? parsed[0] : parsed;

  if (!record || typeof record !== 'object') {
    return buildSnapshot({
      platform: 'windows',
      percent: 0,
      isCharging: false,
      chargingLabel: 'No battery detected',
      healthLabel: 'Not reported',
      readingAtMs: nowMs
    });
  }

  const status = STATUS[record.BatteryStatus] || { charging: false, label: 'Unknown' };

  // DesignVoltage is millivolts on Win32_Battery and is the only voltage exposed.
  const voltageMilliVolts = Number.isFinite(record.DesignVoltage) && record.DesignVoltage > 0
    ? record.DesignVoltage
    : null;

  const snapshot = buildSnapshot({
    platform: 'windows',
    // Win32_Battery is known to over-report on some firmware; clamping in the core
    // keeps a 127% reading from reaching the UI.
    percent: record.EstimatedChargeRemaining,
    isCharging: status.charging,
    chargingLabel: status.label,
    // Windows exposes no current: the adapter says so instead of deriving one.
    currentMilliAmps: null,
    voltageMilliVolts,
    cellCelsius: null,
    socCelsius: null,
    chargeMilliAmpHours: null,
    healthLabel: record.Chemistry ? `Chemistry: ${record.Chemistry}` : 'Not reported',
    readingAtMs: nowMs
  });
  snapshot.batteryName = record.Name || 'Battery';
  return snapshot;
}

/** Reads a live snapshot on Windows. Rejects only if PowerShell itself is missing. */
export async function readSnapshot({ nowMs = 0, runner = exec } = {}) {
  if (process.platform !== 'win32' && !runner.__force) {
    return parseCimJson('null', nowMs);
  }
  const { stdout } = await runner('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', QUERY]);
  return parseCimJson(stdout, nowMs);
}
