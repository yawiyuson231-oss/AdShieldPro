/**
 * AdShield battery core — platform-independent battery maths.
 *
 * Everything in this file is pure: it takes raw readings from a platform adapter
 * and returns normalised values, or explicitly says a value is unavailable. No I/O,
 * no clock reads, no globals. That is what makes the same rules testable on Linux,
 * Windows, macOS and (mirrored) on Android.
 *
 * Canonical units, fixed for every platform:
 *   - current: milliamps, **negative = discharging**, positive = charging
 *   - voltage: millivolts
 *   - power:   milliwatts, same sign convention as current
 *   - energy:  milliwatt-hours
 *   - temperature: degrees Celsius
 *
 * Adapters are responsible only for converting their platform's raw units into
 * these ones; every decision lives here.
 */

/** Where a value came from, so the UI can be honest about it. */
export const Source = Object.freeze({
  MEASURED: 'measured',
  DERIVED: 'derived',
  UNAVAILABLE: 'unavailable'
});

/** Bounds outside which a reading is garbage rather than data. */
export const LIMITS = Object.freeze({
  minMilliAmps: 20,
  maxMilliAmps: 20_000,
  // Wide enough for a phone cell (3.0-4.4 V) and a laptop pack (up to 6S, ~25 V):
  // the bound exists to catch garbage, not to assume a phone.
  minMilliVolts: 2_000,
  maxMilliVolts: 30_000,
  minCelsius: -20,
  maxCelsius: 125
});

/**
 * Normalises a raw current reading.
 *
 * Platform adapters hand over whatever they read plus the device's charging state.
 * Sign conventions differ per platform and per OEM (Linux `current_now` is usually
 * negative while discharging, Windows `EstimatedChargeRemaining` has no current at
 * all, ioreg reports both `Amperage` and `InstantAmperage`). Rather than trusting the
 * sign, the charging state is treated as ground truth and the sign is corrected.
 *
 * @param {number|null|undefined} rawMilliAmps
 * @param {boolean} isCharging
 * @param {{assumePositiveMeansCharging?: boolean}} [opts]
 * @returns {{milliAmps: number, source: string, note: string}}
 */
export function normaliseCurrent(rawMilliAmps, isCharging, opts = {}) {
  const unavailable = {
    milliAmps: 0,
    source: Source.UNAVAILABLE,
    note: 'This device does not report battery current.'
  };
  if (rawMilliAmps === null || rawMilliAmps === undefined || Number.isNaN(rawMilliAmps)) return unavailable;

  const magnitude = Math.abs(rawMilliAmps);
  // Below the floor this is noise (a sleeping laptop draws single-digit mA), and above
  // the ceiling it is a driver bug. Both are reported as unavailable rather than shown.
  if (magnitude < LIMITS.minMilliAmps || magnitude > LIMITS.maxMilliAmps) return unavailable;

  const value = rawMilliAmps;
  const saysDischarging = value < 0;
  const flip = isCharging ? saysDischarging : !saysDischarging;

  return {
    milliAmps: Math.round(flip ? -value : value),
    source: Source.MEASURED,
    note: opts.assumePositiveMeansCharging
      ? 'Measured (sign normalised to the charging state)'
      : 'Measured'
  };
}

/**
 * Instantaneous power in mW, or null when either input is unusable.
 *
 * Derived, never guessed: P = V x I. A wattage computed from a placeholder voltage
 * would look precise and be wrong, which is worse than showing nothing.
 */
export function powerMilliWatts(voltageMilliVolts, currentMilliAmps, currentIsMeasured) {
  if (!currentIsMeasured) return null;
  if (!isPlausibleVoltage(voltageMilliVolts)) return null;
  return Math.round((voltageMilliVolts * currentMilliAmps) / 1000);
}

/** Stored energy in mWh = charge (mAh) x voltage (V). Null if either side is missing. */
export function energyMilliWattHours(chargeMilliAmpHours, voltageMilliVolts) {
  if (chargeMilliAmpHours === null || chargeMilliAmpHours === undefined) return null;
  if (!isPlausibleVoltage(voltageMilliVolts)) return null;
  return Math.round((chargeMilliAmpHours * voltageMilliVolts) / 1000);
}

export function isPlausibleVoltage(voltageMilliVolts) {
  return typeof voltageMilliVolts === 'number'
    && voltageMilliVolts >= LIMITS.minMilliVolts
    && voltageMilliVolts <= LIMITS.maxMilliVolts;
}

export function isPlausibleCelsius(celsius) {
  return typeof celsius === 'number'
    && Number.isFinite(celsius)
    && celsius >= LIMITS.minCelsius
    && celsius <= LIMITS.maxCelsius;
}

/**
 * Chooses the temperature used for decisions and describes where the heat is.
 *
 * The battery cell and the SoC are different sensors with different jobs: the cell
 * limits fast charging, the SoC is what throttles under load. A laptop at 34 °C cell
 * with an 80 °C package is a workload problem, not a charging problem.
 *
 * @param {{cellCelsius?: number|null, socCelsius?: number|null, socLabel?: string}} readings
 */
export function resolveHeat({ cellCelsius = null, socCelsius = null, socLabel = '' } = {}) {
  const cell = isPlausibleCelsius(cellCelsius) ? cellCelsius : null;
  const soc = isPlausibleCelsius(socCelsius) ? socCelsius : null;

  const effective = cell ?? soc;
  let heatSource;
  if (cell !== null && soc !== null) {
    const gap = soc - cell;
    heatSource = gap >= 5
      ? `The CPU/SoC is ${gap.toFixed(1)} °C hotter than the battery — this heat is workload, not the cell.`
      : 'Heat source: battery cell and SoC are close together.';
  } else if (cell !== null) {
    heatSource = 'Heat source: battery cell.';
  } else if (soc !== null) {
    heatSource = `Heat source: ${socLabel || 'SoC sensor'} (battery cell not reported).`;
  } else {
    heatSource = 'No temperature sensor is readable on this device.';
  }

  return {
    effectiveCelsius: effective,
    effectiveSource: cell !== null ? Source.MEASURED : (soc !== null ? Source.DERIVED : Source.UNAVAILABLE),
    cellCelsius: cell,
    socCelsius: soc,
    socLabel,
    heatSource
  };
}

/**
 * Builds the one-line summary used in notifications.
 *
 * Only measured components appear. An unavailable sensor contributes an explicit
 * "not reported" phrase instead of a zero, because "0 mA" is a plausible-looking lie.
 */
export function summaryLine(snapshot) {
  const parts = [`${snapshot.percent}%`];

  if (snapshot.current.source === Source.MEASURED && snapshot.current.milliAmps !== 0) {
    const magnitude = Math.abs(snapshot.current.milliAmps);
    const sign = snapshot.current.milliAmps > 0 ? '+' : '-';
    const watts = snapshot.powerMilliWatts === null || snapshot.powerMilliWatts === undefined
      ? ''
      : ` (${(Math.abs(snapshot.powerMilliWatts) / 1000).toFixed(1)} W)`;
    parts.push(`${sign}${magnitude} mA${watts}`);
  } else {
    parts.push('current not reported');
  }

  if (snapshot.heat.cellCelsius !== null) parts.push(`${snapshot.heat.cellCelsius.toFixed(1)}°C cell`);
  if (snapshot.heat.socCelsius !== null) parts.push(`${snapshot.heat.socCelsius.toFixed(1)}°C chip`);
  if (snapshot.heat.cellCelsius === null && snapshot.heat.socCelsius === null) {
    parts.push('no temperature sensor readable');
  }

  if (snapshot.energyMilliWattHours !== null) {
    parts.push(`${(snapshot.energyMilliWattHours / 1000).toFixed(1)} Wh stored`);
  }

  return parts.join(' • ');
}

/**
 * Assembles a snapshot from an adapter's raw output.
 *
 * @param {object} raw
 * @param {number} raw.percent
 * @param {boolean} raw.isCharging
 * @param {string} [raw.chargingLabel]
 * @param {number|null} [raw.currentMilliAmps]
 * @param {number|null} [raw.voltageMilliVolts]
 * @param {number|null} [raw.cellCelsius]
 * @param {number|null} [raw.socCelsius]
 * @param {string} [raw.socLabel]
 * @param {number|null} [raw.chargeMilliAmpHours]
 * @param {string} [raw.healthLabel]
 * @param {string} [raw.platform]
 */
export function buildSnapshot(raw) {
  const percent = Number.isFinite(raw.percent) ? Math.max(0, Math.min(100, Math.round(raw.percent))) : 0;
  const current = normaliseCurrent(raw.currentMilliAmps ?? null, !!raw.isCharging);
  const measured = current.source === Source.MEASURED;
  const power = powerMilliWatts(raw.voltageMilliVolts ?? null, current.milliAmps, measured);
  const heat = resolveHeat({
    cellCelsius: raw.cellCelsius ?? null,
    socCelsius: raw.socCelsius ?? null,
    socLabel: raw.socLabel || ''
  });

  return {
    platform: raw.platform || 'unknown',
    percent,
    isCharging: !!raw.isCharging,
    chargingLabel: raw.chargingLabel || (raw.isCharging ? 'Charging' : 'Discharging'),
    current,
    powerMilliWatts: power,
    heat,
    voltageMilliVolts: isPlausibleVoltage(raw.voltageMilliVolts) ? raw.voltageMilliVolts : null,
    chargeMilliAmpHours: raw.chargeMilliAmpHours ?? null,
    energyMilliWattHours: energyMilliWattHours(raw.chargeMilliAmpHours ?? null, raw.voltageMilliVolts ?? null),
    healthLabel: raw.healthLabel || 'Not reported',
    readingAtMs: raw.readingAtMs ?? 0
  };
}
