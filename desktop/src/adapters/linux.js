/**
 * Linux battery adapter — reads /sys/class/power_supply.
 *
 * The sysfs tree is the only portable source on Linux, and its shape varies by
 * hardware:
 *   - laptops expose `BAT0`/`BAT1` with `energy_now`/`energy_full`/`power_now`
 *   - some expose `charge_now`/`charge_full`/`current_now` instead
 *   - `status` is `Charging`, `Discharging`, `Full`, `Not charging` or `Unknown`
 *   - current signs are inconsistent between drivers, so the charging state wins
 *
 * Nothing here assumes a laptop: a desktop with no battery returns a snapshot that
 * says so, rather than a fabricated 100%.
 */
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { buildSnapshot } from '../core/battery.js';

const SUPPLY_ROOT = '/sys/class/power_supply';

function readValue(root, dir, name) {
  const path = join(root, dir, name);
  if (!existsSync(path)) return null;
  try {
    const raw = readFileSync(path, 'utf8').trim();
    const n = Number(raw);
    return Number.isFinite(n) ? n : null;
  } catch {
    return null;
  }
}

function readText(root, dir, name) {
  const path = join(root, dir, name);
  if (!existsSync(path)) return null;
  try {
    return readFileSync(path, 'utf8').trim();
  } catch {
    return null;
  }
}

/** Micro-unit conversions used by the sysfs ABI. */
const micro = (v) => (v === null ? null : v / 1_000_000);
const milli = (v) => (v === null ? null : v / 1_000);

/** Picks the battery with the largest capacity; ignores USB/AC/mains supplies. */
export function pickBattery(root = SUPPLY_ROOT) {
  if (!existsSync(root)) return null;
  const dirs = readdirSync(root);
  const batteries = dirs.filter((d) => {
    const type = readText(root, d, 'type');
    return type === 'Battery' && (readText(root, d, 'present') !== '0');
  });
  if (batteries.length === 0) return null;
  if (batteries.length === 1) return batteries[0];

  let best = batteries[0];
  let bestCapacity = -1;
  for (const dir of batteries) {
    const capacity = readValue(root, dir, 'energy_full') ?? readValue(root, dir, 'charge_full') ?? 0;
    if (capacity > bestCapacity) {
      best = dir;
      bestCapacity = capacity;
    }
  }
  return best;
}

/**
 * Reads one battery into a snapshot.
 *
 * @param {{root?: string}} [options] `root` is injectable so tests can point at fixtures.
 */
export function readSnapshot({ root = SUPPLY_ROOT, nowMs = 0 } = {}) {
  const battery = pickBattery(root);
  if (!battery) {
    return buildSnapshot({
      platform: 'linux',
      percent: 0,
      isCharging: false,
      chargingLabel: 'No battery detected',
      healthLabel: 'Not applicable',
      readingAtMs: nowMs
    });
  }

  const status = readText(root, battery, 'status') || 'Unknown';
  const isCharging = status === 'Charging' || status === 'Full';

  // Percentage: prefer the driver's own capacity, fall back to the energy ratio.
  let percent = readValue(root, battery, 'capacity');
  const energyNow = micro(readValue(root, battery, 'energy_now'));
  const energyFull = micro(readValue(root, battery, 'energy_full'));
  const chargeNow = milli(readValue(root, battery, 'charge_now'));
  const chargeFull = milli(readValue(root, battery, 'charge_full'));

  if (percent === null) {
    if (energyNow !== null && energyFull) percent = (energyNow / energyFull) * 100;
    else if (chargeNow !== null && chargeFull) percent = (chargeNow / chargeFull) * 100;
    else percent = 0;
  }

  // Current: `current_now` (µA) is the direct reading. Some drivers only expose
  // `power_now` (µW), which is power, not current — converting it would need the
  // voltage and would be a derivation on top of a derivation, so it is left null.
  const currentMicroAmps = readValue(root, battery, 'current_now');
  const currentMilliAmps = currentMicroAmps === null ? null : currentMicroAmps / 1000;

  // Voltage: `voltage_now` is µV on almost every driver, but a few report mV.
  const rawVoltage = readValue(root, battery, 'voltage_now');
  const voltageMilliVolts = rawVoltage === null
    ? null
    : (rawVoltage > 100_000 ? rawVoltage / 1000 : rawVoltage);

  // Energy is exposed in Wh directly; charge counters are in Ah.
  const chargeMilliAmpHours = chargeNow !== null ? Math.round(chargeNow) : null;
  const energyMilliWattHours = energyNow !== null ? Math.round(energyNow * 1000) : null;

  // Cell temperature: `temp` is in tenths of a degree on the batteries that have it.
  const tempTenths = readValue(root, battery, 'temp');
  const cellCelsius = tempTenths === null ? null : tempTenths / 10;

  const snapshot = buildSnapshot({
    platform: 'linux',
    percent,
    isCharging,
    chargingLabel: status === 'Full' ? 'Fully charged' : status,
    currentMilliAmps,
    voltageMilliVolts,
    cellCelsius,
    // SoC temperature on Linux is per-core and unit-specific; the generic thermal
    // zones are not a reliable package temperature, so it is reported as unavailable
    // rather than reading a random zone.
    socCelsius: null,
    socLabel: '',
    chargeMilliAmpHours,
    healthLabel: readText(root, battery, 'health') || 'Not reported',
    readingAtMs: nowMs
  });

  // `energy_now` from sysfs is already mWh; prefer it over the charge x voltage
  // derivation, which loses precision on devices that report charge in Ah.
  if (energyMilliWattHours !== null) snapshot.energyMilliWattHours = energyMilliWattHours;
  snapshot.batteryName = battery;
  return snapshot;
}
