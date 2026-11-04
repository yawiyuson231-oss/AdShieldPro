/**
 * Unit tests — battery/CPU governor.
 *
 * The governor only ever changes how often an open view is repainted. These
 * tests pin that down, including the "API unavailable" path that must not be
 * dressed up as optimisation.
 */
import test from 'node:test';
import { strict as assert } from 'node:assert';
import { PowerGovernor } from '../../security/power.js';

function fakeBattery(level, charging = false) {
  const listeners = new Map();
  return {
    level,
    charging,
    addEventListener(type, fn) { listeners.set(type, fn); },
    removeEventListener(type, fn) { if (listeners.get(type) === fn) listeners.delete(type); },
    emit(type) { listeners.get(type)?.(); },
    listeners
  };
}

test('unsupported battery API is reported, not hidden', async () => {
  const gov = new PowerGovernor({ getBattery: null });
  const info = await gov.start();
  assert.equal(info.supported, false);
  assert.equal(info.factor, 1);
  assert.match(info.summary, /unavailable/i);
  assert.match(info.summary, /default refresh cadence/i);
});

test('a rejected battery query degrades to the default cadence', async () => {
  const gov = new PowerGovernor({ getBattery: async () => { throw new Error('permission denied'); } });
  const info = await gov.start();
  assert.equal(info.supported, false);
  assert.match(info.summary, /permission denied/);
  assert.equal(gov.intervalFor(1000), 1000);
});

test('bands follow battery level and charging state', async () => {
  const battery = fakeBattery(0.8, false);
  const changes = [];
  const gov = new PowerGovernor({ getBattery: async () => battery, onChange: (i) => changes.push(i.band) });
  await gov.start();
  assert.equal(gov.band, 'normal');
  assert.equal(gov.factor, 1);

  battery.level = 0.2; battery.emit('levelchange');
  assert.equal(gov.band, 'low');
  assert.equal(gov.intervalFor(1000), 2000);

  battery.level = 0.05; battery.emit('levelchange');
  assert.equal(gov.band, 'critical');
  assert.equal(gov.intervalFor(1000), 4000);

  // Plugging in restores the fast cadence immediately.
  battery.charging = true; battery.emit('chargingchange');
  assert.equal(gov.band, 'normal');
  assert.equal(gov.intervalFor(1000), 1000);

  assert.deepEqual(changes, ['low', 'critical', 'normal']);
});

test('intervals are clamped to sane bounds', () => {
  const gov = new PowerGovernor({ getBattery: null });
  gov.observe({ level: 0.01, charging: false });
  assert.equal(gov.intervalFor(100), 400, '250 ms floor applies to the base before throttling');
  assert.equal(gov.intervalFor(60000), 60000, '60 s ceiling holds');
  assert.equal(gov.intervalFor(0), 4000, 'invalid base falls back to 1 s, then throttles');
  assert.equal(gov.intervalFor('nonsense'), 4000, 'non-numeric base is not trusted');
  gov.observe({ level: 0.9, charging: false });
  assert.equal(gov.intervalFor(0), 1000, 'invalid base falls back to 1 s at the default cadence');
});

test('describe() reports measured percentages, never a guess', async () => {
  const battery = fakeBattery(0.42, false);
  const gov = new PowerGovernor({ getBattery: async () => battery });
  await gov.start();
  const info = gov.describe();
  assert.equal(info.supported, true);
  assert.equal(info.level, 0.42);
  assert.match(info.summary, /42%/);
  assert.match(info.summary, /on battery/);
  assert.match(info.summary, /default cadence/);
});

test('stop() unsubscribes from the battery object', async () => {
  const battery = fakeBattery(0.5, false);
  const gov = new PowerGovernor({ getBattery: async () => battery });
  await gov.start();
  assert.equal(battery.listeners.size, 2);
  gov.stop();
  assert.equal(battery.listeners.size, 0);
  // Changes after stop must not fire the observer.
  let fired = 0;
  const gov2 = new PowerGovernor({ getBattery: async () => battery, onChange: () => { fired++; } });
  await gov2.start();
  assert.equal(fired, 0, 'establishing initial state is not a change event');
  gov2.stop();
  battery.level = 0.01; battery.emit('levelchange');
  assert.equal(fired, 0);
});
