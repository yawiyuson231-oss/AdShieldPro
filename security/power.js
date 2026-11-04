/**
 * OmniShield X — power governor.
 *
 * The monitor loop repaints once a second while a live view is open. On a phone
 * that is the single largest avoidable battery cost in this app, so the cadence
 * is derived from measured device state instead of a hard-coded constant.
 *
 * Rules (deliberately boring, so behaviour is predictable):
 *   - charging or plugged in ............ 1x
 *   - battery >= 25% .................... 1x
 *   - battery <  25% and discharging .... 2x slower
 *   - battery <  10% and discharging .... 4x slower
 *   - Battery Status API unavailable .... 1x, reported as unsupported
 *
 * The governor never changes what is analysed or blocked — only how often an
 * open view is repainted. Nothing here is a security decision.
 */

const DEFAULT_THRESHOLDS = { low: 0.25, critical: 0.1 };
const DEFAULT_FACTORS = { normal: 1, low: 2, critical: 4 };

export class PowerGovernor {
  /**
   * @param {{getBattery?:Function, thresholds?:{low:number,critical:number},
   *          factors?:{normal:number,low:number,critical:number},
   *          onChange?:Function, now?:Function}} [options]
   */
  constructor(options = {}) {
    this.getBattery = options.getBattery
      ?? (typeof navigator !== 'undefined' && typeof navigator.getBattery === 'function'
        ? () => navigator.getBattery()
        : null);
    this.thresholds = { ...DEFAULT_THRESHOLDS, ...(options.thresholds || {}) };
    this.factors = { ...DEFAULT_FACTORS, ...(options.factors || {}) };
    this.onChange = options.onChange ?? null;
    this.now = options.now ?? (() => Date.now());
    this.battery = null;
    this.level = null;
    this.charging = null;
    this.supported = false;
    this.reason = 'not started';
    this.startedAt = null;
    this.changes = 0;
    this._listeners = [];
  }

  /** Current throttle band: 'normal' | 'low' | 'critical'. */
  get band() {
    if (!this.supported || this.level === null) return 'normal';
    if (this.charging) return 'normal';
    if (this.level < this.thresholds.critical) return 'critical';
    if (this.level < this.thresholds.low) return 'low';
    return 'normal';
  }

  get factor() { return this.factors[this.band] ?? 1; }

  /** Applies the current band to a base interval, clamped to sane bounds. */
  intervalFor(baseMs) {
    const base = Number(baseMs) > 0 ? Number(baseMs) : 1000;
    return Math.max(250, Math.min(60000, Math.round(base * this.factor)));
  }

  /** Human-readable state for the UI. Never claims support it does not have. */
  describe() {
    if (!this.supported) {
      return {
        supported: false,
        band: 'normal',
        factor: 1,
        summary: `Battery-aware scheduling unavailable (${this.reason}). Using the default refresh cadence.`
      };
    }
    const pct = Math.round((this.level ?? 0) * 100);
    const state = this.charging ? 'charging' : 'on battery';
    const effect = this.factor === 1
      ? 'default cadence'
      : `${this.factor}x slower repaint`;
    return {
      supported: true,
      band: this.band,
      factor: this.factor,
      level: this.level,
      charging: this.charging,
      summary: `${pct}% ${state} · ${effect}`
    };
  }

  /**
   * Subscribes to the battery. Resolves to the describe() snapshot. Failure is
   * reported, never hidden: an unsupported browser simply keeps the default.
   */
  async start() {
    if (this.startedAt !== null) return this.describe();
    this.startedAt = this.now();
    if (typeof this.getBattery !== 'function') {
      this.reason = 'Battery Status API not exposed by this browser';
      return this.describe();
    }
    try {
      const battery = await this.getBattery();
      if (!battery || typeof battery.level !== 'number') {
        this.reason = 'Battery Status API returned no level';
        return this.describe();
      }
      this.battery = battery;
      this.supported = true;
      this.reason = 'ok';
      // The first read establishes state; it is not a *change*, so no event.
      this._read({ silent: true });
      const onLevel = () => { this._read(); };
      battery.addEventListener?.('levelchange', onLevel);
      battery.addEventListener?.('chargingchange', onLevel);
      this._listeners = [['levelchange', onLevel], ['chargingchange', onLevel]];
      return this.describe();
    } catch (err) {
      this.reason = err?.message || 'battery query failed';
      return this.describe();
    }
  }

  _read({ silent = false } = {}) {
    const previousBand = this.band;
    const previousLevel = this.level;
    this.level = typeof this.battery?.level === 'number' ? this.battery.level : null;
    this.charging = this.battery?.charging === true;
    const band = this.band;
    if (silent) return;
    if (band !== previousBand || this.level !== previousLevel) {
      this.changes++;
      try { this.onChange?.(this.describe()); } catch { /* observers must not break scheduling */ }
    }
  }

  /** Feeds an externally observed value (tests, or a native bridge). */
  observe({ level, charging }) {
    this.supported = true;
    this.reason = 'ok';
    this.battery = { level, charging };
    this._read();
    return this.describe();
  }

  stop() {
    for (const [type, handler] of this._listeners) {
      try { this.battery?.removeEventListener?.(type, handler); } catch { /* ignore */ }
    }
    this._listeners = [];
  }
}

export default PowerGovernor;
