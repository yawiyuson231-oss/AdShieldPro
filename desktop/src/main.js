/**
 * AdShield battery monitor — desktop entry point.
 *
 * Deliberately dependency-free: Node's standard library only. That keeps the
 * repository's "no runtime npm dependencies" rule intact and means the same file runs
 * on Windows, macOS and Linux without a build step. The tray/menu-bar shell, if you
 * want one, is the only piece that would need a native dependency, and it can wrap
 * this process instead of being required by it.
 *
 * What it does:
 *   - samples the platform adapter every N seconds
 *   - writes the latest snapshot to a state file that other tools can read
 *   - evaluates the alert rules and delivers notifications
 *   - serves a small JSON endpoint for a local UI
 *
 * Usage:
 *   node desktop/src/main.js              # run
 *   node desktop/src/main.js --once       # one reading, print JSON, exit
 *   node desktop/src/main.js --serve 7317 # also serve JSON on 127.0.0.1:7317
 */
import { createServer } from 'node:http';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { buildSnapshot, summaryLine } from './core/battery.js';
import { DEFAULT_SETTINGS, emptyState, unavailableReasons, evaluate, clampSettings } from './core/alerts.js';
import { readSnapshot as readLinux } from './adapters/linux.js';
import { readSnapshot as readMac } from './adapters/macos.js';
import { readSnapshot as readWindows } from './adapters/windows.js';

const CONFIG_DIR = process.env.ADSHIELD_CONFIG_DIR || join(homedir(), '.config', 'adshield');
const SETTINGS_PATH = join(CONFIG_DIR, 'battery-settings.json');
const STATE_PATH = join(CONFIG_DIR, 'battery-state.json');

/** Picks the adapter for this machine. */
export function adapterFor(platform = process.platform) {
  if (platform === 'linux') return readLinux;
  if (platform === 'darwin') return readMac;
  if (platform === 'win32') return readWindows;
  return async ({ nowMs }) => buildSnapshot({
    platform, percent: 0, isCharging: false,
    chargingLabel: `Unsupported platform: ${platform}`, readingAtMs: nowMs
  });
}

export function loadSettings() {
  try {
    return clampSettings({ ...DEFAULT_SETTINGS, ...JSON.parse(readFileSync(SETTINGS_PATH, 'utf8')) });
  } catch {
    return clampSettings(DEFAULT_SETTINGS);
  }
}

export function saveSettings(settings) {
  mkdirSync(CONFIG_DIR, { recursive: true });
  writeFileSync(SETTINGS_PATH, `${JSON.stringify(clampSettings(settings), null, 2)}\n`);
}

function loadState() {
  try {
    return { ...emptyState(), ...JSON.parse(readFileSync(STATE_PATH, 'utf8')) };
  } catch {
    return emptyState();
  }
}

function saveState(state) {
  mkdirSync(CONFIG_DIR, { recursive: true });
  writeFileSync(STATE_PATH, `${JSON.stringify(state, null, 2)}\n`);
}

/**
 * Delivers a notification with the platform's own notifier.
 *
 * No npm package: each platform already has a shell command that shows a desktop
 * notification. If none is available the alert is still printed, so a missing notifier
 * degrades to a log line instead of a crash.
 */
export function notify(title, body, { platform = process.platform, runner = execFile } = {}) {
  const safe = (s) => s.replace(/["`\\$]/g, ' ');
  if (platform === 'darwin') {
    runner('osascript', ['-e', `display notification "${safe(body)}" with title "${safe(title)}"`], () => {});
    return true;
  }
  if (platform === 'linux') {
    runner('notify-send', ['--app-name=AdShield', '--urgency=normal', title, body], () => {});
    return true;
  }
  if (platform === 'win32') {
    // A toast needs an app id; a PowerShell balloon uses the built-in notifier.
    const script = [
      '[reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null',
      '$n = New-Object System.Windows.Forms.NotifyIcon',
      '$n.Icon = [System.Drawing.SystemIcons]::Information',
      '$n.Visible = $true',
      `$n.ShowBalloonTip(8000, "${safe(title)}", "${safe(body)}", 0)`
    ].join('; ');
    runner('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], () => {});
    return true;
  }
  return false;
}

/** One sample + alert evaluation. Exported so tests drive it without the loop. */
export async function tick({ platform = process.platform, nowMs = Date.now(), settings, state, deliver = notify } = {}) {
  const adapter = adapterFor(platform);
  const snapshot = await adapter({ nowMs });
  const activeSettings = settings || loadSettings();
  const activeState = state || loadState();

  const { alerts, state: nextState } = evaluate(snapshot, activeSettings, activeState, nowMs);

  for (const alert of alerts) {
    deliver(alert.title, alert.body, { platform });
  }

  const result = {
    snapshot,
    summary: summaryLine(snapshot),
    alerts,
    state: nextState,
    limitations: unavailableReasons(snapshot)
  };
  return result;
}

/** Minimal HTTP surface for a local UI or a Stream Deck-style consumer. */
export function serve(port, getLatest) {
  const server = createServer((req, res) => {
    const send = (code, body) => {
      res.writeHead(code, {
        'content-type': 'application/json; charset=utf-8',
        // Loopback-only tool; a page on the same machine may read it.
        'access-control-allow-origin': '*',
        'cache-control': 'no-store'
      });
      res.end(JSON.stringify(body, null, 2));
    };
    if (req.url === '/health') return send(200, { ok: true });
    if (req.url === '/battery') {
      const latest = getLatest();
      return latest ? send(200, latest) : send(503, { error: 'no reading yet' });
    }
    return send(404, { error: 'not found; try /battery' });
  });
  // Bound to loopback on purpose: battery telemetry is local data and this server has
  // no authentication.
  server.listen(port, '127.0.0.1');
  return server;
}

async function main() {
  const args = process.argv.slice(2);
  const once = args.includes('--once');
  const serveIndex = args.indexOf('--serve');
  const port = serveIndex !== -1 ? Number(args[serveIndex + 1]) || 7317 : null;
  const intervalIndex = args.indexOf('--interval');
  const intervalMs = intervalIndex !== -1 ? Number(args[intervalIndex + 1]) * 1000 : 5000;

  if (once) {
    const result = await tick({});
    console.log(JSON.stringify({
      summary: result.summary,
      platform: result.snapshot.platform,
      percent: result.snapshot.percent,
      currentMilliAmps: result.snapshot.current.source === 'measured' ? result.snapshot.current.milliAmps : null,
      powerMilliWatts: result.snapshot.powerMilliWatts,
      voltageMilliVolts: result.snapshot.voltageMilliVolts,
      cellCelsius: result.snapshot.heat.cellCelsius,
      socCelsius: result.snapshot.heat.socCelsius,
      heatSource: result.snapshot.heat.heatSource,
      energyMilliWattHours: result.snapshot.energyMilliWattHours,
      healthLabel: result.snapshot.healthLabel,
      limitations: result.limitations
    }, null, 2));
    return;
  }

  let latest = null;
  if (port) serve(port, () => latest);

  const run = async () => {
    try {
      latest = await tick({});
      saveState(latest.state);
      if (process.stdout.isTTY) {
        process.stdout.write(`\r${latest.summary}`.padEnd(120));
      }
    } catch (err) {
      // A monitor that dies on a transient read error is not a monitor.
      console.error(`\nsample failed: ${err.message}`);
    }
  };

  await run();
  setInterval(run, Math.max(1000, intervalMs));

  process.on('SIGINT', () => {
    if (process.stdout.isTTY) process.stdout.write('\n');
    process.exit(0);
  });
}

if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
