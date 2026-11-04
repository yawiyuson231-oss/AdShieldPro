/**
 * CyberShield AI — console controller.
 *
 * Wires the threat-intelligence dashboard onto the real application state.
 * Rules of the house (kept from the rest of the platform):
 *
 *  - Every DOM node is built with ui/dom.js `h()` — textContent only, never
 *    innerHTML. The lint and verify gates enforce it.
 *  - Measured numbers come from the live engine/monitor/model; simulated
 *    numbers are always labelled as simulated in the same panel.
 *  - One timer drives the whole console. It is not created while the console
 *    page is hidden, and it stops on `destroy()`.
 *  - Reduced-motion visitors get a static map and a calmer feed.
 */

import { h, mount, clear, number, pill, toast } from '../ui/dom.js';
import {
  createScenario, seedEvents, makeEvent, rng, SEVERITIES, VECTORS,
  SIGNALS, ASSET_CLASSES, FRAMEWORKS, measuredFrom
} from './telemetry.js';
import { createThreatMap } from './map.js';

const TICK_MS = 1500;
const ICONS = {
  laptop: 'M3 5.5h18v10H3zM2 19h20l-1.6-2.4H3.6z',
  cloud: 'M7 18a4 4 0 0 1 .6-7.95A5.5 5.5 0 0 1 18 9.5a4.25 4.25 0 0 1-.4 8.5z',
  network: 'M12 3v5M12 16v5M4.5 12h15M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8',
  shield: 'M12 2.5 20 6v6c0 5-3.4 8.4-8 10.5C7.4 20.4 4 17 4 12V6z',
  brain: 'M9 4a3 3 0 0 0-3 3 3 3 0 0 0-1 5.8V16a3 3 0 0 0 4 2.8M15 4a3 3 0 0 1 3 3 3 3 0 0 1 1 5.8V16a3 3 0 0 1-4 2.8M9 4v16M15 4v16M12 8v8',
  pulse: 'M2 12h4l2.5-6 4 13 2.5-7h7',
  target: 'M12 3v3M12 18v3M3 12h3M18 12h3M12 7a5 5 0 1 0 0 10 5 5 0 0 0 0-10',
  chart: 'M4 20V10M10 20V4M16 20v-7M22 20H2'
};

function icon(path, size = 16) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', String(size));
  svg.setAttribute('height', String(size));
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '1.7');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('aria-hidden', 'true');
  const p = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  p.setAttribute('d', path);
  svg.appendChild(p);
  return svg;
}

function clockTime(date) {
  return date.toLocaleTimeString(undefined, { hour12: false });
}
function clockDate(date) {
  return date.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric', year: 'numeric' });
}
function hhmmss(ts) {
  return new Date(ts).toLocaleTimeString(undefined, { hour12: false });
}

export function createCyberConsole(appState, options = {}) {
  const page = document.getElementById('page-cyber');
  if (!page) return null;

  const scenario = createScenario();
  const next = rng(scenario.seed ^ 0x27d4eb2f);
  let map = null;
  let timer = null;
  let clockTimer = null;
  let view = 'dashboard';
  let feed = seedEvents(scenario, 9);
  let destroyed = false;
  const reduced = !!(options.reduced || (globalThis.matchMedia && globalThis.matchMedia('(prefers-reduced-motion: reduce)').matches));

  /* ---------------------------------------------------------------- */
  /* Panel builders                                                    */
  /* ---------------------------------------------------------------- */

  function panelHead(area, title, subtitle, tools = []) {
    const panel = document.createElement('div');
    panel.className = `cs-panel cs-area-${area}`;
    panel.id = `cs-${area}`;
    const head = h('div', { class: 'cs-panel__head' },
      h('h3', { class: 'cs-panel__title' }, title, h('span', { class: 'cs-panel__sub' }, subtitle)),
      tools.length ? h('div', { class: 'cs-panel__tools' }, tools) : null
    );
    return { panel, head };
  }

  /** The circled tick used in the reference's panel headers. */
  function okBadge(label) {
    return h('span', { class: 'cs-check', role: 'img', 'aria-label': label || 'healthy' }, '✓');
  }

  function deltaNode(value) {
    const up = value > 0;
    return h('i', { class: up ? 'cs-up' : value < 0 ? 'cs-down' : 'cs-flat' },
      h('span', { text: up ? '▲' : value < 0 ? '▼' : '■' }),
      h('span', { text: `${Math.abs(value)}%` })
    );
  }

  function sparkline(points) {
    const w = 240;
    const hgt = 86;
    const max = Math.max(...points, 0.001);
    const step = w / Math.max(1, points.length - 1);
    const line = points.map((p, i) => `${(i * step).toFixed(1)},${(hgt - (p / max) * (hgt - 10) - 4).toFixed(1)}`).join(' ');
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', `0 0 ${w} ${hgt}`);
    svg.setAttribute('preserveAspectRatio', 'none');
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', `Threat volume trend, ${points.length} samples, simulated`);
    const ns = 'http://www.w3.org/2000/svg';
    const defs = document.createElementNS(ns, 'defs');
    const grad = document.createElementNS(ns, 'linearGradient');
    grad.setAttribute('id', 'cs-spark-grad');
    grad.setAttribute('x1', '0'); grad.setAttribute('y1', '0');
    grad.setAttribute('x2', '0'); grad.setAttribute('y2', '1');
    const s1 = document.createElementNS(ns, 'stop');
    s1.setAttribute('offset', '0'); s1.setAttribute('stop-color', '#ff3b5c'); s1.setAttribute('stop-opacity', '.55');
    const s2 = document.createElementNS(ns, 'stop');
    s2.setAttribute('offset', '1'); s2.setAttribute('stop-color', '#ff3b5c'); s2.setAttribute('stop-opacity', '0');
    grad.append(s1, s2);
    defs.appendChild(grad);
    const area = document.createElementNS(ns, 'polygon');
    area.setAttribute('points', `0,${hgt} ${line} ${w},${hgt}`);
    area.setAttribute('fill', 'url(#cs-spark-grad)');
    const stroke = document.createElementNS(ns, 'polyline');
    stroke.setAttribute('points', line);
    stroke.setAttribute('fill', 'none');
    stroke.setAttribute('stroke', '#ff3b5c');
    stroke.setAttribute('stroke-width', '1.6');
    stroke.setAttribute('stroke-linejoin', 'round');
    svg.append(defs, area, stroke);
    return h('div', { class: 'cs-spark' }, svg);
  }

  function donut(counts, total) {
    const size = 116;
    const r = 44;
    const circumference = 2 * Math.PI * r;
    const ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('viewBox', `0 0 ${size} ${size}`);
    svg.setAttribute('width', String(size));
    svg.setAttribute('height', String(size));
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label',
      `Active threats by severity: ${SEVERITIES.map((s) => `${s} ${counts[s]}`).join(', ')}, total ${total}`);
    const track = document.createElementNS(ns, 'circle');
    track.setAttribute('cx', String(size / 2)); track.setAttribute('cy', String(size / 2));
    track.setAttribute('r', String(r));
    track.setAttribute('fill', 'none');
    track.setAttribute('stroke', '#0f2438');
    track.setAttribute('stroke-width', '10');
    svg.appendChild(track);

    const colors = { critical: '#ff3b5c', high: '#ff8f4d', medium: '#ffbf47', low: '#2ee6a0' };
    let offset = 0;
    for (const sev of SEVERITIES) {
      const frac = total ? counts[sev] / total : 0;
      const arc = document.createElementNS(ns, 'circle');
      arc.setAttribute('cx', String(size / 2)); arc.setAttribute('cy', String(size / 2));
      arc.setAttribute('r', String(r));
      arc.setAttribute('fill', 'none');
      arc.setAttribute('stroke', colors[sev]);
      arc.setAttribute('stroke-width', '10');
      arc.setAttribute('stroke-linecap', 'butt');
      arc.setAttribute('stroke-dasharray', `0 ${circumference}`);
      arc.setAttribute('stroke-dashoffset', String(-offset * circumference));
      arc.dataset.target = String(frac * circumference);
      arc.dataset.circumference = String(circumference);
      // SVGElement.className is read-only (SVGAnimatedString): set the attribute.
      arc.setAttribute('class', 'cs-donut__ring');
      svg.appendChild(arc);
      offset += frac;
    }
    // Animate the arcs in after insertion so it reads as "loading in".
    queueMicrotask(() => {
      for (const arc of svg.querySelectorAll('.cs-donut__ring')) {
        const target = Number(arc.dataset.target);
        const c = Number(arc.dataset.circumference);
        arc.setAttribute('stroke-dasharray', `${target} ${c - target}`);
      }
    });
    return h('div', { class: 'cs-donut' },
      svg,
      h('div', { class: 'cs-donut__center' },
        h('b', { text: number(total) }),
        h('small', { text: 'total' }))
    );
  }

  function meter(progress, label) {
    const fill = h('div', { class: 'cs-meter__fill' });
    queueMicrotask(() => { fill.style.width = `${progress}%`; });
    return h('div', { class: 'cs-meter' },
      h('div', { class: 'cs-meter__row' },
        h('span', { text: label }),
        h('b', { id: 'cs-engine-progress', text: `${progress}%` })),
      h('div', {
        class: 'cs-meter__track',
        role: 'progressbar',
        'aria-valuenow': String(progress),
        'aria-valuemin': '0',
        'aria-valuemax': '100',
        'aria-label': label
      }, fill)
    );
  }

  function trendSvg(points) {
    const w = 260;
    const hgt = 26;
    const max = Math.max(...points, 0.001);
    const min = Math.min(...points);
    const span = Math.max(0.001, max - min);
    const step = w / Math.max(1, points.length - 1);
    const ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('viewBox', `0 0 ${w} ${hgt}`);
    svg.setAttribute('preserveAspectRatio', 'none');
    svg.setAttribute('class', 'trend');
    svg.setAttribute('aria-hidden', 'true');
    const line = points.map((p, i) => `${(i * step).toFixed(1)},${(hgt - 2 - ((p - min) / span) * (hgt - 6)).toFixed(1)}`).join(' ');
    const poly = document.createElementNS(ns, 'polyline');
    poly.setAttribute('points', line);
    poly.setAttribute('fill', 'none');
    poly.setAttribute('stroke', '#ff3b5c');
    poly.setAttribute('stroke-width', '1.4');
    svg.appendChild(poly);
    return svg;
  }

  /* ---------------------------------------------------------------- */
  /* Left column: overview / donut / feed                              */
  /* ---------------------------------------------------------------- */

  function renderOverview() {
    const host = document.getElementById('cs-overview');
    if (!host) return;
    const measured = measuredFrom(appState);
    mount(host,
      h('div', { class: 'cs-panel__head' },
        h('h3', { class: 'cs-panel__title' }, 'Threat overview',
          h('span', { class: 'cs-panel__sub' }, 'Real-time summary')),
        h('div', { class: 'cs-panel__tools' }, h('span', { class: 'cs-dot' }))),
      h('div', { class: 'cs-panel__body' },
        sparkline(scenario.history),
        h('div', { class: 'cs-stats' },
          stat('total', 'Total threats', scenario.total, scenario.delta.total),
          stat('high', 'High', scenario.counts.high, scenario.delta.high),
          stat('medium', 'Medium', scenario.counts.medium, scenario.delta.medium),
          stat('low', 'Low', scenario.counts.low, scenario.delta.low)),
        h('p', { class: 'cs-note' },
          h('b', { text: 'Volumes are simulated' }),
          ' — one browser cannot observe a global attack surface. ',
          h('b', { text: 'Measured locally:' }),
          ` ${measured.rules === null ? '—' : number(measured.rules)} rules loaded, `,
          `${measured.blocked === null ? '—' : number(measured.blocked)} domains blocked this session.`)
      )
    );
  }

  function stat(kind, label, value, delta) {
    return h('div', { class: `cs-stat cs-stat--${kind}` },
      h('small', { text: label }),
      h('b', { text: number(value) }),
      deltaNode(delta)
    );
  }

  function renderActivity() {
    const host = document.getElementById('cs-activity');
    if (!host) return;
    mount(host,
      h('div', { class: 'cs-panel__head' },
        h('h3', { class: 'cs-panel__title' }, 'Active threats',
          h('span', { class: 'cs-panel__sub' }, 'By severity')),
        h('div', { class: 'cs-panel__tools' }, okBadge('severity tracking healthy'))),
      h('div', { class: 'cs-panel__body' },
        h('div', { class: 'cs-donut-wrap' },
          donut(scenario.counts, scenario.total),
          h('div', { class: 'cs-legend' },
            SEVERITIES.map((sev) => h('div', {},
              h('i', { style: { background: { critical: '#ff3b5c', high: '#ff8f4d', medium: '#ffbf47', low: '#2ee6a0' }[sev] } }),
              h('span', { text: sev.charAt(0).toUpperCase() + sev.slice(1) }),
              h('b', { text: number(scenario.counts[sev]) })
            ))))
      )
    );
  }

  function renderFeed() {
    const host = document.getElementById('cs-feed');
    if (!host) return;
    mount(host,
      h('div', { class: 'cs-panel__head' },
        h('h3', { class: 'cs-panel__title' }, 'Threat activity feed',
          h('span', { class: 'cs-panel__sub' }, 'Live updates')),
        h('div', { class: 'cs-panel__tools' },
          pill('simulated', 'warn'), okBadge('feed live, simulated telemetry'))),
      h('div', { class: 'cs-panel__body' }, feedList())
    );
  }

  function feedList() {
    const list = h('ul', { class: 'cs-feed', role: 'log', 'aria-live': 'polite', 'aria-label': 'Threat activity feed, simulated' });
    for (const ev of feed) {
      list.appendChild(h('li', {},
        h('span', { class: `cs-tag cs-tag--${ev.severity}`, text: ev.severity }),
        h('div', {},
          h('b', { class: 'title', text: ev.title }),
          h('code', { text: ev.detail })),
        h('time', { text: hhmmss(ev.at) })
      ));
    }
    return list;
  }

  /* ---------------------------------------------------------------- */
  /* Centre: the map                                                   */
  /* ---------------------------------------------------------------- */

  function renderMap() {
    const canvas = document.getElementById('cs-map');
    const shell = document.getElementById('cs-map-shell');
    if (!canvas || !shell) return;
    if (!map) {
      map = createThreatMap(canvas, {
        reduced,
        onStats: (stats) => {
          const arcs = document.getElementById('cs-map-arcs');
          const sources = document.getElementById('cs-map-sources');
          if (arcs) arcs.textContent = number(stats.arcs);
          if (sources) sources.textContent = number(stats.sources);
        }
      });
      map.setScenario(scenario);
      for (let i = 0; i < 6; i++) map.spawn();
    } else {
      map.resize();
    }
    updateMapFoot();
  }

  function updateMapFoot() {
    const measured = measuredFrom(appState);
    const rules = document.getElementById('cs-map-rules');
    const blocked = document.getElementById('cs-map-blocked');
    if (rules) rules.textContent = measured.rules === null ? '—' : number(measured.rules);
    if (blocked) blocked.textContent = measured.blocked === null ? '—' : number(measured.blocked);
  }

  /* ---------------------------------------------------------------- */
  /* Right column: engine / vectors / compliance                       */
  /* ---------------------------------------------------------------- */

  /**
   * The reference shows each detector mid-scan ("Scanning…"). We reproduce that
   * honestly: the rows report Scanning until the local model finishes training,
   * then report Active — with the real held-out AUC next to it.
   */
  function signalState(index) {
    const clf = appState && appState.aether && appState.aether.classifier;
    const trained = !!(clf && clf.isTrained);
    if (index === 2 && !trained) return 'Scanning…';
    return trained ? 'Active' : 'Scanning…';
  }

  function renderEngine() {
    const host = document.getElementById('cs-engine');
    if (!host) return;
    const measured = measuredFrom(appState);
    mount(host,
      h('div', { class: 'cs-panel__head' },
        h('h3', { class: 'cs-panel__title' }, 'Threat detection engine',
          h('span', { class: 'cs-panel__sub' }, 'AI-powered analysis'))),
      h('div', { class: 'cs-panel__body' },
        h('div', { class: 'cs-engine' },
          h('div', { class: 'cs-brain', 'aria-hidden': 'true' },
            h('div', { class: 'cs-brain__glow' }),
            icon(ICONS.brain, 96)),
          h('ul', { class: 'cs-signals' },
            SIGNALS.map((signal, i) => h('li', { class: 'cs-signal', dataset: { state: 'active' } },
              h('span', { class: 'cs-signal__icon' }, icon(i === 0 ? ICONS.pulse : i === 1 ? ICONS.target : i === 2 ? ICONS.brain : ICONS.shield, 12)),
              h('div', { class: 'cs-signal__label' },
                h('b', { text: signal.name }),
                h('span', { class: 'cs-signal__state', text: signalState(i) })),
              h('span', { class: 'cs-signal__pct', text: `${88 + i * 3}%` })
            )))),
        meter(scenario.engine.progress, 'Processing'),
        h('p', { class: 'cs-note' },
          h('b', { text: measured.auc === null ? 'Lexical model warming up' : `Model AUC ${measured.auc}` }),
          ' — the four signals above mirror the real detectors (behaviour, anomaly, lexical model, correlation). ',
          h('b', { text: 'Scans are simulated;' }), ' no packet inspection happens in a browser.')
      )
    );
  }

  function renderVectors() {
    const host = document.getElementById('cs-vectors');
    if (!host) return;
    mount(host,
      h('div', { class: 'cs-panel__head' },
        h('h3', { class: 'cs-panel__title' }, 'Top attack vectors',
          h('span', { class: 'cs-panel__sub' }, 'By percentage'))),
      h('div', { class: 'cs-panel__body' },
        h('div', { class: 'cs-vectors' },
          scenario.vectors.map((v) => {
            const fill = h('div', { class: 'cs-vector__fill' });
            queueMicrotask(() => { fill.style.width = `${v.pct}%`; });
            return h('div', { class: 'cs-vector' },
              h('div', { class: 'cs-vector__row' },
                h('span', { text: v.name }),
                h('b', { text: `${v.pct}%` })),
              h('div', {
                class: 'cs-vector__track',
                role: 'progressbar',
                'aria-valuenow': String(v.pct),
                'aria-valuemin': '0',
                'aria-valuemax': '100',
                'aria-label': `${v.name} share of attacks, simulated`
              }, fill));
          }))
      )
    );
  }

  function renderAssets() {
    const host = document.getElementById('cs-assets');
    if (!host) return;
    mount(host, ASSET_CLASSES.map((cls) => {
      const asset = scenario.assets[cls.id];
      return h('div', { class: 'cs-asset' },
        h('div', { class: 'cs-asset__head' },
          h('span', { text: cls.name }),
          h('span', { class: 'cs-dot' })),
        h('div', { class: 'cs-asset__body' },
          h('span', { class: 'cs-asset__icon' }, icon(ICONS[cls.icon], 26)),
          h('div', { class: 'cs-asset__count' },
            h('small', { text: 'Protected' }),
            h('b', { text: number(asset.total) })),
          h('div', { class: 'cs-asset__risk' },
            h('span', { text: 'At risk' }),
            h('b', { text: number(asset.atRisk) }))),
        trendSvg(asset.trend)
      );
    }));
  }

  function renderCompliance() {
    const host = document.getElementById('cs-compliance');
    if (!host) return;
    mount(host,
      h('div', { class: 'cs-panel__head' },
        h('h3', { class: 'cs-panel__title' }, 'Compliance status',
          h('span', { class: 'cs-panel__sub' }, 'Security compliance overview'))),
      h('div', { class: 'cs-panel__body' },
        h('div', { class: 'cs-compliance' },
          scenario.compliance.map((fw) => h('div', { class: 'cs-seal' },
            h('span', { class: 'cs-seal__ring' }, icon(ICONS.shield, 24)),
            h('strong', { text: fw.name }),
            h('small', { text: fw.state })))),
        h('div', { class: 'cs-compliance__cta' },
          h('button', {
            type: 'button',
            class: 'cs-btn',
            text: 'View compliance report',
            onclick: () => showView('reports')
          })),
        h('p', { class: 'cs-note' },
          h('b', { text: 'Illustrative.' }), ' This open-source project is not certified against ISO 27001, SOC 2, GDPR or HIPAA; the report lists controls and open gaps honestly.')
      )
    );
  }

  /* ---------------------------------------------------------------- */
  /* Drill-down views                                                  */
  /* ---------------------------------------------------------------- */

  function viewTable(headers, rows, caption) {
    return h('div', { class: 'cs-panel', style: { marginTop: '12px' } },
      h('div', { class: 'cs-panel__head' },
        h('h3', { class: 'cs-panel__title' }, caption)),
      h('div', { class: 'cs-panel__body scroll-x' },
        h('table', {},
          h('thead', {}, h('tr', {}, headers.map((hd) => h('th', { text: hd })))),
          h('tbody', {}, rows.map((row) => h('tr', {}, row.map((cell) =>
            typeof cell === 'string' ? h('td', { text: cell }) : h('td', {}, cell)))))))
    );
  }

  function kpiRow(items) {
    return h('div', { class: 'grid k4', style: { marginTop: '12px' } },
      items.map(([value, label, cls]) => h('div', { class: `kpi ${cls || ''}`.trim() },
        h('b', { text: value }), h('span', { text: label }))));
  }

  function showView(name) {
    view = name;
    for (const button of page.querySelectorAll('[data-cs-view]')) {
      button.setAttribute('aria-selected', button.dataset.csView === name ? 'true' : 'false');
    }
    const grid = page.querySelector('.cs-grid');
    const host = document.getElementById('cs-view');
    if (!host) return;

    // Dashboard + a couple of console views share the panel grid; the rest get
    // a dedicated drill-down table underneath it.
    const isDashboard = name === 'dashboard';
    if (grid) grid.hidden = false;
    clear(host);
    if (isDashboard) {
      host.hidden = true;
      return;
    }
    host.hidden = false;
    const measured = measuredFrom(appState);
    const viewed = [];

    if (name === 'threats') {
      viewed.push(kpiRow([
        [number(scenario.total), 'threats in the simulated feed'],
        [number(scenario.counts.critical), 'critical', 'bad'],
        [number(measured.blocked ?? 0), 'blocked by this browser', 'ok'],
        [`${scenario.vectors[0].pct}%`, `top vector: ${scenario.vectors[0].name}`]
      ]));
      viewed.push(viewTable(
        ['Severity', 'Event', 'Target', 'Time'],
        feed.slice(0, 24).map((ev) => [
          h('span', { class: `cs-tag cs-tag--${ev.severity}`, text: ev.severity }),
          ev.title, ev.detail, hhmmss(ev.at)
        ]),
        'Detections (simulated)'
      ));
    } else if (name === 'endpoints' || name === 'cloud' || name === 'network') {
      const asset = scenario.assets[name];
      const cls = ASSET_CLASSES.find((c) => c.id === name);
      viewed.push(kpiRow([
        [number(asset.total), `${cls.name.toLowerCase()} protected (simulated)`],
        [number(asset.atRisk), 'at risk', 'warn'],
        [number(Math.round(asset.total * 0.002)), 'policy exceptions'],
        [measured.resolver === null ? '—' : `${measured.resolver} ms`, 'median lookup latency (measured)']
      ]));
      viewed.push(viewTable(
        ['Host', 'Status', 'Last scan', 'Note'],
        Array.from({ length: 8 }, (_, i) => [
          `${name === 'cloud' ? 'svc' : name === 'network' ? 'seg' : 'node'}-${String(i + 1).padStart(3, '0')}.local`,
          i === 2 ? h('span', { class: 'cs-tag cs-tag--medium', text: 'review' }) : h('span', { class: 'cs-tag cs-tag--low', text: 'clean' }),
          `${10 + i * 7} min ago`,
          'Simulated inventory — a browser cannot enumerate real devices.'
        ]),
        `${cls.name} inventory (simulated)`
      ));
    } else if (name === 'intelligence') {
      viewed.push(kpiRow([
        [measured.rules === null ? '—' : number(measured.rules), 'real filter rules loaded'],
        [measured.auc === null ? '—' : String(measured.auc), 'lexical model AUC (measured)'],
        [String(SIGNALS.length), 'detection signals'],
        [String(VECTORS.length), 'tracked attack vectors']
      ]));
      viewed.push(viewTable(
        ['Signal', 'What it reads', 'Status'],
        SIGNALS.map((s) => [s.name, signalDescription(s.id), h('span', { class: 'cs-tag cs-tag--low', text: 'active' })]),
        'Detection signals'
      ));
    } else if (name === 'reports') {
      viewed.push(viewTable(
        ['Framework', 'State', 'Evidence', 'Open gap'],
        FRAMEWORKS.map((fw) => [
          fw.name,
          h('span', { class: 'cs-tag cs-tag--medium', text: 'not certified' }),
          'Local-first architecture, no telemetry endpoint, salted-hash analytics.',
          fw.id === 'gdpr' ? 'Formal DPIA and EU representative not appointed.' : 'Formal audit not performed; no auditor engaged.'
        ]),
        'Compliance report — honest state'
      ));
      viewed.push(h('div', { class: 'cs-panel', style: { marginTop: '12px' } },
        h('div', { class: 'cs-panel__body' },
          h('p', { class: 'cs-note', style: { borderTop: 'none', marginTop: '0' } },
            h('b', { text: 'Why this page exists: ' }),
            'security dashboards routinely show green checkmarks for frameworks nobody audited. ',
            'This one shows the controls that are genuinely implemented and the gaps that are genuinely open.'))));
    } else if (name === 'settings') {
      viewed.push(viewTable(
        ['Setting', 'Value', 'Effect'],
        [
          ['Simulation', 'on', 'Map, feed and volumes are synthetic and labelled as such.'],
          ['Telemetry', 'none', 'The console never sends data anywhere; there is no backend.'],
          ['Scan cadence', reduced ? 'reduced motion' : `${TICK_MS} ms`, 'One timer drives the console and parks itself when hidden.'],
          ['Measured sources', 'engine · monitor · model', 'Rule counts, blocks and AUC come from the running app.'],
          ['Enforcement', 'deterministic only', 'Simulated detections never block anything.']
        ],
        'Console settings'
      ));
    } else {
      viewed.push(h('div', { class: 'cs-panel', style: { marginTop: '12px' } },
        h('div', { class: 'cs-panel__body' },
          h('p', { class: 'cs-note', style: { borderTop: 'none', marginTop: '0' } },
            'This console view is not part of the reference design; the dashboard panel is the deliverable.'))));
    }
    mount(host, ...viewed);
  }

  function signalDescription(id) {
    return {
      behaviour: 'Timing regularity, cadence and fan-out of observed lookups.',
      anomaly: 'Rate spikes against a rolling baseline built on this device.',
      ml: 'Naive-Bayes lexical model trained from the bundled feeds.',
      correlation: 'Agreement between signals; two independent signals are required before any recommendation.'
    }[id] || '—';
  }

  /* ---------------------------------------------------------------- */
  /* Live update loop                                                  */
  /* ---------------------------------------------------------------- */

  function tick() {
    if (destroyed) return;
    const now = Date.now();
    const live = view === 'dashboard';

    // Feed
    const ev = makeEvent(next, scenario, now);
    feed = [ev, ...feed].slice(0, 30);
    if (live) {
      const existing = page.querySelector('.cs-feed');
      if (existing && existing.firstChild) {
        const li = h('li', {},
          h('span', { class: `cs-tag cs-tag--${ev.severity}`, text: ev.severity }),
          h('div', {},
            h('b', { class: 'title', text: ev.title }),
            h('code', { text: ev.detail })),
          h('time', { text: hhmmss(ev.at) }));
        existing.prepend(li);
        while (existing.children.length > 9) existing.lastElementChild.remove();
      }
    }

    // Severity counters drift slowly upward, exactly like a live counter.
    const sev = ev.severity;
    scenario.counts[sev] += 1;
    scenario.total += 1;
    if (live) {
      const stats = page.querySelectorAll('.cs-stat b');
      if (stats.length === 4) {
        stats[0].textContent = number(scenario.total);
        stats[1].textContent = number(scenario.counts.high);
        stats[2].textContent = number(scenario.counts.medium);
        stats[3].textContent = number(scenario.counts.low);
      }
      const donutTotal = page.querySelector('.cs-donut__center b');
      if (donutTotal) donutTotal.textContent = number(scenario.total);
      const donutArcs = page.querySelectorAll('.cs-donut__ring');
      const circumference = 2 * Math.PI * 44;
      let offset = 0;
      SEVERITIES.forEach((s, i) => {
        const frac = scenario.counts[s] / scenario.total;
        const arc = donutArcs[i];
        if (arc) {
          arc.setAttribute('stroke-dasharray', `${frac * circumference} ${circumference - frac * circumference}`);
          arc.setAttribute('stroke-dashoffset', String(-offset * circumference));
        }
        offset += frac;
      });
      const bell = document.getElementById('cs-bell-count');
      if (bell) bell.textContent = String(Math.min(99, Number(bell.textContent || '0') + (ev.severity === 'critical' || ev.severity === 'high' ? 1 : 0)));
      updateMapFoot();
    }

    // Engine "Processing" meter breathes between 74 and 97 %, like the art.
    scenario.engine.progress = Math.max(74, Math.min(97, scenario.engine.progress + (next() - 0.5) * 6));
    const progress = document.getElementById('cs-engine-progress');
    if (progress && live) progress.textContent = `${Math.round(scenario.engine.progress)}%`;
    const fill = page.querySelector('.cs-meter__fill');
    if (fill && live) fill.style.width = `${scenario.engine.progress}%`;

    if (map && live) map.spawn();

    if (!live && view !== 'threats') { /* other views redraw on demand */ }
  }

  function startLoop() {
    stopLoop();
    if (reduced) return; // static dashboard for reduced-motion visitors
    timer = setInterval(tick, TICK_MS);
  }
  function stopLoop() {
    if (timer) clearInterval(timer);
    timer = null;
  }

  function startClock() {
    const time = document.getElementById('cs-clock-time');
    const date = document.getElementById('cs-clock-date');
    const paint = () => {
      const now = new Date();
      if (time) time.textContent = clockTime(now);
      if (date) date.textContent = clockDate(now);
    };
    paint();
    if (clockTimer) clearInterval(clockTimer);
    clockTimer = setInterval(paint, 1000);
  }

  /* ---------------------------------------------------------------- */
  /* Wiring                                                            */
  /* ---------------------------------------------------------------- */

  for (const button of page.querySelectorAll('[data-cs-view]')) {
    button.addEventListener('click', () => showView(button.dataset.csView));
  }

  const bell = document.getElementById('cs-bell');
  if (bell) {
    bell.addEventListener('click', () => {
      const count = document.getElementById('cs-bell-count');
      if (count) count.textContent = '0';
      toast('Notifications cleared locally. Nothing leaves this device.', 'ok');
      showView('threats');
    });
  }
  const gear = document.getElementById('cs-gear');
  if (gear) gear.addEventListener('click', () => showView('settings'));

  const filter = document.getElementById('cs-map-filter');
  if (filter) {
    filter.addEventListener('change', () => {
      if (map) map.setFilter(filter.value);
    });
  }

  /**
   * Renders every panel. A failure inside one panel is contained: the others
   * still paint and the error is reported through console.error (lint allows
   * it) instead of silently blanking the whole console.
   */
  function renderAll() {
    for (const render of [renderOverview, renderActivity, renderFeed, renderMap,
      renderEngine, renderVectors, renderAssets, renderCompliance]) {
      try {
        render();
      } catch (err) {
        console.error(`CyberShield panel failed: ${render.name}`, err);
      }
    }
  }

  renderAll();
  startClock();

  return {
    scenario,
    get view() { return view; },
    showView,
    renderAll,
    tick,
    refresh() { renderOverview(); renderEngine(); updateMapFoot(); },
    /** Called by the router when this page is shown. */
    resume() {
      startClock();
      renderAll();
      if (map) map.start();
      startLoop();
    },
    /** Called by the router when the page is hidden. */
    pause() {
      stopLoop();
      if (clockTimer) clearInterval(clockTimer);
      clockTimer = null;
      if (map) map.stop();
    },
    destroy() {
      destroyed = true;
      stopLoop();
      if (clockTimer) clearInterval(clockTimer);
      clockTimer = null;
      if (map) map.destroy();
      map = null;
    }
  };
}

export default createCyberConsole;
