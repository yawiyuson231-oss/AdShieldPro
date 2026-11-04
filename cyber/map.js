/**
 * CyberShield AI — global threat map renderer.
 *
 * A dot-matrix world map on canvas: continents are rasterised into a dot grid
 * once per resize, then attack arcs animate between region anchors with
 * travelling pulses and expanding rings on impact.
 *
 * Design notes
 *  - Land is described as a set of simple polygons (union of masks). Several
 *    small convex polygons per continent keep the outline organic without
 *    needing a multi-megabyte GeoJSON wired through the network.
 *  - Everything is derived from injectable state; no globals, no timers that
 *    survive destroy(). The loop parks itself when the page is hidden, when
 *    the console is not the active tab, or when the visitor prefers reduced
 *    motion (in which case a single static frame is drawn).
 */

import { REGIONS, makeArc, rng } from './telemetry.js';

const LAND = [
  // North America
  [[-168, 68], [-150, 70], [-140, 60], [-155, 55], [-168, 60]],
  [[-140, 70], [-100, 73], [-80, 73], [-62, 62], [-70, 50], [-95, 48], [-125, 49], [-135, 58]],
  [[-125, 49], [-95, 49], [-82, 45], [-75, 40], [-80, 32], [-95, 29], [-105, 31], [-117, 32], [-124, 40]],
  [[-105, 31], [-95, 29], [-88, 21], [-83, 10], [-78, 8], [-92, 16], [-105, 20]],
  [[-45, 82], [-22, 80], [-20, 70], [-42, 60], [-56, 68]], // Greenland
  // South America
  [[-79, 9], [-70, 11], [-60, 8], [-50, 2], [-36, -6], [-38, -16], [-48, -25], [-58, -34], [-64, -42], [-68, -52], [-74, -52], [-72, -40], [-70, -28], [-71, -18], [-78, -6], [-80, 0]],
  // Europe
  [[-10, 44], [-2, 43], [2, 42], [-2, 37], [-9, 37]],
  [[-2, 43], [8, 44], [12, 55], [8, 58], [0, 51], [-5, 48]],
  [[8, 45], [16, 44], [24, 41], [28, 41], [26, 36], [18, 39], [12, 38]],
  [[5, 58], [10, 64], [22, 70], [30, 70], [32, 60], [22, 56], [12, 56]],
  [[-6, 58], [1, 53], [-2, 50], [-6, 52]],
  [[-24, 66], [-14, 66], [-15, 63], [-23, 63]],
  // Africa
  [[-17, 21], [0, 26], [12, 32], [25, 32], [34, 31], [43, 12], [51, 12], [42, -2], [40, -15], [35, -24], [27, -34], [18, -34], [12, -18], [9, -2], [3, 6], [-8, 5], [-16, 12]],
  [[47, -13], [50, -15], [48, -25], [43, -25], [45, -16]], // Madagascar
  // Asia
  [[34, 31], [43, 12], [52, 17], [57, 25], [48, 30], [43, 38], [36, 37], [30, 31]],
  [[30, 70], [90, 75], [140, 72], [178, 68], [170, 60], [140, 52], [130, 44], [110, 50], [80, 50], [60, 52], [40, 60], [32, 60]],
  [[48, 30], [57, 25], [70, 30], [90, 45], [80, 50], [60, 52], [43, 38]],
  [[90, 45], [110, 50], [130, 44], [122, 33], [110, 22], [98, 22], [88, 28], [78, 32]],
  [[68, 24], [78, 32], [88, 22], [92, 22], [88, 8], [77, 8], [72, 20]],
  [[95, 20], [105, 10], [110, 2], [104, -2], [98, 8], [94, 16]],
  [[130, 34], [141, 41], [145, 44], [142, 36], [134, 32]],
  [[95, 5], [120, 2], [140, -3], [130, -8], [110, -8], [100, -4]],
  [[120, 18], [126, 10], [122, 6], [118, 12]],
  // Oceania
  [[114, -22], [122, -18], [130, -12], [142, -11], [146, -19], [152, -25], [150, -37], [140, -38], [129, -32], [115, -34]],
  [[173, -35], [178, -38], [174, -46], [168, -44]]
];

const LAT_TOP = 84;
const LAT_BOTTOM = -58;
const LON_LEFT = -180;
const LON_RIGHT = 180;

const SEVERITY_RGB = {
  critical: '255,59,92',
  high: '255,122,69',
  medium: '255,191,71',
  low: '125,160,190'
};

const DOT_STEP = 7;
const DOT_RADIUS = 1.45;

/**
 * Animation-frame accessors that work in every environment this module runs in
 * (browser, an embedded webview, and the jsdom test harness where the callback
 * lives on `window` but not on the global object).
 */
const raf = (fn) => (typeof globalThis.requestAnimationFrame === 'function'
  ? globalThis.requestAnimationFrame(fn)
  : setTimeout(() => fn(Date.now()), 16));
const caf = (id) => (typeof globalThis.cancelAnimationFrame === 'function'
  ? globalThis.cancelAnimationFrame(id)
  : clearTimeout(id));

function inside(poly, lon, lat) {
  let hit = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const [xi, yi] = poly[i];
    const [xj, yj] = poly[j];
    if ((yi > lat) !== (yj > lat) && lon < ((xj - xi) * (lat - yi)) / (yj - yi) + xi) hit = !hit;
  }
  return hit;
}

function isLand(lon, lat) {
  for (const poly of LAND) if (inside(poly, lon, lat)) return true;
  return false;
}

/**
 * Mounts the map on a canvas.
 * @param {HTMLCanvasElement} canvas
 * @param {{onStats?: (s: {arcs: number, sources: number}) => void, reduced?: boolean}} [options]
 */
export function createThreatMap(canvas, options = {}) {
  const next = rng(0xc0ffee);
  let ctx = null;
  try { ctx = canvas.getContext('2d'); } catch { ctx = null; }

  const shell = canvas.parentElement || canvas;
  const state = {
    w: 0, h: 0, dpr: 1,
    dots: [],
    nodes: [],
    arcs: [],
    rings: [],
    frame: 0,
    raf: 0,
    running: false,
    visible: true,
    filter: 'all',
    stats: { arcs: 0, sources: 0 }
  };

  const project = (lon, lat) => ({
    x: ((lon - LON_LEFT) / (LON_RIGHT - LON_LEFT)) * state.w,
    y: ((LAT_TOP - lat) / (LAT_TOP - LAT_BOTTOM)) * state.h
  });

  /** Rasterises the land polygons into a dot grid for the current size. */
  function buildDots() {
    const dots = [];
    if (!state.w || !state.h) return dots;
    // Keep the map readable on narrow screens: fewer, slightly larger dots.
    const step = state.w < 420 ? 9 : DOT_STEP;
    const lonPerPx = (LON_RIGHT - LON_LEFT) / state.w;
    const latPerPx = (LAT_TOP - LAT_BOTTOM) / state.h;
    for (let py = step / 2; py < state.h; py += step) {
      const lat = LAT_TOP - py * latPerPx;
      for (let px = step / 2; px < state.w; px += step) {
        const lon = LON_LEFT + px * lonPerPx;
        if (isLand(lon, lat)) dots.push({ x: px, y: py, phase: next() * Math.PI * 2 });
      }
    }
    return dots;
  }

  function buildNodes() {
    return REGIONS.map((region) => {
      const p = project(region.lon, region.lat);
      return { ...region, x: p.x, y: p.y };
    });
  }

  function resize() {
    const rect = shell.getBoundingClientRect();
    const w = Math.max(1, Math.round(shell.clientWidth || rect.width));
    const h = Math.max(220, Math.round(shell.clientHeight || rect.height || 300));
    state.dpr = Math.min(globalThis.devicePixelRatio || 1, 2);
    state.w = w;
    state.h = h;
    if (ctx) {
      canvas.width = Math.round(w * state.dpr);
      canvas.height = Math.round(h * state.dpr);
      ctx.setTransform(state.dpr, 0, 0, state.dpr, 0, 0);
    }
    state.dots = buildDots();
    state.nodes = buildNodes();
    draw(0);
  }

  function severityVisible(arc) {
    if (state.filter === 'all') return true;
    // The filter list maps to vectors; everything else is dimmed out.
    return arc.vector === state.filter;
  }

  function publishStats() {
    const now = performance.now();
    const live = state.arcs.filter((a) => a.t < 1);
    state.stats = {
      arcs: live.length,
      sources: new Set(live.map((a) => a.from)).size,
      blocked: state.stats.blocked
    };
    if (options.onStats && now - (state.lastPublish || 0) > 120) {
      state.lastPublish = now;
      options.onStats(state.stats);
    }
  }

  function drawGrid() {
    const { w, h } = state;
    ctx.save();
    ctx.strokeStyle = 'rgba(46,197,255,0.055)';
    ctx.lineWidth = 1;
    const step = 46;
    for (let x = 0; x <= w; x += step) {
      ctx.beginPath(); ctx.moveTo(x + 0.5, 0); ctx.lineTo(x + 0.5, h); ctx.stroke();
    }
    for (let y = 0; y <= h; y += step) {
      ctx.beginPath(); ctx.moveTo(0, y + 0.5); ctx.lineTo(w, y + 0.5); ctx.stroke();
    }
    ctx.restore();
  }

  function drawDots(time) {
    const pulse = 0.5 + 0.5 * Math.sin(time / 900);
    ctx.save();
    for (const dot of state.dots) {
      const twinkle = 0.55 + 0.35 * Math.sin(time / 1600 + dot.phase);
      ctx.fillStyle = `rgba(84,186,240,${(0.30 + twinkle * 0.30).toFixed(3)})`;
      ctx.beginPath();
      ctx.arc(dot.x, dot.y, DOT_RADIUS, 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.restore();
    return pulse;
  }

  function drawNodeGlow(time) {
    ctx.save();
    for (const node of state.nodes) {
      const intensity = 0.4 + 0.6 * (0.5 + 0.5 * Math.sin(time / 700 + node.lon));
      const radius = 18 + intensity * 12;
      const gradient = ctx.createRadialGradient(node.x, node.y, 0, node.x, node.y, radius);
      gradient.addColorStop(0, `rgba(255,59,92,${(0.30 * intensity).toFixed(3)})`);
      gradient.addColorStop(0.55, `rgba(255,59,92,${(0.09 * intensity).toFixed(3)})`);
      gradient.addColorStop(1, 'rgba(255,59,92,0)');
      ctx.fillStyle = gradient;
      ctx.beginPath();
      ctx.arc(node.x, node.y, radius, 0, Math.PI * 2);
      ctx.fill();
      ctx.fillStyle = `rgba(255,110,135,${(0.75 * intensity).toFixed(3)})`;
      ctx.beginPath();
      ctx.arc(node.x, node.y, 1.9, 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.restore();
  }

  function drawShield(time) {
    const cx = state.w / 2;
    const cy = state.h * 0.56;
    const scale = Math.min(state.w, state.h) / 265;
    const ringPulse = 1 + 0.03 * Math.sin(time / 700);

    ctx.save();
    // Circuit traces radiating from the core, the reference's signature motif.
    ctx.strokeStyle = 'rgba(46,197,255,0.16)';
    ctx.lineWidth = 1;
    for (const angle of [-2.75, -2.05, -1.15, -0.35, 0.45, 1.25, 2.15, 2.9]) {
      const len = 96 * scale;
      const x0 = cx + Math.cos(angle) * 44 * scale;
      const y0 = cy + Math.sin(angle) * 44 * scale;
      ctx.beginPath();
      ctx.moveTo(x0, y0);
      ctx.lineTo(x0 + Math.cos(angle) * len, y0 + Math.sin(angle) * len);
      const bx = x0 + Math.cos(angle) * len;
      const by = y0 + Math.sin(angle) * len;
      ctx.lineTo(bx + (Math.cos(angle) > 0 ? 12 : -12) * scale, by);
      ctx.stroke();
    }

    // Outer halo
    const halo = ctx.createRadialGradient(cx, cy, 6, cx, cy, 74 * scale * ringPulse);
    halo.addColorStop(0, 'rgba(46,197,255,0.30)');
    halo.addColorStop(0.5, 'rgba(46,125,255,0.13)');
    halo.addColorStop(1, 'rgba(46,125,255,0)');
    ctx.fillStyle = halo;
    ctx.beginPath();
    ctx.arc(cx, cy, 74 * scale, 0, Math.PI * 2);
    ctx.fill();

    // Orbital rings
    for (const [r, alpha, width] of [[52, 0.55, 1.4], [44, 0.35, 1], [64, 0.18, 1]]) {
      ctx.strokeStyle = `rgba(46,197,255,${alpha})`;
      ctx.lineWidth = width;
      ctx.beginPath();
      ctx.arc(cx, cy, r * scale * (r === 52 ? ringPulse : 1), 0, Math.PI * 2);
      ctx.stroke();
    }
    // Dashed rotating outer orbit
    ctx.save();
    ctx.translate(cx, cy);
    ctx.rotate((time / 9000) % (Math.PI * 2));
    ctx.strokeStyle = 'rgba(127,224,255,0.34)';
    ctx.lineWidth = 1.2;
    ctx.setLineDash([8, 12]);
    ctx.beginPath();
    ctx.arc(0, 0, 66 * scale, 0, Math.PI * 2);
    ctx.stroke();
    ctx.restore();

    // Shield body
    const sw = 30 * scale;
    const sh = 36 * scale;
    const grad = ctx.createLinearGradient(cx - sw, cy - sh, cx + sw, cy + sh);
    grad.addColorStop(0, 'rgba(127,224,255,0.92)');
    grad.addColorStop(1, 'rgba(47,125,255,0.85)');
    ctx.beginPath();
    ctx.moveTo(cx, cy - sh);
    ctx.lineTo(cx + sw, cy - sh * 0.62);
    ctx.lineTo(cx + sw, cy + sh * 0.05);
    ctx.quadraticCurveTo(cx + sw, cy + sh * 0.68, cx, cy + sh);
    ctx.quadraticCurveTo(cx - sw, cy + sh * 0.68, cx - sw, cy + sh * 0.05);
    ctx.lineTo(cx - sw, cy - sh * 0.62);
    ctx.closePath();
    ctx.fillStyle = 'rgba(6,20,36,0.9)';
    ctx.fill();
    ctx.strokeStyle = grad;
    ctx.lineWidth = 3;
    ctx.shadowColor = 'rgba(46,197,255,0.95)';
    ctx.shadowBlur = 26;
    ctx.stroke();
    ctx.shadowBlur = 0;

    // Padlock
    ctx.strokeStyle = 'rgba(200,240,255,0.95)';
    ctx.lineWidth = 2.2 * scale;
    const lockW = 13 * scale;
    const lockH = 10 * scale;
    ctx.strokeRect(cx - lockW / 2, cy - lockH / 5, lockW, lockH);
    ctx.beginPath();
    ctx.arc(cx, cy - lockH / 5, lockW * 0.34, Math.PI, 0);
    ctx.stroke();
    ctx.fillStyle = 'rgba(200,240,255,0.95)';
    ctx.beginPath();
    ctx.arc(cx, cy + lockH * 0.32, 1.7 * scale, 0, Math.PI * 2);
    ctx.fill();

    ctx.restore();
  }

  function drawArcs(dt) {
    const nodeById = new Map(state.nodes.map((n) => [n.id, n]));
    ctx.save();
    ctx.globalCompositeOperation = 'lighter';
    for (const arc of state.arcs) {
      const from = nodeById.get(arc.from);
      const to = nodeById.get(arc.to);
      if (!from || !to) continue;
      const visible = severityVisible(arc);
      const rgb = SEVERITY_RGB[arc.severity] || SEVERITY_RGB.low;
      const alpha = (visible ? 0.75 : 0.12) * arc.weight;

      const mx = (from.x + to.x) / 2;
      const my = (from.y + to.y) / 2;
      const dx = to.x - from.x;
      const dy = to.y - from.y;
      const dist = Math.hypot(dx, dy) || 1;
      const lift = Math.min(110, dist * 0.24);
      const cx = mx - (dy / dist) * lift;
      const cy = my + (dx / dist) * lift;

      // Full arc, dim
      ctx.strokeStyle = `rgba(${rgb},${(alpha * 0.32).toFixed(3)})`;
      ctx.lineWidth = 0.9;
      ctx.beginPath();
      ctx.moveTo(from.x, from.y);
      ctx.quadraticCurveTo(cx, cy, to.x, to.y);
      ctx.stroke();

      // Progress: a bright head travelling along the same curve.
      const t = Math.min(1, arc.t);
      const steps = 22;
      const tail = Math.max(0, t - 0.34);
      ctx.strokeStyle = `rgba(${rgb},${alpha.toFixed(3)})`;
      ctx.lineWidth = 1.9;
      ctx.shadowColor = `rgba(${rgb},0.9)`;
      ctx.shadowBlur = 9;
      ctx.beginPath();
      for (let i = 0; i <= steps; i++) {
        const u = tail + ((t - tail) * i) / steps;
        const x = (1 - u) * (1 - u) * from.x + 2 * (1 - u) * u * cx + u * u * to.x;
        const y = (1 - u) * (1 - u) * from.y + 2 * (1 - u) * u * cy + u * u * to.y;
        if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      }
      ctx.stroke();
      ctx.shadowBlur = 0;

      // Head glow
      if (t < 1 && visible) {
        const u = t;
        const hx = (1 - u) * (1 - u) * from.x + 2 * (1 - u) * u * cx + u * u * to.x;
        const hy = (1 - u) * (1 - u) * from.y + 2 * (1 - u) * u * cy + u * u * to.y;
        const g = ctx.createRadialGradient(hx, hy, 0, hx, hy, 7);
        g.addColorStop(0, `rgba(255,255,255,${(alpha * 0.9).toFixed(3)})`);
        g.addColorStop(0.4, `rgba(${rgb},${alpha.toFixed(3)})`);
        g.addColorStop(1, `rgba(${rgb},0)`);
        ctx.fillStyle = g;
        ctx.beginPath();
        ctx.arc(hx, hy, 7, 0, Math.PI * 2);
        ctx.fill();
      }

      if (dt) arc.t = Math.min(1, arc.t + dt / arc.duration);
    }
    ctx.restore();
  }

  function drawRings(dt) {
    ctx.save();
    ctx.globalCompositeOperation = 'lighter';
    for (const ring of state.rings) {
      ring.life += dt / ring.duration;
      if (ring.life >= 1) continue;
      const rgb = SEVERITY_RGB[ring.severity] || SEVERITY_RGB.high;
      const r = 4 + ring.life * 30;
      ctx.strokeStyle = `rgba(${rgb},${((1 - ring.life) * 0.7).toFixed(3)})`;
      ctx.lineWidth = 1.4;
      ctx.beginPath();
      ctx.arc(ring.x, ring.y, r, 0, Math.PI * 2);
      ctx.stroke();
    }
    state.rings = state.rings.filter((r) => r.life < 1);
    ctx.restore();
  }

  function draw(dt) {
    if (!ctx) return;
    const time = state.frame;
    ctx.clearRect(0, 0, state.w, state.h);
    // Opaque base: the map must look identical on any panel background.
    ctx.fillStyle = '#040a14';
    ctx.fillRect(0, 0, state.w, state.h);

    // Vignette so the map melts into the panel edges.
    const vignette = ctx.createRadialGradient(
      state.w / 2, state.h / 2, Math.min(state.w, state.h) * 0.18,
      state.w / 2, state.h / 2, Math.max(state.w, state.h) * 0.72
    );
    vignette.addColorStop(0, 'rgba(10,26,44,0.55)');
    vignette.addColorStop(1, 'rgba(3,8,15,0.96)');
    ctx.fillStyle = vignette;
    ctx.fillRect(0, 0, state.w, state.h);

    drawGrid();
    drawDots(time);
    drawNodeGlow(time);
    drawShield(time);
    drawArcs(dt);
    drawRings(dt);
    publishStats();
  }

  /** Spawns a new arc and its impact ring. Called from the controller timer. */
  function spawn() {
    if (state.arcs.length > 40) return;
    const arc = makeArc(next, state.scenario || { counts: { critical: 1, high: 2, medium: 3, low: 6 }, total: 12, vectors: [] });
    arc.t = 0;
    arc.duration = 1500 + next() * 1700;
    state.arcs.push(arc);
    const to = state.nodes.find((n) => n.id === arc.to);
    if (to) state.rings.push({ x: to.x, y: to.y, life: 0, duration: 1100, severity: arc.severity });
    state.arcs = state.arcs.filter((a) => a.t < 1.02);
  }

  function loop(now) {
    if (!state.running) return;
    const dt = state.last ? Math.min(now - state.last, 60) : 16;
    state.last = now;
    state.frame += dt;
    draw(dt);
    state.raf = raf(loop);
  }

  function start() {
    if (state.running || options.reduced) { draw(0); return; }
    state.running = true;
    state.last = 0;
    state.raf = raf(loop);
  }

  function stop() {
    state.running = false;
    if (state.raf) caf(state.raf);
    state.raf = 0;
  }

  /** Attaches the scenario so spawned arcs follow its severity mix. */
  function setScenario(scenario) { state.scenario = scenario; }

  function setFilter(value) {
    state.filter = value;
    draw(0);
  }

  let ro = null;
  if (typeof ResizeObserver !== 'undefined') {
    ro = new ResizeObserver(() => resize());
    ro.observe(shell);
  } else if (typeof window !== 'undefined') {
    window.addEventListener('resize', resize);
  }

  resize();

  return {
    start,
    stop,
    resize,
    spawn,
    setFilter,
    setScenario,
    draw,
    get state() { return state; },
    destroy() {
      stop();
      if (ro) ro.disconnect();
      else if (typeof window !== 'undefined') window.removeEventListener('resize', resize);
    }
  };
}
