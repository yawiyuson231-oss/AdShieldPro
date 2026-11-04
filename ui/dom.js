/**
 * OmniShield X — DOM helpers.
 *
 * SECURITY: every string is inserted with `textContent`, never `innerHTML`.
 * The previous version of this app built result rows with `innerHTML` and
 * interpolated imported JSON and user input directly, which is a stored-XSS
 * bug. Nothing in the UI layer may bypass these helpers.
 */

export function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === 'class' || key === 'className') el.className = value;
    else if (key === 'text') el.textContent = String(value);
    else if (key === 'dataset') Object.assign(el.dataset, value);
    else if (key === 'style' && typeof value === 'object') Object.assign(el.style, value);
    else if (key.startsWith('on') && typeof value === 'function') el.addEventListener(key.slice(2).toLowerCase(), value);
    else if (key === 'value') el.value = value;
    else if (key === 'checked' || key === 'disabled' || key === 'hidden' || key === 'selected') el[key] = !!value;
    else el.setAttribute(key, String(value));
  }
  append(el, children);
  return el;
}

function append(parent, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    parent.appendChild(child instanceof Node ? child : document.createTextNode(String(child)));
  }
}

export function clear(node) {
  if (!node) return node;
  while (node.firstChild) node.removeChild(node.firstChild);
  return node;
}

export function mount(selectorOrNode, ...children) {
  const node = typeof selectorOrNode === 'string' ? document.querySelector(selectorOrNode) : selectorOrNode;
  if (!node) return null;
  clear(node);
  append(node, children);
  return node;
}

export const pill = (text, cls = '') => h('span', { class: `pill ${cls}`.trim() }, text);
export const note = (text, cls = '') => h('div', { class: `note ${cls}`.trim() }, text);
export const empty = (text) => h('div', { class: 'empty' }, text);

export function kpi(value, label, cls = '') {
  return h('div', { class: `kpi ${cls}`.trim() },
    h('b', { text: value }),
    h('span', { text: label }));
}

export function table(headers, rows, options = {}) {
  const thead = h('thead', {}, h('tr', {}, headers.map((hd) => h('th', { text: typeof hd === 'string' ? hd : hd.label }))));
  const tbody = h('tbody', {});
  if (!rows.length) {
    tbody.appendChild(h('tr', {}, h('td', { colspan: headers.length, class: 'empty' }, options.emptyText || 'Nothing to show yet.')));
  }
  for (const row of rows) {
    const tr = h('tr', {});
    for (const cell of row) {
      const td = h('td', {});
      if (cell instanceof Node) td.appendChild(cell);
      else if (Array.isArray(cell)) append(td, cell);
      else td.textContent = cell === null || cell === undefined ? '—' : String(cell);
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
  return h('div', { class: 'scroll-x' }, h('table', {}, thead, tbody));
}

export function kv(pairs) {
  const dl = h('dl', { class: 'kv' });
  for (const [key, value] of pairs) {
    if (value === null || value === undefined) continue;
    dl.appendChild(h('dt', { text: key }));
    const dd = h('dd', {});
    if (value instanceof Node) dd.appendChild(value);
    else dd.textContent = String(value);
    dl.appendChild(dd);
  }
  return dl;
}

export function buttons(list) {
  return h('div', { class: 'row' }, list.map((b) => h('button', {
    class: b.primary ? 'primary' : (b.danger ? 'danger' : ''),
    onclick: b.onClick,
    disabled: b.disabled,
    text: b.label
  })));
}

export function number(n, digits = 0) {
  if (n === null || n === undefined || Number.isNaN(n)) return '—';
  return Number(n).toLocaleString(undefined, { minimumFractionDigits: digits, maximumFractionDigits: digits });
}

export function bytes(n) {
  if (!Number.isFinite(n)) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

export function relativeTime(iso, now = Date.now()) {
  const then = typeof iso === 'number' ? iso : Date.parse(iso);
  if (!Number.isFinite(then)) return '—';
  const diff = now - then;
  const abs = Math.abs(diff);
  const units = [
    [86_400_000, 'day'], [3_600_000, 'hour'], [60_000, 'minute'], [1000, 'second']
  ];
  for (const [ms, name] of units) {
    if (abs >= ms) {
      const value = Math.round(abs / ms);
      return `${value} ${name}${value === 1 ? '' : 's'} ${diff >= 0 ? 'ago' : 'from now'}`;
    }
  }
  return 'just now';
}

/** Draws a lightweight sparkline/bar chart with no external dependency. */
export function drawSeries(canvas, seriesList, options = {}) {
  if (!canvas) return;
  let ctx = null;
  try { ctx = canvas.getContext('2d'); } catch { ctx = null; }
  if (!ctx) return; // e.g. jsdom without canvas support — charts are optional
  const dpr = Math.min(globalThis.devicePixelRatio || 1, 2);
  const width = canvas.clientWidth || 600;
  const height = options.height || 90;
  canvas.width = width * dpr;
  canvas.height = height * dpr;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, width, height);

  const all = seriesList.flatMap((s) => s.points.map((p) => p.value));
  const max = Math.max(options.minMax ?? 1, ...all);
  const points = seriesList[0]?.points.length || 0;
  if (!points) return;

  // Baseline grid
  ctx.strokeStyle = '#16294a';
  ctx.lineWidth = 1;
  for (let i = 1; i <= 2; i++) {
    const y = (height / 3) * i;
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(width, y); ctx.stroke();
  }

  for (const series of seriesList) {
    const step = width / Math.max(1, series.points.length - 1);
    ctx.beginPath();
    series.points.forEach((p, i) => {
      const x = i * step;
      const y = height - (p.value / max) * (height - 8) - 2;
      if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    });
    if (series.fill) {
      const gradient = ctx.createLinearGradient(0, 0, 0, height);
      gradient.addColorStop(0, series.fill);
      gradient.addColorStop(1, 'rgba(0,0,0,0)');
      ctx.save();
      ctx.lineTo(width, height);
      ctx.lineTo(0, height);
      ctx.closePath();
      ctx.fillStyle = gradient;
      ctx.fill();
      ctx.restore();
      ctx.beginPath();
      series.points.forEach((p, i) => {
        const x = i * step;
        const y = height - (p.value / max) * (height - 8) - 2;
        if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      });
    }
    ctx.strokeStyle = series.color || '#2e7dff';
    ctx.lineWidth = 1.8;
    ctx.stroke();
  }

  ctx.fillStyle = '#93a8c8';
  ctx.font = '10px system-ui, sans-serif';
  ctx.fillText(String(max), 2, 10);
}

/** Toast notifications (non-blocking, auto-dismiss). */
export function toast(message, kind = '') {
  const wrap = document.getElementById('toasts');
  if (!wrap) return;
  const el = h('div', { class: `toast ${kind}`.trim(), text: message });
  wrap.appendChild(el);
  setTimeout(() => {
    el.style.opacity = '0';
    el.style.transition = 'opacity .3s';
    setTimeout(() => el.remove(), 320);
  }, 6000);
}

/** Downloads a string as a file (used for exports). */
export function download(filename, text, mime = 'application/json') {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = h('a', { href: url, download: filename });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function setBusy(button, busy, busyLabel = 'Working…') {
  if (!button) return;
  if (busy) {
    button.dataset.label = button.textContent;
    button.textContent = busyLabel;
    button.disabled = true;
  } else {
    if (button.dataset.label) button.textContent = button.dataset.label;
    button.disabled = false;
  }
}

export default { h, clear, mount, pill, note, empty, kpi, table, kv, buttons, number, bytes, relativeTime, drawSeries, toast, download, setBusy };
