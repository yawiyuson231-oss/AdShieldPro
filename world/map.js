/** Offline SVG world map. Camera and clustering are local; no tile-server or geolocation requests. */
import { clusterEvents, validCoordinates } from './model.js';
import { CATEGORIES, REGIONS } from './catalog.js';
import { h, mount } from '../ui/dom.js';
import { icon } from '../ui/icons.js';

export const project = (lat, lon) => ({ x: (lon + 180) * 1000 / 360, y: (90 - lat) * 500 / 180 });
export function cameraBounds(camera) {
  const zoom = Math.max(1, Math.min(8, Number(camera.zoom) || 1));
  const width = 1000 / zoom; const height = 500 / zoom;
  return { zoom, x: Math.max(0, Math.min(1000 - width, Number(camera.x) || 0)), y: Math.max(0, Math.min(500 - height, Number(camera.y) || 0)), width, height };
}
function svg(tag, attrs = {}, text) {
  const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
  if (text !== undefined) el.textContent = text;
  return el;
}

export class WorldMap {
  constructor(host, { onSelect = () => {} } = {}) {
    this.host = host; this.onSelect = onSelect; this.events = []; this.selected = null; this.region = 'world';
    this.camera = cameraBounds({ zoom: 1 }); this.pointers = new Map(); this.dragged = false;
    this.svg = svg('svg', { viewBox: '0 0 1000 500', class: 'wm-map-svg', tabindex: 0, role: 'group', 'aria-label': 'World event map. Arrow keys pan, plus and minus zoom, Home resets. Each marker is keyboard accessible; all records are also in the event list.' });
    this.svg.append(svg('rect', { width: 1000, height: 500, fill: '#0c1d22' }));
    const grid = svg('g', { stroke: '#223c42', 'stroke-width': 0.45, fill: 'none', 'aria-hidden': 'true' });
    for (let lon = -150; lon <= 150; lon += 30) { const x = project(0, lon).x; grid.append(svg('path', { d: `M${x} 0V500` })); }
    for (let lat = -60; lat <= 60; lat += 30) { const y = project(lat, 0).y; grid.append(svg('path', { d: `M0 ${y}H1000` })); }
    this.svg.append(grid, svg('image', { href: new URL('../assets/world-land.svg', import.meta.url).href, width: 1000, height: 500, 'aria-hidden': 'true' }));
    const labels = svg('g', { fill: '#658580', 'font-size': 10, 'letter-spacing': 2, 'text-anchor': 'middle', 'aria-hidden': 'true' });
    for (const [name, lat, lon] of [['NORTH AMERICA', 44, -105], ['SOUTH AMERICA', -18, -60], ['EUROPE', 51, 22], ['AFRICA', 4, 20], ['ASIA', 43, 100], ['OCEANIA', -27, 136], ['PACIFIC OCEAN', -5, -143]]) {
      const p = project(lat, lon); labels.append(svg('text', { x: p.x, y: p.y }, name));
    }
    this.svg.append(labels);
    this.regionLayer = svg('g'); this.nodes = svg('g'); this.svg.append(this.regionLayer, this.nodes);
    const controls = h('div', { class: 'wm-map-controls', 'aria-label': 'Map controls' },
      h('button', { type: 'button', title: 'Zoom in', 'aria-label': 'Zoom in', onclick: () => this.zoom(1.5) }, icon('plus')),
      h('button', { type: 'button', title: 'Zoom out', 'aria-label': 'Zoom out', onclick: () => this.zoom(1 / 1.5) }, icon('minus')),
      h('button', { type: 'button', title: 'Reset world view', 'aria-label': 'Reset world view', onclick: () => this.reset() }, icon('expand')));
    this.caption = h('span', { class: 'wm-map-count' });
    mount(host, this.svg, controls, h('div', { class: 'wm-map-foot' }, this.caption, h('span', {}, 'Natural Earth · public domain')));
    this.wire(); this.draw();
  }
  reset() { this.camera = cameraBounds({ zoom: 1 }); this.draw(); }
  point(event) {
    const rect = this.svg.getBoundingClientRect();
    return { x: (event.clientX - rect.left) / (rect.width || 1000), y: (event.clientY - rect.top) / (rect.height || 500) };
  }
  zoom(factor, point = { x: 0.5, y: 0.5 }) {
    const old = this.camera; const zoom = Math.max(1, Math.min(8, old.zoom * factor));
    this.camera = cameraBounds({ zoom, x: old.x + point.x * (old.width - 1000 / zoom), y: old.y + point.y * (old.height - 500 / zoom) });
    this.draw();
  }
  focus(event) {
    if (!validCoordinates(event.lat, event.lon)) return;
    const p = project(event.lat, event.lon); const zoom = Math.max(this.camera.zoom, 3);
    this.camera = cameraBounds({ zoom, x: p.x - 500 / zoom, y: p.y - 250 / zoom });
    this.selected = event.id; this.draw();
  }
  setRegion(id) {
    this.region = id;
    const region = REGIONS.find((r) => r.id === id);
    if (!region || id === 'world') { this.reset(); return; }
    const [west, south, east, north] = region.bounds;
    const top = project(north, west); const bottom = project(south, east);
    const zoom = Math.min(8, 850 / (bottom.x - top.x), 425 / (bottom.y - top.y));
    this.camera = cameraBounds({ zoom, x: (top.x + bottom.x) / 2 - 500 / zoom, y: (top.y + bottom.y) / 2 - 250 / zoom });
    this.draw();
  }
  update(events, selected) { this.events = events; this.selected = selected; this.draw(); }
  draw() {
    const c = this.camera;
    this.svg.setAttribute('viewBox', `${c.x} ${c.y} ${c.width} ${c.height}`);
    this.nodes.replaceChildren(); this.regionLayer.replaceChildren();
    const region = REGIONS.find((r) => r.id === this.region);
    if (region && region.id !== 'world') {
      const [west, south, east, north] = region.bounds; const a = project(north, west); const b = project(south, east);
      this.regionLayer.append(svg('rect', { x: a.x, y: a.y, width: b.x - a.x, height: b.y - a.y, fill: '#b9dc7c0b', stroke: '#b9dc7c', 'stroke-width': 0.8 / c.zoom, 'stroke-dasharray': `${4 / c.zoom} ${3 / c.zoom}` }));
    }
    const clusters = clusterEvents(this.events, c.zoom);
    for (const group of clusters) {
      const p = project(group.lat, group.lon);
      if (p.x < c.x - 10 || p.x > c.x + c.width + 10 || p.y < c.y - 10 || p.y > c.y + c.height + 10) continue;
      const plural = group.events.length > 1;
      const representative = group.events.find((e) => e.id === this.selected) || group.events[0];
      const colour = CATEGORIES.find((cat) => cat.id === representative.category)?.color || '#b9dc7c';
      const selected = group.events.some((e) => e.id === this.selected);
      const radius = (plural ? 10 : 5.5) / c.zoom;
      const label = plural ? `${group.events.length} events in this area. Activate to zoom in.` : `${representative.title}, ${representative.severity}. Activate for details.`;
      const node = svg('g', { transform: `translate(${p.x} ${p.y})`, class: 'wm-map-node', role: 'button', tabindex: 0, 'aria-label': label, 'data-event-id': representative.id });
      node.append(svg('title', {}, label));
      node.append(svg('circle', { r: radius + 5 / c.zoom, fill: colour, opacity: selected ? 0.25 : 0.09 }));
      node.append(svg('circle', { r: radius, fill: plural ? '#172c30' : colour, stroke: selected ? '#ffffff' : colour, 'stroke-width': (selected ? 2.2 : 1.4) / c.zoom }));
      if (plural) node.append(svg('text', { y: 3.2 / c.zoom, 'text-anchor': 'middle', fill: '#f4f8f3', 'font-size': 9 / c.zoom, 'font-family': 'system-ui', 'font-weight': 600 }, String(group.events.length)));
      const activate = () => {
        if (this.dragged) return;
        if (plural && c.zoom < 7.9) {
          const zoom = Math.min(8, c.zoom * 2);
          this.camera = cameraBounds({ zoom, x: p.x - 500 / zoom, y: p.y - 250 / zoom }); this.draw();
        } else this.onSelect(representative);
      };
      node.addEventListener('click', activate);
      node.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); e.stopPropagation(); this.dragged = false; activate(); } });
      this.nodes.append(node);
    }
    const n = this.events.filter((e) => validCoordinates(e.lat, e.lon)).length;
    this.caption.textContent = `${n} located · ${this.events.length - n} without coordinates · ${c.zoom.toFixed(1)}×`;
  }
  wire() {
    this.svg.addEventListener('wheel', (event) => { event.preventDefault(); this.zoom(event.deltaY < 0 ? 1.2 : 1 / 1.2, this.point(event)); }, { passive: false });
    this.svg.addEventListener('keydown', (event) => {
      const keys = ['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', '+', '=', '-', 'Home'];
      if (!keys.includes(event.key) || event.target !== this.svg) return;
      event.preventDefault();
      if (event.key === 'Home') this.reset();
      else if (['+', '=', '-'].includes(event.key)) this.zoom(event.key === '-' ? 1 / 1.5 : 1.5);
      else {
        const c = this.camera;
        this.camera = cameraBounds({ ...c, x: c.x + (event.key === 'ArrowLeft' ? -1 : event.key === 'ArrowRight' ? 1 : 0) * c.width / 8,
          y: c.y + (event.key === 'ArrowUp' ? -1 : event.key === 'ArrowDown' ? 1 : 0) * c.height / 8 }); this.draw();
      }
    });
    this.svg.addEventListener('pointerdown', (event) => {
      if (event.button > 0) return;
      const p = this.point(event); this.pointers.set(event.pointerId, p); this.dragged = false;
      if (event.target === this.svg || !event.target.closest?.('.wm-map-node')) this.svg.setPointerCapture?.(event.pointerId);
    });
    this.svg.addEventListener('pointermove', (event) => {
      const previous = this.pointers.get(event.pointerId); if (!previous) return;
      const p = this.point(event);
      if (Math.abs(p.x - previous.x) + Math.abs(p.y - previous.y) < 0.002) return;
      this.dragged = true;
      const other = [...this.pointers.entries()].find(([id]) => id !== event.pointerId)?.[1];
      if (other) {
        const before = Math.hypot(previous.x - other.x, previous.y - other.y);
        const after = Math.hypot(p.x - other.x, p.y - other.y);
        if (before > 0.01) this.zoom(after / before, { x: (other.x + p.x) / 2, y: (other.y + p.y) / 2 });
      } else {
        const c = this.camera;
        this.camera = cameraBounds({ ...c, x: c.x - (p.x - previous.x) * c.width, y: c.y - (p.y - previous.y) * c.height }); this.draw();
      }
      this.pointers.set(event.pointerId, p);
    });
    const end = (event) => { this.pointers.delete(event.pointerId); };
    this.svg.addEventListener('pointerup', end); this.svg.addEventListener('pointercancel', end); this.svg.addEventListener('lostpointercapture', end);
  }
}
