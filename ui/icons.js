/** Small, local stroke icons; no icon font, external requests or unsafe markup. */
const paths = {
  globe: ['M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z', 'M3 12h18M12 3c5 5 5 13 0 18-5-5-5-13 0-18Z'],
  shield: ['M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6l-8-3Z', 'm8 12 3 3 5-6'],
  grid: ['M3 3h7v7H3V3Zm11 0h7v7h-7V3ZM3 14h7v7H3v-7Zm11 0h7v7h-7v-7Z'],
  spark: ['m12 3 2.5 6.5L21 12l-6.5 2.5L12 21l-2.5-6.5L3 12l6.5-2.5L12 3Z'],
  network: ['M9 3h6v6H9V3ZM2 16h6v5H2v-5Zm14 0h6v5h-6v-5ZM12 9v4M5 16v-3h14v3'],
  activity: ['M3 12h4l3-8 4 16 3-8h4'],
  layers: ['m12 3 9 5-9 5-9-5 9-5Zm-9 9 9 5 9-5M3 16l9 5 9-5'],
  lock: ['M5 10h14v11H5V10ZM8 10V7a4 4 0 0 1 8 0v3M12 14v3'],
  cloud: ['M7 18a5 5 0 1 1 1-10 6 6 0 0 1 11 3 4 4 0 0 1 0 8H7'],
  extension: ['M9 3h6v4h4v6h-4v4H9v4H3V7h6V3Z'],
  check: ['m5 12 4 4L19 6'],
  search: ['M17 10a7 7 0 1 1-14 0 7 7 0 0 1 14 0Zm-2 5 6 6'],
  arrow: ['M5 12h14m-6-6 6 6-6 6'],
  refresh: ['M20 7v5h-5M4 17v-5h5', 'M5 8a8 8 0 0 1 13-3l2 3M4 16l2 3a8 8 0 0 0 13-3'],
  bookmark: ['M6 3h12v18l-6-4-6 4V3Z'],
  bell: ['M6 8a6 6 0 0 1 12 0v7l3 3H3l3-3V8ZM9 21h6'],
  download: ['M12 3v12m-5-5 5 5 5-5M4 16v5h16v-5'],
  close: ['m6 6 12 12M6 18 18 6'],
  plus: ['M12 5v14M5 12h14'],
  minus: ['M5 12h14'],
  expand: ['M8 3H3v5m13-5h5v5M3 16v5h5m13-5v5h-5'],
  flame: ['M12 2c2 6-5 7-4 12 3 1 5-2 5-4 7 5 6 12-1 12C2 22 2 12 7 8c0 4 4 0 5-6Z'],
  news: ['M4 3h16v18H4V3ZM8 7h8M8 11h8M8 15h4M8 18h8'],
  clock: ['M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0ZM12 7v5l4 2'],
  pin: ['M19 9c0 5-7 12-7 12S5 14 5 9a7 7 0 0 1 14 0ZM14 9a2 2 0 1 1-4 0 2 2 0 0 1 4 0Z'],
  sun: ['M16 12a4 4 0 1 1-8 0 4 4 0 0 1 8 0ZM12 2v2m0 16v2M2 12h2m16 0h2M5 5l2 2m10 10 2 2M5 19l2-2M17 7l2-2'],
  menu: ['M4 6h16M4 12h16M4 18h16']
};
export function icon(name, size = 18) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  for (const [key, value] of Object.entries({ width: size, height: size, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': 1.6, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true', class: 'icon' })) svg.setAttribute(key, value);
  for (const d of paths[name] || paths.globe) { const path = document.createElementNS(svg.namespaceURI, 'path'); path.setAttribute('d', d); svg.appendChild(path); }
  return svg;
}
