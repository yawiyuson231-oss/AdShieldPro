#!/usr/bin/env node
/**
 * OmniShield X — generates the PNG icon set the web manifest needs.
 *
 * A manifest that points at PNGs which do not exist makes the app
 * non-installable (Chrome drops the manifest), so these files are generated
 * from the same shield geometry as assets/icon.svg and committed. No runtime
 * dependency: this uses only Node's zlib and a tiny PNG encoder.
 *
 * Usage: node tools/make-pwa-icons.mjs
 */
import { writeFileSync } from 'node:fs';
import { deflateSync } from 'node:zlib';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** Writes an RGBA PNG from a pixel buffer produced by `shade(x, y, size)`. */
function png(size, shade) {
  const raw = Buffer.alloc(size * size * 4);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const [r, g, b, a] = shade(x, y, size);
      const i = (y * size + x) * 4;
      raw[i] = r; raw[i + 1] = g; raw[i + 2] = b; raw[i + 3] = a;
    }
  }
  const stride = size * 4;
  const filtered = Buffer.alloc((stride + 1) * size);
  for (let y = 0; y < size; y++) {
    filtered[y * (stride + 1)] = 0; // filter: none
    raw.copy(filtered, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;   // bit depth
  ihdr[9] = 6;   // colour type RGBA
  const chunk = (type, data) => {
    const len = Buffer.alloc(4); len.writeUInt32BE(data.length, 0);
    const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
    const crcTable = [];
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      crcTable[n] = c >>> 0;
    }
    let c = 0xffffffff;
    for (const byte of body) c = crcTable[(c ^ byte) & 0xff] ^ (c >>> 8);
    const crc = Buffer.alloc(4); crc.writeUInt32BE((c ^ 0xffffffff) >>> 0, 0);
    return Buffer.concat([len, body, crc]);
  };
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(filtered, { level: 9 })),
    chunk('IEND', Buffer.alloc(0))
  ]);
}

const hex = (h) => [parseInt(h.slice(1, 3), 16), parseInt(h.slice(3, 5), 16), parseInt(h.slice(5, 7), 16)];
const mix = (a, b, t) => [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t];

/** Shield path test in a 128-unit design space (mirrors assets/icon.svg). */
function shieldAt(px, py) {
  // Shield outline: rectangle with a pointed bottom, centred on 64,64.
  const x = px - 64;
  const y = py - 64;
  const halfW = 40;
  const top = -46;
  const shoulder = -18;
  const bottom = 48;
  if (Math.abs(x) > halfW) return 0;
  if (y < top) return 0;
  if (y <= shoulder) return 1;
  // Lower half: a shield curve, not a triangle. The sides stay wide until the
  // last third, then sweep into a rounded point (`t^1.7` shaped power curve).
  const t = (y - shoulder) / (bottom - shoulder);
  const limit = halfW * Math.sqrt(Math.max(0, 1 - Math.pow(t, 1.7)));
  return Math.abs(x) <= limit ? 1 : 0;
}

/** Check-mark stroke test (design space). */
function checkAt(px, py) {
  const pts = [[50, 66], [60, 76], [80, 54]];
  const w = 7 / 2;
  for (let i = 0; i < pts.length - 1; i++) {
    const [x1, y1] = pts[i];
    const [x2, y2] = pts[i + 1];
    const dx = x2 - x1, dy = y2 - y1;
    const len2 = dx * dx + dy * dy;
    let t = ((px - x1) * dx + (py - y1) * dy) / len2;
    t = Math.max(0, Math.min(1, t));
    const cx = x1 + t * dx, cy = y1 + t * dy;
    if (Math.hypot(px - cx, py - cy) <= w) return 1;
  }
  return 0;
}

function iconPixel(px, py, size, { maskable = false } = {}) {
  const u = (px / size) * 128;
  const v = (py / size) * 128;
  const bg = hex('#050b16');
  const blue = hex('#2e7dff');
  const glow = hex('#6fb3ff');
  const green = hex('#34d399');

  // Rounded-square background (square for maskable, which is safe-zone cropped).
  const r = maskable ? 0 : 28;
  const inset = maskable ? 0 : 0;
  const inside = (() => {
    if (!r) return true;
    const cx = Math.min(Math.max(u, r), 128 - r);
    const cy = Math.min(Math.max(v, r), 128 - r);
    return Math.hypot(u - cx, v - cy) <= r;
  })();
  if (!inside) return [0, 0, 0, 0];

  const scale = maskable ? 0.78 : 1; // keep the mark inside the maskable safe zone
  const su = 64 + (u - 64) / scale;
  const sv = 64 + (v - 64) / scale;

  let colour = bg;
  // Radial lift behind the mark.
  const d = Math.hypot(u - 64, v - 64) / 78;
  if (d < 1) colour = mix(bg, blue, 0.16 * (1 - d));

  if (shieldAt(su, sv)) {
    const t = (sv - 18) / 94;
    colour = mix(mix(hex('#0a1730'), blue, 0.22), hex('#0d2a4a'), t);
  }
  // Outline ring
  const edge = shieldAt(su, sv) && (!shieldAt(su - 2.6, sv) || !shieldAt(su + 2.6, sv)
    || !shieldAt(su, sv - 2.6) || !shieldAt(su, sv + 2.6));
  if (edge) colour = mix(colour, glow, 0.85);
  if (checkAt(su, sv)) colour = green;

  void inset;
  return [Math.round(colour[0]), Math.round(colour[1]), Math.round(colour[2]), 255];
}

const targets = [
  ['assets/icon-192.png', 192, (x, y, s) => iconPixel(x, y, s)],
  ['assets/icon-512.png', 512, (x, y, s) => iconPixel(x, y, s)],
  ['assets/icon-maskable-512.png', 512, (x, y, s) => iconPixel(x, y, s, { maskable: true })]
];

for (const [file, size, shade] of targets) {
  writeFileSync(resolve(ROOT, file), png(size, shade));
  console.log(`${file} — ${size}×${size}`);
}
