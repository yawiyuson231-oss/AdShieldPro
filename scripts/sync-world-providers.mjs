#!/usr/bin/env node
/** Keep the Android daily worker on the exact, reviewed browser provider catalogue. */
import { readFileSync, writeFileSync } from 'node:fs';
import { SOURCES, LIMITS } from '../world/catalog.js';
const path = new URL('../world/providers.json', import.meta.url);
const data = JSON.stringify({ version: 1, maxBytes: LIMITS.bytes, sources: SOURCES.map((s) => ({ id: s.id, name: s.name, url: s.url, accept: s.accept || 'application/json', ttlMs: s.ttlMs, format: s.parser || s.id })) }, null, 2) + '\n';
if (process.argv.includes('--check')) {
  if (readFileSync(path, 'utf8') !== data) throw new Error('world/providers.json is stale. Run node scripts/sync-world-providers.mjs.');
  console.log(`World Monitor provider registry matches ${SOURCES.length} public endpoints.`);
} else { writeFileSync(path, data); console.log(`Wrote ${SOURCES.length} background provider definitions.`); }
