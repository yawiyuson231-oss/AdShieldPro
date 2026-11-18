/**
 * Unit tests — the capability-matrix generator (tools/generate_capability_matrix.py).
 *
 * docs/CAPABILITY_MATRIX.md is generated from the Kotlin registry, so a parser bug
 * becomes a published documentation bug. The regression this suite locks in: the
 * registry wraps prose across lines with Kotlin's adjacent string concatenation
 * (`"first " + "second"`), and the generator used to publish that source verbatim —
 * `" +` and stray quotes included — instead of the rendered sentence.
 */
import test from 'node:test';
import { strict as assert } from 'node:assert';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../');

/** The generator is a Python script; --check is its read-only contract. */
function runGenerator(args = []) {
  return execFileSync('python3', ['tools/generate_capability_matrix.py', ...args], {
    cwd: ROOT, encoding: 'utf8', stdio: 'pipe'
  });
}

test('the published capability matrix matches the registry (--check passes)', () => {
  const out = runGenerator(['--check']);
  assert.match(out, /capability matrix up to date/);
});

test('the capability matrix contains rendered prose, not raw Kotlin source', () => {
  const body = readFileSync(resolve(ROOT, 'docs/CAPABILITY_MATRIX.md'), 'utf8');
  assert.equal(body.includes('" +'), false,
    'unfolded Kotlin string concatenation leaked into the published table');
  assert.equal(/"(battery|blocks stay|Only security)/.test(body), false,
    'a fragment of Kotlin source leaked into the published table');
  assert.match(body, /battery threshold crossings, settings changes and WorkManager results/,
    'the joined sentence must read as one line');
});

test('every capability row has exactly seven table columns and no empty cell', () => {
  const body = readFileSync(resolve(ROOT, 'docs/CAPABILITY_MATRIX.md'), 'utf8');
  const rows = body.split('\n').filter((line) => line.startsWith('| **') && !line.startsWith('| **Total**'));
  assert.ok(rows.length > 100, `expected the full registry, found ${rows.length} rows`);
  for (const row of rows) {
    const cells = row.split('|').slice(1, -1).map((c) => c.trim());
    assert.equal(cells.length, 7, `row has ${cells.length} columns: ${row.slice(0, 90)}`);
    assert.ok(cells.every(Boolean), `row has an empty cell: ${row.slice(0, 90)}`);
  }
});

test('totals in the matrix add up to the number of rendered rows', () => {
  const body = readFileSync(resolve(ROOT, 'docs/CAPABILITY_MATRIX.md'), 'utf8');
  const rows = body.split('\n').filter((line) => line.startsWith('| **') && !line.startsWith('| **Total**')).length;
  const total = Number(/^\| \*\*Total\*\* \| \*\*(\d+)\*\* \|$/m.exec(body)?.[1]);
  assert.equal(total, rows, 'the Totals table must match the rows actually rendered');
});
