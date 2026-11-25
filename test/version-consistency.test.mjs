import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = path => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');

test('readme_badgeAndVersionsTable_matchTheSpecificationStatusLine', () => {
  const spec = /Status: \*\*Draft (\d+\.\d+\.\d+)\*\*/.exec(read('spec/v3/PAL-3.0.md'));
  assert.ok(spec, 'status line not found in spec/v3/PAL-3.0.md');
  const readme = read('README.md');
  const badge = /Draft_(\d+\.\d+\.\d+)/.exec(readme);
  assert.ok(badge, 'badge version not found in README.md');
  const table = /\*\*Current\*\*: Draft (\d+\.\d+\.\d+)/.exec(readme);
  assert.ok(table, 'Current cell not found in the README versions table');
  assert.equal(badge[1], spec[1], 'README badge differs from the specification');
  assert.equal(table[1], spec[1], 'README versions table differs from the specification');
});
