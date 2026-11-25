import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';

const root = new URL('../', import.meta.url);
const vectorDir = new URL('test-vectors/v3/', root);

export function normativeSections(specText) {
  const sections = [];
  let current = null;
  let fence = false;
  for (const line of specText.split(/\r?\n/)) {
    if (line.startsWith('```')) fence = !fence;
    if (!fence) {
      const m = /^#{2,4} (?:Appendix )?(\d+(?:\.\d+)*|A(?:\.\d+)?)\.? ?(.*)$/.exec(line);
      if (m) {
        current = { number: m[1], title: m[2].trim(), text: '' };
        sections.push(current);
        continue;
      }
      if (/^#{1,3} /.test(line)) {
        current = null;
        continue;
      }
    }
    if (current) current.text += `${line}\n`;
  }
  return sections.filter((s) => /\bMUST\b/.test(s.text));
}

export function parseCoverageTable(markdown) {
  const rows = [];
  for (const line of markdown.split(/\r?\n/)) {
    if (!line.startsWith('|')) continue;
    const cells = line.split('|').slice(1, -1).map((c) => c.trim());
    if (cells.length !== 5 || cells[0] === 'section' || /^-+$/.test(cells[0])) continue;
    const list = (c) => (c === '-' ? [] : c.split(',').map((x) => x.trim().replace(/`/g, '')).filter(Boolean));
    rows.push({ section: cells[0], title: cells[1], files: list(cells[2]), cases: list(cells[3]), status: cells[4] });
  }
  return rows;
}

export function checkCoverage(specText, markdown) {
  const errors = [];
  const rows = parseCoverageTable(markdown);
  const bySection = new Map(rows.map((r) => [r.section, r]));
  const required = normativeSections(specText);
  for (const s of required) {
    if (!bySection.has(s.number)) errors.push(`section ${s.number} (${s.title}) has MUST text but no row`);
  }
  const known = new Set(required.map((s) => s.number));
  for (const r of rows) {
    if (!known.has(r.section)) errors.push(`row ${r.section} is not a numbered section with MUST text`);
    if (!['covered', 'partial', 'none'].includes(r.status)) errors.push(`row ${r.section} has status "${r.status}"`);
    if (r.status === 'none') {
      if (r.files.length || r.cases.length) errors.push(`row ${r.section} is none but names vectors`);
      continue;
    }
    if (!r.files.length || !r.cases.length) errors.push(`row ${r.section} is ${r.status} but names no file or case`);
    const keySets = [];
    for (const f of r.files) {
      const path = new URL(f, vectorDir);
      if (!existsSync(path)) {
        errors.push(`row ${r.section} names missing vector file ${f}`);
        continue;
      }
      const json = JSON.parse(readFileSync(path, 'utf8'));
      keySets.push(new Set(Object.keys(json).filter((k) => !(typeof json[k] === 'string' && /^pending/i.test(json[k])))));
    }
    for (const c of r.cases) {
      if (!keySets.some((k) => k.has(c))) errors.push(`row ${r.section} names case id ${c} that is in none of its files`);
    }
  }
  return errors;
}

const spec = readFileSync(new URL('spec/v3/PAL-3.0.md', root), 'utf8');
const table = readFileSync(new URL('test-vectors/v3/COVERAGE.md', root), 'utf8');

test('coverage table has a row for every normative section and names only existing vectors', () => {
  assert.deepEqual(checkCoverage(spec, table), []);
});

test('coverage check fails when a normative section row is removed', () => {
  const cut = table.split('\n').filter((l) => !l.startsWith('| 5.3 |')).join('\n');
  assert.match(checkCoverage(spec, cut).join('\n'), /section 5\.3 .* no row/);
});

test('coverage check fails on a missing vector file and on an unknown case id', () => {
  const badFile = table.replace('pal3-v0.6-rekey-vectors.json', 'pal3-v0.6-nope-vectors.json');
  assert.match(checkCoverage(spec, badFile).join('\n'), /missing vector file pal3-v0\.6-nope/);
  const badCase = table.replace('epochLimits', 'noSuchCase');
  assert.match(checkCoverage(spec, badCase).join('\n'), /case id noSuchCase/);
});

test('a case id whose value is a pending placeholder does not count as coverage', () => {
  const row = '| 13.4 | Accepting a Profile | pal3-v0.6-private-network-vectors.json | crossVerification | partial |';
  const edited = table.split('\n').map((l) => (l.startsWith('| 13.4 |') ? row : l)).join('\n');
  assert.match(checkCoverage(spec, edited).join('\n'), /case id crossVerification/);
});

test('a heading with MUST text that is added to the specification needs a row', () => {
  const extra = `${spec}\n### 15.9 New rule\nA peer MUST do it.\n`;
  assert.match(checkCoverage(extra, table).join('\n'), /section 15\.9 .* no row/);
});
