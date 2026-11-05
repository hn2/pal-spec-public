#!/usr/bin/env node
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import {
  PAL3_SPEC_ERROR_CATALOG,
  dissectPal3RecordHeader,
  dissectTlvBuffer,
  runSpecDoctor,
  runValidation,
} from '../validate.mjs';

const NL = String.fromCharCode(10);

export function writeCliOutputFile(filePath, payload, textOutput, { append = false } = {}) {
  if (!filePath) return null;
  const abs = resolve(filePath);
  mkdirSync(dirname(abs), { recursive: true });
  const lower = abs.toLowerCase();
  if (append || lower.endsWith('.jsonl') || lower.endsWith('.ndjson')) {
    const line = JSON.stringify(payload !== undefined ? payload : { output: textOutput }) + NL;
    if (append) appendFileSync(abs, line, 'utf8');
    else writeFileSync(abs, line, 'utf8');
    return abs;
  }
  const content =
    lower.endsWith('.json') && payload !== undefined
      ? JSON.stringify(payload, null, 2) + NL
      : String(textOutput) + (String(textOutput).endsWith(NL) ? '' : NL);
  writeFileSync(abs, content, 'utf8');
  return abs;
}

function extractOption(argv, flags) {
  let value = null;
  const rest = [];
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    const eqFlag = flags.find((f) => token.startsWith(`${f}=`));
    if (eqFlag) {
      value = token.slice(eqFlag.length + 1);
      continue;
    }
    if (flags.includes(token)) {
      if (i + 1 < argv.length) {
        value = argv[i + 1];
        i += 1;
      }
      continue;
    }
    rest.push(token);
  }
  return { value, rest };
}

export function runCli(argv = process.argv.slice(2)) {
  const jsonFlag = argv.includes('--json');
  const appendFlag = argv.includes('--append');
  const strippedFlags = argv.filter((a) => a !== '--json' && a !== '--append');
  const { value: outFile, rest: afterOut } = extractOption(strippedFlags, ['-o', '--out', '--output', '--log-file']);
  const { value: rawType, rest: args } = extractOption(afterOut, ['--type']);
  const inspectType = rawType || 'auto';
  const outputPath = outFile || process.env.PAL_SPEC_OUTPUT_FILE || null;

  const finalize = (exitCode, output, payload) => {
    const writtenFile = writeCliOutputFile(outputPath, payload, output, { append: appendFlag });
    return { exitCode, output, outputFile: writtenFile, payload };
  };

  const cmd = args[0] || 'validate';

  if (cmd === 'doctor') {
    const report = runSpecDoctor();
    const lines = [
      `PAL/3.0 Spec Doctor (${report.elapsedMs}ms): ${report.healthy ? 'HEALTHY' : 'UNHEALTHY'}`,
      ...report.checks.map((c) => `  [${c.status.toUpperCase()}] ${c.name}: ${c.detail}`),
    ];
    const output = jsonFlag ? JSON.stringify(report, null, 2) : lines.join(NL);
    return finalize(report.healthy ? 0 : 1, output, report);
  }

  if (cmd === 'validate' || cmd === 'conformance') {
    try {
      const res = runValidation();
      const payload = { ok: true, protocol: 'PAL/3.0', specVersion: res.version, status: 'PASS' };
      const output = jsonFlag
        ? JSON.stringify(payload, null, 2)
        : `PAL/3.0 conformance vectors (${res.version}) verified: PASS`;
      return finalize(0, output, payload);
    } catch (err) {
      const payload = { ok: false, error: err.message };
      const output = jsonFlag ? JSON.stringify(payload, null, 2) : `FAIL: ${err.message}`;
      return finalize(1, output, payload);
    }
  }

  if (cmd === 'errors') {
    const code = args[1];
    if (code) {
      const entry = PAL3_SPEC_ERROR_CATALOG[code.toUpperCase()];
      if (!entry) {
        const payload = { error: `Unknown error code: ${code}` };
        return finalize(1, jsonFlag ? JSON.stringify(payload) : payload.error, payload);
      }
      const output = jsonFlag
        ? JSON.stringify(entry, null, 2)
        : [
            `${entry.code} [${entry.level}/${entry.category}] retryable=${entry.retryable}`,
            `  ${entry.message}`,
            `  Hint: ${entry.hint}`,
          ].join(NL);
      return finalize(0, output, entry);
    }
    const all = Object.values(PAL3_SPEC_ERROR_CATALOG);
    const output = jsonFlag
      ? JSON.stringify(all, null, 2)
      : all.map((e) => `${e.code} [${e.level}] — ${e.message}`).join(NL);
    return finalize(0, output, all);
  }

  if (cmd === 'inspect') {
    const target = args[1];
    if (!target) {
      return finalize(1, 'Usage: pal-spec inspect <hex-or-file> [--type record|tlv] [--json] [--output <file>]', {
        error: 'missing_target',
      });
    }
    let hex = target.trim();
    if (!/^(0x)?[0-9a-fA-F]+$/.test(hex)) {
      hex = readFileSync(target).toString('hex');
    }
    try {
      const result =
        inspectType === 'tlv'
          ? dissectTlvBuffer(hex)
          : inspectType === 'record'
            ? dissectPal3RecordHeader(hex)
            : (() => {
                try {
                  return dissectPal3RecordHeader(hex);
                } catch {
                  return dissectTlvBuffer(hex);
                }
              })();
      return finalize(0, JSON.stringify(result, null, 2), result);
    } catch (err) {
      const payload = { error: err.message };
      return finalize(1, jsonFlag ? JSON.stringify(payload) : `Inspect error: ${err.message}`, payload);
    }
  }

  return finalize(
    1,
    'Usage: pal-spec <validate|conformance|doctor|inspect|errors> [--json] [-o|--output <file>] [--append]',
    { error: 'unknown_command' },
  );
}

if (process.argv[1]?.endsWith('pal-spec.mjs')) {
  const { exitCode, output } = runCli(process.argv.slice(2));
  if (exitCode === 0) console.log(output);
  else console.error(output);
  process.exit(exitCode);
}

