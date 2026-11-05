import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runCli } from '../bin/pal-spec.mjs';
import {
  encodeTlv,
  sealPal3Record,
  dissectPal3RecordHeader,
  dissectTlvBuffer,
  runSpecDoctor,
} from '../validate.mjs';

test('pal-spec doctor verifies TLV, C2 AEAD, and normative vectors', () => {
  const doc = runSpecDoctor();
  assert.equal(doc.healthy, true);
  assert.equal(doc.checks.length, 3);

  const cliRes = runCli(['doctor', '--json']);
  assert.equal(cliRes.exitCode, 0);
  const parsed = JSON.parse(cliRes.output);
  assert.equal(parsed.healthy, true);
});

test('pal-spec inspect dissects 20-byte C2 record headers and TLV frames safely', () => {
  const sealed = sealPal3Record({
    type: 0x10,
    flags: 0x02,
    keyEpoch: 3,
    streamId: 42,
    channelSeq: 99,
    keyHex: '11'.repeat(32),
    saltHex: 'aabbccdd',
    plaintextHex: 'deadbeef',
  });
  const headerInfo = dissectPal3RecordHeader(sealed.wireHex);
  assert.equal(headerInfo.typeName, 'DATA');
  assert.equal(headerInfo.keyEpoch, 3);
  assert.equal(headerInfo.streamId, 42);
  assert.equal(headerInfo.channelSeq, 99);
  assert.equal(headerInfo.payloadLength, 4);
  assert.equal(headerInfo.validLength, true);

  const tlvBuf = encodeTlv([
    { tag: 0x0001, value: '010203' },
    { tag: 0x8005, value: 'aabb' },
  ]);
  const tlvInfo = dissectTlvBuffer(tlvBuf);
  assert.equal(tlvInfo.entryCount, 2);
  assert.equal(tlvInfo.entries[0].class, 'core');
  assert.equal(tlvInfo.entries[1].class, 'critical-extension');

  const cliRecord = runCli(['inspect', sealed.wireHex, '--type', 'record', '--json']);
  assert.equal(cliRecord.exitCode, 0);
  assert.equal(JSON.parse(cliRecord.output).streamId, 42);
});

test('pal-spec errors queries error catalog', () => {
  const all = runCli(['errors', '--json']);
  assert.equal(all.exitCode, 0);
  assert.ok(JSON.parse(all.output).length >= 5);

  const one = runCli(['errors', 'E_PAL3_SEQ_MISMATCH', '--json']);
  assert.equal(one.exitCode, 0);
  assert.equal(JSON.parse(one.output).code, 'E_PAL3_SEQ_MISMATCH');

  const missing = runCli(['errors', 'E_NO_SUCH_CODE', '--json']);
  assert.equal(missing.exitCode, 1);
});

test('pal-spec writes to CLI and optional file (--output / --append)', async () => {
  const { mkdtempSync, readFileSync, rmSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const tmpDir = mkdtempSync(join(tmpdir(), 'pal-spec-out-'));
  try {
    const jsonPath = join(tmpDir, 'doctor.json');
    const res = runCli(['doctor', '--output', jsonPath]);
    assert.equal(res.exitCode, 0);
    assert.match(res.output, /HEALTHY/);
    assert.equal(res.outputFile, jsonPath);
    const written = JSON.parse(readFileSync(jsonPath, 'utf8'));
    assert.equal(written.healthy, true);

    const jsonlPath = join(tmpDir, 'telemetry.jsonl');
    runCli(['conformance', '-o', jsonlPath, '--append']);
    runCli(['doctor', '-o', jsonlPath, '--append']);
    const lines = readFileSync(jsonlPath, 'utf8').trim().split('\n');
    assert.equal(lines.length, 2);
    assert.equal(JSON.parse(lines[0]).status, 'PASS');
    assert.equal(JSON.parse(lines[1]).healthy, true);
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
});

