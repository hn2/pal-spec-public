import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const vectors = JSON.parse(readFileSync(new URL('../test-vectors/v3/pal3-v0.6-transport-vectors.json', import.meta.url), 'utf8'));
const spec = readFileSync(new URL('../spec/v3/PAL-3.0.md', import.meta.url), 'utf8');
const sha384Hex = (text) => createHash('sha384').update(text, 'utf8').digest('hex');

test('mailbox location key vector matches SHA-384 of the specified input', () => {
  const v = vectors.mailboxLocationKey;
  assert.equal(v.dayIndex, Math.floor(v.unixSeconds / 86400));
  assert.equal(v.inputUtf8, `palexplorer-mailbox-v1\n${v.recipientPublicKey}\n${v.dayIndex}`);
  assert.equal(sha384Hex(v.inputUtf8), v.locationKeyHex);
});

test('specification text quotes the mailbox location key vector', () => {
  const v = vectors.mailboxLocationKey;
  assert.ok(spec.includes(v.locationKeyHex));
  assert.ok(spec.includes(String(v.dayIndex)));
});

test('specification states the transport rules and error identifiers', () => {
  for (const text of ['## 14. Direct by Default', 'MUST try to reach a peer directly', 'chat.deliver', 'E_PAL3_UNREACHABLE', 'E_CHAT_NOT_A_PAL', 'E_MESSAGE_TOO_LARGE']) {
    assert.ok(spec.includes(text), text);
  }
});

test('no address field is exchanged, published or returned (#1277 guard)', () => {
  const body = spec.split('\n').filter((line) => !line.startsWith('**Changes in Draft')).join('\n');
  assert.ok(spec.includes('{ peers: [{ peerPk }] }'));
  for (const text of ['{ peers: [{ peerPk, host, port }] }', 'direct.endpoint', 'direct.consent', 'E_PAL3_NO_RELAY', 'publishes its reachable endpoint', 'MUST reach a peer that is not another device of the same identity through a relay']) {
    assert.ok(!body.includes(text), text);
  }
  const s14 = body.slice(body.indexOf('## 14. '), body.indexOf('### 14.5'));
  assert.ok(s14.includes('### 14.2 Introduction'));
  assert.ok(s14.includes('MUST NOT return an address to an application'));
  assert.ok(!/\{[^}]*\b(host|port|address|ip)\b[^}]*\}/.test(s14), 'no address field in a section 14 wire form');
});

test('both specification copies are identical', () => {
  assert.equal(readFileSync(new URL('../spec/PAL3-PROTOCOL.md', import.meta.url), 'utf8'), spec);
});

test('section 14.5 states the identifier rule normatively (#35, #48)', () => {
  const spec = readFileSync(new URL('../spec/v3/PAL-3.0.md', import.meta.url), 'utf8');
  const section = spec.slice(spec.indexOf('### 14.5 Identifiers'), spec.indexOf('### 14.6'));
  for (const text of ['pal3-id-peer-v1', 'SHA-384 of the file content', 'the Merkle root of the manifest', 'pal3-id-group-v1', 'pal3-id-network-v1', '96 lowercase hexadecimal characters', 'A 64-character value is not an identifier', 'as a map key', 'rejected, never matched by prefix', 'SHA-1, SHA-256, MD5, BLAKE2 and BLAKE3 MUST NOT be used for identifiers', 'BEP 10, BEP 44 targets and `btih`']) {
    assert.ok(section.includes(text), text);
  }
});

test('section 14.11 states the SDK-only and native UDP product boundary rules (#48)', () => {
  const spec = readFileSync(new URL('../spec/v3/PAL-3.0.md', import.meta.url), 'utf8');
  const section = spec.slice(spec.indexOf('### 14.11 Product SDK and Transport Boundaries'), spec.indexOf('## 15.'));
  for (const text of [
    '**SDK-only boundary.**',
    '@hn2/pal-sdk',
    '**Identity-only product API.**',
    '**Native UDP-only boundary.**',
    'enableIceTcp: false',
  ]) {
    assert.ok(section.includes(text), text);
  }
});

test('no wire form carries a hints or observed address field (#1277 draft 0.6.16 guard)', () => {
  const body = spec.split('\n').filter((line) => !line.startsWith('**Changes in Draft')).join('\n');
  assert.ok(!/\bhints\b/.test(body), 'spec text mentions hints');
  for (const f of ['pal3-v0.6-core-operations.json', 'pal3-v0.6-swarm-vectors.json']) {
    const text = readFileSync(new URL(`../test-vectors/v3/${f}`, import.meta.url), 'utf8');
    assert.ok(!/hints|"observed"/.test(text), f);
  }
});
