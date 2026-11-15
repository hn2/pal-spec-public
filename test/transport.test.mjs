import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const vectors = JSON.parse(readFileSync(new URL('../test-vectors/v3/pal3-v0.6-transport-vectors.json', import.meta.url), 'utf8'));
const spec = readFileSync(new URL('../spec/v3/PAL-3.0.md', import.meta.url), 'utf8');
const sha256Hex = (text) => createHash('sha256').update(text, 'utf8').digest('hex');

test('mailbox location key vector matches SHA-256 of the specified input', () => {
  const v = vectors.mailboxLocationKey;
  assert.equal(v.dayIndex, Math.floor(v.unixSeconds / 86400));
  assert.equal(v.inputUtf8, `palexplorer-mailbox-v1\n${v.recipientPublicKey}\n${v.dayIndex}`);
  assert.equal(sha256Hex(v.inputUtf8), v.locationKeyHex);
});

test('specification text quotes the mailbox location key vector', () => {
  const v = vectors.mailboxLocationKey;
  assert.ok(spec.includes(v.locationKeyHex));
  assert.ok(spec.includes(String(v.dayIndex)));
});

test('specification states the transport rules and error identifiers', () => {
  for (const text of ['direct.consent', 'direct.endpoint', 'chat.deliver', 'E_PAL3_DIRECT_NOT_ALLOWED', 'E_PAL3_NO_RELAY', 'E_CHAT_NOT_A_PAL', 'E_MESSAGE_TOO_LARGE']) {
    assert.ok(spec.includes(text), text);
  }
});

test('peer exchange wire form carries no address fields', () => {
  assert.ok(!spec.includes('{ peers: [{ peerPk, host, port }] }'));
  assert.ok(spec.includes('{ peers: [{ peerPk }] }'));
});

test('both specification copies are identical', () => {
  assert.equal(readFileSync(new URL('../spec/PAL3-PROTOCOL.md', import.meta.url), 'utf8'), spec);
});
