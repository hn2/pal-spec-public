import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createPublicKey, verify } from 'node:crypto';

const vectors = JSON.parse(readFileSync(new URL('../test-vectors/v3/pal3-v0.6-private-network-vectors.json', import.meta.url), 'utf8'));
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const verifies = (publicHex, bytesHex, signatureHex) =>
  verify(
    null,
    Buffer.from(bytesHex, 'hex'),
    createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(publicHex, 'hex')]), format: 'der', type: 'spki' }),
    Buffer.from(signatureHex, 'hex')
  );

test('private network profile vector signature verifies under the administrator key', () => {
  const { object, signedBytesHex } = vectors.profile;
  assert.equal(object.admin, vectors.keys.admin.publicKey);
  assert.equal(verifies(object.admin, signedBytesHex, object.signature), true);
});

test('private network profile signed bytes use the v3 context and the fixed key order', () => {
  const { signedBytesUtf8, signedBytesHex } = vectors.profile;
  assert.equal(Buffer.from(signedBytesHex, 'hex').toString('utf8'), signedBytesUtf8);
  const [context, json] = signedBytesUtf8.split('\n');
  assert.equal(context, 'palexplorer-private-network-v3');
  const parsed = JSON.parse(json);
  assert.deepEqual(Object.keys(parsed), ['name', 'admin', 'discoveryServers', 'relays', 'members', 'privacyMode', 'issuedAt', 'version', 'expiresAt']);
  assert.deepEqual(Object.keys(parsed.members[0]), ['publicKey', 'name', 'revoked']);
  assert.equal(parsed.members[1].name, null);
});

test('private network profile signature fails when expiresAt changes', () => {
  const { object, signedBytesUtf8 } = vectors.profile;
  const altered = Buffer.from(signedBytesUtf8.replace(object.expiresAt, '2027-12-15T10:00:00.000Z'), 'utf8').toString('hex');
  assert.equal(verifies(object.admin, altered, object.signature), false);
});

test('private network handover vector verifies and names a member that is not revoked', () => {
  const { object, signedBytesUtf8, signedBytesHex } = vectors.handover;
  assert.equal(verifies(object.from, signedBytesHex, object.signature), true);
  const [context, json] = signedBytesUtf8.split('\n');
  assert.equal(context, 'palexplorer-private-network-handover-v1');
  assert.deepEqual(Object.keys(JSON.parse(json)), ['name', 'from', 'to', 'issuedAt', 'expiresAt']);
  assert.equal(vectors.profile.object.members.find((m) => m.publicKey === object.to)?.revoked, false);
  assert.ok(Date.parse(object.expiresAt) - Date.parse(object.issuedAt) <= 30 * 24 * 3600 * 1000);
});
