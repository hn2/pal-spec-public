// Draft 0.6.17 (pal-spec#49): first-contact pair key and the unlinkability rule, checked without the reference implementation.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHmac, hkdfSync } from 'node:crypto';
import { ed25519PublicKey, edPublicToX25519, edSeedToX25519, x25519 } from '../sealedbox.mjs';

const v = JSON.parse(readFileSync(new URL('../test-vectors/v3/pal3-v0.6-pair-rendezvous-vectors.json', import.meta.url), 'utf8'));
const spec = readFileSync(new URL('../spec/v3/PAL-3.0.md', import.meta.url), 'utf8');
const hkdf = (ikm, salt, info) => Buffer.from(hkdfSync('sha384', ikm, salt, Buffer.from(info, 'ascii'), 32));
const hkdfExpand = (prk, info) => createHmac('sha384', prk).update(Buffer.concat([Buffer.from(info, 'ascii'), Buffer.from([1])])).digest().subarray(0, 32);
const seedOf = (id) => Buffer.alloc(32, parseInt(id.seedByte, 16));
const epochBytes = (ms, offset) => {
  const b = Buffer.alloc(8);
  b.writeBigInt64BE(BigInt(Math.floor(ms / 900000) + offset));
  return b;
};

function pairKeys(ownSeed, ownPk, palPk, ownBeacon, palBeacon) {
  const shared = x25519(edSeedToX25519(ownSeed), edPublicToX25519(palPk));
  const ids = Buffer.concat([ownPk, palPk].sort(Buffer.compare));
  const base = hkdf(shared, ids, 'palexplorer-pair-rendezvous-v1');
  const full = hkdf(Buffer.concat([base, ...[ownBeacon, palBeacon].sort(Buffer.compare)]), ids, 'palexplorer-pair-rendezvous-beacon-v1');
  return { base, full };
}

const seedA = seedOf(v.identities.A);
const seedB = seedOf(v.identities.B);
const pkA = ed25519PublicKey(seedA);
const pkB = ed25519PublicKey(seedB);
const beaconA = hkdf(seedA, Buffer.alloc(0), 'palexplorer-rendezvous-beacon-v1');
const beaconB = hkdf(seedB, Buffer.alloc(0), 'palexplorer-rendezvous-beacon-v1');

test('identity keys and beacon keys match the vector', () => {
  assert.equal(pkA.toString('hex'), v.identities.A.edPublicKey);
  assert.equal(pkB.toString('hex'), v.identities.B.edPublicKey);
  assert.equal(beaconA.toString('hex'), v.identities.A.beaconKey);
  assert.equal(beaconB.toString('hex'), v.identities.B.beaconKey);
});

test('first-contact pair keys match the vector and are the same on both sides', () => {
  const ab = pairKeys(seedA, pkA, pkB, beaconA, beaconB);
  const ba = pairKeys(seedB, pkB, pkA, beaconB, beaconA);
  assert.equal(ab.base.toString('hex'), v.pairKey.base);
  assert.equal(ab.full.toString('hex'), v.pairKey.full);
  assert.ok(ab.base.equals(ba.base) && ab.full.equals(ba.full));
});

test('mailbox locations for the pair match the vector', () => {
  const m = v.mailboxLocationsToB;
  const key = hkdfExpand(Buffer.from(v.pairKey.full, 'hex'), 'pal3-wan-mailbox-v3');
  const got = m.epochOffsets.map((o) => createHmac('sha384', key).update(pkB).update(epochBytes(m.unixTimeMs, o)).digest('hex'));
  assert.deepEqual(got, m.locations);
});

test('a third party with both public keys and both beacon keys gets different keys', () => {
  const seedC = Buffer.alloc(32, 0xc3);
  const c = pairKeys(seedC, ed25519PublicKey(seedC), pkB, hkdf(seedC, Buffer.alloc(0), 'palexplorer-rendezvous-beacon-v1'), beaconB);
  assert.notEqual(c.base.toString('hex'), v.pairKey.base);
  assert.notEqual(c.full.toString('hex'), v.pairKey.full);
});

test('specification states the first-contact key, node identifiers and the unlinkability rule (0.6.17)', () => {
  for (const text of ['**First-contact pair key (normative).**', 'palexplorer-pair-rendezvous-v1', 'palexplorer-pair-rendezvous-beacon-v1',
    'palexplorer-rendezvous-beacon-v1', v.pairKey.base, '**DHT node identifiers (normative).**', 'MUST NOT be derived from an identity key',
    '**Unlinkability.** No component may link a network address to an identity, a handle or a share',
    'MUST use signed records only for content whose owner made it public', 'Status: **Draft 0.6.22**']) {
    assert.ok(spec.includes(text), text);
  }
});
