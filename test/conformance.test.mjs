import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  encodeTlv,
  decodeTlv,
  classifyTlvTag,
  sealPal3Record,
  openPal3Record,
  runValidation,
  runSwarmValidation,
  runCoreValidation,
  runPrimitiveValidation,
  encodePalCbor,
} from '../validate.mjs';

test('PAL/3.0 normative conformance vectors pass', () => {
  const result = runValidation();
  assert.equal(result.ok, true);
  assert.equal(result.version, JSON.parse(readFileSync(new URL('../test-vectors/v3/pal3-v0.5-vectors.json', import.meta.url), 'utf8')).specVersion);
});

test('TLV encoder and decoder reject duplicate and out-of-order tags', () => {
  assert.throws(
    () =>
      encodeTlv([
        { tag: 0x0002, value: '01' },
        { tag: 0x0001, value: '02' },
      ]),
    /E_PAL3_MALFORMED_TLV/
  );
  assert.throws(
    () =>
      encodeTlv([
        { tag: 0x0001, value: '01' },
        { tag: 0x0001, value: '02' },
      ]),
    /E_PAL3_MALFORMED_TLV/
  );
  const badWire = Buffer.from('000200000001aa000100000001bb', 'hex');
  assert.throws(() => decodeTlv(badWire), /E_PAL3_MALFORMED_TLV/);
});

test('Comprehension-bit TLV tag classifier enforces core, critical, and optional ranges', () => {
  assert.equal(classifyTlvTag(0x0001), 'core');
  assert.equal(classifyTlvTag(0x7fff), 'core');
  assert.equal(classifyTlvTag(0x8001), 'critical-extension');
  assert.equal(classifyTlvTag(0xbfff), 'critical-extension');
  assert.equal(classifyTlvTag(0xc001), 'optional-extension');
  assert.equal(classifyTlvTag(0xffff), 'optional-extension');
  assert.throws(() => classifyTlvTag(0x0000), /E_PAL3_MALFORMED_TLV/);
});

test('Record AEAD rejects sequence mismatch and header AAD tampering', () => {
  const keyHex = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
  const saltHex = 'a1b2c3d4';
  const sealed = sealPal3Record({
    type: 0x10,
    flags: 0x00,
    keyEpoch: 0,
    streamId: 1,
    channelSeq: 7,
    keyHex,
    saltHex,
    plaintextHex: '70616c33',
  });

  // Wrong expected sequence number must abort before decryption
  assert.throws(
    () =>
      openPal3Record({
        wireHex: sealed.wireHex,
        keyHex,
        saltHex,
        expectedChannelSeq: 8,
      }),
    /E_PAL3_SEQ_MISMATCH/
  );

  // Tampering with flags byte in 20-byte AAD header must fail Poly1305 tag verification
  const tampered = Buffer.from(sealed.wireHex, 'hex');
  tampered[1] ^= 0x01;
  assert.throws(() =>
    openPal3Record({
      wireHex: tampered.toString('hex'),
      keyHex,
      saltHex,
      expectedChannelSeq: 7,
    })
  );
});

test('§8.5 swarm offloading vectors pass (redistribution, proofs, E_BUSY, relay tree, swarm.v1)', () => {
  const result = runSwarmValidation();
  assert.equal(result.ok, true);
  assert.equal(result.version, '0.6.0');
  assert.ok(result.checks >= 20);
});

test('PAL-CBOR encoder sorts map keys and rejects unsupported values', () => {
  assert.equal(encodePalCbor({ b: 1, a: 'x' }).toString('hex'), '0900000002000161070000000178000162030000000000000001');
  assert.throws(() => encodePalCbor({ a: 1.5 }), /E_PAL3_MALFORMED_BODY/);
});

test('section 7.1 operations are specified and the hybrid-signed objects verify with Ed25519 and ML-DSA-65', () => {
  const r = runCoreValidation();
  assert.equal(r.ok, true);
  assert.equal(r.signed, 3);
  assert.equal(typeof r.mldsaChecked, 'boolean');
  assert.ok(r.operations >= 13);
});

test('BLAKE2b-256 Merkle trees, cookies, proof of work, PSK binder and manifest revision rules match the vectors', () => {
  const r = runPrimitiveValidation();
  assert.equal(r.ok, true);
  assert.ok(r.merkle >= 6);
});
