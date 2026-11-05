import { createHash, createHmac, createCipheriv, createDecipheriv } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Deterministic TLV encoder per PAL/3.0 Appendix A.1.
 * Entries must be sorted by strictly ascending tag (u16be).
 */
export function encodeTlv(entries) {
  let prevTag = -1;
  const buffers = [];
  for (const { tag, value } of entries) {
    if (!Number.isInteger(tag) || tag < 0 || tag > 0xffff) {
      throw new Error('E_PAL3_MALFORMED_TLV: tag out of u16 range');
    }
    if (tag <= prevTag) {
      throw new Error('E_PAL3_MALFORMED_TLV: tags must be strictly ascending without duplicates');
    }
    prevTag = tag;
    const valBuf = Buffer.isBuffer(value) ? value : Buffer.from(value, 'hex');
    const header = Buffer.alloc(6);
    header.writeUInt16BE(tag, 0);
    header.writeUInt32BE(valBuf.length, 2);
    buffers.push(header, valBuf);
  }
  return Buffer.concat(buffers);
}

/**
 * Deterministic TLV decoder per PAL/3.0 Appendix A.1.
 */
export function decodeTlv(buffer) {
  const entries = [];
  let offset = 0;
  let prevTag = -1;
  while (offset < buffer.length) {
    if (offset + 6 > buffer.length) {
      throw new Error('E_PAL3_MALFORMED_TLV: truncated header');
    }
    const tag = buffer.readUInt16BE(offset);
    const length = buffer.readUInt32BE(offset + 2);
    offset += 6;
    if (tag <= prevTag) {
      throw new Error('E_PAL3_MALFORMED_TLV: non-ascending or duplicate tag');
    }
    if (offset + length > buffer.length) {
      throw new Error('E_PAL3_MALFORMED_TLV: truncated value');
    }
    prevTag = tag;
    entries.push({ tag, value: buffer.subarray(offset, offset + length) });
    offset += length;
  }
  return entries;
}

/**
 * Comprehension-bit classification per PAL/3.0 §12.1.
 */
export function classifyTlvTag(tag) {
  if (tag >= 0x0001 && tag <= 0x7fff) return 'core';
  if ((tag & 0xc000) === 0x8000) return 'critical-extension';
  if ((tag & 0xc000) === 0xc000) return 'optional-extension';
  throw new Error('E_PAL3_MALFORMED_TLV: reserved tag 0x0000');
}

function hkdfExpand32(prk, info, length) {
  return createHmac('sha256', prk).update(info).update(Buffer.from([1])).digest().subarray(0, length);
}

/**
 * Draft 0.5 hybrid KEM combiner & key schedule per PAL/3.0 §5.2:
 *   prk_hs = HKDF-Extract(th_hs, ss_x || ss_pq || kem_context); k_id = HKDF-Expand(prk_hs, "pal3-hs-id-v2")
 *   prk_0  = HKDF-Extract(th, prk_hs); key/salt/exporter = HKDF-Expand(prk_0, label || epoch || ...)
 */
export function deriveSessionChannelMaterial({
  ssXHex,
  ssPqHex,
  x25519EphIHex,
  x25519EphRHex,
  mlkemEkISha256Hex,
  mlkemCtSha256Hex,
  thHsHex,
  thHex,
  epoch,
  channelId,
  direction,
}) {
  const kemContext = Buffer.concat([
    Buffer.from(x25519EphIHex, 'hex'),
    Buffer.from(x25519EphRHex, 'hex'),
    Buffer.from(mlkemEkISha256Hex, 'hex'),
    Buffer.from(mlkemCtSha256Hex, 'hex'),
  ]);
  const ikm = Buffer.concat([Buffer.from(ssXHex, 'hex'), Buffer.from(ssPqHex, 'hex'), kemContext]);
  const prkHs = createHmac('sha256', Buffer.from(thHsHex, 'hex')).update(ikm).digest();
  const kId = hkdfExpand32(prkHs, Buffer.from('pal3-hs-id-v2', 'ascii'), 32);
  const prk0 = createHmac('sha256', Buffer.from(thHex, 'hex')).update(prkHs).digest();

  const epochBuf = Buffer.alloc(2);
  epochBuf.writeUInt16BE(epoch, 0);
  const chBuf = Buffer.from([channelId & 0xff]);
  const dirBuf = Buffer.from(direction, 'ascii');
  const key = hkdfExpand32(prk0, Buffer.concat([Buffer.from('pal3-k-v1', 'ascii'), epochBuf, chBuf, dirBuf]), 32);
  const salt = hkdfExpand32(prk0, Buffer.concat([Buffer.from('pal3-s-v1', 'ascii'), epochBuf, chBuf, dirBuf]), 4);
  const exporterSecret = hkdfExpand32(prk0, Buffer.concat([Buffer.from('pal3-exp-v1', 'ascii'), epochBuf]), 32);

  return {
    kemContextHex: kemContext.toString('hex'),
    prkHsHex: prkHs.toString('hex'),
    kIdHex: kId.toString('hex'),
    prk0Hex: prk0.toString('hex'),
    keyHex: key.toString('hex'),
    saltHex: salt.toString('hex'),
    exporterSecretHex: exporterSecret.toString('hex'),
  };
}

/**
 * Hybrid identity digest per PAL/3.0 §4.4.
 */
export function computeIdentityDigest(ed25519PkHex, mldsa65PkHex) {
  return createHash('sha256')
    .update('pal3-identity-v1')
    .update(Buffer.from(ed25519PkHex, 'hex'))
    .update(Buffer.from(mldsa65PkHex, 'hex'))
    .digest('hex');
}

export const PAL3_RECORD_TYPES = Object.freeze({
  0x01: 'HANDSHAKE',
  0x02: 'CONTROL',
  0x10: 'DATA',
  0x11: 'ACK',
  0x12: 'PING',
  0x13: 'PONG',
  0x14: 'REKEY',
  0x15: 'CLOSE',
  0x20: 'MANIFEST',
  0x21: 'CHUNK',
  0x30: 'LIVE_MEDIA',
});

export const PAL3_SPEC_ERROR_CATALOG = Object.freeze({
  E_PAL3_MALFORMED_TLV: {
    code: 'E_PAL3_MALFORMED_TLV',
    level: 'ERROR',
    category: 'wire',
    retryable: false,
    message: 'Malformed PAL/3 TLV frame (non-ascending tag, duplicate tag, reserved 0x0000, or truncated value).',
    hint: 'Ensure TLV entries are sorted by strictly ascending u16be tag with accurate u32be length headers.',
  },
  E_PAL3_RECORD_TOO_SHORT: {
    code: 'E_PAL3_RECORD_TOO_SHORT',
    level: 'ERROR',
    category: 'wire',
    retryable: false,
    message: 'PAL/3 C2 record wire buffer is shorter than the minimum 36 bytes (20B header + 16B Poly1305 tag).',
    hint: 'Verify UDP MTU/fragmentation settings and confirm the sender transmits complete C2 frames.',
  },
  E_PAL3_SEQ_MISMATCH: {
    code: 'E_PAL3_SEQ_MISMATCH',
    level: 'WARN',
    category: 'transport',
    retryable: true,
    message: 'PAL/3 record channel sequence number does not match expected sequence.',
    hint: 'Check for UDP packet reordering, replay, or out-of-window delivery.',
  },
  E_PAL3_LENGTH_MISMATCH: {
    code: 'E_PAL3_LENGTH_MISMATCH',
    level: 'ERROR',
    category: 'wire',
    retryable: false,
    message: 'PAL/3 C2 record wire length does not equal 20 + payloadLength + 16.',
    hint: 'Inspect packet truncation along the UDP path or framing encoder bug.',
  },
  E_PAL3_AEAD_AUTH_FAILED: {
    code: 'E_PAL3_AEAD_AUTH_FAILED',
    level: 'SECURITY',
    category: 'crypto',
    retryable: false,
    message: 'ChaCha20-Poly1305 AEAD tag verification failed on PAL/3 record.',
    hint: 'Verify session key epoch, salt derivation, and 20-byte header AAD integrity.',
  },
  E_PAL3_HANDSHAKE_FAILED: {
    code: 'E_PAL3_HANDSHAKE_FAILED',
    level: 'SECURITY',
    category: 'handshake',
    retryable: true,
    message: 'Hybrid PQC handshake (X25519 + ML-KEM-768 / Ed25519 + ML-DSA-65) failed verification.',
    hint: 'Run `pal-spec doctor` or `pal doctor` to verify hybrid PQC primitives and peer identity pins.',
  },
});

/**
 * Safely dissect a 20-byte PAL/3 C2 record header and frame geometry without exposing plaintext or keys.
 */
export function dissectPal3RecordHeader(wireInput) {
  const wire = Buffer.isBuffer(wireInput) ? wireInput : Buffer.from(String(wireInput).replace(/^0x/i, ''), 'hex');
  if (wire.length < 20) {
    throw new Error('E_PAL3_RECORD_TOO_SHORT: need at least 20 bytes for C2 header');
  }
  const type = wire.readUInt8(0);
  const flags = wire.readUInt8(1);
  const keyEpoch = wire.readUInt16BE(2);
  const streamId = wire.readUInt32BE(4);
  const channelSeq = Number(wire.readBigUInt64BE(8));
  const payloadLength = wire.readUInt32BE(16);
  const expectedWireLength = 20 + payloadLength + 16;
  const tagPresent = wire.length >= expectedWireLength;

  return {
    format: 'PAL/3.0-C2',
    type,
    typeName: PAL3_RECORD_TYPES[type] || `UNKNOWN(0x${type.toString(16).padStart(2, '0')})`,
    flags,
    keyEpoch,
    streamId,
    channelSeq,
    payloadLength,
    wireLength: wire.length,
    expectedWireLength,
    validLength: wire.length === expectedWireLength,
    authTagHex: tagPresent ? wire.subarray(20 + payloadLength, expectedWireLength).toString('hex') : null,
  };
}

/**
 * Safely dissect a PAL/3 TLV buffer into tag metadata (redacting raw values to length + SHA-256 preview).
 */
export function dissectTlvBuffer(wireInput) {
  const buf = Buffer.isBuffer(wireInput) ? wireInput : Buffer.from(String(wireInput).replace(/^0x/i, ''), 'hex');
  const decoded = decodeTlv(buf);
  return {
    format: 'PAL/3.0-TLV',
    totalBytes: buf.length,
    entryCount: decoded.length,
    entries: decoded.map(({ tag, value }) => ({
      tag,
      tagHex: `0x${tag.toString(16).padStart(4, '0')}`,
      class: classifyTlvTag(tag),
      length: value.length,
      valueSha256Prefix: createHash('sha256').update(value).digest('hex').slice(0, 16),
    })),
  };
}

/**
 * Run PAL/3.0 specification & runtime crypto readiness doctor.
 */
export function runSpecDoctor() {
  const started = performance.now();
  const checks = [];

  try {
    const tlv = encodeTlv([{ tag: 0x0001, value: 'deadbeef' }]);
    const parsed = decodeTlv(tlv);
    checks.push({ name: 'tlv_codec', status: parsed.length === 1 ? 'ok' : 'error', detail: 'Deterministic ascending TLV codec' });
  } catch (err) {
    checks.push({ name: 'tlv_codec', status: 'error', detail: err.message });
  }

  try {
    const sealed = sealPal3Record({
      type: 0x10,
      flags: 0,
      keyEpoch: 1,
      streamId: 1,
      channelSeq: 1,
      keyHex: '00'.repeat(32),
      saltHex: '11223344',
      plaintextHex: '70616c33',
    });
    const opened = openPal3Record({
      wireHex: sealed.wireHex,
      keyHex: '00'.repeat(32),
      saltHex: '11223344',
      expectedChannelSeq: 1,
    });
    checks.push({
      name: 'c2_chacha20_poly1305',
      status: opened.toString('utf8') === 'pal3' ? 'ok' : 'error',
      detail: '20B C2 header AAD + ChaCha20-Poly1305 AEAD',
    });
  } catch (err) {
    checks.push({ name: 'c2_chacha20_poly1305', status: 'error', detail: err.message });
  }

  try {
    const val = runValidation();
    checks.push({
      name: 'normative_vectors',
      status: val.ok ? 'ok' : 'error',
      detail: `PAL/3.0 vectors v${val.version} verified`,
    });
  } catch (err) {
    checks.push({ name: 'normative_vectors', status: 'error', detail: err.message });
  }

  const healthy = checks.every((c) => c.status === 'ok');
  return {
    healthy,
    protocol: 'PAL/3.0',
    elapsedMs: Number((performance.now() - started).toFixed(2)),
    checks,
  };
}

/**
 * 20-byte record framing + ChaCha20-Poly1305 AEAD per PAL/3.0 §6.1.
 */
export function sealPal3Record({ type, flags, keyEpoch, streamId, channelSeq, keyHex, saltHex, plaintextHex }) {
  const plaintext = Buffer.from(plaintextHex, 'hex');
  const header = Buffer.alloc(20);
  header.writeUInt8(type, 0);
  header.writeUInt8(flags, 1);
  header.writeUInt16BE(keyEpoch, 2);
  header.writeUInt32BE(streamId, 4);
  header.writeBigUInt64BE(BigInt(channelSeq), 8);
  header.writeUInt32BE(plaintext.length, 16);

  const nonce = Buffer.alloc(12);
  Buffer.from(saltHex, 'hex').copy(nonce, 0, 0, 4);
  nonce.writeBigUInt64BE(BigInt(channelSeq), 4);

  const cipher = createCipheriv('chacha20-poly1305', Buffer.from(keyHex, 'hex'), nonce, {
    authTagLength: 16,
  });
  cipher.setAAD(header, { plaintextLength: plaintext.length });
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  const wire = Buffer.concat([header, ciphertext, tag]);

  return {
    headerHex: header.toString('hex'),
    nonceHex: nonce.toString('hex'),
    wireHex: wire.toString('hex'),
  };
}

export function openPal3Record({ wireHex, keyHex, saltHex, expectedChannelSeq }) {
  const wire = Buffer.from(wireHex, 'hex');
  if (wire.length < 36) {
    throw new Error('E_PAL3_RECORD_TOO_SHORT');
  }
  const header = wire.subarray(0, 20);
  const channelSeq = header.readBigUInt64BE(8);
  if (channelSeq !== BigInt(expectedChannelSeq)) {
    throw new Error('E_PAL3_SEQ_MISMATCH');
  }
  const payloadLength = header.readUInt32BE(16);
  if (wire.length !== 20 + payloadLength + 16) {
    throw new Error('E_PAL3_LENGTH_MISMATCH');
  }
  const ciphertext = wire.subarray(20, 20 + payloadLength);
  const tag = wire.subarray(20 + payloadLength);

  const nonce = Buffer.alloc(12);
  Buffer.from(saltHex, 'hex').copy(nonce, 0, 0, 4);
  nonce.writeBigUInt64BE(channelSeq, 4);

  const decipher = createDecipheriv('chacha20-poly1305', Buffer.from(keyHex, 'hex'), nonce, {
    authTagLength: 16,
  });
  decipher.setAAD(header, { plaintextLength: payloadLength });
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/**
 * Rotating LAN beacon tag per PAL/3.0 §4 R1 (secret beacon key, never the public identity key).
 */
export function computeLanRotatingTag(beaconKeyHex, unixSec) {
  const tagKey = hkdfExpand32(Buffer.from(beaconKeyHex, 'hex'), Buffer.from('pal3-lan-v2', 'ascii'), 32);
  const epochBucket = Buffer.alloc(8);
  epochBucket.writeBigUInt64BE(BigInt(Math.floor(unixSec / 900)), 0);
  return createHmac('sha256', tagKey).update(epochBucket).digest('hex');
}

export function runValidation() {
  const vectorsPath = join(__dirname, 'test-vectors', 'v3', 'pal3-v0.5-vectors.json');
  const vectors = JSON.parse(readFileSync(vectorsPath, 'utf8'));

  // 1. Validate TLV vector
  const encodedTlv = encodeTlv(vectors.tlv.entries);
  if (encodedTlv.toString('hex') !== vectors.tlv.expectedWireHex) {
    throw new Error(`TLV wire mismatch: got ${encodedTlv.toString('hex')}`);
  }
  const decodedTlv = decodeTlv(encodedTlv);
  if (decodedTlv.length !== vectors.tlv.entries.length) {
    throw new Error('TLV round-trip entry count mismatch');
  }

  // 2. Validate comprehension-bit classification
  for (const item of vectors.comprehensionBits) {
    const actual = classifyTlvTag(item.tag);
    if (actual !== item.expectedClass) {
      throw new Error(`Tag ${item.tag} classification mismatch: got ${actual}`);
    }
  }

  // 3. Validate hybrid KEM combiner & key schedule
  const derived = deriveSessionChannelMaterial(vectors.keySchedule.input);
  for (const [k, v] of Object.entries(vectors.keySchedule.expected)) {
    if (derived[k] !== v) throw new Error(`Key schedule derivation mismatch: ${k}`);
  }

  // 4. Validate 20-byte record framing & ChaCha20-Poly1305 AEAD
  const sealed = sealPal3Record(vectors.recordAead.input);
  if (sealed.wireHex !== vectors.recordAead.expected.wireHex ||
      sealed.nonceHex !== vectors.recordAead.expected.nonceHex) {
    throw new Error('Record AEAD wire mismatch');
  }
  const opened = openPal3Record({
    wireHex: sealed.wireHex,
    keyHex: vectors.recordAead.input.keyHex,
    saltHex: vectors.recordAead.input.saltHex,
    expectedChannelSeq: vectors.recordAead.input.channelSeq,
  });
  if (opened.toString('hex') !== vectors.recordAead.input.plaintextHex) {
    throw new Error('Record AEAD decrypt plaintext mismatch');
  }

  // 5. Validate R1 LAN rotating beacon tag
  const lanTag = computeLanRotatingTag(vectors.lanBeacon.beaconKeyHex, vectors.lanBeacon.unixSec);
  if (lanTag !== vectors.lanBeacon.expectedTagHex) {
    throw new Error(`LAN rotating tag mismatch: got ${lanTag}`);
  }

  // 6. Validate hybrid identity digest
  const digest = computeIdentityDigest(vectors.identityDigest.ed25519PkHex, vectors.identityDigest.mldsa65PkHex);
  if (digest !== vectors.identityDigest.expectedDigestHex) {
    throw new Error(`Identity digest mismatch: got ${digest}`);
  }

  return { ok: true, version: vectors.specVersion };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const res = runValidation();
  console.log(`PAL/3.0 conformance vectors (${res.version}) verified: PASS`);
}
