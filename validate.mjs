import { createHash, createHmac, createCipheriv, createDecipheriv, createPublicKey, generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { blake2b256 } from './blake2b.mjs';
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

/**
 * Minimal deterministic PAL-CBOR encoder per Appendix A.3 (int, bigint, bytes, string, array, map).
 * Independent of the reference implementation, used to check the §8.5 vectors.
 */
export function encodePalCbor(value) {
  const parts = [];
  const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
  const walk = (v) => {
    if (typeof v === 'bigint') { const b = Buffer.alloc(9); b[0] = 0x04; b.writeBigUInt64BE(v, 1); parts.push(b); return; }
    if (typeof v === 'number' && Number.isSafeInteger(v)) { const b = Buffer.alloc(9); b[0] = 0x03; b.writeBigInt64BE(BigInt(v), 1); parts.push(b); return; }
    if (Buffer.isBuffer(v)) { parts.push(Buffer.from([0x06]), u32(v.length), v); return; }
    if (typeof v === 'string') { const b = Buffer.from(v, 'utf8'); parts.push(Buffer.from([0x07]), u32(b.length), b); return; }
    if (Array.isArray(v)) { parts.push(Buffer.from([0x08]), u32(v.length)); v.forEach(walk); return; }
    if (v && typeof v === 'object') {
      const keys = Object.keys(v).sort();
      parts.push(Buffer.from([0x09]), u32(keys.length));
      for (const k of keys) { const kb = Buffer.from(k, 'utf8'); const l = Buffer.alloc(2); l.writeUInt16BE(kb.length); parts.push(l, kb); walk(v[k]); }
      return;
    }
    throw new Error(`E_PAL3_MALFORMED_BODY: unsupported value ${typeof v}`);
  };
  walk(value);
  return Buffer.concat(parts);
}

const REDISTRIBUTION_VALUES = ['none', 'pals', 'link-holders'];

// §8.5.2 access rule, written from the spec text.
function specAccessDecision({ redistribution, proofKind, proofValid, ticketRedistribution }) {
  const rule = REDISTRIBUTION_VALUES.includes(redistribution) ? redistribution : 'none';
  if (rule === 'none') return 'E_SWARM_NOT_REDISTRIBUTABLE';
  if (!proofKind) return 'E_SWARM_PROOF_REQUIRED';
  if (!proofValid) return 'E_SWARM_PROOF_INVALID';
  if (proofKind === 'pass') return 'allow';
  return rule === 'link-holders' && ticketRedistribution === 'link-holders' ? 'allow' : 'E_SWARM_PROOF_INVALID';
}

export function runSwarmValidation() {
  const v = JSON.parse(readFileSync(join(__dirname, 'test-vectors', 'v3', 'pal3-v0.6-swarm-vectors.json'), 'utf8'));
  const fail = (m) => { throw new Error(`§8.5 vectors: ${m}`); };
  for (const c of v.redistribution.normalize) {
    if ((REDISTRIBUTION_VALUES.includes(c.input) ? c.input : 'none') !== c.expected) fail(`normalize ${c.input}`);
  }
  const p = v.swarmPass.input;
  const body = encodePalCbor({ v: 1, shareId: Buffer.from(p.shareId, 'hex'), holderEdPk: Buffer.from(p.holderEdPk, 'hex'), holderDsaPk: Buffer.alloc(1952, 0x44), issuedAtMs: BigInt(p.issuedAtMs), expiresAtMs: BigInt(p.expiresAtMs) });
  if (body.toString('hex') !== v.swarmPass.bodyHex) fail('swarm pass body encoding');
  if (p.expiresAtMs - p.issuedAtMs > v.swarmPass.maxLifetimeMs) fail('swarm pass lifetime');
  for (const c of v.swarmPass.bindingCases) {
    const ok = c.pass.holderEdPk === c.session.edPk && c.pass.holderDsaPk === c.session.dsaPk;
    if (ok !== c.expectedValid) fail(`pass binding: ${c.name}`);
  }
  const msg = Buffer.concat([Buffer.from(v.swarmPass.domain, 'ascii'), createHash('sha256').update(body).digest()]);
  if (msg.toString('hex') !== v.swarmPass.signedMessageHex) fail('swarm pass signed message');
  if (!v.shareTicket.signedMessageHex.startsWith(Buffer.from('pal3-share-ticket-v1').toString('hex') + v.shareTicket.bodySha256Hex)) fail('ticket signed message');
  for (const d of v.accessDecisions) if (specAccessDecision(d.input) !== d.expected) fail(`access ${JSON.stringify(d.input)}`);
  for (const c of v.busy.clamp) {
    const n = Number(c.input);
    const want = c.input === null || !Number.isFinite(n) ? 60000 : Math.min(60000, Math.max(100, Math.ceil(n)));
    if (want !== c.expected) fail(`busy clamp ${c.input}`);
  }
  if (v.pieceResource.expected !== `swarm:${v.pieceResource.shareId}:${v.pieceResource.contentId}`) fail('piece resource');
  if (v.sources.maxEntries !== 16 || v.relayTree.maxFanout !== 4) fail('limits');
  const children = new Map();
  const relays = new Set(['root']);
  for (const s of v.relayTree.steps.filter(x => x.op === 'join')) {
    if (!relays.has(s.expected)) fail(`relay tree: ${s.args.pk} assigned to a non-relay`);
    children.set(s.expected, (children.get(s.expected) || 0) + 1);
    if (children.get(s.expected) > 4) fail('relay tree fan-out above 4');
    if (s.args.relay) relays.add(s.args.pk);
  }
  const lost = v.relayTree.steps.find(x => x.op === 'rejoin');
  if (lost && lost.expected === lost.args.lostParent) fail('rejoin kept the lost parent');
  if (v.capability !== 'swarm.v1') fail('capability token');
  for (const c of v.capabilityNegotiation) {
    const has = (x) => x.split(',').includes('swarm.v1');
    if ((has(c.local) && has(c.peer)) !== c.expected) fail('capability');
  }
  return { ok: true, version: v.specVersion, checks: v.accessDecisions.length };
}

// Zero-dependency hybrid signature check: Ed25519 and ML-DSA-65 (context = domain) over ASCII(domain) || SHA-256(body); both must verify.
const MLDSA65_SPKI_PREFIX = Buffer.from('308207b2300b0609608648016503040312038207a100', 'hex');
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

// ML-DSA-65 with a context string needs a recent Node (verified on 24.x); older runtimes check Ed25519 only and say so.
export function mldsaSupported() {
  try {
    const { publicKey, privateKey } = generateKeyPairSync('ml-dsa-65');
    const sig = cryptoSign(null, Buffer.from('probe'), { key: privateKey, context: Buffer.from('ctx') });
    return cryptoVerify(null, Buffer.from('probe'), { key: publicKey, context: Buffer.from('ctx') }, sig)
      && !cryptoVerify(null, Buffer.from('probe'), { key: publicKey, context: Buffer.from('other') }, sig);
  } catch {
    return false;
  }
}

export function verifyHybridObject(o, { mldsa = mldsaSupported() } = {}) {
  const body = Buffer.from(o.bodyHex, 'hex');
  const message = Buffer.concat([Buffer.from(o.domain, 'ascii'), createHash('sha256').update(body).digest()]);
  const edKey = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(o.signer.edPkHex, 'hex')]), format: 'der', type: 'spki' });
  const dsaKey = mldsa ? createPublicKey({ key: Buffer.concat([MLDSA65_SPKI_PREFIX, Buffer.from(o.signer.dsaPkHex, 'hex')]), format: 'der', type: 'spki' }) : null;
  const edOk = cryptoVerify(null, message, edKey, Buffer.from(o.sigEd25519Hex, 'hex'));
  const dsaOk = mldsa ? cryptoVerify(null, message, { key: dsaKey, context: Buffer.from(o.dsaContext, 'ascii') }, Buffer.from(o.sigMldsa65Hex, 'hex')) : true;
  return edOk && dsaOk;
}

export function runPrimitiveValidation() {
  const v = JSON.parse(readFileSync(join(__dirname, 'test-vectors', 'v3', 'pal3-v0.6-primitive-vectors.json'), 'utf8'));
  const fail = (m) => { throw new Error(`primitive vectors: ${m}`); };
  const hex = (b) => Buffer.from(b).toString('hex');
  const fromHex = (h) => Buffer.from(h, 'hex');

  // BLAKE2b-256 (RFC 7693) known answers.
  for (const c of v.blake2b256) if (hex(blake2b256(fromHex(c.inputHex))) !== c.outputHex) fail(`blake2b256 of ${c.inputHex.slice(0, 16)}...`);
  if (hex(blake2b256(Buffer.alloc(0))) !== '0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8') fail('blake2b256 empty input');

  // 8.1 Merkle tree: leaves, promotion of the unpaired rightmost node, root, content id and inclusion proofs.
  const BLOCK = 262144;
  const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
  const leafHash = (index, block) => { const len = Buffer.alloc(4); len.writeUInt32BE(block.length); return blake2b256(Buffer.concat([Buffer.from([0x00]), u64(index), len, block])); };
  const nodeHash = (level, l, r) => blake2b256(Buffer.concat([Buffer.from([0x01, level]), l, r]));
  const emptyRoot = blake2b256(Buffer.concat([Buffer.from([0x02]), u64(0)]));
  for (const c of v.merkle) {
    const data = Buffer.from(Array.from({ length: c.length }, (_, i) => (i * 7 + 3) % 251));
    const leaves = [];
    for (let off = 0; off < data.length; off += BLOCK) leaves.push(leafHash(leaves.length, data.subarray(off, Math.min(off + BLOCK, data.length))));
    if (leaves.map(hex).join() !== c.leavesHex.join()) fail(`merkle ${c.length}: leaves`);
    const levels = [leaves];
    let cur = leaves;
    for (let level = 1; cur.length > 1; level++) {
      const next = [];
      for (let i = 0; i < cur.length; i += 2) next.push(i + 1 < cur.length ? nodeHash(level, cur[i], cur[i + 1]) : cur[i]);
      levels.push(next);
      cur = next;
    }
    const root = leaves.length === 0 ? emptyRoot : cur[0];
    if (hex(root) !== c.rootHex) fail(`merkle ${c.length}: root`);
    if (`pal3:b2t:${hex(root)}:${c.length}` !== c.contentId) fail(`merkle ${c.length}: content id`);
    for (const p of c.proofs) {
      let node = leaves[p.blockIndex];
      let idx = p.blockIndex;
      let used = 0;
      for (let lvl = 0; lvl < levels.length - 1; lvl++) {
        const sib = idx % 2 === 0 ? idx + 1 : idx - 1;
        if (sib < levels[lvl].length) {
          const s = fromHex(p.siblingsHex[used++]);
          node = idx % 2 === 0 ? nodeHash(lvl + 1, node, s) : nodeHash(lvl + 1, s, node);
        }
        idx = Math.floor(idx / 2);
      }
      if (used !== p.siblingsHex.length || hex(node) !== c.rootHex) fail(`merkle ${c.length}: proof for block ${p.blockIndex}`);
    }
  }

  // 5.4 cookie and proof of work.
  const ck = v.cookie;
  const mac = createHmac('sha256', fromHex(ck.secretHex)).update(`pal3-cookie-v1:${ck.address}:${ck.port}:${ck.connId >>> 0}:${Math.floor(ck.nowMs / 60000)}:${ck.powBits}`).digest().subarray(0, 15);
  const cookie = Buffer.concat([mac, Buffer.from([ck.powBits])]);
  if (hex(cookie) !== ck.expectedCookieHex) fail('cookie');
  const leadingZeros = (d) => { let n = 0; for (const byte of d) { if (byte === 0) { n += 8; continue; } n += Math.clz32(byte) - 24; break; } return n; };
  const hdr = Buffer.alloc(8);
  hdr.writeUInt32BE(ck.connId >>> 0, 0);
  hdr.writeUInt32BE(ck.pow.nonce >>> 0, 4);
  if (leadingZeros(createHash('sha256').update(ck.pow.domain).update(cookie).update(hdr).digest()) < ck.pow.bits) fail('proof of work solution');
  hdr.writeUInt32BE((ck.pow.nonce + 1) >>> 0, 4);
  // A neighbouring nonce is not required to fail, but the declared difficulty must be below the cap of 22.
  if (ck.pow.bits > 22) fail('pow bits above the cap');

  // 5.5 resumption secret and binder (HKDF-Expand with a single block).
  const expand = (prk, info) => createHmac('sha256', prk).update(Buffer.concat([Buffer.from(info, 'ascii'), Buffer.from([1])])).digest();
  const rs = expand(fromHex(v.resumption.prkHex), 'pal3-res-v1');
  if (hex(rs) !== v.resumption.resumptionSecretHex) fail('resumption secret');
  const binder = createHmac('sha256', expand(rs, 'pal3-binder-v1')).update(createHash('sha256').update(fromHex(v.resumption.helloWithoutBinderHex)).digest()).digest();
  if (hex(binder) !== v.resumption.binderHex) fail('psk binder');

  // 8.2 manifest revision rules.
  const decide = (prev, next) => {
    if (!prev) return 'accept';
    const p = BigInt(prev.counter);
    const n = BigInt(next.counter);
    if (n < p) return 'rollback';
    if (n - p > 2n ** 32n) return 'jump';
    if (n === p) {
      if (prev.hashHex === next.hashHex) return 'accept';
      const cmp = Buffer.compare(fromHex(next.deviceIdHex), fromHex(prev.deviceIdHex));
      if (cmp === 0) return 'equivocation';
      return cmp < 0 ? 'rollback' : 'accept';
    }
    return 'accept';
  };
  for (const c of v.manifestRevision) if (decide(c.prev, c.next) !== c.expected) fail(`manifest revision: ${c.name}`);
  return { ok: true, blake: v.blake2b256.length, merkle: v.merkle.length, revisions: v.manifestRevision.length };
}

export function runCoreValidation() {
  const dir = join(__dirname, 'test-vectors', 'v3');
  const signed = JSON.parse(readFileSync(join(dir, 'pal3-v0.6-core-vectors.json'), 'utf8'));
  const ops = JSON.parse(readFileSync(join(dir, 'pal3-v0.6-core-operations.json'), 'utf8'));
  const fail = (m) => { throw new Error(`§7.1 / A.5 vectors: ${m}`); };
  for (const o of signed.objects) {
    if (!verifyHybridObject(o)) fail(`${o.name}: signature does not verify`);
    const flipped = { ...o, bodyHex: o.bodyHex.slice(0, -2) + (o.bodyHex.endsWith('00') ? '01' : '00') };
    if (verifyHybridObject(flipped)) fail(`${o.name}: a tampered body still verifies`);
    if (mldsaSupported() && verifyHybridObject({ ...o, dsaContext: `${o.dsaContext}x` })) fail(`${o.name}: a wrong ML-DSA context still verifies`);
    if (verifyHybridObject({ ...o, domain: `${o.domain}x` })) fail(`${o.name}: a wrong domain still verifies`);
  }
  const spec = readFileSync(join(__dirname, 'spec', 'v3', 'PAL-3.0.md'), 'utf8');
  const line = spec.split('\n').find((l) => l.startsWith('- **Core operations:**'));
  if (!line) fail('section 7 has no core operation list');
  const listed = [...line.matchAll(/`([a-z][a-zA-Z0-9.]*)`/g)].map((m) => m[1]);
  const specified = new Set(ops.operations.map((x) => x.name));
  const elsewhere = new Set(ops.servedByEmbeddingProduct);
  for (const name of listed) if (!specified.has(name) && !elsewhere.has(name)) fail(`core operation ${name} is neither specified in 7.1 nor listed as product-served`);
  for (const name of elsewhere) if (!listed.includes(name)) fail(`${name} is product-served but not in the section 7 list`);
  for (const x of ops.operations) {
    if (!spec.includes('`' + x.name + '`')) fail(`${x.name} is not mentioned in the spec text`);
    if (!x.request || !x.response || !Array.isArray(x.errors)) fail(`${x.name} lacks request, response or errors`);
  }
  return { ok: true, version: signed.specVersion, signed: signed.objects.length, operations: ops.operations.length, mldsaChecked: mldsaSupported() };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const res = runValidation();
  console.log(`PAL/3.0 conformance vectors (${res.version}) verified: PASS`);
  const sw = runSwarmValidation();
  const prim = runPrimitiveValidation();
  console.log(`PAL/3.0 primitives verified (BLAKE2b-256 ${prim.blake}, Merkle ${prim.merkle}, cookie and PoW, PSK binder, ${prim.revisions} manifest revision cases): PASS`);
  const core = runCoreValidation();
  console.log(`PAL/3.0 §7.1 operations (${core.operations}) and ${core.signed} hybrid-signed objects verified (${core.mldsaChecked ? 'Ed25519 and ML-DSA-65' : 'Ed25519 only: this Node cannot check ML-DSA-65 contexts, use Node 24+'}): PASS`);
  console.log(`PAL/3.0 §8.5 swarm vectors (${sw.version}, ${sw.checks} access cases) verified: PASS`);
}
