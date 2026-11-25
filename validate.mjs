import { createHash, createHmac, createCipheriv, createDecipheriv, createPrivateKey, createPublicKey, diffieHellman, encapsulate, decapsulate, hkdfSync, generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';
import { readFileSync } from 'node:fs';
const sha384Of = (data) => createHash('sha384').update(data).digest();
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
  return createHmac('sha384', prk).update(info).update(Buffer.from([1])).digest().subarray(0, length);
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
  mlkemEkIHashHex,
  mlkemCtHashHex,
  thHsHex,
  thHex,
  epoch,
  channelId,
  direction,
}) {
  const kemContext = Buffer.concat([
    Buffer.from(x25519EphIHex, 'hex'),
    Buffer.from(x25519EphRHex, 'hex'),
    Buffer.from(mlkemEkIHashHex, 'hex'),
    Buffer.from(mlkemCtHashHex, 'hex'),
  ]);
  const ikm = Buffer.concat([Buffer.from(ssXHex, 'hex'), Buffer.from(ssPqHex, 'hex'), kemContext]);
  const prkHs = createHmac('sha384', Buffer.from(thHsHex, 'hex')).update(ikm).digest();
  const kId = hkdfExpand32(prkHs, Buffer.from('pal3-hs-id-v2', 'ascii'), 32);
  const prk0 = createHmac('sha384', Buffer.from(thHex, 'hex')).update(prkHs).digest();

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
  return createHash('sha384')
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

  // 5. Validate hybrid identity digest
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
    if (v === null) { parts.push(Buffer.from([0x00])); return; }
    if (v === false || v === true) { parts.push(Buffer.from([v ? 0x02 : 0x01])); return; }
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
  const msg = Buffer.concat([Buffer.from(v.swarmPass.domain, 'ascii'), createHash('sha384').update(body).digest()]);
  if (msg.toString('hex') !== v.swarmPass.signedMessageHex) fail('swarm pass signed message');
  const t = v.shareTicket;
  const ticketBody = encodePalCbor({ v: 1, shareId: Buffer.from(t.input.shareId, 'hex'), ownerEdPk: Buffer.from(t.input.ownerEdPk, 'hex'), ownerDsaPk: Buffer.alloc(1952, 0x33), manifestRoot: Buffer.alloc(0), issuedAtMs: BigInt(t.input.issuedAtMs), expiresAtMs: BigInt(t.input.expiresAtMs), redistribution: t.input.redistribution });
  if (ticketBody.toString('hex') !== t.bodyHex) fail('ticket body encoding');
  if (createHash('sha384').update(ticketBody).digest('hex') !== t.bodySha384Hex) fail('ticket body digest');
  if (t.signedMessageHex !== Buffer.concat([Buffer.from(t.domain, 'ascii'), createHash('sha384').update(ticketBody).digest()]).toString('hex')) fail('ticket signed message');
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

// Zero-dependency hybrid signature check: Ed25519 and ML-DSA-65 (context = domain) over ASCII(domain) || SHA-384(body); both must verify.
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
  const message = Buffer.concat([Buffer.from(o.domain, 'ascii'), createHash('sha384').update(body).digest()]);
  const edKey = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(o.signer.edPkHex, 'hex')]), format: 'der', type: 'spki' });
  const dsaKey = mldsa ? createPublicKey({ key: Buffer.concat([MLDSA65_SPKI_PREFIX, Buffer.from(o.signer.dsaPkHex, 'hex')]), format: 'der', type: 'spki' }) : null;
  const edOk = cryptoVerify(null, message, edKey, Buffer.from(o.sigEd25519Hex, 'hex'));
  const dsaOk = mldsa ? cryptoVerify(null, message, { key: dsaKey, context: Buffer.from(o.dsaContext, 'ascii') }, Buffer.from(o.sigMldsa65Hex, 'hex')) : true;
  return edOk && dsaOk;
}

export function runIdentifierValidation() {
  const v = JSON.parse(readFileSync(join(__dirname, 'test-vectors', 'v3', 'pal3-v0.6-identifier-vectors.json'), 'utf8'));
  const fail = (m) => { throw new Error(`identifier vectors: ${m}`); };
  const hex = (b) => Buffer.from(b).toString('hex');
  const fill = (n, seed) => Buffer.from(Array.from({ length: n }, (_, i) => (i * 13 + seed) % 256));
  const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
  const tagged = (domain, ...parts) => sha384Of(Buffer.concat([Buffer.from(domain, 'ascii'), Buffer.alloc(1), ...parts]));
  for (const [kind, id] of [['peer', v.peer.idHex], ['file', v.file.idHex], ['share', v.share.idHex], ['group', v.group.idHex], ['network', v.network.idHex]]) {
    if (!/^[0-9a-f]{96}$/.test(id)) fail(`${kind}: identifier is not 96 lowercase hexadecimal characters`);
  }
  const identityKey = Buffer.concat([Buffer.from(v.peer.ed25519PkHex, 'hex'), fill(1952, 2)]);
  if (hex(tagged(v.peer.domain, identityKey)) !== v.peer.idHex) fail('peer id');
  const content = Buffer.from(Array.from({ length: 1000 }, (_, i) => (i * 7 + 3) % 251));
  if (hex(sha384Of(content)) !== v.file.idHex) fail('file id');
  const nonce = Buffer.from(v.group.nonceHex, 'hex');
  if (hex(tagged(v.group.domain, Buffer.from(v.group.creatorPeerIdHex, 'hex'), nonce, u64(v.group.createdAtMs))) !== v.group.idHex) fail('group id');
  if (hex(tagged(v.network.domain, Buffer.from(v.network.adminEd25519PkHex, 'hex'), Buffer.from(v.network.nonceHex, 'hex'), u64(v.network.createdAtMs))) !== v.network.idHex) fail('network id');
  if (v.group.idHex === v.network.idHex) fail('domain separation: group and network ids must differ');
  return { ok: true, kinds: 5 };
}

export function runPrimitiveValidation() {
  const v = JSON.parse(readFileSync(join(__dirname, 'test-vectors', 'v3', 'pal3-v0.6-primitive-vectors.json'), 'utf8'));
  const fail = (m) => { throw new Error(`primitive vectors: ${m}`); };
  const hex = (b) => Buffer.from(b).toString('hex');
  const fromHex = (h) => Buffer.from(h, 'hex');

  // SHA-384 (FIPS 180-4) known answers.
  for (const c of v.sha384) if (hex(sha384Of(fromHex(c.inputHex))) !== c.outputHex) fail(`sha384 of ${c.inputHex.slice(0, 16)}...`);
  if (hex(sha384Of(Buffer.alloc(0))) !== '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b') fail('sha384 empty input');

  // 8.1 Merkle tree: leaves, promotion of the unpaired rightmost node, root, content id and inclusion proofs.
  const BLOCK = 262144;
  const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
  const leafHash = (index, block) => { const len = Buffer.alloc(4); len.writeUInt32BE(block.length); return sha384Of(Buffer.concat([Buffer.from([0x00]), u64(index), len, block])); };
  const nodeHash = (level, l, r) => sha384Of(Buffer.concat([Buffer.from([0x01, level]), l, r]));
  const emptyRoot = sha384Of(Buffer.concat([Buffer.from([0x02]), u64(0)]));
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
    if (`pal3:s3t:${hex(root)}:${c.length}` !== c.contentId) fail(`merkle ${c.length}: content id`);
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
  const mac = createHmac('sha384', fromHex(ck.secretHex)).update(`pal3-cookie-v1:${ck.address}:${ck.port}:${ck.connId >>> 0}:${Math.floor(ck.nowMs / 60000)}:${ck.powBits}`).digest().subarray(0, 15);
  const cookie = Buffer.concat([mac, Buffer.from([ck.powBits])]);
  if (hex(cookie) !== ck.expectedCookieHex) fail('cookie');
  const leadingZeros = (d) => { let n = 0; for (const byte of d) { if (byte === 0) { n += 8; continue; } n += Math.clz32(byte) - 24; break; } return n; };
  const hdr = Buffer.alloc(8);
  hdr.writeUInt32BE(ck.connId >>> 0, 0);
  hdr.writeUInt32BE(ck.pow.nonce >>> 0, 4);
  if (leadingZeros(createHash('sha384').update(ck.pow.domain).update(cookie).update(hdr).digest()) < ck.pow.bits) fail('proof of work solution');
  hdr.writeUInt32BE((ck.pow.nonce + 1) >>> 0, 4);
  // A neighbouring nonce is not required to fail, but the declared difficulty must be below the cap of 22.
  if (ck.pow.bits > 22) fail('pow bits above the cap');

  // 5.5 resumption secret and binder (HKDF-Expand with a single block).
  const expand = (prk, info) => createHmac('sha384', prk).update(Buffer.concat([Buffer.from(info, 'ascii'), Buffer.from([1])])).digest().subarray(0, 32);
  const rs = expand(fromHex(v.resumption.prkHex), 'pal3-res-v1');
  if (hex(rs) !== v.resumption.resumptionSecretHex) fail('resumption secret');
  const binder = createHmac('sha384', expand(rs, 'pal3-binder-v1')).update(createHash('sha384').update(fromHex(v.resumption.helloWithoutBinderHex)).digest()).digest();
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
  return { ok: true, sha384: v.sha384.length, merkle: v.merkle.length, revisions: v.manifestRevision.length };
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

// ML-KEM-768 (FIPS 203) is a Node built-in from 24.7. Where it is missing the validator checks lengths only and says "structure-only".
const MLKEM768_SEED_PKCS8_PREFIX = Buffer.from('3054020100300b060960864801650304040204428040', 'hex');
const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

export function mlkemSupported() {
  try {
    if (typeof encapsulate !== 'function' || typeof decapsulate !== 'function') return false;
    const key = createPrivateKey({ key: Buffer.concat([MLKEM768_SEED_PKCS8_PREFIX, Buffer.alloc(64, 7)]), format: 'der', type: 'pkcs8' });
    const { ciphertext, sharedKey } = encapsulate(createPublicKey(key));
    return decapsulate(key, ciphertext).equals(sharedKey);
  } catch {
    return false;
  }
}

const hexOf = (b) => Buffer.from(b).toString('hex');
const unhex = (h) => Buffer.from(h, 'hex');
const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const ascii = (s) => Buffer.from(s, 'ascii');
const vectorFile = (name) => JSON.parse(readFileSync(join(__dirname, 'test-vectors', 'v3', name), 'utf8'));
const x25519Private = (sk) => createPrivateKey({ key: Buffer.concat([X25519_PKCS8_PREFIX, sk]), format: 'der', type: 'pkcs8' });
const x25519PublicRaw = (sk) => createPublicKey(x25519Private(sk)).export({ format: 'der', type: 'spki' }).subarray(-32);

// 5.3 epoch rule, written from the specification text: the u16 epoch ends at 65535.
function specRekeyEpochDecision({ currentEpoch, action, initEpoch }) {
  if (action === 'send') return currentEpoch >= 0xffff ? 'E_PAL3_EPOCH_EXHAUSTED' : 'accepted';
  return initEpoch > 0xffff ? 'E_PAL3_EPOCH_EXHAUSTED' : 'accepted';
}

export function runRekeyValidation({ mlkem = mlkemSupported() } = {}) {
  const v = vectorFile('pal3-v0.6-rekey-vectors.json');
  const fail = (m) => { throw new Error(`rekey vectors (5.3): ${m}`); };
  if (v.rekeyDerivation.length < 3) fail('fewer than 3 positive cases');
  if (v.epochLimits.length + v.peerRekeyRate.length < 2) fail('fewer than 2 negative cases');
  let reachedMax = false;
  v.rekeyDerivation.forEach((c, index) => {
    const at = `case ${index}`;
    if (c.newEpoch !== c.epoch + 1 || c.newEpoch > 0xffff) fail(`${at}: epoch ${c.epoch} -> ${c.newEpoch}`);
    if (c.newEpoch === 0xffff) reachedMax = true;
    if (index > 0 && c.epoch === v.rekeyDerivation[index - 1].newEpoch && c.prevExporterSecretHex !== v.rekeyDerivation[index - 1].exporterSecretNextHex) fail(`${at}: not chained from the previous exporter secret`);
    const skI = unhex(c.x25519EphISecretHex);
    const skR = unhex(c.x25519EphRSecretHex);
    if (hexOf(x25519PublicRaw(skI)) !== c.x25519EphIPublicHex || hexOf(x25519PublicRaw(skR)) !== c.x25519EphRPublicHex) fail(`${at}: X25519 public key`);
    const pubOf = (raw) => createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
    const ssX = diffieHellman({ privateKey: x25519Private(skR), publicKey: pubOf(unhex(c.x25519EphIPublicHex)) });
    if (hexOf(ssX) !== c.x25519SharedSecretHex || !ssX.equals(diffieHellman({ privateKey: x25519Private(skI), publicKey: pubOf(unhex(c.x25519EphRPublicHex)) }))) fail(`${at}: X25519 shared secret`);
    const ek = unhex(c.mlkem.encapsulationKeyHex);
    const ct = unhex(c.mlkem.ciphertextHex);
    const ssPq = unhex(c.mlkem.sharedSecretHex);
    if (ek.length !== 1184 || ct.length !== 1088 || ssPq.length !== 32) fail(`${at}: ML-KEM-768 lengths`);
    if (mlkem) {
      const dk = createPrivateKey({ key: Buffer.concat([MLKEM768_SEED_PKCS8_PREFIX, unhex(c.mlkem.seedHex)]), format: 'der', type: 'pkcs8' });
      if (!createPublicKey(dk).export({ format: 'der', type: 'spki' }).subarray(-1184).equals(ek)) fail(`${at}: ML-KEM encapsulation key does not come from the seed`);
      if (!decapsulate(dk, ct).equals(ssPq)) fail(`${at}: ML-KEM shared secret`);
    }
    const kemContext = Buffer.concat([unhex(c.x25519EphIPublicHex), unhex(c.x25519EphRPublicHex), sha384Of(ek), sha384Of(ct)]);
    if (kemContext.length !== 160 || hexOf(kemContext) !== c.kemContextHex) fail(`${at}: kem_context`);
    const ikm = Buffer.concat([ssX, ssPq, kemContext]);
    if (ikm.length !== 224 || hexOf(ikm) !== c.ikmHex) fail(`${at}: ikm`);
    const prk = createHmac('sha384', unhex(c.prevExporterSecretHex)).update(ikm).digest();
    if (hexOf(prk) !== c.prkNextHex) fail(`${at}: prk_{e+1}`);
    if (hexOf(hkdfExpand32(prk, Buffer.concat([ascii('pal3-exp-v1'), u16(c.newEpoch)]), 32)) !== c.exporterSecretNextHex) fail(`${at}: exporter_secret_{e+1}`);
    if (c.recordKeys.length !== 8) fail(`${at}: record key count`);
    for (const k of c.recordKeys) {
      const info = (label) => Buffer.concat([ascii(label), u16(c.newEpoch), Buffer.from([k.channelId]), ascii(k.dir)]);
      if (hexOf(hkdfExpand32(prk, info('pal3-k-v1'), 32)) !== k.keyHex || hexOf(hkdfExpand32(prk, info('pal3-s-v1'), 4)) !== k.saltHex) fail(`${at}: record key of channel ${k.channelId} ${k.dir}`);
    }
    for (const k of c.c2PacketKeys) {
      const info = (label) => Buffer.concat([ascii(label), u16(c.newEpoch), ascii(k.dir)]);
      if (hexOf(hkdfExpand32(prk, info('pal3-c2-k-v1'), 32)) !== k.keyHex || hexOf(hkdfExpand32(prk, info('pal3-c2-iv-v1'), 12)) !== k.ivHex) fail(`${at}: C2 packet key ${k.dir}`);
    }
    const r = c.sealedRecord;
    const ch0 = c.recordKeys.find((k) => k.channelId === 0 && k.dir === 'i2r');
    const sealed = sealPal3Record({ type: r.type, flags: 0, keyEpoch: c.newEpoch, streamId: r.streamId, channelSeq: r.channelSeq, keyHex: ch0.keyHex, saltHex: ch0.saltHex, plaintextHex: r.plaintextHex });
    if (sealed.wireHex !== r.wireHex) fail(`${at}: record sealed under the new epoch`);
  });
  if (!reachedMax) fail('no case reaches epoch 65535');
  for (const c of v.epochLimits) {
    if (specRekeyEpochDecision(c) !== c.expectedError || c.sessionClosed !== true) fail(`epoch limit: ${c.description}`);
  }
  // 5.3: a responder accepts at most 16 peer-initiated rekeys in any 60-second window; the 17th closes the session.
  for (const c of v.peerRekeyRate) {
    if (c.windowMs !== 60000 || c.maxPerWindow !== 16) fail('peer rate constants');
    const accepted = [];
    c.steps.forEach((s, i) => {
      const inWindow = accepted.filter((t) => s.atMs - t < c.windowMs).length;
      const want = inWindow >= c.maxPerWindow ? 'E_PAL3_REKEY_RATE' : 'accepted';
      if (want === 'accepted') accepted.push(s.atMs);
      if (want !== s.result) fail(`peer rate step ${i}: ${c.description}`);
    });
    if (c.sessionClosed !== c.steps.some((s) => s.result === 'E_PAL3_REKEY_RATE')) fail(`peer rate session state: ${c.description}`);
  }
  return { ok: true, version: v.specVersion, positive: v.rekeyDerivation.length, negative: v.epochLimits.length + v.peerRekeyRate.length, validated: mlkem ? 'full' : 'structure-only' };
}

// C2 packet protection per 3.2 and A.4, written from the specification text with Node built-ins only.
const c2Expand = (prk, label, epoch, dir, length) => hkdfExpand32(prk, Buffer.concat([ascii(label), u16(epoch), ascii(dir)]), length);
function c2Keys({ prk0, prkEpoch, epoch, dir }) {
  const prk = epoch === 0 ? prk0 : prkEpoch;
  return {
    key: c2Expand(prk, 'pal3-c2-k-v1', epoch, dir, 32),
    iv: c2Expand(prk, 'pal3-c2-iv-v1', epoch, dir, 12),
    hp: c2Expand(prk0, 'pal3-c2-hp-v1', 0, dir, 32),
  };
}
function c2Nonce(iv, pn) {
  const nonce = Buffer.from(iv);
  nonce.writeUInt32BE((iv.readUInt32BE(4) ^ Math.floor(pn / 0x100000000)) >>> 0, 4);
  nonce.writeUInt32BE((iv.readUInt32BE(8) ^ (pn >>> 0)) >>> 0, 8);
  return nonce;
}
// ChaCha20 with counter = u32le(sample[0..4]) and nonce = sample[4..16] is OpenSSL's 16-byte IV, which is the sample itself.
const c2Mask = (hp, sample) => createCipheriv('chacha20', hp, sample.subarray(0, 16)).update(Buffer.alloc(4));
function c2ReconstructPn(largest, truncated) {
  const expected = largest + 1;
  const win = 0x100000000;
  const candidate = expected - (expected % win) + truncated;
  if (candidate <= expected - win / 2 && candidate + win < 2 ** 62) return candidate + win;
  if (candidate > expected + win / 2 && candidate >= win) return candidate - win;
  return candidate;
}
function c2Protect({ type, cid, packetNumber, plaintext, keys }) {
  const aad = Buffer.concat([Buffer.from([type]), cid, Buffer.alloc(4)]);
  aad.writeUInt32BE(packetNumber >>> 0, aad.length - 4);
  const cipher = createCipheriv('chacha20-poly1305', keys.key, c2Nonce(keys.iv, packetNumber), { authTagLength: 16 });
  cipher.setAAD(aad, { plaintextLength: plaintext.length });
  const body = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  const sample = body.subarray(0, 16);
  const mask = c2Mask(keys.hp, sample);
  const header = Buffer.from(aad);
  for (let i = 0; i < 4; i++) header[header.length - 4 + i] ^= mask[i];
  return { aad, sample, mask, packet: Buffer.concat([header, body]) };
}
// Returns the plaintext, or null when the datagram is dropped. Types 0x03 and 0x05 need c2-key-update (3.2).
function c2Open({ packet, keys, largest, keyUpdateNegotiated }) {
  const type = packet[0];
  if (![0x02, 0x03, 0x04, 0x05].includes(type)) return null;
  if ((type === 0x03 || type === 0x05) && !keyUpdateNegotiated) return null;
  const hdr = type <= 0x03 ? 9 : 13;
  if (packet.length < hdr + 16) return null;
  const mask = c2Mask(keys.hp, packet.subarray(hdr, hdr + 16));
  const aad = Buffer.from(packet.subarray(0, hdr));
  for (let i = 0; i < 4; i++) aad[hdr - 4 + i] ^= mask[i];
  const pn = c2ReconstructPn(largest, aad.readUInt32BE(hdr - 4));
  try {
    const decipher = createDecipheriv('chacha20-poly1305', keys.key, c2Nonce(keys.iv, pn), { authTagLength: 16 });
    decipher.setAAD(aad, { plaintextLength: packet.length - hdr - 16 });
    decipher.setAuthTag(packet.subarray(packet.length - 16));
    return Buffer.concat([decipher.update(packet.subarray(hdr, packet.length - 16)), decipher.final()]);
  } catch {
    return null;
  }
}

export function runHeaderProtectionValidation() {
  const v = vectorFile('pal3-v0.6-header-protection-vectors.json');
  const fail = (m) => { throw new Error(`header protection vectors (3.2): ${m}`); };
  if (v.protectedPackets.length < 3 || v.rejectedPackets.length < 2) fail('fewer than 3 positive or 2 negative cases');
  let zeroLength = false;
  const keysOf = (c, dir) => c2Keys({ prk0: unhex(c.prk0Hex), prkEpoch: c.prkEpochHex ? unhex(c.prkEpochHex) : null, epoch: c.epoch, dir });
  v.protectedPackets.forEach((c, index) => {
    const at = `case ${index}`;
    const keys = keysOf(c, c.direction);
    if (hexOf(keys.key) !== c.keyHex || hexOf(keys.iv) !== c.ivHex || hexOf(keys.hp) !== c.hpKeyHex) fail(`${at}: packet or header protection key`);
    const cid = c.dcidHex ? unhex(c.dcidHex) : unhex(c.connIdHex);
    const type = (c.dcidHex ? 0x04 : 0x02) + (c.epoch % 2);
    const plaintext = unhex(c.plaintextHex);
    if (plaintext.length === 0) zeroLength = true;
    const p = c2Protect({ type, cid, packetNumber: c.packetNumber, plaintext, keys });
    if (hexOf(p.aad) !== c.unprotectedHeaderHex) fail(`${at}: unprotected header`);
    if (hexOf(p.sample) !== c.sampleHex || hexOf(p.mask) !== c.maskHex) fail(`${at}: sample or mask`);
    if (hexOf(p.packet) !== c.packetHex) fail(`${at}: protected packet`);
    const opened = c2Open({ packet: unhex(c.packetHex), keys, largest: c.largestReceivedPn, keyUpdateNegotiated: c.epoch > 0 });
    if (!opened || !opened.equals(plaintext)) fail(`${at}: the packet does not open to the plaintext`);
  });
  if (!zeroLength) fail('no zero-length payload case');
  v.rejectedPackets.forEach((c, index) => {
    const at = `negative ${index}`;
    const src = v.protectedPackets[c.sourceCase];
    if (c.expected !== 'dropped silently' || c.errorCode !== null) fail(`${at}: expected outcome`);
    const keys = keysOf(src, c.receiveDirection);
    if (c2Open({ packet: unhex(c.packetHex), keys, largest: src.largestReceivedPn, keyUpdateNegotiated: c.keyUpdateNegotiated })) fail(`${at}: ${c.description} was accepted`);
  });
  return { ok: true, version: v.specVersion, positive: v.protectedPackets.length, negative: v.rejectedPackets.length };
}

// 10 item 5, Quick Drop SAS.
export function runSasValidation() {
  const v = vectorFile('pal3-v0.6-sas-vectors.json');
  const fail = (m) => { throw new Error(`SAS vectors (10.5): ${m}`); };
  if (v.quickDropSas.length < 3 || v.quickDropSasRejected.length < 2) fail('fewer than 3 positive or 2 negative cases');
  const lp = (b) => { const n = Buffer.alloc(4); n.writeUInt32BE(b.length); return Buffer.concat([n, b]); };
  const commitmentOf = (nonce) => createHash('sha384').update('pal3-sas-commit-v1').update(nonce).digest();
  const compute = (c) => {
    const exporter = unhex(c.exporterSecretHex);
    const commitment = unhex(c.commitmentHex);
    const nonceS = unhex(c.nonceSHex);
    const nonceR = unhex(c.nonceRHex);
    if (exporter.length !== 32 || commitment.length !== 48 || nonceS.length !== 32 || nonceR.length !== 32) return 'E_PAL3_SAS_INVALID';
    if (!commitmentOf(nonceS).equals(commitment)) return 'E_PAL3_SAS_COMMITMENT_MISMATCH';
    const info = Buffer.concat([lp(unhex(c.senderPkHex)), lp(unhex(c.receiverPkHex)), lp(unhex(c.rootHex)), lp(unhex(c.offerIdHex)), nonceS, nonceR]);
    const okm = Buffer.from(hkdfSync('sha384', exporter, ascii('pal3-sas-v1'), info, 8));
    const prk = createHmac('sha384', ascii('pal3-sas-v1')).update(exporter).digest();
    if (!createHmac('sha384', prk).update(info).update(Buffer.from([1])).digest().subarray(0, 8).equals(okm)) fail('HKDF cross-check');
    return (okm.readBigUInt64BE(0) % 10n ** 8n).toString().padStart(8, '0');
  };
  v.quickDropSas.forEach((c, index) => {
    const got = compute(c);
    if (got !== c.expectedSas || !/^\d{8}$/.test(got)) fail(`case ${index}: got ${got}`);
    if (c.mustDifferFromCase !== undefined && got === v.quickDropSas[c.mustDifferFromCase].expectedSas) fail(`case ${index} equals case ${c.mustDifferFromCase}`);
  });
  const base = v.quickDropSas[0];
  if (!v.quickDropSas.some((c) => c.senderPkHex === base.receiverPkHex && c.receiverPkHex === base.senderPkHex)) fail('no swapped-roles case');
  if (!v.quickDropSas.some((c) => c.expectedSas.startsWith('0'))) fail('no leading-zero case');
  v.quickDropSasRejected.forEach((c, index) => {
    if (compute(c) !== c.expectedError) fail(`negative ${index}: ${c.description}`);
  });
  // 5.2, Handshake SAS: HKDF-SHA-384(exporter_secret_0, salt "pal3-handshake-sas-v1", info "sas", 16 bytes).
  if (v.wordlist.length !== 64 || new Set(v.wordlist).size !== 64 || !v.wordlist.every((w) => /^[a-z]+$/.test(w))) fail('the word list must hold 64 distinct lowercase words');
  if (v.handshakeSas.length < 3 || v.handshakeSasRejected.length < 2) fail('handshake SAS: fewer than 3 positive or 2 negative cases');
  const handshakeSas = (exporter) => {
    if (exporter.length !== 32) return 'E_PAL3_HANDSHAKE_INVALID';
    const okm = Buffer.from(hkdfSync('sha384', exporter, ascii('pal3-handshake-sas-v1'), ascii('sas'), 16));
    const prk = createHmac('sha384', ascii('pal3-handshake-sas-v1')).update(exporter).digest();
    if (!createHmac('sha384', prk).update(ascii('sas')).update(Buffer.from([1])).digest().subarray(0, 16).equals(okm)) fail('handshake SAS HKDF cross-check');
    const words = [0, 1, 2, 3].map((i) => v.wordlist[okm[8 + i] & 0x3f]);
    return { digits: (okm.readBigUInt64BE(0) % 10n ** 8n).toString().padStart(8, '0'), words, phrase: words.join('-') };
  };
  v.handshakeSas.forEach((c, index) => {
    const got = handshakeSas(unhex(c.exporterSecretHex));
    if (got.digits !== c.expectedDigits || !/^\d{8}$/.test(got.digits) || got.phrase !== c.expectedPhrase || got.words.join() !== c.expectedWords.join()) fail(`handshake SAS case ${index}: got ${got.digits} ${got.phrase}`);
  });
  if (!v.handshakeSas.some((c) => c.expectedDigits.startsWith('0'))) fail('handshake SAS: no leading-zero case');
  if (new Set(v.handshakeSas.map((c) => c.expectedPhrase)).size !== v.handshakeSas.length) fail('handshake SAS: two cases share a phrase');
  v.handshakeSasRejected.forEach((c, index) => {
    if (handshakeSas(unhex(c.exporterSecretHex)) !== c.expectedError) fail(`handshake SAS negative ${index}: ${c.description}`);
  });
  return { ok: true, version: v.specVersion, positive: v.quickDropSas.length, negative: v.quickDropSasRejected.length, handshake: v.handshakeSas.length };
}

// Decoder for the value codec of A.3 (types 0x00 to 0x09 except float). Rejects trailing bytes.
export function decodePalCbor(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input);
  let off = 0;
  const need = (n) => { if (off + n > buf.length) throw new Error('E_PAL3_MALFORMED_BODY: truncated value'); };
  const walk = (depth) => {
    if (depth > 16) throw new Error('E_PAL3_MALFORMED_BODY: nesting too deep');
    need(1);
    const t = buf[off++];
    switch (t) {
      case 0x00: return null;
      case 0x01: return false;
      case 0x02: return true;
      case 0x03: { need(8); const v = Number(buf.readBigInt64BE(off)); off += 8; return v; }
      case 0x04: { need(8); const v = buf.readBigUInt64BE(off); off += 8; return v; }
      case 0x06: { need(4); const n = buf.readUInt32BE(off); off += 4; need(n); const v = buf.subarray(off, off + n); off += n; return Buffer.from(v); }
      case 0x07: { need(4); const n = buf.readUInt32BE(off); off += 4; need(n); const v = buf.subarray(off, off + n).toString('utf8'); off += n; return v; }
      case 0x08: { need(4); const n = buf.readUInt32BE(off); off += 4; const a = []; for (let i = 0; i < n; i++) a.push(walk(depth + 1)); return a; }
      case 0x09: {
        need(4); const n = buf.readUInt32BE(off); off += 4;
        const m = {}; let prev = null;
        for (let i = 0; i < n; i++) {
          need(2); const kl = buf.readUInt16BE(off); off += 2; need(kl);
          const k = buf.subarray(off, off + kl).toString('utf8'); off += kl;
          if (prev !== null && !(prev < k)) throw new Error('E_PAL3_MALFORMED_BODY: map keys are not strictly ascending');
          prev = k; m[k] = walk(depth + 1);
        }
        return m;
      }
      default: throw new Error(`E_PAL3_MALFORMED_BODY: unsupported type 0x${t.toString(16)}`);
    }
  };
  const v = walk(0);
  if (off !== buf.length) throw new Error('E_PAL3_MALFORMED_BODY: trailing bytes');
  return v;
}

// 9, A.5 items 3 and 4: signed grants.
export function runGrantValidation() {
  const v = vectorFile('pal3-v0.6-grant-vectors.json');
  const fail = (m) => { throw new Error(`grant vectors (9): ${m}`); };
  if (v.objects.length < 3 || v.rejected.length < 2) fail('fewer than 3 positive or 2 negative cases');
  const checkBody = (o) => {
    const body = decodePalCbor(unhex(o.bodyHex));
    if (body.v !== 1 || body.requirePq !== true) return 'E_PAL3_GRANT_INVALID';
    if (body.watermark) return 'E_PAL3_GRANT_UNSUPPORTED_CONSTRAINT';
    if (!Buffer.isBuffer(body.issuerEdPk) || body.issuerEdPk.length !== 32 || !Buffer.isBuffer(body.issuerDsaPk) || body.issuerDsaPk.length !== 1952) return 'E_PAL3_GRANT_INVALID';
    if (hexOf(body.issuerEdPk) !== o.signer.edPkHex || hexOf(body.issuerDsaPk) !== o.signer.dsaPkHex) return 'E_PAL3_GRANT_ISSUER_MISMATCH';
    return body;
  };
  const decide = (o) => {
    if (o.domain !== 'pal3-grant-v1' || o.dsaContext !== 'pal3-grant-v1') fail(`${o.name}: domain and ML-DSA context must be pal3-grant-v1`);
    const body = checkBody(o);
    if (typeof body === 'string') return body;
    let ok = false;
    try { ok = verifyHybridObject(o); } catch { ok = false; }
    if (!ok) return 'E_PAL3_GRANT_AUTH_FAILED';
    if (o.nowMs !== undefined && body.expiresAtMs > 0n && BigInt(o.nowMs) >= body.expiresAtMs) return 'E_PAL3_ACCESS_EXPIRED';
    return 'accepted';
  };
  for (const o of v.objects) {
    const got = decide(o);
    if (got !== 'accepted') fail(`${o.name}: ${got}`);
    if (mldsaSupported() && verifyHybridObject({ ...o, dsaContext: `${o.dsaContext}x` })) fail(`${o.name}: a wrong ML-DSA context still verifies`);
    const body = decodePalCbor(unhex(o.bodyHex));
    if (hexOf(encodePalCbor(body)) !== o.bodyHex) fail(`${o.name}: the body is not in the canonical A.3 form`);
    if (!Array.isArray(body.operations) || [...body.operations].sort().join() !== body.operations.join()) fail(`${o.name}: operations must be sorted`);
    for (const key of ['v', 'grantId', 'issuerEdPk', 'issuerDsaPk', 'subjectType', 'subjectId', 'resource', 'operations', 'issuedAtMs', 'notBeforeMs', 'expiresAtMs', 'maxReads', 'maxBytes', 'bandwidthBps', 'devicesMax', 'requirePq', 'watermark']) {
      if (!(key in body)) fail(`${o.name}: missing field ${key}`);
    }
  }
  if (!v.objects.some((o) => 'futureField' in decodePalCbor(unhex(o.bodyHex)))) fail('no unknown-key case');
  const names = new Set(v.rejected.map((c) => c.expectedError));
  for (const needed of ['E_PAL3_GRANT_AUTH_FAILED', 'E_PAL3_ACCESS_EXPIRED', 'E_PAL3_GRANT_UNSUPPORTED_CONSTRAINT']) if (!names.has(needed)) fail(`no negative case for ${needed}`);
  for (const c of v.rejected) {
    const got = decide(c);
    if (got !== c.expectedError) fail(`${c.name}: expected ${c.expectedError}, got ${got}`);
  }
  return { ok: true, version: v.specVersion, positive: v.objects.length, negative: v.rejected.length, mldsaChecked: mldsaSupported() };
}

// 12.2, A.5 item 7: hybrid-signed extension bundles and publisher certificates.
export function runExtensionSigningValidation() {
  const v = vectorFile('pal3-v0.6-extension-signing-vectors.json');
  const fail = (m) => { throw new Error(`extension signing vectors (12.2): ${m}`); };
  if (v.bundles.length < 3 || v.rejected.length < 2) fail('fewer than 3 positive or 2 negative cases');
  const BUNDLE = { domain: 'pal3-ext-bundle-v1', dsaContext: 'pal3-ext-sig-v1' };
  const CERT = { domain: 'pal3-ext-publisher-cert-v1', dsaContext: 'pal3-ext-cert-v1' };
  const roots = v.trustedRoots;
  const sigOk = (o) => { try { return verifyHybridObject(o); } catch { return false; } };
  const decide = (o) => {
    if (o.domain !== BUNDLE.domain && o.name !== 'bundleSignedUnderTheCertificateLabel') fail(`${o.name}: wrong labels for a bundle`);
    const body = decodePalCbor(unhex(o.bodyHex));
    if (body.v !== 3 || !Buffer.isBuffer(body.signerEdPk) || body.signerEdPk.length !== 32 || !Buffer.isBuffer(body.signerDsaPk) || body.signerDsaPk.length !== 1952) return 'E_PAL3_EXT_BUNDLE_INVALID';
    const asBundle = { ...o, ...BUNDLE };
    if (hexOf(body.signerEdPk) !== o.signer.edPkHex || hexOf(body.signerDsaPk) !== o.signer.dsaPkHex) return 'E_PAL3_EXT_AUTH_FAILED';
    if (!sigOk(asBundle)) return 'E_PAL3_EXT_AUTH_FAILED';
    if (roots.some((r) => r.edPkHex === o.signer.edPkHex && r.dsaPkHex === o.signer.dsaPkHex)) return 'accepted';
    if (!body.publisherCert) return 'E_PAL3_EXT_UNTRUSTED_SIGNER';
    const env = decodePalCbor(body.publisherCert);
    const cert = decodePalCbor(env.body);
    const issuer = { edPkHex: hexOf(cert.issuerEdPk), dsaPkHex: hexOf(cert.issuerDsaPk) };
    const certObject = { ...CERT, signer: issuer, bodyHex: hexOf(env.body), sigEd25519Hex: hexOf(env.sigEd25519), sigMldsa65Hex: hexOf(env.sigMldsa65) };
    if (!roots.some((r) => r.edPkHex === issuer.edPkHex && r.dsaPkHex === issuer.dsaPkHex) || !sigOk(certObject)) return 'E_PAL3_EXT_CERT_INVALID';
    if (cert.expiresAtMs <= BigInt(v.verifierNowMs) || cert.issuedAtMs > BigInt(v.verifierNowMs)) return 'E_PAL3_EXT_CERT_INVALID';
    if (hexOf(cert.publisherEdPk) !== o.signer.edPkHex || hexOf(cert.publisherDsaPk) !== o.signer.dsaPkHex) return 'E_PAL3_EXT_CERT_MISMATCH';
    return 'accepted';
  };
  for (const o of v.bundles) {
    if (o.domain !== BUNDLE.domain || o.dsaContext !== BUNDLE.dsaContext) fail(`${o.name}: wrong labels for a bundle`);
    const got = decide(o);
    if (got !== 'accepted') fail(`${o.name}: ${got}`);
    if (mldsaSupported() && verifyHybridObject({ ...o, dsaContext: CERT.dsaContext })) fail(`${o.name}: verifies under the certificate ML-DSA context`);
    if (verifyHybridObject({ ...o, domain: CERT.domain })) fail(`${o.name}: verifies under the certificate message prefix`);
    if (hexOf(encodePalCbor(decodePalCbor(unhex(o.bodyHex)))) !== o.bodyHex) fail(`${o.name}: the body is not in the canonical A.3 form`);
  }
  for (const c of v.publisherCertificates) {
    if (c.domain !== CERT.domain || c.dsaContext !== CERT.dsaContext) fail(`${c.name}: wrong labels for a certificate`);
    if (!sigOk(c)) fail(`${c.name}: the signature does not verify`);
    const body = decodePalCbor(unhex(c.bodyHex));
    if (hexOf(body.issuerEdPk) !== c.signer.edPkHex) fail(`${c.name}: issuer key differs from the signer`);
    const delegated = v.bundles.find((b) => decodePalCbor(unhex(b.bodyHex)).publisherCert);
    if (!delegated || hexOf(body.publisherEdPk) !== delegated.signer.edPkHex) fail(`${c.name}: the subject is not the signer of the delegated bundle`);
  }
  for (const c of v.rejected) {
    const got = decide(c);
    if (got !== c.expectedError) fail(`${c.name}: expected ${c.expectedError}, got ${got}`);
  }
  if (!v.rejected.some((c) => c.name === 'strippedMldsaSignature' && c.sigMldsa65Hex === '')) fail('no stripped ML-DSA case');
  return { ok: true, version: v.specVersion, positive: v.bundles.length, negative: v.rejected.length, mldsaChecked: mldsaSupported() };
}

// 5.1, SEALED_HELLO: key and nonce derivation, AEAD, TLV layout and the rejection rules.
export function runSealedHelloValidation({ mlkem = mlkemSupported() } = {}) {
  const v = vectorFile('pal3-v0.6-sealed-hello-vectors.json');
  const fail = (m) => { throw new Error(`SEALED_HELLO vectors (5.1): ${m}`); };
  if (v.sealedHello.length < 3 || v.sealedHelloRejected.length < 4) fail('fewer than 3 positive or 4 negative cases');
  const x25519Pub = (sk) => createPublicKey(createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), sk]), format: 'der', type: 'pkcs8' })).export({ format: 'der', type: 'spki' }).subarray(-32);
  const dhOf = (sk, pk) => diffieHellman({
    privateKey: createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), sk]), format: 'der', type: 'pkcs8' }),
    publicKey: createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, pk]), format: 'der', type: 'spki' }),
  });
  const kemKey = (seedHex) => createPrivateKey({ key: Buffer.concat([MLKEM768_SEED_PKCS8_PREFIX, unhex(seedHex)]), format: 'der', type: 'pkcs8' });
  const checkRecipient = (r, at) => {
    if (hexOf(x25519Pub(unhex(r.x25519SecretKeyHex))) !== r.x25519PublicKeyHex) fail(`${at}: recipient X25519 public key`);
    if (unhex(r.mlkemEncapsulationKeyHex).length !== 1184) fail(`${at}: recipient ML-KEM key length`);
    if (mlkem && !createPublicKey(kemKey(r.mlkemSeedHex)).export({ format: 'der', type: 'spki' }).subarray(-1184).equals(unhex(r.mlkemEncapsulationKeyHex))) fail(`${at}: recipient ML-KEM key does not come from the seed`);
  };
  const parseRecord = (recordHex, at) => {
    const rec = unhex(recordHex);
    if (rec.length < 20 || rec[0] !== 0x04 || rec[1] !== 0 || rec.readUInt16BE(2) !== 0 || rec.readUInt32BE(4) !== 0 || rec.readBigUInt64BE(8) !== 0n) fail(`${at}: record header`);
    if (rec.readUInt32BE(16) !== rec.length - 20) fail(`${at}: record payload length`);
    const fields = new Map(decodeTlv(rec.subarray(20)).map((e) => [e.tag, e.value]));
    return { rec, fields };
  };
  const open = (record, recipient, heldPrekeyIdHex, at) => {
    let parsed;
    try { parsed = parseRecord(record, at); } catch { return { error: 'E_PAL3_HANDSHAKE_INVALID' }; }
    const f = parsed.fields;
    const eph = f.get(0x0001);
    const ct = f.get(0x0002);
    const body = f.get(0x0003);
    if (eph?.length !== 32 || ct?.length !== 1088 || !body || body.length < 16) return { error: 'E_PAL3_HANDSHAKE_INVALID' };
    if (f.has(0x0004) && (f.get(0x0004).length !== 8 || f.get(0x0004).toString('hex') !== heldPrekeyIdHex)) return { error: 'E_PAL3_HANDSHAKE_INVALID' };
    const ssX = dhOf(unhex(recipient.x25519SecretKeyHex), eph);
    const ssPq = decapsulate(kemKey(recipient.mlkemSeedHex), ct);
    const kemContext = Buffer.concat([eph, unhex(recipient.x25519PublicKeyHex), sha384Of(unhex(recipient.mlkemEncapsulationKeyHex)), sha384Of(ct)]);
    const ikm = Buffer.concat([ssX, ssPq, kemContext]);
    const okm = Buffer.from(hkdfSync('sha384', ikm, Buffer.alloc(0), ascii('pal3-sealed-hello-v1'), 44));
    const prk = createHmac('sha384', Buffer.alloc(48)).update(ikm).digest();
    const t1 = createHmac('sha384', prk).update(ascii('pal3-sealed-hello-v1')).update(Buffer.from([1])).digest();
    const t2 = createHmac('sha384', prk).update(t1).update(ascii('pal3-sealed-hello-v1')).update(Buffer.from([2])).digest();
    if (!Buffer.concat([t1, t2]).subarray(0, 44).equals(okm)) fail(`${at}: HKDF cross-check`);
    const decipher = createDecipheriv('chacha20-poly1305', okm.subarray(0, 32), okm.subarray(32, 44), { authTagLength: 16 });
    decipher.setAAD(Buffer.concat([eph, sha384Of(ct)]));
    decipher.setAuthTag(body.subarray(body.length - 16));
    try {
      return { plaintext: Buffer.concat([decipher.update(body.subarray(0, body.length - 16)), decipher.final()]), okm, kemContext, ikm, ssX, ssPq };
    } catch {
      return { error: 'E_PAL3_HANDSHAKE_AUTH_FAILED' };
    }
  };
  v.sealedHello.forEach((c, index) => {
    const at = `case ${index}`;
    checkRecipient(c.recipient, at);
    const eph = x25519Pub(unhex(c.ephemeralX25519SecretKeyHex));
    if (hexOf(eph) !== c.ephemeralX25519PublicKeyHex) fail(`${at}: ephemeral public key`);
    if (hexOf(dhOf(unhex(c.ephemeralX25519SecretKeyHex), unhex(c.recipient.x25519PublicKeyHex))) !== c.x25519SharedSecretHex) fail(`${at}: X25519 shared secret`);
    const { fields, rec } = parseRecord(c.recordHex, at);
    if (hexOf(rec.subarray(20)) !== c.payloadHex) fail(`${at}: payload`);
    if (hexOf(fields.get(0x0001)) !== c.ephemeralX25519PublicKeyHex || hexOf(fields.get(0x0002)) !== c.mlkemCiphertextHex || hexOf(fields.get(0x0003)) !== c.ciphertextHex) fail(`${at}: TLV fields`);
    if ((c.prekeyIdHex ? hexOf(fields.get(0x0004) || '') : null) !== c.prekeyIdHex || fields.has(0x0004) !== Boolean(c.prekeyIdHex)) fail(`${at}: prekey_id tag`);
    if (fields.get(0x0001).length !== 32 || fields.get(0x0002).length !== 1088) fail(`${at}: field lengths`);
    if (mlkem) {
      const got = open(c.recordHex, c.recipient, c.prekeyIdHex, at);
      if (!got.plaintext || hexOf(got.plaintext) !== c.plaintextHex) fail(`${at}: the record does not open to the plaintext (${got.error})`);
      if (hexOf(got.kemContext) !== c.kemContextHex || hexOf(got.ikm) !== c.ikmHex) fail(`${at}: kem_context or ikm`);
      if (hexOf(got.okm.subarray(0, 32)) !== c.keyHex || hexOf(got.okm.subarray(32)) !== c.nonceHex) fail(`${at}: key or nonce`);
      if (hexOf(got.ssPq) !== c.mlkemSharedSecretHex) fail(`${at}: ML-KEM shared secret`);
    }
    if (c.kemContextHex.length !== 2 * (32 + 32 + 48 + 48)) fail(`${at}: kem_context length`);
    if (c.aadHex !== c.ephemeralX25519PublicKeyHex + hexOf(sha384Of(unhex(c.mlkemCiphertextHex)))) fail(`${at}: aad`);
    if (unhex(c.ciphertextHex).length !== unhex(c.plaintextHex).length + 16) fail(`${at}: ciphertext length`);
  });
  if (!v.sealedHello.some((c) => c.prekeyIdHex) || !v.sealedHello.some((c) => !c.prekeyIdHex)) fail('both the static-key and the prekey form are required');
  v.sealedHelloRejected.forEach((c, index) => {
    const at = `negative ${index}`;
    checkRecipient(c.openedWith, at);
    if (!mlkem) return;
    const got = open(c.recordHex, c.openedWith, c.heldPrekeyIdHex, at);
    if (got.error !== c.expectedError) fail(`${at}: ${c.description}: got ${got.error || 'accepted'}`);
  });
  return { ok: true, version: v.specVersion, positive: v.sealedHello.length, negative: v.sealedHelloRejected.length, validated: mlkem ? 'full' : 'structure-only' };
}

// 12.5 rule 3, stored state: a device certificate signed before SHA-384 became the only hash must fail the current rules,
// and the migrated certificate must keep the device id and device keys and verify under the current rules.
export function runStoredStateValidation(v = vectorFile('pal3-stored-state-migration-vectors.json')) {
  const fail = (m) => { throw new Error(`stored-state vectors (12.5): ${m}`); };
  const hexOf = (b) => Buffer.from(b).toString('hex');
  const parse = (certHex, at) => {
    const fields = new Map(decodeTlv(Buffer.from(certHex, 'hex')).map(({ tag, value }) => [tag, value]));
    for (const tag of [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]) if (!fields.has(tag)) fail(`${at}: certificate has no tag 0x${tag.toString(16).padStart(4, '0')}`);
    if (fields.get(1)[0] !== 0) fail(`${at}: expected a delegated certificate (flags 0x00)`);
    const body = encodeTlv([...fields].filter(([tag]) => tag < 9).map(([tag, value]) => ({ tag, value })));
    return {
      fields,
      body,
      signer: { edPkHex: hexOf(fields.get(2)), dsaPkHex: hexOf(fields.get(3)) },
      sigEd25519Hex: hexOf(fields.get(9)),
      sigMldsa65Hex: hexOf(fields.get(10)),
    };
  };
  const verifies = (cert, hashName) => {
    const message = Buffer.concat([Buffer.from('pal3-devcert-v1', 'ascii'), createHash(hashName).update(cert.body).digest()]);
    const edKey = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(cert.signer.edPkHex, 'hex')]), format: 'der', type: 'spki' });
    if (!cryptoVerify(null, message, edKey, Buffer.from(cert.sigEd25519Hex, 'hex'))) return false;
    if (!mldsaSupported()) return true;
    const dsaKey = createPublicKey({ key: Buffer.concat([MLDSA65_SPKI_PREFIX, Buffer.from(cert.signer.dsaPkHex, 'hex')]), format: 'der', type: 'spki' });
    return cryptoVerify(null, message, { key: dsaKey, context: Buffer.from('pal3-devcert-v1', 'ascii') }, Buffer.from(cert.sigMldsa65Hex, 'hex'));
  };
  if (!Array.isArray(v.cases) || !v.cases.some((c) => c.case === 'device-cert-pre-sha384')) fail('no device-cert-pre-sha384 case');
  for (const c of v.cases) {
    const after = c.expectedAfterMigration;
    const old = parse(c.oldFormHex, `${c.case} old form`);
    if (verifies(old, 'sha384')) fail(`${c.case}: the old form verifies under the current rules (SHA-384)`);
    if (!verifies(old, 'sha256')) fail(`${c.case}: the old form does not verify under the pre-SHA-384 rules, so it is not an old stored form`);
    if (hexOf(old.fields.get(4)) !== c.deviceId) fail(`${c.case}: old form device id differs from deviceId`);
    if (hexOf(old.fields.get(5)) !== c.devicePublicKeys.device_ed25519_pk || hexOf(old.fields.get(6)) !== c.devicePublicKeys.device_mldsa65_pk) fail(`${c.case}: old form device keys differ from devicePublicKeys`);
    const migrated = parse(after.migratedFormHex, `${c.case} migrated form`);
    const verifiesNow = verifies(migrated, 'sha384');
    if (verifiesNow !== after.certVerifiesUnderCurrentRules || !verifiesNow) fail(`${c.case}: the migrated form must verify under the current rules`);
    if ((after.migratedFormHex !== c.oldFormHex) !== after.certChanged || !after.certChanged) fail(`${c.case}: the migrated form must differ from the old form`);
    if (after.deviceId !== c.deviceId || hexOf(migrated.fields.get(4)) !== after.deviceId) fail(`${c.case}: the device id changed in migration`);
    const keys = after.devicePublicKeys;
    if (JSON.stringify(keys) !== JSON.stringify(c.devicePublicKeys)
      || hexOf(migrated.fields.get(5)) !== keys.device_ed25519_pk || hexOf(migrated.fields.get(6)) !== keys.device_mldsa65_pk) fail(`${c.case}: the device keys changed in migration`);
    if (hexOf(migrated.fields.get(2)) !== old.signer.edPkHex || hexOf(migrated.fields.get(3)) !== old.signer.dsaPkHex) fail(`${c.case}: the identity keys changed in migration`);
  }
  return { ok: true, version: v.specVersion, cases: v.cases.length, mldsaChecked: mldsaSupported() };
}

// 8.1.1: chunk-group verification. The vector holds hashes and a content pattern; everything is recomputed here from node:crypto.
const patternBytes = (p, total) => Buffer.from(Array.from({ length: total }, (_, i) => (p.multiplier * i + p.offset) % 251));
const sha384Parts = (...parts) => { const h = createHash('sha384'); for (const p of parts) h.update(p); return h.digest(); };
const u64be = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
const u32be = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
function promotedRoot(leaves, domain) {
  let level = leaves;
  let depth = 1;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(i + 1 < level.length ? sha384Parts(Buffer.from([domain, depth]), level[i], level[i + 1]) : level[i]);
    level = next;
    depth++;
  }
  return level[0];
}
function promotedProof(width, index) {
  const steps = [];
  let idx = index;
  let w = width;
  while (w > 1) {
    if (idx % 2 === 1 || idx + 1 < w) steps.push(idx % 2 === 1);
    idx = Math.floor(idx / 2);
    w = Math.ceil(w / 2);
  }
  return steps;
}
export function runChunkOutboardValidation(v = vectorFile('pal3-v0.6-chunk-outboard-vectors.json')) {
  const fail = (m) => { throw new Error(`chunk outboard vectors (8.1.1): ${m}`); };
  const CHUNK = v.chunkBytes;
  const BLOCK = v.blockBytes;
  if (CHUNK !== 16384 || BLOCK !== 262144) fail('chunk and block sizes');
  const chunkLeaf = (globalIndex, chunk) => sha384Parts(Buffer.from([0x10]), u64be(globalIndex), u32be(chunk.length), chunk);
  const layout = (total) => Array.from({ length: Math.ceil(total / BLOCK) }, (_, b) => {
    const blockLen = Math.min(BLOCK, total - b * BLOCK);
    return { blockLen, chunks: Math.ceil(blockLen / CHUNK) };
  });
  const emptyRoot = sha384Parts(Buffer.from([0x12, 0x00]), u64be(0));
  if (v.emptyFile.chunkRootHex !== hexOf(emptyRoot) || v.emptyFile.expectedHex !== hexOf(emptyRoot) || v.emptyFile.blockCount !== 0) fail('the empty-file chunkRoot is not SHA-384(0x12 || 0x00 || u64be(0))');
  for (const c of v.contents) {
    const data = patternBytes(v.contentPattern, c.totalBytes);
    const blocks = layout(c.totalBytes);
    if (c.blockCount !== blocks.length || c.blocks.length !== blocks.length) fail(`${c.totalBytes}: block count`);
    const leaves = blocks.map((b, bi) => Array.from({ length: b.chunks }, (_, ci) => {
      const at = bi * BLOCK + ci * CHUNK;
      return chunkLeaf(bi * 16 + ci, data.subarray(at, Math.min(at + CHUNK, c.totalBytes)));
    }));
    const blockRoots = leaves.map((l) => promotedRoot(l, 0x11));
    const root = promotedRoot(blockRoots, 0x12);
    if (hexOf(root) !== c.chunkRootHex) fail(`${c.totalBytes}: chunkRoot`);
    c.blocks.forEach((ob, bi) => {
      const proofLen = promotedProof(blocks.length, bi).length;
      if (ob.chunkCount !== blocks[bi].chunks || ob.proofLength !== proofLen) fail(`${c.totalBytes} block ${bi}: counts`);
      const outboard = unhex(ob.outboardHex);
      if (outboard.length !== (ob.chunkCount + proofLen) * 48) fail(`${c.totalBytes} block ${bi}: outboard length`);
      if (!Buffer.concat(leaves[bi]).equals(outboard.subarray(0, ob.chunkCount * 48))) fail(`${c.totalBytes} block ${bi}: chunk-leaf hashes`);
    });
  }
  const verifyOutboard = (c, blockIndex, outboard) => {
    const blocks = layout(c.totalBytes);
    const proofLen = promotedProof(blocks.length, blockIndex).length;
    const count = blocks[blockIndex].chunks;
    if (outboard.length !== (count + proofLen) * 48) return { error: 'E_PAL3_CHUNK_OUTBOARD_INVALID' };
    const hashes = Array.from({ length: count }, (_, i) => outboard.subarray(i * 48, (i + 1) * 48));
    const siblings = Array.from({ length: proofLen }, (_, i) => outboard.subarray((count + i) * 48, (count + i + 1) * 48));
    let cur = promotedRoot(hashes, 0x11);
    let idx = blockIndex;
    let w = blocks.length;
    let depth = 1;
    let used = 0;
    while (w > 1) {
      const right = idx % 2 === 1;
      if (right || idx + 1 < w) {
        const sib = siblings[used++];
        cur = right ? sha384Parts(Buffer.from([0x12, depth]), sib, cur) : sha384Parts(Buffer.from([0x12, depth]), cur, sib);
      }
      idx = Math.floor(idx / 2);
      w = Math.ceil(w / 2);
      depth++;
    }
    if (hexOf(cur) !== c.chunkRootHex) return { error: 'E_PAL3_CHUNK_OUTBOARD_INVALID' };
    return { hashes };
  };
  if (v.rejected.length < 6) fail('fewer than 6 rejections');
  for (const r of v.rejected) {
    const c = v.contents.find((x) => x.totalBytes === r.totalBytes);
    let got = 'accepted';
    if (r.stage === 'outboard') {
      got = verifyOutboard(c, r.blockIndex, unhex(r.outboardHex)).error || 'accepted';
    } else {
      const checked = verifyOutboard(c, r.blockIndex, unhex(c.blocks[r.blockIndex].outboardHex));
      if (checked.error) fail(`${r.name}: the honest outboard must authenticate`);
      const chunk = unhex(r.chunkHex);
      const blockLen = layout(c.totalBytes)[r.blockIndex].blockLen;
      const expectedLen = Math.min(CHUNK, blockLen - r.chunkIndex * CHUNK);
      const ok = chunk.length === expectedLen && chunkLeaf(r.blockIndex * 16 + r.chunkIndex, chunk).equals(checked.hashes[r.chunkIndex]);
      got = ok ? 'accepted' : 'E_PAL3_CORRUPT_CHUNK';
    }
    if (got !== r.expectedError) fail(`${r.name}: expected ${r.expectedError}, got ${got}`);
  }
  for (const needed of ['E_PAL3_CHUNK_OUTBOARD_INVALID', 'E_PAL3_CORRUPT_CHUNK']) if (!v.rejected.some((r) => r.expectedError === needed)) fail(`no rejection for ${needed}`);
  return { ok: true, version: v.specVersion, contents: v.contents.length, negative: v.rejected.length };
}

// 8.3: private encrypted shares (encrypt-then-Merkle). Recomputed from node:crypto only.
export function runPrivateShareValidation(v = vectorFile('pal3-v0.6-private-share-vectors.json')) {
  const fail = (m) => { throw new Error(`private share vectors (8.3): ${m}`); };
  const BLOCK = 262144;
  if (v.plainBlockBytes !== BLOCK - 16) fail('PRIVATE_PLAIN_BLOCK_BYTES is BLOCK_BYTES - 16');
  const fileKey = (shareKey, fileId) => {
    if (shareKey.length !== 32 || fileId.length !== 16) return null;
    return Buffer.from(hkdfSync('sha384', shareKey, fileId, ascii('pal3-file-key-v1'), 32));
  };
  const nonceAad = (fileId, index) => {
    const idx = Buffer.alloc(8); idx.writeBigUInt64BE(BigInt(index));
    return { nonce: Buffer.concat([ascii('pal3'), idx]), aad: Buffer.concat([fileId, idx]) };
  };
  const seal = (key, fileId, index, plain) => {
    const { nonce, aad } = nonceAad(fileId, index);
    const c = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
    c.setAAD(aad);
    return Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);
  };
  const open = (key, fileId, index, ct) => {
    if (ct.length < 16 || ct.length > BLOCK) return null;
    const { nonce, aad } = nonceAad(fileId, index);
    const d = createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
    d.setAAD(aad);
    d.setAuthTag(ct.subarray(ct.length - 16));
    try { return Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]); } catch { return null; }
  };
  const plain = (n, offset = 0) => Buffer.from(Array.from({ length: n }, (_, i) => (v.plaintextPattern.multiplier * (i + offset) + v.plaintextPattern.offset) % 251));
  const shareKey = unhex(v.shareKeyHex);
  const keys = new Map();
  for (const k of v.fileKeys) {
    const got = fileKey(shareKey, unhex(k.fileIdHex));
    if (!got || hexOf(got) !== k.fileKeyHex) fail(`file key of ${k.fileIdHex}`);
    keys.set(k.fileIdHex, got);
  }
  if (new Set(v.fileKeys.map((k) => k.fileKeyHex)).size !== v.fileKeys.length) fail('two file_ids gave one file key');
  const keyA = keys.get(v.file.fileIdHex);
  const fileIdA = unhex(v.file.fileIdHex);
  v.blocks.forEach((b) => {
    const ct = seal(keyA, fileIdA, b.blockIndex, plain(b.plaintextLength));
    if (ct.length !== b.ciphertextLength || b.ciphertextLength !== b.plaintextLength + 16) fail(`block ${b.blockIndex}: length`);
    if (hexOf(sha384Of(ct)) !== b.ciphertextSha384Hex) fail(`block ${b.blockIndex}: ciphertext`);
    if (b.ciphertextHex && b.ciphertextHex !== hexOf(ct)) fail(`block ${b.blockIndex}: ciphertext bytes`);
    if (!open(keyA, fileIdA, b.blockIndex, ct)?.equals(plain(b.plaintextLength))) fail(`block ${b.blockIndex}: does not open`);
  });
  const parts = [];
  for (let i = 0, off = 0; off < v.file.plaintextLength; i++, off += v.plainBlockBytes) parts.push(seal(keyA, fileIdA, i, plain(Math.min(v.plainBlockBytes, v.file.plaintextLength - off), off)));
  if (parts.map((p) => hexOf(sha384Of(p))).join() !== v.file.blockCiphertextSha384Hex.join()) fail('file block ciphertexts');
  const cipher = Buffer.concat(parts);
  if (cipher.length !== v.file.ciphertextLength || parts.slice(0, -1).some((p) => p.length !== BLOCK)) fail('every full ciphertext block must be exactly one Merkle block');
  const leaves = [];
  for (let off = 0; off < cipher.length; off += BLOCK) {
    const block = cipher.subarray(off, Math.min(off + BLOCK, cipher.length));
    const len = Buffer.alloc(4); len.writeUInt32BE(block.length);
    const idx = Buffer.alloc(8); idx.writeBigUInt64BE(BigInt(leaves.length));
    leaves.push(sha384Of(Buffer.concat([Buffer.from([0x00]), idx, len, block])));
  }
  let level = leaves;
  let depth = 1;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(i + 1 < level.length ? sha384Of(Buffer.concat([Buffer.from([0x01, depth]), level[i], level[i + 1]])) : level[i]);
    level = next;
    depth++;
  }
  const root = level[0];
  if (`pal3:s3t:${hexOf(root)}:${cipher.length}` !== v.file.contentId) fail('the Merkle content id over the ciphertext');
  const seen = new Map();
  for (const r of v.rejected) {
    let got = 'accepted';
    const fileId = unhex(r.fileIdHex);
    if (r.op === 'decrypt') {
      const key = fileKey(shareKey, fileId);
      got = open(key, fileId, r.blockIndex, unhex(r.ciphertextHex)) ? 'accepted' : 'E_PAL3_CRYPTO';
    } else if (r.op === 'encrypt') {
      got = r.plaintextLength > v.plainBlockBytes ? 'E_PAL3_CRYPTO' : 'accepted';
    } else if (r.op === 'deriveKey') {
      got = fileKey(r.shareKeyLength ? shareKey.subarray(0, r.shareKeyLength) : shareKey, fileId) ? 'accepted' : 'E_PAL3_CRYPTO';
    } else if (r.op === 'registry') {
      seen.set(r.fileIdHex, r.firstRootHex);
      got = seen.get(r.fileIdHex) !== r.secondRootHex ? 'E_PAL3_FILE_ID_REUSED' : 'accepted';
    } else fail(`${r.name}: unknown op`);
    if (got !== r.expectedError) fail(`${r.name}: expected ${r.expectedError}, got ${got}`);
  }
  if (v.rejected.length < 6) fail('fewer than 6 rejections');
  return { ok: true, version: v.specVersion, blocks: v.blocks.length, negative: v.rejected.length };
}

// 11.3 and A.1: device certificates and revocation statements, checked from the bytes with node:crypto only.
export function runDeviceRevocationValidation(v = vectorFile('pal3-v0.6-device-revocation-vectors.json')) {
  const fail = (m) => { throw new Error(`device revocation vectors (11.3): ${m}`); };
  const MAX = 65536;
  const tlvMap = (bytes) => {
    if (bytes.length > MAX) throw new Error('E_PAL3_MALFORMED_TLV');
    return new Map(decodeTlv(bytes).map(({ tag, value }) => [tag, value]));
  };
  const sigObject = (fields, domain, signer, upTo) => ({
    domain,
    dsaContext: domain,
    signer,
    bodyHex: hexOf(encodeTlv([...fields].filter(([tag]) => tag !== 9 && tag !== 10 && tag <= upTo).map(([tag, value]) => ({ tag, value })))),
    sigEd25519Hex: hexOf(fields.get(9) || Buffer.alloc(0)),
    sigMldsa65Hex: hexOf(fields.get(10) || Buffer.alloc(0)),
  });
  const u64 = (b) => b.readBigUInt64BE(0);
  const checkCert = (certHex, nowMs) => {
    let fields;
    try { fields = tlvMap(unhex(certHex)); } catch { return { error: 'E_PAL3_MALFORMED_TLV' }; }
    for (const tag of fields.keys()) {
      if (tag >= 1 && tag <= 10) continue;
      if (tag < 0x8000) return { error: 'E_PAL3_UNKNOWN_CORE_TAG' };
      if ((tag & 0xc000) === 0x8000) return { error: 'E_PAL3_UNSUPPORTED_CRITICAL_EXTENSION' };
    }
    const flags = fields.get(1)?.[0];
    if (fields.get(1)?.length !== 1 || (flags !== 0 && flags !== 1)) return { error: 'E_PAL3_CERT_INVALID' };
    const lens = [[2, 32], [3, 1952], [4, 16], [9, 64], [10, 3309], [7, 8], [8, 8]];
    for (const [tag, len] of lens) if (fields.get(tag)?.length !== len) return { error: 'E_PAL3_CERT_INVALID' };
    if (flags === 1 && (fields.has(5) || fields.has(6))) return { error: 'E_PAL3_CERT_INVALID' };
    if (flags === 0 && (fields.get(5)?.length !== 32 || fields.get(6)?.length !== 1952)) return { error: 'E_PAL3_CERT_INVALID' };
    const issued = u64(fields.get(7));
    const expires = u64(fields.get(8));
    if (expires <= issued || BigInt(nowMs) >= expires) return { error: 'E_PAL3_CERT_EXPIRED' };
    if (issued > BigInt(nowMs) + 300000n) return { error: 'E_PAL3_CERT_FUTURE' };
    const signer = { edPkHex: hexOf(fields.get(2)), dsaPkHex: hexOf(fields.get(3)) };
    let ok = false;
    try { ok = verifyHybridObject(sigObject(fields, 'pal3-devcert-v1', signer, 0xffff)); } catch { ok = false; }
    if (!ok) return { error: 'E_PAL3_CERT_INVALID' };
    return {
      flags, signer, deviceId: hexOf(fields.get(4)),
      deviceEd: hexOf(flags === 1 ? fields.get(2) : fields.get(5)), deviceDsa: hexOf(flags === 1 ? fields.get(3) : fields.get(6)),
    };
  };
  const identityDigest = (s) => hexOf(sha384Of(Buffer.concat([ascii('pal3-identity-v1'), unhex(s.edPkHex), unhex(s.dsaPkHex)])));
  const checkStatement = (hexBytes, trusted) => {
    let fields;
    try { fields = tlvMap(unhex(hexBytes)); } catch { return { error: 'E_PAL3_MALFORMED_TLV' }; }
    for (const [tag, len] of [[1, 32], [2, 1952], [3, 8], [4, 8], [9, 64], [10, 3309]]) if (fields.get(tag)?.length !== len) return { error: 'E_PAL3_REVOCATION_INVALID' };
    const list = fields.get(5) || Buffer.alloc(0);
    if (list.length % 16 !== 0) return { error: 'E_PAL3_REVOCATION_INVALID' };
    const signer = { edPkHex: hexOf(fields.get(1)), dsaPkHex: hexOf(fields.get(2)) };
    if (identityDigest(signer) !== identityDigest(trusted)) return { error: 'E_PAL3_REVOCATION_ISSUER_MISMATCH' };
    let ok = false;
    try { ok = verifyHybridObject(sigObject(fields, 'pal3-revocation-v1', signer, 5)); } catch { ok = false; }
    if (!ok) return { error: 'E_PAL3_REVOCATION_INVALID' };
    return { digest: identityDigest(signer), version: u64(fields.get(3)), revoked: new Set(Array.from({ length: list.length / 16 }, (_, i) => hexOf(list.subarray(i * 16, (i + 1) * 16)))) };
  };
  if (v.certificates.length < 3 || v.certificatesRejected.length < 6 || v.receiverSequence.length < 10) fail('too few cases');
  if (v.identity.digestHex !== identityDigest(v.identity)) fail('identity digest is SHA-384("pal3-identity-v1" || ed25519_pk || mldsa65_pk)');
  for (const c of v.certificates) {
    const r = checkCert(c.certHex, c.nowMs);
    if (r.error) fail(`${c.name}: ${r.error}`);
    if (r.flags !== c.flags || r.deviceId !== c.deviceIdHex || r.deviceEd !== c.deviceEdPkHex || r.deviceDsa !== c.deviceDsaPkHex) fail(`${c.name}: fields`);
    if (r.signer.edPkHex !== c.identity.edPkHex || r.signer.dsaPkHex !== c.identity.dsaPkHex) fail(`${c.name}: signer`);
    if (mldsaSupported() && verifyHybridObject({ ...sigObject(tlvMap(unhex(c.certHex)), 'pal3-devcert-v1', r.signer, 0xffff), dsaContext: 'pal3-devcert-v1x' })) fail(`${c.name}: a wrong ML-DSA context still verifies`);
  }
  if (!v.certificates.some((c) => c.flags === 0) || !v.certificates.some((c) => c.flags === 1)) fail('both certificate forms are required');
  for (const c of v.certificatesRejected) {
    const r = checkCert(c.certHex, c.nowMs);
    if (r.error !== c.expectedError) fail(`${c.name}: expected ${c.expectedError}, got ${r.error || 'accepted'}`);
  }
  const trusted = { owner: v.identity, other: v.otherIdentity };
  const store = new Map();
  for (const s of v.receiverSequence) {
    if (s.op === 'import') {
      const r = checkStatement(v.statements[s.statement], trusted[s.trustedIdentity]);
      if (r.error) {
        if (r.error !== s.expectedError) fail(`${s.name}: expected ${s.expectedError}, got ${r.error}`);
        continue;
      }
      if (s.expectedError) fail(`${s.name}: expected ${s.expectedError}, got accepted`);
      const prev = store.get(r.digest);
      const applied = !prev || prev.version < r.version;
      if (applied) store.set(r.digest, r);
      const now = store.get(r.digest);
      if (applied !== s.expected.applied || String(now.version) !== s.expected.version) fail(`${s.name}: applied ${applied}, version ${now.version}`);
    } else {
      const parsed = checkCert(v.certificateHex[s.cert], v.certificates[0].nowMs);
      if (parsed.error) fail(`${s.name}: ${parsed.error}`);
      const entry = store.get(identityDigest(parsed.signer));
      let got = null;
      if (entry && (parsed.flags === 1 || entry.revoked.has(parsed.deviceId))) got = 'E_PAL3_DEVICE_REVOKED';
      if (got !== s.expectedError) fail(`${s.name}: expected ${s.expectedError}, got ${got}`);
    }
  }
  const final = store.get(v.identity.digestHex);
  if (!final || String(final.version) !== v.finalStoredVersion || !final.revoked.has(v.deviceIds.A) || !final.revoked.has(v.deviceIds.B)) fail('final stored state');
  return { ok: true, version: v.specVersion, certificates: v.certificates.length, negative: v.certificatesRejected.length, steps: v.receiverSequence.length, mldsaChecked: mldsaSupported() };
}

// A.6 and 12.5 item 4: version and suite registry, the HELLO decision, capability tokens. No pal-core.
export function runRegistryValidation(v = vectorFile('pal3-v0.6-registry-vectors.json')) {
  const fail = (m) => { throw new Error(`registry vectors (A.6): ${m}`); };
  if (v.wireProtocolVersion !== 3) fail('the wire protocol version is 0x0003');
  const s1 = v.registry.suite1;
  if (s1.id !== 1 || s1.kem !== 'X25519+ML-KEM-768' || s1.signature !== 'Ed25519+ML-DSA-65' || s1.aead !== 'ChaCha20-Poly1305-IETF' || s1.hash !== 'SHA-384') fail('suite 0x0001');
  if (!v.registry.reservedIds.includes(0) || v.registry.unregisteredIds.join() !== '2,3') fail('reserved and unregistered ids');
  const decide = ({ versionListHex, suiteListHex, responderSuites }) => {
    const versions = unhex(versionListHex);
    const suites = unhex(suiteListHex);
    if (versions.length < 2 || versions.length % 2 !== 0 || suites.length < 2 || suites.length % 2 !== 0) return { error: 'E_PAL3_HANDSHAKE_INVALID' };
    const supportsV3 = Array.from({ length: versions.length / 2 }, (_, i) => versions.readUInt16BE(i * 2)).includes(3);
    let selected = null;
    for (let i = 0; i < suites.length; i += 2) {
      const id = suites.readUInt16BE(i);
      if (id === 1 && (responderSuites === null || responderSuites.includes(id))) { selected = id; break; }
    }
    if (!supportsV3 || selected === null) return { error: 'E_PAL3_DOWNGRADE' };
    return { selectedVersion: 3, selectedSuite: selected };
  };
  if (v.selection.length < 8) fail('fewer than 8 selection cases');
  for (const c of v.selection) {
    if (JSON.stringify(decide(c)) !== JSON.stringify(c.expected)) fail(`${c.name}: expected ${JSON.stringify(c.expected)}, got ${JSON.stringify(decide(c))}`);
  }
  if (!v.selection.some((c) => c.expected.error === 'E_PAL3_DOWNGRADE') || !v.selection.some((c) => c.expected.selectedSuite === 1)) fail('selection needs an accepted and a downgrade case');
  const canonical = (tokens) => [...new Set(tokens.map((t) => t.trim()).filter(Boolean))].sort().join(',');
  for (const c of v.capabilityEncoding) {
    const ascii = unhex(c.capabilitiesHex).toString('ascii');
    if (ascii !== c.capabilitiesAscii) fail(`${c.name}: ascii form`);
    const tokens = ascii.split(',');
    if (new Set(tokens).size !== tokens.length || [...tokens].sort().join(',') !== ascii) fail(`${c.name}: tokens must be sorted and unique`);
    if (c.input && canonical(c.input) !== ascii) fail(`${c.name}: the encoding of the input`);
  }
  for (const c of v.capabilityIntersection) {
    const remote = new Set(c.remote);
    if (canonical(c.local.filter((t) => remote.has(t))).split(',').filter(Boolean).join() !== c.expected.join()) fail(`intersection of ${c.local}`);
  }
  for (const r of v.registrationRejected) {
    let got = null;
    if (!Number.isInteger(r.suiteId) || r.suiteId < 1 || r.suiteId > 0xffff) got = 'E_PAL3_SUITE_INVALID';
    else if (r.isPostQuantumHybrid !== true || !/ML-KEM/.test(r.kemName) || !/(ML-DSA|SLH-DSA)/.test(r.sigName)) got = 'E_PAL3_SUITE_REJECTED';
    else if (r.suiteId === 1) got = 'E_PAL3_SUITE_INVALID';
    if (got !== r.expectedError) fail(`${r.name}: expected ${r.expectedError}, got ${got}`);
  }
  return { ok: true, version: v.specVersion, selection: v.selection.length, negative: v.registrationRejected.length };
}

// 6.2: plaintext bulk records and the gate that allows them. No pal-core.
export function runPlaintextRecordValidation(v = vectorFile('pal3-v0.6-plaintext-record-vectors.json')) {
  const fail = (m) => { throw new Error(`plaintext record vectors (6.2): ${m}`); };
  if (v.flagPlaintext !== 0x80 || v.recordTypeData !== 0x13 || v.bulkChannelIds.join() !== '2,3') fail('flag, DATA type or bulk channel ids');
  const parse = (wire) => ({
    type: wire.readUInt8(0), flags: wire.readUInt8(1), epoch: wire.readUInt16BE(2), streamId: wire.readUInt32BE(4), seq: wire.readBigUInt64BE(8), length: wire.readUInt32BE(16),
  });
  const decideOpen = ({ wireHex, channelId, allow }) => {
    const wire = unhex(wireHex);
    if (wire.length < 20) return 'E_PAL3_RECORD_TOO_SHORT';
    const h = parse(wire);
    const plain = (h.flags & v.flagPlaintext) !== 0;
    if (plain && (!allow || !v.bulkChannelIds.includes(channelId) || h.type !== v.recordTypeData)) return 'E_PAL3_PLAINTEXT_FORBIDDEN';
    if (wire.length !== 20 + h.length + (plain ? 0 : 16)) return 'E_PAL3_LENGTH_MISMATCH';
    if (h.seq !== 0n) return 'E_PAL3_SEQ_MISMATCH';
    return 'accepted';
  };
  for (const r of v.records) {
    const wire = unhex(r.wireHex);
    const h = parse(wire);
    const payload = unhex(r.payloadHex);
    if (r.plaintext) {
      if ((h.flags & 0x80) === 0 || wire.length !== 20 + payload.length || h.length !== payload.length || !wire.subarray(20).equals(payload)) fail(`${r.name}: plaintext wire form`);
    } else {
      if (h.flags !== 0 || wire.length !== 20 + payload.length + 16) fail(`${r.name}: sealed wire form`);
      if (!openPal3Record({ wireHex: r.wireHex, keyHex: r.keyHex, saltHex: r.saltHex, expectedChannelSeq: 0 }).equals(payload)) fail(`${r.name}: sealed record does not open`);
    }
    if (decideOpen({ wireHex: r.wireHex, channelId: r.channelId, allow: true }) !== 'accepted') fail(`${r.name}: a receiver that allows plaintext must accept it`);
  }
  if (!v.records.some((r) => r.plaintext) || !v.records.some((r) => !r.plaintext)) fail('plaintext and sealed records are required');
  for (const c of v.rejected) {
    const got = decideOpen({ wireHex: c.wireHex, channelId: c.channelId, allow: c.receiverAllowsPlaintext });
    if (got !== c.expectedError) fail(`${c.name}: expected ${c.expectedError}, got ${got}`);
  }
  for (const c of v.sendSideRejected) {
    const got = !c.enabled || !v.bulkChannelIds.includes(c.channelId) || c.recordType !== v.recordTypeData ? 'E_PAL3_PLAINTEXT_FORBIDDEN' : 'accepted';
    if (got !== c.expectedError) fail(`${c.name}: expected ${c.expectedError}, got ${got}`);
  }
  const KEY = 'c2-key-update';
  const BULK = 'c2-bulk-plaintext-record';
  for (const g of v.gate) {
    const negotiated = g.capabilities.includes(BULK) && g.capabilities.includes(KEY) && g.carrier === 'c2';
    let path = g.initialPathKind;
    let recvUntil = 0;
    const direct = (k) => v.directPathKinds.includes(k);
    for (const s of g.samples) {
      for (const c of g.pathChanges.filter((x) => x.atMs === s.atMs)) {
        if (direct(path) && !direct(c.setPath)) recvUntil = s.atMs + g.drainWindowMs;
        else if (direct(c.setPath)) recvUntil = 0;
        path = c.setPath;
      }
      const send = negotiated && direct(path);
      const receive = negotiated && (direct(path) || s.atMs < recvUntil);
      if (send !== s.senderMayUsePlaintext || receive !== s.receiverAcceptsPlaintext) fail(`${g.name} at ${s.atMs} ms: expected send ${s.senderMayUsePlaintext} receive ${s.receiverAcceptsPlaintext}, got ${send} ${receive}`);
    }
  }
  if (v.gate.length < 8) fail('fewer than 8 gate scenarios');
  return { ok: true, version: v.specVersion, records: v.records.length, negative: v.rejected.length + v.sendSideRejected.length, gate: v.gate.length };
}

// 11.4: sealing to an identity and its devices, device lists, device-signed objects. Recomputed from node:crypto only.
export function runMultiSealValidation(v = vectorFile('pal3-v0.6-multi-seal-vectors.json'), { mlkem = mlkemSupported() } = {}) {
  const fail = (m) => { throw new Error(`multi-seal vectors (11.4): ${m}`); };
  const L = v.limits;
  if (L.wrapBytes !== 16 + 32 + 1088 + 48 || L.deviceListEntryBytes !== 16 + 1216 + 8 || L.deviceListMaxDevices !== L.maxRecipients - 1) fail('limits');
  const hk = (ikm, info, len) => Buffer.from(hkdfSync('sha384', ikm, Buffer.alloc(0), ascii(info), len));
  const CONTEXT = /^[a-z0-9][a-z0-9._-]{0,63}$/;
  const xPriv = (sk) => createPrivateKey({ key: Buffer.concat([X25519_PKCS8_PREFIX, sk]), format: 'der', type: 'pkcs8' });
  const dh = (sk, pk) => diffieHellman({ privateKey: xPriv(sk), publicKey: createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, pk]), format: 'der', type: 'spki' }) });
  const kemPriv = (seedHex) => createPrivateKey({ key: Buffer.concat([MLKEM768_SEED_PKCS8_PREFIX, unhex(seedHex)]), format: 'der', type: 'pkcs8' });
  const keyIdOf = (xHex, kHex) => sha384Of(Buffer.concat([ascii('pal3-enckey-v1'), unhex(xHex), unhex(kHex)])).subarray(0, 16);
  const reduced = (pk) => { for (let i = 0; i < 1152; i += 3) { if ((pk[i] | ((pk[i + 1] & 0x0f) << 8)) >= 3329 || ((pk[i + 1] >> 4) | (pk[i + 2] << 4)) >= 3329) return false; } return true; };
  const lowOrder = (pk) => { try { return dh(Buffer.alloc(32, 9), pk).every((b) => b === 0); } catch { return true; } };
  const keysUsable = (xHex, kHex) => unhex(xHex).length === 32 && unhex(kHex).length === 1184 && reduced(unhex(kHex)) && !lowOrder(unhex(xHex));
  for (const [name, k] of Object.entries(v.keys)) {
    if (hexOf(x25519PublicRaw(unhex(k.x25519SecretKeyHex))) !== k.x25519PublicKeyHex) fail(`${name}: X25519 public key`);
    if (hexOf(keyIdOf(k.x25519PublicKeyHex, k.mlkemEncapsulationKeyHex)) !== k.keyIdHex) fail(`${name}: key_id`);
    if (mlkem && !createPublicKey(kemPriv(k.mlkemSeedHex)).export({ format: 'der', type: 'spki' }).subarray(-1184).equals(unhex(k.mlkemEncapsulationKeyHex))) fail(`${name}: ML-KEM key does not come from the seed`);
  }
  const headerDigest = (ctx, commitment) => sha384Of(Buffer.concat([ascii('pal3-seal-header-v1'), Buffer.from([1, ctx.length]), ascii(ctx), commitment]));
  const aeadOpen = (key, nonce, aad, ct) => {
    if (ct.length < 16) return null;
    const d = createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
    d.setAAD(aad);
    d.setAuthTag(ct.subarray(ct.length - 16));
    try { return Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]); } catch { return null; }
  };
  const open = (sealedHex, who, context) => {
    let f;
    try { f = new Map(decodeTlv(unhex(sealedHex)).map((e) => [e.tag, e.value])); } catch { return { error: 'E_PAL3_SEAL_INVALID' }; }
    for (const tag of f.keys()) {
      if (tag >= 1 && tag <= 5) continue;
      if (tag < 0x8000) return { error: 'E_PAL3_SEAL_INVALID' };
      if ((tag & 0xc000) === 0x8000) return { error: 'E_PAL3_UNSUPPORTED_CRITICAL_EXTENSION' };
    }
    const ver = f.get(1); const ctx = f.get(2); const commit = f.get(3); const wraps = f.get(4); const ct = f.get(5);
    if (!ver || ver.length !== 1 || ver[0] !== 1) return { error: 'E_PAL3_SEAL_INVALID' };
    if (!ctx || ctx.length < 1 || ctx.length > 64 || !CONTEXT.test(ctx.toString('ascii'))) return { error: 'E_PAL3_SEAL_INVALID' };
    if (!commit || commit.length !== 32 || !ct || ct.length < 16 || ct.length > 32768 + 16) return { error: 'E_PAL3_SEAL_INVALID' };
    if (!wraps || wraps.length === 0 || wraps.length % L.wrapBytes !== 0 || wraps.length / L.wrapBytes > L.maxRecipients) return { error: 'E_PAL3_SEAL_INVALID' };
    if (ctx.toString('ascii') !== context) return { error: 'E_PAL3_SEAL_CONTEXT_MISMATCH' };
    const k = v.keys[who];
    const aad = headerDigest(context, commit);
    let matched = false;
    for (let i = 0; i < wraps.length / L.wrapBytes; i++) {
      const w = wraps.subarray(i * L.wrapBytes, (i + 1) * L.wrapBytes);
      if (hexOf(w.subarray(0, 16)) !== k.keyIdHex) continue;
      matched = true;
      if (!mlkem) return { structureOnly: true };
      const eph = w.subarray(16, 48); const kct = w.subarray(48, 48 + 1088); const wrapped = w.subarray(48 + 1088);
      let ssX; let ssPq;
      try { ssX = dh(unhex(k.x25519SecretKeyHex), eph); ssPq = decapsulate(kemPriv(k.mlkemSeedHex), kct); } catch { continue; }
      if (ssX.every((b) => b === 0)) continue;
      const ctxBytes = Buffer.concat([eph, unhex(k.x25519PublicKeyHex), sha384Of(unhex(k.mlkemEncapsulationKeyHex)), sha384Of(kct)]);
      const km = hk(Buffer.concat([ssX, ssPq, ctxBytes]), 'pal3-seal-wrap-v1', 44);
      const ck = aeadOpen(km.subarray(0, 32), km.subarray(32, 44), aad, wrapped);
      if (!ck || !hk(ck, 'pal3-seal-commit-v1', 32).equals(commit)) continue;
      const plain = aeadOpen(hk(ck, 'pal3-seal-key-v1', 32), Buffer.alloc(12), aad, ct);
      if (plain) return { plaintext: plain, wraps: wraps.length / L.wrapBytes };
    }
    return { error: matched ? 'E_PAL3_SEAL_AUTH_FAILED' : 'E_PAL3_SEAL_NO_RECIPIENT' };
  };
  for (const c of v.sealedContent) {
    for (const who of Object.keys(v.keys)) {
      const r = open(c.sealedHex, who, c.context);
      if (c.recipients.includes(who)) {
        if (r.error) fail(`${c.name}: ${who} must open it, got ${r.error}`);
        if (!r.structureOnly && hexOf(r.plaintext) !== c.plaintextHex) fail(`${c.name}: ${who} reads another plaintext`);
      } else if (r.error !== 'E_PAL3_SEAL_NO_RECIPIENT') fail(`${c.name}: ${who} is no recipient but got ${r.error || 'a plaintext'}`);
    }
    const wraps = new Map(decodeTlv(unhex(c.sealedHex)).map((e) => [e.tag, e.value])).get(4);
    if (wraps.length !== c.wraps * L.wrapBytes) fail(`${c.name}: wrap count`);
    c.recipients.forEach((who, i) => { if (hexOf(wraps.subarray(i * L.wrapBytes, i * L.wrapBytes + 16)) !== v.keys[who].keyIdHex) fail(`${c.name}: wrap ${i} is not addressed to ${who}`); });
  }
  if (!v.sealedContent.some((c) => c.recipients.includes('deviceA')) || !v.sealedContent.some((c) => c.recipients.length === 1)) fail('device and identity-only cases are required');
  for (const r of v.sealedRejected) {
    const got = open(r.sealedHex, r.openAs, r.context);
    if (got.structureOnly) continue;
    if (got.error !== r.expectedError) fail(`${r.name}: expected ${r.expectedError}, got ${got.error || 'accepted'}`);
  }
  const split = v.sealedRejected.find((r) => r.name === 'senderWrapsAnotherContentKeyForADevice');
  if (mlkem && split && open(split.sealedHex, 'identity', 'message').error) fail('the split-key message must still open for the identity');
  for (const r of v.sealRejected) {
    let got = 'accepted';
    if (!CONTEXT.test(r.context) || r.plaintextLength > L.maxPlaintextBytes || r.recipientCount < 1 || r.duplicateKey) got = 'E_PAL3_SEAL_INVALID';
    if (r.recipientCount > L.maxRecipients) got = 'E_PAL3_SEAL_TOO_MANY_RECIPIENTS';
    if (r.lowOrderX25519 && !keysUsable(r.x25519PublicKeyHex, v.keys.deviceA.mlkemEncapsulationKeyHex)) got = 'E_PAL3_SEAL_KEY_INVALID';
    if (r.unreducedMlKem && !keysUsable(v.keys.deviceA.x25519PublicKeyHex, r.mlkemEncapsulationKeyHex)) got = 'E_PAL3_SEAL_KEY_INVALID';
    if (got !== r.expectedError) fail(`${r.name}: expected ${r.expectedError}, got ${got}`);
  }
  const certFields = (hexBytes) => new Map(decodeTlv(unhex(hexBytes)).map((e) => [e.tag, e.value]));
  const hybridOk = (fields, domain, signer, skipTags = [9, 10]) => {
    const body = hexOf(encodeTlv([...fields].filter(([t]) => !skipTags.includes(t)).map(([tag, value]) => ({ tag, value }))));
    try { return verifyHybridObject({ domain, dsaContext: domain, signer, bodyHex: body, sigEd25519Hex: hexOf(fields.get(9)), sigMldsa65Hex: hexOf(fields.get(10)) }); } catch { return false; }
  };
  const idSigner = v.identity;
  for (const [name, c] of Object.entries(v.certificates)) {
    const f = certFields(c.certHex);
    if (!hybridOk(f, 'pal3-devcert-v1', idSigner)) fail(`${name}: certificate signature`);
    if (hexOf(f.get(4)) !== c.deviceIdHex) fail(`${name}: device_id`);
    if (name === 'deviceA') {
      if (!f.has(0xc010) || hexOf(f.get(0xc010)) !== c.extensionHex) fail('the encryption key extension must be present');
      const d = v.keys.deviceA;
      if (c.extensionHex !== d.x25519PublicKeyHex + d.mlkemEncapsulationKeyHex) fail('extension value is x25519_pk || mlkem768_pk');
    }
  }
  if (c0xc010Class() !== 'optional') fail('tag 0xC010 must be in the comprehension-optional range');
  const identityDigest = (s) => hexOf(sha384Of(Buffer.concat([ascii('pal3-identity-v1'), unhex(s.edPkHex), unhex(s.dsaPkHex)])));
  const checkList = (listHex, nowMs, trusted) => {
    let f;
    try { f = certFields(listHex); } catch { return { error: 'E_PAL3_DEVICE_LIST_INVALID' }; }
    for (const tag of f.keys()) {
      if (tag >= 1 && tag <= 11) continue;
      if (tag < 0x8000) return { error: 'E_PAL3_DEVICE_LIST_INVALID' };
      if ((tag & 0xc000) === 0x8000) return { error: 'E_PAL3_UNSUPPORTED_CRITICAL_EXTENSION' };
    }
    for (const [t, n] of [[1, 32], [2, 1952], [3, 1216], [4, 8], [5, 8], [6, 8], [7, 8], [9, 64], [10, 3309]]) if (f.get(t)?.length !== n) return { error: 'E_PAL3_DEVICE_LIST_INVALID' };
    if (!f.has(8) || !f.has(11)) return { error: 'E_PAL3_DEVICE_LIST_INVALID' };
    const signer = { edPkHex: hexOf(f.get(1)), dsaPkHex: hexOf(f.get(2)) };
    if (identityDigest(signer) !== identityDigest(trusted)) return { error: 'E_PAL3_DEVICE_LIST_ISSUER_MISMATCH' };
    if (!hybridOk(f, 'pal3-devlist-v1', signer)) return { error: 'E_PAL3_DEVICE_LIST_INVALID' };
    const revision = f.get(4).readBigUInt64BE(0); const issued = f.get(6).readBigUInt64BE(0); const expires = f.get(7).readBigUInt64BE(0);
    if (revision < 1n) return { error: 'E_PAL3_DEVICE_LIST_INVALID' };
    if (expires <= issued || expires - issued > BigInt(L.deviceListMaxLifetimeMs)) return { error: 'E_PAL3_DEVICE_LIST_INVALID' };
    if (issued > BigInt(nowMs + L.maxClockSkewMs)) return { error: 'E_PAL3_DEVICE_LIST_INVALID' };
    if (BigInt(nowMs) >= expires) return { error: 'E_PAL3_DEVICE_LIST_STALE' };
    const caps = f.get(8).length ? f.get(8).toString('ascii').split(',') : [];
    if (caps.some((c) => !CONTEXT.test(c)) || caps.join() !== [...new Set(caps)].sort().join()) return { error: 'E_PAL3_DEVICE_LIST_INVALID' };
    const entries = f.get(11);
    if (entries.length % L.deviceListEntryBytes !== 0 || entries.length / L.deviceListEntryBytes > L.deviceListMaxDevices) return { error: 'E_PAL3_DEVICE_LIST_INVALID' };
    const devices = [];
    for (let o = 0; o < entries.length; o += L.deviceListEntryBytes) {
      const id = entries.subarray(o, o + 16);
      if (devices.length && Buffer.compare(Buffer.from(devices.at(-1).id, 'hex'), id) >= 0) return { error: 'E_PAL3_DEVICE_LIST_INVALID' };
      const x = entries.subarray(o + 16, o + 48); const k = entries.subarray(o + 48, o + 16 + 1216);
      if (!keysUsable(hexOf(x), hexOf(k))) return { error: 'E_PAL3_SEAL_KEY_INVALID' };
      devices.push({ id: hexOf(id), x: hexOf(x), k: hexOf(k), certExpires: Number(entries.readBigUInt64BE(o + 16 + 1216)) });
    }
    if (!keysUsable(hexOf(f.get(3).subarray(0, 32)), hexOf(f.get(3).subarray(32)))) return { error: 'E_PAL3_SEAL_KEY_INVALID' };
    return { revision, revocationVersion: f.get(5).readBigUInt64BE(0), issued: Number(issued), expires: Number(expires), caps, devices, encKeys: hexOf(f.get(3)), digest: identityDigest(signer) };
  };
  const trustOf = (name) => (name === 'stranger' ? v.strangerIdentity : v.identity);
  const byName = new Map();
  for (const l of v.deviceLists) {
    const r = checkList(l.listHex, l.nowMs, v.identity);
    if (r.error) fail(`${l.name}: ${r.error}`);
    if (String(r.revision) !== l.revision || String(r.revocationVersion) !== l.revocationVersion || r.issued !== l.issuedAtMs || r.expires !== l.expiresAtMs || r.caps.join() !== l.capabilities.join() || r.devices.map((d) => d.id).join() !== l.deviceIds.join()) fail(`${l.name}: fields`);
    byName.set(l.name, r);
  }
  if (v.deviceListsRejected.length < 8) fail('fewer than 8 list rejections');
  for (const l of v.deviceListsRejected) {
    const r = checkList(l.listHex, l.nowMs, trustOf(l.trustedIdentity));
    if ((r.error || 'accepted') !== l.expectedError) fail(`${l.name}: expected ${l.expectedError}, got ${r.error || 'accepted'}`);
  }
  const stored = new Map();
  const revoked = new Set();
  let statementVersion = 0n;
  for (const s of v.receiverSequence) {
    if (s.op === 'importList') {
      const r = byName.get(s.list);
      if (s.pinnedEncKeysOf) {
        const pinned = v.keys[s.pinnedEncKeysOf].x25519PublicKeyHex + v.keys[s.pinnedEncKeysOf].mlkemEncapsulationKeyHex;
        const got = r.encKeys !== pinned ? 'E_PAL3_DEVICE_LIST_ENCKEY_CHANGED' : 'accepted';
        if (got !== s.expectedError) fail(`${s.name}: expected ${s.expectedError}, got ${got}`);
        continue;
      }
      const prev = stored.get(r.digest);
      if (prev && prev.encKeys !== r.encKeys) { if (s.expectedError !== 'E_PAL3_DEVICE_LIST_ENCKEY_CHANGED') fail(`${s.name}: pinned keys`); continue; }
      const applied = !prev || prev.revision < r.revision;
      if (applied) stored.set(r.digest, r);
      if (applied !== s.expected.applied || String(stored.get(r.digest).revision) !== s.expected.revision) fail(`${s.name}: applied ${applied}`);
    } else if (s.op === 'importRevocation') {
      const f = certFields(v.statements[s.statement]);
      if (!hybridOk(f, 'pal3-revocation-v1', v.identity)) fail(`${s.name}: statement signature`);
      const list = f.get(5);
      for (let o = 0; o < list.length; o += 16) revoked.add(hexOf(list.subarray(o, o + 16)));
      statementVersion = f.get(3).readBigUInt64BE(0);
    } else if (s.op === 'select') {
      const list = stored.get(identityDigest(v.identity));
      const rec = [{ kind: 'identity', keyIdHex: hexOf(keyIdOf(list.encKeys.slice(0, 64), list.encKeys.slice(64))), deviceIdHex: null }];
      const skipped = [];
      for (const d of list.devices) {
        if (s.nowMs >= list.expires) skipped.push({ deviceIdHex: d.id, reason: 'list-expired' });
        else if (d.certExpires <= s.nowMs) skipped.push({ deviceIdHex: d.id, reason: 'certificate-expired' });
        else if (revoked.has(d.id)) skipped.push({ deviceIdHex: d.id, reason: 'revoked' });
        else rec.push({ kind: 'device', keyIdHex: hexOf(keyIdOf(d.x, d.k)), deviceIdHex: d.id });
      }
      if (JSON.stringify(rec) !== JSON.stringify(s.expectedRecipients) || JSON.stringify(skipped) !== JSON.stringify(s.expectedSkipped)) fail(`${s.name}: recipients`);
    }
  }
  if (statementVersion !== 1n) fail('the sequence must hold a revocation statement');
  const checkSigned = (c) => {
    let f;
    try { f = certFields(c.signedHex); } catch { return 'E_PAL3_DEVICE_SIG_INVALID'; }
    if (f.get(1)?.length !== 48 || f.get(3)?.length !== 64 || f.get(4)?.length !== 3309) return 'E_PAL3_DEVICE_SIG_INVALID';
    const certBytes = f.get(2) || (c.knownCertificatesHex || []).map(unhex).find((b) => sha384Of(b).equals(f.get(1)));
    if (!certBytes) return 'E_PAL3_DEVICE_CERT_UNKNOWN';
    if (!sha384Of(certBytes).equals(f.get(1))) return 'E_PAL3_DEVICE_SIG_INVALID';
    const cf = new Map(decodeTlv(certBytes).map((e) => [e.tag, e.value]));
    const flags = cf.get(1)[0];
    const signer = { edPkHex: hexOf(cf.get(2)), dsaPkHex: hexOf(cf.get(3)) };
    if (BigInt(c.nowMs) >= cf.get(8).readBigUInt64BE(0)) return 'E_PAL3_CERT_EXPIRED';
    if (!hybridOk(cf, 'pal3-devcert-v1', signer)) return 'E_PAL3_CERT_INVALID';
    if (identityDigest(signer) !== identityDigest(trustOf(c.trustedIdentity || 'owner'))) return 'E_PAL3_DEVICE_SIG_ISSUER_MISMATCH';
    if (c.statementHex) {
      const ids = certFields(c.statementHex).get(5);
      for (let o = 0; o < ids.length; o += 16) if (hexOf(ids.subarray(o, o + 16)) === hexOf(cf.get(4)) || flags === 1) return 'E_PAL3_DEVICE_REVOKED';
    }
    const devKeys = flags === 1 ? signer : { edPkHex: hexOf(cf.get(5)), dsaPkHex: hexOf(cf.get(6)) };
    const signedBody = Buffer.concat([Buffer.from([c.context.length]), ascii(c.context), unhex(c.bodyHex)]);
    let ok = false;
    try { ok = verifyHybridObject({ domain: 'pal3-devsig-v1', dsaContext: 'pal3-devsig-v1', signer: devKeys, bodyHex: hexOf(signedBody), sigEd25519Hex: hexOf(f.get(3)), sigMldsa65Hex: hexOf(f.get(4)) }); } catch { ok = false; }
    return ok ? 'accepted' : 'E_PAL3_DEVICE_SIG_INVALID';
  };
  for (const c of v.deviceSigned) {
    const got = checkSigned(c);
    if (got !== 'accepted') fail(`${c.name}: ${got}`);
  }
  if (v.deviceSignedRejected.length < 8) fail('fewer than 8 device-signed rejections');
  for (const c of v.deviceSignedRejected) {
    const got = checkSigned(c);
    if (got !== c.expectedError) fail(`${c.name}: expected ${c.expectedError}, got ${got}`);
  }
  return { ok: true, version: v.specVersion, sealed: v.sealedContent.length, negative: v.sealedRejected.length + v.sealRejected.length + v.deviceListsRejected.length + v.deviceSignedRejected.length, lists: v.deviceLists.length, signed: v.deviceSigned.length, validated: mlkem ? 'full' : 'structure-only' };
}
const c0xc010Class = () => ((0xc010 & 0xc000) === 0xc000 ? 'optional' : (0xc010 & 0xc000) === 0x8000 ? 'critical' : 'core');

// 11.2 items 1, 3, 5, 7: written from the specification text, without pal-core.
export function runHardeningValidation(v = vectorFile('pal3-v0.6-hardening-vectors.json')) {
  const fail = (m) => { throw new Error(`hardening vectors (11.2): ${m}`); };
  const L = v.limits;
  if (L.maxPayloadBytes !== 1200 || L.maxFragmentsPerMessage !== 64 || L.perSourceMessages !== 16 || L.globalMessages !== 128 || L.expiryMs !== 5000) fail('limits');

  // Item 5.
  const parseUri = (input) => {
    if (typeof input !== 'string' || !input.trim().toLowerCase().startsWith('pal://')) return { error: 'E_PAL3_URI_INVALID' };
    const rest = input.trim().slice(6);
    const q = rest.indexOf('?');
    const pathPart = q < 0 ? rest : rest.slice(0, q);
    const query = q < 0 ? '' : rest.slice(q + 1);
    const raw = pathPart.split('/').filter((s) => s.length > 0);
    if (raw.length < 1) return { error: 'E_PAL3_URI_INVALID' };
    let segments;
    try { segments = raw.map((s) => decodeURIComponent(s)); } catch { return { error: 'E_PAL3_URI_INVALID' }; }
    // eslint-disable-next-line no-control-regex
    if (segments.some((s) => s.length === 0 || s === '.' || s === '..' || /[/\\:]/.test(s) || /[\x00-\x1f\x7f]/.test(s))) return { error: 'E_PAL3_URI_TRAVERSAL' };
    const handle = segments[0].startsWith('@') ? segments[0].slice(1) : segments[0];
    if (!handle) return { error: 'E_PAL3_URI_INVALID' };
    let range = null;
    const m = /(?:^|&)range=(\d+)-(\d*)(?:&|$)/.exec(query);
    if (m) {
      const start = Number(m[1]);
      const end = m[2] === '' ? null : Number(m[2]);
      if (end !== null && end < start) return { error: 'E_PAL3_URI_INVALID' };
      range = { start, end };
    }
    return { value: { scheme: 'pal', handle, shareId: segments[1] || null, filePath: segments.length > 2 ? segments.slice(2).join('/') : '', range } };
  };
  if (v.uri.length < 15) fail('fewer than 15 URI cases');
  for (const c of v.uri) {
    const got = parseUri(c.input);
    if (c.expectedError) { if (got.error !== c.expectedError) fail(`uri ${c.name}: expected ${c.expectedError}, got ${got.error || 'accepted'}`); } else if (got.error || JSON.stringify(got.value) !== JSON.stringify(c.expected)) fail(`uri ${c.name}: ${got.error || 'another result'}`);
  }
  for (const needed of ['encodedSlashInSegment', 'encodedDotDot', 'encodedNul', 'encodedBackslash']) if (!v.uri.some((c) => c.name === needed && c.expectedError === 'E_PAL3_URI_TRAVERSAL')) fail(`uri ${needed} must be rejected`);

  // Item 1.
  const scratch = unhex(v.x25519.scratchScalarHex);
  const decideX = (pkHex) => {
    try {
      const secret = diffieHellman({ privateKey: x25519Private(scratch), publicKey: createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, unhex(pkHex)]), format: 'der', type: 'spki' }) });
      return { decision: secret.every((b) => b === 0) ? 'rejected' : 'accepted', secret: hexOf(secret) };
    } catch { return { decision: 'rejected', secret: null }; }
  };
  if (v.x25519.keys.filter((k) => k.decision === 'rejected').length < 6 || !v.x25519.keys.some((k) => k.decision === 'accepted')) fail('x25519 needs low-order and ordinary keys');
  for (const k of v.x25519.keys) {
    const got = decideX(k.publicKeyHex);
    if (got.decision !== k.decision) fail(`x25519 ${k.name}: expected ${k.decision}, got ${got.decision}`);
    if (k.decision === 'accepted' && got.secret !== k.sharedSecretHex) fail(`x25519 ${k.name}: shared secret`);
  }

  // Item 7.
  const reducedKey = (pk) => {
    if (pk.length !== 1184) return false;
    for (let i = 0; i < 1152; i += 3) {
      if ((pk[i] | ((pk[i + 1] & 0x0f) << 8)) >= 3329 || ((pk[i + 1] >> 4) | (pk[i + 2] << 4)) >= 3329) return false;
    }
    return true;
  };
  for (const c of v.mlkem.cases) {
    const got = reducedKey(unhex(c.encapsulationKeyHex)) ? 'accepted' : 'rejected';
    if (got !== c.decision) fail(`mlkem ${c.name}: expected ${c.decision}, got ${got}`);
  }
  if (!v.mlkem.cases.some((c) => c.decision === 'accepted') || v.mlkem.cases.filter((c) => c.decision === 'rejected').length < 3) fail('mlkem needs accepted and rejected keys');

  // Item 3: a model of the rules, run on every scenario.
  const run = (scenario) => {
    const inflight = new Map();
    const groups = new Map();
    const drop = (key) => {
      const e = inflight.get(key);
      if (!e) return;
      inflight.delete(key);
      const n = (groups.get(e.group) || 1) - 1;
      if (n <= 0) groups.delete(e.group); else groups.set(e.group, n);
    };
    const evictOldest = (group) => { for (const [key, e] of inflight) { if (group === undefined || e.group === group) { drop(key); return; } } };
    return scenario.steps.map((s) => {
      const pkt = unhex(s.packetHex);
      if (pkt.length < 8) return { error: 'E_PAL3_CARRIER_PACKET_SHORT' };
      const id = pkt.readUInt32BE(0); const idx = pkt.readUInt16BE(4); const total = pkt.readUInt16BE(6);
      if (total === 0 || idx >= total || total > L.maxFragmentsPerMessage) return { error: 'E_PAL3_CARRIER_PACKET_INVALID' };
      const payload = pkt.subarray(8);
      if (payload.length > L.maxPayloadBytes || (idx < total - 1 && payload.length !== L.maxPayloadBytes)) return { error: 'E_PAL3_CARRIER_PACKET_INVALID' };
      if (total === 1) return { complete: true, frameHex: hexOf(payload) };
      for (const [key, e] of inflight) { if (s.atMs - e.createdAt < L.expiryMs) break; drop(key); }
      const group = s.group ?? s.source;
      const key = `${s.source}|${id}`;
      let e = inflight.get(key);
      if (!e) {
        if ((groups.get(group) || 0) >= L.perSourceMessages) evictOldest(group);
        while (inflight.size >= L.globalMessages) evictOldest();
        e = { group, total, chunks: new Array(total), createdAt: s.atMs };
        inflight.set(key, e);
        groups.set(group, (groups.get(group) || 0) + 1);
      } else if (e.total !== total) {
        return { error: 'E_PAL3_CARRIER_PACKET_INVALID' };
      }
      if (e.chunks[idx]) {
        if (e.chunks[idx].equals(payload)) return { complete: false };
        drop(key);
        return { error: 'E_PAL3_CARRIER_PACKET_CONFLICT' };
      }
      e.chunks[idx] = Buffer.from(payload);
      if (Array.from(e.chunks).some((c) => !c)) return { complete: false };
      drop(key);
      return { complete: true, frameHex: hexOf(Buffer.concat(e.chunks)) };
    });
  };
  if (v.reassembly.length < 12) fail('fewer than 12 reassembly scenarios');
  let steps = 0;
  for (const sc of v.reassembly) {
    const got = run(sc);
    sc.steps.forEach((s, i) => {
      steps++;
      const want = s.expectedError ? { error: s.expectedError } : s.expected;
      if (JSON.stringify(got[i]) !== JSON.stringify(want)) fail(`reassembly ${sc.name}, step ${i}: expected ${JSON.stringify(want).slice(0, 60)}, got ${JSON.stringify(got[i]).slice(0, 60)}`);
    });
  }
  return { ok: true, version: v.specVersion, uri: v.uri.length, x25519: v.x25519.keys.length, mlkem: v.mlkem.cases.length, scenarios: v.reassembly.length, steps };
}

// 12.3 (a linter is not a boundary) and 12.4 (local limits refuse only with E_BUSY, never with a reason): written from the specification text.
export function runLocalPolicyValidation(v = vectorFile('pal3-v0.6-local-policy-vectors.json')) {
  const fail = (m) => { throw new Error(`local policy vectors (12.3, 12.4): ${m}`); };
  const BLOCKED = ['child_process', 'cluster', 'vm', 'v8', 'inspector', 'worker_threads', 'module', 'wasi'];
  const unsafe = (src) => {
    const blockedModule = BLOCKED.some((m) => new RegExp(`['"\`](?:node:)?${m}['"\`]`).test(src));
    return blockedModule
      || /\beval\b/.test(src) || /\bFunction\s*\(/.test(src) || /constructor\s*\.\s*constructor/.test(src)
      || /\b(?:import|require)\s*\(\s*[^'"\s]/.test(src) || /\brequire\b(?!\s*\()/.test(src) || /\bcreateRequire\b/.test(src)
      || /\bprocess\s*(?:\.\s*(?:binding|dlopen)|\[)/.test(src) || /\bglobalThis\s*\[/.test(src) || /\bWebAssembly\b/.test(src);
  };
  if (v.analyzer.length < 12) fail('fewer than 12 linter cases');
  for (const c of v.analyzer) {
    if (c.isSecurityBoundary !== false) fail(`${c.name}: the linter is not a security boundary`);
    if (unsafe(c.source) === c.safe) fail(`${c.name}: expected ${unsafe(c.source) ? 'unsafe' : 'safe'}, vector says safe = ${c.safe}`);
    if (c.safe !== (c.criticalTypes.length === 0)) fail(`${c.name}: critical types and safe disagree`);
  }
  for (const needed of ['directEval', 'functionConstructor', 'computedImport', 'aliasedRequire', 'moduleLoaderInternals', 'staticImportOfChildProcess']) {
    if (v.analyzer.find((c) => c.name === needed)?.safe !== false) fail(`${needed} must be refused`);
  }
  if (v.analyzerBundled.safe !== true || !v.analyzerBundled.manifest.permissions.some((p) => p.startsWith('exec:'))) fail('a bundled extension that names exec: may import child_process');
  const allowed = (granted, required) => granted.includes(required) || (!/^(?:exec|native):/.test(required) && granted.includes('*'));
  for (const p of v.permissions) if (allowed(p.granted, p.required) !== p.allowed) fail(`permission ${p.name}`);

  const L = v.limits;
  const clampRetry = (ms) => (Number.isFinite(ms) ? Math.min(L.busyMaxMs, Math.max(L.busyMinMs, Math.ceil(ms))) : L.busyMaxMs);
  const bucket = (rate, at) => {
    const cap = Math.max(rate * 4, 4 * 256 * 1024);
    return { rate, cap, tokens: cap, at };
  };
  const take = (b, bytes, now) => {
    if (!b.rate) return 0;
    b.tokens = Math.min(b.cap, b.tokens + ((now - b.at) / 1000) * b.rate);
    b.at = now;
    if (b.tokens >= Math.min(bytes, b.cap)) { b.tokens -= bytes; return 0; }
    return ((Math.min(bytes, b.cap) - b.tokens) / b.rate) * 1000;
  };
  const day = (ms) => new Date(ms).toISOString().slice(0, 10);
  const month = (ms) => new Date(ms).toISOString().slice(0, 7);
  let steps = 0;
  if (v.scenarios.length < 10) fail('fewer than 10 scenarios');
  for (const sc of v.scenarios) {
    const s = { privacy: false, uploadBps: 0, perPeerBps: 0, uploadSlots: 4, doNotShare: [], meteredServe: false, meteredDailyBytes: 0, meteredMonthlyBytes: 0, batteryMinPct: 20, onlyWhileCharging: false, ...sc.settings };
    let now = sc.startMs;
    let device = { metered: false, batteryPct: null, charging: null, online: true };
    let usage = { day: day(now), month: month(now), dayBytes: 0, monthBytes: 0 };
    const global = bucket(s.uploadBps, now);
    const perPeer = new Map();
    let active = 0;
    const leases = [];
    const roll = () => {
      if (usage.month !== month(now)) usage = { day: day(now), month: month(now), dayBytes: 0, monthBytes: 0 };
      else if (usage.day !== day(now)) usage = { ...usage, day: day(now), dayBytes: 0 };
    };
    const pause = (shareId) => {
      if (s.privacy) return 'privacy';
      if (shareId && s.doNotShare.includes(shareId)) return 'share-off';
      if (!device.online) return 'offline';
      if (s.uploadSlots === 0) return 'off';
      if (s.onlyWhileCharging && device.charging === false) return 'not-charging';
      if (device.batteryPct !== null && device.charging !== true && s.batteryMinPct > 0 && device.batteryPct < s.batteryMinPct) return 'low-battery';
      if (device.metered) {
        if (!s.meteredServe) return 'metered-off';
        roll();
        if (s.meteredDailyBytes && usage.dayBytes >= s.meteredDailyBytes) return 'daily-cap';
        if (s.meteredMonthlyBytes && usage.monthBytes >= s.meteredMonthlyBytes) return 'monthly-cap';
      }
      return null;
    };
    const record = (bytes) => { if (bytes > 0 && device.metered) { roll(); usage.dayBytes += bytes; usage.monthBytes += bytes; } };
    const busy = (ms) => ({ ok: false, error: 'E_BUSY', text: `E_BUSY: retry after ${clampRetry(ms)} ms`, retryAfterMs: clampRetry(ms) });
    const release = (lease, sent) => { if (lease.done) return; lease.done = true; active = Math.max(0, active - 1); record(sent ?? lease.bytes); };
    for (const st of sc.steps) {
      steps++;
      now = sc.startMs + st.atMs;
      if (st.device) device = { metered: st.device.metered === true, batteryPct: st.device.batteryPct ?? null, charging: typeof st.device.charging === 'boolean' ? st.device.charging : null, online: st.device.online !== false };
      if (st.op === 'release') { release(leases[st.lease], st.sentBytes); continue; }
      const serving = pause(st.shareId) === null;
      let got;
      const reason = pause(st.shareId);
      if (reason) got = busy(L.busyMaxMs);
      else if (active >= s.uploadSlots) got = busy(1000);
      else {
        let peerBucket = null;
        let wait = 0;
        if (s.perPeerBps) {
          const key = st.peer.toLowerCase();
          if (!perPeer.has(key)) perPeer.set(key, bucket(s.perPeerBps, now));
          peerBucket = perPeer.get(key);
          wait = take(peerBucket, st.bytes, now);
          if (wait > 0) got = busy(wait);
        }
        if (!got) {
          wait = take(global, st.bytes, now);
          if (wait > 0) { if (peerBucket) peerBucket.tokens = Math.min(peerBucket.cap, peerBucket.tokens + st.bytes); got = busy(wait); }
        }
        if (!got) {
          active += 1;
          const lease = { bytes: st.bytes, done: false };
          leases.push(lease);
          if (st.release !== undefined) release(lease, st.release);
          got = { ok: true };
        }
      }
      const want = st.expected;
      if (want.serving !== serving || want.ok !== got.ok) fail(`${sc.name} at ${st.atMs} ms: expected ${want.ok ? 'served' : 'E_BUSY'}, got ${got.ok ? 'served' : 'E_BUSY'}`);
      if (!got.ok) {
        if (want.error !== 'E_BUSY' || want.text !== got.text || want.retryAfterMs !== got.retryAfterMs) fail(`${sc.name} at ${st.atMs} ms: the refusal is ${want.text}, expected ${got.text}`);
        if (!/^E_BUSY: retry after \d+ ms$/.test(want.text)) fail(`${sc.name}: a refusal carries no reason`);
      }
    }
  }
  return { ok: true, version: v.specVersion, sources: v.analyzer.length, scenarios: v.scenarios.length, steps };
}

// 13.2 network fields, 13.4, 13.5, 13.6: a model written from the specification text, checked against the vectors.
export function runPrivateNetworkAcceptValidation(v = vectorFile('pal3-v0.6-private-network-accept-vectors.json')) {
  const fail = (m) => { throw new Error(`private network vectors (13.2, 13.4-13.6): ${m}`); };
  const ED_SPKI = Buffer.from('302a300506032b6570032100', 'hex');
  const KEY_RE = /^[0-9a-f]{64}$/i;
  const DATE_RE = /^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/;
  const L = v.limits;
  const signedBytes = (p) => 'palexplorer-private-network-v3\n' + JSON.stringify({
    name: p.name, admin: p.admin, discoveryServers: p.discoveryServers, relays: p.relays,
    members: p.members.map((m) => ({ publicKey: m.publicKey, name: m.name ?? null, revoked: Boolean(m.revoked) })),
    privacyMode: p.privacyMode, issuedAt: p.issuedAt, version: p.version, expiresAt: p.expiresAt,
    networkId: p.networkId ?? null, networkCreator: p.networkCreator ?? null, networkNonce: p.networkNonce ?? null, networkCreatedAtMs: p.networkCreatedAtMs ?? null,
  });
  const edVerify = (message, sigHex, pkHex) => {
    try { return cryptoVerify(null, Buffer.from(message, 'utf8'), createPublicKey({ key: Buffer.concat([ED_SPKI, unhex(pkHex)]), format: 'der', type: 'spki' }), unhex(sigHex)); } catch { return false; }
  };
  // 13.4 items 1 and 4 and 13.1: the profile itself.
  const verifyProfile = (p, now) => {
    if (!p.admin || !KEY_RE.test(p.admin) || !p.signature || !p.issuedAt) return 'E_PRIVATE_NETWORK_UNSIGNED';
    if (!DATE_RE.test(String(p.expiresAt)) || Number.isNaN(Date.parse(p.expiresAt))) return 'E_PRIVATE_NETWORK_BAD_DATE';
    if (!edVerify(signedBytes(p), p.signature, p.admin)) return 'E_PRIVATE_NETWORK_BAD_SIGNATURE';
    if (!DATE_RE.test(p.issuedAt) || Number.isNaN(Date.parse(p.issuedAt)) || Date.parse(p.issuedAt) > now + L.issuedAheadMs) return 'E_PRIVATE_NETWORK_BAD_DATE';
    const issued = Date.parse(p.issuedAt); const expires = Date.parse(p.expiresAt);
    if (expires <= issued || expires - issued > L.maxValidityMs) return 'E_PRIVATE_NETWORK_BAD_DATE';
    if (!(p.version >= 1)) return 'E_PRIVATE_NETWORK_UNSIGNED';
    return null;
  };
  // 13.4 and 13.6.
  const decide = (c) => {
    const st = c.state;
    if (c.options.fileBytes > L.fileBytes) return 'E_PRIVATE_NETWORK_TOO_LARGE';
    const bad = verifyProfile(c.incoming, st.nowMs);
    if (bad) return bad;
    if (Date.parse(c.incoming.expiresAt) <= st.nowMs) return 'E_PRIVATE_NETWORK_EXPIRED';
    const admin = c.incoming.admin;
    const handedOver = Boolean(st.handover && st.currentAdmin === st.handover.from && admin === st.handover.to && Date.parse(st.handover.expiresAt) > st.nowMs);
    if (!handedOver && st.currentAdmin && st.currentAdmin !== admin && !c.options.replace) return 'E_PRIVATE_NETWORK_OTHER_ADMIN';
    if (!handedOver && (!st.currentAdmin || st.currentAdmin !== admin)) {
      const want = String(c.options.expectAdmin || '').toLowerCase();
      if (!want) return 'E_PRIVATE_NETWORK_CONFIRM_ADMIN';
      if (want !== admin) return 'E_PRIVATE_NETWORK_ADMIN_MISMATCH';
    }
    if (st.retired.includes(admin)) return 'E_PRIVATE_NETWORK_RETIRED_ADMIN';
    const floor = Number(st.floor[admin]) || 0;
    if (c.incoming.version === floor && st.currentAdmin === admin && st.storedSignature !== c.incoming.signature) return 'E_PRIVATE_NETWORK_CONFLICT';
    if (c.incoming.version <= floor) return 'E_PRIVATE_NETWORK_OLDER';
    return 'accepted';
  };
  if (v.accept.length < 25) fail('fewer than 25 acceptance cases');
  for (const c of v.accept) {
    const got = decide(c);
    const want = c.expected.error || c.expected.decision;
    if (got !== want) fail(`${c.name}: expected ${want}, got ${got}`);
  }
  for (const needed of ['olderVersionIsRefused', 'sameVersionDifferentSignatureIsAConflict', 'versionFloorSurvivesLeavingTheNetwork', 'expiredProfileIsRefused', 'issuedMoreThan24HoursAheadIsRefused', 'fileAboveOneMebibyteIsRefused', 'retiredAdministratorCannotSignAgain']) {
    if (!v.accept.some((c) => c.name === needed && c.expected.error)) fail(`${needed} must be refused`);
  }
  // 13.2: the network identifier of 14.5.
  const created = Buffer.alloc(8); created.writeBigUInt64BE(BigInt(v.networkId.createdAtMs));
  const nid = sha384Of(Buffer.concat([Buffer.from('pal3-id-network-v1\0', 'latin1'), unhex(v.networkId.creator), unhex(v.networkId.nonceHex), created]));
  if (hexOf(nid) !== v.networkId.expectedHex) fail('networkId');
  const h = v.handoverExample;
  const handoverBytes = 'palexplorer-private-network-handover-v1\n' + JSON.stringify({ name: h.name, from: h.from, to: h.to, issuedAt: h.issuedAt, expiresAt: h.expiresAt });
  if (!edVerify(handoverBytes, h.signature, h.from)) fail('handover signature');
  if (Date.parse(h.expiresAt) - Date.parse(h.issuedAt) > 30 * 24 * 3600 * 1000) fail('handover lifetime above 30 days');
  // 13.5: stored profile, members, hosts.
  const stateOf = (c) => {
    const p = c.profile;
    const isAdminDevice = Boolean(p.admin) && p.admin === c.localPublicKey.toLowerCase();
    if (p.signature) { if (verifyProfile(p, c.nowMs)) return 'lockdown'; } else if (!isAdminDevice) return 'lockdown';
    if (p.expiresAt && Date.parse(p.expiresAt) <= c.nowMs && !isAdminDevice) return 'lockdown';
    return 'active';
  };
  for (const c of v.state) if (stateOf(c) !== c.expected.mode) fail(`state ${c.name}: expected ${c.expected.mode}, got ${stateOf(c)}`);
  const profile = v.activeProfile;
  if (verifyProfile(profile, v.nowMs)) fail('the active profile must verify');
  for (const m of v.members) {
    const got = Boolean(profile.members.find((x) => x.publicKey === String(m.publicKey).toLowerCase() && !x.revoked));
    if (got !== m.allowed) fail(`member ${m.name}`);
  }
  const hostOf = (url) => { try { return new URL(/^[a-z]+:\/\//i.test(url) ? url : `https://${url}`); } catch { return null; } };
  const listed = new Set([...profile.discoveryServers, ...profile.relays].map((x) => hostOf(x)).filter(Boolean).map((u) => u.host.toLowerCase()));
  const names = new Set([...listed].map((x) => x.replace(/:\d+$/, '')));
  for (const c of v.hosts) {
    const u = hostOf(c.url);
    const got = Boolean(u && (listed.has(u.host.toLowerCase()) || names.has(u.hostname.toLowerCase().replace(/^\[|\]$/g, ''))));
    if (got !== c.allowed) fail(`host ${c.name}`);
  }
  return { ok: true, version: v.specVersion, accept: v.accept.length, state: v.state.length, members: v.members.length, hosts: v.hosts.length };
}

// 14.3: peer exchange without addresses, a model written from the specification text.
export function runPexValidation(v = vectorFile('pal3-v0.6-pex-vectors.json')) {
  const fail = (m) => { throw new Error(`pex vectors (14.3): ${m}`); };
  const L = v.limits;
  const PK = /^[0-9a-f]{64}$/;
  const ADDRESS_FIELDS = ['host', 'port', 'ip', 'address', 'addr', 'endpoint'];
  const run = (c) => {
    const table = new Map();
    const register = (pk, reporter) => {
      const verified = reporter === pk;
      const existing = table.get(pk);
      if (existing && !verified) return existing;
      if (!verified) {
        let mine = 0;
        for (const [k, e] of table) if (k !== pk && !e.verified && e.reporter === reporter) mine++;
        if (mine >= L.maxUnverifiedPerReporter) return null;
      }
      const entry = { peerPk: pk, verified, reporter };
      table.delete(pk);
      table.set(pk, entry);
      return entry;
    };
    for (const b of c.before) register(b.peerPk, b.reporterPk);
    const learned = [];
    const peers = Array.isArray(c.response?.peers) ? c.response.peers.slice(0, L.maxEntries) : [];
    for (const p of peers) {
      const pk = String(p?.peerPk || '').toLowerCase();
      if (!PK.test(pk)) continue;
      const e = register(pk, c.reporterPk);
      if (e) learned.push({ peerPk: e.peerPk, verified: e.verified, reporter: e.reporter });
    }
    return { learned, stored: [...table.keys()].sort() };
  };
  if (v.receive.length < 8) fail('fewer than 8 receive cases');
  for (const c of v.receive) {
    const got = run(c);
    if (JSON.stringify(got.learned) !== JSON.stringify(c.expected.learned)) fail(`${c.name}: learned entries`);
    if (JSON.stringify(got.stored) !== JSON.stringify(c.expected.storedPeerPks)) fail(`${c.name}: stored peers`);
    for (const f of c.expected.storedFieldNames) if (ADDRESS_FIELDS.includes(f)) fail(`${c.name}: a stored entry carries ${f}`);
  }
  const hostEntry = v.receive.find((c) => c.name === 'addressFieldsAreIgnored');
  if (!hostEntry?.response.peers.some((p) => 'host' in p && 'port' in p)) fail('a case with host and port in the response is required');
  const r = v.respond;
  if (r.response.peers.length > L.maxEntries || r.expected.peerCount !== r.response.peers.length) fail('a response holds at most 32 entries');
  for (const p of r.response.peers) {
    if (Object.keys(p).join() !== 'peerPk' || !PK.test(p.peerPk)) fail('a response entry carries a public key only');
  }
  if (r.expected.invalidRootHashError !== 'E_PAL3_PEX_INVALID') fail('a root hash that is not 96 hexadecimal characters is refused');
  return { ok: true, version: v.specVersion, receive: v.receive.length, responded: r.response.peers.length };
}

// 4.1: N1 and N3 address rules, the N3 observation table, buddy.intro start times and the N6 relay reservation, written from the specification text.
export function runNatTraversalValidation(v = vectorFile('pal3-v0.6-nat-traversal-vectors.json')) {
  const fail = (m) => { throw new Error(`nat traversal vectors (4.1): ${m}`); };
  const L = v.limits;
  // IP classification.
  const parseIp = (raw) => {
    let s = String(raw).trim().toLowerCase();
    if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
    if (s.startsWith('::ffff:') && s.includes('.')) s = s.slice(7);
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) {
      const o = s.split('.').map(Number);
      return o.every((x) => x <= 255) ? { family: 4, o } : null;
    }
    if (!s.includes(':') || /[^0-9a-f:]/.test(s) || s.split('::').length > 2) return null;
    let groups;
    if (s.includes('::')) {
      const [a, b] = s.split('::');
      const head = a ? a.split(':') : [];
      const tail = b ? b.split(':') : [];
      if (head.length + tail.length > 7) return null;
      groups = [...head, ...Array(8 - head.length - tail.length).fill('0'), ...tail];
    } else groups = s.split(':');
    if (groups.length !== 8 || groups.some((g) => g.length < 1 || g.length > 4)) return null;
    return { family: 6, g: groups.map((x) => parseInt(x, 16)) };
  };
  const globalUnicast = (raw) => {
    const p = parseIp(raw);
    if (!p) return false;
    if (p.family === 4) {
      const [a, b] = p.o;
      return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127));
    }
    const g = p.g;
    if (g.every((x) => x === 0) || (g.slice(0, 7).every((x) => x === 0) && g[7] === 1)) return false;
    if (g[0] === 0x2001 && g[1] === 0x0db8) return false;
    if (g[0] === 0x3fff && (g[1] & 0xf000) === 0) return false;
    if ((g[0] & 0xffc0) === 0xfe80 || (g[0] & 0xfe00) === 0xfc00 || (g[0] & 0xff00) === 0xff00) return false;
    return (g[0] & 0xe000) === 0x2000;
  };
  if (v.addresses.length < 25) fail('fewer than 25 addresses');
  for (const a of v.addresses) if (globalUnicast(a.ip) !== a.globalUnicast) fail(`address ${a.name} (${a.ip}): expected ${a.globalUnicast}`);
  for (const n of ['ipv6Documentation2001Db8', 'ipv6Documentation3fff', 'ipv4CgnatLow', 'ipv4Private192']) if (v.addresses.find((a) => a.name === n)?.globalUnicast !== false) fail(`${n} must not be global unicast`);

  // N3.
  const prefixOf = (raw) => {
    const p = parseIp(raw);
    return p.family === 4 ? p.o.slice(0, 3).join('.') : p.g.slice(0, 3).join(':');
  };
  const runTracker = (sc) => {
    const obs = new Map();
    return sc.steps.map((s) => {
      for (const [k, e] of obs) if (s.atMs - e.ts >= L.observerTtlMs) obs.delete(k);
      if (!globalUnicast(s.observedIp)) return { accepted: false, reason: 'non-global-ip' };
      if (!Number.isInteger(s.observedPort) || s.observedPort < 1 || s.observedPort > 65535) return { accepted: false, reason: 'invalid-port' };
      const id = String(s.observer);
      const prefix = prefixOf(s.observerIp);
      for (const [k, e] of obs) if (e.prefix === prefix && k !== id) obs.delete(k);
      obs.delete(id);
      if (obs.size >= (sc.options.maxObservers ?? L.maxObservers)) obs.delete(obs.keys().next().value);
      obs.set(id, { prefix, ip: s.observedIp, port: s.observedPort, ts: s.atMs });
      const entries = [...obs.values()].sort((x, y) => x.ts - y.ts);
      let quorum = false; let ip = null; let port = null;
      if (entries.length === 1) { ip = entries[0].ip; port = entries[0].port; } else {
        const counts = new Map();
        for (const e of entries) counts.set(e.ip, (counts.get(e.ip) || 0) + 1);
        let best = null; let n = 0;
        for (const [k, c] of counts) if (c > n) { best = k; n = c; }
        if (n >= 2) { quorum = true; ip = best; port = entries.filter((e) => e.ip === best).map((e) => e.port).at(-1); }
      }
      return { accepted: true, quorumMet: quorum, verifiedIp: ip, verifiedPort: port, observers: obs.size };
    });
  };
  if (v.observations.length < 10) fail('fewer than 10 observation scenarios');
  for (const sc of v.observations) {
    const got = runTracker(sc);
    sc.steps.forEach((s, i) => { if (JSON.stringify(got[i]) !== JSON.stringify(s.expected)) fail(`observations ${sc.name}, step ${i}: expected ${JSON.stringify(s.expected)}, got ${JSON.stringify(got[i])}`); });
  }
  if (v.observations.find((s) => s.name === 'singleObservationIsNeverConfirmed')?.steps[0].expected.quorumMet !== false) fail('a single observation never meets the quorum');

  // buddy.intro.
  const clamp = (r) => Math.min(Math.max(r, 0), L.rttClampMs);
  for (const p of v.punchPlans) {
    const ri = clamp(p.initiatorRttMs); const rt = clamp(p.targetRttMs);
    const lead = Math.max(ri, rt) / 2 + L.punchMarginMs;
    if (Math.round(lead - ri / 2) !== p.initiatorStartInMs || Math.round(lead - rt / 2) !== p.targetStartInMs) fail(`punch plan ${p.initiatorRttMs}/${p.targetRttMs}`);
  }
  if (v.punchWithoutRtt.hasStartInMs !== false) fail('without a measured round trip the plan carries only punchAtMs');

  // N6.
  const R = v.relay;
  const pinOf = (edHex, dsaHex) => hexOf(sha384Of(Buffer.concat([ascii('pal3-identity-v1'), unhex(edHex), unhex(dsaHex)])));
  const ids = { relay: { ed: R.identities.relayEdPk, dsa: R.identities.relayDsaPk }, client: { ed: R.identities.clientEdPk, dsa: R.identities.clientDsaPk }, thief: { ed: R.identities.thiefEdPk, dsa: R.identities.thiefDsaPk } };
  for (const k of Object.keys(ids)) if (pinOf(ids[k].ed, ids[k].dsa) !== R.identities[`${k}Pin`]) fail(`${k} pin`);
  const verifyToken = (c) => {
    const session = c.sessionIdHex ? unhex(c.sessionIdHex) : null;
    if (!session || session.length !== 16) return 'E_PAL3_RELAY_INVALID';
    const env = decodePalCbor(unhex(c.tokenHex));
    const body = decodePalCbor(env.body);
    if (body.v !== 2 || !Buffer.isBuffer(body.relayDsaPk) || body.relayDsaPk.length !== 1952 || !Buffer.isBuffer(body.clientDigest) || body.clientDigest.length !== 48) return 'E_PAL3_RELAY_INVALID';
    const expected = R.identities[`${c.expectedRelayIdentity}Pin`];
    if (hexOf(sha384Of(Buffer.concat([ascii('pal3-identity-v1'), body.relayEdPk, body.relayDsaPk]))) !== expected) return 'E_PAL3_RELAY_ISSUER_MISMATCH';
    if (hexOf(body.clientDigest) !== R.identities[`${c.presenter}Pin`]) return 'E_PAL3_RELAY_CLIENT_MISMATCH';
    if (!body.sessionId.equals(session)) return 'E_PAL3_RELAY_SESSION_MISMATCH';
    if (BigInt(c.nowMs) >= body.expiresAtMs) return 'E_PAL3_RELAY_EXPIRED';
    if (body.issuedAtMs > BigInt(c.nowMs + L.clockSkewMs)) return 'E_PAL3_RELAY_INVALID';
    let ok = false;
    try { ok = verifyHybridObject({ domain: R.domain, dsaContext: R.dsaContext, signer: { edPkHex: hexOf(body.relayEdPk), dsaPkHex: hexOf(body.relayDsaPk) }, bodyHex: hexOf(env.body), sigEd25519Hex: hexOf(env.sigEd25519), sigMldsa65Hex: hexOf(env.sigMldsa65) }); } catch { ok = false; }
    return ok ? 'accepted' : 'E_PAL3_RELAY_AUTH_FAILED';
  };
  if (R.reservations.length < 12) fail('fewer than 12 reservation cases');
  for (const c of R.reservations) {
    const got = verifyToken(c);
    const want = c.expected.error || 'accepted';
    if (got !== want) fail(`reservation ${c.name}: expected ${want}, got ${got}`);
  }
  for (const n of ['wrongPresentingClient', 'wrongRelayPin', 'wrongSession', 'sessionNotGiven']) if (!R.reservations.find((c) => c.name === n)?.expected.error) fail(`${n} must be refused`);
  const first = R.reservations.find((c) => c.name === 'valid');
  const reservation = decodePalCbor(decodePalCbor(unhex(first.tokenHex)).body);
  if (Number(reservation.maxBytes) !== L.reservationDefaults.maxBytes || reservation.maxBandwidthBps !== L.reservationDefaults.maxBandwidthBps || Number(reservation.expiresAtMs - reservation.issuedAtMs) !== L.reservationDefaults.durationMs) fail('reservation defaults of 15 min, 256 MiB and 2 MiB/s');
  let used = 0; let tokens = R.quota.maxBandwidthBps; let last = 0;
  for (const s of R.quota.steps) {
    let got;
    if (s.atMs >= L.reservationDefaults.durationMs) got = { error: 'E_PAL3_RELAY_EXPIRED' };
    else if (used + s.bytes > R.quota.maxBytes) got = { error: 'E_PAL3_RELAY_QUOTA' };
    else {
      tokens = Math.min(R.quota.maxBandwidthBps, tokens + ((s.atMs - last) / 1000) * R.quota.maxBandwidthBps);
      last = s.atMs;
      if (s.bytes > tokens) got = { forwarded: false }; else { tokens -= s.bytes; used += s.bytes; got = { forwarded: true }; }
    }
    if (JSON.stringify(got) !== JSON.stringify(s.expected)) fail(`quota at ${s.atMs} ms for ${s.bytes} bytes: expected ${JSON.stringify(s.expected)}, got ${JSON.stringify(got)}`);
  }
  return { ok: true, version: v.specVersion, addresses: v.addresses.length, scenarios: v.observations.length, punch: v.punchPlans.length, reservations: R.reservations.length };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const res = runValidation();
  console.log(`PAL/3.0 conformance vectors (${res.version}) verified: PASS`);
  const sw = runSwarmValidation();
  const prim = runPrimitiveValidation();
  const ids = runIdentifierValidation();
  console.log(`PAL/3.0 identifiers verified (${ids.kinds} kinds, SHA-384): PASS`);
  console.log(`PAL/3.0 primitives verified (SHA-384 ${prim.sha384}, Merkle ${prim.merkle}, cookie and PoW, PSK binder, ${prim.revisions} manifest revision cases): PASS`);
  const core = runCoreValidation();
  console.log(`PAL/3.0 §7.1 operations (${core.operations}) and ${core.signed} hybrid-signed objects verified (${core.mldsaChecked ? 'Ed25519 and ML-DSA-65' : 'Ed25519 only: this Node cannot check ML-DSA-65 contexts, use Node 24+'}): PASS`);
  console.log(`PAL/3.0 §8.5 swarm vectors (${sw.version}, ${sw.checks} access cases) verified: PASS`);
  const rk = runRekeyValidation();
  console.log(`PAL/3.0 §5.3 rekey vectors (${rk.positive} derivations, ${rk.negative} rejections; ML-KEM-768 ${rk.validated}) verified: PASS`);
  const hp = runHeaderProtectionValidation();
  console.log(`PAL/3.0 §3.2 C2 header protection vectors (${hp.positive} packets, ${hp.negative} rejected) verified: PASS`);
  const sas = runSasValidation();
  console.log(`PAL/3.0 §10.5 Quick Drop SAS vectors (${sas.positive} codes, ${sas.negative} rejections) and §5.2 handshake SAS vectors (${sas.handshake} codes) verified: PASS`);
  const gr = runGrantValidation();
  console.log(`PAL/3.0 §9 grant vectors (${gr.positive} grants, ${gr.negative} rejections; ${gr.mldsaChecked ? 'Ed25519 and ML-DSA-65' : 'Ed25519 only'}) verified: PASS`);
  const ex = runExtensionSigningValidation();
  console.log(`PAL/3.0 §12.2 extension signing vectors (${ex.positive} bundles, ${ex.negative} rejections; ${ex.mldsaChecked ? 'Ed25519 and ML-DSA-65' : 'Ed25519 only'}) verified: PASS`);
  const sh = runSealedHelloValidation();
  console.log(`PAL/3.0 §5.1 SEALED_HELLO vectors (${sh.positive} records, ${sh.negative} rejections; ML-KEM-768 ${sh.validated}) verified: PASS`);
  const ss = runStoredStateValidation();
  console.log(`PAL/3.0 §12.5 stored-state migration vectors (${ss.cases} case, old form rejected, migrated form accepted; ${ss.mldsaChecked ? 'Ed25519 and ML-DSA-65' : 'Ed25519 only'}) verified: PASS`);
  const co = runChunkOutboardValidation();
  console.log(`PAL/3.0 §8.1.1 chunk outboard vectors (${co.contents} contents, ${co.negative} rejections, SHA-384) verified: PASS`);
  const ps = runPrivateShareValidation();
  console.log(`PAL/3.0 §8.3 private share vectors (${ps.blocks} blocks, ${ps.negative} rejections, HKDF-SHA-384 and ChaCha20-Poly1305) verified: PASS`);
  const dr = runDeviceRevocationValidation();
  console.log(`PAL/3.0 §11.3 device certificate and revocation vectors (${dr.certificates} certificates, ${dr.negative} rejected, ${dr.steps} receiver steps; ${dr.mldsaChecked ? 'Ed25519 and ML-DSA-65' : 'Ed25519 only'}) verified: PASS`);
  const rg = runRegistryValidation();
  console.log(`PAL/3.0 A.6 registry vectors (${rg.selection} HELLO decisions, ${rg.negative} registration rejections) verified: PASS`);
  const pt = runPlaintextRecordValidation();
  console.log(`PAL/3.0 §6.2 plaintext record vectors (${pt.records} records, ${pt.negative} rejections, ${pt.gate} gate scenarios) verified: PASS`);
  const ms = runMultiSealValidation();
  console.log(`PAL/3.0 §11.4 multi-recipient sealing vectors (${ms.sealed} sealed objects, ${ms.lists} device lists, ${ms.signed} device signatures, ${ms.negative} rejections; ML-KEM-768 ${ms.validated}) verified: PASS`);
  const hd = runHardeningValidation();
  console.log(`PAL/3.0 §11.2 hardening vectors (${hd.uri} URIs, ${hd.x25519} X25519 keys, ${hd.mlkem} ML-KEM keys, ${hd.scenarios} reassembly scenarios with ${hd.steps} steps) verified: PASS`);
  const lp = runLocalPolicyValidation();
  console.log(`PAL/3.0 §12.3 and §12.4 local policy vectors (${lp.sources} linter cases, ${lp.scenarios} limit scenarios with ${lp.steps} steps) verified: PASS`);
  const pn = runPrivateNetworkAcceptValidation();
  console.log(`PAL/3.0 §13.4-13.6 private network vectors (${pn.accept} acceptance decisions, ${pn.state} stored-profile states, ${pn.members} member and ${pn.hosts} host decisions) verified: PASS`);
  const px = runPexValidation();
  console.log(`PAL/3.0 §14.3 peer exchange vectors (${px.receive} receive cases, response of ${px.responded} entries, keys only) verified: PASS`);
  const nt = runNatTraversalValidation();
  console.log(`PAL/3.0 §4.1 NAT traversal vectors (${nt.addresses} addresses, ${nt.scenarios} observation scenarios, ${nt.punch} start-time plans, ${nt.reservations} relay reservations) verified: PASS`);
}
