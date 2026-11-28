// Generates test-vectors/v3/pal3-v0.6-sealed-relay-vectors.json for section 14.10 (relay-seal.v1 and relay-multihop.v1).
// Uses Node built-ins + encodePalCbor from validate.mjs + @noble/post-quantum (from pal-core) with extraEntropy: false for deterministic ML-DSA-65.
// Run: node bin/generate-v0.6-sealed-relay-vectors.mjs
import { createCipheriv, createHash, createHmac, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { existsSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { encodePalCbor } from '../validate.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const palCore = process.env.PAL_CORE || resolve(__dirname, '../../pal-core');
const mldsaPath = resolve(palCore, existsSync(resolve(palCore, 'node_modules/@noble/post-quantum/ml-dsa.js'))
  ? 'node_modules/@noble/post-quantum/ml-dsa.js'
  : 'packages/protocol/node_modules/@noble/post-quantum/ml-dsa.js');
const { ml_dsa65 } = await import(pathToFileURL(mldsaPath).href);

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SEALED_DOMAIN = 'pal3-relay-sealed-v1';
const BLIND_DOMAIN = 'pal3-relay-blind-v1';
const TOKEN_DOMAIN = 'pal3-relay-token-v1';
const CLOCK_SKEW_MS = 300_000;
const MULTIHOP_FRAME_TYPE = 0x52;
const MULTIHOP_MIN_PAYLOAD = 1;
const MULTIHOP_MAX_PAYLOAD = 1200;
const MULTIHOP_MAX_FRAME = 1227;
const REPLAY_WINDOW = 64;

const sha384 = (b) => createHash('sha384').update(b).digest();
const u64be = (n) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
};

function makeIdentity(edByte, dsaByte) {
  const edSeed = Buffer.alloc(32, edByte);
  const edPriv = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, edSeed]), format: 'der', type: 'pkcs8' });
  const edPk = createPublicKey(edPriv).export({ format: 'der', type: 'spki' }).subarray(-32);
  const dsaSeed = Buffer.alloc(32, dsaByte);
  const dsa = ml_dsa65.keygen(dsaSeed);
  const dsaPk = Buffer.from(dsa.publicKey);
  const digest = sha384(Buffer.concat([Buffer.from('pal3-identity-v1', 'ascii'), edPk, dsaPk]));
  return {
    edSeedHex: edSeed.toString('hex'),
    edPk,
    edPkHex: edPk.toString('hex'),
    edPriv,
    dsaSeedHex: dsaSeed.toString('hex'),
    dsaPk,
    dsaPkHex: dsaPk.toString('hex'),
    dsaSecretKey: dsa.secretKey,
    identityDigest: digest,
    identityDigestHex: digest.toString('hex'),
  };
}

function flipLastByte(hex) {
  const b = Buffer.from(hex, 'hex');
  b[b.length - 1] ^= 0x01;
  return b.toString('hex');
}

function computeBlindClientId(rClient, clientDigest, sessionId) {
  return createHmac('sha384', rClient)
    .update(Buffer.concat([Buffer.from(BLIND_DOMAIN, 'ascii'), Buffer.from([0x00]), clientDigest, sessionId]))
    .digest();
}

function sealRelayToken({ relayKey, nonce, sessionId, blindClientId, issuedAtMs, expiresAtMs, byteQuota, bandwidthBps }) {
  const aad = Buffer.concat([Buffer.from(TOKEN_DOMAIN, 'ascii'), Buffer.from([0x00]), sessionId, blindClientId]);
  const plain = Buffer.concat([u64be(issuedAtMs), u64be(expiresAtMs), u64be(byteQuota), u64be(bandwidthBps)]);
  const cipher = createCipheriv('chacha20-poly1305', relayKey, nonce, { authTagLength: 16 });
  cipher.setAAD(aad, { plaintextLength: plain.length });
  const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { aad, plain, token: Buffer.concat([nonce, ct, tag]) };
}

function buildSealedReservation({
  name,
  relay,
  client,
  sessionId,
  rClient,
  relayKey,
  tokenNonce,
  issuedAtMs,
  expiresAtMs,
  byteQuota,
  bandwidthBps,
  nowMs,
}) {
  const blindClientId = computeBlindClientId(rClient, client.identityDigest, sessionId);
  const body = encodePalCbor({
    v: 1,
    sessionId,
    relayEdPk: relay.edPk,
    relayDsaPk: relay.dsaPk,
    blindClientId,
    issuedAtMs: BigInt(issuedAtMs),
    expiresAtMs: BigInt(expiresAtMs),
    byteQuota: BigInt(byteQuota),
    bandwidthBps: BigInt(bandwidthBps),
  });
  const msg = Buffer.concat([Buffer.from(SEALED_DOMAIN, 'ascii'), sha384(body)]);
  const sigEd25519 = sign(null, msg, relay.edPriv);
  const sigMldsa65 = Buffer.from(
    ml_dsa65.sign(msg, relay.dsaSecretKey, { context: Buffer.from(SEALED_DOMAIN, 'ascii'), extraEntropy: false })
  );
  const tok = sealRelayToken({
    relayKey,
    nonce: tokenNonce,
    sessionId,
    blindClientId,
    issuedAtMs,
    expiresAtMs,
    byteQuota,
    bandwidthBps,
  });
  return {
    name,
    nowMs,
    sessionIdHex: sessionId.toString('hex'),
    rClientHex: rClient.toString('hex'),
    clientIdentityDigestHex: client.identityDigestHex,
    blindClientIdHex: blindClientId.toString('hex'),
    expectedRelayPinHex: relay.identityDigestHex,
    expectedClientPinHex: client.identityDigestHex,
    relayKeyHex: relayKey.toString('hex'),
    tokenNonceHex: tokenNonce.toString('hex'),
    tokenAadHex: tok.aad.toString('hex'),
    tokenPlainHex: tok.plain.toString('hex'),
    relayTokenHex: tok.token.toString('hex'),
    issuedAtMs,
    expiresAtMs,
    byteQuota,
    bandwidthBps,
    bodyHex: body.toString('hex'),
    signedMessageHex: msg.toString('hex'),
    sigEd25519Hex: sigEd25519.toString('hex'),
    sigMldsa65Hex: sigMldsa65.toString('hex'),
  };
}

function encodeMultihopFrame({ frameType = MULTIHOP_FRAME_TYPE, sessionId, seq, payload }) {
  const head = Buffer.alloc(1 + 16 + 8 + 2);
  head.writeUInt8(frameType, 0);
  sessionId.copy(head, 1);
  head.writeBigUInt64BE(BigInt(seq), 17);
  head.writeUInt16BE(payload.length, 25);
  return Buffer.concat([head, payload]);
}

const relay = makeIdentity(0x41, 0x51);
const wrongRelay = makeIdentity(0x42, 0x52);
const client = makeIdentity(0x43, 0x53);
const clientTwo = makeIdentity(0x44, 0x54);

const BASE_TIME = 1794744000000;
const relayKey = Buffer.alloc(32, 0x77);

const sealCase1 = buildSealedReservation({
  name: 'defaultSealedReservation',
  relay,
  client,
  sessionId: Buffer.alloc(16, 0x10),
  rClient: Buffer.alloc(32, 0xa1),
  relayKey,
  tokenNonce: Buffer.alloc(12, 0x01),
  issuedAtMs: BASE_TIME,
  expiresAtMs: BASE_TIME + 900_000,
  byteQuota: 268_435_456,
  bandwidthBps: 2_097_152,
  nowMs: BASE_TIME + 10_000,
});

const sealCase2 = buildSealedReservation({
  name: 'customQuotaDifferentClient',
  relay,
  client: clientTwo,
  sessionId: Buffer.alloc(16, 0x20),
  rClient: Buffer.alloc(32, 0xa2),
  relayKey,
  tokenNonce: Buffer.alloc(12, 0x02),
  issuedAtMs: BASE_TIME + 60_000,
  expiresAtMs: BASE_TIME + 1_860_000,
  byteQuota: 67_108_864,
  bandwidthBps: 524_288,
  nowMs: BASE_TIME + 120_000,
});

const sealCase3 = buildSealedReservation({
  name: 'withinClockSkewAllowance',
  relay,
  client,
  sessionId: Buffer.alloc(16, 0x30),
  rClient: Buffer.alloc(32, 0xa3),
  relayKey: Buffer.alloc(32, 0x78),
  tokenNonce: Buffer.alloc(12, 0x03),
  issuedAtMs: BASE_TIME + CLOCK_SKEW_MS,
  expiresAtMs: BASE_TIME + CLOCK_SKEW_MS + 900_000,
  byteQuota: 268_435_456,
  bandwidthBps: 2_097_152,
  nowMs: BASE_TIME,
});

const badSessionLen = buildSealedReservation({
  name: 'invalidSessionIdLength',
  relay,
  client,
  sessionId: Buffer.alloc(15, 0x10),
  rClient: Buffer.alloc(32, 0xb1),
  relayKey,
  tokenNonce: Buffer.alloc(12, 0x11),
  issuedAtMs: BASE_TIME,
  expiresAtMs: BASE_TIME + 900_000,
  byteQuota: 268_435_456,
  bandwidthBps: 2_097_152,
  nowMs: BASE_TIME + 10_000,
});

const futureIssued = buildSealedReservation({
  name: 'issuedTooFarInFuture',
  relay,
  client,
  sessionId: Buffer.alloc(16, 0x15),
  rClient: Buffer.alloc(32, 0xb2),
  relayKey,
  tokenNonce: Buffer.alloc(12, 0x12),
  issuedAtMs: BASE_TIME + CLOCK_SKEW_MS + 1,
  expiresAtMs: BASE_TIME + CLOCK_SKEW_MS + 900_001,
  byteQuota: 268_435_456,
  bandwidthBps: 2_097_152,
  nowMs: BASE_TIME,
});

const relaySealRejected = [
  {
    ...badSessionLen,
    checkSide: 'pal',
    expectedError: 'E_PAL3_RELAY_INVALID',
    description: 'sessionId shorter than 16 bytes must be rejected with E_PAL3_RELAY_INVALID.',
  },
  {
    ...sealCase1,
    name: 'relayPinMismatch',
    checkSide: 'pal',
    expectedRelayPinHex: wrongRelay.identityDigestHex,
    expectedError: 'E_PAL3_RELAY_ISSUER_MISMATCH',
    description: 'Relay hybrid identity digest does not match pinned relay.',
  },
  {
    ...sealCase1,
    name: 'blindClientIdWrongNonce',
    checkSide: 'pal',
    rClientHex: flipLastByte(sealCase1.rClientHex),
    expectedError: 'E_PAL3_RELAY_BLIND_MISMATCH',
    description: 'Wrong rClient blinding nonce fails constant-time blindClientId verification.',
  },
  {
    ...sealCase1,
    name: 'clientIdentityMismatch',
    checkSide: 'pal',
    expectedClientPinHex: clientTwo.identityDigestHex,
    expectedError: 'E_PAL3_RELAY_BLIND_MISMATCH',
    description: 'clientIdentityDigest does not match the expected pal hybrid identity.',
  },
  {
    ...futureIssued,
    checkSide: 'pal',
    expectedError: 'E_PAL3_RELAY_INVALID',
    description: 'issuedAtMs more than 300,000 ms in the future must be rejected.',
  },
  {
    ...sealCase1,
    name: 'expiredReservation',
    checkSide: 'pal',
    nowMs: sealCase1.expiresAtMs,
    expectedError: 'E_PAL3_RELAY_EXPIRED',
    description: 'Reservation at or past expiresAtMs must be rejected.',
  },
  {
    ...sealCase1,
    name: 'tamperedEd25519Signature',
    checkSide: 'pal',
    sigEd25519Hex: flipLastByte(sealCase1.sigEd25519Hex),
    expectedError: 'E_PAL3_RELAY_AUTH_FAILED',
    description: 'Strict-AND: bit flip in Ed25519 signature must fail.',
  },
  {
    ...sealCase1,
    name: 'tamperedMldsa65Signature',
    checkSide: 'pal',
    sigMldsa65Hex: flipLastByte(sealCase1.sigMldsa65Hex),
    expectedError: 'E_PAL3_RELAY_AUTH_FAILED',
    description: 'Strict-AND: bit flip in ML-DSA-65 signature must fail.',
  },
  {
    ...sealCase1,
    name: 'relayTokenTampered',
    checkSide: 'relay',
    relayTokenHex: flipLastByte(sealCase1.relayTokenHex),
    expectedError: 'E_PAL3_RELAY_INVALID',
    description: 'Tampered relayToken AEAD tag must be rejected on relay presentation.',
  },
  {
    ...sealCase1,
    name: 'relayTokenWrongSessionBinding',
    checkSide: 'relay',
    presentedSessionIdHex: Buffer.alloc(16, 0x99).toString('hex'),
    expectedError: 'E_PAL3_RELAY_INVALID',
    description: 'Presenting relayToken under a different sessionId fails AAD binding.',
  },
  {
    ...sealCase1,
    name: 'relayTokenExpired',
    checkSide: 'relay',
    nowMs: sealCase1.expiresAtMs,
    expectedError: 'E_PAL3_RELAY_EXPIRED',
    description: 'Presenting a valid relayToken at or after expiresAtMs fails with E_PAL3_RELAY_EXPIRED.',
  },
];

// Multi-hop carried sessions (relay-multihop.v1)
const sessionId1 = Buffer.alloc(16, 0x10);
const sessionId2 = Buffer.alloc(16, 0x20);
const opaqueSmall = Buffer.from('pal3-c2-opaque-record-payload-01', 'utf8');
const opaqueMax = Buffer.from(Array.from({ length: MULTIHOP_MAX_PAYLOAD }, (_, i) => (i * 19 + 7) & 0xff));

const inboundSmall = encodeMultihopFrame({ sessionId: sessionId1, seq: 7, payload: opaqueSmall });
const outboundSmall = encodeMultihopFrame({ sessionId: sessionId2, seq: 0, payload: opaqueSmall });
const inboundMax = encodeMultihopFrame({ sessionId: sessionId1, seq: 8, payload: opaqueMax });
const outboundMax = encodeMultihopFrame({ sessionId: sessionId2, seq: 1, payload: opaqueMax });

const relayMultihop = {
  capability: 'relay-multihop.v1',
  sessionId1Hex: sessionId1.toString('hex'),
  sessionId2Hex: sessionId2.toString('hex'),
  bridgeFrames: [
    {
      name: 'basicBridgeRewrite',
      optedIn: true,
      privacyMode: 'normal',
      inboundSeq: 7,
      outboundSeq: 0,
      opaqueRecordHex: opaqueSmall.toString('hex'),
      inboundFrameHex: inboundSmall.toString('hex'),
      outboundFrameHex: outboundSmall.toString('hex'),
    },
    {
      name: 'maxPaddedFrame1200',
      optedIn: true,
      privacyMode: 'maximum',
      inboundSeq: 8,
      outboundSeq: 1,
      opaqueRecordHex: opaqueMax.toString('hex'),
      inboundFrameHex: inboundMax.toString('hex'),
      outboundFrameHex: outboundMax.toString('hex'),
    },
  ],
  replayWindowSequence: {
    windowSize: REPLAY_WINDOW,
    steps: [
      { seq: 0, expected: 'accepted' },
      { seq: 10, expected: 'accepted' },
      { seq: 5, expected: 'accepted' },
      { seq: 64, expected: 'accepted' },
      { seq: 1, expected: 'accepted' },
      { seq: 63, expected: 'accepted' },
    ],
  },
};

const wrongTypeFrame = encodeMultihopFrame({ frameType: 0x51, sessionId: sessionId1, seq: 0, payload: opaqueSmall });
const zeroLenFrame = encodeMultihopFrame({ sessionId: sessionId1, seq: 0, payload: Buffer.alloc(0) });
const tooLargePayload = Buffer.alloc(MULTIHOP_MAX_PAYLOAD + 1, 0xaa);
const tooLargeFrame = encodeMultihopFrame({ sessionId: sessionId1, seq: 0, payload: tooLargePayload });
const truncatedFrame = inboundSmall.subarray(0, inboundSmall.length - 1);

const relayMultihopRejected = [
  {
    name: 'notEnabledByOptIn',
    kind: 'policy',
    optedIn: false,
    frameHex: inboundSmall.toString('hex'),
    expectedError: 'E_PAL3_RELAY_NOT_ENABLED',
    description: 'Multi-hop carried sessions require explicit opt-in and are never enabled by default.',
  },
  {
    name: 'wrongFrameType',
    kind: 'frame',
    optedIn: true,
    frameHex: wrongTypeFrame.toString('hex'),
    expectedError: 'E_PAL3_RELAY_INVALID',
    description: 'frame_type != 0x52 must be dropped.',
  },
  {
    name: 'zeroPayloadLength',
    kind: 'frame',
    optedIn: true,
    frameHex: zeroLenFrame.toString('hex'),
    expectedError: 'E_PAL3_RELAY_INVALID',
    description: 'payload_len == 0 must be dropped.',
  },
  {
    name: 'payloadExceeds1200Bytes',
    kind: 'frame',
    optedIn: true,
    frameHex: tooLargeFrame.toString('hex'),
    expectedError: 'E_PAL3_RELAY_INVALID',
    description: 'payload_len > 1200 must be dropped.',
  },
  {
    name: 'mismatchedByteLength',
    kind: 'frame',
    optedIn: true,
    frameHex: truncatedFrame.toString('hex'),
    expectedError: 'E_PAL3_RELAY_INVALID',
    description: 'Frame whose byte length does not equal 27 + payload_len must be dropped.',
  },
  {
    name: 'duplicateSequence',
    kind: 'replay',
    optedIn: true,
    priorAcceptedSeqs: [0, 1, 2],
    seq: 1,
    expectedError: 'E_PAL3_RELAY_REPLAY',
    description: 'Duplicate sequence number on the same leg must be dropped with E_PAL3_RELAY_REPLAY.',
  },
  {
    name: 'belowReplayWindow',
    kind: 'replay',
    optedIn: true,
    priorAcceptedSeqs: [10, 64],
    seq: 0,
    expectedError: 'E_PAL3_RELAY_REPLAY',
    description: 'Sequence number below the 64-entry sliding replay window (highest 64 -> floor 1) must be dropped with E_PAL3_RELAY_REPLAY.',
  },
];

const out = {
  specVersion: '3.0.0-draft.6.23',
  description: 'Sealed relay reservations (relay-seal.v1) and multi-hop carried sessions (relay-multihop.v1) of section 14.10.',
  capabilities: {
    sealedReservation: 'relay-seal.v1',
    multihopCarried: 'relay-multihop.v1',
  },
  limits: {
    sessionIdBytes: 16,
    blindClientIdBytes: 48,
    rClientBytes: 32,
    relayTokenBytes: 60,
    clockSkewMs: CLOCK_SKEW_MS,
    multihopFrameType: MULTIHOP_FRAME_TYPE,
    multihopMinPayloadBytes: MULTIHOP_MIN_PAYLOAD,
    multihopMaxPayloadBytes: MULTIHOP_MAX_PAYLOAD,
    multihopMaxFrameBytes: MULTIHOP_MAX_FRAME,
    replayWindowSize: REPLAY_WINDOW,
  },
  identities: {
    relay: { edSeedHex: relay.edSeedHex, edPkHex: relay.edPkHex, dsaSeedHex: relay.dsaSeedHex, dsaPkHex: relay.dsaPkHex, identityDigestHex: relay.identityDigestHex },
    wrongRelay: { edSeedHex: wrongRelay.edSeedHex, edPkHex: wrongRelay.edPkHex, dsaSeedHex: wrongRelay.dsaSeedHex, dsaPkHex: wrongRelay.dsaPkHex, identityDigestHex: wrongRelay.identityDigestHex },
    client: { edSeedHex: client.edSeedHex, edPkHex: client.edPkHex, dsaSeedHex: client.dsaSeedHex, dsaPkHex: client.dsaPkHex, identityDigestHex: client.identityDigestHex },
    clientTwo: { edSeedHex: clientTwo.edSeedHex, edPkHex: clientTwo.edPkHex, dsaSeedHex: clientTwo.dsaSeedHex, dsaPkHex: clientTwo.dsaPkHex, identityDigestHex: clientTwo.identityDigestHex },
  },
  relaySeal: [sealCase1, sealCase2, sealCase3],
  relaySealRejected,
  relayMultihop,
  relayMultihopRejected,
};

writeFileSync(
  new URL('../test-vectors/v3/pal3-v0.6-sealed-relay-vectors.json', import.meta.url),
  JSON.stringify(out, null, 2) + '\n'
);
