// Generates pal3-v0.6-private-network-vectors.json from the signed-bytes definition in section 13 of the specification.
// Uses Node built-ins for Ed25519 and @noble/post-quantum (from pal-core) with extraEntropy: false for deterministic ML-DSA-65.
// Run: node test-vectors/v3/pal3-v0.6-private-network-generate.mjs
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { existsSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const palCore = process.env.PAL_CORE || resolve(__dirname, '../../../pal-core');
const mldsaPath = resolve(palCore, existsSync(resolve(palCore, 'node_modules/@noble/post-quantum/ml-dsa.js'))
  ? 'node_modules/@noble/post-quantum/ml-dsa.js'
  : 'packages/protocol/node_modules/@noble/post-quantum/ml-dsa.js');
const { ml_dsa65 } = await import(pathToFileURL(mldsaPath).href);

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const PROFILE_V3_CONTEXT = 'palexplorer-private-network-v3\n';
const PROFILE_V4_CONTEXT = 'palexplorer-private-network-v4\n';
const PROFILE_V4_DSA_CONTEXT = 'palexplorer-private-network-v4';
const HANDOVER_V1_CONTEXT = 'palexplorer-private-network-handover-v1\n';
const HANDOVER_V2_CONTEXT = 'palexplorer-private-network-handover-v2\n';
const HANDOVER_V2_DSA_CONTEXT = 'palexplorer-private-network-handover-v2';

function keyFromSeed(seedByte, dsaSeedByte) {
  const seed = Buffer.alloc(32, seedByte);
  const privateKey = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: 'der', type: 'pkcs8' });
  const publicHex = createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
  const dsaSeed = Buffer.alloc(32, dsaSeedByte);
  const dsa = ml_dsa65.keygen(dsaSeed);
  const dsaPublicHex = Buffer.from(dsa.publicKey).toString('hex');
  return { seedHex: seed.toString('hex'), publicHex, privateKey, dsaSeedHex: dsaSeed.toString('hex'), dsaPublicHex, dsaSecretKey: dsa.secretKey };
}

function flipLastByte(hex) {
  const b = Buffer.from(hex, 'hex');
  b[b.length - 1] ^= 0x01;
  return b.toString('hex');
}

function identityPinHex(edPkHex, dsaPkHex) {
  return createHash('sha384')
    .update('pal3-identity-v1')
    .update(Buffer.from(edPkHex, 'hex'))
    .update(Buffer.from(dsaPkHex, 'hex'))
    .digest('hex');
}

function signV4Profile(p, signer, dsaContext = PROFILE_V4_DSA_CONTEXT) {
  const signedBytes = Buffer.from(PROFILE_V4_CONTEXT + JSON.stringify({
    name: p.name,
    admin: p.admin,
    adminDsaPublicKey: p.adminDsaPublicKey,
    discoveryServers: p.discoveryServers,
    relays: p.relays,
    members: p.members.map((m) => ({
      publicKey: m.publicKey,
      dsaPublicKey: m.dsaPublicKey ?? null,
      name: m.name ?? null,
      revoked: m.revoked,
    })),
    privacyMode: p.privacyMode,
    issuedAt: p.issuedAt,
    version: p.version,
    expiresAt: p.expiresAt,
    networkId: p.networkId ?? null,
    networkCreator: p.networkCreator ?? null,
    networkNonce: p.networkNonce ?? null,
    networkCreatedAtMs: p.networkCreatedAtMs ?? null,
  }), 'utf8');
  const signature = sign(null, signedBytes, signer.privateKey).toString('hex');
  const signatureMldsa65 = Buffer.from(
    ml_dsa65.sign(signedBytes, signer.dsaSecretKey, { context: Buffer.from(dsaContext, 'ascii'), extraEntropy: false })
  ).toString('hex');
  return { object: { ...p, signature, signatureMldsa65 }, signedBytes };
}

function signV2Handover(h, signer, dsaContext = HANDOVER_V2_DSA_CONTEXT) {
  const signedBytes = Buffer.from(HANDOVER_V2_CONTEXT + JSON.stringify({
    name: h.name,
    from: h.from,
    fromDsaPublicKey: h.fromDsaPublicKey,
    to: h.to,
    toDsaPublicKey: h.toDsaPublicKey,
    issuedAt: h.issuedAt,
    expiresAt: h.expiresAt,
  }), 'utf8');
  const signature = sign(null, signedBytes, signer.privateKey).toString('hex');
  const signatureMldsa65 = Buffer.from(
    ml_dsa65.sign(signedBytes, signer.dsaSecretKey, { context: Buffer.from(dsaContext, 'ascii'), extraEntropy: false })
  ).toString('hex');
  return { object: { ...h, signature, signatureMldsa65 }, signedBytes };
}

const admin = keyFromSeed(0x01, 0x11);
const memberOne = keyFromSeed(0x02, 0x12);
const memberTwo = keyFromSeed(0x03, 0x13);

// Legacy v3 profile (preserved verbatim for backward-compatibility tests and transition vectors).
const profile = {
  name: 'Example Network',
  admin: admin.publicHex,
  discoveryServers: ['https://discovery.example.org'],
  relays: ['relay.example.org:3478'],
  members: [
    { publicKey: memberOne.publicHex, name: 'Alice', revoked: false },
    { publicKey: memberTwo.publicHex, name: null, revoked: true },
  ],
  privacyMode: 'normal',
  issuedAt: '2026-11-15T10:00:00.000Z',
  version: 3,
  expiresAt: '2026-12-15T10:00:00.000Z',
};

const profileSigned = Buffer.from(PROFILE_V3_CONTEXT + JSON.stringify({
  name: profile.name, admin: profile.admin, discoveryServers: profile.discoveryServers, relays: profile.relays,
  members: profile.members.map((m) => ({ publicKey: m.publicKey, name: m.name, revoked: m.revoked })),
  privacyMode: profile.privacyMode, issuedAt: profile.issuedAt, version: profile.version, expiresAt: profile.expiresAt,
  networkId: null, networkCreator: null, networkNonce: null, networkCreatedAtMs: null,
}), 'utf8');
const profileV3Object = { ...profile, signature: sign(null, profileSigned, admin.privateKey).toString('hex') };

// Legacy v1 handover (preserved verbatim).
const handover = {
  name: profile.name,
  from: admin.publicHex,
  to: memberOne.publicHex,
  issuedAt: '2026-11-15T10:00:00.000Z',
  expiresAt: '2026-12-15T10:00:00.000Z',
};
const handoverSigned = Buffer.from(HANDOVER_V1_CONTEXT + JSON.stringify({
  name: handover.name, from: handover.from, to: handover.to, issuedAt: handover.issuedAt, expiresAt: handover.expiresAt,
}), 'utf8');
const handoverV1Object = { ...handover, signature: sign(null, handoverSigned, admin.privateKey).toString('hex') };

// Hybrid v4 profile (§13.1, §13.2).
const profileV4Base = {
  name: 'Example Network',
  admin: admin.publicHex,
  adminDsaPublicKey: admin.dsaPublicHex,
  discoveryServers: ['https://discovery.example.org'],
  relays: ['relay.example.org:3478'],
  members: [
    { publicKey: memberOne.publicHex, dsaPublicKey: memberOne.dsaPublicHex, name: 'Alice', revoked: false },
    { publicKey: memberTwo.publicHex, dsaPublicKey: null, name: null, revoked: true },
  ],
  privacyMode: 'normal',
  issuedAt: '2026-11-15T10:00:00.000Z',
  version: 4,
  expiresAt: '2026-12-15T10:00:00.000Z',
};
const profileV4Built = signV4Profile(profileV4Base, admin);

// Hybrid v2 handover (§13.3).
const handoverV2Base = {
  name: profileV4Base.name,
  from: admin.publicHex,
  fromDsaPublicKey: admin.dsaPublicHex,
  to: memberOne.publicHex,
  toDsaPublicKey: memberOne.dsaPublicHex,
  issuedAt: '2026-11-15T10:00:00.000Z',
  expiresAt: '2026-12-15T10:00:00.000Z',
};
const handoverV2Built = signV2Handover(handoverV2Base, admin);

// Higher-version v3 profile used to test the v4 -> v3 downgrade prohibition.
const downgradeV3ProfileBase = { ...profile, version: 5 };
const downgradeV3Signed = Buffer.from(PROFILE_V3_CONTEXT + JSON.stringify({
  name: downgradeV3ProfileBase.name, admin: downgradeV3ProfileBase.admin, discoveryServers: downgradeV3ProfileBase.discoveryServers, relays: downgradeV3ProfileBase.relays,
  members: downgradeV3ProfileBase.members.map((m) => ({ publicKey: m.publicKey, name: m.name, revoked: m.revoked })),
  privacyMode: downgradeV3ProfileBase.privacyMode, issuedAt: downgradeV3ProfileBase.issuedAt, version: downgradeV3ProfileBase.version, expiresAt: downgradeV3ProfileBase.expiresAt,
  networkId: null, networkCreator: null, networkNonce: null, networkCreatedAtMs: null,
}), 'utf8');
const downgradeV3ProfileObject = { ...downgradeV3ProfileBase, signature: sign(null, downgradeV3Signed, admin.privateKey).toString('hex') };

// Negative cases for §13.1-§13.3 hybrid rules.
const { signatureMldsa65: _dropSig, ...profileMissingMldsa } = profileV4Built.object;
const { adminDsaPublicKey: _dropKey, ...profileMissingAdminDsa } = profileV4Built.object;
const profileWrongContext = signV4Profile(profileV4Base, admin, 'palexplorer-private-network-v3').object;
const profileActiveMissingDsa = signV4Profile({
  ...profileV4Base,
  members: [
    { publicKey: memberOne.publicHex, dsaPublicKey: null, name: 'Alice', revoked: false },
  ],
}, admin).object;
const handoverWrongContext = signV2Handover(handoverV2Base, admin, 'palexplorer-private-network-handover-v1').object;

const hybridRejected = [
  {
    name: 'profileV4MissingMldsaSignature',
    kind: 'profile',
    priorV4Accepted: false,
    object: profileMissingMldsa,
    expectedError: 'E_PRIVATE_NETWORK_UNSIGNED',
    description: 'adminDsaPublicKey present without signatureMldsa65 must be rejected (§13.1).',
  },
  {
    name: 'profileV4MissingAdminDsaKey',
    kind: 'profile',
    priorV4Accepted: false,
    object: profileMissingAdminDsa,
    expectedError: 'E_PRIVATE_NETWORK_UNSIGNED',
    description: 'signatureMldsa65 present without adminDsaPublicKey must be rejected (§13.1).',
  },
  {
    name: 'profileV4TamperedEd25519Signature',
    kind: 'profile',
    priorV4Accepted: false,
    object: { ...profileV4Built.object, signature: flipLastByte(profileV4Built.object.signature) },
    expectedError: 'E_PRIVATE_NETWORK_BAD_SIGNATURE',
    description: 'Strict-AND: a single bit flip in the Ed25519 signature must fail even when ML-DSA-65 is valid (§13.2).',
  },
  {
    name: 'profileV4TamperedMldsa65Signature',
    kind: 'profile',
    priorV4Accepted: false,
    object: { ...profileV4Built.object, signatureMldsa65: flipLastByte(profileV4Built.object.signatureMldsa65) },
    expectedError: 'E_PRIVATE_NETWORK_BAD_SIGNATURE',
    description: 'Strict-AND: a single bit flip in the ML-DSA-65 signature must fail even when Ed25519 is valid (§13.2).',
  },
  {
    name: 'profileV4WrongMldsaContext',
    kind: 'profile',
    priorV4Accepted: false,
    object: profileWrongContext,
    expectedError: 'E_PRIVATE_NETWORK_BAD_SIGNATURE',
    description: 'ML-DSA-65 signature created with the v3 context string instead of palexplorer-private-network-v4 must fail (§13.2).',
  },
  {
    name: 'profileV4ActiveMemberMissingDsaKey',
    kind: 'profile',
    priorV4Accepted: false,
    object: profileActiveMissingDsa,
    expectedError: 'E_PRIVATE_NETWORK_INVALID',
    description: 'An active unrevoked member in a v4 profile must carry a 3,904-hex dsaPublicKey (§13.1).',
  },
  {
    name: 'profileV3DowngradeAfterV4',
    kind: 'profile',
    priorV4Accepted: true,
    object: downgradeV3ProfileObject,
    expectedError: 'E_PRIVATE_NETWORK_DOWNGRADE',
    description: 'Once a v4 profile has been accepted for an administrator, a subsequent v3 profile must be rejected even with a higher version (§13.2).',
  },
  {
    name: 'handoverV2TamperedEd25519Signature',
    kind: 'handover',
    priorV4Accepted: true,
    object: { ...handoverV2Built.object, signature: flipLastByte(handoverV2Built.object.signature) },
    expectedError: 'E_PRIVATE_NETWORK_BAD_SIGNATURE',
    description: 'Strict-AND: a bit flip in the handover v2 Ed25519 signature must fail (§13.3).',
  },
  {
    name: 'handoverV2TamperedMldsa65Signature',
    kind: 'handover',
    priorV4Accepted: true,
    object: { ...handoverV2Built.object, signatureMldsa65: flipLastByte(handoverV2Built.object.signatureMldsa65) },
    expectedError: 'E_PRIVATE_NETWORK_BAD_SIGNATURE',
    description: 'Strict-AND: a bit flip in the handover v2 ML-DSA-65 signature must fail (§13.3).',
  },
  {
    name: 'handoverV2WrongMldsaContext',
    kind: 'handover',
    priorV4Accepted: true,
    object: handoverWrongContext,
    expectedError: 'E_PRIVATE_NETWORK_BAD_SIGNATURE',
    description: 'ML-DSA-65 handover signature under the wrong context string must fail (§13.3).',
  },
  {
    name: 'handoverV1DowngradeAfterV4',
    kind: 'handover',
    priorV4Accepted: true,
    object: handoverV1Object,
    expectedError: 'E_PRIVATE_NETWORK_DOWNGRADE',
    description: 'Once a v4 profile has been accepted for a network, a v1 handover must be rejected (§13.3).',
  },
];

const out = {
  specVersion: '3.0.0-draft.6.23',
  description: 'Private network profile and handover (section 13): legacy v3/v1 transition vectors and hybrid Ed25519+ML-DSA-65 v4/v2 vectors with strict-AND and no-downgrade rejections.',
  keys: {
    admin: { seedHex: admin.seedHex, publicKey: admin.publicHex, dsaSeedHex: admin.dsaSeedHex, dsaPublicKey: admin.dsaPublicHex, identityPinHex: identityPinHex(admin.publicHex, admin.dsaPublicHex) },
    memberOne: { seedHex: memberOne.seedHex, publicKey: memberOne.publicHex, dsaSeedHex: memberOne.dsaSeedHex, dsaPublicKey: memberOne.dsaPublicHex, identityPinHex: identityPinHex(memberOne.publicHex, memberOne.dsaPublicHex) },
    memberTwo: { seedHex: memberTwo.seedHex, publicKey: memberTwo.publicHex, dsaSeedHex: memberTwo.dsaSeedHex, dsaPublicKey: memberTwo.dsaPublicHex, identityPinHex: identityPinHex(memberTwo.publicHex, memberTwo.dsaPublicHex) },
  },
  profile: {
    object: profileV3Object,
    signedBytesUtf8: profileSigned.toString('utf8'),
    signedBytesHex: profileSigned.toString('hex'),
  },
  handover: {
    object: handoverV1Object,
    signedBytesUtf8: handoverSigned.toString('utf8'),
    signedBytesHex: handoverSigned.toString('hex'),
  },
  profileV4: {
    object: profileV4Built.object,
    signedBytesUtf8: profileV4Built.signedBytes.toString('utf8'),
    signedBytesHex: profileV4Built.signedBytes.toString('hex'),
    dsaContext: PROFILE_V4_DSA_CONTEXT,
    adminIdentityPinHex: identityPinHex(admin.publicHex, admin.dsaPublicHex),
  },
  handoverV2: {
    object: handoverV2Built.object,
    signedBytesUtf8: handoverV2Built.signedBytes.toString('utf8'),
    signedBytesHex: handoverV2Built.signedBytes.toString('hex'),
    dsaContext: HANDOVER_V2_DSA_CONTEXT,
  },
  hybridRejected,
  crossVerification: 'Pending: desktop implementation check tracked in hn2/palexplorer#1234.',
};

writeFileSync(new URL('./pal3-v0.6-private-network-vectors.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
