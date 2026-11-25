// Generates pal3-v0.6-private-network-vectors.json from the signed-bytes definition in section 13 of the specification.
// Standalone: Node built-ins only (ed25519 through node:crypto). Ed25519 signatures are deterministic, so the output is reproducible.
// Run: node test-vectors/v3/pal3-v0.6-private-network-generate.mjs
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { writeFileSync } from 'node:fs';

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const PROFILE_CONTEXT = 'palexplorer-private-network-v3\n';
const HANDOVER_CONTEXT = 'palexplorer-private-network-handover-v1\n';

function keyFromSeed(seedByte) {
  const seed = Buffer.alloc(32, seedByte);
  const privateKey = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: 'der', type: 'pkcs8' });
  const publicHex = createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
  return { seedHex: seed.toString('hex'), publicHex, privateKey };
}

const admin = keyFromSeed(0x01);
const memberOne = keyFromSeed(0x02);
const memberTwo = keyFromSeed(0x03);

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

// Key order is part of the definition: name, admin, discoveryServers, relays, members, privacyMode, issuedAt, version, expiresAt.
const profileSigned = Buffer.from(PROFILE_CONTEXT + JSON.stringify({
  name: profile.name, admin: profile.admin, discoveryServers: profile.discoveryServers, relays: profile.relays,
  members: profile.members.map((m) => ({ publicKey: m.publicKey, name: m.name, revoked: m.revoked })),
  privacyMode: profile.privacyMode, issuedAt: profile.issuedAt, version: profile.version, expiresAt: profile.expiresAt,
  networkId: null, networkCreator: null, networkNonce: null, networkCreatedAtMs: null,
}), 'utf8');

const handover = {
  name: profile.name,
  from: admin.publicHex,
  to: memberOne.publicHex,
  issuedAt: '2026-11-15T10:00:00.000Z',
  expiresAt: '2026-12-15T10:00:00.000Z',
};
const handoverSigned = Buffer.from(HANDOVER_CONTEXT + JSON.stringify({
  name: handover.name, from: handover.from, to: handover.to, issuedAt: handover.issuedAt, expiresAt: handover.expiresAt,
}), 'utf8');

const out = {
  specVersion: '3.0.0-draft.6.9',
  description: 'Private network profile and handover (section 13). Keys are Ed25519 with the 32-byte seed shown; signatures are Ed25519 over the signed bytes, hex encoded.',
  keys: {
    admin: { seedHex: admin.seedHex, publicKey: admin.publicHex },
    memberOne: { seedHex: memberOne.seedHex, publicKey: memberOne.publicHex },
    memberTwo: { seedHex: memberTwo.seedHex, publicKey: memberTwo.publicHex },
  },
  profile: {
    object: { ...profile, signature: sign(null, profileSigned, admin.privateKey).toString('hex') },
    signedBytesUtf8: profileSigned.toString('utf8'),
    signedBytesHex: profileSigned.toString('hex'),
  },
  handover: {
    object: { ...handover, signature: sign(null, handoverSigned, admin.privateKey).toString('hex') },
    signedBytesUtf8: handoverSigned.toString('utf8'),
    signedBytesHex: handoverSigned.toString('hex'),
  },
  crossVerification: 'Pending: desktop implementation check tracked in hn2/palexplorer#1234.',
};

writeFileSync(new URL('./pal3-v0.6-private-network-vectors.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
