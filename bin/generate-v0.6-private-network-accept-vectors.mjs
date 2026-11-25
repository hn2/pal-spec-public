// Generates test-vectors/v3/pal3-v0.6-private-network-accept-vectors.json (spec sections 13.2 network fields, 13.4, 13.5, 13.6).
// Run: node bin/generate-v0.6-private-network-accept-vectors.mjs [--out <file>]
// Standalone: Node built-ins only. Ed25519 signatures are deterministic. The expected decision of every case is written here by hand from the
// specification text and the desktop implementation (hn2/palexplorer lib/core/privateNetwork.js, read at ad22d936); validate.mjs recomputes them.
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : null; };
const out = opt('--out') || resolve(dirname(fileURLToPath(import.meta.url)), '../test-vectors/v3/pal3-v0.6-private-network-accept-vectors.json');

const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const PROFILE_CONTEXT = 'palexplorer-private-network-v3\n';
const HANDOVER_CONTEXT = 'palexplorer-private-network-handover-v1\n';
const key = (b) => {
  const privateKey = createPrivateKey({ key: Buffer.concat([PKCS8, Buffer.alloc(32, b)]), format: 'der', type: 'pkcs8' });
  return { seedHex: Buffer.alloc(32, b).toString('hex'), publicKey: createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex'), privateKey };
};
const admin = key(0x01);
const alice = key(0x02);
const bob = key(0x03);
const otherAdmin = key(0x04);
const newAdmin = key(0x05);

const NOW = Date.UTC(2026, 10, 24, 12, 0, 0);
const DAY = 24 * 3600 * 1000;
const iso = (ms) => new Date(ms).toISOString();
const networkIdOf = (adminHex, nonceHex, createdMs) => {
  const created = Buffer.alloc(8);
  created.writeBigUInt64BE(BigInt(createdMs));
  return createHash('sha384').update(Buffer.from('pal3-id-network-v1\0', 'latin1')).update(Buffer.from(adminHex, 'hex')).update(Buffer.from(nonceHex, 'hex')).update(created).digest('hex');
};
const signedBytes = (p) => PROFILE_CONTEXT + JSON.stringify({
  name: p.name, admin: p.admin, discoveryServers: p.discoveryServers, relays: p.relays,
  members: p.members.map((m) => ({ publicKey: m.publicKey, name: m.name ?? null, revoked: Boolean(m.revoked) })),
  privacyMode: p.privacyMode, issuedAt: p.issuedAt, version: p.version, expiresAt: p.expiresAt,
  networkId: p.networkId ?? null, networkCreator: p.networkCreator ?? null, networkNonce: p.networkNonce ?? null, networkCreatedAtMs: p.networkCreatedAtMs ?? null,
});
const base = (over = {}) => ({
  name: 'Example Network', admin: admin.publicKey, discoveryServers: ['https://discovery.example.org'], relays: ['relay.example.org:3478'],
  members: [{ publicKey: alice.publicKey, name: 'Alice', revoked: false }, { publicKey: bob.publicKey, name: null, revoked: true }],
  privacyMode: 'normal', issuedAt: iso(NOW - DAY), version: 3, expiresAt: iso(NOW + 29 * DAY), ...over,
});
const signed = (p, signer = admin) => ({ ...p, signature: sign(null, Buffer.from(signedBytes(p), 'utf8'), signer.privateKey).toString('hex') });
const handoverBytes = (h) => HANDOVER_CONTEXT + JSON.stringify({ name: h.name, from: h.from, to: h.to, issuedAt: h.issuedAt, expiresAt: h.expiresAt });
const signedHandover = (h, signer = admin) => ({ ...h, signature: sign(null, Buffer.from(handoverBytes(h), 'utf8'), signer.privateKey).toString('hex') });

const nonce = '07'.repeat(32);
const createdMs = Date.UTC(2026, 10, 1);
const networkFields = { networkCreator: admin.publicKey, networkNonce: nonce, networkCreatedAtMs: createdMs, networkId: networkIdOf(admin.publicKey, nonce, createdMs) };

const state = (over = {}) => ({ nowMs: NOW, currentAdmin: null, floor: {}, storedSignature: null, handover: null, retired: [], ...over });
const accept = (name, description, st, incoming, options, expected) => ({ name, description, state: st, incoming, options: { replace: false, expectAdmin: null, fileBytes: 4096, ...options }, expected });
const v5 = signed(base({ version: 5 }));
const accepted = { decision: 'accepted' };
const accepts = [
  accept('firstJoinWithConfirmedAdminKey', 'No network yet; the user confirmed the administrator key', state(), signed(base()), { expectAdmin: admin.publicKey }, accepted),
  accept('firstJoinWithoutConfirmation', 'No network yet and no out-of-band confirmation', state(), signed(base()), {}, { error: 'E_PRIVATE_NETWORK_CONFIRM_ADMIN' }),
  accept('firstJoinNamingAnotherAdministrator', 'The user named a different key than the file is signed by', state(), signed(base()), { expectAdmin: otherAdmin.publicKey }, { error: 'E_PRIVATE_NETWORK_ADMIN_MISMATCH' }),
  accept('currentAdministratorNewerVersion', 'Same administrator, version above the floor, no confirmation needed', state({ currentAdmin: admin.publicKey, floor: { [admin.publicKey]: 3 }, storedSignature: 'aa' }), signed(base({ version: 4 })), {}, accepted),
  accept('olderVersionIsRefused', 'Version 2 after the floor 3: replaying a file from before a revocation', state({ currentAdmin: admin.publicKey, floor: { [admin.publicKey]: 3 } }), signed(base({ version: 2 })), {}, { error: 'E_PRIVATE_NETWORK_OLDER' }),
  accept('sameVersionSameSignatureIsOlder', 'The stored profile imported again is not newer', state({ currentAdmin: admin.publicKey, floor: { [admin.publicKey]: 3 }, storedSignature: signed(base()).signature }), signed(base()), {}, { error: 'E_PRIVATE_NETWORK_OLDER' }),
  accept('sameVersionDifferentSignatureIsAConflict', 'Same version, other bytes (other members): the administrator must sign a new version', state({ currentAdmin: admin.publicKey, floor: { [admin.publicKey]: 3 }, storedSignature: 'bb'.repeat(64) }), signed(base({ members: [] })), {}, { error: 'E_PRIVATE_NETWORK_CONFLICT' }),
  accept('versionFloorSurvivesLeavingTheNetwork', 'The client left the network (no current administrator) but keeps the floor 5', state({ floor: { [admin.publicKey]: 5 } }), signed(base({ version: 4 })), { expectAdmin: admin.publicKey }, { error: 'E_PRIVATE_NETWORK_OLDER' }),
  accept('expiredProfileIsRefused', 'expiresAt one millisecond in the past, no clock-skew allowance', state({ currentAdmin: admin.publicKey }), signed(base({ issuedAt: iso(NOW - 3 * DAY), expiresAt: iso(NOW - 1) })), {}, { error: 'E_PRIVATE_NETWORK_EXPIRED' }),
  accept('expiryExactlyNowIsRefused', 'expiresAt equal to now is not in the future', state({ currentAdmin: admin.publicKey }), signed(base({ issuedAt: iso(NOW - 3 * DAY), expiresAt: iso(NOW) })), {}, { error: 'E_PRIVATE_NETWORK_EXPIRED' }),
  accept('issuedMoreThan24HoursAheadIsRefused', 'issuedAt 24 hours and one millisecond in the future', state({ currentAdmin: admin.publicKey }), signed(base({ issuedAt: iso(NOW + DAY + 1), expiresAt: iso(NOW + 30 * DAY) })), {}, { error: 'E_PRIVATE_NETWORK_BAD_DATE' }),
  accept('issuedExactly24HoursAheadIsAccepted', 'issuedAt exactly 24 hours in the future', state({ currentAdmin: admin.publicKey }), signed(base({ issuedAt: iso(NOW + DAY), expiresAt: iso(NOW + 30 * DAY) })), {}, accepted),
  accept('changedFieldBreaksTheSignature', 'A member added after signing', state({ currentAdmin: admin.publicKey }), { ...signed(base()), members: [...base().members, { publicKey: 'cc'.repeat(32), name: null, revoked: false }] }, {}, { error: 'E_PRIVATE_NETWORK_BAD_SIGNATURE' }),
  accept('extendedExpiryBreaksTheSignature', 'expiresAt moved one day later after signing', state({ currentAdmin: admin.publicKey }), { ...signed(base()), expiresAt: iso(NOW + 30 * DAY) }, {}, { error: 'E_PRIVATE_NETWORK_BAD_SIGNATURE' }),
  accept('unsignedProfileIsRefused', 'No signature', state({ currentAdmin: admin.publicKey }), base(), {}, { error: 'E_PRIVATE_NETWORK_UNSIGNED' }),
  accept('versionZeroIsRefused', 'version must be at least 1', state({ currentAdmin: admin.publicKey }), signed(base({ version: 0 })), {}, { error: 'E_PRIVATE_NETWORK_UNSIGNED' }),
  accept('validityOverThreeHundredSixtySixDaysIsRefused', 'expiresAt 367 days after issuedAt', state({ currentAdmin: admin.publicKey }), signed(base({ issuedAt: iso(NOW - DAY), expiresAt: iso(NOW + 366 * DAY) })), {}, { error: 'E_PRIVATE_NETWORK_BAD_DATE' }),
  accept('validityOfThreeHundredSixtySixDaysIsAccepted', 'expiresAt exactly 366 days after issuedAt', state({ currentAdmin: admin.publicKey }), signed(base({ issuedAt: iso(NOW - DAY), expiresAt: iso(NOW + 365 * DAY) })), {}, accepted),
  accept('expiryBeforeIssueIsRefused', 'expiresAt earlier than issuedAt', state({ currentAdmin: admin.publicKey }), signed(base({ issuedAt: iso(NOW - DAY), expiresAt: iso(NOW - 2 * DAY) })), {}, { error: 'E_PRIVATE_NETWORK_BAD_DATE' }),
  accept('fileAboveOneMebibyteIsRefused', 'A file of 1 MiB + 1 byte', state({ currentAdmin: admin.publicKey }), signed(base()), { fileBytes: 1048577 }, { error: 'E_PRIVATE_NETWORK_TOO_LARGE' }),
  accept('fileOfOneMebibyteIsAccepted', 'A file of exactly 1 MiB', state({ currentAdmin: admin.publicKey }), signed(base({ version: 4 })), { fileBytes: 1048576 }, accepted),
  accept('otherAdministratorWithoutSwitchIsRefused', 'A file from another administrator than the current one', state({ currentAdmin: admin.publicKey }), signed(base({ admin: otherAdmin.publicKey }), otherAdmin), { expectAdmin: otherAdmin.publicKey }, { error: 'E_PRIVATE_NETWORK_OTHER_ADMIN' }),
  accept('otherAdministratorWithExplicitSwitch', 'The user explicitly chose to switch networks and confirmed the key', state({ currentAdmin: admin.publicKey }), signed(base({ admin: otherAdmin.publicKey }), otherAdmin), { replace: true, expectAdmin: otherAdmin.publicKey }, accepted),
  accept('handoverNamesTheNewAdministrator', 'A valid unexpired handover from the current administrator names the signer: no confirmation needed',
    state({ currentAdmin: admin.publicKey, handover: { from: admin.publicKey, to: newAdmin.publicKey, expiresAt: iso(NOW + 10 * DAY) } }), signed(base({ admin: newAdmin.publicKey }), newAdmin), {}, accepted),
  accept('expiredHandoverDoesNotCount', 'The handover has expired', state({ currentAdmin: admin.publicKey, handover: { from: admin.publicKey, to: newAdmin.publicKey, expiresAt: iso(NOW - 1) } }), signed(base({ admin: newAdmin.publicKey }), newAdmin), {}, { error: 'E_PRIVATE_NETWORK_OTHER_ADMIN' }),
  accept('handoverToAnotherKeyDoesNotCount', 'The handover names a different new administrator than the signer', state({ currentAdmin: admin.publicKey, handover: { from: admin.publicKey, to: bob.publicKey, expiresAt: iso(NOW + 10 * DAY) } }), signed(base({ admin: newAdmin.publicKey }), newAdmin), {}, { error: 'E_PRIVATE_NETWORK_OTHER_ADMIN' }),
  accept('retiredAdministratorCannotSignAgain', 'The old key was replaced by a handover', state({ currentAdmin: newAdmin.publicKey, retired: [admin.publicKey] }), signed(base({ version: 9 })), { replace: true, expectAdmin: admin.publicKey }, { error: 'E_PRIVATE_NETWORK_RETIRED_ADMIN' }),
  accept('expiredStoredProfileEndsWithNewerProfileFromTheSameAdministrator', 'The stored profile expired (lockdown); a newer profile from the same administrator ends it without confirmation', state({ currentAdmin: admin.publicKey, floor: { [admin.publicKey]: 3 }, storedSignature: 'aa' }), signed(base({ version: 4 })), {}, accepted),
  accept('networkFieldsAreSigned', 'networkId, creator, nonce and creation time are part of the signed bytes', state({ currentAdmin: admin.publicKey }), signed(base({ version: 4, ...networkFields })), {}, accepted),
  accept('changedNetworkIdBreaksTheSignature', 'networkId replaced after signing', state({ currentAdmin: admin.publicKey }), { ...signed(base({ version: 4, ...networkFields })), networkId: 'dd'.repeat(48) }, {}, { error: 'E_PRIVATE_NETWORK_BAD_SIGNATURE' }),
];

// 13.5: what a client does with a stored profile, and with hosts and keys while a profile is active.
const localKey = (hex) => hex;
const stored = (p, over = {}) => ({ profile: p, localPublicKey: localKey('ee'.repeat(32)), nowMs: NOW, ...over });
const stateCases = [
  { name: 'validStoredProfileIsActive', ...stored(signed(base())), expected: { mode: 'active' } },
  { name: 'tamperedStoredProfileIsLockdown', ...stored({ ...signed(base()), members: [...base().members, { publicKey: 'cc'.repeat(32), name: null, revoked: false }] }), expected: { mode: 'lockdown' } },
  { name: 'unsignedStoredProfileIsLockdown', ...stored(base()), expected: { mode: 'lockdown' } },
  { name: 'expiredStoredProfileIsLockdown', ...stored(signed(base({ issuedAt: iso(NOW - 40 * DAY), expiresAt: iso(NOW - DAY) }))), expected: { mode: 'lockdown' } },
  { name: 'storedProfileExpiringExactlyNowIsLockdown', ...stored(signed(base({ issuedAt: iso(NOW - 40 * DAY), expiresAt: iso(NOW) }))), expected: { mode: 'lockdown' } },
  { name: 'expiredProfileOnTheAdministratorDeviceStaysUsableToSign', ...stored(signed(base({ issuedAt: iso(NOW - 40 * DAY), expiresAt: iso(NOW - DAY) })), { localPublicKey: admin.publicKey }), expected: { mode: 'active' } },
  { name: 'unsignedProfileOnTheAdministratorDeviceIsAccepted', ...stored(base(), { localPublicKey: admin.publicKey }), expected: { mode: 'active' } },
];
const net = signed(base());
const memberCases = [
  ['activeMemberMayConnect', alice.publicKey, true],
  ['revokedMemberIsRefused', bob.publicKey, false],
  ['unknownKeyIsRefused', 'cc'.repeat(32), false],
  ['upperCaseKeyIsTheSameKey', alice.publicKey.toUpperCase(), true],
  ['administratorThatIsNoMemberIsRefused', admin.publicKey, false],
  ['emptyKeyIsRefused', '', false],
].map(([name, publicKey, allowed]) => ({ name, publicKey, allowed }));
const hostCases = [
  ['listedDiscoveryServer', 'https://discovery.example.org/api/v1/shares', true],
  ['listedRelayHostAndPort', 'relay.example.org:3478', true],
  ['relayHostCoversHttpsToThatHost', 'https://relay.example.org/health', true],
  ['otherHostIsRefused', 'https://example.com/', false],
  ['subdomainOfAListedHostIsRefused', 'https://evil.discovery.example.org/', false],
  ['listedHostAsSubstringIsRefused', 'https://discovery.example.org.evil.test/', false],
  ['ipAddressIsRefused', 'https://203.0.113.9/', false],
  ['unreadableAddressIsRefused', 'https://[::1', false],
].map(([name, url, allowed]) => ({ name, url, allowed }));

const doc = {
  specVersion: '0.6.22',
  section: '13.2, 13.4, 13.5, 13.6',
  description: 'Private network profile acceptance (13.4, 13.6), stored-profile verification and lockdown, member and host decisions (13.5), and the network fields of the signed bytes (13.2).',
  generatedBy: 'bin/generate-v0.6-private-network-accept-vectors.mjs',
  nowMs: NOW,
  keys: { admin: { seedHex: admin.seedHex, publicKey: admin.publicKey }, alice: { seedHex: alice.seedHex, publicKey: alice.publicKey }, bob: { seedHex: bob.seedHex, publicKey: bob.publicKey }, otherAdmin: { seedHex: otherAdmin.seedHex, publicKey: otherAdmin.publicKey }, newAdmin: { seedHex: newAdmin.seedHex, publicKey: newAdmin.publicKey } },
  limits: { fileBytes: 1048576, issuedAheadMs: DAY, maxValidityMs: 366 * DAY },
  networkId: { nonceHex: nonce, createdAtMs: createdMs, creator: admin.publicKey, expectedHex: networkFields.networkId },
  handoverExample: signedHandover({ name: 'Example Network', from: admin.publicKey, to: alice.publicKey, issuedAt: iso(NOW - DAY), expiresAt: iso(NOW + 29 * DAY) }),
  accept: accepts,
  state: stateCases,
  activeProfile: net,
  members: memberCases,
  hosts: hostCases,
};
writeFileSync(out, `${JSON.stringify(doc, null, 2)}\n`);
console.log(`wrote ${out}: ${accepts.length} accept, ${stateCases.length} state, ${memberCases.length} member, ${hostCases.length} host cases`);
