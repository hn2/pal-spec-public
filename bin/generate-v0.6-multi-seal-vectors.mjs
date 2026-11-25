// Generates test-vectors/v3/pal3-v0.6-multi-seal-vectors.json (spec section 11.4, A.1 sealed_content, device_list, device_signed, device_cert 0xC010)
// with the reference implementation (hn2/pal-core packages/protocol/lib/pal3/multiSeal.js).
// Run: node bin/generate-v0.6-multi-seal-vectors.mjs --pal-core <path to the hn2/pal-core checkout> [--out <file>]
// Keys come from fixed seeds, the random inputs of sealing come from a fixed SHA-384 stream and ML-DSA is signed in the deterministic mode, so two runs are byte-identical.
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadReference, deterministicSigner } from './vector-signing.mjs';

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : null; };
const palCore = opt('--pal-core');
if (!palCore) { console.error('usage: node bin/generate-v0.6-multi-seal-vectors.mjs --pal-core <path> [--out <file>]'); process.exit(2); }
const out = opt('--out') || resolve(dirname(fileURLToPath(import.meta.url)), '../test-vectors/v3/pal3-v0.6-multi-seal-vectors.json');

const ref = await loadReference(palCore);
const det = deterministicSigner(ref);
const sign = ({ domainLabel, bodyBytes, edSecretKey, dsaSecretKey, dsaContext }) => det({ domain: domainLabel, dsaContext, body: bodyBytes, edSecretKey, dsaSecretKey });
const ms = await ref.lib('pal3/multiSeal.js');
const hs = await ref.lib('pal3/handshake.js');
const { Pal3RevocationStore } = await ref.lib('pal3/revocation.js');
const { encodeTlv, decodeTlv, u8Buf, u64Buf } = await ref.lib('pal3/tlv.js');

const hex = (b) => Buffer.from(b).toString('hex');
const sha384 = (b) => createHash('sha384').update(b).digest();
const code = (fn) => { try { fn(); return 'accepted'; } catch (err) { return /^(E_[A-Z0-9_]+)/.exec(err.message)?.[1] ?? err.message; } };
const stream = (label) => { let i = 0; return (n) => sha384(Buffer.from(`${label}/${i++}`)).subarray(0, n); };
const NOW = 1762560000000;
const DAY = 86_400_000;

const signingId = (n) => hs.generateHybridSigningIdentity({ edSeed: Buffer.alloc(32, n), dsaSeed: Buffer.alloc(32, n + 1) });
const encSeed = (n) => ({ x25519Seed: Buffer.alloc(32, n), kemSeed: Buffer.alloc(64, n + 1) });
const encKeys = (n) => ms.generateDeviceEncryptionKeys(encSeed(n));
const owner = signingId(0x10);
const stranger = signingId(0x20);
const ownerTrust = { edPublicKey: owner.edPublicKey, dsaPublicKey: owner.dsaPublicKey };
const strangerTrust = { edPublicKey: stranger.edPublicKey, dsaPublicKey: stranger.dsaPublicKey };
const party = {
  identity: { enc: encKeys(0x30), seed: encSeed(0x30) },
  deviceA: { enc: encKeys(0x41), seed: encSeed(0x41), signing: signingId(0x51), deviceId: Buffer.alloc(16, 0xa1) },
  deviceB: { enc: encKeys(0x42), seed: encSeed(0x42), signing: signingId(0x53), deviceId: Buffer.alloc(16, 0xb2) },
  deviceC: { enc: encKeys(0x43), seed: encSeed(0x43), signing: signingId(0x55), deviceId: Buffer.alloc(16, 0xc3) },
  stranger: { enc: encKeys(0x44), seed: encSeed(0x44) },
};
const holder = (name) => party[name].enc;
const keysDoc = Object.fromEntries(Object.entries(party).map(([name, p]) => [name, {
  x25519SecretKeyHex: hex(p.enc.x25519SecretKey), x25519PublicKeyHex: hex(p.enc.x25519PublicKey), mlkemSeedHex: hex(p.seed.kemSeed), mlkemEncapsulationKeyHex: hex(p.enc.kemPublicKey),
  keyIdHex: hex(ms.encryptionKeyId(p.enc)),
}]));

// ---- sealed_content
const sealedContent = [];
function seal(name, description, { context, plaintext, to }) {
  const sealed = ms.sealContent({ context, plaintext, recipients: to.map(holder), random: stream(name) });
  const openableBy = to.filter((who) => ms.openSealedContent(sealed, { keys: [holder(who)], context }).plaintext.equals(plaintext));
  if (openableBy.length !== to.length) throw new Error(`reference: not every recipient opens ${name}`);
  for (const who of Object.keys(party).filter((w) => !to.includes(w))) {
    if (code(() => ms.openSealedContent(sealed, { keys: [holder(who)], context })) !== 'E_PAL3_SEAL_NO_RECIPIENT') throw new Error(`reference: ${who} opens ${name}`);
  }
  sealedContent.push({ name, description, context, plaintextHex: hex(plaintext), recipients: to, sealedHex: hex(sealed), wraps: to.length });
  return sealed;
}
const base = seal('identityAndTwoDevices', 'Identity key first, then devices A and B', { context: 'message', plaintext: Buffer.from('a direct message', 'utf8'), to: ['identity', 'deviceA', 'deviceB'] });
seal('identityOnly', 'An identity without devices: one wrap', { context: 'share-key', plaintext: Buffer.alloc(32, 0x5a), to: ['identity'] });
seal('emptyPlaintext', 'An empty plaintext still has a tag and a commitment', { context: 'message', plaintext: Buffer.alloc(0), to: ['identity', 'deviceC'] });
const fields = decodeTlv(base);
const reTlv = (map) => encodeTlv([...map].map(([t, v]) => [t, v]));
const withOptional = reTlv(new Map([...fields, [0xc001, Buffer.from('ignored')]]));
if (ms.openSealedContent(withOptional, { keys: [holder('deviceA')], context: 'message' }).plaintext.toString() !== 'a direct message') throw new Error('optional tag');
sealedContent.push({ name: 'unknownOptionalTagIsIgnored', description: 'An extension tag in the optional range (0xC001) is ignored by a reader that does not know it', context: 'message', plaintextHex: hex(Buffer.from('a direct message')), recipients: ['identity', 'deviceA', 'deviceB'], sealedHex: hex(withOptional), wraps: 3 });

const sealedRejected = [];
function rejectOpen(name, description, sealed, openAs, expectedError, context = 'message') {
  const got = code(() => ms.openSealedContent(sealed, { keys: [holder(openAs)], context }));
  if (got !== expectedError) throw new Error(`reference answered ${got}, not ${expectedError}: ${name}`);
  sealedRejected.push({ name, description, sealedHex: hex(sealed), openAs, context, expectedError });
}
const edit = (tag, fn) => reTlv(new Map([...fields].map(([t, v]) => [t, t === tag ? fn(Buffer.from(v)) : v])));
const flipAt = (i) => (b) => { b[i] ^= 1; return b; };
rejectOpen('keyThatHoldsNoWrap', 'A device that is not a recipient', base, 'stranger', 'E_PAL3_SEAL_NO_RECIPIENT');
rejectOpen('contextOfAnotherPurpose', 'The reader expects the label share-key', base, 'deviceA', 'E_PAL3_SEAL_CONTEXT_MISMATCH', 'share-key');
rejectOpen('ciphertextBitFlipped', 'One bit of the content ciphertext flipped', edit(5, flipAt(0)), 'deviceA', 'E_PAL3_SEAL_AUTH_FAILED');
rejectOpen('commitmentChanged', 'The key commitment replaced', edit(3, flipAt(0)), 'identity', 'E_PAL3_SEAL_AUTH_FAILED');
rejectOpen('mlkemCiphertextOfTheWrapFlipped', 'A bit of the ML-KEM ciphertext inside the first wrap flipped: implicit rejection gives another secret, the wrap does not open', edit(4, flipAt(16 + 32 + 5)), 'identity', 'E_PAL3_SEAL_AUTH_FAILED');
rejectOpen('ephemeralX25519OfTheWrapFlipped', 'A bit of the ephemeral X25519 key inside the wrap flipped', edit(4, flipAt(16 + 3)), 'identity', 'E_PAL3_SEAL_AUTH_FAILED');
// A sender that wraps another content key for device A: the commitment of the shared header does not match that key.
const alt = ms.sealContent({ context: 'message', plaintext: Buffer.from('another plaintext'), recipients: [holder('deviceA')], random: stream('alt') });
const splitWraps = Buffer.concat([fields.get(4).subarray(0, 1184), decodeTlv(alt).get(4)]);
const split = reTlv(new Map([...fields].map(([t, v]) => [t, t === 4 ? splitWraps : v])));
if (ms.openSealedContent(split, { keys: [holder('identity')], context: 'message' }).plaintext.toString() !== 'a direct message') throw new Error('split: identity');
rejectOpen('senderWrapsAnotherContentKeyForADevice', 'Equivocation: the identity wrap holds the real content key, the device wrap another one. The identity reads the message, the device refuses it (see the positive check in the validator)', split, 'deviceA', 'E_PAL3_SEAL_AUTH_FAILED');
rejectOpen('versionTwo', 'An unknown sealed_content version', edit(1, () => Buffer.from([2])), 'identity', 'E_PAL3_SEAL_INVALID');
rejectOpen('wrapsNotAMultipleOfTheWrapSize', 'recipient_wraps shortened by one byte', edit(4, (b) => b.subarray(0, b.length - 1)), 'identity', 'E_PAL3_SEAL_INVALID');
rejectOpen('noWraps', 'recipient_wraps empty', edit(4, () => Buffer.alloc(0)), 'identity', 'E_PAL3_SEAL_INVALID');
rejectOpen('seventeenWraps', 'More wraps than the limit of 16', edit(4, (b) => Buffer.concat(Array.from({ length: 17 }, () => b.subarray(0, 1184)))), 'identity', 'E_PAL3_SEAL_INVALID');
rejectOpen('criticalUnknownTag', 'A critical extension tag (0x8001) the reader does not know', reTlv(new Map([...fields, [0x8001, Buffer.from('x')]])), 'identity', 'E_PAL3_UNSUPPORTED_CRITICAL_EXTENSION');
rejectOpen('contextUppercase', 'A context outside a-z, 0-9, dot, underscore, hyphen', edit(2, () => Buffer.from('Message')), 'identity', 'E_PAL3_SEAL_INVALID', 'Message');

const lowOrder = { ...party.deviceA.enc, x25519PublicKey: Buffer.alloc(32) };
const unreduced = Buffer.from(party.deviceA.enc.kemPublicKey); unreduced[0] = 0xff; unreduced[1] = 0xff;
const sealRejected = [];
function rejectSeal(name, description, params, run, expectedError) {
  const got = code(run);
  if (got !== expectedError) throw new Error(`reference answered ${got}, not ${expectedError}: ${name}`);
  sealRejected.push({ name, description, ...params, expectedError });
}
const manyKeys = Array.from({ length: 17 }, (_, i) => encKeys(0x80 + i));
rejectSeal('seventeenRecipients', 'One more recipient than the limit of 16', { context: 'message', plaintextLength: 1, recipientCount: 17 }, () => ms.sealContent({ context: 'message', plaintext: Buffer.alloc(1), recipients: manyKeys }), 'E_PAL3_SEAL_TOO_MANY_RECIPIENTS');
rejectSeal('plaintextOneByteOverTheLimit', 'A plaintext of 32769 bytes', { context: 'message', plaintextLength: 32769, recipientCount: 1 }, () => ms.sealContent({ context: 'message', plaintext: Buffer.alloc(32769), recipients: [holder('identity')] }), 'E_PAL3_SEAL_INVALID');
rejectSeal('noRecipient', 'An empty recipient list', { context: 'message', plaintextLength: 1, recipientCount: 0 }, () => ms.sealContent({ context: 'message', plaintext: Buffer.alloc(1), recipients: [] }), 'E_PAL3_SEAL_INVALID');
rejectSeal('sameKeyTwice', 'One key listed twice', { context: 'message', plaintextLength: 1, recipientCount: 2, duplicateKey: true }, () => ms.sealContent({ context: 'message', plaintext: Buffer.alloc(1), recipients: [holder('identity'), holder('identity')] }), 'E_PAL3_SEAL_INVALID');
rejectSeal('lowOrderX25519Key', 'A recipient X25519 key that is the all-zero low-order point', { context: 'message', plaintextLength: 1, recipientCount: 1, lowOrderX25519: true, x25519PublicKeyHex: hex(lowOrder.x25519PublicKey) }, () => ms.sealContent({ context: 'message', plaintext: Buffer.alloc(1), recipients: [lowOrder] }), 'E_PAL3_SEAL_KEY_INVALID');
rejectSeal('unreducedMlKemKey', 'A recipient ML-KEM key with a coefficient not reduced modulo q (FIPS 203 modulus check)', { context: 'message', plaintextLength: 1, recipientCount: 1, unreducedMlKem: true, mlkemEncapsulationKeyHex: hex(unreduced) }, () => ms.sealContent({ context: 'message', plaintext: Buffer.alloc(1), recipients: [{ ...party.deviceA.enc, kemPublicKey: unreduced }] }), 'E_PAL3_SEAL_KEY_INVALID');
rejectSeal('contextWithASpace', 'A context label with a space', { context: 'bad context', plaintextLength: 1, recipientCount: 1 }, () => ms.sealContent({ context: 'bad context', plaintext: Buffer.alloc(1), recipients: [holder('identity')] }), 'E_PAL3_SEAL_INVALID');

// ---- certificates with the device encryption key extension
function cert({ device, deviceId, enc, issuedAtMs = NOW - 1000, expiresAtMs = NOW + DAY, signer = owner, withExt = true }) {
  const body = [[1, u8Buf(0)], [2, owner.edPublicKey], [3, owner.dsaPublicKey], [4, deviceId], [5, device.edPublicKey], [6, device.dsaPublicKey], [7, u64Buf(issuedAtMs)], [8, u64Buf(expiresAtMs)]];
  if (withExt) body.push([0xc010, ms.encodeEncryptionKeys(enc)]);
  const bodyBytes = encodeTlv(body);
  const { sigEd25519, sigMldsa65 } = sign({ domainLabel: 'pal3-devcert-v1', dsaContext: 'pal3-devcert-v1', bodyBytes, edSecretKey: signer.edSecretKey, dsaSecretKey: signer.dsaSecretKey });
  return encodeTlv([...body, [9, sigEd25519], [10, sigMldsa65]]);
}
const certA = cert({ device: party.deviceA.signing, deviceId: party.deviceA.deviceId, enc: party.deviceA.enc });
const parsedA = hs.verifyDeviceCertificate(certA, { now: NOW, supportedExtensionTags: [] });
if (!ms.deviceEncKeysOfCertificate(parsedA).kemPublicKey.equals(party.deviceA.enc.kemPublicKey)) throw new Error('cert extension');
const certificates = {
  deviceA: { certHex: hex(certA), nowMs: NOW, deviceIdHex: hex(party.deviceA.deviceId), extensionTag: 0xc010, extensionHex: hex(ms.encodeEncryptionKeys(party.deviceA.enc)), verifiesWithoutKnowingTheTag: true },
  deviceB: { certHex: hex(cert({ device: party.deviceB.signing, deviceId: party.deviceB.deviceId, enc: party.deviceB.enc })), nowMs: NOW, deviceIdHex: hex(party.deviceB.deviceId) },
};

// ---- device_list
const entry = (d, certExpiresAtMs = NOW + DAY) => Buffer.concat([d.deviceId, ms.encodeEncryptionKeys(d.enc), u64Buf(certExpiresAtMs)]);
function buildList({ signer = owner, identity = owner, encFor = party.identity.enc, revision = 1, revocationVersion = 0, issuedAtMs = NOW, expiresAtMs = NOW + 7 * DAY, caps = 'seal.v1', entries }) {
  const body = [[1, identity.edPublicKey], [2, identity.dsaPublicKey], [3, ms.encodeEncryptionKeys(encFor)], [4, u64Buf(revision)], [5, u64Buf(revocationVersion)], [6, u64Buf(issuedAtMs)], [7, u64Buf(expiresAtMs)], [8, Buffer.from(caps, 'ascii')], [0x0b, entries]];
  const bodyBytes = encodeTlv(body);
  const { sigEd25519, sigMldsa65 } = sign({ domainLabel: 'pal3-devlist-v1', dsaContext: 'pal3-devlist-v1', bodyBytes, edSecretKey: signer.edSecretKey, dsaSecretKey: signer.dsaSecretKey });
  return encodeTlv([...body, [9, sigEd25519], [10, sigMldsa65]]);
}
const device = (d) => ({ deviceId: d.deviceId, ...d.enc, certExpiresAtMs: NOW + DAY });
const lists = {
  r1Empty: ms.issueDeviceList({ identity: owner, identityEncKeys: party.identity.enc, revision: 1, issuedAtMs: NOW, capabilities: [], devices: [], sign }),
  r2AB: ms.issueDeviceList({ identity: owner, identityEncKeys: party.identity.enc, revision: 2, revocationVersion: 0, issuedAtMs: NOW, capabilities: ['seal.v1'], devices: [device(party.deviceB), device(party.deviceA)], sign }),
  r3ABC: ms.issueDeviceList({ identity: owner, identityEncKeys: party.identity.enc, revision: 3, revocationVersion: 1, issuedAtMs: NOW, capabilities: ['pad.v1', 'seal.v1'], devices: [device(party.deviceA), device(party.deviceB), device(party.deviceC)], sign }),
};
const listDocs = Object.entries(lists).map(([name, bytes]) => {
  const l = ms.verifyDeviceList(bytes, { expectedIdentity: ownerTrust, now: NOW });
  return { name, listHex: hex(bytes), nowMs: NOW, revision: String(l.revision), revocationVersion: String(l.revocationVersion), issuedAtMs: l.issuedAtMs, expiresAtMs: l.expiresAtMs, capabilities: l.capabilities, deviceIds: l.devices.map((d) => hex(d.deviceId)) };
});

const listsRejected = [];
function rejectList(name, description, bytes, expectedError, { nowMs = NOW, trusted = 'owner' } = {}) {
  const got = code(() => ms.verifyDeviceList(bytes, { expectedIdentity: trusted === 'owner' ? ownerTrust : strangerTrust, now: nowMs }));
  if (got !== expectedError) throw new Error(`reference answered ${got}, not ${expectedError}: ${name}`);
  listsRejected.push({ name, description, listHex: hex(bytes), nowMs, trustedIdentity: trusted, expectedError });
}
const ab = Buffer.concat([entry(party.deviceA), entry(party.deviceB)]);
rejectList('listForAnotherTrustedIdentity', 'The list is valid but the receiver trusts another identity for this issuer', lists.r2AB, 'E_PAL3_DEVICE_LIST_ISSUER_MISMATCH', { trusted: 'stranger' });
rejectList('signedByADevice', 'A malicious paired device signs a list with its device keys under the identity public keys', buildList({ signer: party.deviceA.signing, entries: ab }), 'E_PAL3_DEVICE_LIST_INVALID');
rejectList('entryChangedAfterSigning', 'A device encryption key swapped after signing (a lying server adds its own key)', reTlv(new Map([...decodeTlv(lists.r2AB)].map(([t, v]) => [t, t === 0x0b ? (() => { const b = Buffer.from(v); b[20] ^= 1; return b; })() : v]))), 'E_PAL3_DEVICE_LIST_INVALID');
rejectList('expired', 'now is at expires_at_ms', lists.r2AB, 'E_PAL3_DEVICE_LIST_STALE', { nowMs: NOW + 7 * DAY });
rejectList('lifetimeOverSevenDays', 'expires_at_ms is 7 days and 1 ms after issued_at_ms', buildList({ expiresAtMs: NOW + 7 * DAY + 1, entries: ab }), 'E_PAL3_DEVICE_LIST_INVALID');
rejectList('issuedMoreThanFiveMinutesAhead', 'issued_at_ms 6 minutes after the verifier clock', buildList({ issuedAtMs: NOW + 6 * 60_000, expiresAtMs: NOW + 6 * 60_000 + DAY, entries: ab }), 'E_PAL3_DEVICE_LIST_INVALID');
rejectList('revisionZero', 'list_revision starts at 1', buildList({ revision: 0, entries: ab }), 'E_PAL3_DEVICE_LIST_INVALID');
rejectList('devicesNotAscending', 'Entries in descending device_id order', buildList({ entries: Buffer.concat([entry(party.deviceB), entry(party.deviceA)]) }), 'E_PAL3_DEVICE_LIST_INVALID');
rejectList('sameDeviceTwice', 'One device_id twice', buildList({ entries: Buffer.concat([entry(party.deviceA), entry(party.deviceA)]) }), 'E_PAL3_DEVICE_LIST_INVALID');
rejectList('sixteenDevices', 'More devices than the limit of 15', buildList({ entries: Buffer.concat(Array.from({ length: 16 }, (_, i) => Buffer.concat([Buffer.alloc(16, i + 1), ms.encodeEncryptionKeys(manyKeys[i]), u64Buf(NOW + DAY)]))) }), 'E_PAL3_DEVICE_LIST_INVALID');
rejectList('capabilitiesUnsorted', 'Capability tokens out of order', buildList({ caps: 'seal.v1,pad.v1', entries: ab }), 'E_PAL3_DEVICE_LIST_INVALID');
rejectList('entryWithLowOrderKey', 'A device entry with an all-zero X25519 key', buildList({ entries: Buffer.concat([Buffer.concat([party.deviceA.deviceId, Buffer.alloc(32), party.deviceA.enc.kemPublicKey, u64Buf(NOW + DAY)])]) }), 'E_PAL3_SEAL_KEY_INVALID');
rejectList('trailingEntryByte', 'device entries one byte too long', buildList({ entries: Buffer.concat([ab, Buffer.from([0])]) }), 'E_PAL3_DEVICE_LIST_INVALID');

// ---- receiver sequence: store, revocation, selection
function statement({ version, revoked }) {
  const body = [[1, owner.edPublicKey], [2, owner.dsaPublicKey], [3, u64Buf(BigInt(version))], [4, u64Buf(BigInt(NOW))], [5, Buffer.concat(revoked)]];
  const bodyBytes = encodeTlv(body);
  const { sigEd25519, sigMldsa65 } = sign({ domainLabel: 'pal3-revocation-v1', dsaContext: 'pal3-revocation-v1', bodyBytes, edSecretKey: owner.edSecretKey, dsaSecretKey: owner.dsaSecretKey });
  return encodeTlv([...body, [9, sigEd25519], [10, sigMldsa65]]);
}
const statements = { v1RevokesB: statement({ version: 1, revoked: [party.deviceB.deviceId] }) };
const store = new ms.Pal3DeviceListStore();
const revocations = new Pal3RevocationStore();
const sequence = [];
function importList(name, description, listKey, extra = {}) {
  const bytes = lists[listKey];
  let result;
  const got = code(() => { result = store.import(bytes, { expectedIdentity: ownerTrust, now: NOW, ...extra.options }); });
  sequence.push({ name, description, op: 'importList', list: listKey, ...(extra.pinned ? { pinnedEncKeysOf: extra.pinned } : {}), ...(got === 'accepted' ? { expected: { applied: result.applied, revision: String(result.revision) } } : { expectedError: got }) });
}
function select(name, description, nowMs) {
  const list = store.listFor(ownerTrust);
  const r = ms.selectSealRecipients({ list, revocationStore: revocations, now: nowMs });
  sequence.push({
    name, description, op: 'select', nowMs,
    expectedRecipients: r.recipients.map((x) => ({ kind: x.kind, keyIdHex: hex(x.keyId), deviceIdHex: x.deviceId ? hex(x.deviceId) : null })),
    expectedSkipped: r.skipped.map((x) => ({ deviceIdHex: hex(x.deviceId), reason: x.reason })),
  });
}
importList('firstListIsApplied', 'Revision 1 with no devices', 'r1Empty');
select('onlyTheIdentityKeyWithoutDevices', 'No device is listed: the identity key is the only recipient', NOW);
importList('revisionTwoApplies', 'Revision 2 lists devices A and B (stored in device_id order)', 'r2AB');
importList('olderRevisionIsNotApplied', 'Revision 1 again: a lying server replays an older list', 'r1Empty');
importList('sameRevisionIsNotApplied', 'Revision 2 again', 'r2AB');
select('identityThenDevicesInOrder', 'Identity key, then A, then B', NOW);
sequence.push({ name: 'revocationStatementIsHeld', description: 'The receiver holds the identity statement of version 1 that revokes device B', op: 'importRevocation', statement: 'v1RevokesB' });
revocations.import(statements.v1RevokesB, { expectedIdentity: ownerTrust });
select('revokedDeviceIsSkipped', 'Device B is revoked by the statement the receiver holds, although the list (revision 2) still names it', NOW);
select('expiredCertificateIsSkipped', 'One day later the certificates of A and B have expired', NOW + DAY);
select('staleListAddsNoDevice', 'At expires_at_ms the list adds no device', NOW + 7 * DAY);
importList('revisionThreeApplies', 'Revision 3 (A, B and C; it carries revocation_version 1 and names B because this fixture has not removed it)', 'r3ABC');
select('revisionThreeStillHonoursTheStatement', 'Device B stays skipped because of the statement', NOW);
sequence.push({ name: 'pinnedEncryptionKeysDiffer', description: 'The receiver already trusts other identity encryption keys for this identity: a list that carries different ones is refused', op: 'importList', list: 'r3ABC', pinnedEncKeysOf: 'stranger', expectedError: code(() => new ms.Pal3DeviceListStore().import(lists.r3ABC, { expectedIdentity: ownerTrust, now: NOW, pinnedEncKeys: party.stranger.enc })) });
if (sequence.at(-1).expectedError !== 'E_PAL3_DEVICE_LIST_ENCKEY_CHANGED') throw new Error('pin');

// ---- device_signed
const body = Buffer.from('a device-signed body', 'utf8');
const ds = (context, b, certBytes, signing, attach = true) => ms.signAsDevice({ context, body: b, deviceCert: certBytes, deviceKeys: signing, attachCertificate: attach, sign });
const dsOk = ds('message', body, certA, party.deviceA.signing);
const deviceSigned = [{ name: 'deviceSignsWithBothAlgorithms', description: 'Device A signs with its own Ed25519 and ML-DSA-65 keys and attaches its certificate', context: 'message', bodyHex: hex(body), signedHex: hex(dsOk), nowMs: NOW }];
const dsDetached = ds('message', body, certA, party.deviceA.signing, false);
deviceSigned.push({ name: 'certificateKnownToTheVerifier', description: 'The certificate is not attached: the verifier holds it under its SHA-384 hash', context: 'message', bodyHex: hex(body), signedHex: hex(dsDetached), nowMs: NOW, knownCertificatesHex: [hex(certA)] });
for (const s of deviceSigned) {
  const known = new Map((s.knownCertificatesHex || []).map((c) => [hex(sha384(Buffer.from(c, 'hex'))), Buffer.from(c, 'hex')]));
  ms.verifyDeviceSigned(Buffer.from(s.signedHex, 'hex'), { context: s.context, body: Buffer.from(s.bodyHex, 'hex'), expectedIdentity: ownerTrust, knownCertificates: known, now: NOW });
}
const dsRejected = [];
function rejectSigned(name, description, signed, { context = 'message', bodyBuf = body, trusted = 'owner', known = [], nowMs = NOW, statement = null } = {}, expectedError) {
  const knownMap = new Map(known.map((c) => [hex(sha384(c)), c]));
  const rev = new Pal3RevocationStore();
  if (statement) rev.import(statement, { expectedIdentity: ownerTrust });
  const got = code(() => ms.verifyDeviceSigned(signed, { context, body: bodyBuf, expectedIdentity: trusted === 'owner' ? ownerTrust : strangerTrust, knownCertificates: knownMap, revocationStore: rev, now: nowMs }));
  if (got !== expectedError) throw new Error(`reference answered ${got}, not ${expectedError}: ${name}`);
  dsRejected.push({ name, description, context, bodyHex: hex(bodyBuf), signedHex: hex(signed), nowMs, trustedIdentity: trusted, knownCertificatesHex: known.map(hex), statementHex: statement ? hex(statement) : null, expectedError });
}
const parts = decodeTlv(dsOk);
rejectSigned('ed25519SignatureOnly', 'The ML-DSA-65 part is missing: an Ed25519-only device signature is refused', encodeTlv([...parts].filter(([t]) => t !== 4)), {}, 'E_PAL3_DEVICE_SIG_INVALID');
rejectSigned('mlDsaPartFromAnotherSigner', 'The Ed25519 part is the device and the ML-DSA part is a stranger\'s signature', encodeTlv([...parts].map(([t, v]) => [t, t === 4 ? decodeTlv(ds('message', body, certA, party.deviceB.signing)).get(4) : v])), {}, 'E_PAL3_DEVICE_SIG_INVALID');
rejectSigned('contextChanged', 'The verifier expects another context', dsOk, { context: 'share-key' }, 'E_PAL3_DEVICE_SIG_INVALID');
rejectSigned('bodyChanged', 'The body differs from the signed one', dsOk, { bodyBuf: Buffer.from('another body') }, 'E_PAL3_DEVICE_SIG_INVALID');
rejectSigned('deviceOfAnotherIdentity', 'The certificate is issued by an identity the verifier does not trust for this signer', dsOk, { trusted: 'stranger' }, 'E_PAL3_DEVICE_SIG_ISSUER_MISMATCH');
rejectSigned('certificateExpired', 'The certificate expired one day later', dsOk, { nowMs: NOW + DAY }, 'E_PAL3_CERT_EXPIRED');
rejectSigned('certificateNotAvailable', 'No certificate attached and none known', dsDetached, {}, 'E_PAL3_DEVICE_CERT_UNKNOWN');
rejectSigned('certificateHashDoesNotMatch', 'The attached certificate is another device certificate than the hash names', encodeTlv([...parts].map(([t, v]) => [t, t === 2 ? Buffer.from(certificates.deviceB.certHex, 'hex') : v])), {}, 'E_PAL3_DEVICE_SIG_INVALID');
rejectSigned('deviceIsRevoked', 'The verifier holds a revocation statement that revokes device A', dsOk, { statement: statement({ version: 1, revoked: [party.deviceA.deviceId] }) }, 'E_PAL3_DEVICE_REVOKED');
const forgedCert = cert({ device: party.deviceA.signing, deviceId: party.deviceA.deviceId, enc: party.deviceA.enc, signer: party.deviceB.signing });
rejectSigned('deviceIssuedItsOwnCertificate', 'A malicious device signs its own certificate with its device keys: the chain to the identity does not verify', ds('message', body, forgedCert, party.deviceA.signing), {}, 'E_PAL3_CERT_INVALID');

const doc = {
  specVersion: '0.6.21',
  section: '11.4',
  description: 'Sealing to an identity and its devices: sealed_content, device encryption keys in the device certificate (tag 0xC010), the signed device_list with the receiver rules, and device_signed objects (Ed25519 and ML-DSA-65).',
  generatedBy: 'bin/generate-v0.6-multi-seal-vectors.mjs',
  limits: { maxRecipients: 16, maxPlaintextBytes: 32768, maxContextBytes: 64, wrapBytes: 1184, deviceListMaxDevices: 15, deviceListEntryBytes: 1240, deviceListMaxLifetimeMs: 7 * DAY, maxClockSkewMs: 300000 },
  identity: { edPkHex: hex(owner.edPublicKey), dsaPkHex: hex(owner.dsaPublicKey) },
  strangerIdentity: { edPkHex: hex(stranger.edPublicKey), dsaPkHex: hex(stranger.dsaPublicKey) },
  keys: keysDoc,
  deviceIds: { deviceA: hex(party.deviceA.deviceId), deviceB: hex(party.deviceB.deviceId), deviceC: hex(party.deviceC.deviceId) },
  sealedContent,
  sealedRejected,
  sealRejected,
  certificates,
  deviceLists: listDocs,
  deviceListsRejected: listsRejected,
  statements: Object.fromEntries(Object.entries(statements).map(([k, v]) => [k, hex(v)])),
  receiverSequence: sequence,
  deviceSigned,
  deviceSignedRejected: dsRejected,
};
writeFileSync(out, `${JSON.stringify(doc, null, 2)}\n`);
console.log(`wrote ${out}: ${sealedContent.length} sealed, ${sealedRejected.length + sealRejected.length} sealing rejections, ${listDocs.length} lists, ${listsRejected.length} list rejections, ${sequence.length} steps, ${deviceSigned.length} signed, ${dsRejected.length} signed rejections`);
