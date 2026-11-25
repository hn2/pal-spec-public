// Generates test-vectors/v3/pal3-v0.6-device-revocation-vectors.json (spec section 11.3, A.1 device_cert and revocation_statement)
// with the reference implementation. Every object is signed again in the deterministic FIPS 204 mode (see vector-signing.mjs), so two runs are byte-identical.
// Run: node bin/generate-v0.6-device-revocation-vectors.mjs --pal-core <path to the hn2/pal-core checkout> [--out <file>]
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadReference, deterministicSigner } from './vector-signing.mjs';

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : null; };
const palCore = opt('--pal-core');
if (!palCore) { console.error('usage: node bin/generate-v0.6-device-revocation-vectors.mjs --pal-core <path> [--out <file>]'); process.exit(2); }
const out = opt('--out') || resolve(dirname(fileURLToPath(import.meta.url)), '../test-vectors/v3/pal3-v0.6-device-revocation-vectors.json');

const ref = await loadReference(palCore);
const sign = deterministicSigner(ref);
const { generateHybridSigningIdentity, verifyDeviceCertificate, pal3IdentityDigest } = await ref.lib('pal3/handshake.js');
const { Pal3RevocationStore } = await ref.lib('pal3/revocation.js');
const { encodeTlv, u8Buf, u64Buf } = await ref.lib('pal3/tlv.js');

const hex = (b) => Buffer.from(b).toString('hex');
const code = (fn) => { try { fn(); return 'accepted'; } catch (err) { return /^(E_[A-Z0-9_]+)/.exec(err.message)?.[1] ?? err.message; } };
const NOW = 1762560000000;
const DAY = 86_400_000;
const id = (seed) => generateHybridSigningIdentity({ edSeed: Buffer.alloc(32, seed), dsaSeed: Buffer.alloc(32, seed + 1) });
const owner = id(0x31);
const other = id(0x33);
const deviceA = id(0x35);
const deviceB = id(0x37);
const ids = { A: Buffer.alloc(16, 0xa1), B: Buffer.alloc(16, 0xb2), C: Buffer.alloc(16, 0xc3) };
const pk = (i) => ({ edPkHex: hex(i.edPublicKey), dsaPkHex: hex(i.dsaPublicKey) });

// device_cert (A.1): body = tags 0x0001..0x0008 (and extension tags), signed by `signer` under pal3-devcert-v1.
function cert({ flags = 0, deviceId, device = null, issuedAtMs = NOW - 1000, expiresAtMs = NOW + 365 * DAY, extra = [], signer = owner, identity = owner, tamper = null }) {
  const body = [[1, u8Buf(flags)], [2, identity.edPublicKey], [3, identity.dsaPublicKey], [4, deviceId]];
  if (device) body.push([5, device.edPublicKey], [6, device.dsaPublicKey]);
  body.push([7, u64Buf(issuedAtMs)], [8, u64Buf(expiresAtMs)], ...extra);
  const bodyBytes = encodeTlv(body);
  const { sigEd25519, sigMldsa65 } = sign({ domain: 'pal3-devcert-v1', dsaContext: 'pal3-devcert-v1', body: bodyBytes, edSecretKey: signer.edSecretKey, dsaSecretKey: signer.dsaSecretKey });
  const signed = tamper ? body.map(([t, v]) => (t === tamper.tag ? [t, tamper.value] : [t, v])) : body;
  return encodeTlv([...signed, [9, sigEd25519], [10, sigMldsa65]]);
}
function statement({ identity = owner, version, revoked = [], issuedAtMs = NOW, signer = identity, deviceIdBytes = null }) {
  const packed = deviceIdBytes ?? Buffer.concat(revoked);
  const body = [[1, identity.edPublicKey], [2, identity.dsaPublicKey], [3, u64Buf(BigInt(version))], [4, u64Buf(BigInt(issuedAtMs))], [5, packed]];
  const bodyBytes = encodeTlv(body);
  const { sigEd25519, sigMldsa65 } = sign({ domain: 'pal3-revocation-v1', dsaContext: 'pal3-revocation-v1', body: bodyBytes, edSecretKey: signer.edSecretKey, dsaSecretKey: signer.dsaSecretKey });
  return encodeTlv([...body, [9, sigEd25519], [10, sigMldsa65]]);
}

const certs = {
  delegatedA: cert({ deviceId: ids.A, device: deviceA }),
  delegatedB: cert({ deviceId: ids.B, device: deviceB }),
  selfCertified: cert({ flags: 1, deviceId: ids.C }),
  withOptionalExtension: cert({ deviceId: ids.A, device: deviceA, extra: [[0xc001, Buffer.from('ignored')]] }),
};
const positiveCerts = [
  ['delegatedDeviceCertificate', 'Delegated certificate (flags 0x00): the identity signs the device keys and a 16-byte device_id', 'delegatedA'],
  ['selfCertifiedCertificate', 'Self-certified certificate (flags 0x01): no device key tags, the identity keys are the device keys', 'selfCertified'],
  ['optionalExtensionIsIgnored', 'A comprehension-optional extension tag (0xC001) is covered by the signature and ignored by a verifier that does not know it', 'withOptionalExtension'],
].map(([name, description, key]) => {
  const r = verifyDeviceCertificate(certs[key], { now: NOW });
  return {
    name, description, certHex: hex(certs[key]), nowMs: NOW, flags: r.flags, deviceIdHex: hex(r.deviceId),
    identity: pk(owner), deviceEdPkHex: hex(r.deviceEdPk), deviceDsaPkHex: hex(r.deviceDsaPk), expectedError: null,
  };
});

const rejectedCerts = [];
function rejectCert(name, description, bytes, expectedError, nowMs = NOW) {
  const got = code(() => verifyDeviceCertificate(bytes, { now: nowMs }));
  if (got !== expectedError) throw new Error(`reference answered ${got}, not ${expectedError}: ${name}`);
  rejectedCerts.push({ name, description, certHex: hex(bytes), nowMs, identity: pk(owner), expectedError });
}
rejectCert('expiredCertificate', 'now is at expires_at_ms: a certificate is valid only before it', certs.delegatedA, 'E_PAL3_CERT_EXPIRED', NOW + 365 * DAY);
rejectCert('issuedMoreThanFiveMinutesAhead', 'issued_at_ms is 6 minutes after the verifier clock', cert({ deviceId: ids.A, device: deviceA, issuedAtMs: NOW + 6 * 60_000 }), 'E_PAL3_CERT_FUTURE');
rejectCert('deviceKeySignsItsOwnCertificate', 'A malicious device signs a certificate for itself with its device keys: the signature does not verify under the identity keys',
  cert({ deviceId: ids.B, device: deviceB, signer: deviceB }), 'E_PAL3_CERT_INVALID');
rejectCert('deviceIdChangedAfterSigning', 'The device_id is replaced after signing', cert({ deviceId: ids.A, device: deviceA, tamper: { tag: 4, value: ids.B } }), 'E_PAL3_CERT_INVALID');
rejectCert('deviceKeysSwappedAfterSigning', 'The device keys are replaced by another device after signing',
  cert({ deviceId: ids.A, device: deviceA, tamper: { tag: 5, value: deviceB.edPublicKey } }), 'E_PAL3_CERT_INVALID');
rejectCert('unknownFlags', 'flags 0x02 is neither delegated nor self-certified', cert({ flags: 2, deviceId: ids.A, device: deviceA }), 'E_PAL3_CERT_INVALID');
rejectCert('selfCertifiedWithDeviceKeys', 'A self-certified certificate that also carries device key tags', cert({ flags: 1, deviceId: ids.C, device: deviceA }), 'E_PAL3_CERT_INVALID');
rejectCert('unknownCriticalExtension', 'A critical extension tag (0x8001) the verifier does not know: the certificate is refused', cert({ deviceId: ids.A, device: deviceA, extra: [[0x8001, Buffer.from('x')]] }), 'E_PAL3_UNSUPPORTED_CRITICAL_EXTENSION');
rejectCert('unknownCoreTag', 'An unknown tag below 0x8000', cert({ deviceId: ids.A, device: deviceA, extra: [[0x0042, Buffer.from('x')]] }), 'E_PAL3_UNKNOWN_CORE_TAG');

const st = {
  v1Empty: statement({ version: 1 }),
  v2RevokesA: statement({ version: 2, revoked: [ids.A] }),
  v3RevokesAAndB: statement({ version: 3, revoked: [ids.A, ids.B] }),
  v3SameVersionOtherSet: statement({ version: 3, revoked: [ids.C] }),
  v2Rollback: statement({ version: 2, revoked: [] }),
  forOtherIdentity: statement({ identity: other, version: 9, revoked: [ids.A] }),
  signedByDevice: statement({ version: 10, revoked: [ids.B], signer: deviceA }),
  ragged: statement({ version: 11, deviceIdBytes: Buffer.alloc(17, 1) }),
};
const statements = Object.fromEntries(Object.entries(st).map(([k, b]) => [k, hex(b)]));

// A receiver sequence. `trustedIdentity` names the key pair the receiver already trusts for the sender.
const store = new Pal3RevocationStore();
const steps = [];
const trusted = { owner, other };
function importStep(name, description, key, trust = 'owner') {
  let result;
  const got = code(() => { result = store.import(st[key], { expectedIdentity: trusted[trust] }); });
  steps.push({ name, description, op: 'import', statement: key, trustedIdentity: trust, ...(got === 'accepted' ? { expected: { applied: result.applied, version: String(result.version) } } : { expectedError: got }) });
}
function peerStep(name, description, certKey, expectedError = null) {
  const parsed = verifyDeviceCertificate(certs[certKey], { now: NOW });
  const got = code(() => store.assertPeerAllowed(parsed));
  if (got !== (expectedError ?? 'accepted')) throw new Error(`reference answered ${got} for ${name}`);
  steps.push({ name, description, op: 'assertPeer', cert: certKey, expectedError });
}
peerStep('noStatementYet_delegatedAccepted', 'No statement is held: both certificate forms are accepted', 'delegatedA');
peerStep('noStatementYet_selfCertifiedAccepted', 'No statement is held: the self-certified form is accepted', 'selfCertified');
importStep('firstStatementIsApplied', 'Version 1 with an empty set is the first statement', 'v1Empty');
peerStep('afterAnyStatement_selfCertifiedRefused', 'Once any statement is held the identity self-certified certificates are refused: their device_id cannot be revoked', 'selfCertified', 'E_PAL3_DEVICE_REVOKED');
peerStep('emptySet_delegatedAccepted', 'A delegated certificate whose device_id is not in the set', 'delegatedA');
importStep('revocationVersion2Applies', 'Version 2 revokes device A', 'v2RevokesA');
peerStep('revokedDeviceRefused', 'Device A is in the revoked set', 'delegatedA', 'E_PAL3_DEVICE_REVOKED');
peerStep('otherDeviceStillAccepted', 'Device B is not revoked', 'delegatedB');
importStep('rollbackToOlderVersionIsNotApplied', 'A correctly signed older statement (version 1, stored is 2) must not roll the revocation back', 'v1Empty');
importStep('sameVersionIsNotApplied', 'The same version as the stored one (2, with an empty set) is not applied', 'v2Rollback');
importStep('version3Applies', 'Version 3 revokes A and B', 'v3RevokesAAndB');
importStep('sameVersionOtherSetIsNotApplied', 'Version 3 again with another set (an attempt to change the set at the same version) is not applied', 'v3SameVersionOtherSet');
peerStep('deviceBRevokedAfterVersion3', 'Device B is revoked by version 3 and stays revoked', 'delegatedB', 'E_PAL3_DEVICE_REVOKED');
importStep('statementForAnotherIdentityIsRefused', 'A valid statement whose issuer is not the identity the receiver trusts for the sender', 'forOtherIdentity');
importStep('statementSignedByADeviceIsRefused', 'A malicious device signs a statement with its device keys', 'signedByDevice');
importStep('malformedDeviceIdListIsRefused', 'revoked_device_ids of 17 bytes is not a multiple of 16', 'ragged');

const doc = {
  specVersion: '0.6.20',
  section: '11.3',
  description: 'Device certificates (A.1 device_cert, domain and ML-DSA context pal3-devcert-v1), identity-signed revocation statements (pal3-revocation-v1) and the receiver rules of 11.3 items 3, 4 and 6.',
  generatedBy: 'bin/generate-v0.6-device-revocation-vectors.mjs',
  identity: { ...pk(owner), digestHex: hex(pal3IdentityDigest(owner.edPublicKey, owner.dsaPublicKey)) },
  otherIdentity: pk(other),
  deviceIds: Object.fromEntries(Object.entries(ids).map(([k, v]) => [k, hex(v)])),
  certificates: positiveCerts,
  certificatesRejected: rejectedCerts,
  certificateHex: Object.fromEntries(Object.entries(certs).map(([k, v]) => [k, hex(v)])),
  statements,
  receiverSequence: steps,
  finalStoredVersion: String(store.versionFor(owner)),
};
writeFileSync(out, `${JSON.stringify(doc, null, 2)}\n`);
console.log(`wrote ${out}: ${positiveCerts.length} certificates, ${rejectedCerts.length} rejected, ${steps.length} steps`);
