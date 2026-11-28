// Generates test-vectors/v3/pal3-v0.6-enrollment-binding-vectors.json (spec 11.3 item 2 and 11.2 item 2, hn2/pal-spec#94).
// Both are product behaviour with no reference implementation in pal-core: each case records inputs and the expected decision, written from the
// specification text. validate.mjs checks them with a model written from the same text; a product replays the file against its own code.
// Run: node bin/generate-v0.6-enrollment-binding-vectors.mjs [--out <file>]
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const args = process.argv.slice(2);
const i = args.indexOf('--out');
const out = i >= 0 ? args[i + 1] : resolve(dirname(fileURLToPath(import.meta.url)), '../test-vectors/v3/pal3-v0.6-enrollment-binding-vectors.json');

const c = (name, description, input, expected) => ({ name, description, input, expected });
const NOW = 1_800_000_000_000;
const DAY = 86_400_000;

// 11.3 item 2: what a device does when it loads its identity. "form" is the certificate it holds: selfCertified (flags 0x01, device_id derived from the
// identity key), delegated (flags 0x00) or none. deviceIdSource says where the held device_id came from.
const enrollment = [
  c('selfCertifiedEnrollsOnFirstLoad', 'A self-certified device with the identity secret key enrolls itself on first load', { form: 'selfCertified', identitySecretKeyPresent: true, nowMs: NOW }, { action: 'enroll', newDeviceKeys: true, deviceIdSource: 'random16', certFlags: 0, keepsDeviceId: true }),
  c('noIdentitySecretKeyCannotSelfEnroll', 'A device that holds only device keys cannot issue its own delegated certificate; it waits for one issued at pairing', { form: 'selfCertified', identitySecretKeyPresent: false, nowMs: NOW }, { action: 'none', reason: 'needsPairingIssuedCertificate' }),
  c('delegatedBeforeExpiryRenewsWithSameDeviceId', 'A delegated certificate is renewed before expires_at_ms with the same device_id', { form: 'delegated', identitySecretKeyPresent: true, nowMs: NOW, expiresAtMs: NOW + 2 * DAY, renewWindowMs: 7 * DAY }, { action: 'renew', newDeviceKeys: false, deviceIdSource: 'unchanged', certFlags: 0, keepsDeviceId: true }),
  c('delegatedFarFromExpiryIsLeftAlone', 'Outside the renewal window nothing is done', { form: 'delegated', identitySecretKeyPresent: true, nowMs: NOW, expiresAtMs: NOW + 60 * DAY, renewWindowMs: 7 * DAY }, { action: 'none', reason: 'notDueForRenewal' }),
  c('delegatedWithoutSecretKeyCannotRenewItself', 'Renewal needs the identity secret key on the device', { form: 'delegated', identitySecretKeyPresent: false, nowMs: NOW, expiresAtMs: NOW + 2 * DAY, renewWindowMs: 7 * DAY }, { action: 'none', reason: 'needsPairingIssuedCertificate' }),
  c('deviceIdMustNotBeDerivedFromTheIdentityKey', 'A device_id that equals the identity-derived value of the self-certified form is not acceptable for a delegated certificate', { form: 'delegated', identitySecretKeyPresent: true, nowMs: NOW, expiresAtMs: NOW + 2 * DAY, renewWindowMs: 7 * DAY, deviceIdSource: 'derivedFromIdentityKey' }, { action: 'reject', reason: 'deviceIdDerivedFromIdentity' }),
];

// 11.3 items 2 and 6: which certificate forms a receiver accepts. "revocationStatementHeld" says whether the receiver holds any revocation statement for the identity.
const receiverForms = [
  c('delegatedAcceptedWithoutStatement', 'A receiver with no statement accepts the delegated form', { form: 'delegated', revocationStatementHeld: false }, { accept: true }),
  c('selfCertifiedAcceptedWithoutStatement', 'A receiver with no statement still accepts the self-certified form (migration)', { form: 'selfCertified', revocationStatementHeld: false }, { accept: true }),
  c('delegatedAcceptedWithStatement', 'With a statement held, a delegated certificate whose device_id is not revoked is accepted', { form: 'delegated', revocationStatementHeld: true }, { accept: true }),
  c('selfCertifiedRefusedOnceAStatementIsHeld', 'Once any statement is held the self-certified form is refused: its device_id cannot be revoked separately', { form: 'selfCertified', revocationStatementHeld: true }, { accept: false, error: 'E_PAL3_DEVICE_REVOKED' }),
];

// 11.2 item 2: every operation binds the acting identity to the identity of the handshake-verified certificate.
const callerBinding = [
  c('claimMatchesVerifiedCertificate', 'The identity a request acts as equals the identity of the verified certificate', { verifiedCertificateIdentity: 'idA', claimedIdentity: 'idA', certificateVerified: true }, { allowed: true }),
  c('claimForAnotherIdentityIsRefused', 'A request that names another identity than the verified certificate is refused', { verifiedCertificateIdentity: 'idA', claimedIdentity: 'idB', certificateVerified: true }, { allowed: false }),
  c('noVerifiedCertificateIsRefused', 'Without a handshake-verified certificate no identity can be bound', { verifiedCertificateIdentity: null, claimedIdentity: 'idA', certificateVerified: false }, { allowed: false }),
  c('missingClaimActsAsTheCertificateIdentity', 'An operation that names no identity acts as the certificate identity', { verifiedCertificateIdentity: 'idA', claimedIdentity: null, certificateVerified: true }, { allowed: true, actsAs: 'idA' }),
];

writeFileSync(out, JSON.stringify({ description: 'PAL/3 Draft 0.6 decision vectors for section 11.3 item 2 (enrollment and migration) and 11.2 item 2 (caller binding). Written from the specification text; no reference implementation exists in pal-core.', version: 'v0.6', enrollment, receiverForms, callerBinding }, null, 2) + '\n');
console.log(`wrote ${out}`);
