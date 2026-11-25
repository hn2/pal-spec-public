// pal-core commit needed: 7d211e05a8800431d5c5bf1ec5aa38079dd9e4ae^ (the parent of "SHA-384 as the only hash", hn2/pal-core#371).
// Check out that commit, install @noble/post-quantum 0.7.1 and sodium-native 4.3.3 in the checkout root, then run:
//   node test-vectors/v3/generators/stored-device-cert-pre-sha384.mjs --pal-core <checkout> [--out <file>]
// Generates test-vectors/v3/pal3-stored-state-migration-vectors.json (section 12.5 rule 3).
// Fixed seeds, device id and timestamps; ML-DSA is signed in the deterministic FIPS 204 mode, so two runs are byte-identical.
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadReference } from '../../../bin/vector-signing.mjs';

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : null; };
const palCore = opt('--pal-core');
if (!palCore) { console.error('usage: node stored-device-cert-pre-sha384.mjs --pal-core <path at the commit before SHA-384> [--out <file>]'); process.exit(2); }
const out = opt('--out') || resolve(dirname(fileURLToPath(import.meta.url)), '../pal3-stored-state-migration-vectors.json');

const { lib, ml_dsa65, sodium } = await loadReference(palCore);
const { generateHybridSigningIdentity, issueDeviceCertificate, verifyDeviceCertificate } = await lib('pal3/handshake.js');
const { encodeTlv, decodeTlv } = await lib('pal3/tlv.js');

const hex = (b) => Buffer.from(b).toString('hex');
const identity = generateHybridSigningIdentity({ edSeed: Buffer.alloc(32, 0x71), dsaSeed: Buffer.alloc(32, 0x72) });
const device = generateHybridSigningIdentity({ edSeed: Buffer.alloc(32, 0x73), dsaSeed: Buffer.alloc(32, 0x74) });
const deviceId = Buffer.alloc(16, 0x75);
const OLD_ISSUED_AT = 1763000000000;
const MIGRATED_ISSUED_AT = 1763900000000;
const LIFETIME = 365 * 24 * 3600 * 1000;

const reference = issueDeviceCertificate({
  identity, device: { edPublicKey: device.edPublicKey, dsaPublicKey: device.dsaPublicKey }, deviceId,
  selfCertified: false, issuedAtMs: OLD_ISSUED_AT, expiresAtMs: OLD_ISSUED_AT + LIFETIME,
});
const fields = decodeTlv(reference, 1 << 20);
const bodyOf = (issuedAtMs) => {
  const body = [[0x0001, fields.get(0x0001)], [0x0002, identity.edPublicKey], [0x0003, identity.dsaPublicKey], [0x0004, deviceId],
    [0x0005, device.edPublicKey], [0x0006, device.dsaPublicKey]];
  const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
  body.push([0x0007, u64(issuedAtMs)], [0x0008, u64(issuedAtMs + LIFETIME)]);
  return body;
};
function signed(issuedAtMs, hashName) {
  const body = bodyOf(issuedAtMs);
  const bodyBytes = encodeTlv(body, 1 << 20);
  const msg = Buffer.concat([Buffer.from('pal3-devcert-v1', 'ascii'), createHash(hashName).update(bodyBytes).digest()]);
  const sigEd = Buffer.alloc(64);
  sodium.crypto_sign_detached(sigEd, msg, identity.edSecretKey);
  const sigDsa = Buffer.from(ml_dsa65.sign(msg, identity.dsaSecretKey, { context: Buffer.from('pal3-devcert-v1'), extraEntropy: false }));
  return encodeTlv([...body, [0x0009, sigEd], [0x000a, sigDsa]], 1 << 20);
}

const oldForm = signed(OLD_ISSUED_AT, 'sha256');
verifyDeviceCertificate(oldForm, { now: OLD_ISSUED_AT + 1000 });
const migrated = signed(MIGRATED_ISSUED_AT, 'sha384');

const vector = {
  specVersion: '0.6.20',
  section: '12.5 rule 3, 11.3, A.1',
  description: 'Stored device enrollment certificate signed before SHA-384 became the only hash (message = ascii("pal3-devcert-v1") || SHA-256(body)), and the certificate the migration issues for the same device (message = ascii("pal3-devcert-v1") || SHA-384(body)). Reference: hn2/pal-core before 7d211e0, hn2/palexplorer#1571 and #1572.',
  cases: [{
    case: 'device-cert-pre-sha384',
    oldFormHex: hex(oldForm),
    deviceId: hex(deviceId),
    devicePublicKeys: { device_ed25519_pk: hex(device.edPublicKey), device_mldsa65_pk: hex(device.dsaPublicKey) },
    expectedAfterMigration: {
      deviceId: hex(deviceId),
      devicePublicKeys: { device_ed25519_pk: hex(device.edPublicKey), device_mldsa65_pk: hex(device.dsaPublicKey) },
      certVerifiesUnderCurrentRules: true,
      certChanged: true,
      migratedFormHex: hex(migrated),
    },
  }],
};
writeFileSync(out, `${JSON.stringify(vector, null, 2)}\n`);
console.log(`wrote ${out}`);
