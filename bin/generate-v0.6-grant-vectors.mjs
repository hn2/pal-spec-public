// Generates test-vectors/v3/pal3-v0.6-grant-vectors.json (spec section 9, A.5 item 3) with the reference implementation.
// Run: node bin/generate-v0.6-grant-vectors.mjs --pal-core <path to the hn2/pal-core checkout with dependencies> [--out <file>]
// Identities come from fixed seeds and ML-DSA is signed in the deterministic mode (see vector-signing.mjs), so two runs are byte-identical.
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadReference, deterministicSigner } from './vector-signing.mjs';

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : null; };
const palCore = opt('--pal-core');
if (!palCore) { console.error('usage: node bin/generate-v0.6-grant-vectors.mjs --pal-core <path> [--out <file>]'); process.exit(2); }
const out = opt('--out') || resolve(dirname(fileURLToPath(import.meta.url)), '../test-vectors/v3/pal3-v0.6-grant-vectors.json');

const ref = await loadReference(palCore);
const sign = deterministicSigner(ref);
const { generateHybridSigningIdentity } = await ref.lib('pal3/handshake.js');
const { issueSignedGrant, verifySignedGrant, PAL3_SUBJECT_TYPES, PAL3_OPERATIONS } = await ref.lib('pal3/permissions.js');
const { encodeValue, decodeValue } = await ref.lib('pal3/tlv.js');

const hex = (b) => Buffer.from(b).toString('hex');
const issuer = generateHybridSigningIdentity({ edSeed: Buffer.alloc(32, 0x61), dsaSeed: Buffer.alloc(32, 0x62) });
const subject = generateHybridSigningIdentity({ edSeed: Buffer.alloc(32, 0x63), dsaSeed: Buffer.alloc(32, 0x64) });
const signer = { edPkHex: hex(issuer.edPublicKey), dsaPkHex: hex(issuer.dsaPublicKey) };
const NOW = 1762560000000;
const code = (fn) => { try { fn(); return 'accepted'; } catch (err) { return /^(E_[A-Z0-9_]+)/.exec(err.message)?.[1] ?? err.message; } };

function resign(body) {
  const { sigEd25519, sigMldsa65 } = sign({ domain: 'pal3-grant-v1', dsaContext: 'pal3-grant-v1', body, edSecretKey: issuer.edSecretKey, dsaSecretKey: issuer.dsaSecretKey });
  return { body, sigEd25519, sigMldsa65, envelope: encodeValue({ body, sigEd25519, sigMldsa65 }) };
}
function fromReference(params) {
  const issued = issueSignedGrant({ issuerIdentity: issuer, ...params });
  return resign(decodeValue(issued).body);
}
function object(name, description, g, extra = {}) {
  return {
    name, description, domain: 'pal3-grant-v1', dsaContext: 'pal3-grant-v1', signer,
    bodyHex: hex(g.body), sigEd25519Hex: hex(g.sigEd25519), sigMldsa65Hex: hex(g.sigMldsa65), ...extra,
  };
}
const bodyMap = (g) => decodeValue(g.body);

const grantA = fromReference({
  grantId: Buffer.alloc(16, 0x11), subjectType: PAL3_SUBJECT_TYPES.IDENTITY, subjectId: subject.edPublicKey, resource: 'share:docs',
  operations: [PAL3_OPERATIONS.READ, PAL3_OPERATIONS.LIST], issuedAtMs: NOW, constraints: { expiresAtMs: NOW + 3600_000 },
});
const grantB = fromReference({
  grantId: Buffer.alloc(16, 0x12), subjectType: PAL3_SUBJECT_TYPES.DEVICE, subjectId: Buffer.concat([subject.edPublicKey, Buffer.alloc(16, 0x77)]),
  resource: 'share:photos/2026/', operations: [PAL3_OPERATIONS.READ], issuedAtMs: NOW,
  constraints: { notBeforeMs: NOW, expiresAtMs: NOW + 86_400_000, maxReads: 5, maxBytes: 1048576, bandwidthBps: 65536, devicesMax: 2, timeWindowUtc: [{ days: [1, 2, 3, 4, 5], startMinute: 480, endMinute: 1020 }] },
});
const grantC = fromReference({
  grantId: Buffer.alloc(16, 0x13), subjectType: PAL3_SUBJECT_TYPES.ANONYMOUS, subjectId: Buffer.alloc(0), resource: '*',
  operations: [PAL3_OPERATIONS.LIST], issuedAtMs: NOW,
});
// An extra map key that no rule of A.5 item 3 names: signed, so it verifies, and a verifier ignores it.
const grantExtra = resign(encodeValue({ ...bodyMap(grantA), futureField: 'ignored by this version' }));

const positives = [
  object('baselineIdentityGrant', 'Read and list of one share for an identity, expires one hour after issue', grantA),
  object('deviceGrantWithAllConstraints', 'Device grant over a folder prefix with every constraint and one UTC time window', grantB),
  object('anonymousListGrant', 'Anonymous list of everything, no expiry (expiresAtMs = 0 means no limit)', grantC),
  object('unknownKeyIsIgnored', 'A grant body with an extra map key outside A.5 item 3: the signature covers it, the verifier accepts the grant and ignores the key', grantExtra),
];
for (const [i, g] of [grantA, grantB, grantC, grantExtra].entries()) {
  const result = code(() => verifySignedGrant(g.envelope, { expectedIssuer: issuer }));
  if (result !== 'accepted') throw new Error(`reference rejected positive case ${i}: ${result}`);
}

const negatives = [];
const reject = (name, description, g, expectedError) => {
  const envelope = encodeValue({ body: g.body, sigEd25519: g.sigEd25519, sigMldsa65: g.sigMldsa65 });
  const got = code(() => verifySignedGrant(envelope, { expectedIssuer: issuer }));
  if (got !== expectedError) throw new Error(`reference answered ${got}, not ${expectedError}: ${name}`);
  negatives.push(object(name, description, g, { expectedError }));
};

reject('signatureCoversAnotherResource', 'The body names share:secret but the signatures were made over the body of share:docs',
  { ...grantA, body: encodeValue({ ...bodyMap(grantA), resource: 'share:secret' }) }, 'E_PAL3_GRANT_AUTH_FAILED');

const flippedSig = Buffer.from(grantA.sigEd25519);
flippedSig[0] ^= 0x01;
reject('flippedEd25519Signature', 'One bit of the Ed25519 signature is flipped (strict-AND: the ML-DSA signature alone is not enough)',
  { ...grantA, sigEd25519: flippedSig }, 'E_PAL3_GRANT_AUTH_FAILED');

reject('strippedMldsaSignature', 'The ML-DSA-65 signature is empty (strict-AND)', { ...grantA, sigMldsa65: Buffer.alloc(0) }, 'E_PAL3_GRANT_AUTH_FAILED');

reject('watermarkIsRefused', 'A signed grant with watermark = true: the constraint cannot be enforced, so the verifier refuses the whole grant (section 9)',
  resign(encodeValue({ ...bodyMap(grantA), watermark: true })), 'E_PAL3_GRANT_UNSUPPORTED_CONSTRAINT');

reject('requirePqFalse', 'requirePq is false: unsupported version or missing requirePq',
  resign(encodeValue({ ...bodyMap(grantA), requirePq: false })), 'E_PAL3_GRANT_INVALID');

reject('unknownVersion', 'Grant body version 2', resign(encodeValue({ ...bodyMap(grantA), v: 2 })), 'E_PAL3_GRANT_INVALID');

// Expiry is a decision on the decoded body, not a signature property: grant.issue answers E_PAL3_ACCESS_EXPIRED (section 7.1).
const expiredAt = NOW + 3600_000;
negatives.push(object('expiredGrant', 'A correctly signed grant whose expiresAtMs is not after the receiver clock (nowMs): grant.issue refuses it with E_PAL3_ACCESS_EXPIRED', grantA, {
  expectedError: 'E_PAL3_ACCESS_EXPIRED', nowMs: expiredAt,
}));

const doc = {
  specVersion: '0.6.20',
  section: '9, A.5 items 3 and 4',
  rule: 'Grant = PAL-CBOR map { body, sigEd25519, sigMldsa65 }; msg = ascii("pal3-grant-v1") || SHA-384(body); both signatures MUST verify with ML-DSA context "pal3-grant-v1". Rules checked on the decoded body: v = 1, requirePq = true, watermark = false (E_PAL3_GRANT_UNSUPPORTED_CONSTRAINT otherwise), issuer keys of 32 and 1952 bytes, and a grant with expiresAtMs > 0 and expiresAtMs <= now is expired (E_PAL3_ACCESS_EXPIRED in grant.issue). Unknown map keys are ignored. All signatures are made in the deterministic ML-DSA mode.',
  objects: positives,
  rejected: negatives,
};
writeFileSync(out, `${JSON.stringify(doc, null, 2)}\n`);
console.log(`wrote ${out}`);
