// Generates test-vectors/v3/pal3-v0.6-extension-signing-vectors.json (spec section 12.2, A.5 item 7) with the reference implementation.
// Run: node bin/generate-v0.6-extension-signing-vectors.mjs --pal-core <path to the hn2/pal-core checkout with dependencies> [--out <file>]
// Identities come from fixed seeds and ML-DSA is signed in the deterministic mode (see vector-signing.mjs), so two runs are byte-identical.
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadReference, deterministicSigner } from './vector-signing.mjs';

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : null; };
const palCore = opt('--pal-core');
if (!palCore) { console.error('usage: node bin/generate-v0.6-extension-signing-vectors.mjs --pal-core <path> [--out <file>]'); process.exit(2); }
const out = opt('--out') || resolve(dirname(fileURLToPath(import.meta.url)), '../test-vectors/v3/pal3-v0.6-extension-signing-vectors.json');

const ref = await loadReference(palCore);
const sign = deterministicSigner(ref);
const { generateHybridSigningIdentity } = await ref.lib('pal3/handshake.js');
const { signPal3ExtensionBundle, issuePal3PublisherCertificate, verifyPal3ExtensionBundle } = await ref.lib('pal3/extensions.js');
const { encodeValue, decodeValue } = await ref.lib('pal3/tlv.js');

const hex = (b) => Buffer.from(b).toString('hex');
const identityOf = (byte) => generateHybridSigningIdentity({ edSeed: Buffer.alloc(32, byte), dsaSeed: Buffer.alloc(32, byte + 1) });
const root = identityOf(0x71);
const publisher = identityOf(0x73);
const stranger = identityOf(0x75);
const pk = (id) => ({ edPkHex: hex(id.edPublicKey), dsaPkHex: hex(id.dsaPublicKey) });
const trustedRoots = [{ id: 'vector-root', edPublicKey: root.edPublicKey, dsaPublicKey: root.dsaPublicKey }];
const ISSUED = 1762560000000;
const NOW = ISSUED + 1000;
const code = (fn) => { try { fn(); return 'accepted'; } catch (err) { return /^(E_[A-Z0-9_]+)/.exec(err.message)?.[1] ?? err.message; } };

const BUNDLE = { domain: 'pal3-ext-bundle-v1', dsaContext: 'pal3-ext-sig-v1' };
const CERT = { domain: 'pal3-ext-publisher-cert-v1', dsaContext: 'pal3-ext-cert-v1' };

function resign({ labels, body, id }) {
  const s = sign({ ...labels, body, edSecretKey: id.edSecretKey, dsaSecretKey: id.dsaSecretKey });
  return { body, ...s, envelope: encodeValue({ body, sigEd25519: s.sigEd25519, sigMldsa65: s.sigMldsa65 }) };
}
function reSignedFromReference(reference, labels, id) {
  return resign({ labels, id, body: decodeValue(reference).body });
}
function object(name, description, labels, id, g, extra = {}) {
  return {
    name, description, ...labels, signer: pk(id),
    bodyHex: hex(g.body), sigEd25519Hex: hex(g.sigEd25519), sigMldsa65Hex: hex(g.sigMldsa65), ...extra,
  };
}

const digest = Buffer.alloc(48, 0x42);
const manifest = (id, ops) => ({
  id, name: id, version: '1.0.0', capability: id, supportedTlvTags: [0x8001], operations: ops, permissionVerbs: Object.fromEntries(ops.map((o) => [o, 'read'])),
  permissions: ['read:share'], contentDigest: digest,
});

// Root-signed bundle.
const rootBundle = reSignedFromReference(signPal3ExtensionBundle({ manifest: manifest('com.vector.alpha', ['alpha.ping']), signerIdentity: root, issuedAtMs: ISSUED }), BUNDLE, root);
// Publisher certificate issued by the root, and a bundle signed by the publisher that carries it.
const certRef = issuePal3PublisherCertificate({
  issuerIdentity: root, publisherId: 'vector-publisher', publisherEdPk: publisher.edPublicKey, publisherDsaPk: publisher.dsaPublicKey,
  allowedExtensions: ['com.vector.*'], allowedPermissions: ['read:*'], issuedAtMs: ISSUED, expiresAtMs: ISSUED + 86_400_000,
});
const cert = reSignedFromReference(certRef, CERT, root);
const delegatedBundle = reSignedFromReference(signPal3ExtensionBundle({
  manifest: manifest('com.vector.beta', ['beta.ping', 'beta.stat']), signerIdentity: publisher, publisherCert: cert.envelope, issuedAtMs: ISSUED,
}), BUNDLE, publisher);
const zeroDigest = reSignedFromReference(signPal3ExtensionBundle({
  manifest: { ...manifest('com.vector.gamma', []), supportedTlvTags: [], contentDigest: Buffer.alloc(48, 0) }, signerIdentity: root, issuedAtMs: ISSUED,
}), BUNDLE, root);

const verify = (g, extra = {}) => code(() => verifyPal3ExtensionBundle(g.envelope, { trustedRoots, now: NOW, ...extra }));
for (const [i, g] of [rootBundle, delegatedBundle, zeroDigest].entries()) {
  const got = verify(g);
  if (got !== 'accepted') throw new Error(`reference rejected positive bundle ${i}: ${got}`);
}
if (verify(rootBundle, { expectedContentDigest: digest }) !== 'accepted') throw new Error('reference rejected the matching content digest');

const bundles = [
  object('rootSignedBundle', 'A bundle signed directly by a trusted root', BUNDLE, root, rootBundle, { trust: 'root' }),
  object('publisherDelegatedBundle', 'A bundle signed by a publisher whose certificate (publisherCert in the body) was issued by the trusted root and covers com.vector.*', BUNDLE, publisher, delegatedBundle, { trust: 'publisherCert' }),
  object('bundleWithEmptyOperations', 'A root-signed bundle that declares no operation and no TLV tag', BUNDLE, root, zeroDigest, { trust: 'root' }),
];
const publisherCertificates = [
  object('publisherCertificate', 'The certificate of vector-publisher: the issuer is the trusted root, the subject is the publisher keys of publisherDelegatedBundle', CERT, root, cert, { trust: 'root' }),
];

const rejected = [];
const reject = (name, description, g, id, labels, expectedError, extra = {}) => {
  const got = verify(g);
  if (got !== expectedError) throw new Error(`reference answered ${got}, not ${expectedError}: ${name}`);
  rejected.push(object(name, description, labels, id, g, { expectedError, trustedRootEdPkHex: hex(root.edPublicKey), ...extra }));
};
reject('strippedMldsaSignature', 'The ML-DSA-65 signature of a root-signed bundle is removed: strict-AND fails', { ...rootBundle, sigMldsa65: Buffer.alloc(0), envelope: encodeValue({ body: rootBundle.body, sigEd25519: rootBundle.sigEd25519, sigMldsa65: Buffer.alloc(0) }) }, root, BUNDLE, 'E_PAL3_EXT_AUTH_FAILED');
const flipped = Buffer.from(rootBundle.sigEd25519);
flipped[5] ^= 0x01;
reject('flippedEd25519Signature', 'One bit of the Ed25519 signature is flipped', { ...rootBundle, sigEd25519: flipped, envelope: encodeValue({ body: rootBundle.body, sigEd25519: flipped, sigMldsa65: rootBundle.sigMldsa65 }) }, root, BUNDLE, 'E_PAL3_EXT_AUTH_FAILED');
const tamperedBody = encodeValue({ ...decodeValue(rootBundle.body), name: 'com.vector.evil' });
reject('tamperedBody', 'The bundle name is changed after signing', { ...rootBundle, body: tamperedBody, envelope: encodeValue({ body: tamperedBody, sigEd25519: rootBundle.sigEd25519, sigMldsa65: rootBundle.sigMldsa65 }) }, root, BUNDLE, 'E_PAL3_EXT_AUTH_FAILED');
const selfSigned = reSignedFromReference(signPal3ExtensionBundle({ manifest: manifest('com.vector.alpha', ['alpha.ping']), signerIdentity: stranger, issuedAtMs: ISSUED }), BUNDLE, stranger);
reject('selfSignedBundle', 'A valid signature by a key that is neither a trusted root nor backed by a publisher certificate', selfSigned, stranger, BUNDLE, 'E_PAL3_EXT_UNTRUSTED_SIGNER');
// The strangers key signs a bundle that carries the certificate of the real publisher: the certificate subject is another key.
const mismatched = reSignedFromReference(signPal3ExtensionBundle({
  manifest: manifest('com.vector.beta', ['beta.ping']), signerIdentity: stranger, publisherCert: cert.envelope, issuedAtMs: ISSUED,
}), BUNDLE, stranger);
reject('certificateOfAnotherKey', 'The bundle signer presents the publisher certificate of another key', mismatched, stranger, BUNDLE, 'E_PAL3_EXT_CERT_MISMATCH');
const rootDomainSwap = resign({ labels: { domain: 'pal3-ext-publisher-cert-v1', dsaContext: 'pal3-ext-sig-v1' }, id: root, body: rootBundle.body });
reject('bundleSignedUnderTheCertificateLabel', 'A bundle body signed with the publisher-certificate message prefix instead of the bundle prefix', rootDomainSwap, root, BUNDLE, 'E_PAL3_EXT_AUTH_FAILED');

const doc = {
  specVersion: '0.6.20',
  section: '12.2, A.5 item 7',
  rule: 'A signed bundle is a PAL-CBOR map { body, sigEd25519, sigMldsa65 }. msg = ascii(domain) || SHA-384(body). Bundle: domain "pal3-ext-bundle-v1", ML-DSA context "pal3-ext-sig-v1", signed by signerEdPk and signerDsaPk of the body. Publisher certificate: domain "pal3-ext-publisher-cert-v1", ML-DSA context "pal3-ext-cert-v1", signed by the issuing trusted root. Both signatures MUST verify. The signer is accepted when it equals a trusted root, or when body.publisherCert is a certificate issued by a trusted root whose subject keys equal the signer. All signatures are made in the deterministic ML-DSA mode.',
  trustedRoots: [{ id: 'vector-root', ...pk(root) }],
  verifierNowMs: NOW,
  bundles,
  publisherCertificates,
  rejected,
};
writeFileSync(out, `${JSON.stringify(doc, null, 2)}\n`);
console.log(`wrote ${out}`);
