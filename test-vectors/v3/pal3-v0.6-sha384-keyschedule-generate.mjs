// Regenerates the vectors that depend on the hash of the key schedule, now SHA-384 (hn2/pal-spec#54, Draft 0.6.18):
// pal3-v0.5-vectors (key schedule, identity digest), pal3-v0.6-reset, -beacon, -pair-rendezvous, -primitive (cookie, proof of
// work, binder, manifest revision hashes), -swarm (signed messages, ticket body), and the hybrid-signed objects of
// -core-vectors and -prekey (new key pairs, because the signed digest changed and the old secret keys are not kept).
// Standalone, Node built-ins only. Run: node test-vectors/v3/pal3-v0.6-sha384-keyschedule-generate.mjs
import { createHash, createHmac, hkdfSync, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { deriveSessionChannelMaterial, computeIdentityDigest, encodePalCbor } from '../../validate.mjs';
import { ed25519PublicKey, edPublicToX25519, edSeedToX25519, x25519 } from '../../sealedbox.mjs';

const dir = dirname(fileURLToPath(import.meta.url));
const load = (f) => JSON.parse(readFileSync(join(dir, f), 'utf8'));
const save = (f, o) => writeFileSync(join(dir, f), JSON.stringify(o, null, 2) + '\n');
const sha384 = (b) => createHash('sha384').update(b).digest();
const hmac = (key, data) => createHmac('sha384', key).update(data).digest();
const expand = (prk, info, length = 32) => hmac(prk, Buffer.concat([Buffer.from(info, 'ascii'), Buffer.from([1])])).subarray(0, length);
const hex = (b) => Buffer.from(b).toString('hex');
const rep = (byte, n) => byte.repeat(n);
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };

// pal3-v0.5-vectors: key schedule inputs are now 48-byte hashes, the legacy v2 LAN tag is removed.
{
  const f = 'pal3-v0.5-vectors.json';
  const j = load(f);
  j.specVersion = '0.6.18';
  j.suite = j.suite.replace('SHA256', 'SHA384');
  const i = j.keySchedule.input;
  delete i.mlkemEkISha256Hex; delete i.mlkemCtSha256Hex;
  Object.assign(i, { mlkemEkIHashHex: rep('55', 48), mlkemCtHashHex: rep('66', 48), thHsHex: rep('77', 48), thHex: rep('88', 48) });
  j.keySchedule.expected = deriveSessionChannelMaterial(i);
  delete j.lanBeacon;
  j.identityDigest.expectedDigestHex = computeIdentityDigest(j.identityDigest.ed25519PkHex, j.identityDigest.mldsa65PkHex);
  save(f, j);
}

// pal3-v0.6-reset-vectors
{
  const f = 'pal3-v0.6-reset-vectors.json';
  const j = load(f);
  for (const c of j.statelessResetToken) {
    c.description = c.description.replace('HMAC-SHA-256', 'HMAC-SHA-384');
    c.tokenHex = hex(hmac(Buffer.from(c.resetKeyHex, 'hex'), Buffer.concat([Buffer.from('pal3-stateless-reset-v1'), Buffer.from(c.connectionIdHex, 'hex')])).subarray(0, 16));
  }
  save(f, j);
}

// pal3-v0.6-beacon-vectors: identity digests are 48 bytes, the mailbox location is a full HMAC-SHA-384.
{
  const f = 'pal3-v0.6-beacon-vectors.json';
  const j = load(f);
  for (const p of j.pairBeacon) {
    p.description = p.description.replace(/HMAC-SHA-256/g, 'HMAC-SHA-384');
    const pairKey = expand(Buffer.from(p.exporterSecret0Hex, 'hex'), 'pal3-pair-beacon-v1');
    p.pairBeaconKeyHex = hex(pairKey);
    const bucket = u64(Math.floor(p.unixTimeMs / 1000 / 900));
    const mailboxKey = expand(pairKey, 'pal3-wan-mailbox-v3');
    const lanKey = expand(pairKey, 'pal3-lan-v3');
    p.mailbox.forEach((m, k) => {
      m.recipientIdentityDigestHex = rep(String(k + 1).repeat(2), 48);
      m.locationHex = hex(hmac(mailboxKey, Buffer.concat([Buffer.from(m.recipientIdentityDigestHex, 'hex'), bucket])));
    });
    p.lanTag.forEach((t, k) => {
      t.announcerIdentityDigestHex = rep(String(k + 1).repeat(2), 48);
      t.tagHex = hex(hmac(lanKey, Buffer.concat([Buffer.from(t.announcerIdentityDigestHex, 'hex'), bucket])).subarray(0, 16));
    });
  }
  save(f, j);
}

// pal3-v0.6-pair-rendezvous-vectors
{
  const f = 'pal3-v0.6-pair-rendezvous-vectors.json';
  const j = load(f);
  const hkdf = (ikm, salt, info) => Buffer.from(hkdfSync('sha384', ikm, salt, Buffer.from(info, 'ascii'), 32));
  const seedOf = (id) => Buffer.alloc(32, parseInt(id.seedByte, 16));
  const sa = seedOf(j.identities.A), sb = seedOf(j.identities.B);
  const pkA = ed25519PublicKey(sa), pkB = ed25519PublicKey(sb);
  const bA = hkdf(sa, Buffer.alloc(0), 'palexplorer-rendezvous-beacon-v1');
  const bB = hkdf(sb, Buffer.alloc(0), 'palexplorer-rendezvous-beacon-v1');
  j.identities.A.beaconKey = hex(bA);
  j.identities.B.beaconKey = hex(bB);
  const shared = x25519(edSeedToX25519(sa), edPublicToX25519(pkB));
  const ids = Buffer.concat([pkA, pkB].sort(Buffer.compare));
  const base = hkdf(shared, ids, 'palexplorer-pair-rendezvous-v1');
  const full = hkdf(Buffer.concat([base, ...[bA, bB].sort(Buffer.compare)]), ids, 'palexplorer-pair-rendezvous-beacon-v1');
  j.pairKey = { base: hex(base), full: hex(full) };
  const m = j.mailboxLocationsToB;
  const key = expand(full, 'pal3-wan-mailbox-v3');
  m.locations = m.epochOffsets.map((o) => {
    const b = Buffer.alloc(8);
    b.writeBigInt64BE(BigInt(Math.floor(m.unixTimeMs / 900000) + o));
    return hex(hmac(key, Buffer.concat([pkB, b])));
  });
  j.description = j.description.replace('0.6.17', '0.6.18');
  save(f, j);
}

// pal3-v0.6-primitive-vectors: cookie, proof of work, resumption binder, 48-byte manifest hashes.
{
  const f = 'pal3-v0.6-primitive-vectors.json';
  const j = load(f);
  delete j.sha256;
  const ck = j.cookie;
  const mac = hmac(Buffer.from(ck.secretHex, 'hex'), `pal3-cookie-v1:${ck.address}:${ck.port}:${ck.connId >>> 0}:${Math.floor(ck.nowMs / 60000)}:${ck.powBits}`).subarray(0, 15);
  const cookie = Buffer.concat([mac, Buffer.from([ck.powBits])]);
  ck.expectedCookieHex = hex(cookie);
  const zeros = (d) => { let n = 0; for (const byte of d) { if (byte === 0) { n += 8; continue; } n += Math.clz32(byte) - 24; break; } return n; };
  for (let nonce = 0; ; nonce++) {
    const hdr = Buffer.alloc(8);
    hdr.writeUInt32BE(ck.connId >>> 0, 0);
    hdr.writeUInt32BE(nonce, 4);
    if (zeros(sha384(Buffer.concat([Buffer.from(ck.pow.domain), cookie, hdr]))) >= ck.pow.bits) { ck.pow.nonce = nonce; break; }
  }
  const r = j.resumption;
  r.prkHex = rep('11', 48);
  const rs = expand(Buffer.from(r.prkHex, 'hex'), 'pal3-res-v1');
  r.resumptionSecretHex = hex(rs);
  r.binderHex = hex(hmac(expand(rs, 'pal3-binder-v1'), sha384(Buffer.from(r.helloWithoutBinderHex, 'hex'))));
  for (const c of j.manifestRevision) {
    for (const side of [c.prev, c.next]) if (side) side.hashHex = rep(side.hashHex.slice(0, 2), 48);
  }
  save(f, j);
}

// pal3-v0.6-swarm-vectors: signed messages and the share ticket body hash.
{
  const f = 'pal3-v0.6-swarm-vectors.json';
  const j = load(f);
  const sp = j.swarmPass;
  sp.signedMessageHex = hex(Buffer.concat([Buffer.from(sp.domain, 'ascii'), sha384(Buffer.from(sp.bodyHex, 'hex'))]));
  const t = j.shareTicket;
  const body = encodePalCbor({
    v: 1, shareId: Buffer.from(t.input.shareId, 'hex'), ownerEdPk: Buffer.from(t.input.ownerEdPk, 'hex'), ownerDsaPk: Buffer.alloc(1952, 0x33),
    manifestRoot: Buffer.alloc(0), issuedAtMs: BigInt(t.input.issuedAtMs), expiresAtMs: BigInt(t.input.expiresAtMs), redistribution: t.input.redistribution,
  });
  delete t.bodySha256Hex;
  t.bodyHex = hex(body);
  t.bodySha384Hex = hex(sha384(body));
  t.signedMessageHex = hex(Buffer.concat([Buffer.from(t.domain, 'ascii'), sha384(body)]));
  const root = rep('ab', 48);
  j.pieceResource.contentId = `pal3:s3t:${root}:1048576`;
  j.pieceResource.expected = `swarm:${j.pieceResource.shareId}:pal3:s3t:${root}:1048576`;
  save(f, j);
}

// Hybrid-signed objects: new key pairs (Ed25519 and ML-DSA-65), signatures over domain || SHA-384(body).
function newSigner() {
  const ed = generateKeyPairSync('ed25519');
  const dsa = generateKeyPairSync('ml-dsa-65');
  return { ed, dsa, edPkHex: hex(ed.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32)), dsaPkHex: hex(dsa.publicKey.export({ format: 'der', type: 'spki' }).subarray(-1952)) };
}
function signHybrid(signer, domain, digest) {
  const message = Buffer.concat([Buffer.from(domain, 'ascii'), digest]);
  return {
    sigEd25519Hex: hex(cryptoSign(null, message, signer.ed.privateKey)),
    sigMldsa65Hex: hex(cryptoSign(null, message, { key: signer.dsa.privateKey, context: Buffer.from(domain, 'ascii') })),
  };
}
{
  const f = 'pal3-v0.6-core-vectors.json';
  const j = load(f);
  j.rule = j.rule.replace('SHA-256', 'SHA-384');
  for (const o of j.objects) {
    const s = newSigner();
    o.signer = { edPkHex: s.edPkHex, dsaPkHex: s.dsaPkHex };
    Object.assign(o, signHybrid(s, o.domain, sha384(Buffer.from(o.bodyHex, 'hex'))));
  }
  save(f, j);
}
{
  const f = 'pal3-v0.6-prekey-vectors.json';
  const j = load(f);
  const readMap = (buf) => {
    let o = 5;
    const out = {};
    for (let n = buf.readUInt32BE(1); n > 0; n--) {
      const kl = buf.readUInt16BE(o); o += 2;
      const key = buf.subarray(o, o + kl).toString('utf8'); o += kl;
      const len = buf.readUInt32BE(o + 1);
      out[key] = buf.subarray(o + 5, o + 5 + len); o += 5 + len;
    }
    return out;
  };
  for (const p of j.signedPrekey) {
    const s = newSigner();
    p.deviceEdPublicKeyHex = s.edPkHex;
    p.deviceDsaPublicKeyHex = s.dsaPkHex;
    const pub = readMap(Buffer.from(p.signedHex, 'hex')).pub;
    const sig = signHybrid(s, 'pal3-prekey-v1', sha384(pub));
    p.signedHex = hex(encodePalCbor({ pub, sigEd25519: Buffer.from(sig.sigEd25519Hex, 'hex'), sigMldsa65: Buffer.from(sig.sigMldsa65Hex, 'hex') }));
    p.prekeyIdHex = hex(sha384(pub).subarray(0, 8));
  }
  save(f, j);
}
console.log('regenerated key-schedule vectors');
