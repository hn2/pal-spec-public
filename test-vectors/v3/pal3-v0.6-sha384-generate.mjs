// Generates the SHA-384 identifier vectors (hn2/pal-spec#54): the Merkle cases and SHA-384 known answers in
// pal3-v0.6-primitive-vectors.json, and pal3-v0.6-identifier-vectors.json (peer, file, share, group and network identifiers).
// Standalone, Node built-ins only. Run: node test-vectors/v3/pal3-v0.6-sha384-generate.mjs
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const dir = dirname(fileURLToPath(import.meta.url));
const sha384 = (data) => createHash('sha384').update(data).digest();
const hex = (b) => Buffer.from(b).toString('hex');
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
const BLOCK = 262144;

const leafHash = (index, block) => { const len = Buffer.alloc(4); len.writeUInt32BE(block.length); return sha384(Buffer.concat([Buffer.from([0x00]), u64(index), len, block])); };
const nodeHash = (level, l, r) => sha384(Buffer.concat([Buffer.from([0x01, level]), l, r]));
const emptyRoot = sha384(Buffer.concat([Buffer.from([0x02]), u64(0)]));
const pattern = (length) => Buffer.from(Array.from({ length }, (_, i) => (i * 7 + 3) % 251));

function merkleCase(length) {
  const data = pattern(length);
  const leaves = [];
  for (let off = 0; off < data.length; off += BLOCK) leaves.push(leafHash(leaves.length, data.subarray(off, Math.min(off + BLOCK, data.length))));
  const levels = [leaves];
  let cur = leaves;
  for (let level = 1; cur.length > 1; level++) {
    const next = [];
    for (let i = 0; i < cur.length; i += 2) next.push(i + 1 < cur.length ? nodeHash(level, cur[i], cur[i + 1]) : cur[i]);
    levels.push(next);
    cur = next;
  }
  const root = leaves.length === 0 ? emptyRoot : cur[0];
  const proofs = leaves.map((_, blockIndex) => {
    let idx = blockIndex;
    const siblingsHex = [];
    for (let lvl = 0; lvl < levels.length - 1; lvl++) {
      const sib = idx % 2 === 0 ? idx + 1 : idx - 1;
      if (sib < levels[lvl].length) siblingsHex.push(hex(levels[lvl][sib]));
      idx = Math.floor(idx / 2);
    }
    return { blockIndex, siblingsHex };
  });
  return {
    length, pattern: 'byte i = (i * 7 + 3) mod 251', blockCount: leaves.length, leavesHex: leaves.map(hex), rootHex: hex(root),
    contentId: `pal3:s3t:${hex(root)}:${length}`, proofs: proofs.filter((p, i) => i === 0 || i === proofs.length - 1 || proofs.length <= 3),
  };
}

// Update the primitive vectors: the Merkle cases are now SHA-384, and SHA-384 known answers are added.
const primPath = join(dir, 'pal3-v0.6-primitive-vectors.json');
const prim = JSON.parse(readFileSync(primPath, 'utf8'));
const oldLengths = prim.merkle.map(m => m.length);
prim.specVersion = '0.6.18';
prim.section = '5.4 5.5 8.1 8.2 14.5 primitives';
prim.sha384 = ['', '616263', '00'.repeat(48)].map(inputHex => ({ inputHex, outputHex: hex(sha384(Buffer.from(inputHex, 'hex'))) }));
prim.merkle = oldLengths.map(merkleCase);
writeFileSync(primPath, JSON.stringify(prim, null, 2) + '\n');

// Identifier vectors (section 14.5). Inputs are fixed byte patterns so the file is reproducible.
const fill = (n, seed) => Buffer.from(Array.from({ length: n }, (_, i) => (i * 13 + seed) % 256));
const edPk = fill(32, 1);
const dsaPk = fill(1952, 2);
const identityKey = Buffer.concat([edPk, dsaPk]);
const peerId = sha384(Buffer.concat([Buffer.from('pal3-id-peer-v1\0', 'ascii'), identityKey]));
const fileContent = pattern(1000);
const nonce = fill(32, 3);
const createdAtMs = 1762560000000;
const record = (domain, creator) => sha384(Buffer.concat([Buffer.from(`${domain}\0`, 'ascii'), creator, nonce, u64(createdAtMs)]));
const manifestRoot = fromRoot(merkleCase(786432).rootHex);
function fromRoot(h) { return Buffer.from(h, 'hex'); }

const ids = {
  specVersion: '0.6.18',
  section: '14.5',
  hash: 'SHA-384, 48 bytes, 96 lowercase hexadecimal characters',
  peer: { domain: 'pal3-id-peer-v1', ed25519PkHex: hex(edPk), mldsa65PkFill: 'byte i = (i * 13 + 2) mod 256, 1952 bytes', idHex: hex(peerId) },
  file: { contentPattern: 'byte i = (i * 7 + 3) mod 251, 1000 bytes', idHex: hex(sha384(fileContent)) },
  share: { merkleLength: 786432, manifestRootHex: hex(manifestRoot), idHex: hex(manifestRoot) },
  group: { domain: 'pal3-id-group-v1', creatorPeerIdHex: hex(peerId), nonceHex: hex(nonce), createdAtMs, idHex: hex(record('pal3-id-group-v1', peerId)) },
  network: { domain: 'pal3-id-network-v1', adminEd25519PkHex: hex(edPk), nonceHex: hex(nonce), createdAtMs, idHex: hex(record('pal3-id-network-v1', edPk)) },
};
writeFileSync(join(dir, 'pal3-v0.6-identifier-vectors.json'), JSON.stringify(ids, null, 2) + '\n');
console.log('wrote primitive vectors (merkle + sha384) and identifier vectors');
