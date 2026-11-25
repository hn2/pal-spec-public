// Generates test-vectors/v3/pal3-v0.6-private-share-vectors.json (spec section 8.3) with the reference implementation.
// Run: node bin/generate-v0.6-private-share-vectors.mjs --pal-core <path to the hn2/pal-core checkout> [--out <file>]
// Share key, file ids and plaintext (a byte pattern) are fixed, so two runs are byte-identical.
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : null; };
const palCore = opt('--pal-core');
if (!palCore) { console.error('usage: node bin/generate-v0.6-private-share-vectors.mjs --pal-core <path> [--out <file>]'); process.exit(2); }
const out = opt('--out') || resolve(dirname(fileURLToPath(import.meta.url)), '../test-vectors/v3/pal3-v0.6-private-share-vectors.json');
const lib = (file) => import(pathToFileURL(resolve(palCore, 'packages/protocol/lib', file)).href);

const { derivePrivateFileKey, encryptPrivateBlock, decryptPrivateBlock, Pal3MerkleTree, PrivateFileIdRegistry, PRIVATE_PLAIN_BLOCK_BYTES } = await lib('pal3/merkle.js');

const hex = (b) => Buffer.from(b).toString('hex');
const sha384 = (b) => hex(createHash('sha384').update(b).digest());
const code = (fn) => { try { fn(); return 'accepted'; } catch (err) { return /^(E_[A-Z0-9_]+)/.exec(err.message)?.[1] ?? err.message; } };
const plain = (n, offset = 0) => Buffer.from(Array.from({ length: n }, (_, i) => (7 * (i + offset) + 3) % 251));
const shareKey = Buffer.alloc(32, 0x5a);
const fileIdA = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
const fileIdB = Buffer.from('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff', 'hex');

const fileKeyA = derivePrivateFileKey(shareKey, fileIdA);
const fileKeyB = derivePrivateFileKey(shareKey, fileIdB);

const blocks = [0, 1, 2, 40, 1000, PRIVATE_PLAIN_BLOCK_BYTES].map((len, i) => {
  const block = plain(len);
  const ct = encryptPrivateBlock(fileKeyA, fileIdA, i, block);
  if (!decryptPrivateBlock(fileKeyA, fileIdA, i, ct).equals(block)) throw new Error('reference round trip failed');
  return {
    blockIndex: i, plaintextLength: len, ciphertextLength: ct.length, ciphertextSha384Hex: sha384(ct),
    ...(ct.length <= 1100 ? { ciphertextHex: hex(ct) } : {}),
  };
});

// A whole file of 600000 plaintext bytes: 3 blocks, ciphertext of 600048 bytes, Merkle tree over the ciphertext.
const total = 600000;
const parts = [];
for (let i = 0, off = 0; off < total; i++, off += PRIVATE_PLAIN_BLOCK_BYTES) {
  parts.push(encryptPrivateBlock(fileKeyA, fileIdA, i, plain(Math.min(PRIVATE_PLAIN_BLOCK_BYTES, total - off), off)));
}
const cipher = Buffer.concat(parts);
const tree = Pal3MerkleTree.fromBuffer(cipher);
const file = { fileIdHex: hex(fileIdA), plaintextLength: total, ciphertextLength: cipher.length, blockCiphertextSha384Hex: parts.map(sha384), contentId: tree.contentId };

const goodBlock1 = encryptPrivateBlock(fileKeyA, fileIdA, 1, plain(1000));
const flipped = Buffer.from(goodBlock1); flipped[10] ^= 0x01;
const rejected = [];
const reject = (name, description, params, run, expectedError) => {
  const got = code(run);
  if (got !== expectedError) throw new Error(`reference answered ${got}, not ${expectedError}: ${name}`);
  rejected.push({ name, description, ...params, expectedError });
};
reject('blockOpenedAtAnotherIndex', 'The ciphertext of block 1 opened as block 2: nonce and AAD carry the index',
  { op: 'decrypt', fileIdHex: hex(fileIdA), blockIndex: 2, ciphertextHex: hex(goodBlock1) }, () => decryptPrivateBlock(fileKeyA, fileIdA, 2, goodBlock1), 'E_PAL3_CRYPTO');
reject('blockOpenedUnderAnotherFileId', 'The ciphertext of block 1 opened with the key and file_id of another file of the same share',
  { op: 'decrypt', fileIdHex: hex(fileIdB), blockIndex: 1, ciphertextHex: hex(goodBlock1) }, () => decryptPrivateBlock(fileKeyB, fileIdB, 1, goodBlock1), 'E_PAL3_CRYPTO');
reject('ciphertextBitFlipped', 'One ciphertext bit flipped',
  { op: 'decrypt', fileIdHex: hex(fileIdA), blockIndex: 1, ciphertextHex: hex(flipped) }, () => decryptPrivateBlock(fileKeyA, fileIdA, 1, flipped), 'E_PAL3_CRYPTO');
reject('ciphertextShorterThanTheTag', 'A ciphertext of 15 bytes cannot hold the 16-byte tag',
  { op: 'decrypt', fileIdHex: hex(fileIdA), blockIndex: 0, ciphertextHex: '00'.repeat(15) }, () => decryptPrivateBlock(fileKeyA, fileIdA, 0, Buffer.alloc(15)), 'E_PAL3_CRYPTO');
reject('plaintextBlockOneByteTooLarge', 'A plaintext block of BLOCK_BYTES - 15 bytes would make a ciphertext block larger than one Merkle block',
  { op: 'encrypt', fileIdHex: hex(fileIdA), blockIndex: 0, plaintextLength: PRIVATE_PLAIN_BLOCK_BYTES + 1 }, () => encryptPrivateBlock(fileKeyA, fileIdA, 0, plain(PRIVATE_PLAIN_BLOCK_BYTES + 1)), 'E_PAL3_CRYPTO');
reject('fileIdOfFifteenBytes', 'A file_id that is not 16 bytes', { op: 'deriveKey', fileIdHex: hex(fileIdA.subarray(0, 15)) }, () => derivePrivateFileKey(shareKey, fileIdA.subarray(0, 15)), 'E_PAL3_CRYPTO');
reject('shareKeyOfThirtyOneBytes', 'A share key that is not 32 bytes', { op: 'deriveKey', fileIdHex: hex(fileIdA), shareKeyLength: 31 }, () => derivePrivateFileKey(shareKey.subarray(0, 31), fileIdA), 'E_PAL3_CRYPTO');
const registry = new PrivateFileIdRegistry();
registry.assertFresh(fileIdA, tree.root);
registry.assertFresh(fileIdA, tree.root);
reject('fileIdReusedForOtherContent', 'The registry saw file_id A with this content root; the same file_id with another root is nonce reuse',
  { op: 'registry', fileIdHex: hex(fileIdA), firstRootHex: hex(tree.root), secondRootHex: '11'.repeat(48) }, () => registry.assertFresh(fileIdA, Buffer.alloc(48, 0x11)), 'E_PAL3_FILE_ID_REUSED');

const doc = {
  specVersion: '0.6.20',
  section: '8.3',
  description: 'Private encrypted shares: file_key = HKDF-SHA-384(share_key, salt = file_id, info = "pal3-file-key-v1", 32); chunk i sealed with ChaCha20-Poly1305 (nonce "pal3" || u64be(i), aad = file_id || u64be(i)); Merkle tree over the ciphertext.',
  generatedBy: 'bin/generate-v0.6-private-share-vectors.mjs',
  plaintextPattern: { kind: 'affine-mod-251', multiplier: 7, offset: 3 },
  plainBlockBytes: PRIVATE_PLAIN_BLOCK_BYTES,
  shareKeyHex: hex(shareKey),
  fileKeys: [{ fileIdHex: hex(fileIdA), fileKeyHex: hex(fileKeyA) }, { fileIdHex: hex(fileIdB), fileKeyHex: hex(fileKeyB) }],
  blocks,
  file,
  rejected,
};
writeFileSync(out, `${JSON.stringify(doc, null, 2)}\n`);
console.log(`wrote ${out}: ${blocks.length} blocks, ${rejected.length} rejections`);
