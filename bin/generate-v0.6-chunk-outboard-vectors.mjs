// Generates test-vectors/v3/pal3-v0.6-chunk-outboard-vectors.json (spec section 8.1.1) with the reference implementation.
// Run: node bin/generate-v0.6-chunk-outboard-vectors.mjs --pal-core <path to the hn2/pal-core checkout> [--out <file>]
// The content is a fixed byte pattern (byte i = (31 * i + 7) mod 251), so the file holds hashes and no content and two runs are byte-identical.
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : null; };
const palCore = opt('--pal-core');
if (!palCore) { console.error('usage: node bin/generate-v0.6-chunk-outboard-vectors.mjs --pal-core <path> [--out <file>]'); process.exit(2); }
const out = opt('--out') || resolve(dirname(fileURLToPath(import.meta.url)), '../test-vectors/v3/pal3-v0.6-chunk-outboard-vectors.json');
const lib = (file) => import(pathToFileURL(resolve(palCore, 'packages/protocol/lib', file)).href);

const { ChunkOutboard, ChunkVerifier, EMPTY_CHUNK_ROOT, encodeBlockOutboard, decodeBlockOutboard, CHUNK_BYTES } = await lib('pal3/chunkOutboard.js');

const hex = (b) => Buffer.from(b).toString('hex');
const PATTERN = { kind: 'affine-mod-251', multiplier: 31, offset: 7 };
const content = (n) => Buffer.from(Array.from({ length: n }, (_, i) => (31 * i + 7) % 251));
const code = (fn) => { try { fn(); return 'accepted'; } catch (err) { return /^(E_[A-Z0-9_]+)/.exec(err.message)?.[1] ?? err.message; } };

const sizes = [1, 16384, 16385, 262144, 262145, 600000];
const contents = sizes.map((totalBytes) => {
  const data = content(totalBytes);
  const ob = ChunkOutboard.fromBuffer(data);
  const blocks = Array.from({ length: ob.blockCount }, (_, blockIndex) => {
    const outboard = encodeBlockOutboard(ob.getBlockOutboard(blockIndex));
    const decoded = decodeBlockOutboard(outboard, { totalBytes, blockIndex });
    const verifier = new ChunkVerifier({ chunkRoot: ob.chunkRoot, totalBytes, blockIndex, outboard: decoded });
    for (let c = 0; c < verifier.chunkCount; c++) {
      const at = blockIndex * 262144 + c * CHUNK_BYTES;
      if (!verifier.verifyChunk(c, data.subarray(at, Math.min(at + CHUNK_BYTES, totalBytes)))) throw new Error(`reference rejected chunk ${c} of block ${blockIndex} of ${totalBytes}`);
    }
    return { blockIndex, chunkCount: decoded.chunkHashes.length, proofLength: decoded.proof.length, outboardHex: hex(outboard) };
  });
  return { totalBytes, blockCount: ob.blockCount, chunkRootHex: hex(ob.chunkRoot), blocks };
});

const whole = ChunkOutboard.fromBuffer(Buffer.alloc(0));
const emptyFile = { chunkRootHex: hex(whole.chunkRoot), expectedHex: hex(EMPTY_CHUNK_ROOT), blockCount: whole.blockCount };

// Rejections. Each one names the content (by size), the block and the outboard that the receiver holds, and the chunk it then receives.
const by = (n) => contents.find((c) => c.totalBytes === n);
const rejected = [];
const flip = (h, at) => { const b = Buffer.from(h, 'hex'); b[at] ^= 0x01; return hex(b); };
function outboardCase(name, description, totalBytes, blockIndex, outboardHex, expectedError) {
  const c = by(totalBytes);
  const got = code(() => {
    const decoded = decodeBlockOutboard(Buffer.from(outboardHex, 'hex'), { totalBytes, blockIndex });
    new ChunkVerifier({ chunkRoot: Buffer.from(c.chunkRootHex, 'hex'), totalBytes, blockIndex, outboard: decoded });
  });
  if (got !== expectedError) throw new Error(`reference answered ${got}, not ${expectedError}: ${name}`);
  rejected.push({ name, description, stage: 'outboard', totalBytes, blockIndex, outboardHex, expectedError });
}
function chunkCase(name, description, totalBytes, blockIndex, chunkIndex, chunk, expectedError) {
  const c = by(totalBytes);
  const outboard = Buffer.from(c.blocks[blockIndex].outboardHex, 'hex');
  const v = new ChunkVerifier({ chunkRoot: Buffer.from(c.chunkRootHex, 'hex'), totalBytes, blockIndex, outboard: decodeBlockOutboard(outboard, { totalBytes, blockIndex }) });
  if (v.verifyChunk(chunkIndex, chunk)) throw new Error(`reference accepted ${name}`);
  rejected.push({ name, description, stage: 'chunk', totalBytes, blockIndex, chunkIndex, chunkHex: hex(chunk), expectedError });
}
const blockBytes = (n, blockIndex) => content(n).subarray(blockIndex * 262144, Math.min(n, (blockIndex + 1) * 262144));
const chunkOf = (n, blockIndex, chunkIndex) => { const b = blockBytes(n, blockIndex); return b.subarray(chunkIndex * CHUNK_BYTES, Math.min(b.length, (chunkIndex + 1) * CHUNK_BYTES)); };

const ob600 = by(600000).blocks[1].outboardHex;
outboardCase('chunkHashFlipped', 'One bit of a chunk-leaf hash in the outboard is flipped: it no longer authenticates against the signed chunkRoot', 600000, 1, flip(ob600, 5), 'E_PAL3_CHUNK_OUTBOARD_INVALID');
outboardCase('proofSiblingFlipped', 'One bit of a proof sibling is flipped', 600000, 1, flip(ob600, ob600.length / 2 - 3), 'E_PAL3_CHUNK_OUTBOARD_INVALID');
outboardCase('outboardOfAnotherBlock', 'The outboard of block 0 is presented for block 1 (same length, wrong index in the proof)', 600000, 1, by(600000).blocks[0].outboardHex, 'E_PAL3_CHUNK_OUTBOARD_INVALID');
outboardCase('outboardTruncated', 'The outboard is one hash short', 600000, 1, ob600.slice(0, -96), 'E_PAL3_CHUNK_OUTBOARD_INVALID');
outboardCase('outboardWithoutProof', 'The proof siblings are missing', 600000, 1, ob600.slice(0, by(600000).blocks[1].chunkCount * 96), 'E_PAL3_CHUNK_OUTBOARD_INVALID');
const good = chunkOf(600000, 1, 2);
const flipped = Buffer.from(good); flipped[100] ^= 0x01;
chunkCase('chunkContentChanged', 'A chunk with one bit flipped fails at its own leaf hash', 600000, 1, 2, flipped, 'E_PAL3_CORRUPT_CHUNK');
chunkCase('chunkTooShort', 'A chunk that is one byte short of its expected length', 600000, 1, 2, good.subarray(0, good.length - 1), 'E_PAL3_CORRUPT_CHUNK');
chunkCase('chunkAtWrongIndex', 'The correct bytes of chunk 3 are delivered as chunk 2: the leaf hash binds the index', 600000, 1, 2, chunkOf(600000, 1, 3), 'E_PAL3_CORRUPT_CHUNK');
chunkCase('lastChunkWithPaddedLength', 'The short last chunk of the file padded to 16 KiB', 600000, 2, 4, Buffer.concat([chunkOf(600000, 2, 4), Buffer.alloc(16384 - chunkOf(600000, 2, 4).length)]), 'E_PAL3_CORRUPT_CHUNK');

const doc = {
  specVersion: '0.6.20',
  section: '8.1.1',
  description: 'Chunk-group verification: chunkRoot of 16 KiB chunk sub-trees, the per-block outboard, and rejections. SHA-384 with domain bytes 0x10, 0x11, 0x12.',
  generatedBy: 'bin/generate-v0.6-chunk-outboard-vectors.mjs',
  contentPattern: PATTERN,
  chunkBytes: CHUNK_BYTES,
  blockBytes: 262144,
  emptyFile,
  contents,
  rejected,
};
writeFileSync(out, `${JSON.stringify(doc, null, 2)}\n`);
console.log(`wrote ${out}: ${contents.length} contents, ${rejected.length} rejections`);
