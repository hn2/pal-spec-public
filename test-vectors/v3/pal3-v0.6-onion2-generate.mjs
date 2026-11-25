// Generates pal3-v0.6-onion2-vectors.json: onion/2 cells of section 15.
// Standalone, Node built-ins only. Run: node test-vectors/v3/pal3-v0.6-onion2-generate.mjs
// Ephemeral keys, payload fill and cell padding are random in real use; here they are derived from fixed labels so the file is reproducible.
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { ed25519PublicKey, edPublicToX25519, seal, SEAL_BYTES } from '../../sealedbox.mjs';

const MAX_HOPS = 3;
const NEXT = 32;
const LEN = 2;
const LAYER_GROWTH = NEXT + SEAL_BYTES;
const cellCapacity = (cellSize) => cellSize - 1 - SEAL_BYTES - NEXT - LEN - (MAX_HOPS - 1) * LAYER_GROWTH;
const layerLength = (remainingHops, cellSize) => SEAL_BYTES + NEXT + LEN + cellCapacity(cellSize) + (remainingHops - 1) * LAYER_GROWTH;

const sha384 = (b) => createHash('sha384').update(b).digest();
function labelBytes(label, length) {
  const parts = [];
  for (let i = 0; parts.length * 48 < length; i++) parts.push(sha384(Buffer.from(`pal3-onion2-vector ${label} ${i}`, 'utf8')));
  return Buffer.concat(parts).subarray(0, length);
}
const pad = (head, cellSize, label) => Buffer.concat([head, labelBytes(label, cellSize - head.length)]);

const cellSize = 1024;
const relaySeeds = [1, 2, 3].map((n) => labelBytes(`relay seed ${n}`, 32));
const relayPks = relaySeeds.map(ed25519PublicKey);
const destinationPk = ed25519PublicKey(labelBytes('destination seed', 32));
const payload = Buffer.from('PAL onion/2 vector payload', 'utf8');

const field = Buffer.concat([Buffer.alloc(LEN), payload, labelBytes('payload fill', cellCapacity(cellSize) - payload.length)]);
field.writeUInt16BE(payload.length, 0);

// Layers from the last relay outwards. layers[i] is the sealed layer that relay i opens.
const layers = [];
let inner = field;
let next = destinationPk;
for (let i = relayPks.length - 1; i >= 0; i--) {
  inner = seal(Buffer.concat([next, inner]), edPublicToX25519(relayPks[i]), labelBytes(`ephemeral key ${i + 1}`, 32));
  layers[i] = inner;
  next = relayPks[i];
}

const hops = relayPks.map((pk, i) => {
  const remainingHops = relayPks.length - i;
  return {
    relaySeedHex: relaySeeds[i].toString('hex'),
    relayPublicKeyHex: pk.toString('hex'),
    remainingHops,
    layerLength: layerLength(remainingHops, cellSize),
    cellHex: pad(Buffer.concat([Buffer.from([remainingHops]), layers[i]]), cellSize, `padding ${i + 1}`).toString('hex'),
    replayKeyHex: sha384(Buffer.concat([Buffer.from([remainingHops]), layers[i]])).toString('hex'),
    nextPublicKeyHex: (i + 1 < relayPks.length ? relayPks[i + 1] : destinationPk).toString('hex'),
    forwardedPrefixHex: i + 1 < relayPks.length ? Buffer.concat([Buffer.from([remainingHops - 1]), layers[i + 1]]).toString('hex') : null,
  };
});

const FRAG_HEADER = 12;
const messageId = labelBytes('message id', 8);
const longPayload = Buffer.from(Array.from({ length: 2000 }, (_, i) => i & 0xff));
const chunk = cellCapacity(cellSize) - FRAG_HEADER;
const count = Math.ceil(longPayload.length / chunk);
const fragments = Array.from({ length: count }, (_, i) => {
  const head = Buffer.alloc(FRAG_HEADER);
  messageId.copy(head);
  head.writeUInt16BE(i, 8);
  head.writeUInt16BE(count, 10);
  return Buffer.concat([head, longPayload.subarray(i * chunk, (i + 1) * chunk)]);
});

const out = {
  specVersion: '3.0.0-draft.6.11',
  description: 'onion/2 fixed-size relay cells (section 15). Ephemeral keys, payload fill and padding are derived from fixed labels for reproducibility; an implementation uses random bytes.',
  capability: 'onion/2',
  sizes: [512, 1024, 2048].map((size) => ({
    cellSize: size,
    capacity: cellCapacity(size),
    layerLengthByRemainingHops: { 1: layerLength(1, size), 2: layerLength(2, size), 3: layerLength(3, size) },
    fragmentDataBytes: cellCapacity(size) - FRAG_HEADER,
  })),
  threeHopCell: {
    cellSize,
    destinationPublicKeyHex: destinationPk.toString('hex'),
    payloadHex: payload.toString('hex'),
    payloadFieldHex: field.toString('hex'),
    hops,
  },
  fragmentation: {
    cellSize,
    messageIdHex: messageId.toString('hex'),
    payloadLength: longPayload.length,
    payloadRule: 'byte i is i modulo 256',
    payloadHashHex: sha384(longPayload).toString('hex'),
    fragmentCount: count,
    fragmentHeadersHex: fragments.map((f) => f.subarray(0, FRAG_HEADER).toString('hex')),
    fragmentLengths: fragments.map((f) => f.length),
    fragmentHashHex: fragments.map((f) => sha384(f).toString('hex')),
  },
};

writeFileSync(new URL('./pal3-v0.6-onion2-vectors.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
