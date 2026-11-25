import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { ed25519PublicKey, edSeedToX25519, sealOpen } from '../sealedbox.mjs';

const vectors = JSON.parse(readFileSync(new URL('../test-vectors/v3/pal3-v0.6-onion2-vectors.json', import.meta.url), 'utf8'));
const spec = readFileSync(new URL('../spec/v3/PAL-3.0.md', import.meta.url), 'utf8');
const sha384Hex = (bytes) => createHash('sha384').update(bytes).digest('hex');
const hex = (text) => Buffer.from(text, 'hex');

const capacity = (cellSize) => cellSize - 243;
const layerLength = (remainingHops, cellSize) => 48 + 32 + 2 + capacity(cellSize) + (remainingHops - 1) * 80;

test('onion2_sizes_when_cell_size_allowed_match_section_15_2', () => {
  for (const s of vectors.sizes) {
    assert.equal(s.capacity, capacity(s.cellSize));
    assert.equal(s.fragmentDataBytes, capacity(s.cellSize) - 12);
    for (const h of [1, 2, 3]) assert.equal(s.layerLengthByRemainingHops[h], layerLength(h, s.cellSize));
    assert.equal(1 + layerLength(3, s.cellSize), s.cellSize);
  }
});

test('onion2_three_hop_cell_when_peeled_hop_by_hop_yields_next_hop_and_payload', () => {
  const v = vectors.threeHopCell;
  let field = null;
  for (const hop of v.hops) {
    const cell = hex(hop.cellHex);
    assert.equal(cell.length, v.cellSize);
    assert.equal(cell[0], hop.remainingHops);
    const seed = hex(hop.relaySeedHex);
    assert.equal(ed25519PublicKey(seed).toString('hex'), hop.relayPublicKeyHex);

    const head = cell.subarray(0, 1 + layerLength(hop.remainingHops, v.cellSize));
    assert.equal(sha384Hex(head), hop.replayKeyHex);
    const plain = sealOpen(head.subarray(1), edSeedToX25519(seed));
    assert.ok(plain, `layer for remaining hops ${hop.remainingHops} opens`);
    assert.equal(plain.subarray(0, 32).toString('hex'), hop.nextPublicKeyHex);

    if (hop.remainingHops > 1) {
      const forwarded = Buffer.concat([Buffer.from([hop.remainingHops - 1]), plain.subarray(32)]);
      assert.equal(forwarded.toString('hex'), hop.forwardedPrefixHex);
    } else {
      field = plain.subarray(32);
    }
  }
  assert.equal(v.hops.at(-1).nextPublicKeyHex, v.destinationPublicKeyHex);
  assert.equal(field.toString('hex'), v.payloadFieldHex);
  assert.equal(field.length, 2 + capacity(v.cellSize));
  assert.equal(field.subarray(2, 2 + field.readUInt16BE(0)).toString('hex'), v.payloadHex);
});

test('onion2_layer_when_one_bit_changes_does_not_open', () => {
  const hop = vectors.threeHopCell.hops[0];
  const cell = hex(hop.cellHex);
  cell[100] ^= 1;
  assert.equal(sealOpen(cell.subarray(1, 1 + hop.layerLength), edSeedToX25519(hex(hop.relaySeedHex))), null);
});

test('onion2_replay_key_when_padding_changes_stays_the_same', () => {
  const hop = vectors.threeHopCell.hops[1];
  const cell = hex(hop.cellHex);
  assert.ok(cell.length > 1 + hop.layerLength);
  cell[cell.length - 1] ^= 0xff;
  assert.equal(sha384Hex(cell.subarray(0, 1 + hop.layerLength)), hop.replayKeyHex);
});

test('onion2_fragments_when_reassembled_give_the_payload', () => {
  const f = vectors.fragmentation;
  const payload = Buffer.from(Array.from({ length: f.payloadLength }, (_, i) => i & 0xff));
  assert.equal(sha384Hex(payload), f.payloadHashHex);
  const chunk = capacity(f.cellSize) - 12;
  assert.equal(f.fragmentCount, Math.ceil(f.payloadLength / chunk));
  const parts = [];
  for (let i = 0; i < f.fragmentCount; i++) {
    const head = hex(f.fragmentHeadersHex[i]);
    assert.equal(head.subarray(0, 8).toString('hex'), f.messageIdHex);
    assert.equal(head.readUInt16BE(8), i);
    assert.equal(head.readUInt16BE(10), f.fragmentCount);
    const data = payload.subarray(i * chunk, (i + 1) * chunk);
    assert.equal(12 + data.length, f.fragmentLengths[i]);
    assert.ok(f.fragmentLengths[i] <= capacity(f.cellSize));
    assert.equal(sha384Hex(Buffer.concat([head, data])), f.fragmentHashHex[i]);
    parts.push(data);
  }
  assert.ok(Buffer.concat(parts).equals(payload));
});

test('onion2_specification_text_states_the_constants_and_error_identifiers', () => {
  for (const text of ['`onion/2`', 'CELL_SIZE - 243', '863, 943 and 1023', '769 bytes', 'E_ONION_INVALID', 'E_ONION_TOO_LARGE', 'E_ONION_TTL', 'E_REPLAY', 'pal3-v0.6-onion2-vectors.json']) {
    assert.ok(spec.includes(text), text);
  }
  assert.equal(vectors.capability, 'onion/2');
});
