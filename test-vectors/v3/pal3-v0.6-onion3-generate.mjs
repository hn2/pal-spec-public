// Generates pal3-v0.6-onion3-vectors.json: Sphinx-style header-blinded onion/3 relay cells of section 15.9.
// Standalone, Node built-ins only. Run: node test-vectors/v3/pal3-v0.6-onion3-generate.mjs
import { createCipheriv, createHash, createHmac, hkdfSync } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { ed25519PublicKey, edPublicToX25519, edSeedToX25519, x25519, x25519PublicKey } from '../../sealedbox.mjs';

const MAX_HOPS = 3;
const ALPHA = 32;
const HOP_SLOT = 49;
const BETA_LEN = MAX_HOPS * HOP_SLOT; // 147
const MAC_LEN = 16;
const HEADER_LEN = ALPHA + BETA_LEN + MAC_LEN; // 195
const LEN = 2;
const FRAG_HEADER = 12;

const deltaLen = (cellSize) => cellSize - HEADER_LEN;
const cellCapacity = (cellSize) => deltaLen(cellSize) - LEN;

const sha384 = (b) => createHash('sha384').update(b).digest();
function labelBytes(label, length) {
  const parts = [];
  for (let i = 0; parts.length * 48 < length; i++) {
    parts.push(sha384(Buffer.from(`pal3-onion3-vector ${label} ${i}`, 'utf8')));
  }
  return Buffer.concat(parts).subarray(0, length);
}

const xorBuf = (a, b) => {
  if (a.length !== b.length) throw new Error(`xor length mismatch: ${a.length} vs ${b.length}`);
  const out = Buffer.alloc(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
};

const stream = (key, len) => createCipheriv('chacha20', key, Buffer.alloc(16)).update(Buffer.alloc(len));
const mac = (mu, alpha, beta, delta) =>
  createHmac('sha384', mu).update(Buffer.concat([alpha, beta, delta])).digest().subarray(0, MAC_LEN);

function deriveHopKeys(s, alpha, R) {
  const salt = Buffer.concat([alpha, R]);
  const hkdf = (info) => Buffer.from(hkdfSync('sha384', s, salt, Buffer.from(info, 'ascii'), 32));
  return {
    rho: hkdf('pal3-onion3-rho-v1'),
    mu: hkdf('pal3-onion3-mu-v1'),
    pi: hkdf('pal3-onion3-pi-v1'),
    b: hkdf('pal3-onion3-blind-v1'),
    replayKey: sha384(Buffer.concat([Buffer.from('pal3-onion3-replay-v1', 'ascii'), Buffer.from([0x00]), alpha, R, s])),
  };
}

function buildOnion3Cell({ label, cellSize, relaySeeds, destinationPk, payload, overrideHopType = null, overridePayloadLen = null }) {
  const n = relaySeeds.length;
  const dLen = deltaLen(cellSize);
  const cap = cellCapacity(cellSize);
  const relayPks = relaySeeds.map(ed25519PublicKey);
  const relayXPks = relayPks.map(edPublicToX25519);

  const x = labelBytes(`${label} ephemeral`, 32);
  const alphas = [x25519PublicKey(x)];
  const shared = [];
  const keys = [];

  for (let i = 0; i < n; i++) {
    let t = x25519(x, relayXPks[i]);
    for (let j = 0; j < i; j++) t = x25519(keys[j].b, t);
    if (t.every((byte) => byte === 0)) throw new Error('degenerate shared secret');
    shared.push(t);
    const k = deriveHopKeys(t, alphas[i], relayXPks[i]);
    keys.push(k);
    if (i < n - 1) {
      const nextAlpha = x25519(k.b, alphas[i]);
      if (nextAlpha.every((byte) => byte === 0)) throw new Error('degenerate blinded alpha');
      alphas.push(nextAlpha);
    }
  }

  // Payload field
  const payloadField = Buffer.concat([Buffer.alloc(LEN), payload, labelBytes(`${label} fill`, cap - payload.length)]);
  payloadField.writeUInt16BE(overridePayloadLen ?? payload.length, 0);

  // Deltas from exit back to entry
  const deltas = new Array(n);
  let curDelta = payloadField;
  for (let i = n - 1; i >= 0; i--) {
    curDelta = xorBuf(curDelta, stream(keys[i].pi, dLen));
    deltas[i] = curDelta;
  }

  // Sphinx header fillers phi_0 .. phi_{n-1}
  const phis = [Buffer.alloc(0)];
  for (let k = 1; k < n; k++) {
    const ext = Buffer.concat([phis[k - 1], Buffer.alloc(HOP_SLOT)]);
    const ks = stream(keys[k - 1].rho, BETA_LEN + HOP_SLOT);
    const tail = ks.subarray(BETA_LEN + HOP_SLOT - k * HOP_SLOT);
    phis.push(xorBuf(ext, tail));
  }

  // Betas and gammas from exit back to entry
  const betas = new Array(n);
  const gammas = new Array(n);
  const tailPad = labelBytes(`${label} tailPad`, (MAX_HOPS - n) * HOP_SLOT);
  const exitSlot = Buffer.concat([Buffer.from([overrideHopType ?? 0x02]), destinationPk, Buffer.alloc(MAC_LEN), tailPad]);
  const exitStream = stream(keys[n - 1].rho, BETA_LEN).subarray(0, exitSlot.length);
  betas[n - 1] = Buffer.concat([xorBuf(exitSlot, exitStream), phis[n - 1]]);
  gammas[n - 1] = mac(keys[n - 1].mu, alphas[n - 1], betas[n - 1], deltas[n - 1]);

  for (let i = n - 2; i >= 0; i--) {
    const plain = Buffer.concat([
      Buffer.from([0x01]),
      relayPks[i + 1],
      gammas[i + 1],
      betas[i + 1].subarray(0, BETA_LEN - HOP_SLOT),
    ]);
    betas[i] = xorBuf(plain, stream(keys[i].rho, BETA_LEN));
    gammas[i] = mac(keys[i].mu, alphas[i], betas[i], deltas[i]);
  }

  const cells = Array.from({ length: n }, (_, i) => Buffer.concat([alphas[i], betas[i], gammas[i], deltas[i]]));

  // Self-check every hop using relay secret keys only.
  let wire = cells[0];
  for (let i = 0; i < n; i++) {
    const a = wire.subarray(0, ALPHA);
    const b = wire.subarray(ALPHA, ALPHA + BETA_LEN);
    const g = wire.subarray(ALPHA + BETA_LEN, HEADER_LEN);
    const d = wire.subarray(HEADER_LEN);
    const r = edSeedToX25519(relaySeeds[i]);
    const s = x25519(r, a);
    if (!s.equals(shared[i])) throw new Error(`hop ${i} shared secret mismatch`);
    const k = deriveHopKeys(s, a, relayXPks[i]);
    if (!mac(k.mu, a, b, d).equals(g)) throw new Error(`hop ${i} MAC mismatch`);
    const B = xorBuf(Buffer.concat([b, Buffer.alloc(HOP_SLOT)]), stream(k.rho, BETA_LEN + HOP_SLOT));
    const hopType = B[0];
    const nextHop = B.subarray(1, 33);
    const nextMac = B.subarray(33, 49);
    const nextBeta = B.subarray(49, 49 + BETA_LEN);
    const nextDelta = xorBuf(d, stream(k.pi, d.length));
    if (i < n - 1) {
      if (hopType !== 0x01 || !nextHop.equals(relayPks[i + 1])) throw new Error(`hop ${i} forwarding mismatch`);
      const nextAlpha = x25519(k.b, a);
      wire = Buffer.concat([nextAlpha, nextBeta, nextMac, nextDelta]);
      if (!wire.equals(cells[i + 1])) throw new Error(`hop ${i} forwarded cell mismatch`);
    } else if (overrideHopType === null && overridePayloadLen === null) {
      if (hopType !== 0x02 || !nextHop.equals(destinationPk)) throw new Error('exit hop mismatch');
      if (!nextDelta.equals(payloadField)) throw new Error('exit payloadField mismatch');
    }
  }

  const hops = relaySeeds.map((seed, i) => ({
    relaySeedHex: seed.toString('hex'),
    relayPublicKeyHex: relayPks[i].toString('hex'),
    relayX25519PublicKeyHex: relayXPks[i].toString('hex'),
    alphaHex: alphas[i].toString('hex'),
    sharedSecretHex: shared[i].toString('hex'),
    rhoHex: keys[i].rho.toString('hex'),
    muHex: keys[i].mu.toString('hex'),
    piHex: keys[i].pi.toString('hex'),
    blindScalarHex: keys[i].b.toString('hex'),
    replayKeyHex: keys[i].replayKey.toString('hex'),
    betaHex: betas[i].toString('hex'),
    gammaHex: gammas[i].toString('hex'),
    deltaHex: deltas[i].toString('hex'),
    cellHex: cells[i].toString('hex'),
    hopType: i < n - 1 ? 1 : (overrideHopType ?? 2),
    nextPublicKeyHex: (i < n - 1 ? relayPks[i + 1] : destinationPk).toString('hex'),
    forwardedCellHex: i < n - 1 ? cells[i + 1].toString('hex') : null,
  }));

  return {
    cellSize,
    hopCount: n,
    ephemeralSecretHex: x.toString('hex'),
    destinationPublicKeyHex: destinationPk.toString('hex'),
    payloadHex: payload.toString('hex'),
    payloadFieldHex: payloadField.toString('hex'),
    hops,
  };
}

function flipByte(hex, offset) {
  const b = Buffer.from(hex, 'hex');
  b[offset] ^= 0x01;
  return b.toString('hex');
}

const cellSize = 1024;
const relaySeeds = [1, 2, 3].map((n) => labelBytes(`relay seed ${n}`, 32));
const destinationPk = ed25519PublicKey(labelBytes('destination seed', 32));

const threeHopCell = buildOnion3Cell({
  label: 'three-hop',
  cellSize,
  relaySeeds,
  destinationPk,
  payload: Buffer.from('PAL onion/3 three-hop blinded vector payload', 'utf8'),
});

const twoHopCell = buildOnion3Cell({
  label: 'two-hop',
  cellSize,
  relaySeeds: relaySeeds.slice(0, 2),
  destinationPk,
  payload: Buffer.from('PAL onion/3 two-hop blinded vector payload', 'utf8'),
});

const oneHopCell = buildOnion3Cell({
  label: 'one-hop',
  cellSize,
  relaySeeds: relaySeeds.slice(0, 1),
  destinationPk,
  payload: Buffer.from('PAL onion/3 one-hop blinded vector payload', 'utf8'),
});

// Negative cases
const invalidHopTypeCell = buildOnion3Cell({
  label: 'bad-hop-type',
  cellSize,
  relaySeeds: relaySeeds.slice(0, 1),
  destinationPk,
  payload: Buffer.from('bad hop type', 'utf8'),
  overrideHopType: 0x03,
});

const badPayloadLenCell = buildOnion3Cell({
  label: 'bad-payload-len',
  cellSize,
  relaySeeds: relaySeeds.slice(0, 1),
  destinationPk,
  payload: Buffer.from('bad len', 'utf8'),
  overridePayloadLen: cellCapacity(cellSize) + 1,
});

const baseCell = threeHopCell.hops[0].cellHex;
const baseSeed = threeHopCell.hops[0].relaySeedHex;

const rejected = [
  {
    name: 'cellTooSmall',
    relaySeedHex: baseSeed,
    cellHex: '00'.repeat(511),
    expectedError: 'E_ONION_INVALID',
    description: 'Cell smaller than 512 bytes must be rejected.',
  },
  {
    name: 'cellTooLarge',
    relaySeedHex: baseSeed,
    cellHex: '00'.repeat(2049),
    expectedError: 'E_ONION_INVALID',
    description: 'Cell larger than 2048 bytes must be rejected.',
  },
  {
    name: 'allZeroAlpha',
    relaySeedHex: baseSeed,
    cellHex: '00'.repeat(ALPHA) + baseCell.slice(ALPHA * 2),
    expectedError: 'E_ONION_INVALID',
    description: 'Low-order/all-zero alpha produces all-zero X25519 shared secret and must be rejected.',
  },
  {
    name: 'tamperedAlpha',
    relaySeedHex: baseSeed,
    cellHex: flipByte(baseCell, 0),
    expectedError: 'E_UNAUTHORIZED',
    description: 'Tampering with alpha changes the derived keys and fails MAC verification.',
  },
  {
    name: 'tamperedBeta',
    relaySeedHex: baseSeed,
    cellHex: flipByte(baseCell, ALPHA + 5),
    expectedError: 'E_UNAUTHORIZED',
    description: 'Tampering with beta fails gamma MAC verification.',
  },
  {
    name: 'tamperedGamma',
    relaySeedHex: baseSeed,
    cellHex: flipByte(baseCell, ALPHA + BETA_LEN),
    expectedError: 'E_UNAUTHORIZED',
    description: 'Tampering with gamma fails MAC verification.',
  },
  {
    name: 'tamperedDelta',
    relaySeedHex: baseSeed,
    cellHex: flipByte(baseCell, HEADER_LEN + 10),
    expectedError: 'E_UNAUTHORIZED',
    description: 'Tampering with delta fails gamma MAC verification because gamma authenticates alpha || beta || delta.',
  },
  {
    name: 'replayedCell',
    relaySeedHex: baseSeed,
    cellHex: baseCell,
    seenReplayKeysHex: [threeHopCell.hops[0].replayKeyHex],
    expectedError: 'E_REPLAY',
    description: 'A cell whose replayKey is already in the relay replay cache must be rejected with E_REPLAY.',
  },
  {
    name: 'invalidHopType',
    relaySeedHex: invalidHopTypeCell.hops[0].relaySeedHex,
    cellHex: invalidHopTypeCell.hops[0].cellHex,
    expectedError: 'E_ONION_INVALID',
    description: 'A cell with valid MAC whose decrypted hopType is neither 0x01 nor 0x02 must be dropped with E_ONION_INVALID.',
  },
  {
    name: 'payloadLengthExceedsCapacity',
    relaySeedHex: badPayloadLenCell.hops[0].relaySeedHex,
    cellHex: badPayloadLenCell.hops[0].cellHex,
    expectedError: 'E_ONION_INVALID',
    description: 'An exit cell whose payload length exceeds delta.length - 2 must be dropped with E_ONION_INVALID.',
  },
];

const out = {
  specVersion: '3.0.0-draft.6.23',
  description: 'onion/3 Sphinx-style header-blinded multi-hop relay cells (section 15.9). Ephemeral scalars, payload fill and tail padding are derived from fixed labels for reproducibility.',
  capability: 'onion/3',
  constants: {
    maxHops: MAX_HOPS,
    alphaBytes: ALPHA,
    hopSlotBytes: HOP_SLOT,
    betaBytes: BETA_LEN,
    macBytes: MAC_LEN,
    headerBytes: HEADER_LEN,
    lengthBytes: LEN,
    fragHeaderBytes: FRAG_HEADER,
  },
  sizes: [512, 1024, 2048].map((size) => ({
    cellSize: size,
    headerBytes: HEADER_LEN,
    deltaBytes: deltaLen(size),
    capacity: cellCapacity(size),
    fragmentDataBytes: cellCapacity(size) - FRAG_HEADER,
  })),
  threeHopCell,
  twoHopCell,
  oneHopCell,
  rejected,
};

writeFileSync(new URL('./pal3-v0.6-onion3-vectors.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
