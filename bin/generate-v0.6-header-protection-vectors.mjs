// Generates test-vectors/v3/pal3-v0.6-header-protection-vectors.json (spec section 3.2 and A.4, C2 packet protection and header protection)
// by running the reference C2 connection (Pal3UdpConnection) on fixed keys.
// Run: node bin/generate-v0.6-header-protection-vectors.mjs --pal-core <path to the hn2/pal-core checkout> [--out <file>]
// prk_0 is a fixed test value (0x66 * 48), prk_1 for the key-update case is 0x77 * 48.
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : null; };
const palCore = opt('--pal-core');
if (!palCore) { console.error('usage: node bin/generate-v0.6-header-protection-vectors.mjs --pal-core <path> [--out <file>]'); process.exit(2); }
const out = opt('--out') || resolve(dirname(fileURLToPath(import.meta.url)), '../test-vectors/v3/pal3-v0.6-header-protection-vectors.json');
const lib = (file) => import(pathToFileURL(resolve(palCore, 'packages/protocol/lib', file)).href);

const { PAL3_HYBRID_CRYPTO } = await lib('pal3/cryptoProvider.js');
const { deriveC2PacketKeys } = await lib('pal3/records.js');
const { Pal3UdpConnection } = await lib('pal3/udpTransport.js');

const hex = (b) => Buffer.from(b).toString('hex');
const fromHex = (h) => Buffer.from(h, 'hex');
const PRK0 = Buffer.alloc(48, 0x66);
const PRK1 = Buffer.alloc(48, 0x77);
const CONN_ID = 0x01020304;
const CONN_ID_BYTES = Buffer.from([0x01, 0x02, 0x03, 0x04]);
const DCID = fromHex('a1a2a3a4a5a6a7a8');
const TAG = 16;

// Key sets of the initiator (sends i2r) for packet key epoch 0 and, with c2-key-update, epoch 1. The header protection key never rotates.
const epoch0 = deriveC2PacketKeys(PRK0, true, 0);
const epoch1 = deriveC2PacketKeys(PRK1, true, 1);
const sendKeys = (epoch) => (epoch === 0 ? epoch0.send : { key: epoch1.send.key, iv: epoch1.send.iv, hp: epoch0.send.hp });
const clone = (k) => ({ key: Buffer.from(k.key), iv: Buffer.from(k.iv), hp: Buffer.from(k.hp) });

function connection({ keys, isInitiator, keyUpdate = false }) {
  return new Pal3UdpConnection({
    send() {}, connId: CONN_ID, keys, isInitiator, keyUpdate, keepAlive: false, mtuCandidates: [], idleTimeoutMs: 3_600_000,
  });
}

// A responder that expects packets sent by the initiator under packet key epoch `epoch`.
function responder({ epoch, cid = false, keyUpdate = epoch > 0, largest = -1, wrongDirection = false }) {
  const own = wrongDirection ? epoch0.recv : epoch0.send;
  const rx = connection({ keys: { send: clone(epoch0.recv), recv: clone(own) }, isInitiator: false, keyUpdate });
  if (epoch > 0) rx.epochKeys.set(1, { send: { key: epoch1.recv.key, iv: epoch1.recv.iv }, recv: { key: epoch1.send.key, iv: epoch1.send.iv } });
  if (cid) { rx.cidV2 = true; rx.issuedByCid.set(DCID.toString('latin1'), 0); }
  if (largest >= 0) rx.recvPns.add(largest);
  return rx;
}
function accepts(rx, packet) {
  const ok = rx.onDatagram(Buffer.from(packet));
  return ok && !rx.closed;
}

function positive({ description, form, epoch = 0, cid = false, packetNumber, largestReceivedPn = -1, plaintextHex }) {
  const plaintext = fromHex(plaintextHex);
  const tx = connection({ keys: { send: clone(sendKeys(epoch)), recv: clone(epoch0.recv) }, isInitiator: true, keyUpdate: epoch > 0 });
  tx.packetEpochSend = epoch;
  if (cid) { tx.sendCid = DCID; tx.hdrLen = 13; }
  const hdr = cid ? 13 : 9;
  const buf = Buffer.alloc(hdr + plaintext.length + TAG);
  plaintext.copy(buf, hdr);
  const packet = Buffer.from(tx._protect(buf, plaintext.length, packetNumber));
  const sample = packet.subarray(hdr, hdr + 16);
  const mask = Buffer.alloc(4);
  PAL3_HYBRID_CRYPTO.headerProtection.maskInto(mask, sendKeys(epoch).hp, sample);
  const unprotected = Buffer.from(packet.subarray(0, hdr));
  for (let i = 0; i < 4; i++) unprotected[hdr - 4 + i] ^= mask[i];
  const expectedHeader = Buffer.alloc(hdr);
  expectedHeader[0] = packet[0];
  (cid ? DCID : CONN_ID_BYTES).copy(expectedHeader, 1);
  expectedHeader.writeUInt32BE(packetNumber >>> 0, hdr - 4);
  if (!unprotected.equals(expectedHeader)) throw new Error(`${form}: the unmasked header differs from type || connection id || pn_low32`);
  const receiverAccepts = accepts(responder({ epoch, cid, largest: largestReceivedPn }), packet);
  return {
    description,
    form,
    epoch,
    direction: 'i2r',
    prk0Hex: hex(PRK0),
    ...(epoch > 0 ? { prkEpochHex: hex(PRK1) } : {}),
    ...(cid ? { dcidHex: hex(DCID) } : { connIdHex: hex(CONN_ID_BYTES) }),
    packetNumber,
    largestReceivedPn,
    plaintextHex: hex(plaintext),
    keyHex: hex(sendKeys(epoch).key),
    ivHex: hex(sendKeys(epoch).iv),
    hpKeyHex: hex(sendKeys(epoch).hp),
    unprotectedHeaderHex: hex(unprotected),
    sampleHex: hex(sample),
    maskHex: hex(mask),
    packetHex: hex(packet),
    referenceReceiverAccepts: receiverAccepts,
  };
}

// PATH_CHALLENGE (0x07 and 8 bytes) followed by 23 PADDING frames (0x01): 32 bytes of plaintext that a receiver processes without side effects on the record layer.
const longPlaintext = Buffer.concat([Buffer.from([0x07]), Buffer.from(Array.from({ length: 8 }, (_, i) => i * 17 + 1)), Buffer.alloc(23, 0x01)]);
const cases = [
  positive({ description: 'One PING frame (1 byte of plaintext): the 16-byte sample is the ciphertext byte followed by the first 15 bytes of the tag', form: 'PKT_PROTECTED 0x02, 4-byte conn_id', packetNumber: 0, plaintextHex: '05' }),
  positive({ description: '32 bytes of plaintext (PATH_CHALLENGE and padding) and a packet number above 2^32: only the low 32 bits are on the wire and the nonce uses all 64', form: 'PKT_PROTECTED 0x02, 4-byte conn_id', packetNumber: 4294967297, largestReceivedPn: 4294967290, plaintextHex: hex(longPlaintext) }),
  positive({ description: 'Zero-length payload (no frame): the sample is the 16-byte tag. Protection output only: the reference receiver drops a datagram that carries no frame', form: 'PKT_PROTECTED 0x02, 4-byte conn_id', packetNumber: 7, plaintextHex: '' }),
  positive({ description: 'Eight-byte connection ID form (c2-cid-v2): the 13-byte unprotected header is the AAD and the mask covers the last 4 header bytes', form: 'PKT_PROTECTED_CID 0x04, 8-byte dcid', cid: true, packetNumber: 3, plaintextHex: '0505' }),
  positive({ description: 'Odd packet key epoch (c2-key-update): type 0x03, key and IV of epoch 1, header protection key still from prk_0', form: 'PKT_PROTECTED_PHASE1 0x03, 4-byte conn_id', epoch: 1, packetNumber: 1000, largestReceivedPn: 999, plaintextHex: '0505' }),
];

function negative({ description, source, mutate = (p) => p, wrongDirection = false, keyUpdateNegotiated }) {
  const c = cases[source];
  const packet = mutate(Buffer.from(c.packetHex, 'hex'));
  const keyUpdate = keyUpdateNegotiated ?? c.epoch > 0;
  const rx = responder({ epoch: c.epoch, cid: c.form.includes('CID'), keyUpdate, largest: c.largestReceivedPn, wrongDirection });
  if (accepts(rx, packet)) throw new Error(`${description}: the reference accepted the packet`);
  return {
    description,
    sourceCase: source,
    packetHex: hex(packet),
    receiveDirection: wrongDirection ? 'r2i' : 'i2r',
    keyUpdateNegotiated: keyUpdate,
    expected: 'dropped silently',
    errorCode: null,
  };
}
const flip = (index, bit = 0x01) => (p) => { p[index] ^= bit; return p; };

const doc = {
  specVersion: '0.6.18',
  section: '3.2 and A.4, C2 packet protection and header protection',
  description: 'PAL-UDP PROTECTED packets. key = HKDF-Expand(prk, "pal3-c2-k-v1" || u16be(e) || dir, 32), iv = HKDF-Expand(prk, "pal3-c2-iv-v1" || u16be(e) || dir, 12), hp_key = HKDF-Expand(prk_0, "pal3-c2-hp-v1" || u16be(0) || dir, 32). The AAD is the unprotected header (type || conn_id or dcid || pn_low32). nonce = iv[0..4] || (iv[4..8] XOR hi32(pn)) || (iv[8..12] XOR lo32(pn)). sample = the 16 bytes that follow the header (ciphertext || tag), mask = ChaCha20(hp_key, counter = u32le(sample[0..4]), nonce = sample[4..16]) applied to 4 zero bytes, protected_pn = pn_low32 XOR mask. The full packet number is rebuilt from the low 32 bits around the largest received (RFC 9000 A.3). The packets were produced by the reference C2 connection. The specification defines no error code for a C2 packet that fails authentication: it is dropped silently (3.2), so the negative cases carry errorCode null.',
  protectedPackets: cases,
  rejectedPackets: [
    negative({ description: 'One bit of the protected packet number is flipped: the unmasked pn changes, so the AAD and nonce no longer match', source: 1, mutate: flip(8) }),
    negative({ description: 'One ciphertext bit outside the sample is flipped: the mask is unchanged and the tag fails', source: 1, mutate: flip(9 + 24) }),
    negative({ description: 'One ciphertext bit inside the sample is flipped: the mask changes, so the packet number and the tag fail', source: 1, mutate: flip(9 + 2) }),
    negative({ description: 'The packet is opened with the keys of the opposite direction (hp_key and packet key of r2i)', source: 1, wrongDirection: true }),
    negative({ description: 'Type 0x03 without c2-key-update negotiated: a PROTECTED_PHASE1 packet MUST be dropped (3.2)', source: 0, mutate: flip(0, 0x01), keyUpdateNegotiated: false }),
  ],
};

writeFileSync(out, `${JSON.stringify(doc, null, 2)}\n`);
console.log(`wrote ${out}`);
process.exit(0);
