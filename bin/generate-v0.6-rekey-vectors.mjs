// Generates test-vectors/v3/pal3-v0.6-rekey-vectors.json (spec section 5.3) with the reference implementation.
// Run: node bin/generate-v0.6-rekey-vectors.mjs --pal-core <path to the hn2/pal-core checkout> [--out <file>]
// Keys, seeds and messages are fixed, so two runs give byte-identical output. exporter_secret_0 is the one of pal3-v0.6-beacon-vectors.json.
import { createHash, createHmac, createPrivateKey, createPublicKey } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : null; };
const palCore = opt('--pal-core');
if (!palCore) { console.error('usage: node bin/generate-v0.6-rekey-vectors.mjs --pal-core <path> [--out <file>]'); process.exit(2); }
const out = opt('--out') || resolve(dirname(fileURLToPath(import.meta.url)), '../test-vectors/v3/pal3-v0.6-rekey-vectors.json');
const lib = (file) => import(pathToFileURL(resolve(palCore, 'packages/protocol/lib', file)).href);

const { PAL3_HYBRID_CRYPTO } = await lib('pal3/cryptoProvider.js');
const { kemKeygen, kemEncapsulate, kemDecapsulate } = await lib('pqc.js');
const { deriveRekeyPrk, generateHybridSigningIdentity, issueDeviceCertificate, HandshakeInitiator, processHelloAndCreateAccept, verifyReadyRecord } = await lib('pal3/handshake.js');
const { deriveEpochExporterSecret, deriveChannelTrafficSecret, deriveC2PacketKeys, ChannelRecordProtector, RECORD_TYPE, CHANNEL_ID } = await lib('pal3/records.js');
const { Pal3SessionMux } = await lib('pal3/operations.js');
const { MAX_KEY_EPOCH, REKEY_MAX_PEER_INITS_PER_WINDOW, REKEY_PEER_INIT_WINDOW_MS } = await lib('pal3/rekey.js');

const hex = (b) => Buffer.from(b).toString('hex');
const sha384 = (b) => createHash('sha384').update(b).digest();
const PKCS8_X25519 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const x25519Public = (sk) => createPublicKey(createPrivateKey({ key: Buffer.concat([PKCS8_X25519, sk]), format: 'der', type: 'pkcs8' })).export({ format: 'der', type: 'spki' }).subarray(-32);

const classical = PAL3_HYBRID_CRYPTO.classicalKem;
const DIRS = ['i2r', 'r2i'];

function derivation({ description, epoch, prevExporterSecret, seedByte, payload }) {
  const newEpoch = epoch + 1;
  const skI = Buffer.alloc(32, seedByte);
  const skR = Buffer.alloc(32, seedByte + 1);
  const pkI = x25519Public(skI);
  const pkR = x25519Public(skR);
  const ssX = classical.sharedSecret(skR, pkI);
  if (!ssX.equals(classical.sharedSecret(skI, pkR))) throw new Error('X25519 disagreement');
  const kemSeed = Buffer.alloc(64, seedByte + 2);
  const kemMessage = Buffer.alloc(32, seedByte + 3);
  const kem = kemKeygen(kemSeed);
  const enc = kemEncapsulate(kem.publicKey, kemMessage);
  if (!kemDecapsulate(enc.cipherText, kem.secretKey).equals(enc.sharedSecret)) throw new Error('ML-KEM disagreement');

  const prk = deriveRekeyPrk({
    prevExporterSecret, x25519SharedSecret: ssX, kemSharedSecret: enc.sharedSecret,
    x25519EphI: pkI, x25519EphR: pkR, mlkemEkI: kem.publicKey, mlkemCt: enc.cipherText,
  });
  const kemContext = Buffer.concat([pkI, pkR, sha384(kem.publicKey), sha384(enc.cipherText)]);
  const ikm = Buffer.concat([ssX, enc.sharedSecret, kemContext]);
  if (!createHmac('sha384', prevExporterSecret).update(ikm).digest().equals(prk)) throw new Error('kem_context or ikm layout differs from the reference');

  const recordKeys = [];
  for (let channelId = 0; channelId < 4; channelId++) {
    for (const dir of DIRS) {
      const k = deriveChannelTrafficSecret(prk, newEpoch, channelId, dir);
      recordKeys.push({ channelId, dir, keyHex: hex(k.key), saltHex: hex(k.salt) });
    }
  }
  const c2 = deriveC2PacketKeys(prk, true, newEpoch);
  const protector = new ChannelRecordProtector({ channelId: CHANNEL_ID.CTL, isInitiator: true, epoch: newEpoch, prk });
  const wire = protector.seal({ type: RECORD_TYPE.DATA, streamId: 1, payload: payload.length ? payload : Buffer.alloc(0) });
  return {
    description,
    epoch,
    newEpoch,
    prevExporterSecretHex: hex(prevExporterSecret),
    x25519EphISecretHex: hex(skI),
    x25519EphIPublicHex: hex(pkI),
    x25519EphRSecretHex: hex(skR),
    x25519EphRPublicHex: hex(pkR),
    x25519SharedSecretHex: hex(ssX),
    mlkem: {
      seedHex: hex(kemSeed),
      encapsulationKeyHex: hex(kem.publicKey),
      encapsulationMessageHex: hex(kemMessage),
      ciphertextHex: hex(enc.cipherText),
      sharedSecretHex: hex(enc.sharedSecret),
    },
    kemContextHex: hex(kemContext),
    ikmHex: hex(ikm),
    prkNextHex: hex(prk),
    exporterSecretNextHex: hex(deriveEpochExporterSecret(prk, newEpoch)),
    recordKeys,
    c2PacketKeys: [
      { dir: 'i2r', keyHex: hex(c2.send.key), ivHex: hex(c2.send.iv) },
      { dir: 'r2i', keyHex: hex(c2.recv.key), ivHex: hex(c2.recv.iv) },
    ],
    sealedRecord: {
      description: 'DATA record on channel 0, direction i2r, first record of the new epoch (channel_seq 0)',
      type: RECORD_TYPE.DATA,
      streamId: 1,
      channelSeq: 0,
      plaintextHex: hex(payload),
      wireHex: hex(wire),
    },
  };
}

function createPair(clock) {
  const idI = generateHybridSigningIdentity({ edSeed: Buffer.alloc(32, 0x31), dsaSeed: Buffer.alloc(32, 0x32) });
  const idR = generateHybridSigningIdentity({ edSeed: Buffer.alloc(32, 0x33), dsaSeed: Buffer.alloc(32, 0x34) });
  const hsI = new HandshakeInitiator({ deviceCert: issueDeviceCertificate({ identity: idI }), deviceKeys: idI });
  const respStep = processHelloAndCreateAccept(hsI.createHelloRecord(), { deviceCert: issueDeviceCertificate({ identity: idR }), deviceKeys: idR });
  const finStep = hsI.processAcceptAndCreateFinish(respStep.acceptRecord);
  const doneR = respStep.verifyFinish(finStep.finishRecord);
  verifyReadyRecord(finStep.ctlProtector, doneR.readyRecord);
  const common = { allowUnauthenticated: true, autoRekey: false, now: () => clock.t };
  let muxI;
  let muxR;
  muxI = new Pal3SessionMux({
    isInitiator: true, prk: finStep.prk, exporterSecret: finStep.exporterSecret, ctlProtector: finStep.ctlProtector,
    peerCert: finStep.peerCert, sendWireRecord: async (ch, w) => { await muxR.receiveWireRecord(ch, w); }, ...common,
  });
  muxR = new Pal3SessionMux({
    isInitiator: false, prk: doneR.prk, exporterSecret: doneR.exporterSecret, ctlProtector: doneR.ctlProtector,
    peerCert: doneR.peerCert, sendWireRecord: async (ch, w) => { await muxI.receiveWireRecord(ch, w); }, ...common,
  });
  return { muxI, muxR };
}

const errorCode = (err) => /^(E_[A-Z0-9_]+)/.exec(err.message)?.[1] ?? err.message;
async function outcome(promise) {
  try { await promise; return 'accepted'; } catch (err) { return errorCode(err); }
}

async function exhaustedInitiator() {
  const { muxI } = createPair({ t: 0 });
  muxI.currentEpoch = MAX_KEY_EPOCH;
  const result = await outcome(muxI.rekey());
  return {
    description: 'A side that has reached epoch 65535 closes the session instead of sending a further rekey_init',
    currentEpoch: MAX_KEY_EPOCH,
    action: 'send',
    expectedError: result,
    sessionClosed: muxI.closed,
  };
}

async function exhaustedReceiver() {
  const { muxI, muxR } = createPair({ t: 0 });
  muxR.currentEpoch = MAX_KEY_EPOCH;
  const result = await outcome(muxI._sendRecord(CHANNEL_ID.CTL, RECORD_TYPE.CTRL, 0, {
    op: 'rekey_init', epoch: MAX_KEY_EPOCH + 1, x25519Eph: Buffer.alloc(32, 0x41), mlkemEk: Buffer.alloc(1184, 0x42),
  }));
  return {
    description: 'A rekey_init for epoch 65536 closes the session of the side that receives it',
    currentEpoch: MAX_KEY_EPOCH,
    action: 'receive',
    initEpoch: MAX_KEY_EPOCH + 1,
    expectedError: result,
    sessionClosed: muxR.closed,
  };
}

async function peerRate(description, seventeenthAtMs) {
  const clock = { t: 0 };
  const { muxI, muxR } = createPair(clock);
  const steps = [];
  for (let i = 1; i <= REKEY_MAX_PEER_INITS_PER_WINDOW + 1; i++) {
    clock.t = i <= REKEY_MAX_PEER_INITS_PER_WINDOW ? i * 1000 : seventeenthAtMs;
    steps.push({ atMs: clock.t, result: await outcome(muxI.rekey()) });
  }
  return {
    description,
    windowMs: REKEY_PEER_INIT_WINDOW_MS,
    maxPerWindow: REKEY_MAX_PEER_INITS_PER_WINDOW,
    steps,
    sessionClosed: muxR.closed,
  };
}

const text = (s) => Buffer.from(s, 'ascii');
const doc = {
  specVersion: '0.6.18',
  section: '5.3 rekey',
  description: 'Post-compromise rekey. prk_{e+1} = HKDF-Extract(salt = exporter_secret_e, ikm = ss_x || ss_pq || kem_context) with kem_context = x25519_eph_I || x25519_eph_R || SHA-384(mlkem_ek_I) || SHA-384(mlkem_ct). Every X25519 secret, ML-KEM seed and encapsulation message is a fixed test value; a validator re-derives the shared secrets, prk, exporter secret, record keys, C2 packet keys and the sealed record from them. The error cases are driven through the reference session. The epoch is a u16 and the last usable epoch is 65535.',
  rekeyDerivation: [
    derivation({
      description: 'First rekey, epoch 0 to 1, from the exporter_secret_0 of the pair beacon vector',
      epoch: 0, prevExporterSecret: Buffer.alloc(32, 0x33), seedByte: 0x10, payload: text('pal3 rekey epoch 1 record'),
    }),
    null,
    derivation({
      description: 'Rekey at the end of the epoch space, epoch 65534 to 65535 (the last usable epoch, u16be ffff in every label)',
      epoch: 65534, prevExporterSecret: Buffer.alloc(32, 0x55), seedByte: 0x30, payload: text('pal3 rekey epoch 65535 record'),
    }),
  ],
  epochLimits: [await exhaustedInitiator(), await exhaustedReceiver()],
  peerRekeyRate: [
    await peerRate('The 17th peer-initiated rekey_init inside 60 s closes the session of the responder', 30_000),
    await peerRate('The 17th peer-initiated rekey_init after the 60 s window of the first 16 is accepted', 76_001),
  ],
};
doc.rekeyDerivation[1] = derivation({
  description: 'Second rekey, epoch 1 to 2, chained from exporter_secret_1 of the first case',
  epoch: 1, prevExporterSecret: Buffer.from(doc.rekeyDerivation[0].exporterSecretNextHex, 'hex'), seedByte: 0x20, payload: text('pal3 rekey epoch 2 record'),
});

writeFileSync(out, `${JSON.stringify(doc, null, 2)}\n`);
console.log(`wrote ${out}`);
process.exit(0);
