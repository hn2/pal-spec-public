// Generates test-vectors/v3/pal3-v0.6-plaintext-record-vectors.json (spec section 6.2, capability c2-bulk-plaintext-record) with the reference implementation.
// Run: node bin/generate-v0.6-plaintext-record-vectors.mjs --pal-core <path to the hn2/pal-core checkout> [--out <file>]
// The record keys come from a fixed PRK; the gate table runs the reference session with a fixed clock. Two runs are byte-identical.
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : null; };
const palCore = opt('--pal-core');
if (!palCore) { console.error('usage: node bin/generate-v0.6-plaintext-record-vectors.mjs --pal-core <path> [--out <file>]'); process.exit(2); }
const out = opt('--out') || resolve(dirname(fileURLToPath(import.meta.url)), '../test-vectors/v3/pal3-v0.6-plaintext-record-vectors.json');
const lib = (file) => import(pathToFileURL(resolve(palCore, 'packages/protocol/lib', file)).href);

const hs = await lib('pal3/handshake.js');
const { ChannelRecordProtector, RECORD_TYPE, CHANNEL_ID, FLAG_PLAINTEXT, encodeRecordHeader, deriveChannelTrafficSecret } = await lib('pal3/records.js');
const { Pal3SessionMux } = await lib('pal3/operations.js');

const hex = (b) => Buffer.from(b).toString('hex');
const code = (fn) => { try { fn(); return 'accepted'; } catch (err) { return /^(E_[A-Z0-9_]+)/.exec(err.message)?.[1] ?? err.message; } };
const prk = Buffer.alloc(48, 0x5c);
const payload = (n) => Buffer.from(Array.from({ length: n }, (_, i) => (13 * i + 5) % 251));
const protector = (channelId, isInitiator, allow) => {
  const p = new ChannelRecordProtector({ channelId, isInitiator, epoch: 0, prk });
  if (allow) p.allowPlaintext();
  return p;
};
const keys = (channelId) => { const k = deriveChannelTrafficSecret(prk, 0, channelId, 'i2r'); return { keyHex: hex(k.key), saltHex: hex(k.salt) }; };

const accepted = [];
function positive(name, description, channelId, streamId, payloadLength, plaintext) {
  const tx = protector(channelId, true, true);
  const rx = protector(channelId, false, true);
  const wire = tx.seal({ type: RECORD_TYPE.DATA, streamId, payload: payload(payloadLength), plaintext });
  const rec = rx.open(Buffer.from(wire));
  if (!Buffer.from(rec.payload).equals(payload(payloadLength))) throw new Error(`reference did not return the payload: ${name}`);
  accepted.push({ name, description, channelId, ...keys(channelId), wireHex: hex(wire), flags: wire[1], plaintext, payloadHex: hex(payload(payloadLength)), wireLength: wire.length });
}
positive('plaintextDataOnBulk0', 'A DATA record of 100 bytes on pal3/bulk/0 with FLAG_PLAINTEXT: wire length 120, no tag', CHANNEL_ID.BULK_0, 4, 100, true);
positive('plaintextDataOnBulk1', 'The same on pal3/bulk/1', CHANNEL_ID.BULK_1, 6, 100, true);
positive('plaintextEmptyPayload', 'An empty plaintext DATA record is 20 bytes', CHANNEL_ID.BULK_0, 8, 0, true);
positive('sealedDataOnBulk0', 'The same 100 bytes sealed: wire length 136 with the 16-byte tag, flag 0x00', CHANNEL_ID.BULK_0, 4, 100, false);

const rejected = [];
function negative(name, description, channelId, allow, wire, expectedError) {
  const rx = protector(channelId, false, allow);
  const got = code(() => rx.open(Buffer.from(wire)));
  if (got !== expectedError) throw new Error(`reference answered ${got}, not ${expectedError}: ${name}`);
  rejected.push({ name, description, channelId, receiverAllowsPlaintext: allow, wireHex: hex(wire), expectedError });
}
const header = (type, channelSeq, payloadLength, flags = FLAG_PLAINTEXT) => encodeRecordHeader({ type, flags, keyEpoch: 0, streamId: 4, channelSeq, payloadLength });
const body = payload(40);
negative('plaintextFlagOnAPing', 'FLAG_PLAINTEXT on a non-DATA record', CHANNEL_ID.BULK_0, true, Buffer.concat([header(RECORD_TYPE.PING, 0n, 40), body]), 'E_PAL3_PLAINTEXT_FORBIDDEN');
negative('plaintextFlagOnTheControlChannel', 'FLAG_PLAINTEXT on pal3/ctl, which never allows it', CHANNEL_ID.CTL, false, Buffer.concat([header(RECORD_TYPE.DATA, 0n, 40), body]), 'E_PAL3_PLAINTEXT_FORBIDDEN');
negative('plaintextFlagOnTheMediaChannel', 'FLAG_PLAINTEXT on pal3/media', CHANNEL_ID.MEDIA, false, Buffer.concat([header(RECORD_TYPE.DATA, 0n, 40), body]), 'E_PAL3_PLAINTEXT_FORBIDDEN');
negative('plaintextFlagWithoutTheNegotiatedCapability', 'FLAG_PLAINTEXT DATA on pal3/bulk/0 although the capability was not negotiated', CHANNEL_ID.BULK_0, false, Buffer.concat([header(RECORD_TYPE.DATA, 0n, 40), body]), 'E_PAL3_PLAINTEXT_FORBIDDEN');
negative('plaintextRecordWithATagAppended', 'A plaintext record whose wire length is 20 + payload_length + 16', CHANNEL_ID.BULK_0, true, Buffer.concat([header(RECORD_TYPE.DATA, 0n, 40), body, Buffer.alloc(16)]), 'E_PAL3_LENGTH_MISMATCH');
negative('plaintextRecordShorterThanItsLength', 'A plaintext record that is shorter than 20 + payload_length', CHANNEL_ID.BULK_0, true, Buffer.concat([header(RECORD_TYPE.DATA, 0n, 40), body.subarray(0, 39)]), 'E_PAL3_LENGTH_MISMATCH');
negative('plaintextRecordOutOfSequence', 'The channel_seq rules of 6.1 apply unchanged: sequence 5 when 0 is expected', CHANNEL_ID.BULK_0, true, Buffer.concat([header(RECORD_TYPE.DATA, 5n, 40), body]), 'E_PAL3_SEQ_MISMATCH');
const sendSide = [];
for (const [name, description, channelId, allow, type] of [
  ['sendPlaintextWithoutAllow', 'A sender that has not enabled plaintext records', CHANNEL_ID.BULK_0, false, RECORD_TYPE.DATA],
  ['sendPlaintextOnControlChannel', 'A sender asks for plaintext on pal3/ctl', CHANNEL_ID.CTL, true, RECORD_TYPE.DATA],
  ['sendPlaintextNonData', 'A sender asks for a plaintext PING', CHANNEL_ID.BULK_0, true, RECORD_TYPE.PING],
]) {
  const tx = (() => { try { return protector(channelId, true, allow); } catch (err) { return { enableError: err }; } })();
  const got = tx.enableError ? code(() => { throw tx.enableError; }) : code(() => tx.seal({ type, streamId: 4, payload: payload(8), plaintext: true }));
  if (got !== 'E_PAL3_PLAINTEXT_FORBIDDEN') throw new Error(`reference allowed ${name}: ${got}`);
  sendSide.push({ name, description, channelId, enabled: allow, recordType: type, expectedError: got });
}

// Session gate: negotiated capabilities, carrier and the active path decide whether a sender may send plaintext records
// and whether a receiver still accepts them (3 s drain window after the path stops being direct).
function sessionPair(clock, { caps, carrier, pathKind }) {
  const idI = hs.generateHybridSigningIdentity({ edSeed: Buffer.alloc(32, 0x31), dsaSeed: Buffer.alloc(32, 0x32) });
  const idR = hs.generateHybridSigningIdentity({ edSeed: Buffer.alloc(32, 0x33), dsaSeed: Buffer.alloc(32, 0x34) });
  const init = new hs.HandshakeInitiator({ deviceCert: hs.issueDeviceCertificate({ identity: idI }), deviceKeys: idI });
  const resp = hs.processHelloAndCreateAccept(init.createHelloRecord(), { deviceCert: hs.issueDeviceCertificate({ identity: idR }), deviceKeys: idR });
  const fin = init.processAcceptAndCreateFinish(resp.acceptRecord);
  return new Pal3SessionMux({
    isInitiator: true, prk: fin.prk, exporterSecret: fin.exporterSecret, ctlProtector: fin.ctlProtector, peerCert: fin.peerCert,
    sendWireRecord: async () => {}, allowUnauthenticated: true, autoRekey: false, now: () => clock.t,
    negotiatedCapabilities: caps, carrier, pathKind,
  });
}
const KEY = 'c2-key-update';
const BULK = 'c2-bulk-plaintext-record';
const gateScenarios = [
  ['directC2BothCapabilities', 'Both capabilities, carrier C2, direct UDP path', [KEY, BULK], 'c2', 'direct_udp', []],
  ['lanPath', 'The local network path is direct', [KEY, BULK], 'c2', 'lan', []],
  ['stunPunchPath', 'A hole-punched path is direct', [KEY, BULK], 'c2', 'stun_punch', []],
  ['withoutKeyUpdate', 'c2-bulk-plaintext-record without c2-key-update: always sealed', [BULK], 'c2', 'direct_udp', []],
  ['withoutBulkCapability', 'Only c2-key-update: always sealed', [KEY], 'c2', 'direct_udp', []],
  ['carrierC1', 'Carrier C1 never carries plaintext records', [KEY, BULK], 'c1', 'direct_udp', []],
  ['unknownPath', 'No path kind asserted: sealed', [KEY, BULK], 'c2', null, []],
  ['relayPath', 'A relayed path never carries plaintext records', [KEY, BULK], 'c2', 'buddy_relay', []],
  ['directThenRelay', 'The path leaves direct at t=1000 ms: the sender stops at once, the receiver drains until t=4000 ms', [KEY, BULK], 'c2', 'direct_udp',
    [{ atMs: 1000, setPath: 'buddy_relay' }]],
  ['relayThenDirect', 'A relayed session upgrades to a direct path at t=500 ms', [KEY, BULK], 'c2', 'buddy_relay', [{ atMs: 500, setPath: 'direct_udp' }]],
  ['directThenTurnThenDirect', 'Direct, then TURN at t=100, then direct again at t=2000: the drain window is cancelled', [KEY, BULK], 'c2', 'direct_udp',
    [{ atMs: 100, setPath: 'turn_relay' }, { atMs: 2000, setPath: 'direct_udp' }]],
];
const gate = gateScenarios.map(([name, description, caps, carrier, pathKind, changes]) => {
  const clock = { t: 0 };
  const mux = sessionPair(clock, { caps, carrier, pathKind });
  const times = [0, ...changes.map((c) => c.atMs), 1500, 2999, 3999, 4000, 4001, 6000].sort((a, b) => a - b);
  const samples = [];
  for (const t of [...new Set(times)]) {
    clock.t = t;
    for (const c of changes.filter((x) => x.atMs === t)) mux.setActivePath(c.setPath);
    samples.push({ atMs: t, senderMayUsePlaintext: mux.bulkPlaintext, receiverAcceptsPlaintext: mux._plaintextReceiveAllowed });
  }
  return { name, description, capabilities: caps, carrier, initialPathKind: pathKind, pathChanges: changes, drainWindowMs: 3000, samples };
});

// Stream rule (6.2 Receiver): which streams may carry plaintext DATA, what is discarded and what closes the session.
// Every scenario runs two real sessions; the receiver is the initiator that opened the read. A trailing record is forged with
// the responder's bulk protector, so the bytes are random per run and the vector records only the decision.
const { Pal3MerkleTree } = await lib('pal3/merkle.js');
const fileBytes = Buffer.from(Array.from({ length: 200_000 }, (_, i) => (i * 7 + 3) % 251));
const tree = Pal3MerkleTree.fromBuffer(fileBytes);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function streamSession(connected) {
  const idI = hs.generateHybridSigningIdentity({ edSeed: Buffer.alloc(32, 0x41), dsaSeed: Buffer.alloc(32, 0x42) });
  const idR = hs.generateHybridSigningIdentity({ edSeed: Buffer.alloc(32, 0x43), dsaSeed: Buffer.alloc(32, 0x44) });
  const caps = ['core.v1', 'stream.v1', 'grants.v1', KEY, BULK];
  const init = new hs.HandshakeInitiator({ deviceCert: hs.issueDeviceCertificate({ identity: idI }), deviceKeys: idI, capabilities: caps });
  const resp = hs.processHelloAndCreateAccept(init.createHelloRecord(), { deviceCert: hs.issueDeviceCertificate({ identity: idR }), deviceKeys: idR, capabilities: caps });
  const fin = init.processAcceptAndCreateFinish(resp.acceptRecord);
  const done = resp.verifyFinish(fin.finishRecord);
  hs.verifyReadyRecord(fin.ctlProtector, done.readyRecord);
  const clock = { t: 0 };
  const held = [];
  let rx;
  let tx;
  rx = new Pal3SessionMux({
    isInitiator: true, prk: fin.prk, exporterSecret: fin.exporterSecret, ctlProtector: fin.ctlProtector, peerCert: fin.peerCert,
    negotiatedCapabilities: fin.negotiatedCapabilities, pathKind: 'direct_udp', carrier: 'c2', autoRekey: false, now: () => clock.t,
    sendWireRecord: async (ch, wire) => { if (connected) await tx.receiveWireRecord(ch, wire); },
  });
  tx = new Pal3SessionMux({
    isInitiator: false, prk: done.prk, exporterSecret: done.exporterSecret, ctlProtector: done.ctlProtector, peerCert: done.peerCert,
    negotiatedCapabilities: done.negotiatedCapabilities, pathKind: 'direct_udp', carrier: 'c2', allowUnauthenticated: true, autoRekey: false, now: () => clock.t,
    getContentTree: async () => ({ tree, readBlock: (i) => fileBytes.subarray(i * 262144, (i + 1) * 262144) }),
    sendWireRecord: async (ch, wire) => { held.push({ ch, wire: Buffer.from(wire) }); },
  });
  const settle = async () => { let n = -1; while (n !== held.length) { n = held.length; await sleep(40); } };
  let closeError = null;
  const deliver = async (records) => {
    for (const r of records) {
      try { await rx.receiveWireRecord(r.ch, r.wire); } catch (err) { closeError ??= /^(E_[A-Z0-9_]+)/.exec(err.message)?.[1] ?? err.message; break; }
    }
  };
  const forge = (streamId) => ({ ch: CHANNEL_ID.BULK_0, wire: tx.channels.get(CHANNEL_ID.BULK_0).seal({ type: RECORD_TYPE.DATA, streamId, payload: payload(64), plaintext: true }) });
  return { clock, rx, held, settle, deliver, forge, closeError: () => closeError };
}
const readSpec = { contentId: tree.contentId, expectedRoot: tree.root, totalBytes: fileBytes.length };
async function streamScenarioRun(sc) {
  const live = sc.stream === 'blockRead' || sc.stream === 'batchRead';
  const real = live && sc.streamState !== 'cancelled';
  const S = await streamSession(real);
  let delivered = 0;
  let result = null;
  let streamId = 7;
  const startRead = () => {
    const p = sc.stream === 'blockRead'
      ? S.rx.readVerifiedBlocks({ ...readSpec, onVerifiedBlock: () => { delivered += 1; } })
      : S.rx.readVerifiedBatch({ files: [readSpec], onVerifiedFile: () => { delivered += 1; } });
    p.then((r) => { result = r; }, () => {});
  };
  if (live || sc.stream === 'rpcRequest') {
    if (sc.stream === 'rpcRequest') S.rx.request('share.list', {}).catch(() => {});
    else startRead();
    await sleep(20);
    streamId = [...S.rx.outboundStreams.keys()].at(-1);
  }
  if (sc.streamState === 'cancelled') { await S.rx.cancelStream(streamId); await sleep(20); }
  if (sc.streamState === 'finished') {
    await S.settle();
    await S.deliver(S.held.splice(0));
    await sleep(60);
    if (!result) throw new Error(`the read did not finish: ${sc.name}`);
  }
  if (sc.pathChange) { S.clock.t = sc.pathChange.atMs; S.rx.setActivePath(sc.pathChange.to); }
  S.clock.t = sc.arrivalMs;
  let outcome;
  if (sc.streamState === 'open' && live) {
    await S.settle();
    await S.deliver(S.held.splice(0));
    await sleep(60);
    outcome = S.closeError() ? 'closed' : (result && delivered > 0 ? 'delivered' : 'stalled');
  } else {
    await S.deliver([S.forge(streamId)]);
    outcome = S.closeError() ? 'closed' : (S.rx.closed ? 'closed' : 'discarded');
  }
  const error = S.closeError();
  return { outcome, error: error ?? undefined, sessionClosed: S.rx.closed };
}
const streamScenarios = [
  ['blockReadOpenDirect', 'A block read the receiver opened, path direct: the plaintext DATA is accepted and Merkle-verified', 'blockRead', 'open', null, 0, 'delivered'],
  ['batchReadOpenDirect', 'A batch read the receiver opened, path direct', 'batchRead', 'open', null, 0, 'delivered'],
  ['blockReadOpenInsideDrainWindow', 'The path left direct at t=1000 ms; plaintext DATA in flight arrives at t=2000 ms', 'blockRead', 'open', { atMs: 1000, to: 'buddy_relay' }, 2000, 'delivered'],
  ['blockReadOpenLastMillisecondOfDrainWindow', 'The same at t=3999 ms (the window is [1000, 4000))', 'blockRead', 'open', { atMs: 1000, to: 'buddy_relay' }, 3999, 'delivered'],
  ['blockReadOpenAtEndOfDrainWindow', 'The same at t=4000 ms: the window has ended, the session closes', 'blockRead', 'open', { atMs: 1000, to: 'buddy_relay' }, 4000, 'closed'],
  ['plaintextOnAStreamNeverOpened', 'Plaintext DATA on a stream id the receiver never opened', 'none', 'unknown', null, 0, 'closed'],
  ['plaintextOnARequestStream', 'Plaintext DATA on a stream opened for an ordinary request (not a block or batch read)', 'rpcRequest', 'open', null, 0, 'closed'],
  ['plaintextOnARequestStreamInsideDrainWindow', 'The drain window does not make a request stream eligible', 'rpcRequest', 'open', { atMs: 1000, to: 'buddy_relay' }, 2000, 'closed'],
  ['trailingOnACancelledBlockStream', 'Plaintext DATA after the receiver cancelled its block read: discarded, the session stays open', 'blockRead', 'cancelled', null, 0, 'discarded'],
  ['trailingOnAFinishedBlockStream', 'Plaintext DATA after a block read finished: discarded', 'blockRead', 'finished', null, 0, 'discarded'],
  ['trailingOnAFinishedBatchStream', 'Plaintext DATA after a batch read finished: discarded', 'batchRead', 'finished', null, 0, 'discarded'],
  ['trailingOnACancelledStreamInsideDrainWindow', 'Trailing plaintext DATA of a cancelled stream at t=2000 ms after the path left direct at t=1000 ms: discarded', 'blockRead', 'cancelled', { atMs: 1000, to: 'buddy_relay' }, 2000, 'discarded'],
  ['trailingOnACancelledStreamAfterDrainWindow', 'The same at t=4000 ms: outside the drain window on a non-direct path the record closes the session', 'blockRead', 'cancelled', { atMs: 1000, to: 'buddy_relay' }, 4000, 'closed'],
  ['trailingOnAFinishedStreamAfterDrainWindow', 'A finished stream, the path left direct, t=4000 ms: closes the session', 'blockRead', 'finished', { atMs: 1000, to: 'buddy_relay' }, 4000, 'closed'],
];
const streamRule = [];
for (const [name, description, stream, streamState, pathChange, arrivalMs, expectedOutcome] of streamScenarios) {
  const got = await streamScenarioRun({ name, stream, streamState, pathChange, arrivalMs });
  if (got.outcome !== expectedOutcome) throw new Error(`reference answered ${got.outcome} (${got.error}), not ${expectedOutcome}: ${name}`);
  if (got.outcome === 'closed' && got.error !== 'E_PAL3_PLAINTEXT_FORBIDDEN') throw new Error(`closed with ${got.error}: ${name}`);
  streamRule.push({ name, description, stream, streamState, pathChange, arrivalMs, drainWindowMs: 3000, expected: got.outcome === 'closed' ? { outcome: 'closed', error: 'E_PAL3_PLAINTEXT_FORBIDDEN' } : { outcome: got.outcome } });
}

const doc = {
  specVersion: '0.6.20',
  section: '6.2',
  description: 'Plaintext bulk records: FLAG_PLAINTEXT (0x80) DATA records on pal3/bulk/0..1, their wire form, the record-layer rejections, and the session gate (capabilities, carrier, path kind, 3 s drain window).',
  generatedBy: 'bin/generate-v0.6-plaintext-record-vectors.mjs',
  flagPlaintext: FLAG_PLAINTEXT,
  recordTypeData: RECORD_TYPE.DATA,
  bulkChannelIds: [CHANNEL_ID.BULK_0, CHANNEL_ID.BULK_1],
  directPathKinds: ['lan', 'direct_udp', 'stun_punch'],
  records: accepted,
  rejected,
  sendSideRejected: sendSide,
  gate,
  streamRule,
};
writeFileSync(out, `${JSON.stringify(doc, null, 2)}\n`);
console.log(`wrote ${out}: ${accepted.length} records, ${rejected.length} rejected, ${gate.length} gate scenarios, ${streamRule.length} stream rule scenarios`);
