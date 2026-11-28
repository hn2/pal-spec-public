// Generates test-vectors/v3/pal3-v0.6-hardening-vectors.json (spec section 11.2 items 1, 3, 5, 7) with the reference implementation.
// Run: node bin/generate-v0.6-hardening-vectors.mjs --pal-core <path to the hn2/pal-core checkout> [--out <file>]
// Nothing random reaches the file: reassembly scenarios use fixed frames and message ids, the clock is a scenario input.
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : null; };
const palCore = opt('--pal-core');
if (!palCore) { console.error('usage: node bin/generate-v0.6-hardening-vectors.mjs --pal-core <path> [--out <file>]'); process.exit(2); }
const out = opt('--out') || resolve(dirname(fileURLToPath(import.meta.url)), '../test-vectors/v3/pal3-v0.6-hardening-vectors.json');
const lib = (file) => import(pathToFileURL(resolve(palCore, 'packages/protocol/lib', file)).href);

const carrier = await lib('pal3/carrier.js');
const pqc = await lib('pqc.js');
const sodium = (await import(pathToFileURL(resolve(palCore, 'packages/protocol/node_modules/sodium-native/index.js')).href).catch(() => import('sodium-native'))).default;

const hex = (b) => Buffer.from(b).toString('hex');
const code = (fn) => { try { return { value: fn() }; } catch (err) { return { error: /^(E_[A-Z0-9_]+)/.exec(err.message)?.[1] ?? err.message }; } };

// --- item 5: URI validation ---------------------------------------------------------------------------------------------
const uriInputs = [
  ['plainHandle', 'pal://@alice'],
  ['handleShareAndPath', 'pal://@alice/share1/docs/a.txt'],
  ['handleWithoutAt', 'pal://alice/share1'],
  ['byteRange', 'pal://@alice/share1/a.bin?range=0-1023'],
  ['openEndedRange', 'pal://@alice/share1/a.bin?range=10-'],
  ['encodedSpaceIsKept', 'pal://@alice/share1/my%20file.txt'],
  ['encodedSlashInSegment', 'pal://@alice/share1/a%2Fb'],
  ['encodedBackslash', 'pal://@alice/share1/a%5Cb'],
  ['encodedColon', 'pal://@alice/share1/a%3Ab'],
  ['plainDotDot', 'pal://@alice/share1/../secret'],
  ['encodedDotDot', 'pal://@alice/share1/%2e%2e/secret'],
  ['encodedDot', 'pal://@alice/share1/%2e/a'],
  ['encodedNul', 'pal://@alice/share1/a%00b'],
  ['encodedNewline', 'pal://@alice/share1/a%0Ab'],
  ['encodedDel', 'pal://@alice/share1/a%7Fb'],
  ['encodedSlashInHandle', 'pal://%40al%2Fice/share1'],
  ['malformedPercentEncoding', 'pal://@alice/share1/%E0%A4%A'],
  ['missingHandle', 'pal://'],
  ['wrongScheme', 'http://@alice/share1'],
  ['reversedRange', 'pal://@alice/share1/a.bin?range=9-3'],
];
const uri = uriInputs.map(([name, input]) => {
  const r = code(() => carrier.parsePalUri(input));
  if (r.error) return { name, input, expectedError: r.error };
  const { scheme, handle, shareId, filePath, range } = r.value;
  return { name, input, expected: { scheme, handle, shareId, filePath, range } };
});

// --- item 1: low-order X25519 public keys -------------------------------------------------------------------------------
const lowOrderKeys = [
  ['allZero', '00'.repeat(32)],
  ['one', `01${'00'.repeat(31)}`],
  ['order8a', 'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800'],
  ['order8b', '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157'],
  ['pMinus1', `ecffffff${'ff'.repeat(27)}7f`],
  ['p', `edffffff${'ff'.repeat(27)}7f`],
  ['pPlus1', `eeffffff${'ff'.repeat(27)}7f`],
];
const scratchScalar = Buffer.alloc(32, 9);
const publicOf = (sk) => { const pk = Buffer.alloc(32); sodium.crypto_scalarmult_base(pk, sk); return pk; };
const decisionFor = (pkHex) => {
  const outBuf = Buffer.alloc(32);
  try { sodium.crypto_scalarmult(outBuf, scratchScalar, Buffer.from(pkHex, 'hex')); } catch { return { sharedSecretHex: null, decision: 'rejected' }; }
  return outBuf.every((b) => b === 0) ? { sharedSecretHex: hex(outBuf), decision: 'rejected' } : { sharedSecretHex: hex(outBuf), decision: 'accepted' };
};
const x25519 = {
  scratchScalarHex: hex(scratchScalar),
  rule: 'an all-zero shared secret, or a library error, rejects the key',
  keys: [...lowOrderKeys.map(([name, pkHex]) => ({ name, publicKeyHex: pkHex, ...decisionFor(pkHex) })),
    { name: 'ordinaryKey', publicKeyHex: hex(publicOf(Buffer.alloc(32, 7))), ...decisionFor(hex(publicOf(Buffer.alloc(32, 7)))) }],
};

// --- item 7: ML-KEM encapsulation key modulus check ---------------------------------------------------------------------
const kem = pqc.kemKeygen(Buffer.alloc(64, 5));
const withCoefficient = (i, lo, hi) => { const pk = Buffer.from(kem.publicKey); pk[i] = lo; pk[i + 1] = (pk[i + 1] & 0xf0) | hi; return pk; };
const kemCases = [
  ['reducedKey', Buffer.from(kem.publicKey)],
  ['firstCoefficient4095', withCoefficient(0, 0xff, 0x0f)],
  ['firstCoefficient3329', withCoefficient(0, 0x01, 0x0d)],
  ['firstCoefficient3328', withCoefficient(0, 0x00, 0x0d)],
  ['lastCoefficientOfTheVector4095', (() => { const pk = Buffer.from(kem.publicKey); const i = 1152 - 3; pk[i + 1] = (pk[i + 1] & 0x0f) | 0xf0; pk[i + 2] = 0xff; return pk; })()],
].map(([name, pk]) => ({ name, encapsulationKeyHex: hex(pk), decision: code(() => pqc.kemEncapsulate(pk)).error ? 'rejected' : 'accepted' }));
const mlkem = { rule: 'every 12-bit coefficient of the first 1152 bytes must be below 3329', cases: kemCases };

// --- item 3: datagram reassembly ----------------------------------------------------------------------------------------
const MAX = 1200;
const frame = (len, fill) => Buffer.alloc(len, fill);
const mk = () => new carrier.Pal3DatagramFragmenter({ now: () => clock.t });
const clock = { t: 0 };
const split = (len, fill, messageId) => new carrier.Pal3DatagramFragmenter().fragment(frame(len, fill), messageId).map(hex);
function scenario(name, description, steps) {
  const f = mk();
  clock.t = 0;
  const recorded = steps.map((s) => {
    clock.t = s.atMs;
    const r = code(() => f.acceptPacket(Buffer.from(s.packetHex, 'hex'), s.source, s.group ?? s.source));
    const step = { atMs: s.atMs, source: s.source, ...(s.group ? { group: s.group } : {}), packetHex: s.packetHex };
    if (r.error) return { ...step, expectedError: r.error };
    return { ...step, expected: r.value ? { complete: true, frameHex: hex(r.value) } : { complete: false } };
  });
  return { name, description, steps: recorded };
}
const three = split(MAX * 2 + 100, 0x31, 0x1001);
const two = split(MAX + 10, 0x32, 0x2002);
const conflicting = (pktHex) => { const b = Buffer.from(pktHex, 'hex'); b[b.length - 1] ^= 0xff; return hex(b); };
const rewriteTotal = (pktHex, total) => { const b = Buffer.from(pktHex, 'hex'); b.writeUInt16BE(total, 6); return hex(b); };
const hdr = (id, idx, total, payload) => { const b = Buffer.alloc(8 + payload.length); b.writeUInt32BE(id, 0); b.writeUInt16BE(idx, 4); b.writeUInt16BE(total, 6); payload.copy(b, 8); return hex(b); };
const first = (id, n) => hdr(id, 0, 2, frame(MAX, n & 0xff));
const reassembly = [
  scenario('fragmentsInAnyOrderComplete', 'Three fragments arrive as 2, 0, 1; the frame is returned with the last one', [
    { atMs: 0, source: 'a', packetHex: three[2] }, { atMs: 1, source: 'a', packetHex: three[0] }, { atMs: 2, source: 'a', packetHex: three[1] }]),
  scenario('singleFragmentFrameNeedsNoState', 'total = 1 is returned at once', [
    { atMs: 0, source: 'a', packetHex: split(100, 0x33, 0x3003)[0] }]),
  scenario('identicalRetransmissionIsHarmless', 'The same fragment twice changes nothing', [
    { atMs: 0, source: 'a', packetHex: two[0] }, { atMs: 1, source: 'a', packetHex: two[0] }, { atMs: 2, source: 'a', packetHex: two[1] }]),
  scenario('conflictingDuplicateDropsTheMessage', 'First write wins; a different payload for the same index drops the whole message, so the late fragment starts a new entry', [
    { atMs: 0, source: 'a', packetHex: two[0] }, { atMs: 1, source: 'a', packetHex: conflicting(two[0]) }, { atMs: 2, source: 'a', packetHex: two[1] }]),
  scenario('inconsistentTotalDropsOnlyThatPacket', 'A packet with another total for the same message_id is refused and the legitimate message still completes', [
    { atMs: 0, source: 'a', packetHex: three[0] }, { atMs: 1, source: 'a', packetHex: rewriteTotal(three[1], 4) },
    { atMs: 2, source: 'a', packetHex: three[1] }, { atMs: 3, source: 'a', packetHex: three[2] }]),
  scenario('nonFinalFragmentMustBeFullSize', 'A short fragment that is not the last is refused', [
    { atMs: 0, source: 'a', packetHex: hdr(0x4004, 0, 2, frame(MAX - 1, 0x34)) }]),
  scenario('fragmentLargerThanTheLimitIsRefused', 'A final fragment above 1200 bytes is refused', [
    { atMs: 0, source: 'a', packetHex: hdr(0x4005, 1, 2, frame(MAX + 1, 0x35)) }]),
  scenario('indexNotBelowTotalIsRefused', 'idx = total', [{ atMs: 0, source: 'a', packetHex: hdr(0x4006, 2, 2, frame(10, 1)) }]),
  scenario('totalZeroIsRefused', 'total = 0', [{ atMs: 0, source: 'a', packetHex: hdr(0x4007, 0, 0, frame(10, 1)) }]),
  scenario('totalAboveSixtyFourIsRefused', 'total = 65', [{ atMs: 0, source: 'a', packetHex: hdr(0x4008, 0, 65, frame(MAX, 1)) }]),
  scenario('packetShorterThanTheHeaderIsRefused', '7 bytes', [{ atMs: 0, source: 'a', packetHex: '00112233445566' }]),
  scenario('entryExpiresAfterFiveSeconds', 'The second fragment arrives 5000 ms after the first: the first is gone and the second starts a new, incomplete entry', [
    { atMs: 0, source: 'a', packetHex: two[0] }, { atMs: 5000, source: 'a', packetHex: two[1] }]),
  scenario('entryStillLivesJustBeforeFiveSeconds', '4999 ms', [
    { atMs: 0, source: 'a', packetHex: two[0] }, { atMs: 4999, source: 'a', packetHex: two[1] }]),
  scenario('sourcesNeverMixFragments', 'The same message_id from another source with another payload is a different message, not a conflict', [
    { atMs: 0, source: 'a', packetHex: two[0] }, { atMs: 1, source: 'b', packetHex: conflicting(two[0]) },
    { atMs: 2, source: 'a', packetHex: two[1] }]),
  scenario('perSourceCapOfSixteenEvictsTheOldest', 'Seventeen incomplete messages from one source evict the first one: the second message still completes, and the late fragment of the first one only starts a new incomplete entry', [
    ...Array.from({ length: 17 }, (_, i) => ({ atMs: i, source: 'a', packetHex: first(0x5000 + i, i) })),
    { atMs: 20, source: 'a', packetHex: hdr(0x5001, 1, 2, frame(5, 1)) },
    { atMs: 21, source: 'a', packetHex: hdr(0x5000, 1, 2, frame(5, 0)) }]),
  scenario('globalCapOf128EvictsTheOldest', '129 incomplete messages from 129 sources: the first one was evicted, the last one completes', [
    ...Array.from({ length: 129 }, (_, i) => ({ atMs: i, source: `s${i}`, group: `g${i}`, packetHex: first(0x6000 + i, i) })),
    { atMs: 200, source: 's0', group: 'g0', packetHex: hdr(0x6000, 1, 2, frame(5, 0)) },
    { atMs: 201, source: 's128', group: 'g128', packetHex: hdr(0x6000 + 128, 1, 2, frame(5, 128)) }]),
];

// --- item 4: peer credit is clamped to 16 MiB; block ranges are validated -------------------------------------------------
// A real responder serves a read; the requester is simulated with its record protector. Only decisions are recorded (how many
// bytes of DATA the responder sent, which error it answered), no byte of a session reaches the file.
const hsLib = await lib('pal3/handshake.js');
const { Pal3SessionMux } = await lib('pal3/operations.js');
const { RECORD_TYPE, CHANNEL_ID, MAX_DATA_PAYLOAD } = await lib('pal3/records.js');
const { Pal3MerkleTree } = await lib('pal3/merkle.js');
const { encodeValue, decodeValue } = await lib('pal3/tlv.js');
const MiB = 1024 * 1024;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const bigFile = Buffer.alloc(40 * MiB, 0x5a);
const smallFile = Buffer.alloc(3 * 262144 - 100, 0x33);
const trees = new Map([[0, Pal3MerkleTree.fromBuffer(bigFile)], [1, Pal3MerkleTree.fromBuffer(smallFile)]]);
const files = [bigFile, smallFile];
function serverSession() {
  const idI = hsLib.generateHybridSigningIdentity({ edSeed: Buffer.alloc(32, 0x51), dsaSeed: Buffer.alloc(32, 0x52) });
  const idR = hsLib.generateHybridSigningIdentity({ edSeed: Buffer.alloc(32, 0x53), dsaSeed: Buffer.alloc(32, 0x54) });
  const init = new hsLib.HandshakeInitiator({ deviceCert: hsLib.issueDeviceCertificate({ identity: idI }), deviceKeys: idI });
  const resp = hsLib.processHelloAndCreateAccept(init.createHelloRecord(), { deviceCert: hsLib.issueDeviceCertificate({ identity: idR }), deviceKeys: idR });
  const fin = init.processAcceptAndCreateFinish(resp.acceptRecord);
  const done = resp.verifyFinish(fin.finishRecord);
  hsLib.verifyReadyRecord(fin.ctlProtector, done.readyRecord);
  const held = [];
  const client = new Pal3SessionMux({
    isInitiator: true, prk: fin.prk, exporterSecret: fin.exporterSecret, ctlProtector: fin.ctlProtector, peerCert: fin.peerCert,
    negotiatedCapabilities: fin.negotiatedCapabilities, pathKind: 'direct_udp', carrier: 'c2', autoRekey: false, sendWireRecord: async () => {},
  });
  const server = new Pal3SessionMux({
    isInitiator: false, prk: done.prk, exporterSecret: done.exporterSecret, ctlProtector: done.ctlProtector, peerCert: done.peerCert,
    negotiatedCapabilities: done.negotiatedCapabilities, pathKind: 'direct_udp', carrier: 'c2', allowUnauthenticated: true, autoRekey: false,
    getContentTree: async (contentId) => { const i = Number(contentId.slice(0, 1)); return { tree: trees.get(i), readBlock: (b) => files[i].subarray(b * 262144, (b + 1) * 262144) }; },
    sendWireRecord: async (ch, wire) => { held.push({ ch, wire: Buffer.from(wire) }); },
  });
  const settle = async () => { let n = -1; while (n !== held.length) { n = held.length; await sleep(60); } };
  const seen = { dataBytes: 0, ended: false, error: null };
  const drain = () => {
    for (const r of held.splice(0)) {
      const frame = client.channels.get(r.ch).open(r.wire);
      if (frame.type === RECORD_TYPE.DATA) seen.dataBytes += frame.payload.length;
      else if (frame.type === RECORD_TYPE.END) seen.ended = true;
      else if (frame.type === RECORD_TYPE.ERROR) seen.error = decodeValue(frame.payload);
    }
  };
  const send = async (type, streamId, obj) => {
    const wire = client.channels.get(CHANNEL_ID.BULK_0).seal({ type, streamId, payload: encodeValue(obj) });
    server.receiveWireRecord(CHANNEL_ID.BULK_0, wire).catch(() => {});
    await sleep(20);
  };
  return { settle, drain, seen, send };
}
const read = (fileIndex, startBlock, endBlock, credit) => ({ op: 'file.read', res: `root:${fileIndex}x`, body: { contentId: `${fileIndex}x`, startBlock, endBlock }, credit });

const creditScenarios = [
  ['oneMebibyte', 'The requester grants 1 MiB: the responder stops after 1 MiB', 1 * MiB, []],
  ['sixteenMebibytes', 'A grant of exactly 16 MiB', 16 * MiB, []],
  ['sixtyFourMebibytesIsClampedToSixteen', 'A grant of 64 MiB is clamped to 16 MiB', 64 * MiB, []],
  ['noCreditSendsNothing', 'A grant of 0: nothing is sent until CREDIT arrives', 0, []],
  ['negativeCreditIsZero', 'A negative grant is clamped to 0', -5, []],
  ['creditMessagesAddCredit', 'A grant of 1 MiB, then CREDIT of 1 MiB and of 2 MiB', 1 * MiB, [1 * MiB, 2 * MiB]],
  ['aCreditMessageIsClampedToSixteen', 'A grant of 0, then CREDIT of 1 GiB: at most 16 MiB are sent', 0, [1024 * MiB]],
  ['creditBelowOneBlock', 'A grant of 100000 bytes is less than one 256 KiB block: a block is sent whole, so nothing is sent', 100000, []],
  ['creditOfOneAndAHalfBlocks', 'A grant of 393216 bytes: one whole block is sent', 393216, []],
  ['creditBelowOneBlockThenTopUp', 'A grant of 100000 bytes, then CREDIT of 162144 bytes: together exactly one block', 100000, [162144]],
];
const credit = [];
for (const [name, description, requestCredit, grants] of creditScenarios) {
  const S = serverSession();
  await S.send(RECORD_TYPE.REQ, 1, read(0, 0, 159, requestCredit));
  await S.settle(); S.drain();
  const sentAfter = [S.seen.dataBytes];
  for (const g of grants) {
    await S.send(RECORD_TYPE.CREDIT, 1, { credit: g });
    await S.settle(); S.drain();
    sentAfter.push(S.seen.dataBytes);
  }
  credit.push({ name, description, fileBytes: bigFile.length, requestCredit, creditMessages: grants, sentBytesAfterEachStep: sentAfter });
}
const rangeCases = [
  ['wholeFile', 'Blocks 0 to 2 of a 3-block file', 0, 2, 'accepted'],
  ['lastBlockOnly', 'Block 2 only', 2, 2, 'accepted'],
  ['endBeyondTheLastBlock', 'endBlock 3 in a 3-block file', 0, 3, 'E_PAL3_INVALID_RANGE'],
  ['startBeyondTheLastBlock', 'startBlock 3', 3, 3, 'E_PAL3_INVALID_RANGE'],
  ['endBeforeStart', 'endBlock 1 before startBlock 2', 2, 1, 'E_PAL3_INVALID_RANGE'],
  ['negativeStart', 'startBlock -1', -1, 1, 'E_PAL3_INVALID_RANGE'],
  ['fractionalStart', 'startBlock 0.5', 0.5, 1, 'E_PAL3_INVALID_RANGE'],
  ['textStart', 'startBlock "0"', '0', 1, 'E_PAL3_INVALID_RANGE'],
];
const ranges = [];
for (const [name, description, startBlock, endBlock, expectedDecision] of rangeCases) {
  const S = serverSession();
  await S.send(RECORD_TYPE.REQ, 1, read(1, startBlock, endBlock, 1 * MiB));
  await S.settle(); S.drain();
  const got = S.seen.error ? (/^(E_[A-Z0-9_]+)/.exec(String(S.seen.error.error ?? S.seen.error.message ?? ''))?.[1] ?? 'error') : (S.seen.ended ? 'accepted' : 'none');
  if (got !== expectedDecision) throw new Error(`reference answered ${got}, not ${expectedDecision}: ${name}`);
  ranges.push({ name, description, fileBytes: smallFile.length, blockCount: 3, startBlock, endBlock, expected: got === 'accepted' ? { decision: 'accepted', dataBytes: S.seen.dataBytes } : { error: got, dataBytes: S.seen.dataBytes } });
}

const doc = {
  specVersion: '0.6.22',
  section: '11.2',
  description: 'Hardening invariants that are decisions on bytes: pal:// URI validation (item 5), rejection of low-order X25519 public keys (item 1), the FIPS 203 modulus check of ML-KEM encapsulation keys (item 7) and datagram reassembly (item 3).',
  generatedBy: 'bin/generate-v0.6-hardening-vectors.mjs',
  limits: { maxPeerCreditBytes: 16 * MiB, dataRecordBytes: MAX_DATA_PAYLOAD, blockBytes: 262144, maxPayloadBytes: MAX, maxFragmentsPerMessage: 64, perSourceMessages: 16, globalMessages: 128, expiryMs: 5000 },
  uri,
  x25519,
  mlkem,
  reassembly,
  credit,
  ranges,
};
writeFileSync(out, `${JSON.stringify(doc, null, 2)}\n`);
console.log(`wrote ${out}: ${uri.length} uri, ${x25519.keys.length} x25519, ${kemCases.length} mlkem, ${reassembly.length} reassembly scenarios, ${credit.length} credit, ${ranges.length} ranges`);
