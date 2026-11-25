// Generates test-vectors/v3/pal3-v0.6-registry-vectors.json (spec appendix A.6 and sections 5.1, 12.5 item 4) with the reference implementation.
// Run: node bin/generate-v0.6-registry-vectors.mjs --pal-core <path to the hn2/pal-core checkout> [--out <file>]
// Nothing random reaches the file: the HELLO of each case is built by the reference, only its version_list, suite_list and capabilities are recorded.
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : null; };
const palCore = opt('--pal-core');
if (!palCore) { console.error('usage: node bin/generate-v0.6-registry-vectors.mjs --pal-core <path> [--out <file>]'); process.exit(2); }
const out = opt('--out') || resolve(dirname(fileURLToPath(import.meta.url)), '../test-vectors/v3/pal3-v0.6-registry-vectors.json');
const lib = (file) => import(pathToFileURL(resolve(palCore, 'packages/protocol/lib', file)).href);

const hs = await lib('pal3/handshake.js');
const { PAL3_VERSION, packHandshakeRecord, unpackHandshakeRecord, RECORD_TYPE } = await lib('pal3/records.js');
const { encodeTlv, decodeTlv } = await lib('pal3/tlv.js');

const hex = (b) => Buffer.from(b).toString('hex');
const code = (fn) => { try { return { value: fn() }; } catch (err) { return { error: /^(E_[A-Z0-9_]+)/.exec(err.message)?.[1] ?? err.message }; } };
const idI = hs.generateHybridSigningIdentity({ edSeed: Buffer.alloc(32, 0x41), dsaSeed: Buffer.alloc(32, 0x42) });
const idR = hs.generateHybridSigningIdentity({ edSeed: Buffer.alloc(32, 0x43), dsaSeed: Buffer.alloc(32, 0x44) });
const certI = hs.issueDeviceCertificate({ identity: idI });
const certR = hs.issueDeviceCertificate({ identity: idR });

const helloWith = ({ capabilities, versionListHex, suiteListHex }) => {
  const init = new hs.HandshakeInitiator({ deviceCert: certI, deviceKeys: idI, ...(capabilities ? { capabilities } : {}) });
  const wire = init.createHelloRecord();
  if (!versionListHex && !suiteListHex) return wire;
  const fields = decodeTlv(unpackHandshakeRecord(wire).payload);
  const entries = [...fields.entries()].map(([tag, value]) => [tag, tag === 1 && versionListHex !== undefined ? Buffer.from(versionListHex, 'hex') : tag === 2 && suiteListHex !== undefined ? Buffer.from(suiteListHex, 'hex') : value]);
  return packHandshakeRecord(RECORD_TYPE.HELLO, encodeTlv(entries));
};
const respond = (wire, responderSuites) => {
  const r = code(() => hs.processHelloAndCreateAccept(wire, { deviceCert: certR, deviceKeys: idR, suites: responderSuites }));
  if (r.error) return { error: r.error };
  const accept = decodeTlv(unpackHandshakeRecord(r.value.acceptRecord).payload);
  return { selectedVersion: accept.get(1).readUInt16BE(0), selectedSuite: accept.get(2).readUInt16BE(0) };
};

const selection = [];
function select(name, description, { versionListHex, suiteListHex, responderSuites = null }) {
  const result = respond(helloWith({ versionListHex, suiteListHex }), responderSuites);
  selection.push({ name, description, versionListHex, suiteListHex, responderSuites, registeredSuites: [1], expected: result });
}
select('versionThreeSuiteOne', 'The one registered version and suite', { versionListHex: '0003', suiteListHex: '0001' });
select('versionListOffersAnOldAndTheCurrentVersion', 'A future-proof initiator offers 0x0002 and 0x0003', { versionListHex: '00020003', suiteListHex: '0001' });
select('suiteListPrefersAnUnregisteredSuite', 'Preference order: the unregistered 0x0003 is skipped, the first registered suite is taken', { versionListHex: '0003', suiteListHex: '00030001' });
select('suiteListWithOnlyUnregisteredSuites', 'No offered suite is registered: abort with the one code of 12.5 item 4', { versionListHex: '0003', suiteListHex: '00020003' });
select('reservedSuiteZero', 'Suite 0x0000 is reserved and never selected', { versionListHex: '0003', suiteListHex: '0000' });
select('versionListWithoutThree', 'No supported version', { versionListHex: '0002', suiteListHex: '0001' });
select('responderAcceptsOnlySuiteOne', 'The responder configuration narrows the choice to suite 0x0001', { versionListHex: '0003', suiteListHex: '0001', responderSuites: [1] });
select('versionListOddLength', 'version_list of 3 bytes is malformed', { versionListHex: '000300', suiteListHex: '0001' });
select('suiteListEmpty', 'An empty suite_list is malformed', { versionListHex: '0003', suiteListHex: '' });

const capabilityCases = [
  ['sortedAndUniqueOnTheWire', 'Tokens are sorted bytewise and de-duplicated before they are sent', ['stream.v1', 'core.v1', 'grants.v1', 'core.v1']],
  ['defaultSetOfTheReference', 'The set a reference initiator advertises by default', undefined],
  ['optionalBulkPlaintextToken', 'The optional c2-bulk-plaintext-record token sorts among the others', ['c2-key-update', 'core.v1', 'c2-bulk-plaintext-record', 'swarm.v1']],
].map(([name, description, caps]) => {
  const wire = helloWith({ capabilities: caps });
  const field = decodeTlv(unpackHandshakeRecord(wire).payload).get(8);
  return { name, description, input: caps ?? null, capabilitiesHex: hex(field), capabilitiesAscii: field.toString('ascii') };
});
const intersections = [
  [['core.v1', 'stream.v1', 'grants.v1', 'c2-key-update', 'pad.v1'], ['core.v1', 'stream.v1', 'swarm.v1', 'pad.v1']],
  [['core.v1', 'c2-bulk-plaintext-record'], ['core.v1', 'c2-key-update']],
  [['core.v1'], []],
].map(([local, remote]) => ({ local, remote, expected: hs.intersectCapabilities(local, remote) }));

const registerAttempts = [
  ['suiteZero', { suiteId: 0, descriptor: { isPostQuantumHybrid: true, kemName: 'X25519+ML-KEM-768', sigName: 'Ed25519+ML-DSA-65' } }],
  ['classicalOnlySuite', { suiteId: 0x0100, descriptor: { isPostQuantumHybrid: false, kemName: 'X25519', sigName: 'Ed25519' } }],
  ['hybridKemWithClassicalSignature', { suiteId: 0x0101, descriptor: { isPostQuantumHybrid: true, kemName: 'X25519+ML-KEM-768', sigName: 'Ed25519' } }],
  ['suiteOneAgain', { suiteId: 1, descriptor: { isPostQuantumHybrid: true, kemName: 'X25519+ML-KEM-768', sigName: 'Ed25519+ML-DSA-65' } }],
].map(([name, a]) => {
  const r = code(() => hs.registerPal3CipherSuite(a.suiteId, a.descriptor));
  if (!r.error) throw new Error(`reference registered ${name}`);
  return { name, suiteId: a.suiteId, isPostQuantumHybrid: a.descriptor.isPostQuantumHybrid, kemName: a.descriptor.kemName, sigName: a.descriptor.sigName, expectedError: r.error };
});
const suite1 = hs.getPal3CipherSuite(1);

const doc = {
  specVersion: '0.6.20',
  section: 'A.6',
  description: 'Protocol version and suite registry: the HELLO version_list and suite_list decision (the single E_PAL3_DOWNGRADE of 12.5 item 4), capability token encoding and intersection, and the registration rules of cipher suites.',
  generatedBy: 'bin/generate-v0.6-registry-vectors.mjs',
  wireProtocolVersion: PAL3_VERSION,
  registry: { suite1: { id: 1, kem: suite1.kemName, signature: suite1.sigName, aead: suite1.aeadName, hash: suite1.hashName }, reservedIds: [0], unregisteredIds: [2, 3] },
  selection,
  capabilityEncoding: capabilityCases,
  capabilityIntersection: intersections,
  registrationRejected: registerAttempts,
};
writeFileSync(out, `${JSON.stringify(doc, null, 2)}\n`);
console.log(`wrote ${out}: ${selection.length} selection cases`);
