// Generates test-vectors/v3/pal3-v0.6-pex-vectors.json (spec section 14.3, and 8.4 peer exchange) with the reference implementation.
// Run: node bin/generate-v0.6-pex-vectors.mjs --pal-core <path to the hn2/pal-core checkout> [--out <file>]
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : null; };
const palCore = opt('--pal-core');
if (!palCore) { console.error('usage: node bin/generate-v0.6-pex-vectors.mjs --pal-core <path> [--out <file>]'); process.exit(2); }
const out = opt('--out') || resolve(dirname(fileURLToPath(import.meta.url)), '../test-vectors/v3/pal3-v0.6-pex-vectors.json');
const lib = (file) => import(pathToFileURL(resolve(palCore, 'packages/protocol/lib', file)).href);

const { Pal3PexTable } = await lib('pal3/swarm.js');
const { requestPexPeers, createPexRequestHandler, MAX_PEX_PEERS } = await lib('pal3/pexDialer.js');

const k = (n) => n.toString(16).padStart(2, '0').repeat(32);
const ROOT = 'ab'.repeat(48);
const REPORTER = k(0xa1);
const OTHER_REPORTER = k(0xa2);
const NOW = 1763985600000;

async function learn(name, description, { response, reporterPk = REPORTER, before = [] }) {
  const table = new Pal3PexTable({ now: () => NOW });
  for (const b of before) table.registerPeer(ROOT, { peerPk: b.peerPk }, { reporterPk: b.reporterPk });
  const mux = { peerCert: { identityEdPk: Buffer.from(reporterPk, 'hex') }, request: async () => response };
  const learned = await requestPexPeers({ mux, pex: table, rootHash: ROOT });
  const entries = table.getPeers(ROOT, { maxPeers: 4096 });
  return {
    name, description, rootHashHex: ROOT, reporterPk, before, response,
    expected: {
      learned: learned.map((e) => ({ peerPk: e.peerPk, verified: e.verified, reporter: e.reporter })),
      storedPeerPks: entries.map((e) => e.peerPk).sort(),
      storedFieldNames: [...new Set(entries.flatMap((e) => Object.keys(e)))].sort(),
    },
  };
}

const cases = [
  await learn('plainKeysAreLearned', 'Three entries with a public key only', { response: { peers: [{ peerPk: k(1) }, { peerPk: k(2) }, { peerPk: k(3) }] } }),
  await learn('addressFieldsAreIgnored', 'host and port in an entry are ignored and never stored', { response: { peers: [{ peerPk: k(1), host: '203.0.113.7', port: 52474 }, { peerPk: k(2), host: 'example.org', port: 1 }] } }),
  await learn('upperCaseKeyIsRegisteredLowerCase', 'The key is registered in lower case', { response: { peers: [{ peerPk: k(0xab).toUpperCase() }] } }),
  await learn('malformedEntriesAreSkipped', 'A short key, a non-hex key, a missing key and a non-object entry are skipped; the valid one is kept', {
    response: { peers: [{ peerPk: 'ab'.repeat(31) }, { peerPk: 'zz'.repeat(32) }, {}, null, { peerPk: k(5) }] } }),
  await learn('entriesBeyondTheThirtySecondAreNotRead', 'The 33rd entry is the reporter itself and would be verified if it were read; it is not read', { response: { peers: [...Array.from({ length: MAX_PEX_PEERS }, (_, i) => ({ peerPk: k(0x10 + i) })), { peerPk: REPORTER }] } }),
  await learn('responseThatIsNotAnArrayLearnsNothing', 'peers is an object', { response: { peers: { peerPk: k(1) } } }),
  await learn('reporterAnnouncingItselfIsVerified', 'An entry equal to the authenticated reporter is marked verified; third-party entries are not', { response: { peers: [{ peerPk: REPORTER }, { peerPk: k(7) }] } }),
  await learn('oneReporterCannotFillTheSwarm', 'At most 16 unverified entries per reporter', { response: { peers: Array.from({ length: 20 }, (_, i) => ({ peerPk: k(0x40 + i) })) } }),
  await learn('thirdPartyReportNeverOverwritesAKnownPeer', 'The peer is already known from another reporter and stays so', {
    response: { peers: [{ peerPk: k(9) }] }, reporterPk: OTHER_REPORTER, before: [{ peerPk: k(9), reporterPk: REPORTER }] }),
];

// The responder side: only keys leave, even when the table holds more.
const table = new Pal3PexTable({ now: () => NOW });
for (let i = 1; i <= 40; i++) table.registerPeer(ROOT, { peerPk: k(0x70 + i) }, { reporterPk: k(0x70 + i) });
const handler = createPexRequestHandler(table);
const answer = await handler({ operation: 'pex.exchange', body: { rootHash: ROOT } });
let invalid;
try { await handler({ operation: 'pex.exchange', body: { rootHash: 'abc' } }); invalid = 'accepted'; } catch (err) { invalid = /^(E_[A-Z0-9_]+)/.exec(err.message)?.[1]; }
const responder = {
  rootHashHex: ROOT, registered: 40, response: answer,
  expected: { peerCount: answer.peers.length, entryFieldNames: [...new Set(answer.peers.flatMap((e) => Object.keys(e)))], invalidRootHashError: invalid, otherOperation: await handler({ operation: 'ping', body: {} }) === undefined ? 'not handled' : 'handled' },
};

const doc = {
  specVersion: '0.6.22',
  section: '14.3',
  description: 'Peer exchange without addresses: what a receiver learns from a pex.exchange response and what a responder sends.',
  generatedBy: 'bin/generate-v0.6-pex-vectors.mjs',
  limits: { maxEntries: MAX_PEX_PEERS, maxUnverifiedPerReporter: 16, peerPkHexLength: 64, rootHashHexLength: 96 },
  receive: cases,
  respond: responder,
};
writeFileSync(out, `${JSON.stringify(doc, null, 2)}\n`);
console.log(`wrote ${out}: ${cases.length} receive cases`);
