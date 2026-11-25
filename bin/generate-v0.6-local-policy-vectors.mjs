// Generates test-vectors/v3/pal3-v0.6-local-policy-vectors.json (spec sections 12.3 and 12.4) with the reference implementation.
// Run: node bin/generate-v0.6-local-policy-vectors.mjs --pal-core <path to the hn2/pal-core checkout> [--out <file>]
// 12.3: decisions of the extension source linter (a linter, not a boundary). 12.4: decisions of the local swarm limits, which refuse only with E_BUSY.
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : null; };
const palCore = opt('--pal-core');
if (!palCore) { console.error('usage: node bin/generate-v0.6-local-policy-vectors.mjs --pal-core <path> [--out <file>]'); process.exit(2); }
const out = opt('--out') || resolve(dirname(fileURLToPath(import.meta.url)), '../test-vectors/v3/pal3-v0.6-local-policy-vectors.json');
const lib = (file) => import(pathToFileURL(resolve(palCore, 'packages/protocol/lib', file)).href);

const sandbox = await lib('pal3/sandbox.js');
const swarm = await lib('pal3/swarmAccess.js');

const sources = [
  ['plainFunction', 'export function add(a, b) { return a + b; }'],
  ['importOfAnAllowedModule', "import { createHash } from 'node:crypto';\nexport const h = (b) => createHash('sha384').update(b).digest();"],
  ['directEval', 'export const run = (s) => eval(s);'],
  ['indirectEval', 'export const run = (s) => (0, eval)(s);'],
  ['functionConstructor', "export const f = new Function('return 1');"],
  ['constructorChain', "export const f = (() => {}).constructor.constructor('return 1');"],
  ['staticImportOfChildProcess', "import { exec } from 'node:child_process';\nexport const x = exec;"],
  ['requireOfVm', "const vm = require('vm');\nexport const r = vm;"],
  ['importOfWorkerThreads', "import { Worker } from 'worker_threads';\nexport const W = Worker;"],
  ['computedImport', "const name = 'child' + '_process';\nexport const m = import(name);"],
  ['computedRequire', "const name = 'fs';\nconst m = require(name);"],
  ['aliasedRequire', "const r = require;\nexport const x = r('node:vm');"],
  ['moduleLoaderInternals', "import { createRequire } from 'node:module';\nexport const r = createRequire(import.meta.url);"],
  ['processBinding', "export const b = process.binding('fs');"],
  ['computedProcessAccess', "export const p = process['dlopen'];"],
  ['computedGlobalAccess', "export const g = globalThis['process'];"],
  ['webAssembly', 'export const w = WebAssembly;'],
];
const analyzer = sources.map(([name, source]) => {
  const r = sandbox.analyzeExtensionSource(source);
  return { name, source, safe: r.safe, isSecurityBoundary: r.isSecurityBoundary, criticalTypes: [...new Set(r.blocked.map((f) => f.type))].sort() };
});
const bundled = sandbox.analyzeExtensionSource("import { exec } from 'node:child_process';\nexport const x = exec;", { bundled: true, permissions: ['exec:git'] });
const analyzerBundled = { source: "import { exec } from 'node:child_process';\nexport const x = exec;", manifest: { bundled: true, permissions: ['exec:git'] }, safe: bundled.safe };
const wildcard = [
  ['exact', ['fs:read'], 'fs:read'],
  ['wildcardCoversOrdinary', ['*'], 'fs:read'],
  ['wildcardNeverImpliesExec', ['*'], 'exec:git'],
  ['wildcardNeverImpliesNative', ['*'], 'native:sodium'],
  ['namedExecIsGranted', ['exec:git'], 'exec:git'],
  ['notGranted', ['fs:read'], 'fs:write'],
].map(([name, granted, required]) => ({ name, granted, required, allowed: sandbox.matchExtensionPermission(granted, required) }));

// 12.4: local limits.
const SHARE_A = 'a'.repeat(96);
const SHARE_B = 'b'.repeat(96);
const PEER_1 = '1'.repeat(64);
const PEER_2 = '2'.repeat(64);
const P = 256 * 1024;
const clock = { t: Date.UTC(2026, 10, 24, 12, 0, 0) };
function scenario(name, description, settings, steps, startMs = Date.UTC(2026, 10, 24, 12, 0, 0)) {
  clock.t = startMs;
  const limits = new swarm.SwarmLimits({ settings, now: () => clock.t });
  const leases = [];
  const recorded = steps.map((s) => {
    clock.t = startMs + s.atMs;
    if (s.device) limits.setDevice(s.device);
    const step = { ...s };
    const serving = limits.shouldServe(s.shareId ?? null);
    if (s.op === 'release') { leases[s.lease].release(s.sentBytes); return { ...step, expected: { released: true } }; }
    let outcome;
    try {
      const lease = limits.acquire(s.peer, s.shareId, s.bytes);
      leases.push(lease);
      if (s.release !== undefined) { lease.release(s.release); }
      outcome = { ok: true };
    } catch (err) {
      outcome = { ok: false, error: err.code, text: err.message, retryAfterMs: err.retryAfterMs };
    }
    return { ...step, expected: { serving, ...outcome } };
  });
  return { name, description, startMs, settings, steps: recorded };
}
const acq = (atMs, peer, shareId, bytes = P, extra = {}) => ({ atMs, op: 'acquire', peer, shareId, bytes, ...extra });
const scenarios = [
  scenario('defaultsServe', 'With the defaults a piece is served', {}, [acq(0, PEER_1, SHARE_A, P, { release: P })]),
  scenario('privacyModeServesNothing', 'Privacy mode refuses everything with E_BUSY and does not announce', { privacy: true }, [acq(0, PEER_1, SHARE_A)]),
  scenario('doNotShareRefusesOnlyThatShare', 'A per-share "do not share" refuses that share only', { doNotShare: [SHARE_A] }, [acq(0, PEER_1, SHARE_A), acq(1, PEER_1, SHARE_B, P, { release: P })]),
  scenario('uploadSlotsAreConcurrentLimits', 'One slot: the second concurrent upload is refused until the first is released', { uploadSlots: 1 }, [
    acq(0, PEER_1, SHARE_A), acq(1, PEER_2, SHARE_A), { atMs: 2, op: 'release', lease: 0, sentBytes: P }, acq(3, PEER_2, SHARE_A, P, { release: P })]),
  scenario('zeroSlotsMeansOff', 'uploadSlots 0 serves nothing', { uploadSlots: 0 }, [acq(0, PEER_1, SHARE_A)]),
  scenario('perPeerRateAllowsABurstThenRefuses', 'Per-peer rate of P/4 per second: a burst of 4 pieces, then a refusal; another peer is not affected', { perPeerBps: P / 4 }, [
    ...[0, 1, 2, 3].map((i) => acq(i, PEER_1, SHARE_A, P, { release: P })), acq(4, PEER_1, SHARE_A), acq(5, PEER_2, SHARE_A, P, { release: P })]),
  scenario('overallRateAllowsABurstThenRefuses', 'Overall rate of 2 pieces per second: a burst of 8 pieces (4 s), then a refusal, and one piece again after 1 s', { uploadBps: 2 * P }, [
    ...Array.from({ length: 8 }, (_, i) => acq(i, `${i}`.repeat(64).slice(0, 64), SHARE_A, P, { release: P })), acq(9, PEER_1, SHARE_A), acq(1100, PEER_1, SHARE_A, P, { release: P })]),
  scenario('meteredNetworkIsOffByDefault', 'On a metered network nothing is served unless allowed', {}, [
    { ...acq(0, PEER_1, SHARE_A), device: { metered: true } }, { ...acq(1, PEER_1, SHARE_A), device: { metered: false } }]),
  scenario('meteredDailyCapResetsAtTheNextUtcDay', 'A daily cap of 1000 bytes stops serving on a metered network and resets at the next UTC day', { meteredServe: true, meteredDailyBytes: 1000 }, [
    { ...acq(0, PEER_1, SHARE_A, 800, { release: 800 }), device: { metered: true } }, acq(1, PEER_1, SHARE_A, 300, { release: 300 }), acq(2, PEER_1, SHARE_A, 1),
    acq(24 * 3600 * 1000, PEER_1, SHARE_A, 500, { release: 500 })]),
  scenario('lowBatteryPausesUnlessCharging', 'Below 20 percent battery nothing is served unless the device is charging', {}, [
    { ...acq(0, PEER_1, SHARE_A), device: { batteryPct: 10, charging: false } }, { ...acq(1, PEER_1, SHARE_A, P, { release: P }), device: { batteryPct: 10, charging: true } }]),
  scenario('onlyWhileChargingPauses', 'onlyWhileCharging refuses while on battery', { onlyWhileCharging: true }, [
    { ...acq(0, PEER_1, SHARE_A), device: { charging: false } }, { ...acq(1, PEER_1, SHARE_A, P, { release: P }), device: { charging: true } }]),
  scenario('offlineDeviceServesNothing', 'An offline device refuses', {}, [{ ...acq(0, PEER_1, SHARE_A), device: { online: false } }]),
];

const doc = {
  specVersion: '0.6.22',
  section: '12.3, 12.4',
  description: 'Local policy: the extension source linter decisions (12.3, a linter and not a security boundary) and the local swarm limits (12.4), whose refusals are always E_BUSY with the text "E_BUSY: retry after <n> ms" and never carry a reason.',
  generatedBy: 'bin/generate-v0.6-local-policy-vectors.mjs',
  analyzer,
  analyzerBundled,
  permissions: wildcard,
  limits: { pieceBytes: P, shareA: SHARE_A, shareB: SHARE_B, peer1: PEER_1, peer2: PEER_2, busyMinMs: swarm.BUSY_MIN_MS, busyMaxMs: swarm.BUSY_MAX_MS },
  scenarios,
};
writeFileSync(out, `${JSON.stringify(doc, null, 2)}\n`);
console.log(`wrote ${out}: ${analyzer.length} sources, ${wildcard.length} permissions, ${scenarios.length} scenarios`);
