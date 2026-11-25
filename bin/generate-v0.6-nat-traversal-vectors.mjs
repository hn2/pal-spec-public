// Generates test-vectors/v3/pal3-v0.6-nat-traversal-vectors.json (spec section 4.1: N1 global unicast, N3 observations, N6 relay reservation, buddy.intro start times).
// Run: node bin/generate-v0.6-nat-traversal-vectors.mjs --pal-core <path to the hn2/pal-core checkout> [--out <file>]
// The relay reservation body comes from the reference and is signed in the deterministic FIPS 204 mode (bin/vector-signing.mjs); the reference decides every case.
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadReference, deterministicSigner } from './vector-signing.mjs';

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : null; };
const palCore = opt('--pal-core');
if (!palCore) { console.error('usage: node bin/generate-v0.6-nat-traversal-vectors.mjs --pal-core <path> [--out <file>]'); process.exit(2); }
const out = opt('--out') || resolve(dirname(fileURLToPath(import.meta.url)), '../test-vectors/v3/pal3-v0.6-nat-traversal-vectors.json');
const ref = await loadReference(palCore);
const signer = deterministicSigner(ref);
const rv = await ref.lib('pal3/rendezvous.js');
const mp = await ref.lib('pal3/multipath.js');
const hs = await ref.lib('pal3/handshake.js');
const { encodeValue, decodeValue } = await ref.lib('pal3/tlv.js');

const hex = (b) => Buffer.from(b).toString('hex');
const code = (fn) => { try { return { value: fn() }; } catch (err) { return { error: /^(E_[A-Z0-9_]+)/.exec(err.message)?.[1] ?? err.message }; } };

// N1 and N3: which addresses count as global unicast.
const addresses = [
  ['ipv4Public', '8.8.8.8'], ['ipv4PublicHighOctet', '223.255.255.254'], ['ipv4This', '0.1.2.3'], ['ipv4Private10', '10.1.2.3'], ['ipv4Loopback', '127.0.0.1'],
  ['ipv4LinkLocal', '169.254.1.1'], ['ipv4Private172Low', '172.16.0.1'], ['ipv4Private172High', '172.31.255.255'], ['ipv4Public172Outside', '172.32.0.1'],
  ['ipv4Private192', '192.168.1.1'], ['ipv4CgnatLow', '100.64.0.1'], ['ipv4CgnatHigh', '100.127.255.255'], ['ipv4Public100Outside', '100.128.0.1'],
  ['ipv4Multicast', '224.0.0.1'], ['ipv4Reserved', '240.0.0.1'], ['ipv4Broadcast', '255.255.255.255'], ['ipv4OctetAbove255', '999.1.1.1'],
  ['ipv4MappedPublic', '::ffff:8.8.8.8'], ['ipv4MappedPrivate', '::ffff:10.0.0.1'],
  ['ipv6Global', '2606:4700:4700::1111'], ['ipv6GlobalLowEdge', '2000::1'], ['ipv6GlobalHighEdge', '3fff:1000::1'],
  ['ipv6Unspecified', '::'], ['ipv6Loopback', '::1'], ['ipv6LinkLocal', 'fe80::1'], ['ipv6UniqueLocal', 'fd00::1'], ['ipv6Multicast', 'ff02::1'],
  ['ipv6Documentation2001Db8', '2001:db8::1'], ['ipv6Documentation3fff', '3fff::1'], ['ipv6DocumentationLastOf3fff', '3fff:0fff:ffff::1'],
  ['ipv6OutsideTwoThousandSlash3', '4000::1'], ['ipv6BracketedGlobal', '[2606:4700:4700::1111]'], ['notAnAddress', 'example.org'],
].map(([name, ip]) => ({ name, ip, globalUnicast: rv.isGlobalUnicastIp(ip) }));

// N3: the observation table.
const id = (n) => n.toString(16).padStart(2, '0').repeat(32);
const rec = (atMs, observer, observerIp, observedIp, observedPort) => ({ atMs, observer, observerIp, observedIp, observedPort });
function scenario(name, description, steps, options = {}) {
  const tracker = new rv.ReflexiveAddressTracker(options);
  const recorded = steps.map((s) => {
    const r = tracker.recordObservation({ observerIdentityEdPk: id(s.observer), observerRemoteIp: s.observerIp, observedIp: s.observedIp, observedPort: s.observedPort, nowMs: s.atMs });
    const sum = r.accepted ? r.summary : null;
    return { ...s, expected: r.accepted ? { accepted: true, quorumMet: Boolean(sum.quorumMet), verifiedIp: sum.verifiedIp ?? null, verifiedPort: sum.verifiedPort ?? null, observers: tracker.observations.size } : { accepted: false, reason: r.reason } };
  });
  return { name, description, options, steps: recorded };
}
const T0 = 1763985600000;
const PUBLIC = '8.8.8.8';
const observations = [
  scenario('singleObservationIsNeverConfirmed', 'One observer is not a quorum', [rec(T0, 1, '45.33.1.5', PUBLIC, 40000)]),
  scenario('twoObserversOnDifferentPrefixesAgree', 'Two observers on different /24 prefixes that report the same address confirm it', [
    rec(T0, 1, '45.33.1.5', PUBLIC, 40000), rec(T0 + 1, 2, '45.34.1.5', PUBLIC, 40000)]),
  scenario('twoObserversThatDisagreeConfirmNothing', 'Different reported addresses', [rec(T0, 1, '45.33.1.5', PUBLIC, 40000), rec(T0 + 1, 2, '45.34.1.5', '8.8.4.4', 40000)]),
  scenario('oneObserverPerIdentity', 'The same identity reports twice from two places: it still counts once', [
    rec(T0, 1, '45.33.1.5', PUBLIC, 40000), rec(T0 + 1, 1, '45.34.1.5', PUBLIC, 40000)]),
  scenario('oneObserverPerSourcePrefix', 'Two identities on one /24: only the later one is kept', [
    rec(T0, 1, '45.33.1.5', PUBLIC, 40000), rec(T0 + 1, 2, '45.33.1.77', PUBLIC, 40000)]),
  scenario('observationsExpireAfterTenMinutes', 'The first observation is gone after 10 minutes, so the second is alone', [
    rec(T0, 1, '45.33.1.5', PUBLIC, 40000), rec(T0 + 600000, 2, '45.34.1.5', PUBLIC, 40000)]),
  scenario('observationJustBeforeExpiryStillCounts', '599999 ms', [rec(T0, 1, '45.33.1.5', PUBLIC, 40000), rec(T0 + 599999, 2, '45.34.1.5', PUBLIC, 40000)]),
  scenario('privateAddressIsNotAccepted', 'A reported private address', [rec(T0, 1, '45.33.1.5', '192.168.1.5', 40000)]),
  scenario('documentationIpv6IsNotAccepted', 'A reported 3fff::/20 address', [rec(T0, 1, '45.33.1.5', '3fff::1', 40000)]),
  scenario('portZeroAndAbove65535AreNotAccepted', 'Ports outside 1..65535', [rec(T0, 1, '45.33.1.5', PUBLIC, 0), rec(T0 + 1, 2, '45.34.1.5', PUBLIC, 65536), rec(T0 + 2, 3, '45.36.1.5', PUBLIC, 65535)]),
  scenario('portsAreNotConfirmedByAnIpQuorumAlone', 'Same IP, different ports (symmetric NAT): the IP is confirmed, the port is the last one seen', [
    rec(T0, 1, '45.33.1.5', PUBLIC, 40000), rec(T0 + 1, 2, '45.34.1.5', PUBLIC, 40002)]),
  scenario('tableHoldsAtMostSixtyFourObservers', 'The 65th observer on a new prefix drops the oldest', Array.from({ length: 65 }, (_, i) => rec(T0 + i, i + 1, `${20 + Math.floor(i / 200)}.${i}.0.1`, PUBLIC, 40000))),
];

// buddy.intro start times.
const punch = [[40, 40], [100, 300], [300, 100], [2000, 2000], [5000, 100], [0, 0], [10, 2000]].map(([ri, rt]) => {
  const p = mp.createBuddyHolePunchPlan({ buddyPk: null, initiatorPk: id(1), initiatorEndpoint: { host: '203.0.113.1', port: 1 }, targetPk: id(2), targetEndpoint: { host: '203.0.113.2', port: 2 }, initiatorRttMs: ri, targetRttMs: rt, nowMs: T0 });
  return { initiatorRttMs: ri, targetRttMs: rt, initiatorStartInMs: p.forInitiator.startInMs, targetStartInMs: p.forTarget.startInMs };
});
const punchWithoutRtt = (() => {
  const p = mp.createBuddyHolePunchPlan({ buddyPk: null, initiatorPk: id(1), initiatorEndpoint: { host: '203.0.113.1', port: 1 }, targetPk: id(2), targetEndpoint: { host: '203.0.113.2', port: 2 }, nowMs: T0 });
  return { hasStartInMs: 'startInMs' in p.forInitiator, punchAtMs: p.punchAtMs - T0 };
})();

// N6: relay reservation.
const mk = (n) => hs.generateHybridSigningIdentity({ edSeed: Buffer.alloc(32, n), dsaSeed: Buffer.alloc(32, n + 1) });
const relay = mk(0x61); const client = mk(0x63); const thief = mk(0x65);
const pin = (i) => hs.pal3IdentityDigest(i.edPublicKey, i.dsaPublicKey);
const SESSION = Buffer.alloc(16, 0x5e);
const NOW = T0;
function token({ sessionId = SESSION, issuedAtMs = NOW - 1000, durationMs = 15 * 60 * 1000, maxBytes = 256 * 1024 * 1024, maxBandwidthBps = 2 * 1024 * 1024, clientId = client, signWith = relay } = {}) {
  const body = encodeValue({
    v: 2, sessionId: Buffer.from(sessionId), relayEdPk: Buffer.from(relay.edPublicKey), relayDsaPk: Buffer.from(relay.dsaPublicKey), clientDigest: pin(clientId),
    issuedAtMs: BigInt(issuedAtMs), expiresAtMs: BigInt(issuedAtMs + durationMs), maxBytes: BigInt(maxBytes), maxBandwidthBps: Number(maxBandwidthBps),
  });
  const { sigEd25519, sigMldsa65 } = signer({ domain: 'pal3-relay-v2', dsaContext: rv.DSA_CONTEXT_RELAY, body, edSecretKey: signWith.edSecretKey, dsaSecretKey: signWith.dsaSecretKey });
  return { body, sigEd25519, sigMldsa65 };
}
const encoded = (t) => encodeValue({ body: t.body, sigEd25519: t.sigEd25519, sigMldsa65: t.sigMldsa65 });
const flip = (b) => { const c = Buffer.from(b); c[c.length - 1] ^= 1; return c; };
const reservationCases = [
  ['valid', encoded(token()), {}],
  ['wrongPresentingClient', encoded(token()), { presenter: thief }],
  ['wrongRelayPin', encoded(token()), { expectedRelay: thief }],
  ['wrongSession', encoded(token()), { sessionId: Buffer.alloc(16, 1) }],
  ['sessionNotGiven', encoded(token()), { sessionId: null }],
  ['sessionOfWrongLength', encoded(token()), { sessionId: Buffer.alloc(8, 0x5e) }],
  ['expired', encoded(token({ issuedAtMs: NOW - 20 * 60 * 1000 })), {}],
  ['expiresExactlyNow', encoded(token({ issuedAtMs: NOW - 900000 })), {}],
  ['issuedMoreThanFiveMinutesAhead', encoded(token({ issuedAtMs: NOW + 5 * 60 * 1000 + 1 })), {}],
  ['issuedExactlyFiveMinutesAhead', encoded(token({ issuedAtMs: NOW + 5 * 60 * 1000 })), {}],
  ['bodyChangedAfterSigning', encodeValue({ ...decodeValue(encoded(token())), body: token({ maxBytes: 2 ** 30 }).body }), {}],
  ['versionChangedAfterSigning', encodeValue({ ...decodeValue(encoded(token())), body: flip(token().body) }), {}],
  ['edSignatureChanged', encodeValue({ ...decodeValue(encoded(token())), sigEd25519: flip(token().sigEd25519) }), {}],
  ['mlDsaSignatureChanged', encodeValue({ ...decodeValue(encoded(token())), sigMldsa65: flip(token().sigMldsa65) }), {}],
  ['signedByAnotherKeyButNamingTheRelay', encoded(token({ signWith: thief })), {}],
].map(([name, tokenBytes, over]) => {
  const opts = { expectedRelay: relay, presenter: client, sessionId: SESSION, now: NOW, ...over };
  const r = code(() => rv.verifyRelayReservation(tokenBytes, opts));
  return {
    name, tokenHex: hex(tokenBytes), nowMs: NOW,
    expectedRelayIdentity: opts.expectedRelay === relay ? 'relay' : 'thief', presenter: opts.presenter === client ? 'client' : 'thief',
    sessionIdHex: opts.sessionId ? hex(opts.sessionId) : null, expected: r.error ? { error: r.error } : { accepted: true },
  };
});
const bodyOfValid = rv.verifyRelayReservation(encoded(token({ maxBytes: 1000, maxBandwidthBps: 600 })), { expectedRelay: relay, presenter: client, sessionId: SESSION, now: NOW });
const meterSteps = [[0, 500], [0, 500], [0, 1], [1000, 100], [1000, 100], [1000, 500], [20 * 60 * 1000, 1]];
let clockNow = NOW;
const meter = new rv.RelayQuotaMeter(bodyOfValid, { now: () => clockNow });
const quota = meterSteps.map(([dt, bytes]) => {
  clockNow = NOW + dt;
  const r = code(() => meter.tryConsume(bytes));
  return { atMs: dt, bytes, expected: r.error ? { error: r.error } : { forwarded: r.value } };
});

const doc = {
  specVersion: '0.6.22',
  section: '4.1',
  description: 'N1 global unicast classification, N3 observation table, buddy.intro start times (clock-skew-free punch start), N6 hybrid-signed relay reservation (pinned relay, bound client and session, quota and rate).',
  generatedBy: 'bin/generate-v0.6-nat-traversal-vectors.mjs',
  limits: { observerTtlMs: 600000, maxObservers: 64, punchMarginMs: 50, rttClampMs: 2000, clockSkewMs: 300000, reservationDefaults: { durationMs: 900000, maxBytes: 268435456, maxBandwidthBps: 2097152 } },
  addresses,
  observations,
  punchPlans: punch,
  punchWithoutRtt,
  relay: {
    identities: { relayPin: hex(pin(relay)), clientPin: hex(pin(client)), thiefPin: hex(pin(thief)), relayEdPk: hex(relay.edPublicKey), relayDsaPk: hex(relay.dsaPublicKey), clientEdPk: hex(client.edPublicKey), clientDsaPk: hex(client.dsaPublicKey), thiefEdPk: hex(thief.edPublicKey), thiefDsaPk: hex(thief.dsaPublicKey) },
    domain: 'pal3-relay-v2', dsaContext: rv.DSA_CONTEXT_RELAY,
    reservations: reservationCases,
    quota: { maxBytes: 1000, maxBandwidthBps: 600, steps: quota },
  },
};
writeFileSync(out, `${JSON.stringify(doc, null, 2)}\n`);
console.log(`wrote ${out}: ${addresses.length} addresses, ${observations.length} observation scenarios, ${punch.length} punch plans, ${reservationCases.length} reservation cases`);
