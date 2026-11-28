// Generates test-vectors/v3/pal3-v0.6-transport-policy-vectors.json (spec sections 14.1, 14.2, 14.4 and 14.11).
// These sections are product behaviour: pal-core has no implementation to generate from. Each case records inputs and the expected decision, written from the
// specification text. validate.mjs checks them with a model written from the same text; a product replays the file against its own code.
// Run: node bin/generate-v0.6-transport-policy-vectors.mjs [--pal-core <ignored>] [--out <file>]
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : null; };
const out = opt('--out') || resolve(dirname(fileURLToPath(import.meta.url)), '../test-vectors/v3/pal3-v0.6-transport-policy-vectors.json');

const path = (name, description, input, expected) => ({ name, description, input, expected });
const D = 'direct';
const R = 'relayed';
const U = 'E_PAL3_UNREACHABLE';

// 14.1: which path carries the session. Methods are tried in the order given; "ok" says whether the method opens a path.
const pathPolicy = [
  path('lanWorksNoRelayNeeded', 'The local network opens a path: direct, the NAT probes are not tried', { methods: [{ name: 'lan', ok: true }, { name: 'natProbe', ok: true }], relayOperatorEnabled: true, peerOptedIn: true, userChoseRelay: false, transport: 'udp' }, { decision: D, triedMethods: ['lan'] }),
  path('natProbeAfterLanFails', 'Every direct method is tried before any other path', { methods: [{ name: 'lan', ok: false }, { name: 'natProbe', ok: true }], relayOperatorEnabled: false, peerOptedIn: false, userChoseRelay: false, transport: 'udp' }, { decision: D, triedMethods: ['lan', 'natProbe'] }),
  path('directBeatsEnabledRelay', 'A relay that is enabled and opted into is not used while a direct method works', { methods: [{ name: 'lan', ok: false }, { name: 'natProbe', ok: true }], relayOperatorEnabled: true, peerOptedIn: true, userChoseRelay: false, transport: 'udp' }, { decision: D, triedMethods: ['lan', 'natProbe'] }),
  path('relayFallbackAfterEveryDirectMethodFailed', 'Operator enabled, peer opted in, every direct method failed', { methods: [{ name: 'lan', ok: false }, { name: 'natProbe', ok: false }], relayOperatorEnabled: true, peerOptedIn: true, userChoseRelay: false, transport: 'udp' }, { decision: R, triedMethods: ['lan', 'natProbe'] }),
  path('relayNotEnabledByOperator', 'The peer opted in, the operator did not: no relayed path', { methods: [{ name: 'lan', ok: false }, { name: 'natProbe', ok: false }], relayOperatorEnabled: false, peerOptedIn: true, userChoseRelay: false, transport: 'udp' }, { decision: U, triedMethods: ['lan', 'natProbe'] }),
  path('peerDidNotOptIn', 'The operator enabled it, the peer did not opt in: no relayed path', { methods: [{ name: 'lan', ok: false }, { name: 'natProbe', ok: false }], relayOperatorEnabled: true, peerOptedIn: false, userChoseRelay: false, transport: 'udp' }, { decision: U, triedMethods: ['lan', 'natProbe'] }),
  path('carryingIsNeverTheDefault', 'No direct method is available at all and nothing enabled a relay', { methods: [], relayOperatorEnabled: false, peerOptedIn: false, userChoseRelay: false, transport: 'udp' }, { decision: U, triedMethods: [] }),
  path('noDirectMethodsAtAllUsesAnEnabledRelay', 'An empty method list counts as every direct method failed; the relay is enabled and opted into', { methods: [], relayOperatorEnabled: true, peerOptedIn: true, userChoseRelay: false, transport: 'udp' }, { decision: R, triedMethods: [] }),
  path('userChoiceSkipsTheDirectAttempt', 'The user explicitly chose the relayed path; operator and peer allow it', { methods: [{ name: 'lan', ok: true }], relayOperatorEnabled: true, peerOptedIn: true, userChoseRelay: true, transport: 'udp' }, { decision: R, triedMethods: [] }),
  path('userChoiceStillNeedsTheOperator', 'The user chose the relayed path; the operator did not enable it', { methods: [{ name: 'lan', ok: true }], relayOperatorEnabled: false, peerOptedIn: true, userChoseRelay: true, transport: 'udp' }, { decision: U, triedMethods: [] }),
  path('tcpIsNotACoreTransport', 'The core protocol runs over UDP only', { methods: [{ name: 'lan', ok: true }], relayOperatorEnabled: false, peerOptedIn: false, userChoseRelay: false, transport: 'tcp' }, { decision: 'E_TRANSPORT_NOT_PERMITTED', triedMethods: [] }),
  path('httpIsNotACoreTransport', 'The core protocol runs over UDP only', { methods: [{ name: 'lan', ok: true }], relayOperatorEnabled: true, peerOptedIn: true, userChoseRelay: false, transport: 'http' }, { decision: 'E_TRANSPORT_NOT_PERMITTED', triedMethods: [] }),
  path('browserLinkedToOwnDeviceMayUseABrowserTransport', 'The single exception: a browser linked to the user\'s own device', { methods: [{ name: 'lan', ok: true }], relayOperatorEnabled: false, peerOptedIn: false, userChoseRelay: false, transport: 'websocket', browserLinkedToOwnDevice: true }, { decision: D, triedMethods: ['lan'] }),
  path('browserNotLinkedToOwnDeviceMayNot', 'A browser transport without the link to the user\'s own device is not permitted', { methods: [{ name: 'lan', ok: true }], relayOperatorEnabled: false, peerOptedIn: false, userChoseRelay: false, transport: 'websocket', browserLinkedToOwnDevice: false }, { decision: 'E_TRANSPORT_NOT_PERMITTED', triedMethods: [] }),
];

// 14.1 and 14.2: what a relay may do. "introduce" is always allowed; "carry" follows the path policy.
const relayRole = [
  { name: 'introduceIsAlwaysAllowed', action: 'introduce', relayOperatorEnabled: false, peerOptedIn: false, userChoseRelay: false, afterEveryDirectMethodFailed: false, allowed: true },
  { name: 'carryByDefaultIsRefused', action: 'carry', relayOperatorEnabled: true, peerOptedIn: true, userChoseRelay: false, afterEveryDirectMethodFailed: false, allowed: false },
  { name: 'carryAsFallback', action: 'carry', relayOperatorEnabled: true, peerOptedIn: true, userChoseRelay: false, afterEveryDirectMethodFailed: true, allowed: true },
  { name: 'carryAsUserChoice', action: 'carry', relayOperatorEnabled: true, peerOptedIn: true, userChoseRelay: true, afterEveryDirectMethodFailed: false, allowed: true },
  { name: 'carryWithoutOperatorIsRefused', action: 'carry', relayOperatorEnabled: false, peerOptedIn: true, userChoseRelay: true, afterEveryDirectMethodFailed: true, allowed: false },
  { name: 'carryWithoutPeerOptInIsRefused', action: 'carry', relayOperatorEnabled: true, peerOptedIn: false, userChoseRelay: false, afterEveryDirectMethodFailed: true, allowed: false },
];

// 14.2: what may be done with the address of a peer. "sink" names where the address would go.
const addressHandling = [
  { name: 'returnToApplication', sink: 'applicationReturn', allowed: false },
  { name: 'returnToApplicationProgrammingInterface', sink: 'apiResponse', allowed: false },
  { name: 'showInUserInterface', sink: 'userInterface', allowed: false },
  { name: 'writeToLog', sink: 'logLine', allowed: false },
  { name: 'writeToErrorMessage', sink: 'errorMessage', allowed: false },
  { name: 'storeInTransportShortLivedState', sink: 'transportShortLivedState', allowed: true },
  { name: 'storeInDatabase', sink: 'persistentStore', allowed: false },
  { name: 'storeInPeerTable', sink: 'peerTable', allowed: false },
  { name: 'sendToThePeerBeingIntroducedWithinTheIntroduction', sink: 'introducedPeerWithinIntroduction', allowed: true },
  { name: 'sendToThePeerBeingIntroducedOutsideTheIntroduction', sink: 'introducedPeerOutsideIntroduction', allowed: false },
  { name: 'sendToAnotherPeer', sink: 'otherPeer', allowed: false },
  { name: 'sendToThePeerExchangeResponse', sink: 'pexResponse', allowed: false },
];

// 14.2: who receives the address of A and the address of B when a relay or a common peer introduces A and B.
const introduction = [
  { name: 'aAndBAreIntroduced', introducer: 'relay', introduced: ['A', 'B'], bystanders: ['C'], expected: { receivesAddressOf: { A: ['B'], B: ['A'], C: [] }, introducerLearns: ['A', 'B'], introducerSeesTraffic: false } },
  { name: 'commonPeerIntroduces', introducer: 'commonPeer', introduced: ['A', 'B'], bystanders: [], expected: { receivesAddressOf: { A: ['B'], B: ['A'] }, introducerLearns: ['A', 'B'], introducerSeesTraffic: false } },
];

// 14.4: may this record or message carry the field? "carries" lists the fields a component wants to put in it.
const FIELDS = ['address', 'longTermPublicKey', 'handle', 'name'];
const records = [
  { name: 'mailboxBlobWithoutIdentity', kind: 'mailboxBlob', carries: [], allowed: true },
  { name: 'mailboxBlobWithAddress', kind: 'mailboxBlob', carries: ['address'], allowed: false },
  { name: 'mailboxBlobWithPublicKey', kind: 'mailboxBlob', carries: ['longTermPublicKey'], allowed: false },
  { name: 'discoveryRegistrationWithHandle', kind: 'discoveryRegistration', carries: ['handle'], allowed: false },
  { name: 'discoveryRegistrationWithAddress', kind: 'discoveryRegistration', carries: ['address'], allowed: false },
  { name: 'heartbeatWithAddress', kind: 'heartbeat', carries: ['address'], allowed: false },
  { name: 'heartbeatWithName', kind: 'heartbeat', carries: ['name'], allowed: false },
  { name: 'heartbeatWithNothing', kind: 'heartbeat', carries: [], allowed: true },
  { name: 'localNetworkBeaconWithPublicKey', kind: 'localNetworkBeacon', carries: ['longTermPublicKey'], allowed: false },
  { name: 'localNetworkBeaconWithName', kind: 'localNetworkBeacon', carries: ['name'], allowed: false },
  { name: 'localNetworkBeaconWithAddress', kind: 'localNetworkBeacon', carries: ['address'], allowed: false },
  { name: 'dhtRecordKindOtherThanMOrIWithPublicKey', kind: 'dhtRecord:x', carries: ['longTermPublicKey'], allowed: false },
  { name: 'signedDhtRecordMCarriesPublicKeys', kind: 'dhtRecord:m', carries: ['longTermPublicKey'], publicContent: true, allowed: true },
  { name: 'signedDhtRecordICarriesPublicKeys', kind: 'dhtRecord:i', carries: ['longTermPublicKey'], publicContent: true, allowed: true },
  { name: 'signedDhtRecordNeverCarriesAnAddress', kind: 'dhtRecord:m', carries: ['longTermPublicKey', 'address'], publicContent: true, allowed: false },
  { name: 'signedDhtRecordNeverCarriesAHandle', kind: 'dhtRecord:i', carries: ['longTermPublicKey', 'handle'], publicContent: true, allowed: false },
];
const signedRecordUse = [
  { name: 'publicShareIndex', use: 'publicShareIndex', ownerMadeItPublic: true, allowed: true },
  { name: 'privateContentIsNotPublished', use: 'publicShareIndex', ownerMadeItPublic: false, allowed: false },
  { name: 'findAPal', use: 'findPal', ownerMadeItPublic: true, allowed: false },
  { name: 'reachAPal', use: 'reachPal', ownerMadeItPublic: true, allowed: false },
  { name: 'describeADevice', use: 'describeDevice', ownerMadeItPublic: true, allowed: false },
  { name: 'findADevice', use: 'findDevice', ownerMadeItPublic: true, allowed: false },
];
const rendezvous = [
  { name: 'pairLocationMailbox', method: 'pairMailbox', allowed: true },
  { name: 'publishedAddress', method: 'publishedAddress', allowed: false },
  { name: 'signedDhtRecordLookup', method: 'signedDhtRecord', allowed: false },
  { name: 'discoveryRegistrationLookup', method: 'discoveryRegistration', allowed: false },
];
const unlinkability = [
  { name: 'nextHopLearnsAnAddress', pairs: [{ address: 'nextHop', learns: 'address' }], linksAddressToIdentity: false, allowed: true },
  { name: 'componentPairsAddressWithIdentity', pairs: [{ address: 'node', learns: 'identity' }], linksAddressToIdentity: true, allowed: false },
  { name: 'componentPairsAddressWithHandle', pairs: [{ address: 'node', learns: 'handle' }], linksAddressToIdentity: true, allowed: false },
  { name: 'componentPairsAddressWithShare', pairs: [{ address: 'node', learns: 'share' }], linksAddressToIdentity: true, allowed: false },
];

// 14.11: product boundaries.
const importPaths = [
  { name: 'sdkSurface', module: '@hn2/pal-sdk', importer: 'product', allowed: true },
  { name: 'sdkPal3Entry', module: '@hn2/pal-sdk/pal3', importer: 'product', allowed: true },
  { name: 'applicationSdk', module: '@palexplorer/sdk', importer: 'product', allowed: true },
  { name: 'internalProtocolPathFromProduct', module: '@hn2/protocol/pal3', importer: 'product', allowed: false },
  { name: 'internalProtocolRootFromProduct', module: '@hn2/protocol', importer: 'product', allowed: false },
  { name: 'internalProtocolLibFromProduct', module: '@hn2/protocol/lib/pal3/swarm.js', importer: 'product', allowed: false },
  { name: 'internalProtocolPathFromTransportAdapter', module: '@hn2/protocol/pal3', importer: 'transportAdapter', allowed: true },
];
const FORBIDDEN_FIELDS = ['host', 'port', 'ip', 'pal3Host', 'pal3Port', 'serveUrl', 'directAddress', 'externalAddress', 'localIp', 'remoteAddress', 'remotePort'];
const productSurfaces = [
  { name: 'identityOnlyApiResponse', surface: 'apiResponse', fields: ['peerId', 'displayName'], allowed: true },
  { name: 'identityKeyWhereASignatureIsVerified', surface: 'apiResponse', fields: ['peerId', 'identityKey'], verifiesSignature: true, allowed: true },
  { name: 'identityKeyWithoutASignatureToVerify', surface: 'apiResponse', fields: ['peerId', 'identityKey'], verifiesSignature: false, allowed: false },
  ...FORBIDDEN_FIELDS.map((f) => ({ name: `apiResponseWith_${f}`, surface: 'apiResponse', fields: ['peerId', f], allowed: false })),
  { name: 'persistedRecordWithHost', surface: 'persistedRecord', fields: ['peerId', 'host'], allowed: false },
  { name: 'persistedRecordWithDirectAddress', surface: 'persistedRecord', fields: ['peerId', 'directAddress'], allowed: false },
  { name: 'rendererIpcPayloadWithPort', surface: 'rendererIpcPayload', fields: ['peerId', 'port'], allowed: false },
  { name: 'rendererIpcPayloadIdentityOnly', surface: 'rendererIpcPayload', fields: ['peerId'], allowed: true },
  { name: 'diagnosticLogWithRemoteAddress', surface: 'diagnosticLog', fields: ['peerId', 'remoteAddress'], allowed: false },
  { name: 'diagnosticLogIdentityOnly', surface: 'diagnosticLog', fields: ['peerId'], allowed: true },
  { name: 'transportCarrierMayHoldAnEndpoint', surface: 'transportCarrier', fields: ['host', 'port', 'remoteAddress'], allowed: true },
];
const peerIdentifiers = [
  { name: 'ninetySixHex', value: 'ab'.repeat(48), valid: true },
  { name: 'sixtyFourHexIsNotAPeerHash', value: 'ab'.repeat(32), valid: false },
  { name: 'ninetySevenHex', value: 'ab'.repeat(48) + 'a', valid: false },
  { name: 'nonHex', value: 'zz'.repeat(48), valid: false },
  { name: 'addressIsNotAnIdentifier', value: '203.0.113.7:52474', valid: false },
];
const nativeCarriers = [
  { name: 'c2PalUdp', carrier: 'C2', enableIceTcp: null, allowed: true },
  { name: 'c1UdpOnlyIce', carrier: 'C1', enableIceTcp: false, allowed: true },
  { name: 'c1IceWithTcp', carrier: 'C1', enableIceTcp: true, allowed: false },
  { name: 'c1IceTcpUnspecified', carrier: 'C1', enableIceTcp: null, allowed: false },
  { name: 'tcpFallbackForPeerData', carrier: 'tcp', enableIceTcp: null, allowed: false },
  { name: 'httpFallbackForPeerData', carrier: 'http', enableIceTcp: null, allowed: false },
];
const localControl = [
  { name: 'unixDomainSocket', channel: 'unixDomainSocket', framed: true, allowed: true },
  { name: 'windowsNamedPipe', channel: 'windowsNamedPipe', framed: true, allowed: true },
  { name: 'unframedUnixSocket', channel: 'unixDomainSocket', framed: false, allowed: false },
  { name: 'loopbackHttpListener', channel: 'loopbackHttp', framed: true, allowed: false },
  { name: 'loopbackTcpListener', channel: 'loopbackTcp', framed: true, allowed: false },
];

const doc = {
  specVersion: '0.6.22',
  sections: ['14.1', '14.2', '14.4', '14.11'],
  description: 'Path policy, introduction address handling, address-free records and product SDK and transport boundaries. Decisions recorded from the specification text; replayed by a product against its own code.',
  generatedBy: 'bin/generate-v0.6-transport-policy-vectors.mjs',
  limits: { peerIdentifierHexLength: 96, forbiddenFieldNames: FORBIDDEN_FIELDS, recordFields: FIELDS },
  pathPolicy, relayRole, addressHandling, introduction,
  records, signedRecordUse, rendezvous, unlinkability,
  importPaths, productSurfaces, peerIdentifiers, nativeCarriers, localControl,
};
writeFileSync(out, `${JSON.stringify(doc, null, 2)}\n`);
console.log(`wrote ${out}: ${pathPolicy.length} path cases`);
