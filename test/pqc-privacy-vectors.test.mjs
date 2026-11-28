import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  runPrivateNetworkHybridValidation,
  runMailboxV2Validation,
  runOnion3Validation,
  runSealedRelayValidation,
} from '../validate.mjs';

const load = (name) => JSON.parse(readFileSync(new URL(`../test-vectors/v3/${name}`, import.meta.url), 'utf8'));

test('privateNetworkHybrid_vectors_validateWithoutPalCore', () => {
  const r = runPrivateNetworkHybridValidation();
  assert.equal(r.ok, true);
  assert.ok(r.rejected >= 11);
  assert.equal(r.mldsaChecked, true);
});

test('privateNetworkHybrid_tamperedMldsa65AcceptedAsValid_isRejectedByValidator', () => {
  const v = load('pal3-v0.6-private-network-vectors.json');
  v.hybridRejected.find((c) => c.name === 'profileV4TamperedMldsa65Signature').expectedError = 'accepted';
  assert.throws(() => runPrivateNetworkHybridValidation(v), /profileV4TamperedMldsa65Signature/);
});

test('privateNetworkHybrid_v3DowngradeAfterV4_isRejectedByValidator', () => {
  const v = load('pal3-v0.6-private-network-vectors.json');
  v.hybridRejected.find((c) => c.name === 'profileV3DowngradeAfterV4').expectedError = 'accepted';
  assert.throws(() => runPrivateNetworkHybridValidation(v), /profileV3DowngradeAfterV4/);
});

test('mailboxV2_vectors_validateWithoutPalCore', () => {
  const r = runMailboxV2Validation();
  assert.equal(r.ok, true);
  assert.ok(r.rejected >= 8);
  assert.equal(r.mldsaChecked, true);
});

test('mailboxV2_identityPinMismatchAccepted_isRejectedByValidator', () => {
  const v = load('pal3-v0.6-transport-vectors.json');
  v.mailboxBlobV2Rejected.find((c) => c.name === 'identityPinMismatch').expectedError = 'accepted';
  assert.throws(() => runMailboxV2Validation(v), /identityPinMismatch/);
});

test('mailboxV2_v1DowngradeAccepted_isRejectedByValidator', () => {
  const v = load('pal3-v0.6-transport-vectors.json');
  v.mailboxBlobV2Rejected.find((c) => c.name === 'v1DowngradeFromV2CapablePal').expectedError = 'accepted';
  assert.throws(() => runMailboxV2Validation(v), /v1DowngradeFromV2CapablePal/);
});

test('onion3_vectors_validateWithoutPalCore', () => {
  const r = runOnion3Validation();
  assert.equal(r.ok, true);
  assert.equal(r.hops, 6);
  assert.ok(r.rejected >= 10);
});

test('onion3_tamperedDelta_isRejectedByValidator', () => {
  const v = load('pal3-v0.6-onion3-vectors.json');
  const hop0 = v.threeHopCell.hops[0];
  const b = Buffer.from(hop0.cellHex, 'hex');
  b[220] ^= 0x01;
  hop0.cellHex = b.toString('hex');
  assert.throws(() => runOnion3Validation(v), /E_UNAUTHORIZED/);
});

test('onion3_replayedCell_isRejectedByValidator', () => {
  const v = load('pal3-v0.6-onion3-vectors.json');
  v.rejected.find((c) => c.name === 'replayedCell').expectedError = 'E_UNAUTHORIZED';
  assert.throws(() => runOnion3Validation(v), /replayedCell/);
});

test('sealedRelay_vectors_validateWithoutPalCore', () => {
  const r = runSealedRelayValidation();
  assert.equal(r.ok, true);
  assert.equal(r.relaySeal, 3);
  assert.ok(r.relaySealRejected >= 11);
  assert.equal(r.multihopBridges, 2);
  assert.ok(r.multihopRejected >= 7);
  assert.equal(r.mldsaChecked, true);
});

test('sealedRelay_wrongBlindingNonce_isRejectedByValidator', () => {
  const v = load('pal3-v0.6-sealed-relay-vectors.json');
  v.relaySealRejected.find((c) => c.name === 'blindClientIdWrongNonce').expectedError = 'accepted';
  assert.throws(() => runSealedRelayValidation(v), /blindClientIdWrongNonce/);
});

test('sealedRelay_tamperedRelayToken_isRejectedByValidator', () => {
  const v = load('pal3-v0.6-sealed-relay-vectors.json');
  v.relaySealRejected.find((c) => c.name === 'relayTokenTampered').expectedError = 'accepted';
  assert.throws(() => runSealedRelayValidation(v), /relayTokenTampered/);
});

test('sealedRelay_multihopNotOptedIn_isRejectedByValidator', () => {
  const v = load('pal3-v0.6-sealed-relay-vectors.json');
  v.relayMultihopRejected.find((c) => c.name === 'notEnabledByOptIn').expectedError = 'accepted';
  assert.throws(() => runSealedRelayValidation(v), /notEnabledByOptIn/);
});

test('sealedRelay_multihopReplayBelowWindow_isRejectedByValidator', () => {
  const v = load('pal3-v0.6-sealed-relay-vectors.json');
  v.relayMultihopRejected.find((c) => c.name === 'belowReplayWindow').expectedError = 'accepted';
  assert.throws(() => runSealedRelayValidation(v), /belowReplayWindow/);
});
