import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  runRekeyValidation, runHeaderProtectionValidation, runSasValidation, runSealedHelloValidation, runGrantValidation, runExtensionSigningValidation, runStoredStateValidation,
  runChunkOutboardValidation, runPrivateShareValidation, runDeviceRevocationValidation, runRegistryValidation, runPlaintextRecordValidation, runMultiSealValidation, runHardeningValidation, runLocalPolicyValidation, runPrivateNetworkAcceptValidation, runPexValidation, runNatTraversalValidation, runTransportPolicyValidation, runEnrollmentBindingValidation,
} from '../validate.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));

test('rekey_vectors_validateWithoutPalCore', () => {
  const result = runRekeyValidation();
  assert.equal(result.ok, true);
  assert.ok(result.positive >= 3 && result.negative >= 2);
  assert.equal(result.validated, 'full');
});

test('rekey_vectors_withoutMlKemSupport_reportStructureOnly', () => {
  assert.equal(runRekeyValidation({ mlkem: false }).validated, 'structure-only');
});

test('headerProtection_vectors_validateWithoutPalCore', () => {
  const result = runHeaderProtectionValidation();
  assert.ok(result.positive >= 3 && result.negative >= 2);
});

test('sas_vectors_validateWithoutPalCore', () => {
  const result = runSasValidation();
  assert.ok(result.positive >= 3 && result.negative >= 2);
});

test('sas_vectors_includeTheHandshakeSasWithAWordListOf64', () => {
  const result = runSasValidation();
  assert.ok(result.handshake >= 3);
});

test('sealedHello_vectors_validateWithoutPalCore', () => {
  const result = runSealedHelloValidation();
  assert.equal(result.validated, 'full');
  assert.ok(result.positive >= 3 && result.negative >= 4);
  assert.equal(runSealedHelloValidation({ mlkem: false }).validated, 'structure-only');
});

test('grant_vectors_validateWithoutPalCore', () => {
  const result = runGrantValidation();
  assert.ok(result.positive >= 3 && result.negative >= 2);
});

test('extensionSigning_vectors_validateWithoutPalCore', () => {
  const result = runExtensionSigningValidation();
  assert.ok(result.positive >= 3 && result.negative >= 2);
});

const palCore = process.env.PAL_CORE_PATH;
const generators = ['rekey', 'header-protection', 'sas', 'sealed-hello', 'grant', 'extension-signing', 'chunk-outboard', 'private-share', 'device-revocation', 'registry', 'plaintext-record', 'multi-seal', 'hardening', 'local-policy', 'pex', 'nat-traversal', 'transport-policy', 'enrollment-binding'];

for (const name of generators) {
  test(`${name}_generator_twoRuns_areByteIdenticalAndMatchTheCommittedFile`, { skip: palCore ? false : 'set PAL_CORE_PATH to a hn2/pal-core checkout with dependencies installed' }, () => {
    const dir = mkdtempSync(join(tmpdir(), 'pal-spec-vectors-'));
    try {
      const run = (out) => {
        execFileSync(process.execPath, [join(root, 'bin', `generate-v0.6-${name}-vectors.mjs`), '--pal-core', palCore, '--out', join(dir, out)], { stdio: 'pipe' });
        return readFileSync(join(dir, out));
      };
      const first = run('first.json');
      const second = run('second.json');
      assert.ok(first.equals(second), 'two runs differ');
      assert.ok(first.equals(readFileSync(join(root, 'test-vectors', 'v3', `pal3-v0.6-${name}-vectors.json`))), 'committed file differs from a fresh run');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
}

const storedState = () => JSON.parse(readFileSync(join(root, 'test-vectors', 'v3', 'pal3-stored-state-migration-vectors.json'), 'utf8'));

test('storedState_vectors_validateWithoutPalCore', () => {
  const result = runStoredStateValidation();
  assert.equal(result.cases, 1);
});

test('storedState_oldFormThatVerifiesUnderCurrentRules_isRejectedByTheValidator', () => {
  const v = storedState();
  v.cases[0].oldFormHex = v.cases[0].expectedAfterMigration.migratedFormHex;
  assert.throws(() => runStoredStateValidation(v), /old form verifies under the current rules/);
});

test('storedState_migrationThatChangesDeviceKeys_isRejectedByTheValidator', () => {
  const v = storedState();
  v.cases[0].expectedAfterMigration.devicePublicKeys.device_ed25519_pk = '00'.repeat(32);
  assert.throws(() => runStoredStateValidation(v), /device keys changed/);
});

test('storedState_migratedFormEqualToOldForm_isRejectedByTheValidator', () => {
  const v = storedState();
  v.cases[0].expectedAfterMigration.certChanged = false;
  assert.throws(() => runStoredStateValidation(v), /must differ|must verify/);
});

test('storedState_generator_twoRuns_areByteIdenticalAndMatchTheCommittedFile', { skip: process.env.PAL_CORE_PRE_SHA384_PATH ? false : 'set PAL_CORE_PRE_SHA384_PATH to a pal-core checkout at 7d211e0^ with @noble/post-quantum and sodium-native installed' }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'pal-spec-vectors-'));
  try {
    const run = (out) => {
      execFileSync(process.execPath, [join(root, 'test-vectors', 'v3', 'generators', 'stored-device-cert-pre-sha384.mjs'), '--pal-core', process.env.PAL_CORE_PRE_SHA384_PATH, '--out', join(dir, out)], { stdio: 'pipe' });
      return readFileSync(join(dir, out));
    };
    const first = run('first.json');
    assert.ok(first.equals(run('second.json')), 'two runs differ');
    assert.ok(first.equals(readFileSync(join(root, 'test-vectors', 'v3', 'pal3-stored-state-migration-vectors.json'))), 'committed file differs from a fresh run');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

const vectors = (name) => JSON.parse(readFileSync(join(root, 'test-vectors', 'v3', name), 'utf8'));

test('chunkOutboard_vectors_validateWithoutPalCore', () => {
  const r = runChunkOutboardValidation();
  assert.ok(r.contents >= 6 && r.negative >= 6);
});

test('chunkOutboard_aWrongChunkRoot_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-chunk-outboard-vectors.json');
  v.contents[5].chunkRootHex = '00'.repeat(48);
  assert.throws(() => runChunkOutboardValidation(v), /chunkRoot/);
});

test('chunkOutboard_aRejectionThatTheRulesAccept_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-chunk-outboard-vectors.json');
  const bad = v.rejected.findIndex((r) => r.name === 'outboardOfAnotherBlock');
  v.rejected[bad].outboardHex = v.contents[5].blocks[1].outboardHex;
  assert.throws(() => runChunkOutboardValidation(v), /expected E_PAL3_CHUNK_OUTBOARD_INVALID/);
});

test('privateShare_vectors_validateWithoutPalCore', () => {
  const r = runPrivateShareValidation();
  assert.ok(r.blocks >= 6 && r.negative >= 6);
});

test('privateShare_aChangedFileKey_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-private-share-vectors.json');
  v.fileKeys[0].fileKeyHex = '00'.repeat(32);
  assert.throws(() => runPrivateShareValidation(v), /file key/);
});

test('privateShare_aDecryptionThatSucceedsButIsListedAsRejected_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-private-share-vectors.json');
  const r = v.rejected.find((x) => x.name === 'blockOpenedAtAnotherIndex');
  r.blockIndex = 1;
  assert.throws(() => runPrivateShareValidation(v), /blockOpenedAtAnotherIndex/);
});

test('deviceRevocation_vectors_validateWithoutPalCore', () => {
  const r = runDeviceRevocationValidation();
  assert.ok(r.certificates >= 3 && r.negative >= 6 && r.steps >= 10);
});

test('deviceRevocation_aRollbackThatTheStoreWouldApply_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-device-revocation-vectors.json');
  v.receiverSequence.find((s) => s.name === 'rollbackToOlderVersionIsNotApplied').expected.applied = true;
  assert.throws(() => runDeviceRevocationValidation(v), /rollbackToOlderVersionIsNotApplied/);
});

test('deviceRevocation_aRevokedDeviceListedAsAccepted_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-device-revocation-vectors.json');
  v.receiverSequence.find((s) => s.name === 'revokedDeviceRefused').expectedError = null;
  assert.throws(() => runDeviceRevocationValidation(v), /revokedDeviceRefused/);
});

test('deviceRevocation_aCertificateSignedByTheDevice_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-device-revocation-vectors.json');
  const bad = v.certificatesRejected.find((c) => c.name === 'deviceKeySignsItsOwnCertificate');
  v.certificates.push({ ...v.certificates[0], name: 'forged', certHex: bad.certHex });
  assert.throws(() => runDeviceRevocationValidation(v), /forged/);
});

test('registry_vectors_validateWithoutPalCore', () => {
  const r = runRegistryValidation();
  assert.ok(r.selection >= 8 && r.negative >= 4);
});

test('registry_aDowngradeListedAsSelected_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-registry-vectors.json');
  v.selection.find((c) => c.name === 'versionListWithoutThree').expected = { selectedVersion: 3, selectedSuite: 1 };
  assert.throws(() => runRegistryValidation(v), /versionListWithoutThree/);
});

test('registry_unsortedCapabilityTokens_areRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-registry-vectors.json');
  const c = v.capabilityEncoding[0];
  c.capabilitiesAscii = 'stream.v1,core.v1';
  c.capabilitiesHex = Buffer.from(c.capabilitiesAscii).toString('hex');
  assert.throws(() => runRegistryValidation(v), /sorted and unique/);
});

test('plaintextRecord_vectors_validateWithoutPalCore', () => {
  const r = runPlaintextRecordValidation();
  assert.ok(r.records >= 4 && r.negative >= 8 && r.gate >= 8);
});

test('plaintextRecord_aRelayedPathThatAllowsPlaintext_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-plaintext-record-vectors.json');
  v.gate.find((g) => g.name === 'relayPath').samples[0].senderMayUsePlaintext = true;
  assert.throws(() => runPlaintextRecordValidation(v), /relayPath/);
});

test('plaintextRecord_aDrainWindowThatNeverEnds_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-plaintext-record-vectors.json');
  const g = v.gate.find((x) => x.name === 'directThenRelay');
  g.samples.find((x) => x.atMs === 6000).receiverAcceptsPlaintext = true;
  assert.throws(() => runPlaintextRecordValidation(v), /directThenRelay/);
});

test('plaintextRecord_streamRule_validatesWithoutPalCore', () => {
  assert.ok(runPlaintextRecordValidation().streamRule >= 12);
});

test('plaintextRecord_plaintextOnARequestStreamThatIsAccepted_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-plaintext-record-vectors.json');
  v.streamRule.find((c) => c.name === 'plaintextOnARequestStream').expected = { outcome: 'delivered' };
  assert.throws(() => runPlaintextRecordValidation(v), /plaintextOnARequestStream/);
});

test('plaintextRecord_trailingDataAfterTheDrainWindowThatIsDiscarded_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-plaintext-record-vectors.json');
  v.streamRule.find((c) => c.name === 'trailingOnACancelledStreamAfterDrainWindow').expected = { outcome: 'discarded' };
  assert.throws(() => runPlaintextRecordValidation(v), /trailingOnACancelledStreamAfterDrainWindow/);
});

test('deviceRevocation_operationsAndHandshakeVersion_validateWithoutPalCore', () => {
  const r = runDeviceRevocationValidation();
  assert.ok(r.operations >= 20 && r.handshake >= 6);
});

test('deviceRevocation_aPushByANonPalThatIsApplied_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-device-revocation-vectors.json');
  v.operations.find((c) => c.name === 'pushByANonPal').expected = { ok: true, applied: true, version: '2' };
  assert.throws(() => runDeviceRevocationValidation(v), /pushByANonPal/);
});

test('deviceRevocation_aLowerHandshakeVersionThatIsAccepted_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-device-revocation-vectors.json');
  v.handshakeRevocationVersion.find((c) => c.name === 'responderBelowWhatInitiatorHolds').expected = { refusedBy: null, error: null };
  assert.throws(() => runDeviceRevocationValidation(v), /responderBelowWhatInitiatorHolds/);
});

test('natTraversal_pacingPortsAndDhtAddress_validateWithoutPalCore', () => {
  const r = runNatTraversalValidation();
  assert.ok(r.dht >= 12 && r.pacing >= 6 && r.ports >= 6);
});

test('natTraversal_aProbeIntervalBelowTwentyMilliseconds_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-nat-traversal-vectors.json');
  const c = v.punchPacing.find((x) => x.requestedMs === 5);
  c.effectiveMs = 5; c.probesPerSecondAtMost = 200;
  assert.throws(() => runNatTraversalValidation(v), /pacing of 5/);
});

test('natTraversal_moreThanSixtyFourProbePorts_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-nat-traversal-vectors.json');
  const c = v.portPrediction.find((x) => x.name === 'askingForMoreThanTheBound');
  c.ports = [...c.ports, 60000];
  assert.throws(() => runNatTraversalValidation(v), /askingForMoreThanTheBound/);
});

test('natTraversal_aDhtAddressConfirmedByTwoPrefixes_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-nat-traversal-vectors.json');
  const sc = v.dhtExternalAddress.find((x) => x.name === 'twoPrefixesAreNotEnough');
  sc.steps[1].readOnly = false; sc.steps[1].externalIp = sc.steps[1].reportedIp;
  assert.throws(() => runNatTraversalValidation(v), /twoPrefixesAreNotEnough/);
});

test('hardening_creditClampAndBlockRanges_validateWithoutPalCore', () => {
  const r = runHardeningValidation();
  assert.ok(r.credit >= 8 && r.ranges >= 6);
});

test('hardening_aCreditAboveSixteenMebibytesThatIsHonoured_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-hardening-vectors.json');
  const c = v.credit.find((x) => x.name === 'sixtyFourMebibytesIsClampedToSixteen');
  c.sentBytesAfterEachStep = [32 * 1024 * 1024];
  assert.throws(() => runHardeningValidation(v), /sixtyFourMebibytesIsClampedToSixteen/);
});

test('hardening_anEndBlockBeyondTheFileThatIsAccepted_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-hardening-vectors.json');
  v.ranges.find((x) => x.name === 'endBeyondTheLastBlock').expected = { decision: 'accepted', dataBytes: 786332 };
  assert.throws(() => runHardeningValidation(v), /endBeyondTheLastBlock/);
});

test('privateNetworkAccept_behaviors_validateWithoutPalCore', () => {
  assert.ok(runPrivateNetworkAcceptValidation().behaviors >= 5);
});

test('privateNetworkAccept_aPublicDhtThatIsAllowed_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-private-network-accept-vectors.json');
  v.behaviors.find((b) => b.name === 'publicDhtIsRefused').expected = { decision: 'allowed' };
  assert.throws(() => runPrivateNetworkAcceptValidation(v), /publicDhtIsRefused/);
});

test('multiSeal_vectors_validateWithoutPalCore', () => {
  const r = runMultiSealValidation();
  assert.ok(r.sealed >= 4 && r.lists >= 3 && r.signed >= 2 && r.negative >= 40);
});

test('multiSeal_aDeviceThatIsNotARecipientButOpensTheObject_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-multi-seal-vectors.json');
  v.sealedContent[0].recipients = v.sealedContent[0].recipients.filter((x) => x !== 'deviceA');
  assert.throws(() => runMultiSealValidation(v), /deviceA/);
});

test('multiSeal_aRejectionThatTheRulesAccept_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-multi-seal-vectors.json');
  v.deviceListsRejected[0].expectedError = 'E_PAL3_DEVICE_LIST_STALE';
  assert.throws(() => runMultiSealValidation(v), /expected/);
});

test('multiSeal_aRollbackThatIsAppliedAccordingToTheVector_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-multi-seal-vectors.json');
  const step = v.receiverSequence.find((s) => s.op === 'importList' && s.expected && s.expected.applied === false);
  assert.ok(step);
  step.expected.applied = true;
  assert.throws(() => runMultiSealValidation(v), /applied/);
});

test('multiSeal_aSignatureWithoutTheMlDsaPartThatIsAccepted_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-multi-seal-vectors.json');
  const r = v.deviceSignedRejected.find((x) => x.expectedError === 'E_PAL3_DEVICE_SIG_INVALID');
  r.expectedError = 'E_PAL3_DEVICE_REVOKED';
  assert.throws(() => runMultiSealValidation(v), /expected/);
});

test('hardening_vectors_validateWithoutPalCore', () => {
  const r = runHardeningValidation();
  assert.ok(r.uri >= 15 && r.x25519 >= 7 && r.mlkem >= 4 && r.scenarios >= 12);
});

test('hardening_aTraversalUriThatIsAccepted_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-hardening-vectors.json');
  const c = v.uri.find((x) => x.name === 'encodedDotDot');
  delete c.expectedError;
  c.expected = { scheme: 'pal', handle: 'alice', shareId: 'share1', filePath: '../secret', range: null };
  assert.throws(() => runHardeningValidation(v), /encodedDotDot/);
});

test('hardening_aLowOrderKeyThatIsAccepted_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-hardening-vectors.json');
  v.x25519.keys.find((k) => k.name === 'allZero').decision = 'accepted';
  assert.throws(() => runHardeningValidation(v), /allZero/);
});

test('hardening_anUnreducedMlKemKeyThatIsAccepted_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-hardening-vectors.json');
  v.mlkem.cases.find((k) => k.name === 'firstCoefficient3329').decision = 'accepted';
  assert.throws(() => runHardeningValidation(v), /firstCoefficient3329/);
});

test('hardening_aConflictingDuplicateThatKeepsTheMessage_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-hardening-vectors.json');
  const s = v.reassembly.find((x) => x.name === 'conflictingDuplicateDropsTheMessage');
  delete s.steps[1].expectedError;
  s.steps[1].expected = { complete: false };
  assert.throws(() => runHardeningValidation(v), /conflictingDuplicateDropsTheMessage/);
});

test('hardening_anExpiryThatNeverHappens_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-hardening-vectors.json');
  const s = v.reassembly.find((x) => x.name === 'entryExpiresAfterFiveSeconds');
  s.steps[1].atMs = 4000;
  assert.throws(() => runHardeningValidation(v), /entryExpiresAfterFiveSeconds/);
});

test('localPolicy_vectors_validateWithoutPalCore', () => {
  const r = runLocalPolicyValidation();
  assert.ok(r.sources >= 12 && r.scenarios >= 10);
});

test('localPolicy_aRefusalThatNamesItsReason_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-local-policy-vectors.json');
  const st = v.scenarios.find((s) => s.name === 'privacyModeServesNothing').steps[0];
  st.expected.text += ' (privacy)';
  assert.throws(() => runLocalPolicyValidation(v), /privacyModeServesNothing/);
});

test('localPolicy_aLinterThatCallsItselfABoundary_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-local-policy-vectors.json');
  v.analyzer[0].isSecurityBoundary = true;
  assert.throws(() => runLocalPolicyValidation(v), /not a security boundary/);
});

test('localPolicy_anEvalThatIsCalledSafe_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-local-policy-vectors.json');
  const c = v.analyzer.find((x) => x.name === 'directEval');
  c.safe = true;
  c.criticalTypes = [];
  assert.throws(() => runLocalPolicyValidation(v), /directEval/);
});

test('localPolicy_aWildcardThatImpliesExec_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-local-policy-vectors.json');
  v.permissions.find((x) => x.name === 'wildcardNeverImpliesExec').allowed = true;
  assert.throws(() => runLocalPolicyValidation(v), /wildcardNeverImpliesExec/);
});

test('localPolicy_aBareWildcardThatCoversOrdinary_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-local-policy-vectors.json');
  v.permissions.find((x) => x.name === 'wildcardCoversOrdinary').allowed = true;
  assert.throws(() => runLocalPolicyValidation(v), /wildcardCoversOrdinary/);
});

test('privateNetworkAccept_vectors_validateWithoutPalCore', () => {
  const r = runPrivateNetworkAcceptValidation();
  assert.ok(r.accept >= 25 && r.state >= 6 && r.members >= 5 && r.hosts >= 7);
});

test('privateNetworkAccept_aReplayedOlderVersionThatIsAccepted_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-private-network-accept-vectors.json');
  const c = v.accept.find((x) => x.name === 'olderVersionIsRefused');
  c.expected = { decision: 'accepted' };
  assert.throws(() => runPrivateNetworkAcceptValidation(v), /olderVersionIsRefused/);
});

test('privateNetworkAccept_anExpiredProfileThatStaysActive_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-private-network-accept-vectors.json');
  v.state.find((x) => x.name === 'expiredStoredProfileIsLockdown').expected = { mode: 'active' };
  assert.throws(() => runPrivateNetworkAcceptValidation(v), /expiredStoredProfileIsLockdown/);
});

test('privateNetworkAccept_aRevokedMemberThatMayConnect_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-private-network-accept-vectors.json');
  v.members.find((x) => x.name === 'revokedMemberIsRefused').allowed = true;
  assert.throws(() => runPrivateNetworkAcceptValidation(v), /revokedMemberIsRefused/);
});

test('privateNetworkAccept_aSubstringHostThatIsAllowed_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-private-network-accept-vectors.json');
  v.hosts.find((x) => x.name === 'listedHostAsSubstringIsRefused').allowed = true;
  assert.throws(() => runPrivateNetworkAcceptValidation(v), /listedHostAsSubstringIsRefused/);
});

test('privateNetworkAccept_generator_isDeterministicAndMatchesTheCommittedFile', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pal-spec-pn-'));
  try {
    execFileSync(process.execPath, [join(root, 'bin', 'generate-v0.6-private-network-accept-vectors.mjs'), '--out', join(dir, 'a.json')], { stdio: 'pipe' });
    const fresh = readFileSync(join(dir, 'a.json'), 'utf8').replace(/\r\n/g, '\n');
    const committed = readFileSync(join(root, 'test-vectors', 'v3', 'pal3-v0.6-private-network-accept-vectors.json'), 'utf8').replace(/\r\n/g, '\n');
    assert.equal(fresh, committed);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('pex_vectors_validateWithoutPalCore', () => {
  const r = runPexValidation();
  assert.ok(r.receive >= 8 && r.responded === 32);
});

test('pex_aResponseEntryThatCarriesAnAddress_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-pex-vectors.json');
  v.respond.response.peers[0].host = '203.0.113.7';
  assert.throws(() => runPexValidation(v), /public key only/);
});

test('pex_aThirdPartyReportThatReplacesAKnownPeer_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-pex-vectors.json');
  const c = v.receive.find((x) => x.name === 'thirdPartyReportNeverOverwritesAKnownPeer');
  c.expected.learned[0].reporter = c.reporterPk;
  assert.throws(() => runPexValidation(v), /thirdPartyReportNeverOverwritesAKnownPeer/);
});

test('pex_aQuotaThatIsNotEnforced_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-pex-vectors.json');
  const c = v.receive.find((x) => x.name === 'oneReporterCannotFillTheSwarm');
  c.expected.storedPeerPks.push('ff'.repeat(32));
  assert.throws(() => runPexValidation(v), /oneReporterCannotFillTheSwarm/);
});

test('natTraversal_vectors_validateWithoutPalCore', () => {
  const r = runNatTraversalValidation();
  assert.ok(r.addresses >= 25 && r.scenarios >= 10 && r.punch >= 5 && r.reservations >= 12);
});

test('natTraversal_aDocumentationAddressThatIsGlobal_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-nat-traversal-vectors.json');
  v.addresses.find((a) => a.name === 'ipv6Documentation3fff').globalUnicast = true;
  assert.throws(() => runNatTraversalValidation(v), /ipv6Documentation3fff/);
});

test('natTraversal_aSingleObservationThatIsConfirmed_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-nat-traversal-vectors.json');
  v.observations.find((s) => s.name === 'singleObservationIsNeverConfirmed').steps[0].expected.quorumMet = true;
  assert.throws(() => runNatTraversalValidation(v), /singleObservationIsNeverConfirmed/);
});

test('natTraversal_aReservationWithoutTheSessionThatIsAccepted_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-nat-traversal-vectors.json');
  v.relay.reservations.find((c) => c.name === 'sessionNotGiven').expected = { accepted: true };
  assert.throws(() => runNatTraversalValidation(v), /sessionNotGiven/);
});

test('natTraversal_aStartTimeThatIgnoresTheMargin_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-nat-traversal-vectors.json');
  v.punchPlans[0].initiatorStartInMs = 0;
  assert.throws(() => runNatTraversalValidation(v), /punch plan/);
});

test('natTraversal_aReservationThatSkipsTheSignatureCheck_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-nat-traversal-vectors.json');
  v.relay.reservations.find((c) => c.name === 'mlDsaSignatureChanged').expected = { accepted: true };
  assert.throws(() => runNatTraversalValidation(v), /mlDsaSignatureChanged/);
});

test('transportPolicy_vectors_validateWithoutPalCore', () => {
  const r = runTransportPolicyValidation();
  assert.ok(r.path >= 12 && r.address >= 12 && r.records >= 16 && r.boundary >= 30);
});

test('transportPolicy_aRelayThatCarriesByDefault_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-transport-policy-vectors.json');
  v.pathPolicy.find((x) => x.name === 'directBeatsEnabledRelay').expected.decision = 'relayed';
  assert.throws(() => runTransportPolicyValidation(v), /directBeatsEnabledRelay/);
});

test('transportPolicy_anAddressInALog_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-transport-policy-vectors.json');
  v.addressHandling.find((x) => x.name === 'writeToLog').allowed = true;
  assert.throws(() => runTransportPolicyValidation(v), /writeToLog/);
});

test('transportPolicy_aRecordThatCarriesAHandle_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-transport-policy-vectors.json');
  v.records.find((x) => x.name === 'discoveryRegistrationWithHandle').allowed = true;
  assert.throws(() => runTransportPolicyValidation(v), /discoveryRegistrationWithHandle/);
});

test('transportPolicy_aLoopbackHttpListener_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-transport-policy-vectors.json');
  v.localControl.find((x) => x.name === 'loopbackHttpListener').allowed = true;
  assert.throws(() => runTransportPolicyValidation(v), /loopbackHttpListener/);
});

test('enrollmentBinding_vectors_validateWithoutPalCore', () => {
  const r = runEnrollmentBindingValidation();
  assert.ok(r.enrollment >= 6 && r.receiverForms >= 4 && r.callerBinding >= 4);
});

test('enrollmentBinding_aSelfCertifiedFormAcceptedAfterAStatement_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-enrollment-binding-vectors.json');
  v.receiverForms.find((c) => c.name === 'selfCertifiedRefusedOnceAStatementIsHeld').expected = { accept: true };
  assert.throws(() => runEnrollmentBindingValidation(v), /selfCertifiedRefusedOnceAStatementIsHeld/);
});

test('enrollmentBinding_aClaimForAnotherIdentity_isRejectedByTheValidator', () => {
  const v = vectors('pal3-v0.6-enrollment-binding-vectors.json');
  v.callerBinding.find((c) => c.name === 'claimForAnotherIdentityIsRefused').expected = { allowed: true };
  assert.throws(() => runEnrollmentBindingValidation(v), /claimForAnotherIdentityIsRefused/);
});
