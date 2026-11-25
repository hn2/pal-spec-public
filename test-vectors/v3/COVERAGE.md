# PAL/3 conformance vector coverage

One row per numbered section of `spec/v3/PAL-3.0.md` (Draft 0.6.22) whose text contains a normative MUST. The table is checked by `test/coverage-table.test.mjs`: a section with MUST text and no row fails, and so does a vector file or case id that does not exist. A case id is a top-level key of the named vector file.

Status: `covered` = the normative rules of the section that can be expressed as bytes have vectors; `partial` = some rules have vectors, others (behaviour, state machines, policy) do not; `none` = no vector.

Section 12.5 is `partial`: rule 3 (stored state) has the migration vector; rule 4 (`E_PAL3_DOWNGRADE`) is tested in the reference implementation (hn2/pal-core#437), and no vector holds it yet.

| section | title | vector file | case ids | status |
|---|---|---|---|---|
| 3.2 | C2 — PAL-UDP (Normative) | pal3-v0.6-header-protection-vectors.json, pal3-v0.6-reset-vectors.json | protectedPackets,rejectedPackets,statelessResetToken | partial |
| 4 | Rendezvous & NAT Traversal | pal3-v0.6-beacon-vectors.json, pal3-v0.6-pair-rendezvous-vectors.json, pal3-v0.6-prekey-vectors.json | pairBeacon,pairKey,mailboxLocationsToB,signedPrekey | partial |
| 4.1 | NAT Traversal Hierarchy (N1–N7) | pal3-v0.6-nat-traversal-vectors.json | addresses,observations,punchPlans,relay | partial |
| 4.4 | Identity Pins | pal3-v0.5-vectors.json | identityDigest | partial |
| 5.1 | Wire Messages (on `pal3/ctl`, Deterministic Binary TLV) | pal3-v0.5-vectors.json, pal3-v0.6-sealed-hello-vectors.json | tlv,sealedHello,sealedHelloRejected | partial |
| 5.2 | Cryptographic Rules & Key Schedule | pal3-v0.5-vectors.json, pal3-v0.6-sas-vectors.json | keySchedule,handshakeSas,handshakeSasRejected | partial |
| 5.3 | Rekey (`REKEY`) | pal3-v0.6-rekey-vectors.json | rekeyDerivation,epochLimits,peerRekeyRate | partial |
| 5.4 | Address Validation & DoS Shield | pal3-v0.6-primitive-vectors.json | cookie | partial |
| 5.5 | PSK Resumption | pal3-v0.6-primitive-vectors.json | resumption | partial |
| 6.1 | Wire Layout (20-Byte Header + Ciphertext + 16-Byte Tag) | pal3-v0.5-vectors.json, pal3-v0.6-header-protection-vectors.json | recordAead,protectedPackets | partial |
| 6.2 | Plaintext bulk records (optional capability `c2-bulk-plaintext-record`) | pal3-v0.6-plaintext-record-vectors.json | records,rejected,sendSideRejected,gate | partial |
| 7.1 | Payloads of the Operations Defined Here | pal3-v0.6-core-operations.json, pal3-v0.6-core-vectors.json | operations,servedByEmbeddingProduct,objects | covered |
| 8.1 | Domain-Separated Merkle Tree (256 KiB Blocks) | pal3-v0.6-primitive-vectors.json | merkle | covered |
| 8.1.1 | Chunk-Group Verification (optional) | pal3-v0.6-chunk-outboard-vectors.json | emptyFile,contents,rejected | covered |
| 8.2 | Hybrid-Signed Manifests, Rollback & Equivocation | pal3-v0.6-primitive-vectors.json, pal3-v0.6-core-vectors.json | manifestRevision,objects | covered |
| 8.3 | Private Encrypted Shares (Encrypt-Then-Merkle) | pal3-v0.6-private-share-vectors.json | fileKeys,blocks,file,rejected | covered |
| 8.4 | Swarm, Deduplication, Preview, Upload Queue & PEX | pal3-v0.6-swarm-vectors.json | sources,pieceResource | partial |
| 8.5 | Swarm Offloading (`swarm.v1`) | pal3-v0.6-swarm-vectors.json | redistribution,swarmPass,shareTicket,accessDecisions,busy,relayTree,capabilityNegotiation | covered |
| 9 | Capability Permissions Engine | pal3-v0.6-grant-vectors.json | objects,rejected | covered |
| 10 | Cross-Platform File-System Layer | pal3-v0.6-sas-vectors.json | quickDropSas,quickDropSasRejected | partial |
| 11.2 | Normative Hardening Invariants | pal3-v0.6-hardening-vectors.json | uri,x25519,mlkem,reassembly | partial |
| 11.3 | Device Enrollment and Revocation | pal3-v0.6-device-revocation-vectors.json | certificates,certificatesRejected,statements,receiverSequence | partial |
| 11.4 | Sealing to an Identity and Its Devices | pal3-v0.6-multi-seal-vectors.json | sealedContent,sealedRejected,sealRejected,deviceLists,deviceListsRejected,receiverSequence,deviceSigned,deviceSignedRejected | covered |
| 12.1 | Comprehension-Bit TLV Tag Ranges | pal3-v0.5-vectors.json | comprehensionBits | covered |
| 12.2 | Extension Registry & Hybrid Extension Signing (`PAL-EXT-SIG-V3`) | pal3-v0.6-extension-signing-vectors.json | trustedRoots,bundles,publisherCertificates,rejected | covered |
| 12.3 | Extension Isolation | pal3-v0.6-local-policy-vectors.json | analyzer,analyzerBundled,permissions | partial |
| 12.4 | Local Settings and Policy | pal3-v0.6-local-policy-vectors.json | scenarios | partial |
| 12.5 | Versioning and Compatibility | pal3-stored-state-migration-vectors.json | cases | partial |
| 13.1 | Profile Object | pal3-v0.6-private-network-vectors.json | profile | covered |
| 13.2 | Signed Bytes | pal3-v0.6-private-network-vectors.json | profile | covered |
| 13.3 | Handover | pal3-v0.6-private-network-vectors.json | handover | covered |
| 13.4 | Accepting a Profile | pal3-v0.6-private-network-accept-vectors.json | accept | covered |
| 13.5 | Behavior While a Profile Is Active | pal3-v0.6-private-network-accept-vectors.json | state,members,hosts | partial |
| 13.6 | Edge Cases | pal3-v0.6-private-network-accept-vectors.json | accept | covered |
| 14.1 | Default Path and Transport | - | - | none |
| 14.2 | Introduction | - | - | none |
| 14.3 | Peer Exchange Without Addresses | pal3-v0.6-pex-vectors.json | receive,respond | covered |
| 14.4 | Address Records and Unlinkability | - | - | none |
| 14.5 | Identifiers | pal3-v0.6-identifier-vectors.json | peer,file,share,group,network | covered |
| 14.6 | Message Delivery | pal3-v0.6-transport-vectors.json | mailboxLocationKey | partial |
| 14.11 | Product SDK and Transport Boundaries | - | - | none |
| 15.1 | Scope and Capability | pal3-v0.6-onion2-vectors.json | capability | partial |
| 15.2 | Constants | pal3-v0.6-onion2-vectors.json | sizes | covered |
| 15.4 | Sealed Box | pal3-v0.6-onion2-vectors.json | threeHopCell | partial |
| 15.5 | Building and Relaying | pal3-v0.6-onion2-vectors.json | threeHopCell | partial |
| 15.6 | Fragmentation | pal3-v0.6-onion2-vectors.json | fragmentation | covered |
| A.1 | Deterministic TLV Encoding | pal3-v0.5-vectors.json | tlv | covered |
| A.4 | C2 PAL-UDP Datagram and Frame Layout | pal3-v0.6-header-protection-vectors.json, pal3-v0.6-primitive-vectors.json, pal3-v0.6-reset-vectors.json | protectedPackets,cookie,statelessResetToken | covered |
| A.5 | Record Payloads and Signed Objects | pal3-v0.6-core-vectors.json, pal3-v0.6-grant-vectors.json, pal3-v0.6-extension-signing-vectors.json | objects,bundles,rejected | covered |
| A.6 | Protocol Version and Suite Registry | pal3-v0.6-registry-vectors.json | registry,selection,capabilityEncoding,capabilityIntersection,registrationRejected | covered |
