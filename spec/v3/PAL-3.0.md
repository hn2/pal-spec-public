# PAL/3.0 Post-Quantum Peer-to-Peer Wire Protocol Specification

> **Copyright © 2026 Palexplorer. All rights reserved.**
> Canonical Specification: `hn2/pal-spec` · Status: **Draft 0.6.23** (2026-11-28)
> Permission is granted to read, copy, and cite this unmodified specification for security auditing, regulatory review, and interoperable extension development per the LICENSE. All rights to the Palexplorer runtime engine and trademarks are reserved.

PAL/3.0 is an integrated, zero-TCP, post-quantum peer-to-peer protocol. It carries peer discovery, mutual identity authentication with identity protection, capability permissions, Merkle-verified file transfer, low-latency media streaming, delta synchronization, encrypted messaging, and network diagnostics over UDP carriers. A small mandatory core is extended by signed, capability-negotiated extensions (§12).

**Changes since Draft 0.4.0** (security review, 2026-10):
- The handshake now protects identities (§5). It uses true HKDF-Expand for record keys (§5.2).
- Rendezvous tags and mailbox locations are derived from a secret beacon key (§4).
- Pins cover the hybrid identity digest (§4.4).
- Address validation is mandatory, and bans apply only to validated sources (§5.4).
- The C2 transport is specified normatively, with authenticated packet headers and congestion control (§3.2). PSK resumption is added (§5.5).
- Further changes:
  - Automatic and race-free rekey (§5.3).
  - Default-deny authorization bound to server-derived resources (§9).
  - Private-share `file_id` rules (§8.3).
  - Manifest rollback state and equivocation (§8.2).
  - Authenticated PEX (§8.4).
  - Commit-then-reveal SAS (§10.5).
  - Extension sandbox requirements (§12.3).

**Changes in Draft 0.6.23** (2026-11-28): hybrid post-quantum upgrades for private network profiles, administrator handovers and offline mailbox blobs (hn2/pal-spec#104), and additive privacy specifications for blinded multi-hop relay cells (`onion/3`), sealed relay reservations (`relay-seal.v1`) and optional multi-hop carried sessions (`relay-multihop.v1`) (hn2/pal-spec#105). Each change states whether it is wire compatible and stored-state compatible with 0.6.22.
- §13.1 to §13.3: Private Network Profile v4 (`palexplorer-private-network-v4`) and Handover v2 (`palexplorer-private-network-handover-v2`) require strict-AND hybrid Ed25519 + ML-DSA-65 signatures (`adminDsaPublicKey`, `members[].dsaPublicKey`, `fromDsaPublicKey`, `toDsaPublicKey`, `signatureMldsa65`) with a no-downgrade transition rule from v3 profiles and v1 handovers. Vectors added to `test-vectors/v3/pal3-v0.6-private-network-vectors.json`. Wire compatible with 0.6.22: yes during transition (v3 profiles and v1 handovers remain accepted before a v4 profile is seen); no downgrade to v3/v1 once v4 is accepted. Stored-state compatible: yes (stored v3 profiles stay valid until upgraded to v4).
- §14.5: removed the resolved open question about the private network identifier (already specified in §13.1 and §13.2). Editorial. Wire compatible: yes. Stored-state compatible: yes.
- §14.6: corrected the mailbox location key length from `32 bytes` to `48 bytes` to match `SHA-384` and the 96-hex test vector, and specified hybrid Ed25519 + ML-DSA-65 Mailbox Blob v2 (`"v": 2`, context `palexplorer-mailbox-v2`, `fromDsaPublicKey`, `signatureMldsa65`, 24 KiB limit) with a no-downgrade transition rule from `"v": 1`. Vectors added to `test-vectors/v3/pal3-v0.6-transport-vectors.json`. Wire compatible with 0.6.22: yes during transition (`"v": 1` remains accepted until a pal uses `"v": 2` or is pinned for v2). Stored-state compatible: yes.
- §14.10: specified additive capability-negotiated extensions `relay-seal.v1` (sealed relay reservations with HMAC-SHA-384 blind client commitment, hybrid-signed `pal3-relay-sealed-v1` reservation and ChaCha20-Poly1305 `relay_token`) and `relay-multihop.v1` (optional two-relay carried sessions with `RELAY_MH` framing and per-leg session ID and sequence rewriting). New vectors: `test-vectors/v3/pal3-v0.6-sealed-relay-vectors.json`. Additive. Wire compatible: yes. Stored-state compatible: yes.
- §15.9: specified `onion/3`, an additive Sphinx-style header-blinded multi-hop relay cell using sequential RFC 7748 X25519 blinding, HKDF-SHA-384 per-hop keys, RFC 8439 ChaCha20 header and payload streams, and full-cell HMAC-SHA-384 MACs, eliminating the cleartext `remainingHops` byte of `onion/2`. New vectors: `test-vectors/v3/pal3-v0.6-onion3-vectors.json`. Additive. Wire compatible: yes. Stored-state compatible: yes.

**Changes in Draft 0.6.22** (2026-11-24): conformance vectors for sections that had none, and the text changes that writing them showed to be necessary (hn2/pal-spec#63 criterion 2). Each change states whether it is wire compatible and stored-state compatible with 0.6.21.
- §13.1 and §13.2: the signed bytes of a profile end with `networkId`, `networkCreator`, `networkNonce` and `networkCreatedAtMs` (`null` when absent), which is what the shipped desktop client signs and verifies (hn2/palexplorer `lib/core/privateNetwork.js`). The earlier text left them out, so a profile signed from the text did not verify in the client. The fields bind a profile to one network identifier (§14.5), so keeping them is the safer behaviour and the text follows the client. Wire compatible with the shipped client: yes; with a profile signed from the 0.6.21 text: no (such a profile was never accepted by the client). Stored-state compatible: yes. §13.4 to §13.6: vectors `pal3-v0.6-private-network-accept-vectors.json` (31 acceptance decisions, stored-profile lockdown, member and host decisions); §13.5 states that a relay entered as `host:port` also covers `https://host`, which is what the client does. The replay in the desktop client (hn2/palexplorer#1692) found that a `networkId` that is not derived from its creator, nonce and creation time is refused before the signature is checked and carried no error identifier; the client now reports `E_PRIVATE_NETWORK_BAD_NETWORK_ID`, the vector `changedNetworkIdBreaksTheSignature` (which expected `BAD_SIGNATURE` for such a profile) is replaced by `networkIdNotDerivedFromItsFieldsIsRefused` and `networkIdentityReplacedAfterSigningBreaksTheSignature` (a consistent replacement that only the signature catches). Wire compatible: yes. Stored-state compatible: yes.
- §4.1 N1: the documentation prefixes are `2001:db8::/32` and `3fff::/20` (RFC 9637), and the IPv4 rule is written out. Code change in hn2/pal-core#453: the reference had excluded only `2001:db8::/32`, so a `3fff::/20` address was accepted as a global unicast candidate; the safer rule wins. §4.1 N6: verification takes the id of the presenting session as an input and fails closed without it (`E_PAL3_RELAY_INVALID`); the reference compared the session only when the caller passed one. The IPv4 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) are not filtered, which the text now says (the reference tests use them as stand-in addresses and an observer cannot gain anything from them that it cannot gain from any other address). Vectors: `pal3-v0.6-nat-traversal-vectors.json` (33 addresses, 12 observation scenarios, 7 start-time plans, 15 reservation cases, quota steps). Wire compatible: yes. Stored-state compatible: yes.
- §14.3 states how a receiver registers peer exchange entries (reference behaviour): only the first 32 entries are read, an entry with a `peerPk` that is not 64 hexadecimal characters is skipped, the key is lower-cased, an entry equal to the authenticated reporter is verified and any other is not, one reporter registers at most 16 unverified entries per swarm and a report about an already known peer never replaces it. §14.1: `E_PAL3_UNREACHABLE` is how the specification names the failure; the reference implementation reports it as the catalog error `E_PEER_UNREACHABLE` (`PAL3-NET-1001`). Vectors: `pal3-v0.6-pex-vectors.json`. Editorial. Wire compatible: yes. Stored-state compatible: yes.
- §12.4 states the wire form of a local refusal: `E_BUSY: retry after <n> ms` with `n` from 100 to 60000 and no reason (hn2/pal-core#451: the reference implementation appended the reason, the safer form wins and the code was changed). §12.3 is covered by linter decisions. Vectors: `pal3-v0.6-local-policy-vectors.json`. Wire compatible: yes (a client reads only the number). Stored-state compatible: yes.
- §11.2 item 3 states what a reassembly table does when a cap is reached (the oldest entry of that source, or of the table, is evicted), that an identical retransmission is ignored and that a frame of one fragment needs no state; item 5 limits the segment rule to `pal://` URIs (the reference implementation has no parser for `pal3://share/<token>`, whose token has no path segments). Vectors: `pal3-v0.6-hardening-vectors.json` (URI validation, low-order X25519 keys, the ML-KEM modulus check, 16 reassembly scenarios). Editorial: the reference behaviour is unchanged. Wire compatible: yes. Stored-state compatible: yes.
- §6.2 the receiver rule for trailing plaintext data: a plaintext record on a cancelled or finished stream is discarded only while plaintext records are accepted at all (path direct, or inside the drain window `[t, t + 3 s)`); outside it the session closes (`E_PAL3_PLAINTEXT_FORBIDDEN`), which is what the reference does. Vectors: `streamRule` of `pal3-v0.6-plaintext-record-vectors.json` (14 scenarios from real sessions). Editorial. Wire compatible: yes. Stored-state compatible: yes.
- §11.3 items 5 and 7: vectors for `device.revocation.push` and `.get` as served (27 cases: statement version rules, session binding, pals only, size and form of the body, the bounded table, fail closed without a store) and for `revocation_version` in the handshake (8 cases, both roles). The reference agreed with the text. Item 2 (enrollment and migration) is product behaviour and has no vector yet. Editorial. Wire compatible: yes. Stored-state compatible: yes.
- §4.1 N4 and N5: the pacing and the port bound are now stated as limits an implementation MUST NOT exceed (20 ms, at most 50 probes per second; at most 64 distinct ports between 1024 and 65535). Code change in hn2/pal-core#458: the reference allowed a 5 ms floor and 256 ports, the specification and the safer bound win. §4.1 N3: the PAL-DHT quorum states when an entry is gone (its 30th minute), how the 64-entry table drops entries and that a non-global address reported by a non-global reporter needs no quorum (private networks), which is what the reference does. Vectors: `punchPacing`, `portPrediction` and `dhtExternalAddress` of `pal3-v0.6-nat-traversal-vectors.json`. Wire compatible: yes. Stored-state compatible: yes.
- §11.2 item 4 states the credit clamp for a request and for each `CREDIT` record, that a Merkle block is sent whole, and the range rule with `E_PAL3_INVALID_RANGE`. Vectors: `credit` (10 scenarios) and `ranges` (8 cases) of `pal3-v0.6-hardening-vectors.json`. Editorial: the reference behaviour is unchanged. Wire compatible: yes. Stored-state compatible: yes.
- §13.5: behavior cases (no public DHT, no public bootstrap list, lockdown without servers, an edited stored profile) in `pal3-v0.6-private-network-accept-vectors.json`. Editorial. Wire compatible: yes. Stored-state compatible: yes.

**Changes in Draft 0.6.21** (2026-11-24): multi-recipient sealing so that a device paired without the identity secret key can open content sealed to its identity and can sign with both algorithms (hn2/pal-spec#87, hn2/pal-core#449, hn2/palexplorer#1687). Everything is additive.
- New §11.4 (and A.1 tables) defines device encryption keys in the optional certificate extension `0xC010`, `sealed_content` (one content key, a key commitment and one X25519 + ML-KEM-768 hybrid wrap per recipient, at most 16), the identity-signed `device_list` (revision, 7-day lifetime, at most 15 devices) and `device_signed` (Ed25519 and ML-DSA-65 by the device keys). Vectors: `pal3-v0.6-multi-seal-vectors.json`. Wire compatible with 0.6.20: yes. A 0.6.20 verifier ignores `0xC010` (comprehension-optional range) and never receives the new objects. The new operations `device.list.push` and `device.list.get` (§7.1) and the multi-recipient form are used only with the capability `seal.v1` (A.6, §12.2, §12.5 item 1); without it the sender keeps the earlier single-recipient form. Stored-state compatible with 0.6.20: yes. Certificates without `0xC010`, pins and revocation statements stay valid; a device that has no encryption keys is simply not in a list.

**Changes in Draft 0.6.20** (2026-11-24): the specification now states what the reference implementation (`@hn2/protocol` 9.0.2 and later, hn2/pal-core) does where the two differed, and the implementation is changed where it was weaker than this text (hn2/pal-core#420 to #429, hn2/pal-spec#56). Each change states whether it is wire compatible and stored-state compatible with 0.6.19.
- Conventions name HKDF with SHA-384, the hash of every registered suite (hn2/pal-core#420). Editorial. Wire compatible: yes. Stored-state compatible: yes.
- §5.1 gives the `SEALED_HELLO` key, nonce and AAD derivation, with the label `pal3-sealed-hello-v1` and vectors `pal3-v0.6-sealed-hello-vectors.json` (hn2/pal-core#422). The implementation was not changed. Wire compatible: yes. Stored-state compatible: yes.
- §5.2 gives the handshake SAS (label `pal3-handshake-sas-v1`, 8 digits, 4 words from a 64-word list) with vectors in `pal3-v0.6-sas-vectors.json` (hn2/pal-core#424). The implementation was not changed. Wire compatible: yes. Stored-state compatible: yes. §5.2 step 4 now says `ikm` is 224 bytes, which is what 32 + 32 + 160 gives and what the implementation and the vectors use (the text said 192).
- §5.4 item 1 describes the address token (label `pal3-addrtoken-v1`, 16 bytes in the cookie slot, 18 to 24 hours, bound to the IP address, single use, ignored while proof-of-work is demanded) (hn2/pal-core#423). The implementation was not changed. Wire compatible: yes. Stored-state compatible: yes (a token is never stored by a peer for longer than its lifetime).
- §5.4 item 3: a dialer ignores an unauthenticated challenge above 16 bits when it arrives and, if no `ACCEPT` follows, ends the attempt with `E_PAL3_POW_TOO_HARD` instead of a plain timeout (hn2/pal-core#429). Code change in hn2/pal-core. Wire compatible: yes. Stored-state compatible: yes.
- §5.5 states that the ticket plaintext holds exactly the tags `0x0001`, `0x0003`, `0x0004`, `0x0005` and `0x0006`, and that any other ticket is ignored (hn2/pal-core#425). Code change in hn2/pal-core: the earlier form (tag `0x0002` with the whole certificate, no count) and an `expires_at` more than 24 hours after `issued_at` are no longer accepted when a ticket is opened. Wire compatible: yes (the responder completes a full handshake). Stored-state compatible: no, for tickets of the earlier form held by a client (at most 24 hours old): they stop resuming and cost one full handshake.
- §8.2, §8.6, A.5 items 2 and 5 give `shareId` and `authorDeviceId` as 48 bytes, which is what the implementation requires since 0.6.18 and what §14.5 implies for the share identifier; `authorDeviceId` is 48 opaque bytes chosen by the authoring device (hn2/pal-core#427). The vectors `pal3-v0.6-swarm-vectors.json` use 48-byte share identifiers. Wire compatible with 0.6.19 text: no (a manifest, swarm pass or share ticket built from the 16-byte form is rejected, as it is by the implementation). Stored-state compatible: no (stored manifests, tickets and passes with 16-byte identifiers are not accepted). Deployed 0.4.15x desktop clients that still build the 16-byte form are not verified here.
- §7.1 and §11.3 specify `device.revocation.push` and `device.revocation.get` (request and response forms the desktop product already sends) and the error `E_PAL3_DEVICE_REVOKED`; hn2/pal-core now keeps the statement with the highest version per identity and enforces §11.3 item 6 at the handshake in both roles, full and resumed (hn2/pal-core#426). Code change in hn2/pal-core. Wire compatible: yes. Stored-state compatible: yes.
- §12.2 and A.5 item 7 state what an extension bundle and a publisher certificate sign (message prefixes `pal3-ext-bundle-v1` and `pal3-ext-publisher-cert-v1`, ML-DSA contexts `pal3-ext-sig-v1` and `pal3-ext-cert-v1`, body fields) (hn2/pal-spec#56). The implementation was not changed. Wire compatible: yes. Stored-state compatible: yes.
- §3.2 and A.4: `sample` is the first 16 bytes of `ciphertext || tag`, which differs from `ciphertext[0..16]` only for payloads shorter than 16 bytes. Editorial. Wire compatible: yes. Stored-state compatible: yes.
- Appendix A.2 and A.6 name the current draft, the implementing package version and every vector file; new vectors: `pal3-v0.6-sealed-hello-vectors.json`, `pal3-v0.6-grant-vectors.json`, `pal3-v0.6-extension-signing-vectors.json`, the handshake SAS cases of `pal3-v0.6-sas-vectors.json`, and 48-byte identifiers in `pal3-v0.6-swarm-vectors.json` (hn2/pal-core#421, hn2/pal-core#428, hn2/pal-spec#56). The identifier derivations of §14.5 are implemented in `@hn2/protocol` (`identifiers.js`) and tested against `pal3-v0.6-identifier-vectors.json`. Wire compatible: yes. Stored-state compatible: yes.

**Changes in Draft 0.6.19** (2026-11-24): editorial and additive. New §12.5 states the versioning and compatibility rules that apply from `1.0.0` (semantic parts of the version, the 90-day acceptance window, migration of stored state, the rejection code, the changelog facts) and new §12.6 lists the exit criteria for `1.0.0`. No byte, label, hash or requirement of the protocol changes. Wire compatible with 0.6.18: yes. Stored-state compatible with 0.6.18: yes.

**Changes in Draft 0.6.18** (2026-11-18): identifiers and content hashes use SHA-384 (hn2/pal-spec#54). The network is under development and a breaking change is accepted: there is no compatibility with 0.6.17 identifiers. (1) §14.5: every identifier is the full 48-byte SHA-384 value, 96 lowercase hexadecimal characters, with no algorithm tag; the peer, file, share, group and network identifiers have a stated derivation, and the group and network identifiers use a signed creation record, so a rename never changes them. (2) §8.1: the Merkle leaf, node and empty root use SHA-384 and the content identifier prefix changes from `pal3:s2t` to `pal3:s3t` with a 96-character root. (3) SHA-384 is now the only hash the protocol chooses, replacing the rule of 0.6.12: suite `0x0001` names SHA-384, the key schedule uses HKDF-SHA-384 and HMAC-SHA-384, the handshake transcripts, hybrid-signature digests, cookies, proof of work, resumption binder, rendezvous tags, mailbox location keys, DHT identifiers, the sealed box and the relay replay key use SHA-384, and the pin `identity_digest` is 48 bytes. Truncated outputs keep their length (reset token, beacon tag, cookie MAC); a field that carried a whole hash grows from 32 to 48 bytes (cookie, certificate hash, `chunkRoot`, chunk-leaf and proof hashes, `psk_binder`, `confirm`, `finished`, `expected_id_R`, kem_context 128 to 160 bytes). Keys stay 32 bytes. (4) New vectors `test-vectors/v3/pal3-v0.6-identifier-vectors.json` and SHA-384 cases in `pal3-v0.6-primitive-vectors.json`, both from `pal3-v0.6-sha384-generate.mjs`. (5) The transition rule for version 2 beacon tags and mailbox locations is removed: the network is under development and keeps no compatibility. Not wire compatible with 0.6.17.

**Changes in Draft 0.6.17** (2026-11-16): unlinkability is stated as a rule and the first-contact pair key is specified (hn2/pal-spec#49, hn2/pal-core#363, owner rule "the PAL network is pure P2P and anonymous"). No wire change. (1) §4: two pals that have never held a session derive a first-contact pair key from their identities alone (static X25519 between the two Ed25519 keys, mixed with both beacon keys once they are known), so the R1 tags and R3 mailbox locations of a new pair need no server and no prior handshake; the vector `test-vectors/v3/pal3-v0.6-pair-rendezvous-vectors.json` gives the beacon keys, both pair keys and three mailbox locations. (2) §4: DHT node identifiers are derived from the source address and fresh randomness, never from an identity key. (3) §14.4: the unlinkability rule; signed DHT records are limited to content its owner made public, because they carry the publisher's keys. (4) §14.9: what a DHT storing node learns.

**Changes in Draft 0.6.16** (2026-11-16): the last operations that carried an address are changed (hn2/palexplorer#1277, owner instruction "remove ip discovery"). The wire is not compatible with 0.6.15. (1) §8.5 item 3: `swarm.sources` takes `{ shareId, serve }` and answers entries `{ edPk, dsaPk }`; the fields `hints` and `observed` are removed, and a receiver ignores them if present. (2) §8.5 item 5 and the `live.*` operations: the request carries no `hints`, and the answer names the parent as `{ edPk, dsaPk }`. (3) §8.6: the share ticket body no longer has `hints`; a reader ignores the field in an older ticket and never dials an address from it. A peer found through any of these is reached by its public key, through the introduction of §14.2. Vectors regenerated: the `shareTicket` hashes and the `sources` entry keys of `pal3-v0.6-swarm-vectors.json`, and `pal3-v0.6-core-operations.json`.

**Changes in Draft 0.6.15** (2026-11-16): no address is exchanged, published or returned (hn2/palexplorer#1277, owner instruction "remove ip discovery"). Direct peer to peer stays the default; the connection is arranged by an introduction handled inside the transport. (1) §8.4 and §14.3: peer exchange is `{ peers: [{ peerPk }] }` again; a receiver ignores `host` and `port` in an entry. (2) §14.2 is now Introduction: a relay or common peer coordinates the simultaneous probes (§4.1, `buddy.intro`); the addresses that the coordination needs stay inside the transport and are never returned to an application, shown in an interface, written to a log or sent to a third peer. (3) §14.4: no DHT record, discovery registration, heartbeat or local-network beacon carries an address or a long-term key; a peer is found by its public key through a pair-derived mailbox, never by an address. (4) Error `E_PAL3_UNREACHABLE` is unchanged. Not wire compatible with 0.6.13 and 0.6.14 for peer exchange.

**Changes in Draft 0.6.14** (2026-11-15): the identifier rule is stated as a whole (§14.5): how each identifier is derived, that a short form is display-only and never an input to a lookup, and that BEP 10, BEP 44 targets and `btih` are not identifiers. Editorial for implementations that already follow 0.6.12 and 0.6.13; no wire change.

**Changes in Draft 0.6.13** (2026-11-15): direct by default. Draft 0.6.10 required a relay as the default path and allowed a direct connection only to own devices and by mutual consent; the protocol owner never approved that rule and it is withdrawn. (1) §14.1: a peer MUST attempt a direct path first, including NAT traversal; a relay introduces peers and carries a session only as an opt-in fallback or as the user's explicit privacy choice. (2) The operations `direct.consent` and `direct.endpoint`, the error `E_PAL3_DIRECT_NOT_ALLOWED` and the session flag `peerAllowsDirect` are removed. (3) §8.4 and §14.3: peer exchange carries `{ peerPk, host, port }` again so that swarm peers can connect to each other directly. (4) §14.4: publishing a reachable address in the DHT, in a discovery registration and on the local network is on by default, because peers must be able to find each other; the user can turn it off. Unchanged: full-length SHA-256 identifiers (§14.5), message delivery (§14.6), UDP only. Not wire compatible with 0.6.10 to 0.6.12 for peer exchange.

**Changes in Draft 0.6.12** (2026-11-15): SHA-256 is the only hash the protocol chooses; BLAKE2b is removed (`hn2/pal-core#352`). This draft is not wire compatible with 0.6.11. (1) Merkle leaves, nodes and the empty root (§8.1) and the 16 KiB chunk tree (§8.1.1) use SHA-256 with the same domain bytes and layouts. (2) The content identifier prefix changes from `pal3:b2t` to `pal3:s2t`. (3) Suite `0x0001` names SHA-256 as its hash. (4) DHT node identifiers, record targets and index targets are SHA-256 over the same inputs. (5) The sealed box of §15.4 is ephemeral X25519, HKDF-SHA-256 and ChaCha20-Poly1305, with the output order `E || ciphertext || tag`; its 48-byte overhead and every cell size are unchanged. (6) Vectors regenerated: `pal3-v0.6-primitive-vectors.json` (the `blake2b256` cases are replaced by `sha256` cases), `pal3-v0.6-onion2-vectors.json`, and the content identifiers in `pal3-v0.6-swarm-vectors.json`. Not changed by this draft: Ed25519 (SHA-512 inside, RFC 8032), ML-DSA-65 and ML-KEM-768 (SHAKE inside, FIPS 204 and FIPS 203), and the conversion of an Ed25519 seed to an X25519 key (SHA-512); these hashes are fixed by the algorithms.

**Changes in Draft 0.6.11** (2026-11-15): multi-hop relay cells are specified (§15), written from the reference implementation (`hn2/pal-core#337`): the capability `onion/2`, the fixed-size cell layout, the sealed box of each layer, relay processing with a replay key that excludes the padding, fragmentation, and what each party learns. New vector `test-vectors/v3/pal3-v0.6-onion2-vectors.json`. Additive: a peer without `onion/2` sees no change.

**Changes in Draft 0.6.10** (2026-11-15): relay by default, mutual direct consent, address-free peer exchange and full-length SHA-256 identifiers (§14). Peer exchange (§8.4) no longer carries addresses; a peer that still sends them is ignored. New operations `direct.consent`, `direct.endpoint` and `chat.deliver`, the mailbox location key and blob, a statement of what each party learns, and the vector `test-vectors/v3/pal3-v0.6-transport-vectors.json`. The wire form of `pex.exchange` changed in this draft.

**Changes in Draft 0.6.9** (2026-11-15): the private network profile is specified (§13): the profile object, the signed bytes under the context `palexplorer-private-network-v3`, administrator handover, the rules for accepting a profile (signature, version floor, expiry), behavior while a profile is active, lockdown, and a test vector `test-vectors/v3/pal3-v0.6-private-network-vectors.json`. Additive: a peer that does not use a private network sees no change.

**Changes in Draft 0.6.8** (2026-11-10): stateless reset for `c2-cid-v2` connections (§3.2). A responder that has lost its connection state can end a peer's connection quickly instead of leaving it to time out. The reset is sent only for connection IDs of the 8-byte form and a peer that does not implement it simply waits for its idle timeout as before.

**Changes in Draft 0.6.7** (2026-11-10): the LAN beacon tag includes the announcer's identity digest (§4, R1), so the two peers of a pair announce different tags, and §3.2 states the residual linkability of the first packet on a new path. The LAN tag changed in this draft; version 3 pair beacon keys had not shipped before it.

**Changes in Draft 0.6.6** (2026-11-10): the two directions of a pair use different mailbox locations (§4, R3), and `test-vectors/v3/pal3-v0.6-beacon-vectors.json` fixes the pair beacon key, LAN tag and mailbox location derivations, and `test-vectors/v3/pal3-v0.6-prekey-vectors.json` gives a signed prekey that must verify. Mailbox locations for pair beacon keys changed in this draft; version 3 pair beacon keys had not shipped before it.

**Changes in Draft 0.6.5** (2026-11-10): signed signaling prekeys, per-contact beacon keys, a handshake budget per source prefix, rekey limits and a constant-time requirement for long-term-key operations. Written from the reference implementation `@hn2/protocol`. Each change is negotiated or additive, and a peer that implements none of them sees no change.
- Added: §4.5 signed signaling prekeys. A device publishes short-lived, device-signed key pairs, and `SEALED_HELLO` and signaling blobs sealed to a prekey stay confidential after the static signaling key is compromised. New core operation `signaling.prekey` (§7.1), optional `SEALED_HELLO` tag `0x0004` (§5.1) and optional blob field `prekeyId` (§4).
- Changed: §4 R1 and R3. Beacon tags and mailbox locations derive from a pair beacon key that both peers compute from their own session, so one contact cannot follow a peer through another contact's key and removing a contact is a local operation. Draft 0.6.4 and earlier announced a single shared beacon key; both forms are accepted during a transition period.
- Added: §5.4 handshake budget per source prefix, applied after address validation and before any post-quantum operation.
- Added: §5.3 limits on peer-initiated rekeys and the end of the key epoch space.
- Added: §3.2 the initiator behavior when an `ACCEPT` fails to verify, so that one forged datagram cannot abort a connection attempt.
- Added: §11.2 item 7, a constant-time requirement for operations that use a long-term secret on input chosen by an unauthenticated party, and the ML-KEM encapsulation-key check.
- Editorial: references to private repositories and pull requests were removed from normative text.

**Changes in Draft 0.6.4** (2026-11-10): rotating 8-byte connection IDs, written from the reference implementation.
- Added: capability `c2-cid-v2`, packet types `0x04` and `0x05`, and frames `0x0C NEW_CONNECTION_ID` and `0x0D RETIRE_CONNECTION_ID` (§3.2, A.4, A.6).
- Changed: the statement that the connection ID never changes (§3.2). With `c2-cid-v2` both peers change connection ID when a path change is validated, so an observer of two paths cannot link a migrating peer by its connection ID. Peers without the capability see the Draft 0.6.3 wire format.

**Changes in Draft 0.6.3** (2026-11-10): C2 packet key update, resumption ticket contents and control padding, written from the merged reference implementation `@hn2/protocol`.
- Added: C2 packet type `0x03` and the capability `c2-key-update`: the C2 packet keys rotate with every record-layer rekey (§3.2, §5.1, §5.3, A.4, A.6). A peer that does not list `c2-key-update` sees no change.
- Changed: plaintext bulk records now require `c2-key-update` and carrier C2, and the statement that they have no forward secrecy is replaced (§6.2).
- Changed: the resumption ticket holds the SHA-256 hash of the initiator certificate and a resumption count instead of the certificate. Its lifetime is at most 24 hours, and a full handshake follows 7 consecutive resumptions (§5.5). The ticket is opaque to the initiator, so no message the initiator parses changes.
- Clarified: `CTRL` padding (§6.1) uses random bytes, covers every `CTRL` record after `READY`, and has three stated exceptions. `pad.v1` is advertised by default.
- Corrected: the authentication-failure limit in §3.2 is the 2^36 that the reference implementation enforces (the 0.6.2 text said 1,000,000).

**Changes in Draft 0.6.2** (2026-11-10): the specification is synchronized with the reference implementation `@hn2/protocol` 5.1.0. No wire change; every edit describes what the implementation already does.
- Added: §8.1.1 chunk-group verification and `file.outboard`; the `buddy.intro` punch start (§4.1); the BEP44 / Mainline DHT paragraph and the DHT and mailbox value bounds (§4, R3); the PEX wire form and quota (§8.4); §6.2 plaintext bulk records and capability `c2-bulk-plaintext-record` (A.6).
- Corrected: `CLOSE` frame layout and the `PATH_CHALLENGE`, `PATH_RESPONSE`, `STREAM_RESET` and `STOP_SENDING` frames (§3.2, A.4); the authentication-failure limit and the spoofed-packet statement (§3.2); the proof-of-work cap of 16 bits (§5.4); resumption ticket contents and lifetime (§5.5); the `addr.observe` quorum (§4.1 N3).
- Added statements on limits: what PAL/3 does not hide (§11.1), what a rekey does and does not restore (§5.3), and the sensitivity of the ticket key (§5.5).
- Editorial: references to private issue numbers and source file paths were removed.

**Changes in Draft 0.6.1** (2026-11-08): vectors `pal3-v0.6-primitive-vectors.json` for BLAKE2b-256, the Merkle tree and inclusion proofs (§8.1), the cookie and proof of work (§5.4), the resumption secret and binder (§5.5) and the manifest revision rules (§8.2), checked by a zero-dependency BLAKE2b in `validate.mjs`; the validator needs Node 24.7+ for ML-DSA-65.

**Also in Draft 0.6.1** (2026-11-08): capabilities `pad.v1` (`CTRL` records padded to 256-byte buckets, was a SHOULD) and `fec.v1` (C2 `REPAIR` frame 0x0B, XOR parity over 8 data packets); grant `bandwidth_bps` is enforced and `watermark` is declared unsettable (§9); ECN is explicitly not specified (A.4). §7.1 (new) specifies the payloads of `grant.request`, `grant.issue`, `grant.revoke`, `identity.state`, `rendezvous.forward`, `receipt.delivery` and the `swarm.v1` operations, with machine-readable `pal3-v0.6-core-operations.json` and signed-object vectors `pal3-v0.6-core-vectors.json`. The reference implementation serves them as of `@hn2/protocol` 5.1.0. Additive.

**Changes in Draft 0.6.0** (swarm offloading, 2026-11-05). Additive: a peer without `swarm.v1` sees no change.
- §8.5 (new): swarm offloading — owner-signed redistribution rule, proof of access before any byte from a non-owner, opt-in swarm membership with capped random `swarm.sources`, `E_BUSY` with retry-after and measured-only ranking, live relay tree join/leave/failover, capability `swarm.v1`.
- §8.6 (new): the share-link ticket is specified, with `redistribution`.
- §8.2, A.5: manifest key `redistribution`; swarm pass and ticket signed objects. A.6: token `swarm.v1` and the swarm error codes. §12.4: the local limits a swarm peer applies.

**Changes in Draft 0.5.2** (editorial corrections against the reference implementation, `@hn2/protocol` 5.0.0). No wire change; every correction describes what conforming peers already send.
- §3.2: congestion control and ACK frequency are local sender choices; path validation text matches the implementation (no connection-ID rotation, bounded challenges).
- §7: the `CREDIT` field is `credit`.
- §12.4: reduced to the normative rule. The settings and firewall catalogs were local implementation policy, not protocol.
- A.3: PAL-CBOR type bytes, limits, map key encoding and error codes corrected.
- A.4: `FR_CLOSE` layout corrected; frames `0x07`–`0x0A` added.
- A.5: record payloads aligned with §6.1; manifests and grants are PAL-CBOR maps, not TLV.
- A.6: capability tokens and package versions corrected.

**Changes in Draft 0.5.1** (2026-11-01):
- HELLO tag `0x0002` is a `suite_list`. A one-entry list is byte-identical to the Draft 0.5.0 `suite` field (§5.1, A.6).
- A normative cipher suite registry forbids classical-only suites (A.6).
- There is no 0-RTT early data. Tag `0x000B` in HELLO and tag `0x0008` in ACCEPT are not core tags, and a responder that issues tickets MUST keep a single-use cache (§5.5).
- §12.4 describes local transport settings that are not negotiated and cannot change the handshake.

## Conventions

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals. `||` is byte concatenation; `u16be`/`u32be`/`u64be` are big-endian unsigned integers; `HKDF-Extract`/`HKDF-Expand` are RFC 5869 with SHA-384 (HMAC-SHA-384), the hash of every registered suite (A.6).

## 0. Architectural Decisions

| # | Decision |
|---|---|
| D1 | Legacy BitTorrent/WebTorrent protocols (BEP 3, BEP 10, torrents, trackers, PEX, LSD, magnet links) are completely replaced by PAL/3.0. |
| D2 | **No raw TCP and no HTTP** in the P2P stack (`net`, `tls`, `http`, `http2` are forbidden in core). All peer traffic is UDP-based. |
| D3 | Post-quantum cryptography is mandatory: hybrid `X25519 + ML-KEM-768` (FIPS 203) key establishment and hybrid `Ed25519 + ML-DSA-65` (FIPS 204) authentication, verified strict-AND. Classical-only modes, classical-only pins and silent fallbacks are forbidden. |
| D4 | Granular capability permissions and byte-range media streaming are core protocol operations. Authorization is default-deny. |
| D5 | Core works with zero central servers (LAN multicast + endpoint cache + mutual-peer introducer + serverless WAN mailbox). Servers (TURN, rendezvous, discovery, `@handles`) remain optional extensions. |
| D6 | Portable cross-platform file-system metadata across Windows, macOS, and Linux is first-class (§10). |
| D7 | PAL/3.0 is a clean-slate binary wire protocol. Handshake frames use deterministic binary TLV (Appendix A); operation bodies use a deterministic binary codec (PAL-CBOR subset) with strict pre-allocation bounds. |
| D8 | Long-term identities never appear in cleartext on the wire, and rendezvous metadata is unlinkable without a contact's secret beacon key. |
| D9 | The core is small and closed. New features are extensions: comprehension-bit TLV tags, capability-negotiated operations and streams, hybrid-signed extension bundles, all outside the core codebase (§12). |

---

## 1. Protocol Objectives & Verification Targets

| ID | Objective | Acceptance Target | Verification Method |
|---|---|---|---|
| O1 | Zero TCP in P2P | Zero TCP sockets during any P2P operation; WebRTC ICE with `enableIceTcp: false` | Static import gate and packet capture. A runtime socket guard is not implemented yet. |
| O2 | Mandatory hybrid PQC | 100% of sessions use hybrid KEM + hybrid signatures (or a PSK derived from such a session, §5.5). Downgrade, replay, reflection, unknown-key-share, truncation, identity-misbinding and forged-block attacks are rejected | Deterministic vectors (Appendix A), adversarial fault-injection suite |
| O3 | High-throughput, low-latency | The handshake is 1-RTT before the initiator may send. Cold time-to-first-byte is ≤ 500 ms on a LAN, and a resumed session is ≤ 1 RTT plus one KEM. A single large file on 1 GbE reaches ≥ 100 MB/s over C2 | Multi-platform benchmark harness (loopback + LAN) |
| O4 | Serverless NAT traversal | ≥ 90% direct UDP across consumer/SOHO NAT pairings, and ≥ 99% with the end-to-end encrypted peer relay (N6) | Network-namespace NAT matrix |
| O5 | Cryptographic block integrity | Every 256 KiB block is verified against a hybrid-signed Merkle root before any disk write. No partially written file is ever visible under its final name | Bit-flip, leaf/interior swap, proof forgery, truncation tests |
| O6 | Granular capability grants | Default deny. Every operation is authorized against server-derived resources before the first byte and re-checked at every 256 KiB block. Revocation halts streams within one block | Permission matrix and mid-stream revocation tests |
| O7 | Low-latency media seek | Byte-range seek to first verified bytes is ≤ 300 ms on a LAN, and ≤ 1.5 s on a 20 Mbit/s, 50 ms RTT link | Media seek profiles |
| O8 | Cross-OS file-system fidelity | The portable metadata set (§10) round-trips. Incoming files receive quarantine / Mark-of-the-Web | 3-OS round-trip |
| O9 | Bounded memory & fuzz safety | Every parser rejects malformed input before unbounded allocation, and all per-peer state is capped (LRU + TTL). Memory is ≤ 256 MiB at 64 concurrent streams | Continuous fuzzing, soak tests |
| O10 | Identity privacy | Handshake frames carry no identity public key or certificate in cleartext. Beacon tags and mailbox keys are unlinkable without the beacon key | Packet-capture assertions (test suite) |

---

## 2. Protocol Layers

```
Extensions     signed bundles · capability-gated ops/streams · comprehension-bit TLV tags (§12)
Application    shares · permissions · file.read · media.stream · sync · chat · groups · receipts · MFT
Content        signed manifests · SHA-384 Merkle trees (256 KiB blocks) · resume bitmaps
Operations     request/response + streams · credit flow control · priorities · cancel
Records        ChaCha20-Poly1305 (IETF) per channel, direction and epoch · strict sequence numbers
Session        PAL/3 handshake (hybrid KEM + hybrid signatures, identity-protected SIGMA-I) · epochs · PSK resumption
Carrier        C1 WebRTC data channels (UDP: ICE/DTLS/SCTP) · C2 PAL-UDP (authenticated packets, congestion control)
Rendezvous     R1 LAN multicast · R2 endpoint cache · R3 serverless WAN mailbox · R4 mutual peer · R5 extensions
```

Each layer communicates only with its adjacent layers.

---

## 3. Carrier Layer

Both carriers deliver four independent, ordered, reliable byte channels per peer device pair. Channel `0` is `pal3/ctl`, channel `1` is `pal3/media`, and channels `2..3` are `pal3/bulk/0..1`. Records (§6) are carried unchanged on either carrier.

### 3.1 C1 — WebRTC DataChannels (Required)
- **Single-port UDP multiplexing:** Implementations SHOULD bind one UDP socket (`enableIceUdpMux`, default port `52474`, falling back to an OS-assigned port) with `enableIceTcp: false`.
- **Channels:** `pal3/ctl` (ID 0) carries the handshake, control, chat, permission events and diagnostics. `pal3/media` (ID 1) has a small send high-water mark of `clamp(RTT × bandwidth, 256 KiB, 1 MiB)` so seeks are never queued behind bulk data. `pal3/bulk/0..1` (IDs 2–3) use `clamp(RTT × bandwidth, 512 KiB, 4 MiB)`. All are ordered and reliable.
- **End-to-end security independent of DTLS:** DTLS is classical and terminates at relays, so every record is authenticated and encrypted end-to-end at the Record layer.

### 3.2 C2 — PAL-UDP (Normative)
C2 is a QUIC-style datagram transport over `dgram`.

**Handshake phase.**
- Handshake records (`HELLO`, `ACCEPT`, `COOKIE_REQ`, `SEALED_HELLO`) are sent in `INITIAL` packets: `type=0x01 (u8) || conn_id (u32be) || frag_index (u16be) || frag_total (u16be) || payload`.
- The fragment size is ≤ 1200 bytes, there are at most 64 fragments per handshake record, and reassembly is keyed by `(source address, conn_id)` (§11.2-3).
- The initiator retransmits `HELLO` with exponential backoff, starting at 250 ms with at most 5 tries. An `ACCEPT` that fails decapsulation, decryption or signature verification is dropped like any other unauthenticated datagram: the initiator keeps its ephemeral secrets and keeps waiting for a valid `ACCEPT` until the attempt times out, so a forged datagram cannot abort a connection attempt. The responder answers a retransmitted `HELLO` with the same `ACCEPT` it cached for that `conn_id`, holding it for at most 10 s.

**Address validation.**
- Before allocating any session state or doing any post-quantum work for a non-loopback source, a responder MUST validate the source address with the stateless cookie exchange in §5.4.
- Until validation completes, the bytes a responder sends to an address MUST NOT exceed 3× the bytes it received from that address.

**Protected packets.** After the handshake, every packet is a `PROTECTED` packet:
```
type (u8: 0x02, or 0x03 with c2-key-update) || conn_id (u32be) || protected_pn (4 bytes) || AEAD ciphertext || tag (16)
```
- The packet key and IV of packet key epoch `e` are `HKDF-Expand(prk, "pal3-c2-k-v1" || u16be(e) || dir, 32)` and `HKDF-Expand(prk, "pal3-c2-iv-v1" || u16be(e) || dir, 12)`, where `dir` is `"i2r"` or `"r2i"`. Epoch 0 uses `prk_0`. Epoch `e` > 0 uses `prk_e`, the record-layer key of the rekey that created record epoch `e` (§5.3), so the packet key epoch equals the record key epoch.
- **Key update (capability `c2-key-update`, §5.1).** When both peers list `c2-key-update`, every record-layer rekey (§5.3) also rotates the packet keys. The low bit of the packet type is the key phase: an even packet key epoch uses type `0x02` and an odd one uses type `0x03`. The type is part of the AAD, so the phase bit is authenticated. Without the capability, a packet of type `0x03` MUST be dropped and the packet keys stay at epoch 0 for the life of the connection.
  - The packet number is not reset by a key update, and the nonce rule below is unchanged.
  - The header-protection key (below) is derived once from `prk_0` and never rotates, so a receiver can unmask the packet number before it knows which epoch's key applies.
  - **Switching.** The rekey initiator switches its send direction to epoch `e + 1` as soon as it has derived `prk_{e+1}`. The rekey responder derives the same keys but keeps sending under epoch `e` until it receives the first authenticated packet of the new phase, because `rekey_resp` and the `REKEY` markers (§5.3) can still be queued and the peer cannot read them under keys it derives only after it has received them. That first authenticated packet also moves the responder's receive direction to epoch `e + 1`.
  - **Receiving.** A receiver holds the keys of at most three epochs: previous, current and next. A packet whose phase bit matches the current epoch is opened with the current keys. A packet with the other phase bit is tried against epoch `current + 1` if it is installed (a successful open advances the receive epoch) and then against epoch `current - 1` (a packet delayed across the change).
  - **Retirement.** After the receive epoch advances, the keys of the previous epoch are kept for `max(3 × PTO, 2 s)` so that delayed packets still open, and are then erased. Installing a fourth epoch erases the oldest at once. A sender erases the keys of its previous send epoch when it switches. A packet key update that fails closes the session.
- A connection closes after more than 2^36 packets that fail authentication (the RFC 9001 section 6.6 forgery limit for ChaCha20-Poly1305). The counter restarts at zero whenever the receive epoch advances.
- The nonce is `iv XOR (0^4 || u64be(pn))`. The AEAD is ChaCha20-Poly1305, with the unprotected header (the 1-byte type, the connection identifier and the unprotected `pn`, u32be low bits) as AAD. The connection identifier is `conn_id` in the 4-byte form and `dcid` in the 8-byte form below.
- Header protection follows the QUIC model. `hp_key = HKDF-Expand(prk_0, "pal3-c2-hp-v1" || u16be(0) || dir, 32)`, `sample` is the first 16 bytes of `ciphertext || tag`, and `mask = ChaCha20(hp_key, counter = u32le(sample[0..4]), nonce = sample[4..16])[0..4]`. The packet number is XORed with this mask.
- Packet numbers are 62-bit per direction and strictly increasing. The receiver reconstructs them from the low 32 bits around the largest acknowledged.
- Any packet that fails authentication is dropped silently. A single spoofed packet never tears down the connection and cannot acknowledge anything. Spoofed packets can close a connection only by exceeding the limit above.

**Connection IDs (capability `c2-cid-v2`).** The 4-byte `conn_id` is fixed for the life of a connection and appears in clear in every packet, so an observer of two network paths can link a peer that migrates between them. When both peers list `c2-cid-v2` (§5.1), each side issues 8-byte connection IDs to the other and every `PROTECTED` packet is addressed with one of them.
- **Header.** `type (u8: 0x04, or 0x05 under an odd packet key epoch) || dcid (8 bytes) || protected_pn (4 bytes)`. Types `0x04` and `0x05` correspond to `0x02` and `0x03` and follow the same key phase rule. The AAD is the 13-byte unprotected header `type || dcid || pn_low32`. Packet keys, header protection and nonces are unchanged. Handshake packets (`INITIAL`, `COOKIE_CHALLENGE`) keep the 4-byte `conn_id`.
- **Issuing.** Each side issues two connection IDs to its peer when the handshake completes, using `NEW_CONNECTION_ID{seq u32be, cid 8 bytes, reset_token 16 bytes}` (`0x0C`). Sequence numbers start at 0 and increase by one. An issuer chooses each ID at random and MUST NOT issue an ID that it already routes to any connection. The `reset_token` is carried and stored; stateless reset is not specified in this draft.
- **Using.** A side sends 4-byte-form packets until it has received the first `NEW_CONNECTION_ID` from its peer, and the 8-byte form afterwards. A receiver finds the connection by the `dcid` of an 8-byte-form packet and by `conn_id` for a 4-byte-form packet.
- **Retiring.** `RETIRE_CONNECTION_ID{seq u32be}` (`0x0D`) tells the issuer that the ID will not be used again. The issuer stops routing it at once and issues a replacement, so that two issued IDs stay active. A packet already in flight to a retired ID is dropped and recovered by loss detection.
- **Stateless reset.** The `reset_token` in `NEW_CONNECTION_ID` is `HMAC-SHA-384(reset_key, "pal3-stateless-reset-v1" || cid)[0..16]`, where `reset_key` is a 32-byte secret of the issuing responder; a responder that keeps `reset_key` across restarts can answer for connections it no longer knows. When a responder receives a protected packet of the 8-byte form for a connection ID it does not know, it MAY send one datagram that begins with the 8-byte-form packet type, is filled with random bytes, ends with the reset token for the received ID, and is at least 43 bytes and shorter than the packet that triggered it. A responder sends at most one stateless reset per source address per second. A peer that receives a datagram of at least 43 bytes in the 8-byte form whose last 16 bytes equal, in constant time, a reset token it holds for the connection closes the connection without further messages. No other datagram closes a connection. A reset cannot be forged without the token, which is delivered inside the encrypted connection.
- **Rotation.** When a path change is validated (below), both sides change ID: the validating side when the challenged address echoes its challenge, and the migrating side when it receives the `PATH_CHALLENGE` for its new path, once per challenged path. A side switches to the lowest-numbered unused ID that its peer issued and sends `RETIRE_CONNECTION_ID` for the one it leaves. When no unused ID is available the rotation is skipped and the current ID stays in use. The rotation happens after validation, so the first packets sent from a new address, up to the path challenge exchange, still carry the previous ID; an observer of both paths can link a migration through that short exchange, but not the connection before or after it.
- **Violations** (`E_PAL3_C2_FRAME`): a connection ID frame on a connection that did not negotiate `c2-cid-v2`, retiring a sequence number that was never issued, reusing a sequence number for a different ID, and a peer holding more than 4 unretired IDs of ours.
- A peer without `c2-cid-v2` never sees a packet type, header or frame defined in this paragraph.

**Frames.** A frame starts with a u8 type. Frame types: `0x01 PADDING`, `0x02 ACK{largest u64, ack_delay_us u32, ranges}`, `0x03 STREAM{channel u8, offset u64, len u16, data}`, `0x04 MAX_DATA{channel u8, max_offset u64}`, `0x05 PING`, `0x06 CLOSE{code u8, reason_len u8, reason utf8}`, `0x07 PATH_CHALLENGE{data 8B}`, `0x08 PATH_RESPONSE{data 8B}`, `0x09 STREAM_RESET{channel u8, final_size u64}`, `0x0A STOP_SENDING{channel u8}`, `0x0B REPAIR` (capability `fec.v1`), `0x0C NEW_CONNECTION_ID{seq u32, cid 8B, reset_token 16B}` and `0x0D RETIRE_CONNECTION_ID{seq u32}` (capability `c2-cid-v2`). A sender MUST NOT send a `CLOSE` reason longer than 128 bytes, and cuts it on a UTF-8 character boundary. Byte-exact layouts are in A.4.

**Reliability and congestion.**
- Loss detection and probe timeouts follow RFC 9002: a packet threshold of 3, a time threshold of 9/8 × max(SRTT, latest RTT), and PTO = SRTT + max(4·RTTVAR, 1 ms) + max_ack_delay. `max_ack_delay` is 25 ms.
- A receiver acknowledges at least every second ack-eliciting packet for the first 100 packets of a connection, then at least every tenth, and always within 25 ms. It acknowledges immediately on reordering or a gap.
- Congestion control is a local sender choice and does not affect interoperability. It MUST react to loss at least as conservatively as RFC 9002 §7 NewReno. The reference implementation starts each path with CUBIC (RFC 9438, β = 0.7, C = 0.4), an initial window of 10 × MSS and pacing. Its listener and dialer default to a mode that switches a path to BBR after two loss episodes classified as random when these outnumber the congestive ones; fixed CUBIC, BBR and NewReno are selectable. A new path restarts congestion control (RFC 9000 §9.4).
- A sender SHOULD occasionally skip a packet number and treat an ACK that covers a skipped or never-sent packet number as a fatal protocol violation (optimistic-ACK defense, RFC 9000 §21.4).
- Streams are reordered by offset, with a per-channel receive window advertised by `MAX_DATA`.

**Path validation and connection migration.**
- A `PROTECTED` packet from a new source address proves only that its sender holds the keys; the source may be spoofed. A receiver MUST keep sending on the current path until the new address is validated.
- **Path challenge:** the receiver sends `FR_PATH_CHALLENGE` with 8 random bytes to the new address. The peer echoes them in `FR_PATH_RESPONSE`. The connection moves only when the matching response arrives from that same address.
- **Bounded probing:** a receiver sends at most one challenge per max(SRTT, 50 ms) per connection and at most 3 challenges per candidate address. A peer queues at most 4 pending path responses.
- Without `c2-cid-v2`, `conn_id` does not change during a connection. With it, both sides change connection ID when a path change is validated (above).

**Efficiency.** Implementations SHOULD batch datagrams, using `sendmmsg`/GSO where available, and use one AEAD pass per packet. Handshake signature and KEM operations SHOULD run off the I/O thread (worker pool).

### 3.3 Record Sizing
`MAX_DATA_PAYLOAD = 65,536` bytes and `MAX_RECORD_WIRE = 65,572` bytes (a 20-byte header plus a 16-byte tag). A 256 KiB Merkle block is carried in at most four `DATA` records.

---

## 4. Rendezvous & NAT Traversal

A peer is identified by its **Identity Key** (`Ed25519` 32 B + `ML-DSA-65` 1,952 B), and each machine by a **Device Key** certified by the Identity Key. Each pair of peers shares a secret 32-byte **Pair Beacon Key**, derived on both sides from their own authenticated session: `pair_beacon_key = HKDF-Expand(exporter_secret_0, "pal3-pair-beacon-v1", 32)`, where `exporter_secret_0` is the epoch-0 exporter secret of §5.2. A full handshake replaces the stored key, and a resumed session (§5.5) keeps it. Because every pair has its own key, no contact can compute the tags that belong to another pair, and removing a contact deletes one key locally without involving anyone else. Draft 0.6.4 and earlier used a single **Beacon Key** shared with all contacts (version 2); see "Transition from version 2" below.

| ID | Mechanism | Normative Behavior |
|---|---|---|
| R1 | LAN multicast (`239.255.42.99:52473`) | Announces one 16-byte tag per announced contact: `tag = HMAC-SHA-384(HKDF-Expand(pair_beacon_key, "pal3-lan-v3", 32), announcer_identity_digest || u64be(floor(unix_sec / 900)))[0..16]`, where `announcer_identity_digest` is the identity digest of the announcing peer. The two peers of a pair therefore announce different tags, and an observer cannot link two addresses as contacts by intersecting their tag lists. An announcement carries the tags of at most the 64 most recently seen contacts in random order, followed by random 16-byte filler tags up to the next multiple of 16, so the tag count does not reveal the number of contacts. A contact holding the pair key matches a tag within ±1 epoch. Others cannot link tags, even if they know the identity public key. |
| R2 | Endpoint cache | Persists the last verified `(ip, port, family, lastSeen)` per device for direct reconnect. |
| R3 | Serverless WAN mailbox (PAL-DHT) | Stores sealed signaling blobs under `HMAC-SHA-384(HKDF-Expand(pair_beacon_key, "pal3-wan-mailbox-v3", 32), recipient_identity_digest || u64be(floor(unix_sec / 900)))`, where `recipient_identity_digest` is the identity digest of the peer that reads the mailbox. The two directions of a pair therefore use different locations, so a peer never reads back its own blobs, and every blob is sealed to its recipient. Stores MUST accept only well-formed sealed envelopes and MUST cap blobs per key, keys, and total bytes. Signed DHT record values are bounded at 30 KiB; mailbox blobs are bounded at 32 KiB. |
| R4 | Mutual peer introducer | Forwards sealed blobs over `pal3/ctl` (`rendezvous.forward`). It cannot decrypt or forge them. |
| R5 | Optional server extensions | Self-hosted rendezvous, `@handle` discovery, TURN. |

**First-contact pair key (normative).** Two pals that have never held a session have no `pair_beacon_key`. Each identity has a secret 32-byte **identity beacon key** `beacon = HKDF-SHA-384(ikm = ed25519_seed, salt = empty, info = "palexplorer-rendezvous-beacon-v1", 32)`, the same on every device of the identity, which it gives to a pal only in a pal code, an invite or a sealed blob. With `lo || hi` the two Ed25519 public keys sorted bytewise, `bLo || bHi` the two beacon keys sorted bytewise, and `X25519(own, pal)` computed from the X25519 forms of the own Ed25519 secret key and the pal's Ed25519 public key:

- `base = HKDF-SHA-384(ikm = X25519(own, pal), salt = lo || hi, info = "palexplorer-pair-rendezvous-v1", 32)`
- `full = HKDF-SHA-384(ikm = base || bLo || bHi, salt = lo || hi, info = "palexplorer-pair-rendezvous-beacon-v1", 32)`

Both pals compute the same keys; a third party who knows both public keys and both beacon keys cannot, because it lacks either X25519 secret. Until the first full handshake a pal uses `full` as the pair key of R1 and R3 when it holds the other beacon key, and `base` otherwise, and polls the locations of every pair key it holds. In these derivations the recipient and announcer are identified by their 32-byte Ed25519 public key, because the ML-DSA-65 key may not be known before the first session. After a full handshake the `pair_beacon_key` above replaces them. An X25519 result of 32 zero bytes MUST be rejected. Vector: `test-vectors/v3/pal3-v0.6-pair-rendezvous-vectors.json` (`base` = `de2f0a8d251b6494970ce3e4b53340d7d362d439d9b6649cb195b610383009e3`).

**DHT node identifiers (normative).** A PAL-DHT node identifier is derived from the node's source address and fresh random bytes (BEP 42 adapted to SHA-384) and is new on every start. It MUST NOT be derived from an identity key, a device key, a handle or any other long-term value.

**BEP44 / Mainline DHT (normative).** BEP44 storage nodes may reject values whose bencoded form exceeds 1,000 bytes; mutable items use Ed25519 signatures, while immutable items are identified by hash. An ML-DSA-65 signature alone is 3,309 bytes and does not fit in one interoperable BEP44 value. Any BEP44 / Mainline-DHT bridge MUST carry only opaque sealed pointers signed by beacon-derived Ed25519 keys and MUST NOT be treated as an authentication source. Post-quantum authentication happens inside the PAL/3 session. The 30 KiB bound in R3 limits the PAL-DHT value; hybrid signatures and message overhead are additional.

**Signaling blobs.**
- Replay-cache capacity is partitioned: senders the receiver does not know may use at most 25%, so free Sybil identities cannot lock out contacts.
- Every blob MUST be hybrid-sealed to the recipient's signaling keys and hybrid-signed by the sender. The sender seals to a current signed prekey of the recipient (§4.5) when it holds one, and to the static signaling keys otherwise. A blob sealed to a prekey carries an additional outer field `prekeyId` (8 bytes); a blob without it is sealed to the static keys, exactly as in Draft 0.6.4.
- A blob carries an outer `timestamp_ms`, bound into the AEAD AAD. Receivers MUST reject a blob outside ±5 min **before** any ML-KEM decapsulation or ML-DSA verification.
- The inner `(session_id, timestamp_ms)` MUST equal the outer values.
- The replay cache keyed on `(sender, session_id, signal_seq)` MUST NOT evict an entry while it is still live, and MUST cap entries per sender. When it is full of live entries, new blobs are refused (fail closed).

### 4.1 NAT Traversal Hierarchy (N1–N7)
1. **N1, IPv6 direct:** Use global unicast candidates (`2000::/3`, excluding the documentation prefixes `2001:db8::/32` and `3fff::/20`). An IPv4 address is global unicast unless it is in `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.168.0.0/16` or `224.0.0.0/4` and above; the IPv4 documentation ranges are not filtered. IPv6 link-local, unique-local and multicast addresses are not global unicast.
2. **N2, router port mapping:** Use PCP, NAT-PMP or UPnP-IGD for the muxed port, and detect CGNAT.
3. **N3, serverless reflexive discovery (`addr.observe`):** Connected peers report the caller's observed source. A reported address is accepted into the observation table only if it is global unicast and its port is 1..65535. The reported IP address is treated as confirmed only when at least 2 observers agree on it. Each observer identity holds one observation, and each observer source prefix (`/24` for IPv4, `/48` for IPv6) holds one observer. Observations expire after 10 min, and the table holds at most 64 observers (the oldest is dropped first). A single observation never meets the quorum. Implementations SHOULD prefer observations from contacts. The PAL-DHT node uses a stricter rule for its own external address: at least 3 distinct reporter prefixes (`/16` for IPv4, `/48` for IPv6) that report the same address, with entries kept for 30 min (an entry is gone at its 30th minute) and at most 64 entries (the oldest is dropped first, and one reporter prefix holds one entry). An address that is not global unicast, reported by a reporter that is not global unicast, needs no quorum (private networks).
4. **N4, simultaneous open:** Paced connectivity checks at 20 ms intervals; an implementation MUST NOT send them faster (at most 50 per second), whatever interval a caller asks for.
5. **N5, symmetric NAT port prediction:** Bounded probing with max 64 sockets (at most 64 distinct ports, each between 1024 and 65535, whatever bound a caller asks for) and ≤ 50 probes/s for 3 s.
6. **N6, end-to-end encrypted peer relay:**
   - The relay issues a hybrid-signed `RelayReservation`. Its fields are session ID, relay keys, the client's hybrid identity digest, issue and expiry times, byte quota and bandwidth cap (defaults: 15 min, 256 MiB, 2 MiB/s).
   - Verification MUST pin the relay identity and MUST bind the presenting client and session. The id of the presenting session is an input; a verification without a 16-byte session id fails (`E_PAL3_RELAY_INVALID`). The checks run in this order: session id given, token form (`E_PAL3_RELAY_INVALID`), relay pin (`E_PAL3_RELAY_ISSUER_MISMATCH`), client (`E_PAL3_RELAY_CLIENT_MISMATCH`), session (`E_PAL3_RELAY_SESSION_MISMATCH`), expiry (`E_PAL3_RELAY_EXPIRED`; a token is expired at `expires_at`), issue time more than 5 minutes ahead (`E_PAL3_RELAY_INVALID`), then both signatures (`E_PAL3_RELAY_AUTH_FAILED`). The relay MUST meter the quota and the rate per token, shared across all connections that present it.
   - The relay forwards opaque `RELAY{session_id, opaque_record}` frames.
   - The path upgrades to direct through authenticated `path.challenge`/`path.response` (an HMAC under the exporter secret that binds the candidate address) and `PATH_SWITCH{switch_id, last_seq}`.
7. **N7, TURN and UDP 443 fallback:** Optional (off by default).

**Clock-skew-free punch start (`buddy.intro`).** An introducer MUST NOT rely on the two peers' wall clocks agreeing. It measures its round-trip time to each peer (smallest of three `ping` round trips) and computes `lead = max(rtt)/2 + 50 ms` and, per side, `startInMs = lead - rtt_side/2` (RTTs clamped to 2,000 ms). Wire form: the initiator sends `buddy.intro { targetPk }` (64-hex identity key) and receives its plan as the response; the introducer sends the target `buddy.punch { sessionId, peerPk, dialHost, dialPort, punchAtMs, punchToken, startInMs }` at the same moment. Each side starts its probe burst `startInMs` after it *received* the plan, measured on its own clock; `punchAtMs` is the fallback for peers that do not send `startInMs`. `startInMs` is capped at 5,000 ms by the receiver.

### 4.2 Reachability Tiers & AutoNAT
- **High ID:** Inbound reachability is verified by port mapping or `autonat.dialback`. These peers can act as introducers (`buddy.intro`).
- **Medium ID:** The NAT uses endpoint-independent mapping, so peers can hole-punch.
- **Low ID:** Symmetric NAT, CGNAT or blocked UDP. These peers use N6 or N7.

### 4.3 Happy-Eyeballs Multipath
Candidates are raced in this order: `lan` > `direct_udp` > `stun_punch` > `udp_443` > `buddy_relay` > `turn_relay`. A relay-bound session migrates to a validated direct path with zero dropped bytes.

### 4.4 Identity Pins
A pin is `identity_digest = SHA-384("pal3-identity-v1" || ed25519_pk || mldsa65_pk)` (48 bytes). Every place that pins a peer MUST compare the full hybrid digest. This covers handshake target identities, manifest owners, grant issuers, signaling senders, diagnostic signers, relays and extension roots. Ed25519-only pins are forbidden (D3), because they would let a party that can forge Ed25519 substitute its own ML-DSA key.

---

### 4.5 Signed Signaling Prekeys

Sealing only to a static signaling key gives no forward secrecy: if that key is stolen later, every recorded `SEALED_HELLO` and signaling blob opens, and with them the candidate addresses and the record of who contacted whom. A device therefore publishes short-lived signed prekeys and keeps the static key as a fallback.

- **Prekey.** An X25519 key pair and an ML-KEM-768 key pair. The public part is the TLV `0x0001 x25519_pk (32 B)`, `0x0002 mlkem_ek (1,184 B)`, `0x0003 created_at_ms (u64be)`, `0x0004 expires_at_ms (u64be)`. `prekey_id = SHA-384(public TLV)[0..8]`.
- **Signed form.** A PAL-CBOR map `{ pub, sigEd25519, sigMldsa65 }`, where `pub` is the public TLV and both signatures are made by the device keys, verified strict-AND (D3), over `"pal3-prekey-v1" || SHA-384(pub)` with the ML-DSA context `pal3-prekey-v1`. A signed prekey is at most 16 KiB.
- **Lifetime.** A device creates a new prekey every 7 days. A prekey is valid for at most 14 days: a verifier rejects a prekey whose lifetime exceeds 14 days, that was created more than 5 minutes in the future, or that has expired. A device erases the secret keys of an expired prekey. A sender does not use a cached prekey in the last hour of its validity, so that it cannot expire while a message is in flight.
- **Distribution.** The core operation `signaling.prekey` (§7.1) is available to authenticated peers only and returns the device's newest signed prekey, or fails with `E_PAL3_UNSUPPORTED_OP` when the device has none. A sender verifies the prekey against the device certificate of the session and caches it per device.
- **Use.** A sender seals a `SEALED_HELLO` (§5.1) or a signaling blob to the prekey in place of the static signaling key, with the same key derivation, and names the prekey with its `prekey_id`. The responder looks the prekey up by id and rejects an unknown or expired id. Sealing without a prekey is byte-identical to Draft 0.6.4.

## 5. Session Handshake (1-RTT, Identity-Protected Hybrid SIGMA-I)

### 5.1 Wire Messages (on `pal3/ctl`, Deterministic Binary TLV)

```
HELLO   I→R (clear):  version_list, suite_list, nonce_I (32B), cookie (0|48B),
                      x25519_eph_I (32B), mlkem_ek_I (1184B), capabilities_I, [extensions]
ACCEPT  R→I (clear):  version (u16), suite (u16), nonce_R (32B), x25519_eph_R (32B), mlkem_ct (1088B),
                      encrypted_identity_R = ChaCha20-Poly1305(k_id, nonce = 0^12, aad = th_hs,
                          TLV{ device_cert_R, capabilities_R, revocation_version_R (u64), [extensions],
                               sig_ed25519_R (64B), sig_mldsa65_R (3309B) })
        sig_R signs "pal3-hs-v2-responder" || SHA-384(HELLO || ACCEPT_clear || identity_body_R)
FINISH  I→R (first encrypted record on pal3/ctl, epoch 0, seq 0, type CTRL):
                      device_cert_I, revocation_version_I (u64), expected_id_R (0|48B identity digest),
                      [extensions], sig_ed25519_I, sig_mldsa65_I
        sig_I signs "pal3-hs-v2-initiator" || SHA-384(HELLO || ACCEPT || finish_body_I)
READY   R→I (first encrypted record R→I on pal3/ctl): CTRL{op: "ready"}
```

**Suite negotiation.**
- `suite_list` lists the initiator's suites in preference order. The responder selects the first entry it supports and echoes it in ACCEPT `suite`. If no entry is supported, it aborts with `E_PAL3_DOWNGRADE`.
- The initiator MUST abort with `E_PAL3_DOWNGRADE` if ACCEPT names a suite it did not offer.
- Both signatures cover HELLO, so a stripped or reordered `suite_list` breaks authentication.
- Every suite in the registry is hybrid (A.6). No negotiation outcome can produce a classical-only session.

**Capability `c2-key-update`.** A peer advertises it by default. It takes effect only when both peers list it, and only on carrier C2: the C2 packet keys then rotate with every record-layer rekey (§3.2, §5.3).

Here `ACCEPT_clear` is the TLV of tags `0x0001..0x0006` of ACCEPT, `identity_body_R` is the encrypted identity TLV without its signature tags, and `finish_body_I` is the FINISH TLV without its signature tags.

**Identity protection.**
- A passive observer learns neither identity.
- The initiator reveals its identity only after it has authenticated the responder, so its identity is protected even against an active attacker.
- The responder reveals its identity to any initiator that completes the KEM. This is the same exposure as TLS 1.3 and Noise XX, and responders that need more SHOULD accept only `SEALED_HELLO` from known contacts.
- `SEALED_HELLO` (type `0x04`) hybrid-seals the HELLO to the responder's signaling keys, so it travels opaquely through relays. Its payload is the TLV `0x0001 eph_x25519_pk (32 B)`, `0x0002 mlkem_ct (1,088 B)`, `0x0003 ciphertext` (the HELLO and a 16-byte tag), and optionally `0x0004 prekey_id (8 B)`. The responder resolves the recipient keys by `prekey_id` when tag `0x0004` is present (§4.5) and uses the static signaling keys otherwise. A responder that accepts only known contacts and holds signaling keys SHOULD refuse a plain `HELLO` and accept only `SEALED_HELLO`.
- **`SEALED_HELLO` construction.** The initiator generates a fresh X25519 key pair (`eph_x25519_pk`) and encapsulates to the recipient's ML-KEM-768 key, giving `mlkem_ct` and `ss_pq`. The recipient keys are the prekey named by tag `0x0004`, or the static signaling keys when the tag is absent. Then:
  1. `ss_x = X25519(eph_sk, recipient_x25519_pk)`. An all-zero result MUST be rejected.
  2. `kem_context = eph_x25519_pk || recipient_x25519_pk || SHA-384(recipient_mlkem_ek) || SHA-384(mlkem_ct)` (160 bytes).
  3. `ikm = ss_x || ss_pq || kem_context` (224 bytes).
  4. `key || nonce = HKDF-SHA-384(salt = empty, ikm, info = "pal3-sealed-hello-v1", 44 bytes)`, where an empty salt means a string of 48 zero bytes (RFC 5869). `key` is the first 32 bytes and `nonce` the last 12.
  5. `ciphertext = ChaCha20-Poly1305-IETF(key, nonce, aad = eph_x25519_pk || SHA-384(mlkem_ct), plaintext = HELLO record)`, followed by the 16-byte tag. Tag `0x0003` carries it.
  The key and nonce are used once, because `eph_x25519_pk` and `mlkem_ct` are fresh for every message. A recipient that cannot open the record, or that does not hold the named prekey, drops it (`E_PAL3_HANDSHAKE_AUTH_FAILED`, `E_PAL3_HANDSHAKE_INVALID`). All intermediate secrets MUST be zeroized after use. The vectors are in `test-vectors/v3/pal3-v0.6-sealed-hello-vectors.json`.

### 5.2 Cryptographic Rules & Key Schedule
- **Strict-AND hybrid signatures:** Both `Ed25519` and `ML-DSA-65` (FIPS 204 context `"pal3-hs-v2"`) MUST verify, or the handshake aborts.
- **Device certificate:** Certifies the device Ed25519 and ML-DSA keys under the identity keys over `"pal3-devcert-v1" || SHA-384(cert_body)`, with FIPS 204 context `"pal3-devcert-v1"`. Self-bound single-device identities MAY use `flags = 0x01` (no duplicate device keys). The issue and expiry times are verified against the local clock, with ±5 min skew allowed for issue.
- **Key schedule (suite `0x0001`):**
  1. `ss_x = X25519(eph_sk, peer_eph_pk)`. An all-zero result MUST be rejected.
  2. `ss_pq = ML-KEM-768.Decaps(dk_I, mlkem_ct)` on the initiator, or `Encaps(ek_I)` on the responder.
  3. `kem_context = x25519_eph_I || x25519_eph_R || SHA-384(mlkem_ek_I) || SHA-384(mlkem_ct)` (160 bytes).
  4. `ikm = ss_x || ss_pq || kem_context` (224 bytes).
  5. `th_hs = SHA-384(HELLO || ACCEPT_clear)`, then `prk_hs = HKDF-Extract(salt = th_hs, ikm)`.
  6. `k_id = HKDF-Expand(prk_hs, "pal3-hs-id-v2", 32)`.
  7. `th = SHA-384(HELLO || ACCEPT)`, then `prk_0 = HKDF-Extract(salt = th, ikm = prk_hs)`.
  8. For each channel `ch_id` (0–3) and direction `dir` (`"i2r"` or `"r2i"`):
     - `key = HKDF-Expand(prk_e, "pal3-k-v1" || u16be(e) || u8(ch_id) || dir, 32)`
     - `salt = HKDF-Expand(prk_e, "pal3-s-v1" || u16be(e) || u8(ch_id) || dir, 4)`
  9. `exporter_secret_e = HKDF-Expand(prk_e, "pal3-exp-v1" || u16be(e), 32)`.

  `HKDF-Expand` is applied directly to the PRK, with no second Extract. All intermediate secrets MUST be zeroized after use.

- **Handshake SAS.** After a handshake, both sides can show a short authentication string for first-contact verification, derived from `exporter_secret_0` (step 9, epoch 0):
  1. `okm = HKDF-SHA-384(salt = "pal3-handshake-sas-v1", ikm = exporter_secret_0, info = "sas", 16 bytes)`.
  2. `digits` is `u64be(okm[0..8]) mod 10^8` written as 8 decimal digits with leading zeros.
  3. Word `i` (0 to 3) is `wordlist[okm[8 + i] & 0x3f]`. The phrase is the four words joined by `-`.
  4. The word list, 64 lowercase words, index 0 first:
  -  0 to  7: `amber`, `anchor`, `apollo`, `atlas`, `aurora`, `beacon`, `bison`, `breeze`
  -  8 to 15: `canyon`, `cedar`, `cobalt`, `comet`, `coral`, `cosmos`, `crystal`, `cypress`
  - 16 to 23: `delta`, `dolphin`, `dragon`, `dune`, `eagle`, `echo`, `ember`, `emerald`
  - 24 to 31: `falcon`, `fjord`, `flint`, `forest`, `frost`, `galaxy`, `garnet`, `glacier`
  - 32 to 39: `granite`, `harbor`, `horizon`, `husky`, `indigo`, `island`, `ivory`, `jade`
  - 40 to 47: `jasper`, `juniper`, `kestrel`, `lagoon`, `lantern`, `laurel`, `legend`, `lotus`
  - 48 to 55: `magnet`, `maple`, `marble`, `meadow`, `mercury`, `meteor`, `mirage`, `monarch`
  - 56 to 63: `nebula`, `nectar`, `nimbus`, `nomad`, `obsidian`, `ocean`, `olive`, `onyx`
  Two people compare the digits or the phrase out of band. The SAS is bound to the session keys, so a machine in the middle that holds two sessions shows two different codes. The code is a display value: it MUST NOT be used as a key or an identifier. Vectors: `pal3-v0.6-sas-vectors.json`, `handshakeSas`.

### 5.3 Rekey (`REKEY`)
**Triggers.**
- Implementations MUST rekey automatically at the soft limits: 2^31 records on a channel, 32 GiB in either direction, or 1 hour per epoch.
- `seal` MUST refuse at the hard limits: 2^32 records or 64 GiB.

**Who may trigger.** Only application records may trigger an automatic rekey. A pending exchange that gets no answer is abandoned after 30 s.

**Exchange.**
- The exchange is `rekey_init{epoch, x25519_eph, mlkem_ek}` / `rekey_resp{epoch, x25519_eph, mlkem_ct}` on `pal3/ctl`.
- It derives `prk_{e+1} = HKDF-Extract(salt = exporter_secret_e, ikm = ss_x' || ss_pq' || kem_context')`.
- **Limits.** A responder accepts at most 16 peer-initiated rekeys in any 60-second window; it checks the limit before any key generation, and the 17th closes the session (`E_PAL3_REKEY_RATE`). Only rekeys initiated by the peer count. The key epoch is a u16: a `rekey_init` for an epoch above 65,535 closes the session, and a side that has reached epoch 65,535 closes the session instead of sending a further `rekey_init` (`E_PAL3_EPOCH_EXHAUSTED`). At 1 Gbit/s and the 32 GiB trigger the epoch space lasts about 200 days; a peer then reconnects.
- A rekey is authenticated by the current session keys only. It restores secrecy against an attacker who obtained keys and then only observes, but not against one who stays active.

**Simultaneous rekey.** If both sides send `rekey_init` for the same epoch, the session initiator's exchange wins. The initiator ignores the peer's `rekey_init`. The responder abandons its own exchange and answers the initiator's.

**Epoch transition.**
- Each side sends `REKEY{new_epoch, last_seq}` as its final epoch-`e` record on each channel and resets `channel_seq = 0` for the new epoch.
- A `REKEY` marker can arrive before the receiver has installed epoch `e+1`, because channels are ordered independently. The receiver MUST then queue that channel's subsequent records, at most 1024, until the epoch is installed. Receiving the marker early MUST NOT be treated as an error.

**C2 packet keys.** With `c2-key-update` negotiated on carrier C2, installing record epoch `e+1` also derives the packet keys of epoch `e+1` from `prk_{e+1}` and flips the key phase of the C2 packet type (§3.2). The initiator sends under the new packet keys at once. The responder keeps its old send phase until it receives the first authenticated packet of the new phase.

### 5.4 Address Validation & DoS Shield
1. **Stateless cookies (mandatory for non-loopback sources).**
   - The cookie is `cookie = HMAC-SHA-384(secret_epoch, "pal3-cookie-v1:" || ip || ":" || port || ":" || conn_id || ":" || floor(unix_ms / 60000) || ":" || pow_bits)[0..14] || u8(pow_bits)`. It is carried in a 28-byte `PKT_COOKIE_CHALLENGE` (`0x06`) and echoed in the client's next INITIAL packets.
   - The difficulty is authenticated inside the cookie, so the server verifies the puzzle at exactly the difficulty it issued.
   - `secret_epoch` rotates every 2 minutes. The previous epoch is accepted.
   - Cookies are single-use per `(port, conn_id)`.
   - No session state or post-quantum operation is performed for an unvalidated source.
   - **Handshake budget.** After cookie validation and the capacity check, a responder counts handshakes per source prefix (IPv4 /24, IPv6 /48). The default budget is 30 handshakes per minute per prefix, and 0 disables it. A `HELLO` over budget is dropped silently and is not a violation. A `SEALED_HELLO` that opens under the responder's signaling keys is exempt, so known contacts are served first under load. The budget exists because a responder spends an ML-KEM encapsulation and an ML-DSA signature on every source that returns a valid cookie.
   - The HELLO-level `COOKIE_REQ` (`0x03`, 48-byte cookie over `SHA-384(HELLO without cookie)`) is an equivalent stateless retry for carriers without a pre-handshake packet exchange, such as C1.
   - **Address token.** After every completed handshake, the responder sends the initiator an address token in the `ticket` record (`CTRL{op: "resumption_ticket", ticket, addressToken}`). On its next connection to the same responder the initiator MAY present the token in the cookie slot of its first INITIAL packets instead of a cookie, which saves the cookie round trip. The token proves return-routability of the address, as a cookie does, so it does not weaken the rule above; it is not a way to skip it.
     - Format: 16 bytes, `token = HMAC-SHA-384(token_key, "pal3-addrtoken-v1:" || ip || ":" || bucket || ":" || nonce)[0..11] || nonce (4 bytes) || 0x80`, where `ip` is the normalised source address, `bucket = floor(unix_ms / 21,600,000)` (6 hours) and `nonce` is 4 random bytes. The last byte `0x80` is a value no cookie can have, because the last byte of a cookie is `pow_bits` (at most 16).
     - Lifetime: the responder accepts a token of the current and the three previous buckets, so it is valid for 18 to 24 hours. It is bound to the IP address and not to the port (a NAT can rebind the port).
     - Single use: the responder spends each token once and remembers spent tokens for 24 hours. A token that is forged, expired, spent or presented from another address is treated as no cookie, and the responder answers with a normal challenge.
     - Proof-of-work: while `pow_bits` is above 0 the responder ignores the token and challenges as usual, so one solved puzzle does not buy a chain of puzzle-free handshakes.
     - `token_key` is secret to the responder. A responder that restarts without a persistent key invalidates all tokens, and clients fall back to the cookie.
2. **Anti-amplification.**
   - A 28-byte challenge is smaller than any INITIAL packet (≥ 33 bytes), so challenges cannot amplify. Pre-validation replies are limited to 3× the received bytes.
   - Challenge budgets exist only to stop non-amplifying reflection. They MUST be generous enough that spoofed floods cannot starve legitimate clients of challenges (per source ≥ 1024 per 10 s).
3. **Adaptive proof-of-work.**
   - Under load, `pow_bits` scales from 12 upward, adding 1 bit per doubling of the handshake rate beyond the trigger, up to a cap of 16 bits.
   - The solution must satisfy `SHA-384("pal3-pow-v1" || cookie || u32be(conn_id) || u32be(pow_nonce))` ≥ `pow_bits` leading zeros.
   - A wrong solution is dropped and is not counted as a violation.
   - Clients MUST refuse `pow_bits` > 16 (`E_PAL3_POW_TOO_HARD`) and answer at most 3 challenges per connection attempt, because challenges are unauthenticated.
   - A dialer that receives a challenge above 16 bits MUST NOT solve it. Because a challenge is unauthenticated, it MUST NOT abort the attempt at once either (an injected challenge would otherwise end every dial): it ignores the challenge, keeps its retry schedule, and if no `ACCEPT` arrives before the attempt times out it ends the attempt with `E_PAL3_POW_TOO_HARD` instead of a plain timeout. The solver functions of a library throw `E_PAL3_POW_TOO_HARD` at once.
   - Proof-of-work raises the cost of single-host floods. It is not a defense against botnets.
4. **Trusted allowlist.** Addresses of known contacts skip proof-of-work only, never the cookie, because an IP address can be spoofed.
5. **Blackholing.**
   - Only cookie-validated (return-routable) sources, or authenticated session peers, may accumulate violations and be blackholed (20 within 10 s, giving a 15 min ban). Packets from unvalidated sources are dropped and never counted.
   - Per-source state is an LRU + TTL map keyed by IPv4 address or IPv6 `/64`.
   - A C2 responder holds at most 16 connections per source key, including handshakes in progress. A connection that does not complete FINISH within 10 s is closed.
   - Libraries MUST NOT modify OS firewall rules themselves. A host application MAY do so, but MUST NOT block loopback.
6. **Port hopping.** A host MAY rotate its UDP port under sustained floods and notify contacts over encrypted signaling.

### 5.5 PSK Resumption
After a full handshake, the responder MAY issue a `ticket` on `pal3/ctl`:
```
ticket = nonce (12) || AEAD(ticket_key, aad = "pal3-ticket-v1",
                            TLV{ 0x0001 resumption_secret (32B), 0x0003 issued_at (u64be ms), 0x0004 expires_at (u64be ms),
                                 0x0005 certificate hash (48B), 0x0006 resumption_count (u8) })
certificate hash = SHA-384(the initiator's full `device_cert`, A.1)
resumption_secret = HKDF-Expand(prk_0, "pal3-res-v1", 32)
```
- The ticket carries the SHA-384 hash of the initiator's certificate, not the certificate. The responder keeps the full certificates of initiators that completed a full handshake in a bounded cache keyed by that hash (at most 4096 entries, least recently used evicted first, each held for 24 hours from the full handshake). A ticket whose certificate is not in the cache is ignored, and the responder completes a full handshake.
- `expires_at` is at most 24 hours after `issued_at`, whatever lifetime the issuer asks for.
- The plaintext holds exactly the tags `0x0001`, `0x0003`, `0x0004`, `0x0005` and `0x0006`, with lengths 32, 8, 8, 48 and 1 bytes. A responder MUST ignore (and complete a full handshake for) a ticket with another tag set, with a certificate instead of its hash, without a count, or whose `expires_at` is not after `issued_at` or is more than 24 hours after it. The cap is checked when a ticket is opened, not only when it is issued.
- `resumption_count` is 0 in a ticket issued after a full handshake. A ticket issued after a resumed handshake carries the count of the ticket that was used, plus one. A responder MUST ignore a ticket whose count is 7 or more and complete a full handshake, so at most 7 consecutive resumptions follow one full handshake.
A resuming initiator sends a `HELLO` carrying `psk_ticket` (tag `0x0009`) and `psk_binder` (tag `0x000A`), with fresh `x25519_eph_I` and `mlkem_ek_I`. `psk_binder` is `HMAC-SHA-384(HKDF-Expand(resumption_secret, "pal3-binder-v1", 32), SHA-384(HELLO without binder))`.

On a valid binder for an unexpired, unused ticket, the responder answers with a resumed ACCEPT. It carries `psk_accepted` (tag `0x0007`, u8 `1`) in the clear part and no certificate or signatures. Any other ticket is ignored, and the responder completes a full handshake from the same HELLO. The resumed schedule uses:
- `prk_hs = HKDF-Extract(salt = th_hs, ikm = ikm || resumption_secret)`, where `th_hs` covers ACCEPT_clear including `psk_accepted`.
- `encrypted_identity_R` carries `capabilities_R`, `revocation_version_R` and `confirm` (tag `0x0004`) `= HMAC(k_id, th_hs)`.
- FINISH carries `revocation_version_I` and `finished` (tag `0x0004`) `= HMAC(HKDF-Expand(prk_hs, "pal3-res-fin-v1", 32), SHA-384(HELLO || ACCEPT))`, with no certificate or signatures.
- Each side uses the peer certificate from the original session: the initiator keeps it, and the responder looks it up by the hash in the ticket. The certificate is re-checked for expiry.
- The ticket is delivered after every completed handshake, full or resumed, as `CTRL{op: "resumption_ticket", ticket}` on `pal3/ctl`.
- The ticket key rotates every 24 hours, and the responder accepts tickets sealed under the previous key. A ticket is usable for at most 24 hours, because `expires_at` is at most 24 hours after issue.
- A resumed handshake has no signatures. The ticket key and the resumption secret are therefore as sensitive as a device signing key for the ticket lifetime.

**Properties.**
- Fresh hybrid KEM shares keep forward secrecy and post-quantum confidentiality.
- Resumption remains visible to an observer: the `HELLO` carries `psk_ticket` and `psk_binder`, and the clear `ACCEPT` carries `psk_accepted`. Hashing the certificate in the ticket and counting resumptions do not hide that a resumption happened.
- Authentication carries over from the original hybrid-signed session.
- There is no 0-RTT data, so a replayed HELLO cannot produce a usable session. Data keyed only by `resumption_secret` would have no forward secrecy: a leaked ticket key or resumption secret would expose every recorded payload. Implementations MUST NOT add early data, including as an extension.
- Tickets are single-use. A responder that issues tickets MUST keep a bounded used-ticket cache until expiry, and MUST NOT accept tickets without one.

---

## 6. Record Layer

### 6.1 Wire Layout (20-Byte Header + Ciphertext + 16-Byte Tag)
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    type (u8)  |   flags (u8)  |         key_epoch (u16be)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        stream_id (u32be)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       channel_seq (u64be)                     |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      payload_length (u32be)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   ciphertext (payload_length bytes)          ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        poly1305_tag (16 bytes)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
- **AAD:** The 20-byte header. **AEAD:** ChaCha20-Poly1305 (RFC 8439).
- **Nonce:** `salt (4) || u64be(channel_seq)`. Keys and salts are distinct per (epoch, channel, direction).
- **Strict monotonicity:** `channel_seq` MUST equal the expected value before any decryption or state change. Any gap or repeat aborts the session. Carriers are reliable and ordered, and C2 drops unauthenticated packets below this layer.
- **Bounds:** `MAX_DATA_PAYLOAD = MAX_CONTROL_PAYLOAD = 65,536` bytes and `MAX_HANDSHAKE_WIRE = 32,768` bytes. Lengths are checked before allocation.
- **Types:**
  - Unencrypted handshake frames: `0x01 HELLO`, `0x02 ACCEPT`, `0x03 COOKIE_REQ`, `0x04 SEALED_HELLO`.
  - Encrypted records: `0x10 CTRL`, `0x11 REQ`, `0x12 RES`, `0x13 DATA`, `0x14 END`, `0x15 CANCEL`, `0x16 CREDIT`, `0x17 ERROR`, `0x18 PING`, `0x19 PONG`, `0x1A REKEY`, `0x1B PATH_SWITCH`, `0x1C RELAY`, `0x1D CLOSE`.
- **Length rule:** `payload_length` is the plaintext length, and the wire record is exactly `20 + payload_length + 16` bytes.
- **Metadata:** On C1 the record header is inside DTLS, and on C2 it is inside the packet AEAD (§3.2). Only relays see record headers in the clear, through `RELAY` frames. `pad.v1` (A.6) is advertised by default. When both peers negotiated it, a sender MUST pad every `CTRL` record sent after `READY` by adding a byte string under the map key `pad` so that `payload_length` is a multiple of 256; a receiver ignores `pad`. The reference implementation fills `pad` with random bytes; the record is encrypted, so the content is not significant. Three cases are not padded: the handshake `FINISH` and `READY` records, which are TLV and not maps; a map that already contains a `pad` key, which is sent unchanged; and a map whose encoding is longer than 65,536 − 256 bytes, so that padding never exceeds `MAX_CONTROL_PAYLOAD`. Without `pad.v1` no `CTRL` padding is applied.

### 6.2 Plaintext bulk records (optional capability `c2-bulk-plaintext-record`)

This capability lets a sender omit the record AEAD on bulk data when the path is direct, because every block is verified against the signed Merkle root (§8.1) and C2 already encrypts and authenticates every packet (§3.2).

- **Flag:** record header flag `0x80` (`FLAG_PLAINTEXT`). A record with this flag has no 16-byte tag. Its wire length is `20 + payload_length`, and the payload follows the header unencrypted at the record layer. The `key_epoch` and `channel_seq` rules of §6.1 apply unchanged.
- **Where it is allowed:**
  - Only `DATA` records, and only on `pal3/bulk/0` and `pal3/bulk/1` (channels 2 and 3).
  - Only when both peers negotiated `c2-bulk-plaintext-record` and `c2-key-update` (A.6), and only on carrier C2. Without `c2-key-update`, or on any other carrier, `DATA` records are always sealed.
  - Only while the active path kind is `lan`, `direct_udp` or `stun_punch` (§4.3). A sender checks this before every plaintext record, and stops sending plaintext records as soon as the path stops being direct.
- **Receiver:** a receiver accepts plaintext `DATA` records only on a stream that it opened for a block or batch read verified against a trusted Merkle root. After the active path stops being direct, the receiver keeps accepting plaintext records that were already in flight for a drain window of 3 seconds. A plaintext record on trailing data of a stream the receiver already cancelled or finished is discarded while plaintext records are accepted at all (path direct, or inside the drain window); outside it the record closes the session like any other plaintext record. The drain window of a path change is `[t, t + 3 s)`, with `t` the time the path stopped being direct.
- **Errors:** any other plaintext record closes the session (`E_PAL3_PLAINTEXT_FORBIDDEN`). That includes the flag on a non-`DATA` record, on a channel other than `pal3/bulk/0..1`, without the negotiated capability, or outside the drain window on a non-direct path.

**Security considerations.**
- With this mode, bulk data is protected only by the C2 packet keys. When `c2-key-update` is negotiated, which this mode requires, those keys rotate with every session rekey (§5.3). Keys of an earlier epoch are erased after the retirement window in §3.2, so a later compromise of the current keys does not expose bulk data that was sent under erased keys. Bulk data sent between two rekeys shares one set of packet keys, so the rekey triggers of §5.3 bound the amount.
- The mode MUST NOT be used on carrier C1 or on any relayed path.

---

## 7. Operations & Credit-Controlled Streams

- **Requests:** Each request uses a directional `stream_id` (odd for the initiator, even for the responder, 0 for control), an ASCII operation name of ≤ 128 bytes, and a deterministic binary body.
- **Credit flow control:** Receivers grant credits with `CREDIT{credit}` (bytes granted). The initial window is 512 KiB per stream, auto-tuned up to 16 MiB from RTT × throughput. The cap is 64 MiB per connection across all streams. Sending beyond granted credit is fatal.
- **Core operations:** `share.list`, `share.manifest`, `share.browse`, `file.read`, `file.readBatch`, `media.stream`, `have`, `sources`, `pex.exchange`, `buddy.intro`, `autonat.dialback`, `path.challenge`, `path.response`, `identity.state`, `addr.observe`, `rendezvous.forward`, `signaling.prekey`, `device.revocation.push`, `device.revocation.get`, `device.list.push`, `device.list.get`, `sync.offer`, `sync.manifest`, `sync.push`, `sync.ack`, `wishlist.poll`, `access.request`, `access.resolve`, `quickdrop.offer`, `quickdrop.accept`, `chat.message`, `chat.receipt`, `group.invite`, `group.event`, `device.sync`, `grant.request`, `grant.issue`, `grant.revoke`, `receipt.delivery`, `presence`, `ping`.

### 7.1 Payloads of the Operations Defined Here

Request bodies and response results are PAL-CBOR maps (A.3). The machine-readable form is `test-vectors/v3/pal3-v0.6-core-operations.json`, and `npm run validate` checks that every name in the core list above is either specified there or served by the embedding product. In every operation the caller is the identity of the authenticated session; no body field names the caller. Handlers MUST fail closed: an operation whose backing state the node does not keep answers `E_PAL3_UNSUPPORTED_OP`.

| Operation | Request | Response | Rules |
|---|---|---|---|
| `grant.request` | `resource` (text ≤ 256), `operations` (1–8 permission verbs), optional `note` (≤ 256) | `requestId` (16 B), `status = "pending"` | Any authenticated peer. The node queues at most 8 pending requests per identity and 256 in total (`E_BUSY` beyond), and answers a repeat of the same resource and verbs with the same `requestId`. A request never grants anything. |
| `grant.issue` | `grant` (signed grant, A.5, ≤ 16 KiB) | `grantId`, `accepted` | The grant MUST verify (`E_PAL3_GRANT_AUTH_FAILED`), MUST be signed by the identity of this session (`E_PAL3_GRANT_ISSUER_MISMATCH`), MUST name this identity or `identity_key ‖ device_id` of this device (`E_PAL3_GRANT_INVALID`), and MUST NOT be expired (`E_PAL3_ACCESS_EXPIRED`). |
| `grant.revoke` | `grantId` (16 B) | `revoked` | Only the identity that issued the grant may revoke it (`E_PAL3_ACCESS_DENIED`). Revocation aborts active streams under the grant immediately (§9). An unknown `grantId` answers `revoked = false`. |
| `identity.state` | empty | `revocationVersion` (u64), `devices` (≤ 64 of `deviceId`, `name`, `addedAtMs`, `revoked`) | Only the same hybrid identity digest (§4.4) may ask (`E_PAL3_ACCESS_DENIED`). |
| `rendezvous.forward` | `to` (32 B identity key), `blob` (1–32768 B sealed signaling blob, §4) | `forwarded`, `duplicate` | The introducer (R4) forwards only to a mutual peer (`E_PAL3_ACCESS_DENIED`), never opens the blob, drops a blob it forwarded in the last 5 minutes (`duplicate = true`) and accepts at most 30 forwards per identity per minute (`E_BUSY`). |
| `signaling.prekey` | none | `prekey`: the newest signed signaling prekey of this device (§4.5), at most 16 KiB | Authenticated peers only (`E_PAL3_ACCESS_DENIED` otherwise). `E_PAL3_UNSUPPORTED_OP` when the device publishes no prekey. |
| `device.revocation.push` | `statement` (base64 text of a `revocation_statement`, A.1, at most 64 KiB) | `ok = true`, `applied` (bool), `version` (decimal text of the stored version) | Pals only. The statement MUST be signed by the identity that is trusted for this session and MUST verify (`E_PAL3_REVOCATION_ISSUER_MISMATCH`, `E_PAL3_REVOCATION_INVALID`). A version lower than or equal to the stored one is not applied (`applied = false`, `version` is the stored one). The table is bounded and answers `E_BUSY` for a new identity when full, and never evicts a statement. |
| `device.revocation.get` | empty, or `identity` (64 lowercase hexadecimal characters of an Ed25519 identity key) | `ok = true`, `statement` (base64 text, or null when none is held) | Pals only. An empty body returns the responder's own statement. |
| `device.list.push` | `list` (base64 text of a `device_list`, 11.4, at most 88 KiB) | `ok = true`, `applied` (bool), `revision` (decimal text of the stored revision) | Pals only, capability `seal.v1`. The sender MUST be the identity that signed the list. The list MUST verify against the identity trusted for this session (`E_PAL3_DEVICE_LIST_ISSUER_MISMATCH`, `E_PAL3_DEVICE_LIST_INVALID`, `E_PAL3_DEVICE_LIST_STALE`, `E_PAL3_DEVICE_LIST_ENCKEY_CHANGED`). A revision lower than or equal to the stored one is not applied. The table is bounded and answers `E_BUSY` for a new identity when full. |
| `device.list.get` | empty, or `identity` (64 lowercase hexadecimal characters of an Ed25519 identity key) | `ok = true`, `list` (base64 text, or null when none is held) | Pals only, capability `seal.v1`. An empty body returns the responder's own list. The caller verifies the answer as in 11.4 item 6 and does not trust the responder. |
| `receipt.delivery` | `receiptId` (16 B), `messageId` (≤ 64 B), `deliveredAtMs` (u64), `sigEd25519`, `sigMldsa65` | `accepted`, `duplicate` | The receipt is a hybrid-signed object (A.5, domain and ML-DSA context `pal3-receipt-v1`) over the PAL-CBOR map `{v: 1, receiptId, messageId, deliveredAtMs, recipientEdPk, recipientDsaPk}` with the keys of the session identity. `deliveredAtMs` may be at most 5 minutes in the future (`E_PAL3_INVALID_INPUT`). A bad signature answers `E_PAL3_AUTH_FAILED`. A repeated `receiptId` from the same identity is accepted once. |
| `swarm.prove`, `swarm.have`, `swarm.leaves`, `swarm.sources`, `live.join`, `live.leave`, `live.rejoin` | see §8.5 and the JSON file (`live.*` name the station with `stationId`) | see the JSON file (`live.join` and `live.rejoin` answer `{ depth, parent: { edPk, dsaPk } }` as in §8.5) | Require `swarm.v1` on both sides (`E_SWARM_NOT_NEGOTIATED`). Every operation except `swarm.prove` needs a proven session (`E_SWARM_PROOF_REQUIRED`). `swarm.leaves` returns at most 1024 leaf hashes per request. `swarm.sources` from a peer with `serve = true` opts that peer into the membership list under its session identity, never one named in the body. |

- **Extensions:** All other operations (for example `diag.*`, `buddy.relay`, `sign.*`, `msg.deliver`, `drop.offer`) are extension operations (§12), and each is registered with a capability and a permission verb.

---

## 8. Content Model & SHA-384 Merkle Trees

### 8.1 Domain-Separated Merkle Tree (256 KiB Blocks)
- **Blocks:** `BLOCK_BYTES = 262,144`, and `num_blocks = ceil(size / 262144)`.
- **Empty file:** `empty_root = SHA-384(0x02 || u64be(0))`.
- **Leaf:** `SHA-384(0x00 || u64be(index) || u32be(len) || block)`.
- **Node:** `SHA-384(0x01 || u8(level) || left || right)`. An unpaired rightmost node is promoted unchanged.
- **Content ID:** `pal3:s3t:<root-hex-96>:<size-decimal>`.
- **Pre-write verification:** Receivers MUST verify the index bounds, the exact length and the inclusion proof against the signed `(root, size)` before writing.

### 8.1.1 Chunk-Group Verification (optional)
Receivers MAY verify at 16 KiB granularity. This is additive: `pal3:s3t` content IDs and leaf hashes are unchanged, and receivers without a `chunkRoot` verify whole blocks as in 8.1.
- Chunks are 16 KiB; each 256 KiB block has a sub-tree over up to 16 chunk-leaf hashes, giving `blockChunkRoot_i`. `chunkRoot` is a binary Merkle tree over all `blockChunkRoot_i` (unpaired nodes promoted, as in 8.1).
- SHA-384 with domain bytes `0x10` chunk leaf (`0x10 || u64be(global_chunk_index) || u32be(len) || chunk`), `0x11` chunk node (`0x11 || u8(level) || left || right`), `0x12` block-chunk node (same layout). The empty-file `chunkRoot` is `SHA-384(0x12 || 0x00 || u64be(0))`.
- `chunkRoot` (48 B) is an optional field of a file entry in the hybrid-signed manifest (8.2), so the publisher signature binds it.
- Per block the sender supplies an outboard: the chunk-leaf hashes (up to 16 x 48 B) followed by the inclusion proof of `blockChunkRoot_i` in `chunkRoot` (about 0.2% overhead). The receiver MUST authenticate the outboard against the signed `chunkRoot` before using it, MUST verify each chunk's length, index and hash, and still verifies the completed block against its 8.1 leaf hash.

**Wire form.** Operation `file.outboard` (requires the same read permission as `file.read`): request `{ contentId, blockIndex }`, response `{ outboard }` where `outboard` is the chunk-leaf hashes (`ceil(blockLen / 16 KiB)` x 48 B) followed by the proof siblings of `blockChunkRoot_i` in `chunkRoot` (48 B each; counts are implied by the content size and block index). A sender without an outboard answers `E_PAL3_NO_OUTBOARD` (or `E_PAL3_UNSUPPORTED_OP` if it predates the operation); the receiver then falls back to whole-block verification. A receiver that holds a signed `chunkRoot` fetches the outboards of the requested block range before the `file.read`, rejects the read with `E_PAL3_CHUNK_OUTBOARD_INVALID` if any outboard does not authenticate against `chunkRoot`, and aborts the stream with `E_PAL3_CORRUPT_CHUNK` at the first 16 KiB chunk that fails, before the rest of the block is received.

### 8.2 Hybrid-Signed Manifests, Rollback & Equivocation
- **Signing:** Manifests are signed by the owner's hybrid identity under context `"pal3-manifest-v1"`. Each carries `revision_counter (u64)` and `author_device_id (48B)`. `author_device_id` is 48 opaque bytes chosen by the authoring device and kept constant for that device. It is not the 16-byte certificate `device_id` (§11.3) and a verifier does not check it against a certificate; it is compared bytewise only to detect equivocation and to order equal counters (below). RECOMMENDED: `SHA-384` of the author device's `device_cert`, so two devices of an identity never share one.
- **Rollback state:** Receivers MUST persist `(revision_counter, author_device_id, manifest_hash = SHA-384(body))` per share, and verification MUST be given this state, with "none" allowed only for a share seen for the first time.
- **Revision rules:**
  - A lower counter is a rollback.
  - An equal counter with an equal hash is the same manifest and is accepted.
  - An equal counter from the same device with a different hash is **equivocation** and is rejected.
  - An equal counter from different devices resolves to the larger `author_device_id`.
  - A counter jump > 2^32 is rejected.

### 8.3 Private Encrypted Shares (Encrypt-Then-Merkle)
- **File key:** `file_key = HKDF(share_key, salt = file_id, info = "pal3-file-key-v1", 32)`.
- **`file_id` uniqueness:** `file_id` is 16 random bytes and MUST be freshly generated for **every content version**. Block nonces are deterministic per `(file_id, index)`, so reusing a `file_id` for different content reuses nonces. Encrypted manifests MUST give every file entry a unique `file_id`. Receivers SHOULD track `file_id → content root` and reject reuse.
- **Block encryption:** Plaintext is split into `PRIVATE_PLAIN_BLOCK_BYTES = BLOCK_BYTES − 16` chunks. Chunk `i` is encrypted with `ChaCha20-Poly1305(file_key, nonce = "pal3" || u64be(i), aad = file_id || u64be(i))`, so each full ciphertext block is exactly one Merkle block. The Merkle tree is computed over the ciphertext, which lets holders verify blocks without the key.

### 8.4 Swarm, Deduplication, Preview, Upload Queue & PEX
1. **Swarm pieces:**
   - Piece hash lists MUST be bound to a trusted root before use. The piece Merkle root is domain-separated: the leaf is `SHA-384("pal3-piece-leaf-v1" || u64be(i) || h)`, the node is `SHA-384("pal3-piece-node-v1" || u8(depth) || l || r)`, and an unpaired node is promoted.
   - Peers sending corrupt pieces are struck and banned after 3 strikes.
   - In-flight pieces time out (30 s) and are released when a peer leaves.
2. **Local deduplication:** A verified local match is copied from disk with zero network bytes.
3. **Preview priority:** Piece 0 and piece N−1 are fetched first for media containers.
4. **Upload queue:** Requests are ranked by `wait × clamp(credit, 0.5, 10) × priority × (friend ? 5 : 1)`, with reserved friend slots.
5. **PEX (`pex.exchange`):**
   - A peer is registered by `peerPk` alone. A peer MUST NOT announce, and a receiver MUST NOT accept or store, a host or port from peer exchange. Third-party entries may add unknown peers; their self-reported High-ID and piece counts MUST be ignored for ranking.
   - Tables are bounded with a TTL.
   - **Wire form:** request `{ rootHash }` (64 hex), response `{ peers: [{ peerPk }] }` with at most 32 entries and no address fields (§14.3); `peerPk` is the peer's 64-hex identity Ed25519 key. Entries learned this way are unverified and attributed to the responding peer.
   - **Quota and promotion:** a table keeps at most 16 live unverified entries per reporter per swarm (extra reports are dropped). An entry is promoted to verified only after an authenticated session whose identity equals `peerPk` succeeds; an entry is dropped after 2 failed dials, timeouts or identity mismatches.

### 8.5 Swarm Offloading (`swarm.v1`)

Peers that hold verified pieces of a share MAY serve them to other peers, so the owner or a station server carries less. The mechanism below is wire protocol, so every client interoperates. How much a device serves is local policy (§12.4).

1. **Redistribution rule.**
   - The owner signs a `redistribution` key into the manifest body (§8.2, A.5) and into each share-link ticket (§8.6). Values: `none`, `pals`, `link-holders`. An absent or unknown value is `none`, so a manifest signed before this draft is never swarmed.
   - Defaults: a private (encrypted, §8.3) share is `none`; a share readable only by named pals or groups is `pals`; a public link share or a station is `link-holders`. The owner MAY lower the rule; it MUST NOT be wider than who may read the share.
   - The rule in force is the one in the newest manifest revision the seeder verified (§8.2). A peer MUST NOT serve pieces of, announce itself for, or list sources of a `none` share.
2. **Proof of access.** A non-owner seeder sends no byte of a share to a peer that has not proved access on the same session.
   - `swarm.pass` (owner → reader): the owner issues a swarm pass only to a peer its §9 rules allow to read the share. The pass is a hybrid-signed object (A.5) bound to the reader's full hybrid handshake identity (both holder public keys), valid for at most 10 minutes (60 s clock skew allowed).
   - `swarm.prove { shareId, kind, proof }` (requester → seeder): `kind` is `pass` or `ticket`. The seeder verifies the proof against the owner keys in its own verified manifest of that share — never keys supplied by the requester. A pass MUST carry both holder public keys and both MUST equal the session's authenticated handshake keys (§4.4); a pass naming only the Ed25519 key is invalid, because an Ed25519-only identity pin is forbidden. A `pals` share accepts only a pass; a `link-holders` share accepts a pass, or a valid unexpired ticket (§8.6) whose own `redistribution` is `link-holders`. The owner can therefore mint links that do not open the swarm.
   - A proof is bound to the session until its expiry or the end of the session. When the rule in force narrows, proofs that no longer qualify are dropped.
   - Swarm reads — `swarm.have`, `swarm.leaves`, `swarm.sources` and pieces via `media.stream` with resource `swarm:<shareId>:<contentId>` — without a proven session fail with `E_SWARM_PROOF_REQUIRED`. The owner keeps answering under §9 as before.
   - A seeder MUST rate-limit `swarm.prove` (at most 8 attempts per session per minute), because each attempt costs a hybrid signature check.
3. **Swarm membership (`swarm.sources`).**
   - Request `{ shareId, serve }`. `serve: true` announces that the requester serves this share; `serve: false` withdraws at once. Only peers that announced `serve: true` within the last 3 minutes are listed. A peer that only listens or downloads is never listed.
   - The answer holds at most 16 entries `{ edPk, dsaPk }`, drawn at random from the opted-in peers. It never contains the requester. A table holds at most 256 peers per share (LRU and TTL, §11.2).
   - A node answers a given (peer, share) at most once every 20 s; earlier requests get `E_BUSY` (item 4). A list therefore cannot be used to enumerate a station's listeners.
   - Answering requires the same authorisation as reading the share: §9 on the owner, a proven session (item 2) on a seeder. The PEX rules of §8.4 apply to the entries.
4. **Busy signal.**
   - `E_BUSY` carries `retryAfterMs`, clamped to 100…60 000. In the text-only `ERROR` record (A.5) the form is `E_BUSY: retry after <n> ms`. A seeder sends it when it has no free upload slot, is over its rate limit, or is paused by local policy; it does not say which.
   - The requester MUST NOT ask that peer again before `retryAfterMs` has passed, and SHOULD move the piece to another source at once.
   - Source ranking MUST use only values the requester measured itself: throughput of completed, verified pieces and the session RTT. Self-reported speeds, piece counts and High-ID claims are ignored. A requester SHOULD try the owner or station server only after the peers that have the piece.
5. **Live relay tree** (`live.join`, `live.leave`, `live.rejoin`, live stations).
   - `live.join { stationId, relay, capacity }`. The root assigns the joiner the shallowest node that opted in to relay (`relay: true`) and has a free slot. A node's fan-out is min(4, its offered `capacity`); the root's fan-out is its own choice. Depth is at most 8.
   - The join answer names only the joiner's parent `{ edPk, dsaPk }` and its depth. The root MUST NOT return the tree topology or other listeners' identities.
   - `live.leave`: the root moves the leaver's children, with their subtrees, to the shallowest free relays; a child that does not fit is told to join again later (`E_BUSY`).
   - Failover: a child that receives no chunk from its parent for 3 s sends `live.rejoin { lostParent }`. The root moves the child (and its subtree) under another parent and assigns the lost parent no new children for 30 s. Reports from two distinct children remove the lost parent. A node without a heartbeat for 15 s is removed.
   - A relay that cannot take a child answers it `E_BUSY`; the root then assigns another parent.
6. **Capability negotiation.** All `swarm.*` operations, `swarm:` resources and the relay fields above require the `swarm.v1` token on both sides of the session (A.6); otherwise they fail with `E_SWARM_NOT_NEGOTIATED`. The owner issues no pass to, and lists no source for, a peer without `swarm.v1`, and serves it through the normal `share.*`, `file.read` and `media.stream` operations. A client without swarm support keeps working.
7. **Errors:** `E_BUSY`, `E_SWARM_PROOF_REQUIRED`, `E_SWARM_PROOF_INVALID`, `E_SWARM_NOT_REDISTRIBUTABLE`, `E_SWARM_NOT_NEGOTIATED`. Each piece received from the swarm is checked against the manifest's Merkle root before it is played, cached or forwarded (§8.1, §8.4).

### 8.6 Share-Link Tickets

A share link (`pal3://share/<token>`) carries an owner-signed ticket. `token` is the base64url (no padding) PAL-CBOR map `{ body, sigEd25519, sigMldsa65 }`, signed with context `pal3-share-ticket-v1` (A.5), at most 16 KiB. `body` is `{ v: 1, shareId (48B), ownerEdPk (32B), ownerDsaPk (1952B), manifestRoot (48B, or empty), issuedAtMs (u64), expiresAtMs (u64), redistribution }`. A reader verifies both signatures and the expiry, and pins the owner keys from the ticket when it fetches the manifest. An optional `#k=` fragment carries a share key and is never sent on the wire.

---

## 9. Capability Permissions Engine

- **Subjects:** `identity`, `device`, `group`, `link-capability` (bound to the first authenticated claimant), `password` (Argon2id-wrapped share key), `anonymous`.
- **Operations:** `list`, `read`, `stream`, `write`, `delete`, `reshare`, `chat`, `sync`, `relay`.
- **Constraints:** `expires_at_ms`, `not_before_ms`, `max_reads`, `max_bytes`, `bandwidth_bps`, `devices_max`, `time_window_utc`, `watermark`.
  - `expires_at_ms`, `not_before_ms` and `time_window_utc` are enforced at every block boundary, and a stream blocked on credit is aborted when the grant expires or its time window closes.
  - `bandwidth_bps` is a sender-side token bucket shared by all streams under the grant (burst capacity `max(bandwidth_bps, 64 KiB)`). A grant with value 0 is not paced. Revocation wakes a paced sender at once.
  - `watermark` MUST NOT be set: every block is verified against the signed Merkle root (§8.1), so a per-recipient mark inside the protocol would make the block fail verification. Issuers MUST NOT set it and verifiers MUST refuse a grant that does (`E_PAL3_GRANT_UNSUPPORTED_CONSTRAINT`). Watermarking is an application concern above the protocol.
- **Default deny:** A session without a permission manager MUST deny every request. Implementations MAY offer an explicit opt-out for trusted loopback testing only. Extension operations MAY declare `authenticatedOnly` (any handshake-authenticated peer, no grant), but only if they are cheap and reveal no personal data.
- **Server-derived resources:** For `file.read`, `media.stream` and `file.readBatch`, the authorized resource is derived by the server from the requested `contentId`: `root:<contentId>` plus the share paths that contain it. A client-supplied resource string is never trusted. Every file in a batch is authorized before any byte is sent.
- **Caller identity:** The caller's identity is always the handshake-verified certificate, never a value in the request body.
- **Grant issuers:** Grants MUST be verified against a pinned trusted issuer. Re-adding the same grant is idempotent: it keeps the usage counters and the link binding. A different grant with the same ID is rejected. Revocations persist even when the grant record is removed.
- **Evaluation order:**
  1. Deny list and revocation.
  2. An active signed grant matching the subject, operation and server-derived resource.
  3. Time-window and quota checks.
  4. Default deny.
  5. The lease is re-verified at every 256 KiB block.

---

## 10. Cross-Platform File-System Layer

1. **Path segments:** Receivers MUST reject:
   - empty segments, `"."` and `".."`;
   - segments > 255 UTF-8 bytes, and paths > 4096 bytes or > 128 levels deep;
   - `/`, `\`, `:` (drive letters and NTFS alternate data streams), C0/C1 control characters, DEL, and Unicode bidi overrides;
   - Windows reserved names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`, `CONIN$`, `CONOUT$`, `CLOCK$`, with or without an extension);
   - segments ending in a dot or a space.
2. **NFC & case collisions:** Paths are normalized to NFC and checked for case-insensitive collisions before extraction.
3. **No-symlink staging & atomic commit:** Data is staged to `.palpart-*` files with `.bitmap` resume state, tagged with quarantine / Mark-of-the-Web, flushed with `datasync()`, and atomically renamed.
4. **Versioning, ignore rules and stubs:** `.palversions/`, `.palignore`, `.palplaceholder`.
5. **Quick Drop SAS (commit-then-reveal):**
   - The sender sends `commitment = SHA-384("pal3-sas-commit-v1" || nonce_S)` in `quickdrop.offer`.
   - The receiver replies with `nonce_R` (32 random bytes).
   - The sender reveals `nonce_S`, and the receiver checks it against the commitment.
   - Both sides display `SAS = HKDF(exporter_secret, salt = "pal3-sas-v1", info = lp(sender_pk) || lp(receiver_pk) || lp(root) || lp(offer_id) || nonce_S || nonce_R, 8) mod 10^8`, where `lp` is a u32be length prefix. That is 8 digits.
   - A MITM holds two sessions with different exporter secrets and must commit before seeing the other nonce, so it succeeds with probability 10^-8 per attempt.

---

## 11. Diagnostics & Security Model

### 11.0 Diagnostics (`diag.v1`, extension)
- Encrypted `PING`/`PONG` records give SRTT = 7/8·SRTT + 1/8·R, RFC 3550 jitter, a loss ratio, and a quality tier.
- `diag.ping`, `diag.report` (hybrid-signed, context `"pal3-diag-v1"`) and `addr.observe` are `authenticatedOnly`.
- `diag.trace` forwards to other peers, so it requires a grant.

### 11.1 "Harvest Now, Decrypt Later" Threat Model
- **Session keys:** Every session key depends on both `ss_x25519` and `ss_mlkem768`. Breaking X25519 with a quantum computer is insufficient, because ML-KEM-768 (FIPS 203, Category 3) must also be broken.
- **Symmetric keys:** The 256-bit ChaCha20 keys keep about 128-bit security against Grover's algorithm.
- **Ephemeral secrets:** Ephemeral secrets are zeroized after derivation, and automatic rekey mixes fresh hybrid entropy. A later compromise of long-term keys does not reveal recorded sessions.
- **Identity metadata:** Identities and beacon tags are protected (§4, §5). Beacon tags and mailbox locations are derived per pair, so they cannot be linked across contacts, and signaling sealed to a prekey (§4.5) stays closed after the static signaling key is compromised, so recorded traffic does not reveal who talked to whom.
- **Password-only shares:** Shares protected only by a password rely on Argon2id. Passphrases SHOULD have ≥ 75 bits of entropy.
- **Limits:** PAL/3 hides identities and rendezvous tags. It does not hide that PAL/3 is in use, packet sizes, timing, or transfer sizes.

### 11.2 Normative Hardening Invariants
1. **Low-order points:** Every X25519 operation rejects all-zero shared secrets.
2. **Caller binding:** All operations bind the acting identity to the handshake-verified certificate.
3. **Datagram reassembly:**
   - State is keyed by `(source, message_id)`, with per-source (16) and global (128) caps. When a cap is reached, the oldest entry of that source (or of the table) is evicted. A frame of one fragment (`frag_total = 1`) needs no state. An identical retransmission of a stored fragment is ignored.
   - First write wins, and a conflicting duplicate fragment drops the message.
   - An inconsistent `total` drops only that packet.
   - Non-final fragments must be full-size, and entries expire after 5 s.
   - UDP servers MUST NOT allocate sessions for stray data packets.
4. **Revocation and credit bounds:** Revocation (section 11.3) cuts off a device as soon as a peer holds the signed list; it does not stop a party that holds the identity key. Peer credit is clamped to 16 MiB, both in the credit of a request and in the credit a `CREDIT` record adds (a negative credit counts as 0); a responder sends a Merkle block (256 KiB) whole, so a block goes out only when the credit left covers it. Block lengths and ranges are validated: `startBlock` and `endBlock` MUST be whole numbers with `0 <= startBlock <= endBlock < block count`, otherwise the request ends with `E_PAL3_INVALID_RANGE` and no data.
5. **URI validation and quarantine:** `pal://` parsers (the `pal3://share/<token>` link of §8.6 carries one base64url token and no path segments) reject decoded `/`, `\`, `:`, `.`, `..` and control bytes. Received executables are never launched directly, and they are stamped with Mark-of-the-Web.
6. **Bounded state:** Every peer-influenced table is bounded with LRU and TTL. This covers shield sources, bans, cookies, the replay cache, mailboxes, PEX, reflexive observations and reassembly.
7. **Constant-time long-term-key operations:** An operation that uses a long-term secret on input chosen by an unauthenticated remote party SHOULD run on a constant-time implementation. In this protocol those are ML-KEM decapsulation with a signaling key (`SEALED_HELLO`, signaling blobs) and the ML-DSA signature that a responder makes in every `ACCEPT`. An ML-KEM encapsulation key received from a peer MUST pass the FIPS 203 modulus check before use. The reference implementation uses the ML-KEM-768 and ML-DSA-65 of the platform runtime where the runtime provides them and a pure-JavaScript library otherwise.

### 11.3 Device Enrollment and Revocation

An identity is the Ed25519 and ML-DSA-65 key pair that names it (handle, pals, shares). A *device* is one machine of that identity. This section is normative for implementations that let one identity run on several machines.

1. **Per-device keys.** Each device MUST generate its own Ed25519 and ML-DSA-65 key pair and a random 16-byte `device_id` (it MUST NOT derive the `device_id` from the identity key). The identity key signs a delegated `device_cert` (`flags = 0x00`, Appendix A.1) that binds the device keys and the `device_id` to the identity. The device signs the handshake with its device keys; peers verify the delegated certificate against the identity key they already trust for that peer. The identity key, and with it the peer's trust, does not change.
2. **Enrollment and migration.** A device that has only used the self-certified form (`flags = 0x01`, `device_id` derived from the identity key) enrolls itself the first time it loads its identity: it generates device keys and a `device_id`, issues its own delegated certificate (the identity secret key is present on the device) and keeps the `device_id` for its lifetime. Certificates are renewed before `expires_at_ms` with the same `device_id`. Peers that have not been told about revocation continue to accept both forms.
3. **Revocation statement.** The identity signs a statement (Appendix A.1, `revocation_statement`) over `{identity_ed25519_pk, identity_mldsa65_pk, revocation_version (u64), issued_at_ms, revoked_device_ids}` with both algorithms (domain `pal3-revocation-v1`). `revocation_version` strictly increases with every change and `revoked_device_ids` is the full set (a later statement supersedes an earlier one; devices are never un-revoked by omission within the same version).
4. **Verification and storage.** A receiver MUST verify both signatures and that the statement issuer equals the identity key it already trusts for the sender (it MUST NOT accept a statement for another identity). It keeps, per identity, the statement with the highest valid version. A statement whose version is lower than or equal to the stored one MUST NOT be applied, so an old statement cannot roll a revocation back.
5. **Distribution.** The identity owner pushes its statement to connected peers (`device.revocation.push`, body `{ statement: base64 }`, the sender MUST be the identity itself) and answers `device.revocation.get` (body `{}` returns the statement of the responder's own identity; `{ identity }` returns the stored statement of that identity). A peer SHOULD request the statement of a peer identity when it connects, at most every ten minutes. Both operations require the caller to be a pal.
6. **Enforcement.** After the certificate is verified, in both handshake roles and before any application request, a peer MUST close the session when the certificate's `device_id` is in the stored `revoked_device_ids` of its identity. The session ends with `E_PAL3_DEVICE_REVOKED` (an initiator learns it before it sends FINISH; a responder closes before READY), also when the handshake is a resumption. Open grant leases of that device abort at the next 256 KiB block check (section 9). Once a receiver holds any revocation statement for an identity it MUST also refuse that identity's self-certified certificates, because their `device_id` cannot be revoked separately.
7. **`revocation_version` in the handshake.** A device advertises the highest revocation version it knows for its own identity in `revocation_version_R` / `revocation_version_I`; a receiver MAY refuse a lower value than it already holds for that identity (`E_PAL3_STALE_REVOCATION`).
8. **Security considerations.** Revocation removes a device's certificate, not the identity key. Because every device of an identity holds the identity key (needed to enroll devices and to recover), a party that extracts the identity key can enroll a new device with a new `device_id`; revocation cannot prevent that, and the identity SHOULD be replaced if the identity key may be exposed. Implementations MAY keep the identity secret key only on designated owner devices, in which case other devices hold only device keys and a certificate issued at pairing; this is outside the requirements above.

### 11.4 Sealing to an Identity and Its Devices

A device that was paired without the identity secret key (item 8 of 11.3) holds only its own device keys. Content that a sender seals to the identity key alone cannot be opened on that device, and a signature that the device makes with its device keys must not be weaker than one made with the identity key. This section defines one sealed object with one wrap per recipient, a signed list of the device encryption keys that a sender uses, and a hybrid signature made by a device. It is normative for implementations that advertise the capability `seal.v1` (A.6). The vector `test-vectors/v3/pal3-v0.6-multi-seal-vectors.json` holds the keys, sealed objects, lists, statements and signatures below and the rejected inputs.

1. **Device encryption keys.** A device MUST generate its own X25519 key pair and its own ML-KEM-768 key pair, separate from its signing keys and from the identity keys, and MUST NOT export the secret keys. The delegated certificate (A.1) carries the public keys in the optional extension tag `0xC010` (`x25519_pk || mlkem768_ek`, 32 + 1184 = 1216 bytes). The tag is in the comprehension-optional range (§12.1), so a verifier that does not know it still verifies the certificate. The identity has one more pair of encryption keys, which the identity owner publishes in the device list (item 5). The `key_id` of a pair is the first 16 bytes of SHA-384(`"pal3-enckey-v1"` || x25519_pk || mlkem768_ek). A sender MUST refuse an encryption key of the wrong length, an ML-KEM key with a coefficient not reduced modulo q (FIPS 203 modulus check, 11.2 item 7) and an X25519 key that is a low-order point (`E_PAL3_SEAL_KEY_INVALID`).
2. **`sealed_content` (A.1).** The sender picks a random 32-byte content key `ck` and derives `aead_key = HKDF-SHA-384(ck, salt = empty, info = "pal3-seal-key-v1", 32)` and `commitment = HKDF-SHA-384(ck, salt = empty, info = "pal3-seal-commit-v1", 32)`. The object carries `version = 1`, a `context` label (1 to 64 characters of `a-z`, `0-9`, `.`, `_`, `-`, starting with a letter or digit) that names what is sealed, the `commitment`, the wraps (item 3) and the ciphertext. The ciphertext is ChaCha20-Poly1305 IETF of the plaintext (at most 32 KiB) under `aead_key`, a 12-byte zero nonce (the key is used once) and the additional data `header_digest = SHA-384("pal3-seal-header-v1" || u8 version || u8 len(context) || context || commitment)`. The `context` and the `commitment` are thus bound to every wrap and to the ciphertext.
3. **One wrap per recipient.** Each wrap is `key_id (16) || x25519_eph (32) || mlkem_ct (1088) || wrapped_ck (48)`, 1184 bytes. The sender draws a fresh X25519 ephemeral key and encapsulates to the ML-KEM-768 key of the recipient, then derives `HKDF-SHA-384(ss_x25519 || ss_mlkem || kem_context, salt = empty, info = "pal3-seal-wrap-v1", 44)`, where `kem_context = x25519_eph || recipient_x25519_pk || SHA-384(recipient_mlkem_ek) || SHA-384(mlkem_ct)` (the pattern of 5.1). The first 32 bytes are the key and the last 12 the nonce of a ChaCha20-Poly1305 IETF seal of `ck` with the additional data `header_digest`. An all-zero X25519 shared secret MUST be refused. A sender MUST NOT reuse an ephemeral key or an encapsulation across wraps. Recipients are the identity key first, then devices in ascending `device_id` order, at most 16 and none twice (`E_PAL3_SEAL_TOO_MANY_RECIPIENTS`, `E_PAL3_SEAL_INVALID`).
4. **Opening.** A receiver MUST find the wrap whose `key_id` equals the `key_id` of a key it holds (`E_PAL3_SEAL_NO_RECIPIENT` when none does), decapsulate, derive the wrap key, open `ck`, recompute `commitment` from `ck` and compare it with the object's `commitment` in constant time, and only then open the ciphertext. A wrap that was addressed to the receiver and does not open, a commitment that does not match and a ciphertext that does not open all end with `E_PAL3_SEAL_AUTH_FAILED`. The commitment is what stops a sender from giving different devices different plaintexts under the same object: all wraps carry the one `ck`, and `ck` determines the commitment. A `context` other than the one the caller expects ends with `E_PAL3_SEAL_CONTEXT_MISMATCH`. Tags below `0x8000` that are not defined, an unsupported version, a wrap count that is not a multiple of 1184 bytes or is above 16, and a malformed TLV end with `E_PAL3_SEAL_INVALID`; an unknown tag in the critical range ends with `E_PAL3_UNSUPPORTED_CRITICAL_EXTENSION`.
5. **`device_list` (A.1).** The identity signs, with both algorithms (domain and ML-DSA context `pal3-devlist-v1`, strict AND), a list of `{identity keys, identity encryption keys, revision (u64), revocation_version (u64), issued_at_ms, expires_at_ms, capabilities, devices}`. Each device entry is `device_id (16) || x25519_pk (32) || mlkem768_ek (1184) || cert_expires_at_ms (u64)`, 1240 bytes, in strictly ascending `device_id` order, at most 15. `revision` starts at 1 and strictly increases with every change. A list is valid for at most 7 days, is refused when `issued_at_ms` is more than 5 minutes ahead of the receiver's clock (`E_PAL3_DEVICE_LIST_INVALID`) and is stale at `expires_at_ms` (`E_PAL3_DEVICE_LIST_STALE`). `capabilities` is the sorted, unique list of tokens that every listed device supports (for this section `seal.v1`). Only a device that holds the identity secret key can issue a list.
6. **Learning the list.** The server, a relay and a paired device are couriers and are never trusted. A receiver MUST verify the list against the identity it already trusts for that sender: the issuer keys must hash (A.5 identity digest) to that identity (`E_PAL3_DEVICE_LIST_ISSUER_MISMATCH`; a list names its own issuer and anybody can sign a list for a key pair of their own) and both signatures MUST verify. It keeps, per identity, the list with the highest valid `revision`. A list with a revision lower than or equal to the stored one MUST NOT be applied (`applied = false`), so an old list cannot roll a device back in. The identity encryption keys are pinned from the first valid list, or from a contact record the receiver already holds, and a later list with other identity encryption keys MUST be rejected (`E_PAL3_DEVICE_LIST_ENCKEY_CHANGED`); changing them needs a new identity pin, as for any identity key. When the receiver already holds the certificate of a listed device, the entry MUST carry the same encryption keys as the certificate extension, otherwise the whole list is rejected. The table is bounded, answers `E_BUSY` for a new identity when full and never evicts a list.
7. **Choosing recipients.** To seal, a sender uses the stored valid list of the receiving identity. The recipients are the identity encryption keys and each listed device whose `cert_expires_at_ms` is in the future and whose `device_id` is not in the revocation statement the sender holds for that identity (11.3 item 4). After `expires_at_ms` no device is added and the identity key alone is used. A sender MUST NOT add a device key that is not in a valid list, and MUST NOT take a key from a server answer that is not that list. A sender seals to a device only when the list `capabilities` include `seal.v1`. Otherwise it keeps the single-recipient form it used before.
8. **`device_signed` (A.1).** A device signs an object with its device Ed25519 key and its device ML-DSA-65 key (domain and ML-DSA context `pal3-devsig-v1`) over `u8 len(context) || context || body`, and attaches its certificate or only SHA-384 of it. A signature without the ML-DSA part is not a device signature (`E_PAL3_DEVICE_SIG_INVALID`). A verifier MUST check that the certificate matches its hash, that it is unexpired and verifies (`E_PAL3_CERT_EXPIRED`, `E_PAL3_CERT_INVALID`), that it belongs to the identity trusted for the signer (`E_PAL3_DEVICE_SIG_ISSUER_MISMATCH`), that the device is not revoked (`E_PAL3_DEVICE_REVOKED`, and for a self-certified certificate once any statement is held, 11.3 item 6) and that both signatures verify. A hash with no certificate attached or known ends with `E_PAL3_DEVICE_CERT_UNKNOWN`.
9. **Distribution.** The identity owner pushes its list with `device.list.push` (7.1, body `{ list: base64 }`, the sender MUST be the identity) and a peer answers `device.list.get`. A client SHOULD refresh the list of a peer identity when it connects, at most every ten minutes, and the owner re-issues the list at the latest after half of its lifetime and after every enrollment or revocation. Both operations require the caller to be a pal.
10. **Security considerations.** A malicious paired device holds no identity secret key, so it cannot issue a list or a revocation statement and cannot add itself or another device as recipient; it can only open what is sealed to its own key. A lying server can withhold or delay a list, in which case the sender uses an older valid list (until it expires) and then the identity key alone, which is the earlier behaviour; it cannot add a key, remove a revocation or roll a revision back. A revoked device keeps the keys it already had, so content sealed before the revocation stays readable on it; revocation protects content sealed after a sender holds the statement, and a revocation statement takes precedence over a list that still contains the device. Neither wire format reveals which recipient is which beyond the `key_id`, which is a hash of public keys.

---

## 12. Versioning & Extensions (Outside the Core)

PAL/3 keeps the core small and moves everything else into extensions. Extensions add TLV fields, operations, streams and handshake parameters without changing core code or breaking peers that do not implement them.

### 12.1 Comprehension-Bit TLV Tag Ranges
- **`0x0001..0x7FFF` — core tags.** An unknown core tag MUST abort with `E_PAL3_UNKNOWN_CORE_TAG`.
- **`0x8000..0xBFFF` — critical extension tags.** An unknown critical tag MUST abort with `E_PAL3_UNSUPPORTED_CRITICAL_EXTENSION`.
- **`0xC000..0xFFFF` — optional extension tags.** Unknown optional tags MUST be preserved in the transcript hash and signatures and surfaced to the application.
- **Placement:** Extension tags are allowed in HELLO, in the encrypted ACCEPT identity, in FINISH, and in device certificates.

### 12.2 Extension Registry & Hybrid Extension Signing (`PAL-EXT-SIG-V3`)
- **What an extension declares:** an ID, a capability, operations and stream handlers with permission verbs, handshake TLV tags, and lifecycle hooks. Operations are reachable only when the capability is negotiated, if declared, and the permission engine authorizes them (§9).
- **Signing:** Bundles MUST be signed with both Ed25519 and ML-DSA-65 (context `"pal3-ext-sig-v1"`) by a trusted root, or by a publisher holding a delegated `publisherCert` (`"pal3-ext-cert-v1"`). The publisher certificate scopes `allowedExtensions`, `allowedPermissions` and `expiresAtMs`.
- **Wildcards:** A bare `*` grant never matches any permission (least privilege), and wildcards never imply `exec:*` or `native:*`.
- **Signed bytes.** A bundle and a publisher certificate are PAL-CBOR maps `{ body, sigEd25519, sigMldsa65 }` (A.5 item 7). The message is `ascii(prefix) || SHA-384(body)`. For a bundle the prefix is `pal3-ext-bundle-v1` and the ML-DSA context is `pal3-ext-sig-v1`; for a publisher certificate the prefix is `pal3-ext-publisher-cert-v1` and the context is `pal3-ext-cert-v1`. Prefix and context differ here, unlike the objects of A.5 item 4. Both signatures MUST verify.
- **Trust.** A verifier accepts the signer when its keys equal a trusted root, or when `body.publisherCert` is a certificate issued by a trusted root whose subject keys equal the signer (`E_PAL3_EXT_CERT_MISMATCH` otherwise) and whose scope covers the bundle `id`, `name` and `permissions` (`E_PAL3_EXT_SCOPE_VIOLATION`, `E_PAL3_EXT_PERMISSION_VIOLATION`). A signer that is neither is refused (`E_PAL3_EXT_UNTRUSTED_SIGNER`); a bad signature gives `E_PAL3_EXT_AUTH_FAILED`.

### 12.3 Extension Isolation
- **Static analysis is not a boundary.** The static source analyzer is a linter. It rejects known escape patterns, such as `eval`, `Function`, computed imports, aliased `require`, module-loader internals and blocked modules, but it is **not** a security boundary.
- **The analyzer vectors record best effort.** The `analyzer` rows of `pal3-v0.6-local-policy-vectors.json` record what the reference linter rejects today. A linter that misses a row (for example an aliased `require`, WebAssembly, or module-loader internals) is not non-conformant, because the linter is not the boundary; a linter that flags more is also conformant. Permission matching is not best effort: a bare wildcard `*` in a grant never matches any permission — neither ordinary permissions nor exec-capable or native ones (`wildcardCoversOrdinary`, `wildcardNeverImpliesExec`, `wildcardNeverImpliesNative`).
- **Isolation is required.** Untrusted extension code MUST run in OS or process isolation: a separate process with Node's `--permission` model, or an equivalent sandbox without `child_process`, `vm`, `worker_threads` or native addons, and with only the file-system scope its permissions grant.

### 12.4 Local Settings and Policy

Implementations have local settings, such as pacing, compression, packet padding, resume journals and inbound or outbound firewall policy. These are not wire protocol and are not negotiated. A local setting MUST NOT change the handshake, the cipher suite, the key schedule or the record format, and turning one off MUST NOT weaken a session's cryptography. A local policy that refuses a peer or an operation does so with the normal error records (§6.1, §9).

A swarm peer (§8.5) typically offers these local limits; none is negotiated, and a refusal is always `E_BUSY` with the text `E_BUSY: retry after <n> ms` (`n` from 100 to 60000) and no reason, so the reason is not disclosed: upload rate overall and per peer; upload slots; piece-cache size; daily and monthly caps on metered networks (a phone SHOULD default to serving on Wi-Fi only); a battery threshold or serving only while charging; a per-share "do not share"; a privacy mode that serves nothing and announces nothing (`serve: false`); and using the owner or station server only as a last resort.

### 12.5 Versioning and Compatibility

This section is normative from the first version published as `1.0.0`. Drafts before `1.0.0` carry no compatibility promise: Draft 0.6.12 and Draft 0.6.18 each changed the wire incompatibly.

1. **Specification version.** The specification version is `MAJOR.MINOR.PATCH`. A PATCH change is editorial and changes no byte, label, hash or requirement. A MINOR change is additive only: it adds capability-negotiated extensions (§12.2) or comprehension-bit tags (§12.1), and an implementation of the previous MINOR keeps interoperating with it. A MAJOR change, or a new cipher suite identifier (A.6), is any change to bytes on the wire, to a hash function, to a domain label, or to a key-schedule input.
2. **Acceptance window.** After `1.0.0`, an implementation MUST accept peers that implement the previous MINOR for at least 90 days after a new MINOR is published.
3. **Stored state.** A change that invalidates state an implementation stores (device certificates, pins, resumption tickets, enrollment records, mailbox keys) MUST ship with an automatic migration that runs without user action, and with a conformance vector that holds the old stored form and the expected migrated form. A release that cannot migrate stored state MUST NOT change the wire.
4. **Rejection reasons.** The HELLO `version_list` and `suite_list` (§5.1, A.6) carry the offered versions and suites. A responder that finds no supported version or no supported suite in them MUST abort with `E_PAL3_DOWNGRADE` (§5.1). That is the only code defined for this case; this draft defines no separate code for an unsupported version. An initiator that receives `E_PAL3_DOWNGRADE` SHOULD tell the user that the other device runs an incompatible version and that both devices should be updated. A responder MUST NOT reveal its own version list in the abort.
5. **Changelog.** Every published version has a changelog entry that states two facts: wire compatible with the previous version (yes or no) and stored-state compatible with the previous version (yes or no).

### 12.6 Exit Criteria for Version 1.0.0

This checklist is unchecked until every line is true. A line is ticked only with a link to its evidence.

- [ ] An independent cryptographic review of §5, §6 and the key schedule is complete and every finding is resolved or accepted in writing.
- [ ] Every normative section has conformance vectors, and `npm run validate` passes.
- [ ] The cross-network run matrix and the 12-hour soak are recorded for the reference implementation (`hn2/palexplorer#1595`).
- [ ] A second implementation, or the native port, passes every vector and interoperates with the reference implementation.
- [ ] The rules of §12.5 are implemented and tested in the reference implementation, including the previous-release stored-state test.


---

## 13. Private Network Profile

A private network confines a client to one administrator's discovery servers, relays and members. One signed profile describes it. This section is normative unless marked informative. The vector `test-vectors/v3/pal3-v0.6-private-network-vectors.json` gives a profile, a handover, their keys and the exact signed bytes.

### 13.1 Profile Object

A profile is a JSON object with these fields. A hybrid v4 profile carries `adminDsaPublicKey` and `signatureMldsa65`; a legacy v3 transition profile omits both. A profile that carries `adminDsaPublicKey` without `signatureMldsa65`, or `signatureMldsa65` without `adminDsaPublicKey`, MUST be rejected (`E_PRIVATE_NETWORK_UNSIGNED`).

| Field | Type | Rule |
|---|---|---|
| `name` | string | At most 128 characters. |
| `admin` | string | 64 hexadecimal characters: the administrator's Ed25519 public key. |
| `adminDsaPublicKey` | string | Required in v4 (absent in v3): 3,904 hexadecimal characters (1,952-byte ML-DSA-65 public key of the administrator). |
| `discoveryServers` | array of string | 1 to 64 `https://` URLs. |
| `relays` | array of string | 0 to 64 entries, each `host:port` or an `https://` URL. |
| `members` | array of object | 0 to 10000 entries `{ publicKey, name, revoked }` (v3) or `{ publicKey, dsaPublicKey, name, revoked }` (v4): `publicKey` is 64 hexadecimal characters, `dsaPublicKey` is 3,904 hexadecimal characters (required for every active unrevoked member in v4; `null` is permitted only for legacy revoked entries without an ML-DSA-65 key), `name` is a string of at most 128 characters or `null`, `revoked` is a boolean. |
| `privacyMode` | string | `normal`, `enhanced` or `maximum`. |
| `issuedAt` | string | UTC time `YYYY-MM-DDTHH:MM:SS(.sss)Z`. |
| `expiresAt` | string | UTC time in the same form. It MUST be later than `issuedAt` and at most 366 days after it. An administrator signs a validity of 1 to 365 days. |
| `version` | integer | At least 1. |
| `networkId`, `networkCreator`, `networkNonce`, `networkCreatedAtMs` | string, string, string, integer | Optional, all or none. `networkCreator` is 64 hexadecimal characters, `networkNonce` is 64 hexadecimal characters, `networkCreatedAtMs` is a non-negative integer and `networkId` is 96 hexadecimal characters and MUST equal the network identifier of §14.5 computed from them; a profile where it does not is refused (`BAD_NETWORK_ID`, §13.7) whatever its signature. Signed (§13.2). |
| `signature` | string | 128 hexadecimal characters: Ed25519 signature by `admin` over the signed bytes (§13.2). |
| `signatureMldsa65` | string | Required in v4 (absent in v3): 6,618 hexadecimal characters (3,309-byte ML-DSA-65 signature by `adminDsaPublicKey` over the v4 signed bytes with ML-DSA context `palexplorer-private-network-v4`, §13.2). |

A profile file larger than 1 MiB MUST be rejected. While a profile is active its `privacyMode` takes precedence over the user's own setting.

### 13.2 Signed Bytes

**Hybrid v4 (`palexplorer-private-network-v4`, required for new profiles).** The signed bytes are the UTF-8 encoding of the context string `palexplorer-private-network-v4` followed by one line feed (`0x0A`), followed by a JSON text with no whitespace and with exactly this key order: `name`, `admin`, `adminDsaPublicKey`, `discoveryServers`, `relays`, `members` (each member as `publicKey`, `dsaPublicKey`, `name`, `revoked`, with a missing `dsaPublicKey` or `name` written as `null`), `privacyMode`, `issuedAt`, `version`, `expiresAt`, `networkId`, `networkCreator`, `networkNonce`, `networkCreatedAtMs` (each `null` when the profile has no value). `signature` is Ed25519 (RFC 8032) by `admin` over these bytes, and `signatureMldsa65` is ML-DSA-65 (FIPS 204) by `adminDsaPublicKey` over these bytes with ASCII context `palexplorer-private-network-v4`. Both signatures MUST verify (strict-AND, D3); if either fails or is missing, the profile MUST be rejected (`E_PRIVATE_NETWORK_BAD_SIGNATURE`). The administrator's hybrid identity pin (§4.4) is `SHA-384("pal3-identity-v1" || unhex(admin) || unhex(adminDsaPublicKey))`.

**Legacy v3 transition (`palexplorer-private-network-v3`) and no-downgrade rule.** For transition from Draft 0.6.22, a profile without `adminDsaPublicKey` and `signatureMldsa65` uses the context string `palexplorer-private-network-v3`, followed by one line feed (`0x0A`), followed by a JSON text with no whitespace and with key order `name`, `admin`, `discoveryServers`, `relays`, `members` (each member as `publicKey`, `name`, `revoked`, with a missing name written as `null`), `privacyMode`, `issuedAt`, `version`, `expiresAt`, `networkId`, `networkCreator`, `networkNonce`, `networkCreatedAtMs` (each `null` when absent), signed with Ed25519 by `admin`. A client that has never accepted a v4 profile for an administrator MAY accept a v3 profile during transition. Once a client has accepted a v4 profile for an administrator or network, it MUST record the administrator's hybrid identity `(admin, adminDsaPublicKey)` and MUST reject every subsequent v3 profile for that administrator or network (`E_PRIVATE_NETWORK_DOWNGRADE`), even if its `version` is higher; a subsequent v4 profile for the same `admin` MUST carry the same `adminDsaPublicKey` unless transferred by a valid v2 handover (§13.3). A change to any signed field, including `expiresAt`, invalidates the signature. Profiles signed with a context string earlier than `v3` MUST be rejected.

### 13.3 Handover

A handover moves the administrator role to a new key.

**Hybrid v2 (`palexplorer-private-network-handover-v2`).** It is a JSON object `{ name, from, fromDsaPublicKey, to, toDsaPublicKey, issuedAt, expiresAt, signature, signatureMldsa65 }`, where `from` and `to` are 64-hex Ed25519 public keys and `fromDsaPublicKey` and `toDsaPublicKey` are 3,904-hex ML-DSA-65 public keys. The signed bytes are the UTF-8 encoding of `palexplorer-private-network-handover-v2`, one line feed (`0x0A`), and a JSON text with no whitespace and the key order `name`, `from`, `fromDsaPublicKey`, `to`, `toDsaPublicKey`, `issuedAt`, `expiresAt`. `signature` is Ed25519 by `from` and `signatureMldsa65` is ML-DSA-65 by `fromDsaPublicKey` with ASCII context `palexplorer-private-network-handover-v2`. Both signatures MUST verify (strict-AND, D3). The lifetime (`expiresAt` minus `issuedAt`) MUST NOT exceed 30 days. `(from, fromDsaPublicKey)` MUST be the current administrator's hybrid identity. `(to, toDsaPublicKey)` MUST match an unrevoked member's hybrid identity in the active profile and MUST differ from `(from, fromDsaPublicKey)`. After a client has accepted one v4 profile signed by `(to, toDsaPublicKey)`, it MUST retire `(from, fromDsaPublicKey)` permanently and MUST reject every later profile that `from` or `fromDsaPublicKey` signs.

**Legacy v1 transition (`palexplorer-private-network-handover-v1`) and no-downgrade rule.** For a network still on a v3 profile, a handover MAY use `{ name, from, to, issuedAt, expiresAt, signature }` with signed bytes `palexplorer-private-network-handover-v1`, one line feed, and JSON key order `name`, `from`, `to`, `issuedAt`, `expiresAt`, signed with Ed25519 by `from`, subject to the same 30-day lifetime, unrevoked-member and permanent-retirement rules. Once a client has accepted a v4 profile for a network, it MUST require `palexplorer-private-network-handover-v2` and MUST reject any v1 handover (`E_PRIVATE_NETWORK_DOWNGRADE`).

### 13.4 Accepting a Profile

A client MUST accept a profile only when all of the following hold:
1. The signature verifies and the field rules of §13.1 hold.
2. `version` is greater than the highest version the client has seen from that administrator. This floor MUST survive leaving the network.
3. `expiresAt` is in the future, with no clock-skew allowance.
4. `issuedAt` is not more than 24 hours in the future.
5. The administrator is the current administrator, or a valid unexpired handover from the current administrator names it, or the user confirmed the administrator key or its peer hash out of band. A file from a different administrator than the current one is refused unless the user explicitly chooses to switch networks.

### 13.5 Behavior While a Profile Is Active

While a profile is active a client:
- MUST contact only the listed discovery servers and relays, over any protocol, and MUST refuse any other host (hosts are compared by name; a relay entered as `host:port` also covers `https://host`, and a subdomain or a longer name that contains a listed name is another host);
- MUST NOT use a public bootstrap list or a public DHT;
- MUST refuse a session, inbound or outbound, with a key that is not a member that is not revoked;
- MUST verify the stored profile again at least every 60 seconds, and a hand-edited stored profile MUST NOT widen access.

A stored profile that fails verification, or that has passed its `expiresAt`, MUST put the client in lockdown: no discovery servers, no relays and no members, so that it refuses instead of falling back to the public network. A lockdown ends when the client imports a newer valid profile from the same administrator.

### 13.6 Edge Cases

- **Same version, different signature.** If a profile has the same `version` as the stored profile from the same administrator and a different signature, the client MUST reject it as a conflict. The administrator signs a new version. The same version with the same signature is not newer and is rejected as older.
- **Future-dated `issuedAt`.** More than 24 hours in the future: reject.
- **Large file.** Larger than 1 MiB: reject, for profiles and for handovers.
- **The administrator's own expired profile.** On a device that holds the administrator key, an expired stored profile remains usable to sign a new profile and for nothing else.
- **Revocation.** Revocation reaches a member only through a newer profile. The version floor prevents replaying a profile from before a revocation.

### 13.7 Error Identifiers (informative)

The reference implementation reports these, each prefixed `E_PRIVATE_NETWORK_`: `UNSIGNED`, `BAD_SIGNATURE`, `BAD_NETWORK_ID`, `BAD_DATE`, `BAD_VALIDITY`, `EXPIRED`, `OLDER`, `CONFLICT`, `TOO_LARGE`, `OTHER_ADMIN`, `CONFIRM_ADMIN`, `ADMIN_MISMATCH`, `RETIRED_ADMIN`, `HANDOVER`, `DOWNGRADE`, `NOT_MEMBER`, `EGRESS` and `INVALID`.

### 13.8 Open Questions

- Automatic distribution of profiles: today a member obtains a new profile by file.
- Authentication of members to the discovery servers.
- Confidentiality of the member list: the profile lists member keys in the clear to every holder of the file.

## 14. Direct by Default, Introduction Without Addresses

This section is normative unless marked informative. It states which paths a peer may use to reach another peer, what may be exchanged to arrange a direct connection, which identifiers appear on the wire, and how chat messages are delivered. The vector `test-vectors/v3/pal3-v0.6-transport-vectors.json` gives the mailbox location key of §14.6.

### 14.1 Default Path and Transport

- **Direct first.** An implementation MUST try to reach a peer directly, peer to peer, and MUST use every direct method it has before any other path: the local network and NAT traversal by simultaneous UDP probes (§4.1), arranged by an introduction (§14.2).
- **UDP only.** The core protocol runs over UDP only. The single permitted exception is a browser that is linked to the user's own device, which MAY use a transport that a browser can speak.
- **Relay.** A relay MAY introduce two peers so that they can open a direct path. A relay MUST NOT carry a session unless the relay operator enabled it and the peer opted in, either as a fallback after every direct method failed or as the user's explicit choice. Carrying sessions is never the default.
- **No path.** If no direct path can be opened and the relayed path is not enabled, the attempt fails with `E_PAL3_UNREACHABLE`.

### 14.2 Introduction

A direct path is arranged by an introduction: a relay or a common peer tells both peers when to probe (`buddy.intro`, §4.1) and the two peers open the path. The addresses that the probes need are handled inside the transport only. An implementation MUST NOT return an address to an application, an application programming interface or a user interface, MUST NOT write an address to any log or error message, MUST NOT store an address except in the transport's own short-lived state, and MUST NOT send the address of one peer to any peer other than the one being introduced, and then only within the introduction. A direct connection necessarily reveals each peer's network address to the other at the network layer; the protocol adds no other disclosure.

### 14.3 Peer Exchange Without Addresses

The response of `pex.exchange` (§8.4) is `{ peers: [{ peerPk }] }` with at most 32 entries, where `peerPk` is 64 hexadecimal characters. A response MUST contain public keys only. A receiver MUST ignore any address field (`host`, `port`) in an entry, whether the sender is an old peer or not, and MUST register the entry by `peerPk` alone. It reads only the first 32 entries, skips an entry whose `peerPk` is not 64 hexadecimal characters, registers the key in lower case, marks an entry verified only when it equals the authenticated key of the sender of the response, accepts at most 16 unverified entries per reporter and swarm, and never lets a report about a known peer replace that entry. A swarm member reaches a registered peer through an introduction (§14.2). No operation of this protocol returns the address of a third party.

### 14.4 Address Records and Unlinkability

**Unlinkability.** No component may link a network address to an identity, a handle or a share. In any network the next hop learns an address; the rule is that nothing pairs that address with who the peer is or what it shares.

No DHT record, discovery registration, heartbeat or local-network beacon carries an address, a long-term public key, a handle or a name. A peer is found by its public key through the pair-derived mailbox (§4, §14.6) and the introduction of §14.2, never by a published address. Pal-to-pal rendezvous MUST use the mailbox at a pair location; the location is computable only by the two pals and the stored blob is sealed.

The one exception is a signed DHT record (kind `m` or `i`): it carries the publisher's Ed25519 and ML-DSA-65 public keys and is written with a token that proves the publisher's address, so the storing nodes can link the two. A peer MUST use signed records only for content whose owner made it public (for example a public share index), never to find, reach or describe a pal or a device.

### 14.5 Identifiers

Every identifier is the full 48-byte SHA-384 value (96 lowercase hexadecimal characters in text), on the wire, in storage and in a lookup key. There is no algorithm tag; a change of hash is a protocol version change.

| Identifier | Derivation |
|---|---|
| Peer identifier (peer hash) | `SHA-384("pal3-id-peer-v1" || 0x00 || identity_key)`, where `identity_key` is the Identity Key of §4: the 32-byte Ed25519 public key followed by the 1,952-byte ML-DSA-65 public key |
| File identifier | SHA-384 of the file content |
| Share identifier | the Merkle root of the manifest (§8.1) |
| Group identifier | `SHA-384("pal3-id-group-v1" || 0x00 || creator_peer_id || nonce || u64be(created_at_ms))`: `creator_peer_id` is the 48-byte peer identifier, `nonce` is 32 random bytes and `created_at_ms` is the creation time in Unix milliseconds |
| Network identifier | `SHA-384("pal3-id-network-v1" || 0x00 || admin_ed25519_pk || nonce || u64be(created_at_ms))`: `admin_ed25519_pk` is the 32-byte key of the administrator who created the network |

A name, a slug or a description is display text. It is not part of any identifier, so a rename never changes an identifier. The group and network creation record (creator, nonce, time) is signed by its creator; two records with the same identifier are the same object, and a record whose creator signature does not verify is rejected. A slug is an alias that MUST be unique among the networks a server lists, compared without regard to case.

A truncated form MAY be shown to a person and MUST NOT be used on the wire, as a map key, in a lookup or as a resource identifier; an input that is shorter than 96 hexadecimal characters is not an identifier and is rejected, never matched by prefix (a person's search box MAY match a prefix of 8 or more characters, and the match is resolved to the full identifier before any lookup). A 64-character value is not an identifier. SHA-1, SHA-256, MD5, BLAKE2 and BLAKE3 MUST NOT be used for identifiers. BEP 10, BEP 44 targets and `btih` info-hashes are not identifiers in PAL/3. The single exception to the hash rule is the message integrity mechanism inside the TURN standard (RFC 8489, RFC 8656) that the relay extension uses.

Values that are not identifiers stay as they are and are outside this section: signatures, session and capability tokens, challenges, ephemeral keys, message authentication codes and encryption keys.

### 14.6 Message Delivery

A chat message is delivered in one of two ways: in a session to the recipient, or through a mailbox.

| Operation | Request | Response | Rules |
|---|---|---|---|
| `chat.deliver` | `payload` (map, the end-to-end encrypted message), `timestamp` (integer) | `ok` (boolean `true`) | Accepted only from a pal of the recipient. A sender that is not a pal receives `E_CHAT_NOT_A_PAL`. A message larger than the blob limit below receives `E_MESSAGE_TOO_LARGE`. |

**Mailbox location key.** `locationKey = SHA-384(UTF-8("palexplorer-mailbox-v1\n" + recipientPublicKey + "\n" + dayIndex))`, where `recipientPublicKey` is 64 lowercase hexadecimal characters and `dayIndex` is `floor(unixSeconds / 86400)` written in decimal digits. The key is 48 bytes. It is distinct from the pair-derived mailbox location of §4 R3.

Test vector: for `recipientPublicKey` = 32 bytes of `0xab` (`abab...ab`, 64 characters) and `unixSeconds` = 1794744000 (2026-11-15T12:00:00Z), `dayIndex` = 20772 and `locationKey` = `b9ff47eaa7c505130ea28d99e0117afd9d184c0d0cfed8f798bc56b6c8173352e95159c1d9b1b1ac7c05c1a83f80d4f1`.

**Mailbox blob v2 (hybrid Ed25519 + ML-DSA-65, required for new senders).** The blob is the UTF-8 JSON text of `{ "v": 2, "from": senderPublicKey, "fromDsaPublicKey": senderDsaPublicKey, "timestamp": integer, "payload": object, "signature": hex, "signatureMldsa65": hex }`, where `from` is 64 lowercase hexadecimal characters (Ed25519 public key), `fromDsaPublicKey` is 3,904 lowercase hexadecimal characters (1,952-byte ML-DSA-65 public key), `signature` is 128 lowercase hexadecimal characters (64-byte Ed25519 signature), and `signatureMldsa65` is 6,618 lowercase hexadecimal characters (3,309-byte ML-DSA-65 signature). `payload` is already end-to-end encrypted. The signed bytes are the UTF-8 bytes of `palexplorer-mailbox-v2`, a line feed (`0x0A`), and the JSON text (no whitespace) of the object holding the fields in the exact order `v`, `from`, `fromDsaPublicKey`, `timestamp`, `payload`. `signature` is the Ed25519 signature by `from`, and `signatureMldsa65` is the ML-DSA-65 signature by `fromDsaPublicKey` with ASCII context `palexplorer-mailbox-v2`. Both signatures MUST verify (strict-AND, D3), and `SHA-384("pal3-identity-v1" || unhex(from) || unhex(fromDsaPublicKey))` MUST equal the pinned hybrid identity digest (§4.4) of the sending pal (`E_MAILBOX_IDENTITY_MISMATCH` otherwise). A v2 blob MUST NOT exceed 24 KiB (24,576 bytes; `E_MESSAGE_TOO_LARGE` otherwise).

**Legacy mailbox blob v1 transition and no-downgrade rule.** For transition from Draft 0.6.22, a `"v": 1` blob is `{ "v": 1, "from": senderPublicKey, "timestamp": integer, "payload": object, "signature": hex }` signed with Ed25519 by `from` over `palexplorer-mailbox-v1`, a line feed, and the JSON text (no whitespace) in key order `v`, `from`, `timestamp`, `payload`, at most 16 KiB. Once a recipient has received a valid `"v": 2` blob from a pal, or holds a pinned hybrid identity for that pal marked as v2-capable, the recipient MUST reject every subsequent `"v": 1` blob from that pal (`E_MAILBOX_DOWNGRADE`). A recipient reads the locations of the current day and the previous 6 days, verifies the signature (and hybrid pin for v2), ignores entries older than 7 days, and drops duplicates by `(from, timestamp, SHA-384(payload))`, so a message that arrives both in a session and through a mailbox is delivered once. A blob whose signature fails, is missing `signatureMldsa65` under `"v": 2`, or fails after a change to `timestamp`, MUST be dropped (`E_MAILBOX_BAD_SIGNATURE`).

A sender uses a mailbox only when no session can be opened. While a private network profile is active, the public DHT MUST NOT be used, so delivery is by session only and the message stays queued.

### 14.7 Edge Cases

- **Both peers behind address translation:** simultaneous UDP probes arranged by an introduction (§4.1, §14.2); if that fails, the relayed path is used only where it is enabled (§14.1).
- **Old peers that still send addresses in peer exchange:** the addresses are ignored (§14.3).
- **A registered peer that cannot be introduced:** it is dropped after repeated failures; it is never trusted without a pinned handshake.
- **Clock skew across a day boundary:** the 7-day read window covers it.

### 14.8 Error Identifiers (informative)

`E_PAL3_UNREACHABLE`, `E_CHAT_NOT_A_PAL`, `E_MESSAGE_TOO_LARGE`, `E_MAILBOX_BAD_SIGNATURE`, `E_MAILBOX_IDENTITY_MISMATCH`, `E_MAILBOX_DOWNGRADE`, `E_PAL3_RELAY_BLIND_MISMATCH`, `E_PAL3_RELAY_REPLAY`, `E_PAL3_RELAY_NOT_ENABLED`.

### 14.9 Privacy Considerations (informative)

- **The two peers** of a direct connection learn each other's network address at the network layer; no operation, record or interface hands it on.
- **A relay or common peer that introduces** two peers learns their addresses and that an introduction happened, and none of their traffic. A relay that carries a session also learns its timing and size, and no content.
- **A DHT node that stores or serves a mailbox blob** learns the address of the peer that wrote or read it and a location that changes every 900 seconds and names no one; it cannot open the blob. Two addresses that use the same location in the same epoch are visibly in contact, but neither identity is revealed.
- **Everyone else** learns nothing about an address: peer exchange, records, heartbeats and beacons carry none.

### 14.10 Sealed Relay Reservations and Multi-Hop Carried Sessions

Both mechanisms in this section are additive capability-negotiated extensions (§12.2, §12.5 item 1). Peers that do not negotiate them continue to use §4.1 N6 single-hop reservations unchanged. The vector `test-vectors/v3/pal3-v0.6-sealed-relay-vectors.json` gives valid and rejected cases for both extensions.

**Sealed relay reservations (`relay-seal.v1`).** To hide the reserving peer's long-term identity from the relay, a client advertising `relay-seal.v1` replaces the cleartext client identity digest of §4.1 N6 with a fresh per-reservation HMAC commitment and an AEAD-sealed accounting token:

1. **Blind client commitment.** For a 16-byte `session_id` and its own 48-byte hybrid identity digest `client_identity_digest` (§4.4), the reserving client generates a fresh 32-byte random blinding nonce `r_client` and computes `blind_client_id = HMAC-SHA-384(key = r_client, data = "pal3-relay-blind-v1" || 0x00 || client_identity_digest || session_id)` (48 bytes). The client MUST send only `blind_client_id` to the relay and MUST NOT reveal `client_identity_digest` or `r_client` to the relay.
2. **Signed reservation and sealed `relay_token`.** The relay constructs the PAL-CBOR map `body = { v: 1, sessionId (16B), relayEdPk (32B), relayDsaPk (1952B), blindClientId (48B), issuedAtMs (u64), expiresAtMs (u64), byteQuota (u64), bandwidthBps (u64) }` and signs `msg = ascii("pal3-relay-sealed-v1") || SHA-384(body)` with both Ed25519 and ML-DSA-65 (ASCII context `pal3-relay-sealed-v1`, strict-AND). The relay also seals its accounting state under a relay-local 32-byte key `K_relay` (rotated at least every 24 hours, never shared): `aad = "pal3-relay-token-v1" || 0x00 || sessionId (16B) || blindClientId (48B)`, `token_plain = u64be(issuedAtMs) || u64be(expiresAtMs) || u64be(byteQuota) || u64be(bandwidthBps)` (32 bytes), and `relay_token = nonce (12B) || ChaCha20-Poly1305(K_relay, nonce, aad, token_plain)` (60 bytes total).
3. **Blind reservation envelope and verification.** The reserving client delivers `{ body, sigEd25519, sigMldsa65, relayToken, rClient (32B), clientIdentityDigest (48B) }` to its pal inside an end-to-end encrypted signaling blob (§4) or `onion/3` control cell (§15.9). The pal MUST verify in order: `sessionId` is 16 bytes (`E_PAL3_RELAY_INVALID`), the relay's hybrid identity digest matches the pinned relay (`E_PAL3_RELAY_ISSUER_MISMATCH`), `blindClientId` equals `HMAC-SHA-384(rClient, "pal3-relay-blind-v1" || 0x00 || clientIdentityDigest || sessionId)` in constant time (`E_PAL3_RELAY_BLIND_MISMATCH`), `clientIdentityDigest` equals the expected pal's pinned hybrid identity (`E_PAL3_RELAY_BLIND_MISMATCH`), `issuedAtMs <= now + 300_000` (`E_PAL3_RELAY_INVALID`), `expiresAtMs > now` (`E_PAL3_RELAY_EXPIRED`), and both Ed25519 and ML-DSA-65 signatures verify (`E_PAL3_RELAY_AUTH_FAILED`).
4. **Relay presentation.** When a peer presents `(sessionId, blindClientId, relayToken)` to the relay, the relay MUST authenticate and decrypt `relayToken` under `K_relay` with `aad = "pal3-relay-token-v1" || 0x00 || sessionId || blindClientId`, reject any authentication failure or mismatch (`E_PAL3_RELAY_INVALID`) or expiry (`E_PAL3_RELAY_EXPIRED`), and meter `byteQuota` and `bandwidthBps` per `(sessionId, blindClientId)`.

**Optional multi-hop carried sessions (`relay-multihop.v1`).** To prevent a single carried-session relay from seeing both peers' network addresses, two peers that both negotiate `relay-multihop.v1` and have explicitly opted into relayed carriage (§14.1; never enabled by default, `E_PAL3_RELAY_NOT_ENABLED` otherwise) MAY chain an entry relay `R1` and a rendezvous relay `R2` operated independently:

1. **Circuit binding.** Peer A holds a sealed reservation on `R1` (`session_id_1`, 16 bytes) and receives Peer B's sealed reservation on `R2` (`session_id_2`, 16 bytes) over an end-to-end encrypted `onion/3` control message (§15.9). Peer A instructs `R1` over its authenticated `PAL/3` control session to bridge `session_id_1` to `session_id_2` at `R2`; the bridge instruction MUST NOT include Peer B's long-term identity.
2. **Wire framing (`RELAY_MH`).** Each carried datagram on a leg carries `frame_type (u8 = 0x52) || hop_session_id (16 B) || seq (u64be) || payload_len (u16be) || opaque_record (payload_len B)`. `payload_len` MUST be at least 1 and at most 1,200 bytes (total frame at most 1,227 bytes); any frame with `frame_type != 0x52`, `payload_len == 0`, `payload_len > 1200`, or mismatched byte length MUST be dropped (`E_PAL3_RELAY_INVALID`).
3. **Per-leg rewriting and replay protection.** When forwarding between `Peer A <-> R1` (`session_id_1`) and `R1 <-> R2` (`session_id_2`), `R1` MUST replace `hop_session_id` with the outbound leg's session identifier and MUST assign an independent monotonic per-leg `seq` starting at `0`, leaving `opaque_record` untouched. Each relay MUST maintain a sliding-window replay filter of at least 64 sequence numbers per leg and drop duplicate or below-window `seq` values (`E_PAL3_RELAY_REPLAY`).
4. **Padding.** When `privacyMode` is `maximum`, endpoints SHOULD pad each `opaque_record` to 1,200 bytes with `pad.v1` (§6.1) before framing.

### 14.11 Product SDK and Transport Boundaries

- **SDK-only boundary.** Products built on PAL/3 (desktop, CLI, mobile, server and agent delegates) MUST consume the protocol through the versioned SDK surface (`@hn2/pal-sdk` for protocol nodes and `@palexplorer/sdk` for application capabilities) and MUST NOT import internal `@hn2/protocol` paths directly outside the dedicated transport adapter module.
- **Identity-only product API.** Product-facing APIs address peers by their peer identifier (the 96-hex SHA-384 peer hash of §14.5) only, and carry the Ed25519 identity key only where a signature is verified. Transient network endpoints (`host`, `port`, `ip`, `pal3Host`, `pal3Port`, `serveUrl`, `directAddress`, `externalAddress`, `localIp`, `remoteAddress`, `remotePort`) are confined to the transport carrier and MUST NOT appear in product API responses, persisted database records, renderer IPC payloads or diagnostic logs.
- **Native UDP-only boundary.** Native peer-to-peer product traffic MUST use UDP carriers only (`C2` PAL-UDP or `C1` UDP-only ICE with `enableIceTcp: false`) and MUST NOT fall back to TCP or HTTP for peer data. Local daemon-to-application control on the same host MUST use framed OS IPC (Unix domain sockets or Windows named pipes), never a loopback HTTP listener.

---

## 15. Multi-Hop Relay Cells (`onion/2`)

This section is normative unless marked informative. It specifies the cell that carries a small payload through one, two or three relays so that no single relay knows both the sender and the destination. It is written from the reference implementation (`hn2/pal-core#337`). The vector `test-vectors/v3/pal3-v0.6-onion2-vectors.json` gives the sizes, a three-hop cell with every forwarded cell, and a fragmentation case.

### 15.1 Scope and Capability

- **Capability.** A peer that implements this section advertises the capability string `onion/2`. A sender MUST NOT send a cell through a relay, or to a destination, that does not advertise `onion/2`.
- **What a cell carries.** A cell carries control messages. The payload MUST already be encrypted end to end for the destination; the last relay sees the payload bytes.
- **Bulk data.** File data SHOULD NOT be sent in cells: three hops multiply the traffic roughly fourfold.
- **Carriage.** How a cell travels between two hops is not part of this section. A hop treats a cell as one opaque byte string of the cell size.

### 15.2 Constants

| Name | Value | Meaning |
|---|---|---|
| `MAX_HOPS` | 3 | Largest number of relays on a path |
| `CELL_SIZE` | 1024 bytes by default; 512 to 2048 allowed | Size of every cell on a path |
| `SEAL` | 48 bytes | Sealed-box overhead: 32-byte ephemeral public key and 16-byte tag |
| `NEXT` | 32 bytes | Ed25519 public key of the next hop |
| `LEN` | 2 bytes | Payload length, unsigned, big-endian |
| `LAYER_GROWTH` | `NEXT + SEAL` = 80 bytes | Bytes that each additional layer adds |

- **Capacity.** `capacity = CELL_SIZE - 1 - SEAL - NEXT - LEN - (MAX_HOPS - 1) × LAYER_GROWTH = CELL_SIZE - 243`. It is 781 bytes for a 1024-byte cell, and it is the same for one, two and three hops.
- **Layer length.** `layerLength(h) = SEAL + NEXT + LEN + capacity + (h - 1) × LAYER_GROWTH`, where `h` is the remaining-hops value. For a 1024-byte cell it is 863, 943 and 1023 bytes for `h` = 1, 2 and 3.
- **Cell size.** Every cell on a path MUST have the same size, and a relay MUST forward a cell of the size it received. A sender SHOULD use 1024 bytes unless the network it belongs to sets another size. A cell whose size is outside 512 to 2048 bytes MUST be rejected.

### 15.3 Cell Layout

```
cell          = remainingHops (1 byte) || layer (layerLength(remainingHops) bytes) || padding
layer         = sealedBox(relayKey, nextHop (32 bytes) || inner)
inner         = layer for the next relay            when remainingHops > 1
              = payloadField                        when remainingHops = 1
payloadField  = length (2 bytes, big-endian) || payload || fill      (LEN + capacity bytes)
```

- **`remainingHops`** is the number of relays that still have to open a layer, from 1 to `MAX_HOPS`. It is in the clear (§15.8).
- **`nextHop`** is the Ed25519 public key of the next relay, or of the destination when `remainingHops` is 1.
- **`fill`** and **`padding`** are fresh random bytes. `padding` fills the cell to the cell size; it is empty when `remainingHops` is 3.
- **`payload`** is at most `capacity` bytes. A longer payload is fragmented (§15.6).

### 15.4 Sealed Box

`sealedBox(relayKey, m)` is:

1. The relay's X25519 public key `R` is derived from its Ed25519 public key: `u = (1 + y) / (1 - y) mod 2^255 - 19`. The matching secret key is the first 32 bytes of SHA-512 of the Ed25519 seed, clamped.
2. The sender generates a fresh X25519 key pair `(e, E)` for every layer of every cell.
3. `shared = X25519(e, R)`. If `shared` is 32 zero bytes, the sender MUST abort and the relay MUST reject the cell.
4. `key = HKDF-SHA-384(ikm = shared, salt = E || R, info = "pal-sealed-box-v1", length = 32)`.
5. The output is `E (32 bytes) || ciphertext || tag (16 bytes)`, where ciphertext and tag are ChaCha20-Poly1305 (RFC 8439) of `m` under `key`, with a nonce of 12 zero bytes and no associated data. The key is used for exactly one message, so the nonce never repeats under a key.

A sender MUST NOT reuse an ephemeral key. The box does not authenticate the sender: a cell is anonymous by design, and the payload carries its own authentication.

### 15.5 Building and Relaying

**Sender.** For relays `r1 … rn` (`r1` first, `1 ≤ n ≤ MAX_HOPS`) and destination `d`:

1. Build `payloadField`.
2. Set `inner = payloadField` and `next = d`. For `i = n` down to 1: `inner = sealedBox(ri, next || inner)`, then `next = ri`.
3. Send `n || inner || padding` to `r1`.

**Relay.** A relay that receives a cell MUST do the following in order, and MUST drop the cell without a reply when a step fails:

1. Check that the cell size is allowed (`E_ONION_INVALID`) and that `remainingHops` is from 1 to `MAX_HOPS` (`E_ONION_TTL`).
2. Compute the replay key: SHA-384 of the first `1 + layerLength(remainingHops)` bytes of the cell. The padding is not part of the key, because anyone on the link can change it. If the key is in the replay cache, drop the cell (`E_REPLAY`).
3. Open the layer with its own key (`E_UNAUTHORIZED` when the box does not open). Add the replay key to the cache.
4. If `remainingHops` is greater than 1: forward `(remainingHops - 1) || inner || fresh random padding` to `nextHop`.
5. If `remainingHops` is 1: read `length`, reject a length above `capacity` (`E_ONION_INVALID`), and deliver `payload` to `nextHop`, the destination.

- **Replay cache.** A relay MUST keep replay keys for at least as long as it would still forward the cell, and MUST bound the size of the cache.
- **Jitter.** A relay SHOULD delay each forwarded cell by a random time; the reference implementation uses 0 to 20 milliseconds.
- **Padding.** A relay MUST replace the padding with fresh random bytes. It MUST NOT copy the padding it received.

### 15.6 Fragmentation

A payload longer than `capacity` is split into fragments. Each fragment is the payload of one cell:

```
fragment = messageId (8 bytes) || index (2 bytes, big-endian) || count (2 bytes, big-endian) || data
```

- `messageId` is random and the same for all fragments of one payload. `index` counts from 0. `count` is the number of fragments, from 1 to 65535.
- `data` is at most `capacity - 12` bytes: 769 bytes for a 1024-byte cell. Every fragment except the last carries exactly that many bytes.
- The destination MUST reject a fragment set when `count` is 0, an `index` is not below `count`, the fragments disagree on `messageId` or `count`, or a fragment is missing (`E_ONION_INVALID`). It MUST bound the memory and the time it spends on incomplete payloads.
- The sender SHOULD send the fragments of one payload over paths that are chosen independently.

### 15.7 Error Identifiers (informative)

`E_ONION_INVALID`, `E_ONION_TOO_LARGE`, `E_ONION_TTL`, `E_UNAUTHORIZED`, `E_REPLAY`. These are local results. A relay never returns an error to the previous hop.

### 15.8 Privacy Considerations (informative)

- **Size.** Every cell on a path has one size, so the size identifies neither the message nor the hop count.
- **A relay** learns the previous hop and the next hop. The first relay learns the sender's network address; the last relay learns the destination's public key and the end-to-end encrypted payload.
- **All relays together** learn the full path. The protection depends on relays that are run by independent operators.
- **A link observer** watching `onion/2` cells sees `remainingHops` and therefore how far along its path a cell is. `onion/3` (§15.9) eliminates cleartext `remainingHops` via Sphinx-style header blinding so that cells at every hop are bitwise indistinguishable.
- **A global observer** can correlate cells that enter and leave relays by timing. Jitter helps only in part, and nothing is claimed against this adversary.

### 15.9 Blinded Multi-Hop Relay Cells (`onion/3`)

`onion/3` is an additive Sphinx-style header-blinded replacement for `onion/2` that removes the cleartext `remainingHops` byte and makes every forwarded cell bitwise unlinkable and indistinguishable across hop positions and path lengths (1 to 3 hops). The vector `test-vectors/v3/pal3-v0.6-onion3-vectors.json` gives the constants, three-hop, two-hop and one-hop cells with every forwarded cell, and rejection cases.

- **Capability.** A peer that implements this subsection advertises `onion/3` (and MAY also advertise `onion/2` for transition). When every relay on a path and the destination advertise `onion/3`, the sender MUST use `onion/3`. A sender MUST NOT send an `onion/3` cell through a relay, or to a destination, that does not advertise `onion/3`.
- **Constants and layout.** `MAX_HOPS` = 3, `CELL_SIZE` = 1024 bytes by default (512 to 2048 allowed; any size outside 512..2048 MUST be rejected with `E_ONION_INVALID`), `ALPHA` = 32 bytes, `HOP_SLOT` = 49 bytes (`hopType (1 B) || nextHop (32 B) || nextMac (16 B)`), `BETA_LEN` = `MAX_HOPS × HOP_SLOT` = 147 bytes, `MAC` = 16 bytes, `HEADER_LEN` = `ALPHA + BETA_LEN + MAC` = 195 bytes, `DELTA_LEN` = `CELL_SIZE - HEADER_LEN` = `CELL_SIZE - 195` bytes, `LEN` = 2 bytes, and `capacity` = `DELTA_LEN - LEN` = `CELL_SIZE - 197` bytes (827 bytes for a 1024-byte cell; fragment data is at most `capacity - 12` = 815 bytes using the fragmentation header of §15.6).

```
cell          = alpha (32 B) || beta (147 B) || gamma (16 B) || delta (CELL_SIZE - 195 B)
payloadField  = length (2 B, big-endian) || payload || fill      (DELTA_LEN bytes)
```

There is no cleartext `remainingHops` byte on the wire; every hop sends and receives `CELL_SIZE` bytes with an identical 195-byte header.

- **Key derivation and stream cipher.** Let `R_i` be relay `i`'s X25519 public key derived from its Ed25519 public key (§15.4) and `r_i` its matching clamped X25519 secret key. Given the hop group element `alpha_i` (32 bytes) and shared secret `s_i` (32 bytes), both sender and relay derive:
  - `rho_i = HKDF-SHA-384(ikm = s_i, salt = alpha_i || R_i, info = "pal3-onion3-rho-v1", length = 32)` (header stream key)
  - `mu_i  = HKDF-SHA-384(ikm = s_i, salt = alpha_i || R_i, info = "pal3-onion3-mu-v1", length = 32)` (MAC key)
  - `pi_i  = HKDF-SHA-384(ikm = s_i, salt = alpha_i || R_i, info = "pal3-onion3-pi-v1", length = 32)` (payload stream key)
  - `b_i   = HKDF-SHA-384(ikm = s_i, salt = alpha_i || R_i, info = "pal3-onion3-blind-v1", length = 32)` (next-hop X25519 blinding scalar)
  - `replayKey_i = SHA-384("pal3-onion3-replay-v1" || 0x00 || alpha_i || R_i || s_i)` (48 bytes)
  - `stream(key, len)` is the RFC 8439 IETF ChaCha20 keystream of `len` bytes under 32-byte `key`, 12-byte all-zero nonce, and initial 32-bit block counter `0`.
  - `mac(mu_i, alpha_i, beta_i, delta_i)` is the first 16 bytes of `HMAC-SHA-384(mu_i, alpha_i || beta_i || delta_i)`.

- **Sender.** For relays `0 .. n-1` (`1 ≤ n ≤ MAX_HOPS`, public keys `P_0 .. P_{n-1}`, X25519 keys `R_0 .. R_{n-1}`) and destination Ed25519 key `D`:
  1. Generate a fresh 32-byte random X25519 private scalar `x` (MUST NOT be reused across cells). Set `alpha_0 = X25519(x, G)`.
  2. For `i = 0 .. n-1`: compute `s_i` sequentially using standard RFC 7748 X25519: start with `t = X25519(x, R_i)`, and for `j = 0 .. i-1` set `t = X25519(b_j, t)`, then `s_i = t`. If `s_i` is 32 zero bytes, abort. Derive `(rho_i, mu_i, pi_i, b_i)` from `(s_i, alpha_i, R_i)`. If `i < n-1`, compute `alpha_{i+1} = X25519(b_i, alpha_i)` (abort if all-zero).
  3. Build `delta_n = payloadField` (`DELTA_LEN` bytes, with fresh random `fill`). For `i = n-1` down to `0`, compute `delta_i = delta_{i+1} XOR stream(pi_i, DELTA_LEN)`.
  4. Compute the Sphinx header fillers: `phi_0` is empty; for `k = 1 .. n-1`, `phi_k = (phi_{k-1} || 0x00^{HOP_SLOT}) XOR stream(rho_{k-1}, BETA_LEN + HOP_SLOT)[BETA_LEN + HOP_SLOT - k × HOP_SLOT .. BETA_LEN + HOP_SLOT]`.
  5. Build the exit-hop header for `i = n-1`: let `tailPad` be `(MAX_HOPS - n) × HOP_SLOT` fresh random bytes, `slot = 0x02 || D || 0x00^{16} || tailPad` (`(MAX_HOPS - (n - 1)) × HOP_SLOT` bytes), and `beta_{n-1} = (slot XOR stream(rho_{n-1}, BETA_LEN)[0 .. len(slot)]) || phi_{n-1}`. Compute `gamma_{n-1} = mac(mu_{n-1}, alpha_{n-1}, beta_{n-1}, delta_{n-1})`.
  6. For `i = n-2` down to `0`: `beta_i = (0x01 || P_{i+1} || gamma_{i+1} || beta_{i+1}[0 .. BETA_LEN - HOP_SLOT]) XOR stream(rho_i, BETA_LEN)` and `gamma_i = mac(mu_i, alpha_i, beta_i, delta_i)`.
  7. Send `alpha_0 || beta_0 || gamma_0 || delta_0` to relay `0`.

- **Relay.** A relay that receives a cell MUST perform these steps in order and MUST drop the cell without a reply when any step fails:
  1. Verify `cell.length` is between 512 and 2048 bytes (`E_ONION_INVALID`). Split into `alpha` (32 B), `beta` (147 B), `gamma` (16 B), `delta` (`cell.length - 195` B).
  2. Compute `s = X25519(r, alpha)`. If `s` is 32 zero bytes, drop (`E_ONION_INVALID`).
  3. Derive `(rho, mu, pi, b, replayKey)` from `(s, alpha, R)`.
  4. Check `replayKey` against the bounded replay cache; if present, drop (`E_REPLAY`).
  5. Verify `gamma == mac(mu, alpha, beta, delta)` in constant time; if not equal, drop (`E_UNAUTHORIZED`). Because `gamma` covers `alpha || beta || delta`, any tampering with the header or payload is rejected immediately.
  6. Insert `replayKey` into the replay cache.
  7. Decrypt the zero-extended header: `B = (beta || 0x00^{HOP_SLOT}) XOR stream(rho, BETA_LEN + HOP_SLOT)`. Read `hopType = B[0]`, `nextHop = B[1..33]`, `nextMac = B[33..49]`, `nextBeta = B[49 .. 49 + BETA_LEN]`.
  8. Decrypt the payload: `nextDelta = delta XOR stream(pi, delta.length)`.
  9. If `hopType == 0x01`: compute `nextAlpha = X25519(b, alpha)` (drop with `E_ONION_INVALID` if all-zero) and forward `nextAlpha || nextBeta || nextMac || nextDelta` to `nextHop` (with random jitter as in §15.5).
  10. If `hopType == 0x02`: read `length = uint16be(nextDelta[0..2])`, reject if `length > nextDelta.length - 2` (`E_ONION_INVALID`), and deliver `nextDelta[2 .. 2 + length]` to `nextHop` (the destination).
  11. Any other `hopType` MUST be dropped (`E_ONION_INVALID`).

---

## Appendix A. Byte-Exact Wire Encodings

### A.1 Deterministic TLV Encoding
```
tag (u16be) | length (u32be) | value (length bytes)
```
Fields are sorted by strictly ascending tag. Duplicate or out-of-order tags MUST be rejected (`E_PAL3_MALFORMED_TLV`).

#### Device Certificate (`device_cert`)
| Tag | Field | Encoding |
|---|---|---|
| `0x0001` | `flags` | `u8` (`0x00` delegated, `0x01` self-certified) |
| `0x0002` | `identity_ed25519_pk` | 32 B |
| `0x0003` | `identity_mldsa65_pk` | 1952 B |
| `0x0004` | `device_id` | 16 B |
| `0x0005` | `device_ed25519_pk` | 32 B (omitted when self-certified) |
| `0x0006` | `device_mldsa65_pk` | 1952 B (omitted when self-certified) |
| `0x0007` | `issued_at_ms` | u64be |
| `0x0008` | `expires_at_ms` | u64be |
| `0x0009` | `cert_sig_ed25519` | 64 B |
| `0x000A` | `cert_sig_mldsa65` | 3309 B |

A self-certified certificate is about 5.4 KB, and a delegated one is about 7.4 KB, including TLV headers.

#### Revocation Statement (`revocation_statement`)
| Tag | Field | Encoding |
|---|---|---|
| `0x0001` | `identity_ed25519_pk` | 32 B |
| `0x0002` | `identity_mldsa65_pk` | 1952 B |
| `0x0003` | `revocation_version` | u64be |
| `0x0004` | `issued_at_ms` | u64be |
| `0x0005` | `revoked_device_ids` | `16·N` bytes (concatenated `device_id`s, may be empty) |
| `0x0009` | `sig_ed25519` | 64 B |
| `0x000A` | `sig_mldsa65` | 3309 B |

The signatures cover the TLV body of tags `0x0001`..`0x0005` under the domain label `pal3-revocation-v1` and the ML-DSA context `pal3-revocation-v1`.

#### Device Encryption Keys (`device_cert` extension)
| Tag | Field | Encoding |
|---|---|---|
| `0xC010` | `device_enc_keys` | 1216 B: `x25519_pk` (32) `\|\| mlkem768_ek` (1184); optional, delegated certificates only (11.4 item 1) |

#### Sealed Content (`sealed_content`, 11.4)
| Tag | Field | Encoding |
|---|---|---|
| `0x0001` | `version` | u8 (`1`) |
| `0x0002` | `context` | 1 to 64 ASCII characters, `a-z 0-9 . _ -` |
| `0x0003` | `commitment` | 32 B |
| `0x0004` | `wraps` | `1184·N` bytes, `N` from 1 to 16: `key_id` (16) `\|\| x25519_eph` (32) `\|\| mlkem_ct` (1088) `\|\| wrapped_ck` (48) |
| `0x0005` | `ciphertext` | plaintext length (at most 32 KiB) plus 16 B |

#### Device List (`device_list`, 11.4)
| Tag | Field | Encoding |
|---|---|---|
| `0x0001` | `identity_ed25519_pk` | 32 B |
| `0x0002` | `identity_mldsa65_pk` | 1952 B |
| `0x0003` | `identity_enc_keys` | 1216 B |
| `0x0004` | `revision` | u64be, from 1 |
| `0x0005` | `revocation_version` | u64be, the revocation version the issuer held |
| `0x0006` | `issued_at_ms` | u64be |
| `0x0007` | `expires_at_ms` | u64be, at most 7 days after `issued_at_ms` |
| `0x0008` | `capabilities` | sorted, unique, comma-separated tokens (may be empty) |
| `0x0009` | `sig_ed25519` | 64 B |
| `0x000A` | `sig_mldsa65` | 3309 B |
| `0x000B` | `devices` | `1240·N` bytes, `N` from 0 to 15, ascending `device_id`: `device_id` (16) `\|\| x25519_pk` (32) `\|\| mlkem768_ek` (1184) `\|\| cert_expires_at_ms` (8) |

The signatures cover the TLV body of every tag except `0x0009` and `0x000A` under the domain label `pal3-devlist-v1` and the ML-DSA context `pal3-devlist-v1`. A list is at most 64 KiB.

#### Device-Signed Object (`device_signed`, 11.4)
| Tag | Field | Encoding |
|---|---|---|
| `0x0001` | `cert_hash` | 48 B, SHA-384 of the `device_cert` |
| `0x0002` | `device_cert` | optional, the certificate itself |
| `0x0003` | `sig_ed25519` | 64 B |
| `0x0004` | `sig_mldsa65` | 3309 B |

The signatures cover `u8 len(context) || context || body` under the domain label `pal3-devsig-v1` and the ML-DSA context `pal3-devsig-v1`, with the device keys of the certificate (the identity keys for a self-certified certificate).

#### `HELLO` (`record.type = 0x01`)
| Tag | Field | Encoding |
|---|---|---|
| `0x0001` | `version_list` | `2·N` bytes of u16be (`0x0003`) |
| `0x0002` | `suite_list` | `2·N` bytes of u16be, preference order (`0x0001`) |
| `0x0003` | `nonce_I` | 32 B |
| `0x0004` | `cookie` | 0 or 48 B |
| `0x0006` | `x25519_eph_I` | 32 B |
| `0x0007` | `mlkem_ek_I` | 1184 B |
| `0x0008` | `capabilities_I` | sorted comma-separated ASCII tokens |
| `0x0009` | `psk_ticket` | resumption only (§5.5) |
| `0x000A` | `psk_binder` | resumption only, 48 B |

#### `ACCEPT` (`record.type = 0x02`)
| Tag | Field | Encoding |
|---|---|---|
| `0x0001` | `version` | u16be |
| `0x0002` | `suite` | u16be |
| `0x0003` | `nonce_R` | 32 B |
| `0x0005` | `x25519_eph_R` | 32 B |
| `0x0006` | `mlkem_ct` | 1088 B |
| `0x0007` | `psk_accepted` | u8 `1`, resumed sessions only (§5.5) |
| `0x000B` | `encrypted_identity_R` | AEAD ciphertext of the identity TLV below |

Encrypted identity TLV, full handshake: `0x0001 device_cert_R`, `0x0002 capabilities_R`, `0x0003 revocation_version_R (u64be)`, extension tags, `0x0009 sig_ed25519_R`, `0x000A sig_mldsa65_R`.

Encrypted identity TLV, resumed handshake: `0x0002`, `0x0003`, `0x0004 confirm` (48 B), extension tags.

#### `FINISH` (`record.type = 0x10 CTRL`, epoch 0, seq 0)
| Tag | Field | Encoding |
|---|---|---|
| `0x0001` | `device_cert_I` | nested TLV |
| `0x0002` | `revocation_version_I` | u64be |
| `0x0003` | `expected_id_R` | 0 or 48 B identity digest |
| `0x0004` | `finished` | 48 B, resumed sessions only (replaces tags `0x0001`, `0x0003`, `0x0009` and `0x000A`) |
| `0x0009` | `sig_ed25519_I` | 64 B |
| `0x000A` | `sig_mldsa65_I` | 3309 B |

### A.2 Conformance Vectors
All files are in `hn2/pal-spec/test-vectors/v3/` and are checked by `npm run validate`. `pal3-v0.5-vectors.json` contains vectors for TLV encoding, comprehension bits, the Draft 0.5 key schedule (`prk_hs`, `k_id`, `prk_0`, channel key, salt and exporter), record AEAD framing, beacon tags and identity digests. The Draft 0.6 files are listed in A.6.

### A.3 Deterministic PAL-CBOR Value Codec

Structured payloads (record bodies on `REQ`, `RES`, `ERROR`, `CANCEL`, `CREDIT`, `END`, `CTRL`, manifests and grants) use this deterministic tagged value encoding. It is not RFC 8949 CBOR; the name is historical.

| Type byte | Type | Wire encoding | Rules |
|---|---|---|---|
| `0x00` | null | no bytes | Map values that are absent are omitted, not encoded as null. |
| `0x01` | false | no bytes | |
| `0x02` | true | no bytes | |
| `0x03` | int | `i64be` | Only safe integers (−(2^53−1) .. 2^53−1). |
| `0x04` | bigint | `u64be` | Unsigned, 0 .. 2^64−1. Used for counters and millisecond timestamps. |
| `0x05` | float | `f64be` | Only finite, non-integer numbers. |
| `0x06` | bytes | `u32be len \|\| bytes` | |
| `0x07` | string | `u32be len \|\| utf8` | |
| `0x08` | array | `u32be count \|\| item*` | At most 4096 items. |
| `0x09` | map | `u32be count \|\| (u16be key_len \|\| utf8 key \|\| value)*` | At most 4096 keys; key at most 1024 bytes. Keys strictly ascending, no duplicates. `__proto__`, `constructor` and `prototype` are forbidden. |

- **Key order** is ascending by UTF-16 code unit (the order of JavaScript string comparison). This equals UTF-8 byte order except when keys mix code points above U+FFFF with code points U+E000–U+FFFF. Core keys are ASCII.
- **Limits:** nesting depth at most 16. The encoded value is at most 65,536 bytes unless the message defines a larger cap (manifests: 16 MiB, A.5). Trailing bytes after the root value are rejected.
- **Errors:** malformed input fails with `E_PAL3_MALFORMED_BODY`; an encoder that exceeds the cap fails with `E_PAL3_BODY_TOO_LARGE`.

### A.4 C2 PAL-UDP Datagram and Frame Layout

1. **`PKT_INITIAL` (`0x01`):** 25-byte header, then an 8-byte fragment header, then a fragment of a handshake record.
   ```
   type (u8 = 0x01) | conn_id (u32be) | cookie (16B) | pow_nonce (u32be)
   msg_id (u32be) | frag_idx (u16be) | frag_total (u16be) | fragment
   ```
   - Before a challenge, `cookie` is 16 zero bytes and `pow_nonce` is 0. `msg_id` is set to `conn_id`.
2. **`PKT_COOKIE_CHALLENGE` (`0x06`, 28 bytes):**
   ```
   type (u8 = 0x06) | conn_id (u32be) | pow_bits (u8) | cookie (16B) | reserved (6B = 0)
   ```
   - Puzzle: find `pow_nonce` such that `SHA-384("pal3-pow-v1" || cookie || conn_id (u32be) || pow_nonce (u32be))` has at least `pow_bits` leading zero bits. A client MUST refuse `pow_bits > 16` (`E_PAL3_POW_TOO_HARD`).
3. **`PKT_PROTECTED` (`0x02`) and `PKT_PROTECTED_PHASE1` (`0x03`):** 9-byte header, ciphertext, 16-byte Poly1305 tag.
   ```
   type (u8 = 0x02 or 0x03) | conn_id (u32be) | protected_pn (u32be) | ciphertext || tag (16B)
   ```
   - Type `0x02` is sent under an even packet key epoch and `0x03` under an odd one (§3.2). `0x03` is valid only when `c2-key-update` is negotiated; otherwise it is dropped.
   - AEAD: ChaCha20-Poly1305 IETF. AAD is the unprotected header `type || conn_id || pn_low32`. Nonce = `iv[0..4] || (iv[4..8] XOR hi32(pn)) || (iv[8..12] XOR lo32(pn))`.
   - Header protection: `sample` = the first 16 bytes of `ciphertext || tag` (the same bytes as `ciphertext[0..16]` when the ciphertext has at least 16 bytes); `mask = ChaCha20-IETF(hp_key, counter = u32le(sample[0..4]), nonce = sample[4..16])` applied to 4 zero bytes; `protected_pn = pn_low32 XOR mask`. The full packet number is reconstructed as in RFC 9000 §A.3 with a 32-bit window.
3a. **`PKT_PROTECTED_CID` (`0x04`) and `PKT_PROTECTED_CID_PHASE1` (`0x05`):** 13-byte header, ciphertext, 16-byte Poly1305 tag. Valid only when `c2-cid-v2` is negotiated.
   ```
   type (u8 = 0x04 or 0x05) | dcid (8B) | protected_pn (u32be) | ciphertext || tag (16B)
   ```
   - Type `0x04` is sent under an even packet key epoch and `0x05` under an odd one. The AAD is `type || dcid || pn_low32` (13 bytes). The nonce, the header protection (applied to the `protected_pn` bytes) and the packet number reconstruction are those of `0x02` (§3.2).
4. **Frames inside `PKT_PROTECTED` plaintext.** An unknown frame type is fatal (`E_PAL3_C2_FRAME`). `channel` is 0..3.

   | Type | Frame | Layout after the type byte |
   |---|---|---|
   | `0x01` | `PADDING` | none |
   | `0x02` | `ACK` | `largest (u64be) \| ack_delay_us (u32be) \| extra_ranges (u8) \| first_range_len (u32be) \| (gap (u32be) \| range_len (u32be))*` |
   | `0x03` | `STREAM` | `channel (u8) \| offset (u64be) \| len (u16be) \| data` |
   | `0x04` | `MAX_DATA` | `channel (u8) \| max_stream_data (u64be)` |
   | `0x05` | `PING` | none (ack-eliciting) |
   | `0x06` | `CLOSE` | `code (u8) \| reason_len (u8) \| reason (utf8, ≤ 128 bytes)` |
   | `0x07` | `PATH_CHALLENGE` | `data (8B)` |
   | `0x08` | `PATH_RESPONSE` | `data (8B)` |
   | `0x09` | `STREAM_RESET` | `channel (u8) \| final_size (u64be)` |
   | `0x0A` | `STOP_SENDING` | `channel (u8)` |
   | `0x0B` | `REPAIR` | `base_pn (u64be) \| count (u8, 1-8) \| reserved (u8, 0) \| parity_len (u16be) \| count × (pn_delta (u8) \| plaintext_len (u16be)) \| parity (parity_len bytes)` |
| `0x0C` | `NEW_CONNECTION_ID` | `seq (u32be) \| cid (8B) \| reset_token (16B)` (ack-eliciting; capability `c2-cid-v2`) |
| `0x0D` | `RETIRE_CONNECTION_ID` | `seq (u32be)` (ack-eliciting; capability `c2-cid-v2`) |

   - `REPAIR` (capability `fec.v1`, A.6): after every 8 packets that carry `STREAM` frames, the sender sends one packet holding a `REPAIR` frame. `parity` is the byte-wise XOR of the 8 packets' plaintext frame bytes, each zero-extended to `parity_len`, and the `pn_delta` list names those packets (`base_pn + pn_delta`). A sender that uses `fec.v1` limits the plaintext of data packets so the `REPAIR` packet fits in the datagram. When exactly one named packet is missing and the other seven were received, the receiver XORs them out of `parity`, truncates to the stated length, processes the frames as if the packet had arrived and acknowledges its packet number. A `REPAIR` packet is not ack-eliciting and is never retransmitted. A receiver without `fec.v1` negotiated parses and ignores `REPAIR`. ECN is not part of this version: the reference platform exposes neither the ECN bits on send nor on receive, so no ECN behavior is specified or negotiated.

   - `ACK` ranges: the first range covers `largest − first_range_len .. largest`. Each further range starts `gap + 1` below the previous range's low end and covers `range_len + 1` packet numbers.

### A.5 Record Payloads and Signed Objects

1. **Record payloads** (record types in §6.1; bodies are PAL-CBOR maps, A.3):
   - `REQ` (`0x11`): `{ op, res, body, cap? }`. `cap` names the capability grant being used. Streaming operations add `credit`, the initial credit in bytes.
   - `RES` (`0x12`): `{ result }`. For `file.read`, each block is preceded by a `RES` header `{ blockIndex, blockLength, proof }`, where `proof` is the Merkle sibling path (§8.1).
   - `DATA` (`0x13`): raw block bytes, at most `blockLength` in total after the matching `RES` header. `DATA` without a header, or beyond granted credit, is fatal.
   - `END` (`0x14`): `{ blocksSent }`.
   - `CANCEL` (`0x15`): `{}`.
   - `CREDIT` (`0x16`): `{ credit }`.
   - `ERROR` (`0x17`): `{ error, code? }`. `error` is a message with sensitive values redacted.
2. **Signed manifest** (§8.2): PAL-CBOR map `{ body, sigEd25519, sigMldsa65 }`. `body` is the encoded map `{ v: 1, shareId (48B), ownerEdPk, ownerDsaPk, revisionCounter (u64), authorDeviceId (48B), publishedAtMs (u64), encrypted, entries, extensions?, redistribution?, pad? }`, at most 16 MiB. `redistribution` is `none`, `pals` or `link-holders` (§8.5); absent means `none`.
3. **Signed capability grant** (§9): PAL-CBOR map `{ body, sigEd25519, sigMldsa65 }`. `body` is `{ v: 1, grantId, issuerEdPk, issuerDsaPk, subjectType, subjectId, resource, operations (sorted, unique), issuedAtMs, notBeforeMs, expiresAtMs, maxReads, maxBytes, bandwidthBps, devicesMax, requirePq: true, watermark }`. A zero limit means no limit. `subjectType` is one of `identity`, `device`, `group`, `link-capability`, `password`, `anonymous`.
4. **Hybrid signature over a signed object:** `msg = ascii(context) || SHA-384(body)`. `sigEd25519 = Ed25519(msg)` and `sigMldsa65 = ML-DSA-65(msg, ctx = context)`. Both MUST verify (D3). Contexts: `pal3-manifest-v1`, `pal3-grant-v1`, `pal3-share-ticket-v1`, `pal3-swarm-pass-v1`.
5. **Swarm pass** (§8.5): PAL-CBOR map `{ body, sigEd25519, sigMldsa65 }`, context `pal3-swarm-pass-v1`. `body` is `{ v: 1, shareId (48B), holderEdPk (32B), holderDsaPk (1952B), issuedAtMs (u64), expiresAtMs (u64) }` with `expiresAtMs − issuedAtMs ≤ 600 000`.
6. **Share-link ticket** (§8.6): context `pal3-share-ticket-v1`.
7. **Extension bundle and publisher certificate** (§12.2): PAL-CBOR map `{ body, sigEd25519, sigMldsa65 }`.
   - Bundle `body`: `{ v: 3, id, name, version, capability, supportedTlvTags, operations, streamHandlers, operationPolicies, streamPolicies, permissionVerbs, permissions, contentDigest (48B), issuedAtMs (u64), signerEdPk (32B), signerDsaPk (1952B), publisherCert? }`, at most 16 MiB. Message prefix `pal3-ext-bundle-v1`, ML-DSA context `pal3-ext-sig-v1`.
   - Publisher certificate `body`: `{ v: 3, publisherId, issuerEdPk, issuerDsaPk, publisherEdPk, publisherDsaPk, allowedExtensions, allowedPermissions, issuedAtMs (u64), expiresAtMs (u64) }`. Message prefix `pal3-ext-publisher-cert-v1`, ML-DSA context `pal3-ext-cert-v1`.
   - Vectors: `test-vectors/v3/pal3-v0.6-extension-signing-vectors.json`.

### A.6 Protocol Version and Suite Registry
- **Wire protocol version:** `0x0003` (`PAL/3`).
- **Cipher suite registry:**

  | Id | Suite |
  |---|---|
  | `0x0000` | Reserved. MUST NOT be assigned. |
  | `0x0001` | `X25519 + ML-KEM-768`, `Ed25519 + ML-DSA-65`, ChaCha20-Poly1305 IETF, SHA-384 |
  | `0x0002`, `0x0003` | Not registered. The reference implementation carries optional CNSA (`0x0002`) and BSI AES-256-GCM (`0x0003`) suites that are implementation-private until their key-share carriage is specified here. |

  Every registered suite MUST pair a classical KEM with a post-quantum KEM (ML-KEM) and a classical signature with a post-quantum signature (ML-DSA or SLH-DSA), both verified strict-AND (D3). A classical-only suite MUST NOT be assigned an id. A suite with different key-share sizes MUST define how its key shares are carried before it is registered.
- **Capability tokens:** sorted, unique, comma-separated UTF-8 tokens in HELLO `0x0008` and in the encrypted identity `0x0002`. The session uses the intersection. Core tokens: `core.v1`, `stream.v1`, `grants.v1`; `seal.v1` is sealing to an identity and its devices (§11.4); `diag.v1` is the diagnostics extension (§11.0); `swarm.v1` is swarm offloading (§8.5); `pad.v1` is `CTRL` record padding (§6.1); `fec.v1` is XOR forward error correction on C2 (A.4); `onion/2` and `onion/3` are multi-hop relay cells (§15, §15.9); `relay-seal.v1` is sealed relay reservations (§14.10); `relay-multihop.v1` is optional multi-hop carried sessions (§14.10). `c2-key-update` rotates the C2 packet keys with every record-layer rekey (§3.2, §5.3) and is advertised by default. `c2-cid-v2` issues and rotates 8-byte connection IDs on C2 (§3.2, A.4) and is advertised by default. Optional: `c2-bulk-plaintext-record` allows plaintext `DATA` records on `pal3/bulk/0..1` over direct paths; it takes effect only together with `c2-key-update` on carrier C2 (§6.2).
- **Swarm error codes** (`ERROR.code`): `E_BUSY` (text form `E_BUSY: retry after <n> ms`), `E_SWARM_PROOF_REQUIRED`, `E_SWARM_PROOF_INVALID`, `E_SWARM_NOT_REDISTRIBUTABLE`, `E_SWARM_NOT_NEGOTIATED`.
- **This draft:** PAL/3 Draft 0.6.23, implemented by `@hn2/protocol` 9.1.0 and later (hn2/pal-core, `packages/protocol`). Conformance vectors: `test-vectors/v3/pal3-v0.5-vectors.json`, `test-vectors/v3/pal3-v0.6-beacon-vectors.json`, `test-vectors/v3/pal3-v0.6-chunk-outboard-vectors.json`, `test-vectors/v3/pal3-v0.6-core-operations.json`, `test-vectors/v3/pal3-v0.6-core-vectors.json`, `test-vectors/v3/pal3-v0.6-device-revocation-vectors.json`, `test-vectors/v3/pal3-v0.6-enrollment-binding-vectors.json`, `test-vectors/v3/pal3-v0.6-extension-signing-vectors.json`, `test-vectors/v3/pal3-v0.6-grant-vectors.json`, `test-vectors/v3/pal3-v0.6-hardening-vectors.json`, `test-vectors/v3/pal3-v0.6-header-protection-vectors.json`, `test-vectors/v3/pal3-v0.6-identifier-vectors.json`, `test-vectors/v3/pal3-v0.6-local-policy-vectors.json`, `test-vectors/v3/pal3-v0.6-multi-seal-vectors.json`, `test-vectors/v3/pal3-v0.6-nat-traversal-vectors.json`, `test-vectors/v3/pal3-v0.6-onion2-vectors.json`, `test-vectors/v3/pal3-v0.6-onion3-vectors.json`, `test-vectors/v3/pal3-v0.6-pair-rendezvous-vectors.json`, `test-vectors/v3/pal3-v0.6-pex-vectors.json`, `test-vectors/v3/pal3-v0.6-plaintext-record-vectors.json`, `test-vectors/v3/pal3-v0.6-prekey-vectors.json`, `test-vectors/v3/pal3-v0.6-primitive-vectors.json`, `test-vectors/v3/pal3-v0.6-private-network-accept-vectors.json`, `test-vectors/v3/pal3-v0.6-private-network-vectors.json`, `test-vectors/v3/pal3-v0.6-private-share-vectors.json`, `test-vectors/v3/pal3-v0.6-registry-vectors.json`, `test-vectors/v3/pal3-v0.6-rekey-vectors.json`, `test-vectors/v3/pal3-v0.6-reset-vectors.json`, `test-vectors/v3/pal3-v0.6-sas-vectors.json`, `test-vectors/v3/pal3-v0.6-sealed-hello-vectors.json`, `test-vectors/v3/pal3-v0.6-sealed-relay-vectors.json`, `test-vectors/v3/pal3-v0.6-swarm-vectors.json`, `test-vectors/v3/pal3-v0.6-transport-policy-vectors.json`, `test-vectors/v3/pal3-v0.6-transport-vectors.json`. `pal3-v0.6-onion2-generate.mjs`, `pal3-v0.6-onion3-generate.mjs` and the other `*-generate.mjs` files in that directory, and `bin/generate-v0.6-*-vectors.mjs`, regenerate vector files.
