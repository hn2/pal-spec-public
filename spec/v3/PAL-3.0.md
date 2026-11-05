# PAL/3.0 Post-Quantum Peer-to-Peer Wire Protocol Specification

> **Copyright © 2026 Palexplorer. All rights reserved.**
> Canonical Specification: `hn2/pal-spec` · Status: **Draft 0.5.2** (2026-11-05)
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

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals. `||` is byte concatenation; `u16be`/`u32be`/`u64be` are big-endian unsigned integers; `HKDF-Extract`/`HKDF-Expand` are RFC 5869 with SHA-256.

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
| O1 | Zero TCP in P2P | Zero TCP sockets during any P2P operation; WebRTC ICE with `enableIceTcp: false` | Static import gate, runtime socket guard, packet capture |
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
Content        signed manifests · BLAKE2b-256 Merkle trees (256 KiB blocks) · resume bitmaps
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
- The initiator retransmits `HELLO` with exponential backoff, starting at 250 ms with at most 5 tries. The responder answers a retransmitted `HELLO` with the same `ACCEPT` it cached for that `conn_id`, holding it for at most 10 s.

**Address validation.**
- Before allocating any session state or doing any post-quantum work for a non-loopback source, a responder MUST validate the source address with the stateless cookie exchange in §5.4.
- Until validation completes, the bytes a responder sends to an address MUST NOT exceed 3× the bytes it received from that address.

**Protected packets.** After the handshake, every packet is a `PROTECTED` packet:
```
type=0x02 (u8) || conn_id (u32be) || protected_pn (4 bytes) || AEAD ciphertext || tag (16)
```
- The packet key and IV are `HKDF-Expand(prk_0, "pal3-c2-k-v1" || u16be(0) || dir, 32)` and `HKDF-Expand(prk_0, "pal3-c2-iv-v1" || u16be(0) || dir, 12)`, where `dir` is `"i2r"` or `"r2i"`.
- Packet keys stay at epoch 0 for the life of the connection. The records inside are rekeyed per §5.3, and a connection closes after 2^20 authentication failures, well inside the ChaCha20-Poly1305 integrity limit.
- The nonce is `iv XOR (0^4 || u64be(pn))`. The AEAD is ChaCha20-Poly1305, with the 1-byte type, `conn_id` and unprotected `pn` (u32be low bits) as AAD.
- Header protection follows the QUIC model. `hp_key = HKDF-Expand(prk_0, "pal3-c2-hp-v1" || u16be(0) || dir, 32)`, `sample = ciphertext[0..16]`, and `mask = ChaCha20(hp_key, counter = u32le(sample[0..4]), nonce = sample[4..16])[0..4]`. The packet number is XORed with this mask.
- Packet numbers are 62-bit per direction and strictly increasing. The receiver reconstructs them from the low 32 bits around the largest acknowledged.
- Any packet that fails authentication is dropped silently. It never tears down the connection, so spoofed packets cannot reset, stall or acknowledge anything.

**Frames.** A frame starts with a u8 type. Frame types: `0x01 PADDING`, `0x02 ACK{largest u64, ack_delay_us u32, ranges}`, `0x03 STREAM{channel u8, offset u64, len u16, data}`, `0x04 MAX_DATA{channel u8, max_offset u64}`, `0x05 PING`, `0x06 CLOSE{code u16}`.

**Reliability and congestion.**
- Loss detection and probe timeouts follow RFC 9002: a packet threshold of 3, a time threshold of 9/8 × max(SRTT, latest RTT), and PTO = SRTT + max(4·RTTVAR, 1 ms) + max_ack_delay. `max_ack_delay` is 25 ms.
- A receiver acknowledges at least every second ack-eliciting packet for the first 100 packets of a connection, then at least every tenth, and always within 25 ms. It acknowledges immediately on reordering or a gap.
- Congestion control is a local sender choice and does not affect interoperability. It MUST react to loss at least as conservatively as RFC 9002 §7 NewReno. The reference implementation uses CUBIC (RFC 9438, β = 0.7, C = 0.4) by default, with an initial window of 10 × MSS and pacing. A new path restarts congestion control (RFC 9000 §9.4).
- A sender SHOULD occasionally skip a packet number and treat an ACK that covers a skipped or never-sent packet number as a fatal protocol violation (optimistic-ACK defense, RFC 9000 §21.4).
- Streams are reordered by offset, with a per-channel receive window advertised by `MAX_DATA`.

**Path validation and connection migration.**
- A `PROTECTED` packet from a new source address proves only that its sender holds the keys; the source may be spoofed. A receiver MUST keep sending on the current path until the new address is validated.
- **Path challenge:** the receiver sends `FR_PATH_CHALLENGE` with 8 random bytes to the new address. The peer echoes them in `FR_PATH_RESPONSE`. The connection moves only when the matching response arrives from that same address.
- **Bounded probing:** a receiver sends at most one challenge per max(SRTT, 50 ms) per connection and at most 3 challenges per candidate address. A peer queues at most 4 pending path responses.
- `conn_id` does not change during a connection.

**Efficiency.** Implementations SHOULD batch datagrams, using `sendmmsg`/GSO where available, and use one AEAD pass per packet. Handshake signature and KEM operations SHOULD run off the I/O thread (worker pool).

### 3.3 Record Sizing
`MAX_DATA_PAYLOAD = 65,536` bytes and `MAX_RECORD_WIRE = 65,572` bytes (a 20-byte header plus a 16-byte tag). A 256 KiB Merkle block is carried in at most four `DATA` records.

---

## 4. Rendezvous & NAT Traversal

A peer is identified by its **Identity Key** (`Ed25519` 32 B + `ML-DSA-65` 1,952 B), and each machine by a **Device Key** certified by the Identity Key. Each peer also holds a secret 32-byte **Beacon Key**, which it shares with contacts only over an authenticated session (pairing). Rotating the beacon key and re-sharing it with the remaining contacts revokes a former contact's ability to track the peer.

| ID | Mechanism | Normative Behavior |
|---|---|---|
| R1 | LAN multicast (`239.255.42.99:52473`) | Announces `tag = HMAC-SHA-256(HKDF-Expand(beacon_key, "pal3-lan-v2", 32), u64be(floor(unix_sec / 900)))` with a 16-byte random nonce. Contacts holding the beacon key match it within ±1 epoch. Others cannot link tags, even if they know the identity public key. |
| R2 | Endpoint cache | Persists the last verified `(ip, port, family, lastSeen)` per device for direct reconnect. |
| R3 | Serverless WAN mailbox (PAL-DHT) | Stores sealed signaling blobs under `HMAC-SHA-256(HKDF-Expand(beacon_key, "pal3-wan-mailbox-v2", 32), u64be(floor(unix_sec / 900)))`. Stores MUST accept only well-formed sealed envelopes and MUST cap blobs per key, keys, and total bytes. DHT records are bounded at 32 KiB. |
| R4 | Mutual peer introducer | Forwards sealed blobs over `pal3/ctl` (`rendezvous.forward`). It cannot decrypt or forge them. |
| R5 | Optional server extensions | Self-hosted rendezvous, `@handle` discovery, TURN. |

**Signaling blobs.**
- Replay-cache capacity is partitioned: senders the receiver does not know may use at most 25%, so free Sybil identities cannot lock out contacts.
- Every blob MUST be hybrid-sealed to the recipient's static signaling keys and hybrid-signed by the sender.
- A blob carries an outer `timestamp_ms`, bound into the AEAD AAD. Receivers MUST reject a blob outside ±5 min **before** any ML-KEM decapsulation or ML-DSA verification.
- The inner `(session_id, timestamp_ms)` MUST equal the outer values.
- The replay cache keyed on `(sender, session_id, signal_seq)` MUST NOT evict an entry while it is still live, and MUST cap entries per sender. When it is full of live entries, new blobs are refused (fail closed).

### 4.1 NAT Traversal Hierarchy (N1–N7)
1. **N1, IPv6 direct:** Use global unicast candidates (`2000::/3`, excluding documentation prefixes).
2. **N2, router port mapping:** Use PCP, NAT-PMP or UPnP-IGD for the muxed port, and detect CGNAT.
3. **N3, serverless reflexive discovery (`addr.observe`):** Connected peers report the caller's observed source. A reported address is accepted only if it is global unicast and confirmed by ≥ 2 **distinct observer identities** on distinct `/24` (IPv4) or `/48` (IPv6) prefixes. Each identity holds one observation and each prefix holds one observer. Observations expire after 10 min and the table is bounded. Implementations SHOULD prefer observations from contacts.
4. **N4, simultaneous open:** Paced connectivity checks at 20 ms intervals.
5. **N5, symmetric NAT port prediction:** Bounded probing with max 64 sockets and ≤ 50 probes/s for 3 s.
6. **N6, end-to-end encrypted peer relay:**
   - The relay issues a hybrid-signed `RelayReservation`. Its fields are session ID, relay keys, the client's hybrid identity digest, issue and expiry times, byte quota and bandwidth cap (defaults: 15 min, 256 MiB, 2 MiB/s).
   - Verification MUST pin the relay identity and MUST bind the presenting client and session. The relay MUST meter the quota and the rate per token, shared across all connections that present it.
   - The relay forwards opaque `RELAY{session_id, opaque_record}` frames.
   - The path upgrades to direct through authenticated `path.challenge`/`path.response` (an HMAC under the exporter secret that binds the candidate address) and `PATH_SWITCH{switch_id, last_seq}`.
7. **N7, TURN and UDP 443 fallback:** Optional (off by default).

### 4.2 Reachability Tiers & AutoNAT
- **High ID:** Inbound reachability is verified by port mapping or `autonat.dialback`. These peers can act as introducers (`buddy.intro`).
- **Medium ID:** The NAT uses endpoint-independent mapping, so peers can hole-punch.
- **Low ID:** Symmetric NAT, CGNAT or blocked UDP. These peers use N6 or N7.

### 4.3 Happy-Eyeballs Multipath
Candidates are raced in this order: `lan` > `direct_udp` > `stun_punch` > `udp_443` > `buddy_relay` > `turn_relay`. A relay-bound session migrates to a validated direct path with zero dropped bytes.

### 4.4 Identity Pins
A pin is `identity_digest = SHA-256("pal3-identity-v1" || ed25519_pk || mldsa65_pk)` (32 bytes). Every place that pins a peer MUST compare the full hybrid digest. This covers handshake target identities, manifest owners, grant issuers, signaling senders, diagnostic signers, relays and extension roots. Ed25519-only pins are forbidden (D3), because they would let a party that can forge Ed25519 substitute its own ML-DSA key.

---

## 5. Session Handshake (1-RTT, Identity-Protected Hybrid SIGMA-I)

### 5.1 Wire Messages (on `pal3/ctl`, Deterministic Binary TLV)

```
HELLO   I→R (clear):  version_list, suite_list, nonce_I (32B), cookie (0|32B),
                      x25519_eph_I (32B), mlkem_ek_I (1184B), capabilities_I, [extensions]
ACCEPT  R→I (clear):  version (u16), suite (u16), nonce_R (32B), x25519_eph_R (32B), mlkem_ct (1088B),
                      encrypted_identity_R = ChaCha20-Poly1305(k_id, nonce = 0^12, aad = th_hs,
                          TLV{ device_cert_R, capabilities_R, revocation_version_R (u64), [extensions],
                               sig_ed25519_R (64B), sig_mldsa65_R (3309B) })
        sig_R signs "pal3-hs-v2-responder" || SHA-256(HELLO || ACCEPT_clear || identity_body_R)
FINISH  I→R (first encrypted record on pal3/ctl, epoch 0, seq 0, type CTRL):
                      device_cert_I, revocation_version_I (u64), expected_id_R (0|32B identity digest),
                      [extensions], sig_ed25519_I, sig_mldsa65_I
        sig_I signs "pal3-hs-v2-initiator" || SHA-256(HELLO || ACCEPT || finish_body_I)
READY   R→I (first encrypted record R→I on pal3/ctl): CTRL{op: "ready"}
```

**Suite negotiation.**
- `suite_list` lists the initiator's suites in preference order. The responder selects the first entry it supports and echoes it in ACCEPT `suite`. If no entry is supported, it aborts with `E_PAL3_DOWNGRADE`.
- The initiator MUST abort with `E_PAL3_DOWNGRADE` if ACCEPT names a suite it did not offer.
- Both signatures cover HELLO, so a stripped or reordered `suite_list` breaks authentication.
- Every suite in the registry is hybrid (A.6). No negotiation outcome can produce a classical-only session.

Here `ACCEPT_clear` is the TLV of tags `0x0001..0x0006` of ACCEPT, `identity_body_R` is the encrypted identity TLV without its signature tags, and `finish_body_I` is the FINISH TLV without its signature tags.

**Identity protection.**
- A passive observer learns neither identity.
- The initiator reveals its identity only after it has authenticated the responder, so its identity is protected even against an active attacker.
- The responder reveals its identity to any initiator that completes the KEM. This is the same exposure as TLS 1.3 and Noise XX, and responders that need more SHOULD accept only `SEALED_HELLO` from known contacts.
- `SEALED_HELLO` (type `0x04`) hybrid-seals the HELLO to the responder's static signaling keys, so it travels opaquely through relays.

### 5.2 Cryptographic Rules & Key Schedule
- **Strict-AND hybrid signatures:** Both `Ed25519` and `ML-DSA-65` (FIPS 204 context `"pal3-hs-v2"`) MUST verify, or the handshake aborts.
- **Device certificate:** Certifies the device Ed25519 and ML-DSA keys under the identity keys over `"pal3-devcert-v1" || SHA-256(cert_body)`, with FIPS 204 context `"pal3-devcert-v1"`. Self-bound single-device identities MAY use `flags = 0x01` (no duplicate device keys). The issue and expiry times are verified against the local clock, with ±5 min skew allowed for issue.
- **Key schedule (suite `0x0001`):**
  1. `ss_x = X25519(eph_sk, peer_eph_pk)`. An all-zero result MUST be rejected.
  2. `ss_pq = ML-KEM-768.Decaps(dk_I, mlkem_ct)` on the initiator, or `Encaps(ek_I)` on the responder.
  3. `kem_context = x25519_eph_I || x25519_eph_R || SHA-256(mlkem_ek_I) || SHA-256(mlkem_ct)` (128 bytes).
  4. `ikm = ss_x || ss_pq || kem_context` (192 bytes).
  5. `th_hs = SHA-256(HELLO || ACCEPT_clear)`, then `prk_hs = HKDF-Extract(salt = th_hs, ikm)`.
  6. `k_id = HKDF-Expand(prk_hs, "pal3-hs-id-v2", 32)`.
  7. `th = SHA-256(HELLO || ACCEPT)`, then `prk_0 = HKDF-Extract(salt = th, ikm = prk_hs)`.
  8. For each channel `ch_id` (0–3) and direction `dir` (`"i2r"` or `"r2i"`):
     - `key = HKDF-Expand(prk_e, "pal3-k-v1" || u16be(e) || u8(ch_id) || dir, 32)`
     - `salt = HKDF-Expand(prk_e, "pal3-s-v1" || u16be(e) || u8(ch_id) || dir, 4)`
  9. `exporter_secret_e = HKDF-Expand(prk_e, "pal3-exp-v1" || u16be(e), 32)`.

  `HKDF-Expand` is applied directly to the PRK, with no second Extract. All intermediate secrets MUST be zeroized after use.

### 5.3 Rekey (`REKEY`)
**Triggers.**
- Implementations MUST rekey automatically at the soft limits: 2^31 records on a channel, 32 GiB in either direction, or 1 hour per epoch.
- `seal` MUST refuse at the hard limits: 2^32 records or 64 GiB.

**Who may trigger.** Only application records may trigger an automatic rekey. A pending exchange that gets no answer is abandoned after 30 s.

**Exchange.**
- The exchange is `rekey_init{epoch, x25519_eph, mlkem_ek}` / `rekey_resp{epoch, x25519_eph, mlkem_ct}` on `pal3/ctl`.
- It derives `prk_{e+1} = HKDF-Extract(salt = exporter_secret_e, ikm = ss_x' || ss_pq' || kem_context')`.

**Simultaneous rekey.** If both sides send `rekey_init` for the same epoch, the session initiator's exchange wins. The initiator ignores the peer's `rekey_init`. The responder abandons its own exchange and answers the initiator's.

**Epoch transition.**
- Each side sends `REKEY{new_epoch, last_seq}` as its final epoch-`e` record on each channel and resets `channel_seq = 0` for the new epoch.
- A `REKEY` marker can arrive before the receiver has installed epoch `e+1`, because channels are ordered independently. The receiver MUST then queue that channel's subsequent records, at most 1024, until the epoch is installed. Receiving the marker early MUST NOT be treated as an error.

### 5.4 Address Validation & DoS Shield
1. **Stateless cookies (mandatory for non-loopback sources).**
   - The cookie is `cookie = HMAC-SHA-256(secret_epoch, "pal3-cookie-v1:" || ip || ":" || port || ":" || conn_id || ":" || floor(unix_ms / 60000) || ":" || pow_bits)[0..14] || u8(pow_bits)`. It is carried in a 28-byte `PKT_COOKIE_CHALLENGE` (`0x06`) and echoed in the client's next INITIAL packets.
   - The difficulty is authenticated inside the cookie, so the server verifies the puzzle at exactly the difficulty it issued.
   - `secret_epoch` rotates every 2 minutes. The previous epoch is accepted.
   - Cookies are single-use per `(port, conn_id)`.
   - No session state or post-quantum operation is performed for an unvalidated source.
   - The HELLO-level `COOKIE_REQ` (`0x03`, 32-byte cookie over `SHA-256(HELLO without cookie)`) is an equivalent stateless retry for carriers without a pre-handshake packet exchange, such as C1.
2. **Anti-amplification.**
   - A 28-byte challenge is smaller than any INITIAL packet (≥ 33 bytes), so challenges cannot amplify. Pre-validation replies are limited to 3× the received bytes.
   - Challenge budgets exist only to stop non-amplifying reflection. They MUST be generous enough that spoofed floods cannot starve legitimate clients of challenges (per source ≥ 1024 per 10 s).
3. **Adaptive proof-of-work.**
   - Under load, `pow_bits` scales from 12 upward, adding 1 bit per doubling of the handshake rate beyond the trigger, up to a cap of 22.
   - The solution must satisfy `SHA-256("pal3-pow-v1" || cookie || u32be(conn_id) || u32be(pow_nonce))` ≥ `pow_bits` leading zeros.
   - A wrong solution is dropped and is not counted as a violation.
   - Clients MUST refuse `pow_bits` > 22 and answer at most 3 challenges per connection attempt, because challenges are unauthenticated.
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
ticket = AEAD(ticket_key, TLV{ resumption_secret, peer identity digest, peer cert hash, issued_at, expires_at (≤ 7 days) })
resumption_secret = HKDF-Expand(prk_0, "pal3-res-v1", 32)
```
A resuming initiator sends a `HELLO` carrying `psk_ticket` (tag `0x0009`) and `psk_binder` (tag `0x000A`), with fresh `x25519_eph_I` and `mlkem_ek_I`. `psk_binder` is `HMAC-SHA-256(HKDF-Expand(resumption_secret, "pal3-binder-v1", 32), SHA-256(HELLO without binder))`.

On a valid binder for an unexpired, unused ticket, the responder answers with a resumed ACCEPT. It carries `psk_accepted` (tag `0x0007`, u8 `1`) in the clear part and no certificate or signatures. Any other ticket is ignored, and the responder completes a full handshake from the same HELLO. The resumed schedule uses:
- `prk_hs = HKDF-Extract(salt = th_hs, ikm = ikm || resumption_secret)`, where `th_hs` covers ACCEPT_clear including `psk_accepted`.
- `encrypted_identity_R` carries `capabilities_R`, `revocation_version_R` and `confirm` (tag `0x0004`) `= HMAC(k_id, th_hs)`.
- FINISH carries `revocation_version_I` and `finished` (tag `0x0004`) `= HMAC(HKDF-Expand(prk_hs, "pal3-res-fin-v1", 32), SHA-256(HELLO || ACCEPT))`, with no certificate or signatures.
- Each side uses the peer certificate from the original session: the initiator keeps it, and the responder stores it in the ticket. The certificate is re-checked for expiry.
- The ticket is delivered after a full handshake as `CTRL{op: "resumption_ticket", ticket}` on `pal3/ctl`.

**Properties.**
- Fresh hybrid KEM shares keep forward secrecy and post-quantum confidentiality.
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
- **Metadata:** On C1 the record header is inside DTLS, and on C2 it is inside the packet AEAD (§3.2). Only relays see record headers in the clear, through `RELAY` frames. Senders SHOULD pad `CTRL` records to 256-byte buckets.

---

## 7. Operations & Credit-Controlled Streams

- **Requests:** Each request uses a directional `stream_id` (odd for the initiator, even for the responder, 0 for control), an ASCII operation name of ≤ 128 bytes, and a deterministic binary body.
- **Credit flow control:** Receivers grant credits with `CREDIT{credit}` (bytes granted). The initial window is 512 KiB per stream, auto-tuned up to 16 MiB from RTT × throughput. The cap is 64 MiB per connection across all streams. Sending beyond granted credit is fatal.
- **Core operations:** `share.list`, `share.manifest`, `share.browse`, `file.read`, `file.readBatch`, `media.stream`, `have`, `sources`, `pex.exchange`, `buddy.intro`, `autonat.dialback`, `path.challenge`, `path.response`, `identity.state`, `addr.observe`, `rendezvous.forward`, `sync.offer`, `sync.manifest`, `sync.push`, `sync.ack`, `wishlist.poll`, `access.request`, `access.resolve`, `quickdrop.offer`, `quickdrop.accept`, `chat.message`, `chat.receipt`, `group.invite`, `group.event`, `device.sync`, `grant.request`, `grant.issue`, `grant.revoke`, `receipt.delivery`, `presence`, `ping`.
- **Extensions:** All other operations (for example `diag.*`, `live.*`, `buddy.relay`, `sign.*`, `msg.deliver`, `drop.offer`) are extension operations (§12), and each is registered with a capability and a permission verb.

---

## 8. Content Model & BLAKE2b-256 Merkle Trees

### 8.1 Domain-Separated Merkle Tree (256 KiB Blocks)
- **Blocks:** `BLOCK_BYTES = 262,144`, and `num_blocks = ceil(size / 262144)`.
- **Empty file:** `empty_root = BLAKE2b-256(0x02 || u64be(0))`.
- **Leaf:** `BLAKE2b-256(0x00 || u64be(index) || u32be(len) || block)`.
- **Node:** `BLAKE2b-256(0x01 || u8(level) || left || right)`. An unpaired rightmost node is promoted unchanged.
- **Content ID:** `pal3:b2t:<root-hex-64>:<size-decimal>`.
- **Pre-write verification:** Receivers MUST verify the index bounds, the exact length and the inclusion proof against the signed `(root, size)` before writing.

### 8.2 Hybrid-Signed Manifests, Rollback & Equivocation
- **Signing:** Manifests are signed by the owner's hybrid identity under context `"pal3-manifest-v1"`. Each carries `revision_counter (u64)` and `author_device_id (16B)`.
- **Rollback state:** Receivers MUST persist `(revision_counter, author_device_id, manifest_hash = SHA-256(body))` per share, and verification MUST be given this state, with "none" allowed only for a share seen for the first time.
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
   - Piece hash lists MUST be bound to a trusted root before use. The piece Merkle root is domain-separated: the leaf is `SHA-256("pal3-piece-leaf-v1" || u64be(i) || h)`, the node is `SHA-256("pal3-piece-node-v1" || u8(depth) || l || r)`, and an unpaired node is promoted.
   - Peers sending corrupt pieces are struck and banned after 3 strikes.
   - In-flight pieces time out (30 s) and are released when a peer leaves.
2. **Local deduplication:** A verified local match is copied from disk with zero network bytes.
3. **Preview priority:** Piece 0 and piece N−1 are fetched first for media containers.
4. **Upload queue:** Requests are ranked by `wait × clamp(credit, 0.5, 10) × priority × (friend ? 5 : 1)`, with reserved friend slots.
5. **PEX (`pex.exchange`):**
   - An entry is *verified* only when a peer announces its own address over an authenticated session, and the announced host equals the address that session was observed from.
   - Third-party entries may add unknown peers but MUST NOT overwrite a known peer's address. Their self-reported High-ID and piece counts MUST be ignored for ranking.
   - Hosts MUST be global unicast, unless a LAN-only swarm explicitly allows private addresses.
   - Tables are bounded with a TTL.

---

## 9. Capability Permissions Engine

- **Subjects:** `identity`, `device`, `group`, `link-capability` (bound to the first authenticated claimant), `password` (Argon2id-wrapped share key), `anonymous`.
- **Operations:** `list`, `read`, `stream`, `write`, `delete`, `reshare`, `chat`, `sync`, `relay`.
- **Constraints:** `expires_at_ms`, `not_before_ms`, `max_reads`, `max_bytes`, `bandwidth_bps`, `devices_max`, `time_window_utc`, `watermark`.
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
   - The sender sends `commitment = SHA-256("pal3-sas-commit-v1" || nonce_S)` in `quickdrop.offer`.
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
- **Identity metadata:** Identities and beacon tags are protected (§4, §5), so recorded traffic does not reveal who talked to whom.
- **Password-only shares:** Shares protected only by a password rely on Argon2id. Passphrases SHOULD have ≥ 75 bits of entropy.

### 11.2 Normative Hardening Invariants
1. **Low-order points:** Every X25519 operation rejects all-zero shared secrets.
2. **Caller binding:** All operations bind the acting identity to the handshake-verified certificate.
3. **Datagram reassembly:**
   - State is keyed by `(source, message_id)`, with per-source (16) and global (128) caps.
   - First write wins, and a conflicting duplicate fragment drops the message.
   - An inconsistent `total` drops only that packet.
   - Non-final fragments must be full-size, and entries expire after 5 s.
   - UDP servers MUST NOT allocate sessions for stray data packets.
4. **Revocation and credit bounds:** Revocation cuts off a device immediately. Peer credit is clamped to 16 MiB. Block lengths and ranges are validated.
5. **URI validation and quarantine:** `pal://` and `pal3://` parsers reject decoded `/`, `\`, `:`, `.`, `..` and control bytes. Received executables are never launched directly, and they are stamped with Mark-of-the-Web.
6. **Bounded state:** Every peer-influenced table is bounded with LRU and TTL. This covers shield sources, bans, cookies, the replay cache, mailboxes, PEX, reflexive observations and reassembly.

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
- **Wildcards:** A wildcard permission never implies `exec:*` or `native:*`.

### 12.3 Extension Isolation
- **Static analysis is not a boundary.** The static source analyzer is a linter. It rejects known escape patterns, such as `eval`, `Function`, computed imports, aliased `require`, module-loader internals and blocked modules, but it is **not** a security boundary.
- **Isolation is required.** Untrusted extension code MUST run in OS or process isolation: a separate process with Node's `--permission` model, or an equivalent sandbox without `child_process`, `vm`, `worker_threads` or native addons, and with only the file-system scope its permissions grant.

### 12.4 Local Settings and Policy

Implementations have local settings, such as pacing, compression, packet padding, resume journals and inbound or outbound firewall policy. These are not wire protocol and are not negotiated. A local setting MUST NOT change the handshake, the cipher suite, the key schedule or the record format, and turning one off MUST NOT weaken a session's cryptography. A local policy that refuses a peer or an operation does so with the normal error records (§6.1, §9).

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

#### `HELLO` (`record.type = 0x01`)
| Tag | Field | Encoding |
|---|---|---|
| `0x0001` | `version_list` | `2·N` bytes of u16be (`0x0003`) |
| `0x0002` | `suite_list` | `2·N` bytes of u16be, preference order (`0x0001`) |
| `0x0003` | `nonce_I` | 32 B |
| `0x0004` | `cookie` | 0 or 32 B |
| `0x0006` | `x25519_eph_I` | 32 B |
| `0x0007` | `mlkem_ek_I` | 1184 B |
| `0x0008` | `capabilities_I` | sorted comma-separated ASCII tokens |
| `0x0009` | `psk_ticket` | resumption only (§5.5) |
| `0x000A` | `psk_binder` | resumption only, 32 B |

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

Encrypted identity TLV, resumed handshake: `0x0002`, `0x0003`, `0x0004 confirm` (32 B), extension tags.

#### `FINISH` (`record.type = 0x10 CTRL`, epoch 0, seq 0)
| Tag | Field | Encoding |
|---|---|---|
| `0x0001` | `device_cert_I` | nested TLV |
| `0x0002` | `revocation_version_I` | u64be |
| `0x0003` | `expected_id_R` | 0 or 32 B identity digest |
| `0x0004` | `finished` | 32 B, resumed sessions only (replaces tags `0x0001`, `0x0003`, `0x0009` and `0x000A`) |
| `0x0009` | `sig_ed25519_I` | 64 B |
| `0x000A` | `sig_mldsa65_I` | 3309 B |

### A.2 Conformance Vectors
`hn2/pal-spec/test-vectors/v3/pal3-v0.5-vectors.json` contains vectors for TLV encoding, comprehension bits, the Draft 0.5 key schedule (`prk_hs`, `k_id`, `prk_0`, channel key, salt and exporter), record AEAD framing, beacon tags and identity digests.

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
   - Puzzle: find `pow_nonce` such that `SHA-256("pal3-pow-v1" || cookie || conn_id (u32be) || pow_nonce (u32be))` has at least `pow_bits` leading zero bits. A client MUST refuse `pow_bits > 16` (`E_PAL3_POW_TOO_HARD`).
3. **`PKT_PROTECTED` (`0x02`):** 9-byte header, ciphertext, 16-byte Poly1305 tag.
   ```
   type (u8 = 0x02) | conn_id (u32be) | protected_pn (u32be) | ciphertext || tag (16B)
   ```
   - AEAD: ChaCha20-Poly1305 IETF. AAD is the unprotected header `type || conn_id || pn_low32`. Nonce = `iv[0..4] || (iv[4..8] XOR hi32(pn)) || (iv[8..12] XOR lo32(pn))`.
   - Header protection: `sample = ciphertext[0..16]`; `mask = ChaCha20-IETF(hp_key, counter = u32le(sample[0..4]), nonce = sample[4..16])` applied to 4 zero bytes; `protected_pn = pn_low32 XOR mask`. The full packet number is reconstructed as in RFC 9000 §A.3 with a 32-bit window.
4. **Frames inside `PKT_PROTECTED` plaintext.** An unknown frame type is fatal (`E_PAL3_C2_FRAME`). `channel` is 0..3.

   | Type | Frame | Layout after the type byte |
   |---|---|---|
   | `0x01` | `PADDING` | none |
   | `0x02` | `ACK` | `largest (u64be) \| ack_delay_us (u32be) \| extra_ranges (u8) \| first_range_len (u32be) \| (gap (u32be) \| range_len (u32be))*` |
   | `0x03` | `STREAM` | `channel (u8) \| offset (u64be) \| len (u16be) \| data` |
   | `0x04` | `MAX_DATA` | `channel (u8) \| max_stream_data (u64be)` |
   | `0x05` | `PING` | none (ack-eliciting) |
   | `0x06` | `CLOSE` | `code (u8) \| reason_len (u8) \| reason (utf8, ≤ 255 bytes)` |
   | `0x07` | `PATH_CHALLENGE` | `data (8B)` |
   | `0x08` | `PATH_RESPONSE` | `data (8B)` |
   | `0x09` | `STREAM_RESET` | `channel (u8) \| final_size (u64be)` |
   | `0x0A` | `STOP_SENDING` | `channel (u8)` |

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
2. **Signed manifest** (§8.2): PAL-CBOR map `{ body, sigEd25519, sigMldsa65 }`. `body` is the encoded map `{ v: 1, shareId (16B), ownerEdPk, ownerDsaPk, revisionCounter (u64), authorDeviceId (16B), publishedAtMs (u64), encrypted, entries, extensions?, pad? }`, at most 16 MiB.
3. **Signed capability grant** (§9): PAL-CBOR map `{ body, sigEd25519, sigMldsa65 }`. `body` is `{ v: 1, grantId, issuerEdPk, issuerDsaPk, subjectType, subjectId, resource, operations (sorted, unique), issuedAtMs, notBeforeMs, expiresAtMs, maxReads, maxBytes, bandwidthBps, devicesMax, requirePq: true, watermark }`. A zero limit means no limit. `subjectType` is one of `identity`, `device`, `group`, `link-capability`, `password`, `anonymous`.
4. **Hybrid signature over a signed object:** `msg = ascii(context) || SHA-256(body)`. `sigEd25519 = Ed25519(msg)` and `sigMldsa65 = ML-DSA-65(msg, ctx = context)`. Both MUST verify (D3). Contexts: `pal3-manifest-v1`, `pal3-grant-v1`.

### A.6 Protocol Version and Suite Registry
- **Wire protocol version:** `0x0003` (`PAL/3`).
- **Cipher suite registry:**

  | Id | Suite |
  |---|---|
  | `0x0000` | Reserved. MUST NOT be assigned. |
  | `0x0001` | `X25519 + ML-KEM-768`, `Ed25519 + ML-DSA-65`, ChaCha20-Poly1305 IETF, BLAKE2b-256 |

  Every registered suite MUST pair a classical KEM with a post-quantum KEM (ML-KEM) and a classical signature with a post-quantum signature (ML-DSA or SLH-DSA), both verified strict-AND (D3). A classical-only suite MUST NOT be assigned an id. A suite with different key-share sizes MUST define how its key shares are carried before it is registered.
- **Capability tokens:** sorted, unique, comma-separated UTF-8 tokens in HELLO `0x0008` and in the encrypted identity `0x0002`. The session uses the intersection. Core tokens: `core.v1`, `stream.v1`, `grants.v1`; `diag.v1` is the diagnostics extension (§11.0).
- **This draft:** PAL/3 Draft 0.5.2, implemented by `@hn2/protocol` 5.0.0.
