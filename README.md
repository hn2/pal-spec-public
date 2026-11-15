# PAL Protocol Specification (`pal-spec`)

[![Current Spec](https://img.shields.io/badge/PAL%2F3.0-Draft_0.6.11-blue.svg)](spec/v3/PAL-3.0.md)
[![Copyright](https://img.shields.io/badge/Copyright-%C2%A9_2026_Palexplorer-informational.svg)](LICENSE)

Publicly readable specification and deterministic conformance test-vector repository for the **PAL Peer-to-Peer Wire Protocol** family (`PAL/3.0` and future generations `PAL/4.0+`), developed by [Palexplorer](https://palexplorer.com).

---

## Specification Versions

| Generation | Status | Normative Specification | Conformance Vectors | Summary |
|---|---|---|---|---|
| **PAL/3.0** | **Current**: Draft 0.6.11, `@hn2/protocol` 5.1.0 | [`spec/v3/PAL-3.0.md`](spec/v3/PAL-3.0.md) | [`pal3-v0.5-vectors.json`](test-vectors/v3/pal3-v0.5-vectors.json), [`pal3-v0.6-swarm-vectors.json`](test-vectors/v3/pal3-v0.6-swarm-vectors.json), [`pal3-v0.6-core-operations.json`](test-vectors/v3/pal3-v0.6-core-operations.json), [`pal3-v0.6-core-vectors.json`](test-vectors/v3/pal3-v0.6-core-vectors.json), [`pal3-v0.6-primitive-vectors.json`](test-vectors/v3/pal3-v0.6-primitive-vectors.json), [`pal3-v0.6-beacon-vectors.json`](test-vectors/v3/pal3-v0.6-beacon-vectors.json), [`pal3-v0.6-prekey-vectors.json`](test-vectors/v3/pal3-v0.6-prekey-vectors.json), [`pal3-v0.6-reset-vectors.json`](test-vectors/v3/pal3-v0.6-reset-vectors.json), [`pal3-v0.6-transport-vectors.json`](test-vectors/v3/pal3-v0.6-transport-vectors.json), [`pal3-v0.6-onion2-vectors.json`](test-vectors/v3/pal3-v0.6-onion2-vectors.json), [`pal3-v0.6-private-network-vectors.json`](test-vectors/v3/pal3-v0.6-private-network-vectors.json) | Zero-TCP, zero-BitTorrent, mandatory hybrid Post-Quantum (`X25519 + ML-KEM-768` / `Ed25519 + ML-DSA-65`) wire protocol over WebRTC DataChannels and PAL-UDP |
| **PAL/4.0+** | Reserved | `spec/v4/` *(future)* | `test-vectors/v4/` *(future)* | Reserved for future cryptographic suite agility and transport generations |

---

## What Is Published Here vs. Kept Private

- **Published in `pal-spec`:**
  - The normative wire protocol specification (`spec/v3/PAL-3.0.md`): byte-exact TLV encodings, 1-RTT identity-protected SIGMA-I hybrid post-quantum handshake, hybrid KEM combiner (HKDF-SHA-256 over both shared secrets and the key-exchange context), `ChaCha20-Poly1305` records with a 20-byte header, domain-separated `BLAKE2b-256` 256 KiB Merkle tree equations, capability grant evaluation order, `PAL-EXT-SIG-V3` extension bundle signing, and `diag.v1` diagnostics.
  - Deterministic byte-exact conformance test vectors (`test-vectors/v3/pal3-v0.5-vectors.json`) and zero-dependency validator (`validate.mjs`).
  - Vector coverage today: TLV, comprehension bits, key schedule, record AEAD, LAN beacon and identity digest (v0.5); BLAKE2b-256, Merkle trees, stateless cookie and PoW, resumption binder, manifest revision, swarm decisions, busy clamp, relay tree, negotiation, pair beacon, signed prekey, stateless reset, mailbox location key, private network profile and `onion/2` relay cells (v0.6). Rekey, C2 header protection, grants, Quick Drop SAS and extension signing have no vectors yet.
- **Strictly Proprietary (Not Published):**
  - The Palexplorer desktop/CLI/mobile applications, `pal-core` runtime engine, adaptive multi-source scheduler, and discovery/rendezvous server implementations remain closed-source and proprietary.

---

## Running the Conformance Validator

Requires Node.js 24.7+ (zero external npm dependencies):

```bash
npm run validate
npm test
```

---

## Copyright & Licensing

**Copyright © 2026 Palexplorer. All rights reserved.**

- **Specification Documents (`spec/**`, `README.md`):** Copyright © 2026 Palexplorer. Permission is granted to read, redistribute, and cite the unmodified specification for security auditing, regulatory review (NIS2/DORA/GDPR), academic research, and interoperable extension/SDK development. Publishing modified derivative standards under the `PAL` or `Palexplorer` name is prohibited, and all rights to the proprietary Palexplorer engine and trademarks are reserved.
- **Conformance Vectors & Validator (`test-vectors/**`, `validate.mjs`, `test/**`):** Released under the MIT License (`Copyright (c) 2026 Palexplorer`) for automated interoperability and cryptographic verification.

See [LICENSE](LICENSE) and [NOTICE](NOTICE) for full legal terms.
