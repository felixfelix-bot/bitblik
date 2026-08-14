# BitBlik Ring Signature Trust Proof — LSAG Demo

> **"I am one of N trusted people" — without revealing who.**

A TypeScript demo of Linkable Spontaneous Anonymous Group (LSAG) ring signatures on secp256k1, applied to BitBlik's P2P BLIK/Lightning exchange. The taker (code provider) proves membership in a coordinator's trusted set without disclosing their identity, and a key-image nullifier prevents proof reuse.

---

## Table of Contents

1. [The Problem](#1-the-problem)
2. [The Solution — LSAG Ring Signatures](#2-the-solution--lsag-ring-signatures)
3. [How It Works](#3-how-it-works)
4. [How to Run](#4-how-to-run)
5. [Demo Output](#5-demo-output)
6. [Q&A Breadcrumbs](#6-qa-breadcrumbs)
7. [Migration Path to Dart](#7-migration-path-to-dart)
8. [Terminology](#8-terminology)
9. [References](#9-references)

---

## 1. The Problem

BitBlik is a peer-to-peer BLIK/Lightning exchange over Nostr. The flow is:

1. **Taker** (code provider) funds a Lightning hold invoice and lists a BLIK code offer
2. **Maker** (cash withdrawer) reserves the offer and pays via BLIK code
3. **Coordinator** settles atomically — reveals the hold invoice preimage

**The risk**: The maker can be associated with fraud if the taker's BLIK code was funded with a stolen card. The maker needs assurance that the taker belongs to a trusted set — the coordinator's Nostr web-of-trust (follow list) — **without revealing which specific member** the taker is.

**Why not just check the follow list directly?** If the maker asks "are you pubkey X in the follow list?", the taker's identity is revealed. If the taker simply asserts "I'm in the list", there's no cryptographic proof. We need a mechanism that proves membership *and* preserves anonymity *and* prevents reuse.

---

## 2. The Solution — LSAG Ring Signatures

**LSAG (Linkable Spontaneous Anonymous Group)** signatures, introduced by Liu, Wei, and Wong (2004), provide exactly the three properties we need:

| Property | What it means | How LSAG delivers it |
|----------|---------------|----------------------|
| **Anonymity** | The verifier cannot determine which ring member signed | The signature is a ring of equations; every position is equally plausible |
| **Linkability** | Two signatures from the same key can be detected | A key image `I = x_s · H(P_s)` is deterministic per signer and included in every signature |
| **Spontaneity** | No group setup ceremony needed | The ring is formed from public keys the signer already knows |

**Why LSAG over alternatives?**

- **secp256k1 native**: Nostr keys ARE secp256k1/BIP-340 keys. The taker's npub is already a curve point on the right curve. No key conversion needed.
- **Key image = nullifier**: The key image is cryptographically bound to the signer's private key — stronger than a SHA256 hash of transaction data.
- **Simple enough for a demo**: ~200 lines of TypeScript. The math is ring closure over a hash chain.
- **Battle-tested**: LSAG is the foundation of Monero's ring signatures (later upgraded to MLSAG/CLSAG). Security properties are formally proven.

**Why NOT Borromean?** Not linkable — no key image, so no nullifier. We'd need a separate nullifier mechanism, which is weaker.

**Why NOT RingCT?** Designed for hiding transaction amounts in Monero. Massively over-engineered for a membership proof.

---

## 3. How It Works

### 3.1 The Cast

```
┌─────────────────────────────────────────────────────────────┐
│  COORDINATOR                                                │
│  Publishes kind 3 (Contact List) with trusted pubkeys       │
│  Each 'p' tag = one trusted member → this IS the ring       │
└─────────────────────────────────────────────────────────────┘
        │ follow list (kind 3)
        ↓
┌──────────────┐                          ┌──────────────┐
│   TAKER      │ ── ring signature ──→    │   MAKER      │
│ (code provider)                         │ (cash withdrawer)│
│ has x_s     │                          │ verifies     │
│ generates   │                          │ checks nullifier│
│ proof       │                          │              │
└──────────────┘                          └──────────────┘
```

### 3.2 Setup Phase (One-Time)

The coordinator maintains a Nostr identity and publishes a kind 3 (Contact List) event. Each `p` tag in the event contains the hex pubkey of a trusted member. This follow list IS the ring membership set — no custom event kind needed, it's standard NIP-02.

### 3.3 Proof Generation (Taker)

**Inputs:**
- `x_s` — taker's Nostr private key (32-byte scalar)
- `P_s` — taker's Nostr npub (in the follow list)
- Ring: `[P_0, P_1, ..., P_{N-1}]` — the coordinator's follow list pubkeys
- Message: `m = "bitblik/trust-proof/v1:{offer_id}:{tx_id}"`

**Steps:**

1. **Compute key image**: `I = x_s · H(P_s)`
   - `H()` is a hash-to-curve function: `H(data) = hash_to_curve("bitblik/trust-nullifier/v1" || data)`
   - Uses try-and-increment: hash with SHA256, attempt to decompress as a secp256k1 point, increment counter until valid

2. **Pick random scalar** `r_s` and compute the first challenge:
   ```
   L_s = r_s · G
   R_s = r_s · H(P_s)
   c_{s+1} = H(m, L_s, R_s)
   ```

3. **Walk the ring forward** (indices mod N):
   ```
   For i = s+1, s+2, ..., s-1 (wrapping around):
     L_i = r_i · G + c_i · P_i
      R_i = r_i · H(P_i) + c_i · I
      c_{i+1} = H(m, L_i, R_i)
   ```
   Each `r_i` for `i ≠ s` is a fresh random scalar.

4. **Close the ring** at the signer's index:
   ```
   r_s = r_s_random - c_s · x_s   (mod n)
   ```
   This is the critical closure step. It works because at index `s`, the verify equation computes:
   ```
   L_s = r_s · G + c_s · P_s
       = (r_s_random - c_s · x_s) · G + c_s · (x_s · G)
       = r_s_random · G - c_s · x_s · G + c_s · x_s · G
       = r_s_random · G  ✓  (the c_s · x_s · G terms cancel)
   ```
   The same cancellation happens for `R_s` because `I = x_s · H(P_s)`.

5. **Output**: `(I, c_0, [r_0, r_1, ..., r_{N-1}])` plus the message and ring pubkeys.

> **Critical**: In the verify equation, `r_i` multiplies the base points (`G`, `H(P_i)`) and `c_i` multiplies the public keys (`P_i`, `I`). Swapping these roles breaks the closure — the `c_s · x_s` terms no longer cancel, leaving an irreducible `x_s² · c_s · G` term. See the [closure derivation](#closure-derivation) below.

### 3.4 Proof Verification (Maker)

**Inputs:**
- The proof from the taker (key image, ring pubkeys, c_0, responses, message)
- The coordinator's kind 3 event (fetched from relays)
- Local nullifier database (for reuse check)

**Steps:**

1. **Verify ring matches follow list**: `proof.ring_pubkeys` must match the `p` tags from the coordinator's kind 3 event (or be a subset, if subset rings are allowed).

2. **Recompute the ring**:
   ```
   c_1 = H(m, r_0 · G + c_0 · P_0, r_0 · H(P_0) + c_0 · I)
   c_2 = H(m, r_1 · G + c_1 · P_1, r_1 · H(P_1) + c_1 · I)
   ...
   c_0' = H(m, r_{N-1} · G + c_{N-1} · P_{N-1}, r_{N-1} · H(P_{N-1}) + c_{N-1} · I)
   ```

3. **Check closure**: `c_0' == c_0`. If the ring closes, the signature is valid.

4. **Check nullifier (key image)**:
   - If `I` is in the local nullifier DB with the same `tx_id` → already verified (idempotent OK)
   - If `I` is in the DB with a different `tx_id` → same signer detected (per-transaction policy: allowed for new transactions)
   - If `I` is not in the DB → store and accept

5. **Result**: The maker knows the taker is in the coordinator's follow list, does NOT know which specific pubkey, and the key image prevents proof replay.

### 3.5 The Verify Equation (Corrected)

The correct LSAG verify equation (per Liu-Wei-Wong 2004 and Monero's MLSAG implementation) is:

```
c_{i+1} = H(m, r_i · G + c_i · P_i, r_i · H(P_i) + c_i · I)
```

| Component | Correct (Liu-Wei-Wong) | Wrong (breaks closure) |
|-----------|----------------------|----------------------|
| Verify L  | `r_i · G + c_i · P_i` | `c_i · G + r_i · P_i` |
| Verify R  | `r_i · H(P_i) + c_i · I` | `c_i · H(P_i) + r_i · I` |
| Closure   | `r_s = r_s_random - c_s · x_s` | (same formula, but doesn't close) |

**The rule**: `r_i` multiplies the generators (`G`, `H(P_i)`); `c_i` multiplies the public keys (`P_i`, `I`). The signer's random `r_s` must multiply the generators in the initial `c_{s+1}` computation, and the same `r_s` (after closure adjustment) must multiply the same generators in verify. The challenge `c_s` multiplies the public keys which contain the secret, enabling cancellation.

<a name="closure-derivation"></a>
<details>
<summary>Closure derivation (click to expand)</summary>

At the signer's index `s`, verify computes:

```
L_s = r_s_final · G + c_s · P_s
    = (r_s_random - c_s · x_s) · G + c_s · (x_s · G)
    = r_s_random · G - c_s · x_s · G + c_s · x_s · G
    = r_s_random · G  ✓
```

The `c_s · x_s · G` terms cancel exactly, leaving `r_s_random · G` — which is the L-component the signer used to compute `c_{s+1}`.

Similarly for R:

```
R_s = r_s_final · H(P_s) + c_s · I
    = (r_s_random - c_s · x_s) · H(P_s) + c_s · (x_s · H(P_s))
    = r_s_random · H(P_s) - c_s · x_s · H(P_s) + c_s · x_s · H(P_s)
    = r_s_random · H(P_s)  ✓
```

**Why the wrong equation fails**: If we swap the terms to `c_i · G + r_i · P_i`:

```
L_s = c_s · G + r_s_final · P_s
    = c_s · G + (r_s_random - c_s · x_s) · (x_s · G)
    = c_s · G + x_s · r_s_random · G - x_s² · c_s · G
    = (1 + x_s · r_s_random - x_s² · c_s) · G
```

This is NOT equal to `r_s_random · G`. The `x_s² · c_s` term does not cancel. ✗

</details>

### 3.6 Nullifier Design

The LSAG key image `I = x_s · H(P_s)` IS the nullifier:

| Property | How it works |
|----------|-------------|
| **Deterministic** | Same private key → same key image, always |
| **Unlinkable to pubkey** | Given `P_s` and `I`, you cannot determine if `I` was derived from `P_s`'s private key (discrete log problem) |
| **Constant across messages** | Depends only on the signer's key, not the message — so the same taker signing different messages produces the same key image |
| **Forgeable only with private key** | Computing `I` requires `x_s` |

**Domain separator**: `"bitblik/trust-nullifier/v1"` — used in the hash-to-curve function to ensure the key image is specific to BitBlik and cannot be replayed from another protocol's ring signatures.

**Nullifier policy (demo)**: Per-transaction. The key image is stored with the `tx_id`. Same key image + same `tx_id` = replay (rejected). Same key image + different `tx_id` = new transaction (accepted). This allows the same taker to prove membership for multiple offers while preventing replay of the same proof.

---

## 4. How to Run

### Prerequisites

- Node.js 18+ (for `tsx` and native ESM support)
- npm or compatible package manager

### Install

```bash
cd demo/trust-proof
npm install
```

### Run the Demo

```bash
npm run demo
# or: npx tsx src/demo.ts
```

### Run Tests

```bash
npm test
# or: npx vitest run
```

### Type Check

```bash
npx tsc --noEmit
```

### Dependencies

| Package | Purpose |
|---------|---------|
| `@noble/curves` | secp256k1 curve operations (point multiplication, addition, scalar arithmetic) |
| `@noble/hashes` | SHA256 and hash-to-curve |
| `tsx` | TypeScript execution without build step |
| `vitest` | Test runner |
| `typescript` | Type checking |

---

## 5. Demo Output

The demo runs through 5 phases with ASCII art output:

```
╔══════════════════════════════════════════════════════════╗
║  BitBlik Ring Signature Trust Proof — LSAG Demo          ║
║  "I am one of 5 trusted people" — without revealing who  ║
╚══════════════════════════════════════════════════════════╝

════════════════════════════════════════════════════════════
  SETUP — Coordinator publishes follow list (kind 3)
════════════════════════════════════════════════════════════
  Coordinator npub: npub1abc...
  Follow list (5 members):
    [0] npub1aaa...  (decoy)
    [1] npub1bbb...  (decoy)
    [2] npub1ccc...  ← taker's key (but verifier doesn't know this)
    [3] npub1ddd...  (decoy)
    [4] npub1eee...  (decoy)

════════════════════════════════════════════════════════════
  STEP 1 — Taker generates ring signature
════════════════════════════════════════════════════════════
  Message: bitblik/trust-proof/v1:offer-001:tx-001
  Key image (nullifier): 7a3f...
  Ring size: 5
  Signature: ✅ generated

════════════════════════════════════════════════════════════
  STEP 2 — Maker verifies ring signature
════════════════════════════════════════════════════════════
  Ring matches follow list: ✅
  Signature valid: ✅
  Key image not seen before: ✅
  → ACCEPT: taker is one of 5 trusted members

════════════════════════════════════════════════════════════
  STEP 3 — Nullifier check (reuse detection)
════════════════════════════════════════════════════════════
  Same taker, new transaction:
  Key image: 7a3f... (SAME as before)
  Message: bitblik/trust-proof/v1:offer-002:tx-002 (DIFFERENT)
  → Same signer detected (key image match)
  → New transaction allowed (per-transaction nullifier policy)

════════════════════════════════════════════════════════════
  STEP 4 — Security checks
════════════════════════════════════════════════════════════
  Wrong message → signature fails:           ✅ (correctly rejected)
  Non-member key → signature fails:         ✅ (correctly rejected)
  Tampered ring → signature fails:          ✅ (correctly rejected)
  Tampered response → signature fails:      ✅ (correctly rejected)
```

---

## 6. Q&A Breadcrumbs

**Q: How is this different from the blind signature trust demo?**

The blind signature demo proves "the coordinator issued me a token" — it requires coordinator interaction at proof time and the coordinator can log proof generation requests. The ring signature demo proves "I am in the coordinator's follow list" — no coordinator interaction at proof time, stronger privacy. The key image is also a better nullifier: it's cryptographically bound to the signer's key, not just a hash of transaction data.

**Q: What if the coordinator's follow list is small?**

A small ring (10-50 members) means weak anonymity. In production, the coordinator can pad the ring with decoy pubkeys from the broader Nostr network. The trade-off: larger rings = more anonymity but slower signing/verification (O(N) for both). The demo uses 5 pubkeys — small enough to print, large enough to illustrate the concept.

**Q: What if the follow list changes between proof generation and verification?**

The proof includes `follow_list_event_id` and `follow_list_created_at` from the kind 3 event. The maker fetches the specific event by ID, not just the latest kind 3. If the event is pruned by relays, the maker fetches the closest prior version. For the demo, the follow list is static.

**Q: How does hash-to-curve work on secp256k1?**

The "try-and-increment" method: hash the input with a counter, attempt to decompress the hash as a secp256k1 point (try even y-coordinate), increment the counter until a valid point is found. Expected ~1 iteration. The domain separator `"bitblik/trust-nullifier/v1"` prevents cross-protocol replay.

**Q: Nostr uses BIP-340 x-only pubkeys (32 bytes). LSAG traditionally uses ECDSA keys (33 bytes). Is this a problem?**

No. LSAG operates on curve points and scalars, not on the signing scheme. The taker's Nostr private key (32-byte scalar) works directly as `x_s`. The Nostr pubkey (32-byte x-only) is decompressed to a full curve point for the ring. Both `@noble/curves` (JS) and `bip340` (Dart) provide these primitives.

**Q: Can the same taker prove membership for multiple transactions?**

Yes — with per-transaction nullifier policy. The key image is constant per signer (it doesn't depend on the message), so the same taker will always produce the same key image. The maker checks: same key image + same `tx_id` = replay (rejected); same key image + different `tx_id` = new transaction (accepted). The message `m` changes per transaction, so the signature itself is different even though the key image is the same.

**Q: Why not combine blind signatures with ring signatures?**

For the demo, ring-only gives a cleaner story: one cryptographic claim ("I'm in the follow list") vs two ("coordinator gave me a token" AND "I'm in the follow list"). Combined adds complexity without demo value — if the coordinator already issued the token, the coordinator knows who the taker is, partially undermining the ring signature's anonymity. Combined makes sense later if BitBlik needs per-token revocation or rate limiting.

**Q: Where does the trust proof fit in BitBlik's existing flow?**

As an optional gate between `reserved` and `blikReceived`:

```
funded → reserved → [TRUST_PROOF_VERIFIED] → blikReceived → ...
                     ↑
                     maker verifies taker's
                     ring signature here
```

The taker includes the trust proof in the `submit_blik` RPC params (demo approach) or publishes a kind 38384 event (production approach). The maker verifies before calling `get_blik`.

**Q: What stops a taker from using someone else's pubkey in the ring?**

Nothing stops them from *including* other pubkeys in the ring — that's the point (decoys). But they can only *sign* at the position corresponding to a key they hold the private key for. If they don't hold `x_s` for any `P_s` in the ring, the closure equation fails and the signature is invalid.

---

## 7. Migration Path to Dart

The TypeScript demo is a reference implementation. For production in BitBlik (a Flutter/Dart monorepo), the same logic ports to Dart using existing dependencies.

### 7.1 Dependency Mapping

| TypeScript (demo) | Dart (production) | Notes |
|-------------------|-------------------|-------|
| `@noble/curves` secp256k1 | `bip340` package | Already a BitBlik dependency. Provides Schnorr signing + curve operations (point multiplication, addition, scalar arithmetic) |
| `@noble/hashes` SHA256 | `crypto` package | Standard Dart crypto. SHA256 for hash-to-curve |
| `@noble/hashes` hash-to-curve | Custom impl (~30 LoC) | Try-and-increment: SHA256(domain ‖ data ‖ counter) → decompress as secp256k1 point |
| `tsx` / `vitest` | `dart test` | Dart's built-in test runner |

### 7.2 Porting Steps

1. **Port `hashToCurve`**: Implement try-and-increment in Dart using `crypto` for SHA256 and `bip340` for point decompression. ~30 lines.

2. **Port `generateKeyPair`**: Use `bip340` to generate a secp256k1 keypair. The private key is a 32-byte scalar; the public key is a curve point.

3. **Port `sign`**: The ring closure logic is pure scalar/point arithmetic — direct translation from TypeScript. The `bip340` package provides `Point.mul(scalar)`, `Point.add(point)`, and scalar arithmetic mod n.

4. **Port `verify`**: Same — recompute the ring and check closure. No special Dart packages needed beyond curve operations.

5. **Port the demo script**: Replace `console.log` with `print`. The ASCII art output is identical.

6. **Integrate with BitBlik's Nostr layer**: Use the existing `core` package's NostrService to fetch the coordinator's kind 3 event. The ring pubkeys come from the `p` tags.

### 7.3 File Structure (Dart)

```
packages/core/lib/src/trust_proof/
  lsag.dart           # Ring signature library (sign, verify, key image)
  hash_to_curve.dart  # Try-and-increment hash-to-curve
  trust_proof.dart    # Proof generation + verification wrapper
  trust_proof_test.dart
```

### 7.4 Key Differences

- **No `@noble/curves`**: Dart uses `bip340` for curve operations. The API is slightly different (methods vs functions) but the math is identical.
- **No `Buffer`**: Dart uses `Uint8List` for byte arrays. Hex encoding/decoding via `package:hex`.
- **No `process.argv`**: Dart CLI args via `dart:io`'s `Platform.arguments`.
- **BigInt vs number**: Dart's `BigInt` for scalar arithmetic vs JavaScript's `BigInt`. Both are arbitrary precision.

### 7.5 Production Considerations

- **Ring padding**: In production, pad the ring with decoy pubkeys from popular Nostr relays to increase the anonymity set beyond the coordinator's follow list size.
- **Multi-coordinator proofs**: The maker could require proofs from multiple coordinators (AND logic) for higher trust. Each coordinator has a different follow list.
- **Kind 38384 event**: For production, define a kind 38384 (Trust Proof) event — ephemeral, NIP-44 encrypted, direct taker→maker. The demo uses RPC params (simpler, coordinator-mediated).
- **Nullifier DB**: In production, the nullifier database should be shared among makers (or maintained by the coordinator) to detect reuse across transactions. For the demo, it's local to the maker.

---

## 8. Terminology

This demo uses X6's convention, which flips the original BitBlik terminology:

| Role | Original BitBlik | This Demo (X6's Convention) | In the Trust Proof Flow |
|------|-----------------|------------------------------|------------------------|
| Code provider | Maker | **Taker** | Sells BLIK codes, funds hold invoice, **generates** the ring signature |
| Cash withdrawer | Taker | **Maker** | Buys BLIK codes, withdraws cash, **verifies** the ring signature |

> **Why the flip**: The cash withdrawer is the one "making" the withdrawal. The code provider is "taking" the offer. This convention puts the party at risk (the maker/cash withdrawer) in the verification role — they're the one who needs the trust proof.

### Cryptographic Terms

| Term | Definition |
|------|-----------|
| **Ring signature** | A signature where the verifier knows the signer is one of N public keys but cannot determine which |
| **LSAG** | Linkable Spontaneous Anonymous Group signature — the specific ring signature scheme used here |
| **Key image** (aka linking tag) | `I = x_s · H(P_s)` — a curve point deterministically derived from the signer's private key. Serves as the nullifier. |
| **Nullifier** | A value that prevents proof reuse. The key image IS the nullifier in LSAG. |
| **Ring closure** | The property that the hash chain `c_0 → c_1 → ... → c_{N-1} → c_0` closes back on itself. This is what makes the signature valid. |
| **Hash-to-curve** | A function `H()` that maps arbitrary data to a point on the secp256k1 curve. Used to compute the key image. |
| **Domain separator** | `"bitblik/trust-nullifier/v1"` — prevents cross-protocol replay of key images |
| **secp256k1** | The elliptic curve used by Bitcoin and Nostr (BIP-340). All operations in this demo are on this curve. |
| **BIP-340** | The Schnorr signature standard for secp256k1. Nostr uses BIP-340 keys. |

---

## 9. References

### Academic

- **Liu, J.K., Wei, V.K., Wong, D.S.** (2004). "Linkable Spontaneous Anonymous Group Signature for Ad Hoc Groups." *Security and Privacy in the Age of Ubiquitous Computing*. The original LSAG paper.
- **Noether, S., Mackenzie, A.** (2016). "Ring Confidential Transactions." *Ledger Journal*. Monero's RingCT, which builds on LSAG.
- **Back, A., et al.** (2015). "Confidential Transactions." *Bitcoin mailing list*. Pedersen commitments and range proofs (context for why RingCT is overkill here).

### Implementations

- **Monero MLSAG/CLSAG**: The production ring signature implementation used by Monero. Reference for the verify equation term ordering. See `ringct/ringSAG` in the Monero codebase.
- **@noble/curves**: JavaScript secp256k1 library used in this demo. [GitHub](https://github.com/paulmillr/noble-curves)
- **@noble/hashes**: JavaScript hash functions. [GitHub](https://github.com/paulmillr/noble-hashes)
- **bip340 (Dart)**: Dart BIP-340 Schnorr signature library. Used in the production Dart port. [pub.dev](https://pub.dev/packages/bip340)

### BitBlik Context

- **`docs/trust-proof-analysis.md`**: Full cryptographic protocol design analysis for this demo.
- **`ANALYSIS.md`**: BitBlik technical architecture breakdown — protocol, Nostr kinds, RPC methods, state machine.
- **`README.md`** (root): BitBlik project overview — packages, protocol, communication.

### Standards

- **NIP-02** (Contact List): The kind 3 event that stores the coordinator's follow list. This IS the ring membership set.
- **NIP-44** (Encryption): Used to encrypt trust proofs in the production kind 38384 event design.
- **NIP-65** (Relay List): Used for relay discovery — the coordinator publishes its relay list as kind 10002.
- **BIP-340** (Schnorr Signatures): The signing scheme used by Nostr. LSAG operates on the same curve (secp256k1) but uses its own signing logic.
