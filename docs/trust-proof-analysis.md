# BitBlik Anonymous Web-of-Trust Membership Proofs
## Cryptographic Protocol Design Analysis

> **Status**: Design analysis for demo implementation  
> **Scope**: Ring signature membership proofs for BitBlik P2P exchange  
> **Terminology**: Per X6's request — "maker" = cash withdrawer (buys BLIK codes), "taker" = code provider (sells BLIK codes). This flips the original BitBlik convention so the cash withdrawer is the one "making" the withdrawal.
>
> **Design evolution**: the trust ring is no longer coordinator-only — every maker curates their own ring. See [§10 Design Evolution](#10-design-evolution-per-counterparty-trust-rings).

---

## 1. Problem Statement

In BitBlik's P2P BLIK/Lightning exchange:

1. **Taker** (code provider) funds a Lightning hold invoice and lists a BLIK code offer
2. **Maker** (cash withdrawer) reserves the offer and pays via BLIK code
3. **Coordinator** settles atomically — reveals the hold invoice preimage

**Risk**: The maker (cash withdrawer) can be associated with fraud if the taker's BLIK code was funded with a stolen card. The maker needs assurance that the taker belongs to a trusted set — the coordinator's Nostr web-of-trust (follow list) — **without revealing which specific member** the taker is.

**Solution**: Ring signatures let the taker prove "I am one of N trusted pubkeys" without disclosing which one. Combined with a nullifier to prevent proof reuse.

---

## 2. Ring Signature Scheme Recommendation

### 2.1 Schemes Considered

| Scheme | Curve | Linkability | Complexity | JS/TS Availability | Fit |
|--------|-------|-------------|------------|-------------------|-----|
| **Borromean** | secp256k1 | No (not linkable) | Medium | Custom impl needed | ❌ No linkability = no nullifier |
| **LSAG** (Linkable Spontaneous Anonymous Group) | secp256k1 | Yes (via key image) | Medium | Custom impl, ~200 LoC | ✅ **Recommended** |
| **RingCT** (Monero-style) | secp256k1 | Yes | High | Complex, overkill | ❌ Too complex for demo |
| **CLSAG** (Concise LSAG) | secp256k1 | Yes | Medium | Custom impl, ~250 LoC | ✅ Good alternative |
| **BLS ring sig** | BLS12-381 | Yes | Medium | No native Nostr key compat | ❌ Wrong curve |

### 2.2 Recommendation: LSAG (Linkable Spontaneous Anonymous Group Signatures)

**Why LSAG over alternatives:**

1. **secp256k1 native**: Nostr keys ARE secp256k1/BIP-340 keys. The taker's npub is already a curve point on the right curve. No key conversion needed. The `bip340` Dart package (already a dependency in BitBlik) provides Schnorr signing primitives we can build on.

2. **Linkability via key image**: LSAG produces a **key image** (also called "linking tag") that is deterministically derived from the signer's private key. This IS our nullifier — it's cryptographically bound to the signer's identity, not just a hash of transaction data. Two signatures from the same key on different messages produce the same key image → **double-spend detection**.

3. **Spontaneous**: No group setup ceremony. The ring is formed from public keys the signer already knows (the coordinator's follow list). The taker picks the ring, signs, and the maker verifies — no coordinator interaction at signing time.

4. **Simple enough for a demo**: ~200 lines of TypeScript/Dart. The math is:
   - Ring of N public keys: `P_0, P_1, ..., P_{N-1}`
   - Signer knows `x_s` (private key for `P_s`)
   - Key image: `I = x_s * H(P_s)` where `H` is a hash-to-curve function
   - Ring signature: `c_0, c_1, ..., c_{N-1}, r_0, r_1, ..., r_{N-1}, I`
   - Verification: recompute the ring and check the closure equation

5. **Well-understood security**: LSAG is the foundation of Monero's ring signatures (later upgraded to MLSAG/CLSAG). The security model (unforgeability, anonymity, linkability) is formally proven.

### 2.3 Why NOT Borromean

Borromean ring signatures are **not linkable** — they don't produce a key image. Without linkability, we can't detect proof reuse. We'd need a separate nullifier mechanism (like the SHA256 hash in the existing demo), which is weaker because it's not cryptographically bound to the signer's key.

### 2.4 Why NOT RingCT

RingCT (Ring Confidential Transactions) is designed for hiding transaction amounts in Monero. It's massively over-engineered for this use case — we don't need amount hiding, just membership proof. The implementation complexity (Pedersen commitments, range proofs) would make the demo incomprehensible.

---

## 3. Blind Signature Integration: Ring-Only vs Combined

### 3.1 The Two Options

**Option A: Ring-Only**
- Taker generates LSAG ring signature using their Nostr private key
- Ring = coordinator's follow list (kind 3 event pubkeys)
- Maker verifies the ring signature against the published follow list
- Key image serves as nullifier
- No coordinator interaction at proof time

**Option B: Combined (Blind Signature + Ring Signature)**
- Coordinator blind-signs a token for the taker (existing demo flow)
- Taker also generates a ring signature proving membership
- Maker verifies BOTH: blind signature (coordinator issued token) + ring signature (taker is in follow list)
- Two nullifiers: key image (from ring sig) + hash nullifier (from blind sig)

### 3.2 Recommendation: Ring-Only for the Demo

**Rationale:**

1. **Simpler story for the demo**: "I am one of N trusted people" is a single cryptographic claim. Adding blind signatures muddies the narrative — now there are two claims ("coordinator gave me a token" AND "I'm in the follow list") and the audience has to understand both.

2. **Ring-only is self-contained**: The taker doesn't need to interact with the coordinator at proof time. The coordinator's role is purely passive — they publish their follow list (kind 3), and that's it. This is a stronger privacy story: the coordinator can't log proof generation requests.

3. **Key image IS the nullifier**: LSAG's key image is cryptographically bound to the signer's private key. It's a better nullifier than a SHA256 hash because:
   - It's deterministic from the key (same key → same key image, always)
   - It's unlinkable to the pubkey (computing the key image from the pubkey requires the private key)
   - It works across different messages/transactions (same signer → same key image → detected)

4. **The existing blind signature demo already works**: The blind signature demo (`demo-bitblik-trust.ts`) demonstrates the "coordinator issues token" flow. The ring signature demo demonstrates a DIFFERENT flow: "I'm in the follow list." Keeping them separate makes each demo's contribution clear.

5. **Combined adds complexity without demo value**: In a combined scheme, the blind signature proves "coordinator issued this" and the ring signature proves "I'm in the follow list." But if the coordinator already issued the token, the coordinator already knows who the taker is (they had to interact). The ring signature's anonymity is partially undermined by the blind signature's issuance trail. For a demo, ring-only gives cleaner anonymity guarantees.

**When to reconsider combined**: If BitBlik later needs per-token revocation (coordinator can revoke individual tokens without changing the follow list), or rate limiting (coordinator limits tokens per user), then blind signatures add value. The ring signature alone can't support per-individual revocation — you'd have to remove the pubkey from the follow list.

---

## 4. Complete Proof Generation → Verification Flow

### 4.1 Terminology (X6's Convention)

| Role | Original BitBlik | X6's Convention | In This Flow |
|------|-----------------|-----------------|--------------|
| Code provider | Maker | **Taker** | Sells BLIK codes, funds hold invoice |
| Cash withdrawer | Taker | **Maker** | Buys BLIK codes, withdraws cash |

> **Note**: In the ring signature flow, the **taker** (code provider) generates the proof, and the **maker** (cash withdrawer) verifies it. This is because the maker is the one at risk — they're withdrawing cash and could be associated with a fraudulent BLIK code.

### 4.2 Setup Phase (One-Time)

```
┌─────────────────────────────────────────────────────────┐
│  COORDINATOR                                             │
│  1. Maintains a Nostr identity (npub)                    │
│  2. Publishes kind 3 (Contact List) with trusted pubkeys │
│     - Each 'p' tag = one trusted member                  │
│     - This IS the ring membership set                    │
│  3. Updates follow list as trust changes                 │
│     (adding/removing members)                            │
└─────────────────────────────────────────────────────────┘
```

The coordinator's kind 3 event is already standard Nostr (NIP-02). No custom event needed for the trust set — it's just a follow list. The `p` tags contain the hex pubkeys of trusted members.

### 4.3 Proof Generation (Taker / Code Provider)

```
┌─────────────────────────────────────────────────────────┐
│  TAKER (Code Provider) — generates ring signature        │
│                                                          │
│  INPUTS:                                                 │
│  - taker_privkey (x_s) — their Nostr private key         │
│  - taker_pubkey (P_s) — their Nostr npub (in follow list)│
│  - coordinator_pubkey — to fetch the follow list        │
│  - message (m) — the transaction context:               │
│      "bitblik/trust-proof/v1:{offer_id}:{tx_id}"         │
│                                                          │
│  STEPS:                                                  │
│  1. Fetch coordinator's kind 3 event from relays        │
│  2. Extract ring = [P_0, P_1, ..., P_{N-1}] from p-tags │
│  3. Verify P_s is in the ring (else: not trusted)        │
│  4. Compute key image: I = x_s · H(P_s)                  │
│     where H() = hash-to-curve (secp256k1)                │
│  5. Generate LSAG signature:                             │
│     - Pick random scalar r                               │
│     - Compute ring closure: c_{i+1} = H(m, c_i, r_i·G)  │
│     - At signer index s: substitute r_s using x_s        │
│     - Output: (I, c_0, [r_0, ..., r_{N-1}])              │
│  6. Package proof:                                       │
│     {                                                    │
│       key_image: I (hex),                               │
│       ring_pubkeys: [P_0, ..., P_{N-1}] (hex array),    │
│       c_0: (hex),                                        │
│       responses: [r_0, ..., r_{N-1}] (hex array),        │
│       message: m,                                        │
│       coordinator_pubkey: (hex),                        │
│       follow_list_event_id: (event id of kind 3)        │
│     }                                                    │
└─────────────────────────────────────────────────────────┘
```

### 4.4 Proof Verification (Maker / Cash Withdrawer)

```
┌─────────────────────────────────────────────────────────┐
│  MAKER (Cash Withdrawer) — verifies ring signature      │
│                                                          │
│  INPUTS:                                                 │
│  - proof (from taker, via Nostr event or DM)             │
│  - coordinator's kind 3 event (from relays)             │
│  - nullifier database (local, for reuse check)           │
│                                                          │
│  STEPS:                                                  │
│  1. Fetch coordinator's kind 3 event                     │
│     - Verify event_id matches proof.follow_list_event_id │
│     - Verify event is signed by coordinator_pubkey       │
│  2. Verify ring matches follow list:                     │
│     - proof.ring_pubkeys == set of p-tags from kind 3   │
│     - (or: proof.ring_pubkeys ⊆ p-tags, if subset ring)  │
│  3. Verify LSAG signature:                              │
│     - Recompute ring: c_{i+1} = H(m, c_i, r_i·G)        │
│     - Check closure: c_0 == H(m, c_{N-1}, r_{N-1}·G)    │
│     - Verify key image: I == r_s·H(P_s) - c_s·P_s       │
│       (implicit in the ring verification)                │
│  4. Check nullifier (key image):                         │
│     - If I in local nullifier DB → REJECT (reuse)        │
│     - Else: store I with tx_id, timestamp                │
│  5. If all checks pass: ACCEPT — taker is trusted        │
│                                                          │
│  RESULT:                                                 │
│  ✅ Maker knows taker is in coordinator's follow list     │
│  ✅ Maker does NOT know which specific pubkey            │
│  ✅ Key image prevents taker from reusing proof           │
└─────────────────────────────────────────────────────────┘
```

### 4.5 Integration with BitBlik's Existing Flow

The trust proof fits into BitBlik's existing state machine as an **optional gate** between `reserved` and `blikReceived`:

```
funded → reserved → [TRUST_PROOF_VERIFIED] → blikReceived → ...
                     ↑
                     maker verifies taker's
                     ring signature here
```

In the existing flow:
1. Taker calls `reserve_offer` (kind 25195 RPC) → state moves to `reserved`
2. **NEW**: Taker includes a trust proof in the `submit_blik` RPC params, OR sends it as a separate kind 25195 RPC with method `submit_trust_proof`
3. Maker verifies the proof before calling `get_blik` (fetching the BLIK code)
4. If proof is invalid or missing → maker can `mark_blik_invalid` or refuse to proceed

**Alternative integration**: The trust proof could be attached to the kind 38383 offer event itself, as a tag. The taker publishes the proof alongside their offer, and the maker verifies it before reserving. This is more passive but less flexible (the proof is tied to the offer, not the transaction).

---

## 5. Custom Event Kind Design

### 5.1 New Event Kind: 38384 (Trust Proof)

> **Kind**: 38384  
> **Type**: Ephemeral (not stored permanently)  
> **Content**: NIP-44 encrypted JSON containing the ring signature proof  
> **Tags**: `['p', maker_pubkey]`, `['coordinator', coordinator_pubkey]`, `['offer_id', offer_id]`

**Why 38384**: Adjacent to the existing offer kind 38383. Ephemeral because trust proofs are transaction-specific and shouldn't persist. NIP-44 encrypted because the proof reveals the ring membership (though not the specific signer) and should be private between taker and maker.

**Content structure (after NIP-44 decryption)**:

```json
{
  "version": 1,
  "type": "lsag_trust_proof",
  "message": "bitblik/trust-proof/v1:{offer_id}:{tx_id}",
  "ring_signature": {
    "key_image": "<hex>",
    "ring_pubkeys": ["<hex>", "<hex>", "..."],
    "c0": "<hex>",
    "responses": ["<hex>", "<hex>", "..."]
  },
  "coordinator_pubkey": "<hex>",
  "follow_list_event_id": "<hex event id>",
  "follow_list_created_at": <unix timestamp>,
  "nullifier": "<hex key image>"
}
```

### 5.2 Why Not Reuse Existing Kinds

| Kind | Why not |
|------|---------|
| 38383 (offer) | Public, parameterized replaceable. Trust proofs are per-transaction, not per-offer. Publishing publicly would leak ring membership to all observers. |
| 25195 (RPC req) | Could work — add a `submit_trust_proof` RPC method. But this routes through the coordinator, who would see the proof (even if encrypted, the coordinator decrypts it). We want maker-verification without coordinator seeing the proof. |
| 25196 (RPC resp) | Same issue — coordinator-mediated. |
| 25197 (status update) | One-way coordinator→client. Wrong direction. |

**Kind 38384 is direct taker→maker**: The taker publishes a kind 38384 event encrypted for the maker's pubkey. The maker's NDK subscription picks it up. No coordinator involvement in the proof exchange.

### 5.3 Alternative: Embed in RPC Params

If we want to keep everything coordinator-mediated (simpler for the demo), we can add the trust proof as a field in the `submit_blik` RPC params:

```json
{
  "method": "submit_blik",
  "params": {
    "offer_id": "...",
    "blik_code": "...",
    "trust_proof": { ... }
  }
}
```

The coordinator would pass `trust_proof` through to the maker in the `get_blik` response. This is simpler but the coordinator sees the proof (though not the private key — the ring signature is still anonymous). For the demo, this is acceptable and avoids defining a new event kind.

**Recommendation for demo**: Use the RPC param approach (simpler, no new event kind needed). Mention kind 38384 as the "proper" design for production.

---

## 6. Nullifier Design

### 6.1 LSAG Key Image as Nullifier

The LSAG key image `I = x_s · H(P_s)` IS the nullifier. It has these properties:

| Property | How it works |
|----------|-------------|
| **Deterministic** | Same private key → same key image, always. Computed from `x_s` and `H(P_s)`. |
| **Unlinkable to pubkey** | Given `P_s` and `I`, you cannot determine if `I` was derived from `P_s`'s private key (discrete log problem). |
| **Constant across messages** | The key image depends only on the signer's key, not the message. So the same taker signing different messages produces the same key image. |
| **Forgeable only with private key** | Computing `I` requires `x_s`. An attacker with only `P_s` cannot produce a valid `I`. |

### 6.2 Domain Separator

```
"bitblik/trust-nullifier/v1"
```

This is used in the **hash-to-curve** function `H()` that maps a pubkey to a curve point:

```
H(P) = hash_to_curve("bitblik/trust-nullifier/v1" || P)
```

The domain separator ensures the key image is specific to BitBlik and cannot be replayed from another protocol's ring signatures.

### 6.3 Nullifier Inputs

The key image (nullifier) takes only TWO inputs:
1. **Signer's private key** (`x_s`) — known only to the taker
2. **Signer's public key** (`P_s`) — public, in the follow list

It does NOT take `tx_id` or `token_secret` as inputs. This is by design:
- The key image is **constant per signer** — it identifies the signer, not the transaction
- Transaction binding comes from the **message** `m = "bitblik/trust-proof/v1:{offer_id}:{tx_id}"` which is part of the ring signature
- The maker checks: (a) key image not seen before (nullifier check), AND (b) signature is valid for this specific message (transaction binding)

### 6.4 Nullifier Check Flow

```
MAKER maintains a local key-value store:
  key_image → { tx_id, timestamp, offer_id }

On receiving a trust proof:
  1. Verify ring signature (including message binding)
  2. Look up proof.key_image in local store
     - If found AND same tx_id → already verified, idempotent OK
     - If found AND different tx_id → REJECT (same taker already proved for different tx)
       [or: ACCEPT if we allow the same taker to prove for multiple transactions]
     - If not found → store and ACCEPT
```

**Design decision**: Should the same taker be allowed to prove membership for multiple transactions?

- **Strict (one-time)**: Key image can only be used once. After the first proof, the taker can never prove again. This is like a one-time-use credential. Too restrictive for a P2P exchange where the same taker makes multiple offers.

- **Per-transaction (recommended)**: Key image can be reused across different transactions, but the **message** changes (different `offer_id`/`tx_id`). The maker checks that the key image hasn't been used for THIS specific transaction. This allows the same taker to prove membership for multiple offers while preventing replay of the same proof.

- **Rate-limited**: Track how many times a key image has been used in a time window. Reject if over threshold. Requires coordination among makers (shared nullifier DB) — too complex for demo.

**For the demo**: Use per-transaction nullifier checking. The key image is stored with the `tx_id`. Same key image + same `tx_id` = replay (rejected). Same key image + different `tx_id` = new transaction (accepted).

---

## 7. Key Challenges and Solutions

### Challenge 1: Ring Size and Anonymity Set

**Problem**: The coordinator's follow list might be small (10-50 members). A small ring means weak anonymity — an observer can narrow the taker to one of N people.

**Solution**: 
- For the demo, use a ring of 5-10 pubkeys (enough to illustrate the concept)
- In production, the coordinator can pad the ring with decoy pubkeys from the broader Nostr network (random npubs from popular relays). The taker's real key is hidden among decoys.
- Document the trade-off: larger rings = more anonymity but slower signing/verification (O(N) for both)

### Challenge 2: Follow List Synchronization

**Problem**: The taker generates the proof using the follow list at time T1. The maker verifies using the follow list at time T2. If the coordinator updated the list between T1 and T2, verification fails.

**Solution**:
- The proof includes `follow_list_event_id` and `follow_list_created_at` (from the kind 3 event)
- The maker fetches the specific event by ID (not just the latest kind 3)
- If the event is not found (pruned by relays), the maker fetches the closest prior version
- For the demo: the follow list is static during the demo, so this isn't an issue

### Challenge 3: Hash-to-Curve on secp256k1

**Problem**: LSAG requires `H(P)` — a hash function that maps a pubkey (or arbitrary data) to a point on the secp256k1 curve. This is not a standard Nostr primitive.

**Solution**:
- Implement `hash_to_curve` using the "try-and-increment" method:
  ```
  hash_to_curve(data):
    counter = 0
    while true:
      h = SHA256(domain_separator || data || counter)
      point = decompress(h || 0x02)  // try even y-coordinate
      if point is valid:
        return point
      counter++
  ```
- This is simple, deterministic, and well-understood. Expected ~1 iteration.
- The `bip340` package doesn't provide this directly, but it provides the curve operations (point multiplication, addition) we need.

### Challenge 4: Nostr Key Format Compatibility

**Problem**: Nostr uses BIP-340 Schnorr keys (x-only pubkeys, 32 bytes). LSAG traditionally uses ECDSA keys (33-byte compressed pubkeys with parity). The math is slightly different.

**Solution**:
- LSAG operates on curve points and scalars, not on the signing scheme itself
- We can use the raw secp256k1 curve operations (point multiplication, addition) that underlie both BIP-340 and ECDSA
- The taker's Nostr private key (32-byte scalar) works directly as `x_s`
- The Nostr pubkey (32-byte x-only) needs to be converted to a full curve point for the ring (decompress to get (x, y))
- The `bip340` Dart package and `@noble/curves` JS package both provide these primitives

### Challenge 5: Demo Simplicity

**Problem**: Ring signatures are complex cryptography. The demo needs to be understandable in 1 minute with 2 minutes of Q&A.

**Solution**:
- **Visual metaphor**: Show the ring as a circle of N pubkeys. The taker "signs at one position" but the verifier can't tell which. Animate the ring closure.
- **Console output**: Follow the existing demo's style (ASCII art, step-by-step, ✅/❌ checks)
- **Minimal ring**: Use 5 pubkeys (1 real + 4 decoys). Small enough to print, large enough to illustrate anonymity.
- **No network calls**: Generate all keys locally. Simulate the follow list as a hardcoded array. This avoids relay latency and makes the demo deterministic.

### Challenge 6: Key Image as Nullifier vs Hash Nullifier

**Problem**: The existing demo uses `SHA256(domain | tx_id | token_secret)` as the nullifier. The ring signature approach uses the key image. These are fundamentally different nullifier constructions.

**Solution**:
- The key image is a **stronger** nullifier because it's cryptographically bound to the signer's key
- The hash nullifier is **weaker** because it's just a hash of transaction data — anyone who knows the inputs can compute it
- For the demo, show BOTH nullifiers side by side:
  - "Blind signature nullifier: SHA256(tx_id, token_secret) — prevents token reuse"
  - "Ring signature nullifier: key_image = x_s · H(P_s) — prevents identity reuse"
- Explain that the key image is the "cryptographic fingerprint" of the signer, while the hash nullifier is just a transaction ID

### Challenge 7: Coordinator's Follow List as Trust Anchor

**Problem**: The entire trust model depends on the coordinator's follow list being meaningful. If the coordinator follows random people, the trust proof is worthless.

**Solution**:
- The coordinator's follow list IS their web-of-trust. It's a subjective trust graph.
- The maker chooses which coordinator(s) to trust. Different coordinators can have different follow lists.
- The proof includes `coordinator_pubkey` so the maker knows whose follow list to check against.
- In production, the maker could require proofs from MULTIPLE coordinators (AND logic) for higher trust.
- For the demo: use a single coordinator with a small, curated follow list.

---

## 8. Implementation Plan for the Demo

### 8.1 TypeScript Demo (extends existing auditable-voting demo)

File: `tollgate-infrastructure-kit/auditable-voting/web/scripts/demo-bitblik-ring-trust.ts`

```
Phase 1: Key generation
  - Generate 5 Nostr keypairs (1 taker + 4 decoys)
  - Generate 1 coordinator keypair
  - Coordinator "publishes" follow list (hardcoded array of 5 pubkeys)

Phase 2: Proof generation
  - Taker fetches follow list (reads the array)
  - Taker generates LSAG ring signature
  - Output: key_image, ring_pubkeys, c0, responses, message

Phase 3: Proof verification
  - Maker fetches follow list (reads the same array)
  - Maker verifies ring signature
  - Maker checks key image against nullifier DB (empty → accept)

Phase 4: Reuse detection
  - Taker tries to reuse same proof for different tx
  - Maker detects: same key image, different message → show that the
    signature is valid but the nullifier check reveals same signer

Phase 5: Security checks
  - Wrong message → signature fails
  - Non-member key → signature fails
  - Tampered ring → signature fails
```

### 8.2 Dependencies

- `@noble/curves` (secp256k1) — for curve operations in TypeScript
- `@noble/hashes` — for SHA256 and hash-to-curve
- No new Dart dependencies needed — `bip340` package provides the primitives

### 8.3 Output Format

Follow the existing demo's style:
```
╔══════════════════════════════════════════════════════════╗
║  BitBlik Ring Signature Trust Proof — LSAG Demo          ║
║  'I am one of 5 trusted people' — without revealing who ║
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
```

---

## 9. Summary of Recommendations

| Decision | Recommendation | Rationale |
|----------|---------------|----------|
| Ring signature scheme | **LSAG** | secp256k1 native, linkable (key image = nullifier), spontaneous (no setup), simple enough for demo |
| Blind signature integration | **Ring-only** | Simpler story, stronger privacy (no coordinator interaction at proof time), key image is better nullifier |
| Trust set publication | **Each maker's own kind 3 (NIP-02)** | Per-counterparty rings: every maker curates their list; a coordinator's list is a copyable seed, not the trust set (see §10) |
| Proof event kind | **38384** (for production) or **RPC param** (for demo) | Ephemeral, NIP-44 encrypted, direct taker→maker |
| Nullifier | **LSAG key image** | Cryptographically bound to signer's key, deterministic, unlinkable to pubkey |
| Domain separator | **"bitblik/trust-nullifier/v1"** | Used in hash-to-curve, prevents cross-protocol replay |
| Nullifier policy | **Per-transaction** | Same taker can prove for multiple offers; same proof can't be replayed for same tx |
| Demo ring size | **5 pubkeys** | Small enough to print, large enough to illustrate anonymity |

---

## 10. Design Evolution: Per-Counterparty Trust Rings

Sections 1–9 analyzed a **coordinator-only** model: one coordinator's kind 3 follow list defines THE ring, and every proof is checked against it. The approved design change removes that single point of trust.

### 10.1 What Changed

| | Coordinator-only (original analysis) | Per-counterparty rings (current design) |
|---|---|---|
| Ring definition | The coordinator's kind 3 follow list | Each maker's own kind 3 follow list |
| Who verifies | Maker, against the coordinator's list | Maker, against their OWN list |
| Coordinator role | Gatekeeper — defines the trust set | Seed/curator — publishes a list others may copy |
| Bootstrap | n/a — you trusted the coordinator or you didn't | New maker copies a seed list once, then curates |
| Trust topology | Hub | Web (the literal web-of-trust) |

- **Every counterparty** (each maker/cash withdrawer) maintains their own kind 3 follow list — their personal trust ring.
- The **taker** (code provider) proves membership in the **specific maker's ring** they transact with; that maker verifies against their own list.
- A **new maker bootstraps** by copying a coordinator's (or anyone's) published follow list in one action, then diverges by curating.
- **No single party dictates trust.**

### 10.2 Rationale

1. **Decentralization / censorship resistance**: a coordinator-gatekeeper can be pressured, censor, or be compelled to unfollow people — and that one edit instantly changes who may transact *everywhere*. Per-counterparty rings remove the single decision-maker: excluding someone from one list never excludes them from the network.
2. **Subjective trust, stored where it's used**: "trusted" is a claim by a specific verifier about specific peers. The new model keeps the trust data with the party at risk — the maker — instead of outsourcing judgement to a hub.
3. **Bootstrap UX**: copying a seed list is one action. New makers start from a curated baseline without asking anyone's permission, then diverge as they gain first-hand experience.
4. **Standard Nostr all the way down**: NIP-02 lists are already per-account and public; no new event kinds, no protocol additions.

### 10.3 Trade-offs and Mitigations

| Trade-off | Detail | Mitigation |
|---|---|---|
| Anonymity set = list size | Your anonymity in a proof is exactly the size of the verifying maker's ring. A tightly curated list of 10–20 pubkeys weakens anonymity — the signer is one of few plausible people. | **Ring padding with decoys**: pad the proof ring with pubkeys from the broader Nostr network (the demo's `--npub` flag inserts participant npubs as decoys live). Larger rings cost O(N) sign/verify — choose N accordingly. |
| Fragmented verification data | With one coordinator list, everyone verified against the same event. Now every maker has their own list — and list versions. | The proof already carries `follow_list_event_id` / `follow_list_created_at`; verification pins the exact event **per maker**. |
| Cross-maker proof replay | Could a proof accepted by maker A be replayed to maker B? | The signed message binds `offer_id` + `tx_id` (`bitblik/trust-proof/v1:{offer_id}:{tx_id}`), so a proof for one transaction fails for any other; and the ring itself is maker-specific, so ring-matching rejects it before the math even runs. |
| Bootstrap herding | If everyone copies the same seed list and never edits it, the seed author's judgement is effectively re-centralized. | Curation is expected and cheap (follow/unfollow); the coordinator is framed as a starting point, not an authority. |

### 10.4 What Stays the Same

LSAG itself, the key-image nullifier, the domain separator
(`bitblik/trust-nullifier/v1`), the per-transaction nullifier policy, the kind
38384 proof event, and the Dart migration plan are unchanged — only the
provenance of the ring (whose list it is) moved from the coordinator to each
maker.
