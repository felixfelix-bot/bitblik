# ADR 0001: Trust-Proof Protocol — LSAG Ring Signatures for BLIK Trades

| | |
|---|---|
| **Status** | DRAFT — discussion draft, **NOT agreed** |
| **Decider** | X6 (BitBlik maintainer) — decides **all** OPEN items below |
| **Date** | 2026-08-15 |
| **Authors** | Felix & agent team (fork: `github.com/felixfelix-bot/bitblik`) |
| **Branches** | demo: `feat/trust-proof-demo` · this doc: `feat/trust-proof-adr` |
| **References** | [docs/trust-proof-upstream-roadmap.md](../trust-proof-upstream-roadmap.md) (full context), [docs/trust-proof-analysis.md](../trust-proof-analysis.md) (crypto design), `demo/trust-proof/` (working demo, 86 tests green) |

> **Reading note.** Every decision in this ADR is marked **OPEN** with a stated
> lean from the agent team. Nothing here is agreed. The maintainer (X6) rules
> on each OPEN item; when a ruling lands, the item's status changes from OPEN
> to ACCEPTED (or the ADR is superseded). This document exists so those
> rulings have concrete options to react to, per Phase 1 of
> [the roadmap](../trust-proof-upstream-roadmap.md) §9.

---

## 1. Context

BitBlik trades pair a **maker** (cash withdrawer at the ATM — the verifier)
with a **taker** (code provider — the prover), matched by a coordinator. The
maker's risk: if the taker's BLIK code was funded by a stolen card, the maker
is the one standing at the ATM associated with fraud. The taker's countervailing
interest: not revealing *which* trusted person they are.

A TypeScript demo (this fork, `demo/trust-proof/`, branch `feat/trust-proof-demo`,
86 tests green) proves the concept end-to-end:

- **LSAG ring signatures** on secp256k1 (Liu–Wong shape) — closure, linkability
  via key image, negative tests — using `@noble/curves` + `@noble/hashes`.
- Transport over a **real local Nostr relay** (NIP-01 WebSocket, schnorr-signed
  event, `d` tag) — local-only kind 30221.
- **Proof-gated trade ordering**, test-locked: offer → ring proof → sats only
  if the proof verifies → BLIK code last.

What the demo does **not** yet do (honest list, roadmap §4): the ring comes
from a local fixture rather than a live kind-3 list; replay binding is designed
but not enforced in the signature (the signed message is a constant today —
`demo.ts:661`; `offer_id` rides only in an unsigned `d` tag); there is no
persistent key-image registry; it is TypeScript while BitBlik's app is
Dart/Flutter; and no independent crypto review has happened.

A code audit (roadmap §5) found six bounded blockers — B1…B6 — that must land
in the demo repo regardless of how the decisions below are ruled. This ADR
does not re-litigate them; it records where each decision interacts with them.

### 1.1 Integration surface (from reading `packages/core/`, `packages/app/`)

The proof slots into the existing flow engine as an **optional gate**:

```
funded → reserved → [proof verified] → submit_blik → blikReceived → get_blik → …
```

- New taker action `submit_proof` between `reserved` → `submit_blik` in
  `packages/core/lib/flows/blik.yml`.
- Maker's `get_blik` / `confirm_payment` gated on a verified proof —
  **per-offer toggle, default off**, so the default flow is untouched.
- Ring fetched from the maker's own kind-3 list via Ndk + the existing
  objectbox/drift caches.
- Proof rides the existing coordinator RPC envelope — see [D4](#d4-envelope--existing-rpc-kinds-2519525196).

---

## 2. Decision summary

| # | Decision | Status | Lean |
|---|----------|--------|------|
| D1 | Ring source | **OPEN** | Maker's kind-3 follows; coordinator list = bootstrap seed only |
| D2 | Minimum ring size & ring hygiene | **OPEN** | ≥ 4 members, deduplicated, canonical points only |
| D3 | Key-image scope | **OPEN** | Per-maker (trade-off vs global cross-maker linkability noted) |
| D4 | Wire envelope | **OPEN** | Existing RPC kinds 25195/25196; versioned JSON `{v:1, type:"bitblik.trust-proof", …}` |
| D5 | H1 — hedged nonces | **OPEN — DEFERRED** | Defer; revisit before any mainnet use |

Explicitly outside this ADR (still the maintainer's, roadmap §8 items 5–6):
failure UX (hard gate vs warning banner), audit bar (independent review before
mainnet vs pilot-behind-flag), and the port strategy (roadmap recommends
pure-Dart, ~4–6 person-days — that recommendation stands regardless of the
rulings above).

---

## D1 — Ring source: maker's kind-3 follows

**Status: OPEN. Lean: kind-3 follows (per-maker rings); a coordinator's list is
a copyable bootstrap seed, nothing more.**

### Options

1. **Per-maker kind-3 rings** *(lean)* — every maker curates their own follow
   list; the taker proves membership in *the specific maker's* ring they
   transact with; that maker verifies against their own list.
2. Coordinator list as *the* trust set — hub model; one unfollow edit changes
   who may transact everywhere.
3. Hybrid — coordinator list authoritative, per-maker overrides.

### Rationale for the lean

- Removes the single gatekeeper: a coordinator can be pressured, censor, or be
  compelled to unfollow — and that one edit instantly changes who may transact
  *everywhere*. Per-maker rings make exclusion local, never network-wide.
- "Trusted" is a claim by a specific verifier about specific peers; the data
  lives with the party at risk (the maker), not a hub.
- Bootstrap stays one action: a new maker copies a published seed list (a
  coordinator's, or anyone's), then diverges by curating.
- Standard Nostr all the way down — NIP-02 lists are already per-account and
  public. No new event kinds.

### Consequences to accept with the lean

- Anonymity set = that maker's list size; tightly curated lists of 10–20
  weaken anonymity. Mitigation: ring padding with decoys (the demo's `--npub`
  flag already inserts participant npubs as decoys live); interacts with [D2](#d2--minimum-ring-size--ring-hygiene).
- Verification pins `follow_list_event_id` / `follow_list_created_at` **per
  maker**, so stale-list sync is a real (handled) edge: the verifier fetches
  the pinned event, not "latest".
- Bootstrap herding: if everyone copies the same seed and never edits it, the
  seed author's judgement is quietly re-centralized. Framed as a starting
  point, not an authority.
- Interacts with blocker **B1**: the verifier must check the proof against a
  ring derived from *their own* list; the `ring` field inside an incoming
  proof event is display-only, never trusted.

### Still to be ruled by X6

The lean itself (kind-3, seed-only coordinator), and whether multiple seed
lists should be first-class (a maker copying from several curators).

---

## D2 — Minimum ring size & ring hygiene

**Status: OPEN. Lean: enforce minimum ring size ≥ 4, reject duplicate keys,
reject non-canonical point encodings.**

### Rationale for the lean

- Blocker **B4**: the demo today accepts a ring of size 1 — an "anonymity set"
  of one, which is no anonymity at all. A floor of 4 is the smallest size at
  which the proof means anything; the demo's illustrations use 5.
- **Dedupe**: the same pubkey twice in a ring inflates the apparent anonymity
  set without adding any. `ring.length` must equal `new Set(ring).size`.
- **Canonical points**: every ring member must decode to a valid, canonically
  encoded secp256k1 point (33-byte compressed, valid curve point) — malleable
  or unreduced encodings rejected before the math runs, so two verifiers can't
  disagree about what ring was signed.
- Cost of size is linear (O(N) sign and verify); 4 is cheap everywhere,
  including low-end phones and the web flavor.

### Consequences to accept with the lean

- Signers whose curated ring falls below the floor **cannot prove** — the
  failure surfaces at proof time. Failure UX (hard fail vs pad-automatically
  vs warn) is deliberately not decided here; it belongs with roadmap §8 item 5.
- Larger floors trade verification time for anonymity; decoy padding (D1) can
  lift the effective set above the floor without growing the curated list.

### Still to be ruled by X6

The exact floor (lean: 4); whether padding with network decoys is required,
optional, or off by default; and the decoy-selection policy if so (random from
relays vs curated pool).

---

## D3 — Key-image scope: per-maker

**Status: OPEN. Lean: per-maker key images. The trade-off against global
cross-maker linkability must be weighed by the decider — it is real.**

### Background

The LSAG key image `I = x_s · H(P_s)` is the nullifier: deterministic from the
signer's key, constant across messages, unlinkable to the pubkey by anyone
without the private key. What it links is *signatures from the same key*.
Which signatures get linked is a protocol choice, because it depends on *which
key* the taker signs with:

1. **Global signing key** (taker signs with their one Nostr identity key) —
   every proof by that taker, to every maker, produces the **same key image**.
   Two makers comparing notes learn "the same taker proved to both" (not who).
   This buys **cross-maker double-sign detection**: coordinated makers can pool
   key images and detect one taker farming proofs at scale — but it is exactly
   the linkability the privacy promise argues against. In the worst case the
   pooled images become a cross-maker tracking database.
2. **Per-maker subkey** *(lean)* — the taker derives a distinct signing subkey
   per maker relationship (deterministic derivation from the identity key +
   the maker's pubkey, BIP32/HKDF-style). Each maker's ring contains that
   maker-facing subkey, and key images never collide across makers:
   **no cross-maker linkability at all**. The price: **no cross-maker
   double-sign detection** either — a maker's key-image blocklist only ever
   catches reuse against *that maker*, and abuse that spans many makers is
   invisible to each of them individually.

### Rationale for the lean

The product's stated promise is "nobody learns which member" — per-maker
images keep that promise even against colluding makers, and a single maker's
local blocklist is sufficient for the per-transaction reuse policy (below).
Cross-maker farming detection, if wanted later, can be rebuilt as an explicit,
consented mechanism rather than leaking it through the nullifier.

### Consequences to accept with the lean

- Rings are per-maker **by construction**: a maker's kind-3 list contains the
  taker's maker-facing subkey, so curation relationships are per-subkey. This
  is consistent with D1 (each maker curates their own list anyway) but changes
  what "following" means for takers who adopt subkeys.
- Cross-maker double-sign detection is forfeited (above). If X6 weighs abuse
  detection above unlinkability, option 1 is the honest choice and this lean
  flips.
- Interacts with blocker **B3**: whatever the scope, the verifier needs a
  **persistent key-image blocklist checked before sats move** — the demo's
  in-process check does not survive an app restart.
- Orthogonal and already settled in the analysis (§6.4): the **per-transaction
  reuse policy** — same key image + same `tx_id` = replay, reject; same key
  image + different `tx_id` = new transaction, allow. Scope (this decision)
  changes *which* images can ever collide; it does not change that policy.

### Still to be ruled by X6

The lean itself (per-maker vs global), and if per-maker: the subkey derivation
scheme and how subkeys enter follow lists.

---

## D4 — Envelope: existing RPC kinds 25195/25196

**Status: OPEN. Lean: proof rides the existing coordinator RPC envelope
(`kKindCoordinatorRequest = 25195` / `kKindCoordinatorResponse = 25196`,
`packages/core/lib/src/constants/kinds.dart`), as a versioned canonical-JSON
payload — no new relay-visible event kind.**

### Payload shape (lean)

```json
{
  "v": 1,
  "type": "bitblik.trust-proof",
  "offer_id": "<hex>",
  "tx_id": "<hex>",
  "ring": ["<33-byte compressed pubkey hex>", "..."],
  "key_image": "<33-byte compressed point hex>",
  "c0": "<32-byte scalar hex>",
  "s": ["<32-byte scalar hex>", "..."]
}
```

Versioned (`v`) so future scheme changes (e.g. CLSAG) can be introduced
without a new transport; canonical field order and fixed-width hex so the
signed message is byte-identical for both signer and verifier.

### Rationale for the lean

- No new relay-visible kind. The roadmap's standing commitment (§10): *no new
  relay-visible event kinds without X6's sign-off*. Reusing 25195/25196 keeps
  the feature invisible to relays.
- The plumbing already exists end-to-end in the app; the proof becomes one
  more field in an RPC round trip (`submit_proof` per §1.1).
- This supersedes the analysis doc's kind-38384 proposal (§5) — that idea
  predates the per-maker-ring design. The demo's kind 30221 was local-only
  scaffolding and stays that way.

### Consequences to accept with the lean (the honest cost)

- The RPC path is **coordinator-mediated**: the coordinator relays the proof
  and therefore *sees* it. The ring signature remains anonymous — the
  coordinator learns "some member of this maker's ring", never which — but
  metadata (who proved, when, to whom, ring contents) is visible to the
  coordinator, exactly as the analysis noted when it proposed the
  NIP-44-encrypted direct kind 38384. If that visibility is unacceptable,
  the honest alternative is a direct taker→maker kind, which requires the
  new-kind sign-off this lean deliberately avoids.
- Interacts with blockers **B2** and **B6**: the signed message must be the
  canonical binding object `{offer_id, tx_id, maker-issued nonce, ring-hash,
  amount}` — not a constant (B2) — and the base challenge must fold
  `(msg, ring, key_image)` so a proof cannot be translated across rings (B6).
  The envelope carries the fields; the binding is what makes them load-bearing.

### Still to be ruled by X6

The lean itself (existing envelope vs dedicated direct kind), and if the
existing envelope: the maker-issued nonce in B2's binding object (fresh per
reservation vs per-offer).

---

## D5 — H1: hedged nonces — DEFERRED

**Status: OPEN — DEFERRED.**

The demo draws LSAG nonces from `randomSecretKey()` per signature. Hedged
(nonce-prefix) signing — BIP-340-`aux`-style, mixing the message and key into
nonce derivation — removes catastrophic RNG failure as a single point of key
compromise (a repeated or biased nonce in LSAG leaks the signer's long-term
key, which here is the taker's money identity).

- **Why defer:** it is a hardening layer, not a correctness one; it touches
  only the signer, so it can land in either implementation (TS demo or Dart
  port) without wire-format changes; and it is small, bounded work that is
  easy to bolt on during the port.
- **Why it must not be forgotten:** until it lands, a faulty RNG on a taker's
  phone is a full key compromise. The roadmap already gates real money flow
  behind B1–B6 and (separately, §8 item 6) an audit-bar decision; hedged
  nonces should ride that same review, and **must land before any mainnet
  use**.

**Still to be ruled by X6:** confirm the deferral and pin it to the audit-bar
decision (roadmap §8 item 6), or pull it forward into the initial Dart port.

---

## 3. Consequences if all leans are accepted as drafted

**Positive**

- The trust claim becomes verifiable and private: a maker accepts a code only
  from "someone in my own curated ring" and cannot learn who; no coordinator
  gatekeeping; no new relay-visible events; default app behavior untouched
  (per-offer toggle, default off).
- The demo's 86 tests, relay transport, and ordering lock carry over; B1–B6
  are all bounded fixes on proven code, and the demo suite doubles as test
  vectors for the Dart port (roadmap §6, pure-Dart recommendation).

**Negative / accepted risks**

- Coordinator sees proof metadata under D4's lean (above).
- Cross-maker double-sign detection is forfeited under D3's lean (above).
- Small curated rings are weak anonymity unless padded (D1/D2 interaction);
  padding policy is itself an OPEN sub-item.
- Hedged nonces deferred (D5): RNG quality is load-bearing for key safety
  until it lands.

**Neutral**

- Key-image blocklists are per-maker local state (objectbox/drift), seeded per
  `tx_id` under the per-transaction reuse policy; no shared nullifier DB is
  proposed or needed under these leans.

## 4. Process

- This draft is the input to roadmap §9 **Phase 1** ("short co-authored ADR
  locking those decisions"). X6 rules on each OPEN item — in comments here, in
  the upstream discussion, or by editing the table in §2 directly.
- When every OPEN item has a ruling, status flips DRAFT → ACCEPTED, each item
  records its ruling inline, and the demo fixes (B1–B6) + Dart port proceed
  against a frozen spec.
- If a lean is rejected, the item stays OPEN with the new direction recorded;
  this ADR is superseded only if the scheme itself (LSAG, per-maker rings)
  falls.

---

*— Felix & agent team, 2026-08-15. Discussion draft for the BitBlik
maintainer (X6). Not a PR request; no merge requested or implied.*
