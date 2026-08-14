# PRESENTER.md — Live Demo Script & Q&A Cheat Sheet

Everything you need to run the trust-proof demo in front of an audience: a
1-minute scripted walkthrough keyed to the `--interactive` pauses, and a
2-minute Q&A cheat sheet with breadcrumbs into [README.md](README.md).

**The story in one line**: every maker (cash withdrawer) publishes their own
Nostr follow list — their personal trust ring — and a taker (code provider)
proves "I'm in YOUR ring" with a ring signature, without revealing which
member they are. A coordinator's list is just a seed you can copy once and
then diverge from. Seed/curator, not gatekeeper.

## Setup (before the audience arrives)

```bash
cd demo/trust-proof
npm install                       # once
npx tsx src/demo.ts --quick       # dry run — must end "ALL SECURITY CHECKS PASSED"
```

Optional hook: collect one audience npub beforehand and pass it as a ring
decoy — see [The npub hook](#the-npub-hook).

## The 1-Minute Script

Run with:

```bash
npx tsx src/demo.ts --interactive --quick
```

`--interactive` pauses after each of the six section headers with
`[Enter] to continue...` — that's your cue to talk. Timings below sum to ~60s.
(On screen, ring members are labeled `maker[0..4]` — legacy label from the
coordinator-only framing; read them as "the pubkeys in the verifying maker's
ring".)

### Pause 1 — `1. Setup — Generate 5 maker keypairs` (~15s)

> "BitBlik swaps BLIK codes for Lightning. The party at risk is the maker —
> the cash withdrawer. In BitBlik every maker keeps their OWN trust ring: a
> plain Nostr follow list, kind 3. These five keys are one maker's ring. A new
> maker seeds theirs by copying a published list in one action — the
> coordinator is a seed, not a gatekeeper — then curates it themselves."

### Pause 2 — `2. Taker generates ring signature` (~10s)

> "Now the taker — the code provider selling the BLIK code — proves 'I am one
> of the five people in THIS maker's ring' without saying which one. That's an
> LSAG ring signature: one shot, no coordinator involved, and this key image
> is a nullifier cryptographically bound to their secret key."

### Pause 3 — `3. Maker (cash withdrawer) verifies the proof` (~10s)

> "The maker checks the proof against their OWN list. Three greens: signature
> valid, signer really is in the ring — and, the point — the maker cannot tell
> which of the five it was."

### Pause 4 — `4. Nullifier reuse detection (linkability)` (~10s)

> "Same taker proves twice: same key image both times, so the maker can link
> repeat provers — and still can't name them. A different taker yields a
> different key image. Reuse detection without identification."

### Pause 5 — `5. Security checks` (~5s, one line with --quick)

> "And it's not forgeable: wrong key, tampered message, tampered response,
> tampered nullifier — all four rejected."

### Pause 6 — `Summary` (~10s)

> "So: every maker curates their own ring, membership is proven without
> identification, and a nullifier stops replay. Per-counterparty trust — the
> literal web-of-trust."

## The npub hook

The crowd-pleaser. Before the demo (or right at Pause 6), ask:

> **"Give me your npub — I'll add you to the ring."**

Then rerun with the participant as a decoy:

```bash
npx tsx src/demo.ts --interactive --quick --npub npub1your...participant
```

Their pubkey is inserted into the ring BEFORE signing; they become an
anonymous ring member and the proof still verifies (~15 second rerun). This
is also the honest answer to "small rings are weak": ring padding with decoys
is literally a CLI flag.

## 2-Minute Q&A Cheat Sheet

| If they ask... | You say... | Breadcrumb |
|---|---|---|
| "Whose ring is this verified against?" | The specific maker you're transacting with. Every maker's kind 3 follow list IS their personal ring; proofs are per-maker and don't transfer. | [README §3.1–3.2, §6](README.md) |
| "How does a new maker get a ring?" | One action: copy a published seed list (e.g. the coordinator's) to seed yours, then curate. Coordinator = seed/curator, not gatekeeper — no single party dictates trust. | [README §3.2, §6](README.md); [analysis §10](../../docs/trust-proof-analysis.md) |
| "Can the taker reuse a proof / double-spend?" | The key image is the nullifier: same signer → same key image, always. Per-transaction policy — replaying the same proof to the same tx is rejected; a new tx gets a fresh signature over a new message. | [README §3.6](README.md) |
| "Could a proof for maker A be replayed to maker B?" | No — the signed message binds `offer_id` + `tx_id`, and the ring itself is maker-specific, so ring-matching rejects it before the math even runs. | [analysis §10.3](../../docs/trust-proof-analysis.md) |
| "Why LSAG and not Borromean ring signatures?" | Borromean isn't linkable — no key image, so no nullifier; we'd have to bolt on a weaker hash-based one. LSAG is secp256k1-native (Nostr keys work as-is) and comes from Monero's lineage. | [README §2](README.md) |
| "What if a maker's ring is tiny?" | Anonymity set = ring size, so pad it with decoy pubkeys — the demo does it live with `--npub`. Bigger rings cost O(N) sign/verify. | [README §6](README.md); [analysis §10.3](../../docs/trust-proof-analysis.md) |
| "Does this go into the Dart app?" | Yes — same math ports to Dart on the existing `bip340` + `crypto` packages, ~30 lines of hash-to-curve; this TS demo is the reference. | [README §7](README.md) |
| "What stops a taker putting random pubkeys in the ring?" | Nothing — decoys are the feature. But you can only SIGN at a position whose secret key you hold; otherwise ring closure fails. | [README §6](README.md) |
| "I'm a maker — how do I get provers into MY ring?" | That's the hook: they hand you their npub, you follow them (kind 3 edit), done — no coordinator permission involved. | [README §3.2](README.md) |

## One-sentence fallback

If you only get one sentence:

> "Every maker publishes a follow list; you prove you're in THAT list with a
> ring signature, so they know you're trusted without learning who you are —
> and a key image stops you replaying the proof."

## References

- [README.md](README.md) — full design, LSAG math, Q&A breadcrumbs
- [../../docs/trust-proof-analysis.md](../../docs/trust-proof-analysis.md) — scheme comparison, protocol design, and the coordinator-only → per-counterparty design evolution (§10)
