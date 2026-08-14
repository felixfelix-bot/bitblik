# Trust Proofs: From Demo to Feature

**Status: discussion draft for the BitBlik maintainer (X6). Not a PR request. Everything below is the maintainer's call.**

## 1. TL;DR

A working TypeScript demo (this fork, branch `feat/trust-proof-demo`, 86 tests green) proves the LSAG ring-signature math, a real Nostr relay transport, and proof-gated trade ordering. Getting from there to a shippable BitBlik feature takes three things:

1. **6 small, well-defined protocol fixes** (code audit found them — all bounded work),
2. **One port decision** — we recommend pure-Dart, ~4–6 person-days,
3. **~6 design decisions that are yours to make** (§8).

This doc exists so the discussion has shared ground truth. No merge is requested or implied.

## 2. Problem (your issue, your terminology)

- **maker** = creates offer, withdraws cash at ATM → **verifier**
- **taker** = reserves offer, provides BLIK code → **prover**
- taker proves: *"I am one of the pubkeys in YOUR trust ring"* — nobody learns which one. Protects the maker from codes funded by stolen cards; protects the taker's privacy.

## 3. What the demo PROVES today

- LSAG on secp256k1 (Liu–Wong shape): closure, linkability via key image, negative tests — 86 tests, @noble/curves + @noble/hashes
- Proof travels over a **real local Nostr relay** (NIP-01 WebSocket, schnorr-signed event, `d`-tag)
- Trade ordering **test-locked**: offer → ring proof → sats ONLY if proof valid → BLIK code last
- Presenter UX: field-by-field pointing panels, `--interactive`, `npm run preflight`

## 4. What it does NOT yet do (honest list)

- Ring comes from a local fixture, not a live kind-3 (follows) list
- Replay binding is designed but **not enforced in the signature** — code-level: the signed message is currently a constant; `offer_id` rides only in an unsigned tag. Fix = B2 below
- No keyImage registry / revocation mechanism
- TypeScript only; BitBlik is Dart/Flutter
- No independent crypto review yet

## 5. Blockers before any real money flow (code-audit output)

| # | Blocker | Fix |
|---|---------|-----|
| B1 | Verifier currently trusts the event's attacker-supplied `ring` tag | maker verifies only against a ring derived from **their own** kind-3 list; event ring = display-only |
| B2 | Proof replays anywhere, forever | sign canonical binding object `{offer_id, tx_id, maker-issued nonce, ring-hash, amount}` |
| B3 | keyImage reuse check is in-process only | persistent keyImage blocklist, checked **before** sats move |
| B4 | Ring-size-1 is accepted (anonymity set = 1) | enforce min ring size ≥4, dedupe keys, reject non-canonical points |
| B5 | All 86 tests are self-consistency | fixed-hex vectors cross-verified against an independent LSAG reference |
| B6 | Challenge doesn't bind ring/keyImage | fold `(msg, ring, I)` into base challenge — kills proof translation across rings |

Hardening (non-blocking): hedged nonces (BIP-340-aux style), signer-position shuffle, per-maker vs global keyImage trade-off, explicit threat-model doc, version pinning.

## 6. Port strategy: recommend pure-Dart

| Option | Effort | Verdict |
|--------|--------|---------|
| **A. Pure-Dart LSAG** (pointycastle EC ops, bip340 adjacent) | 4–6 pd | **Recommended** — one language, web flavor keeps working, demo tests become cross-impl vectors |
| B. FFI / rust bridge to libsecp256k1 | 10–15 pd | breaks the app's web flavor, CI ×4 platforms, heavy review burden |
| C. TS sidecar service | 3–4 pd | dead end — the prover is the taker's phone |

## 7. Where it plugs into BitBlik (from reading `core/`, `app/`, `coordinator/`)

- New taker action `submit_proof` between `reserved` → `submit_blik` in `blik.yml` (FlowEngine)
- Maker's `get_blik` / `confirm_payment` gated on verified proof — **per-offer toggle, default off**
- Ring = maker's kind-3 follows, fetched via Ndk + existing objectbox/drift caches
- Proof rides the **existing RPC envelope** (kinds 25195/25196) — no new relay-visible kind needed (demo's 30221 was local-only)
- Versioned canonical JSON envelope: `{v:1, type:"bitblik.trust-proof", offer_id, tx_id, ring[], key_image, c0, s[]}`

## 8. Open decisions (maintainer's, ranked by blocking-ness)

1. **Ring source**: kind-3 follows vs coordinator list vs hybrid *(our lean: kind-3; coordinator = bootstrap seed only)*
2. **Min ring size + decoy policy** *(lean: ≥4, dedupe, pad)*
3. **keyImage scope**: global pseudonym vs per-maker subkeys *(trade-off: cross-maker double-sign detection vs unlinkability)*
4. **Wire format**: existing RPC envelope vs dedicated kind *(lean: existing envelope)*
5. **Failure UX**: hard gate vs warning banner when taker can't prove
6. **Audit bar**: independent review before mainnet, or pilot-behind-flag first

## 9. Phased plan

- **Phase 0 (now):** this doc — align on §8 decisions
- **Phase 1:** short co-authored ADR locking those decisions; TS fixes B1–B6 land in the demo repo
- **Phase 2:** pure-Dart port; cross-implementation test vectors green both ways
- **Phase 3:** pilot behind opt-in flag; default flow untouched

**"Viable feature" =** ADR agreed + both implementations pass shared vectors + one proof-gated trade completed on the pilot + maintainer sign-off.

## 10. What we will NOT do

- No PR until you explicitly ask for one
- No NIP proposal — this stays app-level
- No new relay-visible event kinds without your sign-off
- No timeline pressure

## 11. Links

- Demo + guide: `demo/trust-proof/` (README.md, PRESENTER.md, `npm run preflight`)
- Fork: github.com/felixfelix-bot/bitblik, branch `feat/trust-proof-demo`
- This doc: `docs/trust-proof-upstream-roadmap.md`

— Felix & agent team, 2026-08-15
