# BitBlik — Technical Architecture Breakdown

Peer-to-peer BLIK/Lightning exchange over Nostr, with atomic settlement via Lightning hold invoices. Makers lock Lightning sats; takers pay fiat (BLIK / MB WAY / TWINT codes); the coordinator mediates and atomically settles.

> Repository: `~/repos/bitblik` · Flutter/Dart monorepo · **4 packages**: `core`, `coordinator`, `cli`, `app`. This analysis covers the first three plus the protocol layer (app omitted — UI only).

---

## 1. Architecture at a Glance

```
        ┌──────────────────── Maker / Taker clients ────────────────────┐
        │   app (Flutter)          cli (Dart console)                    │
        │        \                    /                                   │
        │         \                  /   NIP-44 encrypted RPC             │
        │          ↓                ↓   (kind 25195 req / 25196 resp)     │
        └─────────────────────────────────────────────────────────────────┘
                                  │  Nostr relays
                                  ↓
              ┌────────── Coordinator (server) ──────────┐
              │  NostrService ── decrypt → _processRequest│
              │  CoordinatorService                       │
              │     ├─ OfferFlow (generic yaml OR legacy) │
              │     ├─ DatabaseService  (SQLite)          │
              │     ├─ PaymentService (LND OR NWC)        │
              │     │     ├─ hold invoice lifecycle       │
              │     │     └─ Lightning payout             │
              │     ├─ TelegramService / Matrix / SimpleX │
              │     └─ broadcast kind 38383 + 25197       │
              └───────────────────────────────────────────┘
                                  │
                                  ↓
                    Lightning node (LND / NWC wallet)
```

**Three roles**
| Role | What it does |
|------|--------------|
| **Maker** | Creates an offer: locks `amountSats + makerFees` in a Lightning **hold invoice** at a coordinator; later confirms whether the taker's BLIK/fiat code actually paid them. |
| **Taker** | Reserves a listed offer, submits a payment code (BLIK) **or** pays a maker-issued code (TWINT), provides a payout invoice / Lightning address, and gets paid in sats. |
| **Coordinator** | The trusted mediator: owns the hold-invoice preimage, enforces the state machine, settles/cancels the hold invoice, and pays the taker's invoice on settlement. Also publishes offers and pushes status updates over Nostr. |

Atomicity comes from the hold invoice: the maker's sats are **locked but not paid** until the coordinator reveals the preimage (`settle_invoice`), and refunded automatically if the coordinator cancels (`cancel_invoice`).

---

## 2. PROTOCOL — Nostr Kinds, Relays, RPC Methods

### 2.1 Nostr Event Kinds  (`core/lib/src/constants/kinds.dart`)

| Kind | Name | Type | Purpose |
|------|------|------|---------|
| `15125` | `kKindCoordinatorInfo` | Replaceable | Coordinator advertises metadata (name, fees, limits, currencies, `payment_system`, channel links). |
| `25195` | `kKindCoordinatorRequest` | Ephemeral | **NIP-44 encrypted** client → coordinator RPC envelope. |
| `25196` | `kKindCoordinatorResponse` | Ephemeral | **NIP-44 encrypted** coordinator → client RPC reply (matched by request `id`). |
| `25197` | `kKindOfferStatusUpdate` | Ephemeral | **NIP-44 encrypted** push notification of an offer's new state, tagged `[offer_id, ...]`. |
| `38383` | `kKindOffer` | Parameterized replaceable | NIP-69-style public order listing (the offer feed). |
| `10002` | `kKindRelayList` | Replaceable (NIP-65) | Per-identity relay list. Coordinators publish it; the Bitblik project identities publish discovery relay sets. |

### 2.2 Relay Discovery  (`core/lib/src/constants/relays.dart`)

Three **market identities** (one per country), each is a hex pubkey whose NIP-65 (`kind 10002`) event lists that market's discovery relays:

| Market | Currency | Identity pubkey (npub) |
|--------|----------|------------------------|
| **Bitblik** (BLIK / Poland) | PLN | `npub1k3g092rlzvn7nftz3jte9pkx63zp705nh78r6hjpjm55fjg7r2cqx8stj3` |
| **Bitway** (MB WAY / Portugal) | EUR | `npub180nj93uqjvvjksryaxaz8fk9gxwwtg06gxlkd5csrj6rqfg3phhs09n5s9` |
| **Bittwint** (TWINT / Switzerland) | CHF | `npub1jwyfy9ah5g6p6r509vcesmyjwwa93p9qrk4kx365d7pynxfkmqysf5a66q` |

```dart
const List<String> kDiscoveryRelays = [
  'wss://relay.primal.net',
  'wss://nos.lol',
  'wss://nostr.mom',
  'wss://relay.damus.io',
];
```

**Discovery flow:** client connects to the bootstrap relays → fetches the market identity's `kind 10002` → learns the live discovery relays → queries `kind 15125` there to find coordinators → reads each coordinator's own `kind 10002` to route all RPC traffic to that coordinator's relays.

### 2.3 RPC Method Vocabulary  (`core/lib/src/constants/rpc_methods.dart`)

The `method` field inside every encrypted `NostrRequest`. **The RPC method name IS the flow state-machine event name** — the coordinator's flow engine dispatches directly off it.

```dart
// Coordinator metadata
const String kRpcGetInfo = 'get_info';

// Offer lifecycle — maker side
const String kRpcInitiateOffer   = 'initiate_offer';   // not a flow event; handled directly
const String kRpcCancelOffer     = 'cancel_offer';
const String kRpcGetBlik         = 'get_blik';         // returns the code, no state change to offer fields
const String kRpcConfirmPayment  = 'confirm_payment';
const String kRpcMarkBlikInvalid = 'mark_blik_invalid';
const String kRpcOpenDispute     = 'open_dispute';

// Offer lifecycle — taker side
const String kRpcReserveOffer          = 'reserve_offer';
const String kRpcSubmitBlik            = 'submit_blik';
const String kRpcCancelReservation     = 'cancel_reservation';
const String kRpcUpdateTakerInvoice    = 'update_taker_invoice';   // payout retry
const String kRpcRetryTakerPayment     = 'retry_taker_payment';
const String kRpcMarkBlikCharged       = 'mark_blik_charged';

// Queries
const String kRpcGetOfferDetails            = 'get_offer_details';
// Deprecated, kept for old clients:
const String kRpcGetMyActiveOffer           = 'get_my_active_offer';
const String kRpcGetMyFinishedOffers        = 'get_my_finished_offers';
const String kRpcGetSuccessfulOffersStats   = 'get_successful_offers_stats';
```

TWINT adds `mark_twint_charged`, `start_dispute`, `enter_new_twint` — all defined in `twint.yml`, dispatched by the same generic engine with **no per-flow code**.

---

## 3. PROTOCOL CODEC — Wire Format & NIP-44

### 3.1 JSON-RPC Envelope  (`core/lib/src/protocol/rpc_envelope.dart`)

Plain JSON-RPC 2.0-ish envelope. Encryption is layered on top, not in the envelope.

```dart
class NostrRequest {
  final String method;                 // == flow event name (e.g. 'reserve_offer')
  final Map<String, dynamic> params;   // { 'offer_id': ..., 'blik_code': ..., ... }
  final String? id;                    // random 16-byte hex; coordinator echoes it
  final String? client;                // 'app-bitblik-android/0.8.0', 'cli-bitway-linux/0.1.0'
}

class NostrResponse {
  final String? id;                    // matches the request id
  final Map<String, dynamic>? result;  // present on success
  final Map<String, dynamic>? error;   // { 'code': '...', 'message': '...' } on failure
  bool get isSuccess => error == null;
}
```

### 3.2 NIP-44 Wrapping  (`core/lib/src/protocol/protocol_codec.dart`)

`ProtocolCodec` is the **single source of truth** for how every wire event is built. Every request, response, and status update uses NIP-44 (via NDK's `Nip44.encryptMessage`):

```dart
static Future<Nip01Event> encryptRequest({
  required NostrRequest request,
  required String senderPrivateKeyHex,
  required String senderPubkeyHex,
  required String coordinatorPubkey,
}) async {
  final encrypted = await Nip44.encryptMessage(
    jsonEncode(request.toJson()),
    senderPrivateKeyHex,
    coordinatorPubkey,
  );
  return Nip01Event(
    kind: kKindCoordinatorRequest,            // 25195
    pubKey: senderPubkeyHex,
    content: encrypted,
    tags: [['p', coordinatorPubkey]],          // NIP-44 recipient tag
    createdAt: DateTime.now().millisecondsSinceEpoch ~/ 1000,
  );
}
```

- The event is returned **unsigned**; the caller signs it via the injected `Bip340EventSigner`. This keeps the signer abstraction out of core.
- Status updates (`kind 25197`) add a second tag `['offer_id', offerId]` so clients can fan out updates per offer.
- Decryption uses `Nip44.decryptMessage(content, myPrivKey, event.pubKey)`.

### 3.3 Client Transport  (`core/lib/src/protocol/bitblik_rpc_client.dart`)

`BitblikRpcClient` is the request/response correlator on top of NDK:

1. `start()` opens a single subscription for `kind 25196` events tagged `p = <my pubkey>` (`since: now`).
2. `send(req, coordinatorPubkey)`:
   - generates a 16-byte hex `id` if absent,
   - **expands the response subscription** to also cover the target coordinator's relays (race-free),
   - prefers already-connected relays to avoid connect latency,
   - builds the encrypted event, signs, broadcasts with `specificRelays`,
   - registers a `Completer<NostrResponse>` keyed by `id`,
   - awaits the completer with a `timeout` (default 5s + 3s grace).
3. Incoming responses are decrypted, matched by `id` **and** verified to come from the expected `coordinatorPubkey` — preventing cross-coordinator response injection.

```dart
if (event.pubKey != pending.coordinatorPubkey) return;  // drop foreign responses
```

`updateResponseRelays(union)` re-points the subscription when the set of enabled coordinators changes — clients follow coordinators as they're discovered.

---

## 4. STATE MACHINE — The Offer Flow Engine

This is the most interesting part of the codebase. It's a **declarative, YAML-driven state machine** with a thin, generic executor. The same engine runs BLIK, MB WAY, and TWINT with zero per-flow code on the coordinator.

### 4.1 Engine Core  (`core/lib/src/flow/`)

**`flow_models.dart`** — the parsed definition. Three trigger types:

```dart
enum FlowTriggerType { userAction, timeout, auto }
enum FlowActor { maker, taker, coordinator, server }

@immutable
class FlowTransition {
  final FlowTriggerType trigger;
  final String? event;           // == RPC method name for userAction transitions
  final FlowActor? actor;        // required role; null = anyone
  final String target;           // destination state
  final String? onFailTarget;    // route on definitive action failure
  final int? durationSeconds;    // for timeouts ('after:')
  final String? fromField;       // base timestamp for timeouts ('from:')
  final List<String> actions;    // 'do:' keywords executed by the coordinator
  final String? returns;         // field to echo in RPC response (e.g. 'blik_code')
}

class FlowState {
  final String name;
  final bool initial;
  final bool terminal;
  final String? nip69;           // NIP-69 status for public broadcast
  final List<String> actions;    // post-commit 'do:' on state entry
  final List<FlowTransition> transitions;
}

class FlowDefinition {
  final String id;
  final Map<String, FlowState> states;
  final String initialState;
  // parse() validates: exactly one initial state, no terminal state has
  // transitions, every target/on_fail target names a known state.
}
```

Flow files **import** a shared fragment:

```yaml
# blik.yml, mbway.yml, twint.yml all start with:
imports: [common.yml]
id: blik
states: { ...method-specific states... }
```

`common.yml` contributes the **settlement tail** shared by every method:
`makerConfirmed → settled → payingTaker → takerPaid` (or `→ takerPaymentFailed`).

**`flow_engine.dart`** — `FlowEngine` is **pure and side-effect free**. It only *resolves* what a transition should do; the coordinator performs the actual DB compare-and-set:

```dart
class FlowEngine {
  FlowResolution resolveUserAction({fromState, event, actor});
  FlowTransition? timeoutFor(String state);
  List<FlowTransition> userActionsFor(String state, FlowActor actor);  // drives UI buttons
  FlowTransition? transitionFor(String state, String event, {actor});
  Set<String> statesAllowing(String event, {actor});                   // for compare-and-set guards
}
```

The schema-v2 commit model is documented in the YAML header:

> *A transition is an attempt. When `on` fires, run `do`; if every action succeeds, commit and advance to `to`. If any action fails, the state does not advance and nothing is committed. `on_fail` routes definitive transition failure. `on: auto` transitions are detached/internal attempts. State-level `do:` runs after the state commit, best-effort.*

### 4.2 BLIK Flow  (`core/lib/flows/blik.yml`)

Poland / 6-digit code / 2-min validity. **Taker generates the code** after reserving. Happy path in bold:

```
funded ──reserve_offer(taker)──▶ reserved ──submit_blik(taker)──▶ blikReceived
  ▲                                  │                                 │
  │                                  │                          get_blik(maker)
  │    cancel_reservation            │                                 │
  └──────────────────────────────────┘                                 ▼
                                                              blikSentToMaker
                                                                   │
                                              ┌────────────────────┼────────────────────┐
                                              │                    │                    │
                                  confirm_payment(maker)  mark_blik_invalid(maker)    timeout(120s from code_received_at)
                                              │                    │                    │
                                              ▼                    ▼                    ▼
                                       makerConfirmed        invalidBlik          expiredSentBlik
                                              │                    │                    │
                                              ▼                    │     mark_blik_charged(taker)
                                          settled ◀──auto──── ...  │                    │
                                              ▼                    ▼                    ▼
                                          payingTaker          conflict ◀─────── takerCharged
                                              │                    │                    │
                                       send_payment(auto)         ...                  ...
                                              ▼
                                          takerPaid (terminal)
```

**Key timeouts** (all from the YAML, none hardcoded):

| State | Timeout | Action |
|-------|---------|--------|
| `funded` | 600s from `created_at` (total lifetime) | cancel hold invoice → `expired` |
| `reserved` | 61s | cancel reservation → `funded` (re-list) |
| `blikReceived` | 120s (BLIK confirmation window) | → `expiredBlik` |
| `blikSentToMaker` | 120s from `code_received_at` | → `expiredSentBlik` |
| `invalidBlik` | 3600s | settle + escalate → `dispute` |
| `expiredSentBlik` | 3600s | settle + escalate → `dispute` |
| `takerCharged` | 1800s | **auto-confirm in taker's favour** → `makerConfirmed` |
| `conflict` | 3600s | settle + escalate → `dispute` |

**Failure recovery states** `invalidBlik`, `expiredBlik`, `expiredSentBlik`, `takerCharged`, `conflict` give either party a way back: the same taker can re-reserve, cancel, or escalate.

### 4.3 MB WAY Flow  (`mbway.yml`)

Portugal / 10-digit code / 30-min validity / ATM cash-out only. Same shape as BLIK, but:
- Confirmation window is **1800s** (30 min) instead of 120s.
- `requiresCodeConfirmation: false` — the taker doesn't push-confirm anything; the maker just enters the code at the ATM.
- `reservation` window is 62s.
- Restricted to `OfferCategory.atm`.

### 4.4 TWINT Flow  (`twint.yml`)

Switzerland / 5-digit code / 5-min validity. **Maker provides the code at offer creation** (`makerProvidesCodeAtOfferCreation: true`). This inverts the model:

```
funded (code already attached)
  │ reserve_offer(taker)  ── do: reserve_taker, accept_taker_invoice,
  │                            send_twint_code_to_taker  (code revealed to taker)
  ▼
reserved
  ├──confirm_payment(maker)──▶ makerConfirmed ──▶ settled ──▶ payingTaker ──▶ takerPaid
  ├──mark_twint_charged(taker)──▶ takerCharged ──▶ (maker confirms or auto-confirm @3600s)
  ├──cancel_reservation(taker)──▶ funded
  └──timeout(300s from code_received_at)──▶ expiredTwint
                                            ├──mark_twint_charged──▶ takerCharged
                                            └──timeout(300s)──▶ invalidTwint
                                              enter_new_twint(maker)──▶ funded (fresh code)
```

The TWINT flow is the **first market on the generic yaml-driven engine** — its states (`invalidTwint`, `expiredTwint`) have no `OfferStatus` enum value and are stored/persisted purely as raw strings.

### 4.5 Common Settlement Tail  (`common.yml`)

Once a maker confirms (or auto-confirms), the same chain runs for every method:

```yaml
makerConfirmed:    transitions: [{ on: auto, do: [settle_offer_funds], to: settled }]
settled:           transitions: [{ on: auto, to: payingTaker }]
payingTaker:       transitions:
  - { on: auto, do: [send_payment], to: takerPaid, on_fail: takerPaymentFailed }
  - { on: timeout, after: 300, to: takerPaymentFailed }
takerPaid:         terminal: true        # success
takerPaymentFailed:
  - update_taker_invoice(taker)  → payingTaker
  - retry_taker_payment(taker)   → payingTaker
dispute:                                  # formal dispute, coordinator-ruled
  - resolve_dispute_refund_maker(coordinator) → cancelled [refunds maker]
  - resolve_dispute_pay_taker(coordinator)    → payingTaker
```

---

## 5. OFFER MODEL  (`core/lib/src/models/offer.dart`)

`Offer` is the central data structure, persisted by the coordinator and shipped (selectively) over RPC.

### 5.1 Status — Dual Representation

```dart
enum OfferStatus {
  created, funded, expired, cancelled,
  reserved, blikReceived, blikSentToMaker, expiredBlik, expiredSentBlik,
  takerCharged, invalidBlik, conflict, dispute,
  makerConfirmed, settled, payingTaker, takerPaymentFailed, takerPaid,
  unknown,   // sentinel: persisted status not recognized by this client build
}
```

`OfferStatus` is **append-only** — never rename/remove. But generic flows (TWINT) have states with no enum value, so `Offer` carries **both**:

```dart
final OfferStatus status;       // parsed enum; unknown for generic-only states
final String statusRaw;         // verbatim flow-state id ('invalidTwint', 'blikReceived', ...)
// statusRaw is the source of truth for the flow engine; status is for legacy clients/UI.
```

`flow_status_map.dart` does the purely lexical camelCase ⇄ snake_case bridge (`blikSentToMaker` ⇄ `blik_sent_to_maker`).

### 5.2 Key Fields

```dart
class Offer {
  final String id;                          // UUID (post-funding); == paymentHash pre-funding
  final int amountSats;                     // sats the taker receives (after premium)
  final int makerFees;                      // coordinator's maker cut
  final double fiatAmount;
  final String fiatCurrency;                // 'PLN', 'EUR', 'CHF'
  final String makerPubkey;
  final String coordinatorPubkey;
  final String? takerPubkey;                // null until reserved
  final String? blikCode;                   // payment code (BLIK/MBWAY/TWINT all use this field)
  final String? holdInvoice;                // bolt11 string
  final String? holdInvoicePaymentHash;     // the offer's pre-funding id
  final String? holdInvoicePreimage;        // coordinator-only; never shipped to clients
  final String? takerLightningAddress;
  final String? takerInvoice;               // bolt11 the coordinator pays out to
  final double premiumPercent;              // maker premium above market (reduces locked sats)
  // Lifecycle timestamps:
  final DateTime createdAt;
  final DateTime? reservedAt, blikReceivedAt, makerConfirmedAt,
      settledAt, takerChargedAt, disputeAt, takerPaidAt;
  final DisputeEscalationReason? disputeEscalationReason;
  final String? takerPaymentFailureReason;
  final OfferCategory? category;            // shop | atm | online
  final String? clientVersion;              // coordinator-only, never serialized to clients
}
```

### 5.3 Privacy-Aware Serialization

`toRpcJson(...)` is critical for security — it prevents information leakage:

```dart
Map<String, dynamic> toRpcJson({
  bool includeBlikCode = false,
  bool includeTakerInvoice = false,
  bool includeHoldInvoicePreimage = false,
  bool forTaker = false,                    // strips maker-private fields
}) {
  final json = toJsonWithPubkeys();
  // ...
  if (forTaker) {
    json.remove('maker_pubkey');             // public offers hide the maker
    json.remove('hold_invoice');
    json.remove('maker_fees');
    json.remove('payment_wallet_id');
  }
}
```

This is necessary because public offer events deliberately hide the maker's pubkey, so reserving an offer must not reveal it either. NIP-44 caps plaintext at 65,535 bytes, hence the slim `toStatsJson()` for stats endpoints.

`Offer.fromNostrEvent()` parses the public NIP-69-style `kind 38383` event from tags (`d`=id, `amt`, `fa`, `f`, `s`=nip69 status, `maker`, `p`=coordinator, `taker`, `premium`, `category`, …).

### 5.4 Coordinator Record  (`coordinator_record.dart`)

`CoordinatorRecord` wraps a coordinator's `CoordinatorInfo` with discovery metadata and ranking signals:

```dart
class CoordinatorRecord {
  final String pubkeyHex;
  final CoordinatorInfo? info;
  final List<String> relays;                // from the coordinator's NIP-65
  final bool relayListFromNip65;
  final bool enabled, manualAdded;
  // Reliability / ranking:
  final bool? responsive;
  final int successfulProbes, failedProbes;
  final int networkFinishedCount;           // count of #s=success offers signed recently
  final int networkDistinctCounterpartyCount;
  final int networkFinishedVolumeSats;
  final int localFinishedCount;

  double get score {                         // composite reliability ranking
    final responsiveTier = responsive == true ? 1000.0 : 0.0;
    // + personal usage, breadth, log(volume), probe ratio, observed age
  }
}
```

`CoordinatorInfo` is parsed from a `kind 15125` event (one tag per field) — `name`, `maker_fee`, `taker_fee`, `min/max_amount_sats`, `currencies`, `payment_system`, `reservation_seconds`, `taker_charged_auto_confirm_seconds`, `max_premium_percent`, `version`, channel links.

---

## 6. COORDINATOR — Hold Invoice Lifecycle & Settlement

The coordinator is a long-running Dart server built around `CoordinatorService` (`packages/coordinator/lib/src/services/coordinator_service.dart`, ~2126 lines), with the flow logic split into `part` files.

### 6.1 Hold Invoice Lifecycle

**Step 1 — `initiate_offer` RPC** (NOT a flow event; handled directly by `_processRequest`):

```dart
Future<Map<String, dynamic>> initiateOfferFiat({...}) async {
  // 1. Validate fiat amount, currency, category against _paymentSystem limits.
  // 2. Fetch BTC/fiat rate from CoinGecko / Yadio / Blockchain.info (averaged).
  final rate = await _getRate(fiatCurrency);
  final baseSats = (fiatAmount / rate * 1e8).round();
  // 3. Apply premium (reduces locked sats) and compute fees.
  final satsAmount = (baseSats * (1 - premium / 100)).round();
  final makerFees = OfferQuote.makerFeeSats(baseSats, _makerFeePercentage);
  // 4. Generate preimage + payment hash. Coordinator keeps the preimage secret.
  final preimage = _generatePreimage();
  final paymentHash = sha256.convert(preimage).bytes;
  // 5. Ask the payment backend (LND or NWC) to create the hold invoice.
  final backendResponse = await _paymentBackend!.createHoldInvoice(
      amountSats: totalAmountSats, memo: memo, paymentHashHex: paymentHashHex);
  // 6. Stash pending record + subscribe to invoice updates.
  _pendingOffers[returnedPaymentHashHex] = _PendingOfferRecord(data: {...});
  _startInvoiceSubscription(returnedPaymentHashHex);
  _armPendingOfferTimeout(returnedPaymentHashHex);
  return { 'holdInvoice': holdInvoice, 'paymentHash': ..., ... };
}
```

**Step 2 — maker pays the hold invoice.** The backend subscription fires `InvoiceStatus.ACCEPTED`:

```dart
_subscription = _paymentBackend!.subscribeToInvoiceUpdates(paymentHashHex: ...)
  .listen((update) async {
    if (update.status == InvoiceStatus.ACCEPTED) {
      await _createOfferFromFundedInvoice(paymentHashHex);  // INSERT offer, status=funded
      await _clearPendingOffer(paymentHashHex);
    } else if (update.status == InvoiceStatus.CANCELED) {
      await _clearPendingOffer(paymentHashHex);
    }
  });
```

`_createOfferFromFundedInvoice` does the genesis write: `Offer(id: Uuid().v4(), status: funded, statusRaw: <flowInitialState>, ...)`, broadcasts the NIP-69 order, calls `flow.onOfferFunded(offer)` (which seeds offer_state_history + arms timers), and publishes the first status update.

The Lightning hold-invoice states map directly to coordinator actions:
- **OPEN** → pending offer (`_pendingOffers` map)
- **ACCEPTED** (maker's sats locked) → offer is `funded`
- **SETTLED** (coordinator reveals preimage via `settleInvoice(preimageHex)`) → maker's sats move to coordinator, taker gets paid
- **CANCELED** (`cancelInvoice(paymentHashHex)`) → maker's sats refund automatically

### 6.2 RPC Dispatch  (`nostr_service.dart`)

Every encrypted `kind 25195` event hits `_handleRequest` → `_processRequest`:

```dart
Future<Map<String, dynamic>> _processRequest(method, params, userPubkey, ...) async {
  // 1. Offer-action RPCs (the state machine) delegate to the active flow:
  if (_coordinatorService.flow.handlesRpc(method)) {
    return await _coordinatorService.flow.handleRpc(method, params, userPubkey, ...);
  }
  // 2. Shared query/info/payout RPCs:
  switch (method) {
    case kRpcGetInfo:              return (await getCoordinatorInfo()).toJson();
    case kRpcInitiateOffer:        return initiateOfferFiat(...);
    case kRpcGetOfferDetails:      return offer.toRpcJson(forTaker: ...);
    case kRpcUpdateTakerInvoice:   return updateTakerInvoice(...);
    case kRpcRetryTakerPayment:    return retryTakerPayment(...);
    case kRpcGetMyActiveOffer:     // deprecated
    case kRpcGetMyFinishedOffers:  // deprecated
    case kRpcGetSuccessfulOffersStats: // deprecated
  }
}
```

### 6.3 Generic Flow Executor  (`coordinator_flow_generic.dart`)

`GenericOfferFlow` is **state-name agnostic** — every behaviour comes from the YAML. The `handlesRpc` set is derived from the loaded flow:

```dart
late final Set<String> _handledEvents = {
  for (final s in _engine.definition.states.values)
    for (final t in s.transitions)
      if (t.trigger == FlowTriggerType.userAction && t.event != null) t.event!,
};

@override
bool handlesRpc(String method) => _handledEvents.contains(method);
```

The atomic transition apply (`_applyTransition`) is the heart of the design:

```dart
Future<bool> _applyTransition(offer, t, params, {trigger, actorName, ...}) async {
  // 1. Build the write accumulator (shared across all actions of one attempt).
  final ctx = FlowEffectContext(offer: offer, transition: t, write: OfferWriteSpec(), ...);
  var targetState = t.target;
  try {
    // 2. Run every 'do:' action in order. All must succeed.
    for (final a in t.actions) await _runAction(a, ctx);
  } on FlowTransitionFailure catch (e) {
    if (t.onFailTarget == null) rethrow;
    targetState = t.onFailTarget!;     // route to failure target
  }
  // 3. ATOMIC compare-and-set: only commits if expectedCurrentStatuses still matches.
  final applied = await _c._dbService.updateOfferRawStatusIfCurrent(
    offer.id, targetState,
    expectedCurrentStatuses: [offer.statusRaw],   // optimistic-concurrency guard
    expectedTakerPubkey: w.expectedTakerPubkey,   // race-safe taker binding
    takerPubkey: w.takerPubkey, reservedAt: ..., code: ..., ...,
    transitionMeta: StateTransitionMeta(trigger, event, actor, extra: audit),
  );
  if (!applied) return false;          // someone else moved first; nothing committed
  // 4. Post-commit side effects: broadcast + arm timer + run auto edges.
  _cancelTimer(offer.id);
  final updated = await _c._dbService.getOfferById(offer.id);
  if (updated != null) await _enterState(updated);
  return true;
}
```

**Atomicity guarantees:**
1. All `do:` actions run against an in-memory `OfferWriteSpec` **before** any DB write — if any throws, nothing is persisted.
2. The DB write is a single `UPDATE ... WHERE status IN (expectedCurrentStatuses)` compare-and-set — concurrent RPCs from different clients cannot corrupt state.
3. `expectedTakerPubkey` makes the taker-binding reservation race-safe.

**Timers** are armed in `_enterState` after a successful commit:

```dart
void _armTimer(Offer offer) {
  final t = _engine.timeoutFor(offer.statusRaw);
  if (t == null || t.durationSeconds == null) return;
  final DateTime base;
  switch (t.fromField) {                // 'from:' in the YAML
    case 'code_received_at': base = offer.blikReceivedAt ?? offer.updatedAt ?? offer.createdAt;
    case 'created_at':       base = offer.createdAt;      // total lifetime, NOT reset by reserve
    default:                 base = offer.updatedAt ?? offer.createdAt;  // state entry
  }
  final fireAt = base.add(Duration(seconds: t.durationSeconds!));
  _stateTimers[offer.id] = Timer(fireAt.difference(_c._clock.now()), () {
    _fireTimeout(offer.id, expectedState, t);  // re-checks state, then _applyTransition
  });
}
```

A timer fire is itself a transition attempt with `trigger: 'timeout'` — it goes through the same compare-and-set, so a stale timer cannot overwrite a newer state.

**`auto` transitions** are detached: `_driveAuto` reads the new state's `auto` edge and runs it as a separate `_applyTransition(trigger: 'auto')`. This is how `makerConfirmed → settled → payingTaker → takerPaid` chains without external input.

**Startup recovery** (`recoverTimers`):
1. Re-arm timers for every non-terminal offer (computing remaining time from the base timestamp).
2. Re-drive any interrupted `auto` chain (e.g. crashed mid-payout).
3. **`_recoverFailedPayouts`** — reconciles `takerPaymentFailed` offers against the wallet, because the NWC `pay_invoice` call is **not idempotent**: a transport timeout can leave the offer marked failed even though the wallet actually settled. The wallet's `reconcileOutgoingPayment` is the source of truth.

### 6.4 Action Implementations  (`coordinator/lib/src/services/actions/`)

Each `do:` keyword is a self-describing `FlowAction` subclass. The registry is built from `allFlowActions` (the only compile-time anchor — Dart AOT has no reflection):

```dart
final List<FlowAction> allFlowActions = [
  AcceptTakerInvoiceAction(), AssertAssignedTakerAction(),
  CancelHoldInvoiceAction(), CancelReservationAction(),
  ClearTakerFieldsAction(), RefundMakerAction(),
  RequireMakerRefundInvoiceAction(), ResolveTakerInvoiceAction(),
  ReserveTakerAction(), SendOfferNotificationsAction(),
  SendPaymentAction(), SettleOfferFundsAction(),
  StampCodeReceivedAtAction(), StampMakerConfirmedAtAction(),
  StampReservedAtAction(), StampTakerChargedAtAction(),
  ValidateCodeAction(),
  NotifyMakerOfChargeAction(), SendTwintCodeToTakerAction(), SetNewCodeAction(),
];
```

Key examples:

**`reserve_taker`** — atomic taker binding:
```dart
class ReserveTakerAction extends FlowAction {
  String get name => 'reserve_taker';
  Future<void> run(flow, ctx) async {
    ctx.write.takerPubkey = ctx.userPubkey;
    ctx.write.reservedAt = ctx.now.add(const Duration(seconds: 1));
    // The compare-and-set in _applyTransition binds this atomically.
  }
}
```

**`settle_offer_funds`** — reveals the preimage, moving maker's locked sats to the coordinator:
```dart
class SettleOfferFundsAction extends FlowAction {
  String get name => 'settle_offer_funds';
  Future<void> run(flow, ctx) async {
    ctx.write.settledAt = ctx.now;
    await flow._c._paymentBackend!
        .settleInvoice(preimageHex: ctx.offer.holdInvoicePreimage!);
  }
}
```

**`send_payment`** — Lightning payout to the taker (with built-in validation rules):
```dart
class SendPaymentAction extends FlowAction {
  String get name => 'send_payment';
  Future<void> run(flow, ctx) async {
    final netAmountSats = offer.amountSats - takerFees;
    // Resolve invoice from LNURL if only a Lightning address was given.
    // Validate the invoice amount matches netAmountSats.
    final res = await c._attemptTakerPayment(invoice, netAmountSats, feeLimitSat);
    if (!res.ok) throw FlowTransitionFailure(res.error ?? 'Payment failed');
    ctx.write.takerPaidAt = ctx.now;
  }
  // Wiring validation — enforced at startup:
  List<String> validate(engine, state, edge) {
    if (edge.trigger != FlowTriggerType.auto)
      return ['send_payment must run on an auto transition'];
    if (edge.onFailTarget == null)
      return ['send_payment transition must declare on_fail'];
    return const [];
  }
}
```

**`refund_maker`** — coordinator pays a maker-provided invoice out of the settled funds:
```dart
class RefundMakerAction extends FlowAction {
  String get name => 'refund_maker';
  Future<void> run(flow, ctx) async {
    final refundSats = offer.amountSats + offer.makerFees;
    final res = await flow._c._attemptTakerPayment(invoice, refundSats, feeLimit);
    if (!res.ok) throw FlowTransitionFailure(res.error ?? 'Dispute refund payment failed');
  }
}
```

If a yml references an action not in `allFlowActions`, **flow validation aborts coordinator startup** — no silent breakage.

### 6.5 Legacy Enum Flow  (`coordinator_flow_legacy.dart`)

The pre-generic-engine hardcoded BLIK state machine. Still deployed for BLIK + MB WAY. Mirrors the same RPC set but with hardcoded `switch (method)` and six separate timer maps. Documented as deletable: "delete `coordinator_flow_legacy.dart`, remove its `part` directive and the construction branch in `CoordinatorService.flow`."

Engine selection per payment system (`payment_system.dart`):

| Method | `flowEngineMode` |
|--------|------------------|
| BLIK | `legacyEnum` (but `flowId: 'blik'` exists for shadow/generic mode) |
| MB WAY | `legacyEnum` |
| TWINT | `generic` |

The `FLOW_MODE` env var overrides per-deployment ("dry-run a method on the generic executor").

---

## 7. CLI  (`packages/cli/lib/`)

Single binary per market (`bitblik` / `bitway` / `bittwint`) — the `paymentSystem` arg selects discovery identity, currency, and flow. **Maker-focused** — no taker-reserve commands (those live in the app).

### 7.1 Command Surface  (`cli_app.dart`)

| Command | RPC | Notes |
|---------|-----|-------|
| `coordinators list [--health] [--json]` | — | Discovers `kind 15125` events; `--health` probes each coordinator. |
| `offer create --fiat <amt> --coordinator <npub\|hex> [--code <code>] [--currency ...] [--json]` | `initiate_offer` | Prints the hold invoice to pay. TWINT requires `--code`; BLIK/MB WAY reject it. Guards against duplicate active offers per coordinator. |
| `offer list [--finished] [--json]` *or* `offer list --coordinator <npub\|hex>` | — | Local `OfferStore` (SQLite) by default; queries `kind 38383` events with `--coordinator`. |
| `offer get-blik [--offer <id>] [--coordinator <npub\|hex>] [--no-wait] [--json]` | `get_blik` | **Polls `kind 25197` status updates** until `blikReceived`/`blikSentToMaker`, then fetches the code. `--no-wait` returns exit 2 for polling loops / MCP agents. |
| `offer cancel` | `cancel_offer` | Cancels via coordinator (voids hold invoice). |
| `offer mark-blik-invalid` | `mark_blik_invalid` | After `get-blik`, when the code fails at the terminal. |
| `offer confirm-payment` | `confirm_payment` | Tells the coordinator the fiat arrived; coordinator settles + pays taker. |
| `offer dispute` (alias `open-dispute`) | `open_dispute` / `start_dispute` | Event chosen dynamically from the loaded flow. |
| `offer new-code --code <code>` | `enter_new_twint` | TWINT-only (after code expiry). Hidden for BLIK/MB WAY. |
| `offer sync [--relay <url>]` | `get_offer_details` | Refreshes status of active local offers from each coordinator. |

### 7.2 Flow-Aware CLI  (`flow_cli.dart`)

`MakerFlow` wraps the loaded `FlowEngine` and answers maker-side questions **without naming states** — the same CLI binary supports BLIK, MB WAY, and TWINT because everything keys off `Offer.statusRaw`:

```dart
class MakerFlow {
  static Future<MakerFlow> load() async =>
      MakerFlow(await FlowFileLoader.load(activePaymentSystem.flowId));

  bool makerCan(String state, String event) =>
      engine.resolveUserAction(fromState: state, event: event, actor: FlowActor.maker).allowed;

  Set<String> makerStatesFor(String event) =>
      engine.statesAllowing(event, actor: FlowActor.maker);

  String? get disputeEvent =>         // flow-driven: open_dispute OR start_dispute
      const ['open_dispute', 'start_dispute'].firstWhere(...);
  String? get newCodeEvent => ...;    // enter_new_twint
  bool get supportsGetCode => ...;    // false for TWINT (maker provides code)
}
```

The help text is **derived from the flow** — only maker actions the flow actually offers are shown.

### 7.3 Local Stores

- `SecretsStore` (`~/.config/bitblik/secrets.json`) — Nostr private key + Cashu seed.
- `OfferStore` (SQLite) — local mirror of offers; `statusRaw` round-trips generic-flow states.
- `CoordinatorFileStore` — discovered coordinator records, persisted as JSON.

---

## 8. Key Design Observations

1. **Schema-v2 atomicity model.** A transition is an *attempt*, not a guaranteed write. All `do:` actions populate an in-memory `OfferWriteSpec`; only if all succeed does a single compare-and-set commit. `expectedCurrentStatuses` makes it optimistic-concurrency-safe.

2. **Event name == RPC method == flow event.** The coordinator dispatches incoming wire RPCs directly into the flow engine with no translation layer. Adding a new taker action is purely a YAML edit.

3. **YAML as single source of truth.** Timers, transitions, action lists, and NIP-69 broadcast categories all live in `*.yml`. Flow validation runs at startup and aborts on any inconsistency (unknown action, timeout without `after`, multiple `auto` edges, invalid `nip69`).

4. **Dual status representation.** `OfferStatus` enum (legacy, append-only) coexists with `statusRaw` (verbatim flow state). Generic-flow states with no enum value round-trip as `OfferStatus.unknown` but their raw string drives the engine. `flow_status_map.dart` bridges them lexically.

5. **Atomic settlement via hold invoices.** The coordinator's preimage is the single atomic switch: `settle_invoice` moves maker's sats to the coordinator (then pays taker); `cancel_invoice` refunds the maker automatically. No 2-phase commit needed.

6. **Dispute escalation is time-bounded.** Every conflict state (`invalidBlik`, `expiredSentBlik`, `conflict`) auto-settles the hold invoice (securing funds with the coordinator) and escalates to `dispute` after 1h. The coordinator then rules manually: refund maker or pay taker.

7. **Taker-favourable silence.** If a maker goes silent after the taker reports a charge, the `takerCharged → makerConfirmed` auto-transition (1800s for BLIK, 3600s for MB WAY / TWINT) settles in the taker's favour — defending takers against maker griefing.

8. **Privacy in RPC responses.** `toRpcJson(forTaker: true)` strips maker pubkey, hold invoice, and maker fees — necessary because public offer events already hide the maker.

9. **Non-idempotent payout reconciliation.** NWC's `pay_invoice` can leave the offer marked failed when the wallet actually settled. `_recoverFailedPayouts` runs at startup and reconciles via the wallet's `reconcileOutgoingPayment`.

10. **Market isolation by Nostr identity.** Each country has its own project identity whose NIP-65 yields separate discovery relays + coordinator set, and offers carry a `y` (platform) tag so clients filter to their own market.
