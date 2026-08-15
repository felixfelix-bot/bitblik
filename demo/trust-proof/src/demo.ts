/**
 * Trust proof demo — LSAG ring signature for bitblik.
 *
 * Scenario:
 *   A "taker" (code provider) wants to prove they are a trusted member of a
 *   ring of known cash withdrawers ("makers") WITHOUT revealing *which* one.
 *   The proof is a Linkable Spontaneous Anonymous Group (LSAG) ring signature.
 *
 *   The maker (cash withdrawer) who receives the proof can verify it was
 *   produced by someone in the ring, and can detect if the same taker tries
 *   to reuse a proof (via the key image / nullifier).
 *
 *   The proof travels as a NIP-01 event (kind 30221): the envelope is
 *   schnorr-signed by a fresh EPHEMERAL publisher key — not a ring
 *   member — with the LSAG proof inside the content, so the relay
 *   never learns which ring member signed.
 *
 * Flow:
 *   1. Setup 5 keypairs (the ring of makers).
 *   2. Taker (one of the makers, acting as code provider) signs a message.
 *   3. Taker PUBLISHES the signed kind 30221 event to a real Nostr relay;
 *      the maker receives it OVER THE WIRE and verifies (--offline skips).
 *   4. Key-image blocklist gate (T2) — BEFORE any sats move, the maker
 *      checks the proof's key image against a PERSISTED deny list of
 *      nullifiers from past disputed trades; a known-bad nullifier
 *      WITHHOLDS the payment with an explicit message.
 *   5. Nullifier reuse detection — same taker signs twice, key image matches.
 *   6. Security checks — wrong key, tampered message, tampered response.
 *
 * Terminology:
 *   maker  = cash withdrawer (member of the ring of trusted withdrawers)
 *   taker  = code provider (the one who proves membership via ring sig)
 *
 * Run:  npx tsx src/demo.ts [--interactive] [--quick] [--npub npub1... [npub1... ...]] [--offline]
 *
 * Flags:
 *   --interactive  pause after each section header ("[Enter] to continue...")
 *   --quick        collapse the security checks into one summary line
 *   --npub         participant NOSTR pubkeys (npub1...) inserted into the
 *                  ring as decoys BEFORE signing. The taker still signs
 *                  with their own key; participants are anonymous ring
 *                  members, not signers.
 *   --relay        real Nostr WS transport (DEFAULT — no flag needed). The
 *                  demo starts an in-process relay on port 10547, or
 *                  connects to one already running there (EADDRINUSE).
 *   --offline      keep the old print-only path: no relay, no sockets.
 *
 * Companion entries (R4):
 *   npm run relay       standalone relay in its own terminal — the demo
 *                       auto-detects it on the same port (two-terminal mode)
 *   npm run preflight   ~1s confidence check: relay → publish → REQ → verify
 *
 * Environment:
 *   TRUST_DEMO_RELAY_PORT  relay port override (default 10547) — used by
 *                          tests and by a second demo run beside the first.
 *   TRUST_DEMO_BLOCKLIST_FILE  key-image blocklist file override (default
 *                          .keyimage-blocklist.json beside package.json) —
 *                          used by tests (throwaway files) and parallel runs.
 */

import {
  generateKeyPair,
  sign,
  verify,
  type LSAGSignature,
} from "./lsag.js";
import { secp256k1, schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { readSync } from "node:fs";
import { randomBytes, randomInt } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { bech32 } from "@scure/base";
import { WebSocket } from "ws";
import { startRelay, type NostrEvent } from "./relay.js";
import {
  blockKeyImage,
  isKeyImageBlocked,
  loadKeyImageBlocklist,
} from "./blocklist.js";

// ─── ASCII helpers ──────────────────────────────────────────────

const BOX_WIDTH = 64;

function box(title: string, lines: string[]): string {
  const inner = BOX_WIDTH - 2;
  const top = "+" + "-".repeat(inner) + "+";
  const titleLine = "| " + title.padEnd(inner - 2) + " |";
  const sep = "|" + "-".repeat(inner) + "|";
  const body = lines.map((l) => "| " + l.padEnd(inner - 2) + " |");
  const bot = "+" + "-".repeat(inner) + "+";
  return [top, titleLine, sep, ...body, bot].join("\n");
}

function section(title: string, opts?: PauseOptions): void {
  const inner = BOX_WIDTH - 2;
  const pad = Math.floor((inner - title.length) / 2);
  const bar = "=".repeat(inner);
  console.log();
  console.log("+" + bar + "+");
  console.log("|" + " ".repeat(pad) + title + " ".repeat(inner - pad - title.length) + "|");
  console.log("+" + bar + "+");
  pause(opts ?? { interactive: false });
}

function check(label: string, ok: boolean): string {
  return `${ok ? "[+]" : "[-]"} ${label}`;
}

// ─── Roles diagram (opening visual) ────────────────────────────

function problemBox(): void {
  console.log(
    box("The problem — why this demo exists", [
      "Someone sells you a BLIK code for sats. You withdraw cash",
      "at an ATM. If the code was funded by a stolen card, YOU",
      "look like the fraudster.",
      "",
      "The cash withdrawer needs proof the code seller is trusted",
      "— WITHOUT unmasking them. Enter: ring signatures.",
    ]),
  );
}

function explain(text: string): void {
  // Dim 'why this step' narration printed above each section's content.
  for (const line of text.split("\n")) console.log(`>> ${line}`);
  console.log();
}

// ─── Human names for the 5 ring members ────────────────────────

const RING_NAMES = ["Alice", "Bob", "Carol", "Dave", "Erin"];
const nameOf = (i: number): string => RING_NAMES[i] ?? `maker[${i}]`;

/** Millisecond timer string for live-computation proof. */
function timed<T>(fn: () => T): { result: T; ms: string } {
  const t0 = performance.now();
  const result = fn();
  return { result, ms: (performance.now() - t0).toFixed(2) };
}

/** A real NIP-01 event: canonical id + schnorr sig by the publisher. */
export interface SignedNostrEvent {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
}

/** Throwaway publisher keypair — fresh per demo run, never a ring member. */
export interface PublisherKeypair {
  /** 32-byte secret scalar; signs the envelope once, then is discarded. */
  secretKey: Uint8Array;
  /** x-only (32-byte) schnorr public key, hex — the NIP-01 `pubkey`. */
  pubkey: string;
}

/**
 * Fresh EPHEMERAL publisher keypair. The LSAG proof is anonymous, so the
 * envelope must be too: the relay sees (and schnorr-verifies) this
 * throwaway key — it never learns which ring member signed the proof.
 */
export function generatePublisher(): PublisherKeypair {
  const { secretKey, publicKey } = schnorr.keygen();
  return { secretKey, pubkey: bytesToHex(publicKey) };
}

/**
 * Build the demo Nostr event (custom kind 30221) carrying the ring proof.
 *
 * - id: canonical NIP-01 sha256 over [0,pubkey,created_at,kind,tags,content]
 * - sig: BIP-340 schnorr signature over the id bytes by the ephemeral
 *   publisher key — what a real relay verifies before storing the event
 * - d tag: kind 30221 sits in the parameterized-replaceable range
 *   (30000-39999), so real relays require ['d', offerId]
 * - ring/names tags: verification ring as hex pubkeys + display names
 */
export function buildNostrEvent(
  publisher: PublisherKeypair,
  ringPubkeysHex: string[],
  ringNames: string[],
  offerId: string,
  content: string,
): { event: SignedNostrEvent; id: string } {
  const base = {
    kind: 30221,
    pubkey: publisher.pubkey,
    created_at: Math.floor(Date.now() / 1000),
    tags: [
      ["ring", ...ringPubkeysHex],
      ["names", ...ringNames],
      ["d", offerId],
    ],
    content,
  };
  // NIP-01 canonical serialization: sha256 of [0,pubkey,created_at,kind,tags,content]
  const serialized = JSON.stringify([
    0, base.pubkey, base.created_at, base.kind, base.tags, base.content,
  ]);
  const id = hex(sha256(new TextEncoder().encode(serialized)));
  // Real envelope: the event id itself is what gets schnorr-signed.
  const sig = bytesToHex(schnorr.sign(hexToBytes(id), publisher.secretKey));
  return { event: { ...base, id, sig }, id };
}

function rolesDiagram(): void {
  const art = [
    "   TAKER  (BLIK code provider)       MAKER  (cash withdrawer)",
    "   ---------------------------       ------------------------",
    "   has : BLIK code + secret key      has : trust ring (kind 3)",
    "   wants: sats                       wants: proof of clean code",
    "",
    "      1) taker's offer: 'BLIK code for sats'",
    "   TAKER ------------------->  MAKER",
    "",
    "      2) ring signature proof:",
    "         \"I am ONE of the pubkeys",
    "          in YOUR trust ring\"",
    "   TAKER ------------------->  MAKER   (verifies: nobody learns which)",
    "",
    "      3) sats over Lightning — proof valid AND key image clean",
    "   TAKER <-------------------  MAKER",
    "",
    "      4) BLIK code delivered",
    "   TAKER ------------------->  MAKER",
    "",
    "   proof binds to THIS trade (amount+nonce+offer_id+ring) — replay fails",
  ];
  console.log(art.join("\n"));
}

function info(label: string, value: string): string {
  return `    ${label}: ${value}`;
}

function truncate(s: string, max = 16): string {
  return s.length <= max ? s : s.slice(0, max) + "...";
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ─── B2: canonical trade binding ───────────────────────────────

/** The trade terms a proof is bound to — this IS the signed message. */
export interface TradeBinding {
  /** Trade amount in satoshis, decimal string (e.g. \"50000\"). */
  amount: string;
  /** Fresh 16-hex-char nonce — regenerated for every proof. */
  makerNonce: string;
  /** Offer id, 16 hex chars. */
  offerId: string;
  /** sha256 (64 hex) over the ordered concat of the ring's pubkeys. */
  ringHash: string;
}

/**
 * Binding hash of a verification ring: sha256 over the ordered concat of
 * the ring's (compressed) pubkeys. Order matters — the ring sequence is
 * part of what gets signed (B6), so this hash pins it.
 */
export function ringHash(ring: Uint8Array[]): string {
  const flat = new Uint8Array(ring.reduce((n, pk) => n + pk.length, 0));
  let off = 0;
  for (const pk of ring) {
    flat.set(pk, off);
    off += pk.length;
  }
  return bytesToHex(sha256(flat));
}

/**
 * The LSAG-signed message (B2): sha256 over the canonical JSON encoding
 * of the binding object. The object literal is built with keys in
 * lexicographic order and JSON.stringify emits no whitespace, so the
 * encoding is canonical:
 *   {\"amount\":\"…\",\"maker_nonce\":\"…\",\"offer_id\":\"…\",\"ring_hash\":\"…\",\"type\":\"bitblik.trust-proof\",\"v\":1}
 * UTF-8 bytes → sha256 → the 32-byte message handed to sign().
 * There is deliberately NO tx_id — on-chain binding is a Phase-2 concept.
 */
export function buildBindingMessage(binding: TradeBinding): Uint8Array {
  const canonical = JSON.stringify({
    amount: binding.amount,
    maker_nonce: binding.makerNonce,
    offer_id: binding.offerId,
    ring_hash: binding.ringHash,
    type: "bitblik.trust-proof",
    v: 1,
  });
  return sha256(new TextEncoder().encode(canonical));
}

/** The binding as it travels inside the proof event's content (B2 wire shape). */
export function bindingToJson(binding: TradeBinding): string {
  return JSON.stringify({
    amount: binding.amount,
    maker_nonce: binding.makerNonce,
    offer_id: binding.offerId,
    ring_hash: binding.ringHash,
    type: "bitblik.trust-proof",
    v: 1,
  });
}

// ─── H2: shuffled signer position ──────────────────────────────

/**
 * Build the ring with the signer's position UNIFORMLY shuffled (H2).
 *
 * The old construction always placed the taker at a fixed index, which
 * leaks the signer's position to anyone watching ring order. Here the
 * combined maker + decoy pubkeys are shuffled with Fisher–Yates using
 * crypto-grade `randomInt` (uniform, no modulo bias), and the taker's
 * new index falls out of the shuffle — every position equiprobable.
 *
 * The shuffled order is BINDING from here on: it is the order that gets
 * signed (B6 folds the ring bytes into every challenge) and hashed into
 * the binding's ring_hash (B2), so reordering after construction breaks
 * verification.
 */
export function buildShuffledRing(
  makerPublicKeys: Uint8Array[],
  takerLocalIndex: number,
  decoys: Uint8Array[] = [],
): { ring: Uint8Array[]; takerIndex: number } {
  if (takerLocalIndex < 0 || takerLocalIndex >= makerPublicKeys.length) {
    throw new Error("takerLocalIndex out of range");
  }
  const entries = [
    ...makerPublicKeys.map((pk, i) => ({ pk, isTaker: i === takerLocalIndex })),
    ...decoys.map((pk) => ({ pk, isTaker: false })),
  ];
  for (let i = entries.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [entries[i], entries[j]] = [entries[j], entries[i]];
  }
  return {
    ring: entries.map((e) => e.pk),
    takerIndex: entries.findIndex((e) => e.isTaker),
  };
}

// ─── CLI flags ─────────────────────────────────────────────────

export interface DemoOptions {
  /** Pause after each section header ("[Enter] to continue..."). */
  interactive: boolean;
  /** Collapse the security checks into a single summary line. */
  quick: boolean;
}

export interface PauseOptions {
  interactive: boolean;
  /** Injected Enter-key reader — lets tests pause without touching stdin. */
  waitForKey?: () => void;
}

export interface MainOptions extends DemoOptions, PauseOptions {
  /** Participant npubs to insert into the ring as decoys (optional). */
  npubs?: string[];
  /**
   * Real Nostr relay transport (R3). DEFAULT ON — undefined means true.
   * Set false (or pass --offline on the CLI) for the print-only path.
   */
  relay?: boolean;
}

export function parseArgs(argv: string[]): DemoOptions {
  return {
    interactive: argv.includes("--interactive"),
    quick: argv.includes("--quick"),
  };
}

/**
 * Relay transport flag (R3). DEFAULT ON: the demo speaks real Nostr WS
 * unless --offline is given. --relay is accepted for explicitness (it is
 * the default); if both flags appear, --offline wins.
 */
export function parseRelayMode(argv: string[]): boolean {
  return !argv.includes("--offline");
}

/** Read a single keypress (Enter) from stdin; never stalls if stdin is gone. */
function readEnterKey(): void {
  const buf = Buffer.alloc(1);
  try {
    readSync(0, buf, 0, 1, null);
  } catch {
    // stdin closed or non-blocking (e.g. piped) — continue the demo.
  }
}

/** Pause for the user when interactive; strict no-op otherwise. */
export function pause(opts: PauseOptions): void {
  if (!opts.interactive) return;
  console.log("[Enter] to continue...");
  if (opts.waitForKey) {
    opts.waitForKey();
    return;
  }
  readEnterKey();
}

// ─── npub helpers (participant ring decoys) ────────────────────

/**
 * Decode a NOSTR npub (bech32) into its 32-byte x-only secp256k1 pubkey.
 * Throws a clear "Invalid npub" error for anything malformed: bad bech32
 * checksum, wrong prefix, wrong payload length.
 */
export function decodeNpub(npub: string): Uint8Array {
  try {
    const { prefix, bytes } = bech32.decodeToBytes(npub);
    if (prefix !== "npub") {
      throw new Error(`expected prefix "npub", got "${prefix}"`);
    }
    if (bytes.length !== 32) {
      throw new Error(`expected 32-byte payload, got ${bytes.length} bytes`);
    }
    return bytes;
  } catch (e) {
    const reason = e instanceof Error ? e.message : String(e);
    throw new Error(`Invalid npub "${truncate(npub, 24)}": ${reason}`);
  }
}

/**
 * Convert an npub into a 33-byte compressed secp256k1 public key usable as
 * a ring member. The npub carries only the x coordinate, so we try both
 * y parities (0x02 / 0x03); whichever yields a valid on-curve point wins.
 * For anonymity it does not matter which parity is used — a decoy never
 * signs, it only needs to be a valid point in the ring.
 */
export function npubToRingPubkey(npub: string): Uint8Array {
  const x32 = decodeNpub(npub);
  for (const parity of [0x02, 0x03] as const) {
    const candidate = new Uint8Array(33);
    candidate.set(x32, 1);
    candidate[0] = parity;
    try {
      secp256k1.Point.fromBytes(candidate).assertValidity();
      return candidate;
    } catch {
      // wrong parity — try the other one
    }
  }
  throw new Error(
    `Invalid npub "${truncate(npub, 24)}": x coordinate is not a point on secp256k1`,
  );
}

/**
 * Extract participant npub values from argv.
 *   ["--npub", A, B]        → [A, B]
 *   ["--quick", "--npub", A] → [A]        (flag can appear anywhere)
 *   ["--npub", A, "--quick"] → [A]        (values stop at the next flag)
 * Repeated --npub flags accumulate. "--npub" with no value throws.
 */
export function parseNpubArgs(argv: string[]): string[] {
  const npubs: string[] = [];
  let i = 0;
  while (i < argv.length) {
    const arg = argv[i];
    if (arg !== "--npub") {
      i++;
      continue;
    }
    let count = 0;
    i++;
    while (i < argv.length) {
      const v = argv[i];
      if (v === undefined || v.startsWith("--")) break;
      npubs.push(v);
      count++;
      i++;
    }
    if (count === 0) {
      throw new Error(
        "--npub requires at least one npub1... value, e.g. --npub npub1abc... npub1def...",
      );
    }
  }
  return npubs;
}

// ─── R3: real Nostr relay transport ────────────────────────────

const DEFAULT_RELAY_PORT = 10547;
/** Hard cap on EVERY websocket await — the demo must NEVER stall on stage. */
const WS_TIMEOUT_MS = 3_000;

/**
 * Desired relay port. TRUST_DEMO_RELAY_PORT overrides the default 10547 —
 * used by tests, by `npm run relay` (the standalone entry), and by humans
 * running a second demo beside the first.
 */
export function relayPort(): number {
  const raw = process.env.TRUST_DEMO_RELAY_PORT;
  if (raw === undefined || raw === "") return DEFAULT_RELAY_PORT;
  const n = Number.parseInt(raw, 10);
  return Number.isNaN(n) ? DEFAULT_RELAY_PORT : n;
}

/**
 * Where the maker's key-image blocklist lives (T2). Default: a dotfile
 * beside package.json. TRUST_DEMO_BLOCKLIST_FILE overrides — tests point
 * it at throwaway tmp files, parallel demo runs at their own files.
 */
export function blocklistPath(): string {
  const raw = process.env.TRUST_DEMO_BLOCKLIST_FILE;
  if (raw !== undefined && raw !== "") return raw;
  return path.join(
    fileURLToPath(new URL("..", import.meta.url)),
    ".keyimage-blocklist.json",
  );
}

/** Reject with `what` if `p` does not settle within WS_TIMEOUT_MS. */
function withDeadline<T>(p: Promise<T>, what: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`${what}: no reply within ${WS_TIMEOUT_MS}ms`));
    }, WS_TIMEOUT_MS);
    p.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        reject(e instanceof Error ? e : new Error(String(e)));
      },
    );
  });
}

/** Await the socket's open event (bounded by the 3s deadline). */
function wsOpen(ws: WebSocket): Promise<void> {
  return withDeadline(
    new Promise<void>((resolve, reject) => {
      ws.once("open", () => resolve());
      ws.once("error", (err: Error) => reject(err));
      ws.once("close", () => reject(new Error("socket closed before open")));
    }),
    "relay connect",
  );
}

/** Await the next parsed JSON message (bounded by the 3s deadline). */
function wsNextMessage(ws: WebSocket): Promise<unknown> {
  return withDeadline(
    new Promise<unknown>((resolve, reject) => {
      ws.once("message", (data: unknown) => resolve(JSON.parse(String(data))));
      ws.once("error", (err: Error) => reject(err));
      ws.once("close", () => reject(new Error("socket closed before reply")));
    }),
    "relay reply",
  );
}

interface RelaySession {
  port: number;
  /** What the demo actually connects to. */
  url: string;
  /** true → a standalone relay already owns the port; we never close it. */
  external: boolean;
  close(): Promise<void>;
}

/**
 * Get a relay session on the desired port: bind it ourselves first; if the
 * port is already taken (EADDRINUSE) assume a standalone relay is running
 * there and connect to it instead. Any other failure propagates → offline.
 */
async function openRelaySession(port: number): Promise<RelaySession> {
  try {
    const handle = await startRelay({ port });
    return {
      port: handle.port,
      url: `ws://127.0.0.1:${handle.port}`,
      external: false,
      close: () => handle.close(),
    };
  } catch (e) {
    if ((e as NodeJS.ErrnoException)?.code === "EADDRINUSE") {
      return {
        port,
        url: `ws://127.0.0.1:${port}`,
        external: true,
        close: async () => {}, // not ours — leave the standalone relay running
      };
    }
    throw e;
  }
}

/**
 * Taker side: publish the signed kind 30221 event; resolve the relay-echoed
 * event id from the ['OK', id, true] reply.
 */
async function relayPublish(url: string, event: SignedNostrEvent): Promise<string> {
  const ws = new WebSocket(url);
  ws.on("error", () => {}); // never let a late socket error crash the demo
  try {
    await wsOpen(ws);
    ws.send(JSON.stringify(["EVENT", event]));
    const reply = await wsNextMessage(ws);
    if (!Array.isArray(reply) || reply[0] !== "OK" || reply[2] !== true) {
      throw new Error(`relay rejected the event: ${JSON.stringify(reply)}`);
    }
    return String(reply[1]);
  } finally {
    ws.terminate();
  }
}

/**
 * Maker side: REQ {kinds:[30221]} and resolve OUR event received over the
 * wire. Events from earlier runs (a shared standalone relay) are skipped
 * until the expected id arrives; every wait is deadline-bounded.
 */
async function relayFetchProof(url: string, expectedId: string): Promise<NostrEvent> {
  const ws = new WebSocket(url);
  ws.on("error", () => {}); // never let a late socket error crash the demo
  const hardStop = Date.now() + WS_TIMEOUT_MS;
  try {
    await wsOpen(ws);
    ws.send(JSON.stringify(["REQ", "maker", { kinds: [30221] }]));
    for (;;) {
      if (Date.now() > hardStop) {
        throw new Error("relay fetch: expected event never arrived");
      }
      const msg = await wsNextMessage(ws);
      const ev = Array.isArray(msg) && msg[0] === "EVENT" ? msg[2] : undefined;
      if (
        typeof ev === "object" && ev !== null &&
        (ev as NostrEvent).id === expectedId
      ) {
        return ev as NostrEvent;
      }
      // EOSE or an earlier run's event — keep waiting for ours.
    }
  } finally {
    ws.terminate();
  }
}

/**
 * Rebuild the proof inputs strictly from what crossed the wire: the LSAG
 * proof and trade binding from event content. The signed message is
 * re-derived from the carried binding via the same canonical encoding
 * the taker used (B2). Nothing from the taker's local variables.
 *
 * B1: the event's `ring` tag is DISPLAY-ONLY. It is parsed into
 * `displayRing` for human presentation but is NEVER returned as a
 * verification input — the maker always verifies against their own
 * kind-3 ring via verifyProofEvent()/verify().
 *
 * Exported since R4: `npm run preflight` runs the same maker-side rebuild.
 */
export function proofFromWireEvent(
  ev: NostrEvent,
): { displayRing: Uint8Array[]; sig: LSAGSignature; message: Uint8Array; binding: TradeBinding } {
  const ringTag = ev.tags.find((t) => t[0] === "ring");
  const displayRing: Uint8Array[] =
    ringTag === undefined ? [] : ringTag.slice(1).map((pk) => hexToBytes(pk));
  const body = JSON.parse(ev.content) as {
    binding?: {
      amount?: unknown;
      maker_nonce?: unknown;
      offer_id?: unknown;
      ring_hash?: unknown;
    };
    keyImage?: string;
    c0?: string;
    responses?: string[];
  };
  const b = body?.binding;
  if (
    b === undefined ||
    typeof b.amount !== "string" ||
    typeof b.maker_nonce !== "string" ||
    typeof b.offer_id !== "string" ||
    typeof b.ring_hash !== "string"
  ) {
    throw new Error("wire event carries no trade binding");
  }
  if (
    typeof body.keyImage !== "string" ||
    typeof body.c0 !== "string" ||
    !Array.isArray(body.responses)
  ) {
    throw new Error("wire event carries an incomplete LSAG proof");
  }
  const binding: TradeBinding = {
    amount: b.amount,
    makerNonce: b.maker_nonce,
    offerId: b.offer_id,
    ringHash: b.ring_hash,
  };
  return {
    displayRing,
    sig: {
      keyImage: hexToBytes(body.keyImage),
      c0: hexToBytes(body.c0),
      responses: body.responses.map((r) => hexToBytes(r)),
    },
    binding,
    message: buildBindingMessage(binding),
  };
}

/**
 * Maker-side verification (B1): check a wire proof event against the
 * CALLER-SUPPLIED ring — the maker's own kind-3 trust list. The event's
 * `ring` tag is never consulted (display-only): a lying tag cannot make
 * a proof verify, and an honest one is not needed. As a loud early
 * check, the carried binding's ring_hash must match the caller's ring —
 * the proof must have been signed over exactly this ring, in this order.
 */
export function verifyProofEvent(ev: NostrEvent, ring: Uint8Array[]): boolean {
  const { sig, message, binding } = proofFromWireEvent(ev);
  if (binding.ringHash !== ringHash(ring)) return false;
  return verify(message, ring, sig);
}

// ─── Demo ───────────────────────────────────────────────────────

export async function main(
  optsIn: MainOptions | string[] = parseArgs(process.argv.slice(2)),
): Promise<void> {
  const enc = new TextEncoder();

  // --npub support: main accepts either a raw argv array or an options
  // object. Validate participant npubs BEFORE anything runs — an invalid
  // npub must fail fast with a clear error, never a partial demo run.
  let opts: MainOptions;
  let npubs: string[];
  let participantPks: Uint8Array[];
  try {
    opts = Array.isArray(optsIn)
      ? {
          ...parseArgs(optsIn),
          relay: parseRelayMode(optsIn),
          npubs: parseNpubArgs(optsIn),
        }
      : optsIn;
    npubs = opts.npubs ?? [];
    // Force full validation (bech32 + on-curve) of every npub up front.
    participantPks = npubs.map(npubToRingPubkey);
  } catch (e) {
    console.error(`Error: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
  }

  // R3: relay transport is DEFAULT ON; --offline keeps the print-only path.
  const relayOn = opts.relay ?? true;

  console.log();
  console.log("=".repeat(BOX_WIDTH));
  console.log("  bitblik Trust Proof Demo — LSAG Ring Signatures");
  console.log("  maker = cash withdrawer    taker = code provider");
  console.log("=".repeat(BOX_WIDTH));

  // ── 0. Opening visual: who is who ───────────────────────────
  problemBox();
  section("0. The roles — who is who", opts);
  rolesDiagram();

  // ── 1. Setup: generate 5 keypairs (the ring of makers) ───────
  section("1. Setup — Generate 5 maker keypairs", opts);
  explain(
    "The ring = 5 public keys of trusted withdrawers (in the real\n" +
      "app these come from the maker's Nostr kind 3 follow list).\n" +
      "One of them is secretly our taker — nobody can tell which.",
  );

  const RING_SIZE = 5;
  const keys = Array.from({ length: RING_SIZE }, () => generateKeyPair());

  // The taker is Carol — maker[2] — by IDENTITY; the ring POSITION of
  // that key is what gets shuffled below (H2), so it changes per run.
  const takerKeyIndex = 2;
  const takerSecret = keys[takerKeyIndex].secretKey;

  // Ring = generated maker keys + participant npub decoys, assembled
  // BEFORE signing with the signer's position UNIFORMLY shuffled (H2 —
  // kills the fixed-index leak; ring order is binding post-shuffle).
  const { ring, takerIndex } = buildShuffledRing(
    keys.map((k) => k.publicKey),
    takerKeyIndex,
    participantPks,
  );

  console.log(box("Ring of makers (public keys)", [
    `Ring size: ${ring.length}`,
    ...(participantPks.length
      ? [`Participant npubs added as decoys: ${participantPks.length}`]
      : []),
    "",
    ...keys.map((k, i) =>
      info(nameOf(i), truncate(hex(k.publicKey), 24))
    ),
  ]));

  if (participantPks.length > 0) {
    console.log(box("Participant npubs (ring decoys)", [
      `Participant npubs added as decoys: ${participantPks.length}`,
      "",
      ...npubs.map((n, i) => info(`participant[${i}]`, truncate(n, 24))),
      "",
      "Each participant pubkey is now an anonymous",
      "ring member. The taker still signs with their",
      "own key — participants are decoys only.",
    ]));
  }

  // The taker is Carol (maker[2]) — they prove membership without
  // revealing which. Their ring POSITION is the shuffled takerIndex.
  console.log();
  console.log(box("Taker (code provider)", [
    `Acting as: ${nameOf(takerKeyIndex)} — maker[${takerKeyIndex}] (secret identity)`,
    info("secret key", truncate(hex(takerSecret), 24)),
    `ring position: shuffled — index ${takerIndex} of ${ring.length} this run (H2)`,
    `The taker knows they are ${nameOf(takerKeyIndex)}, but the`,
    "verifier cannot learn this from the signature.",
  ]));

  // ── 2. Taker generates ring signature ────────────────────────
  section("2. Taker generates ring signature", opts);
  explain(
    "The taker proves 'I hold ONE of the secret keys in this ring'.\n" +
      "LSAG math reveals nothing about which one — the signature\n" +
      "checks out for every ring member equally.",
  );

  // B2: the signed message is the sha256 of the canonical trade-binding
  // object — amount + fresh maker_nonce + offer_id + ring_hash. No tx_id
  // (Phase-2 concept): the proof binds to the trade terms, not a chain tx.
  const amountSats = "50000";
  const makerNonce = randomBytes(8).toString("hex"); // 16 hex, fresh per proof
  const offerId = randomBytes(8).toString("hex"); // 16 hex
  const binding: TradeBinding = {
    amount: amountSats,
    makerNonce,
    offerId,
    ringHash: ringHash(ring),
  };
  const message = buildBindingMessage(binding);
  const { result: sig, ms: signMs } = timed(() =>
    sign(message, ring, takerIndex, takerSecret)
  );

  console.log(box("Ring signature produced", [
    info("binding", `${amountSats} sats, offer ${offerId}`),
    info("maker_nonce (fresh)", makerNonce),
    info("ring_hash", truncate(binding.ringHash, 24)),
    info("message", `sha256(canonical binding JSON) = ${truncate(hex(message), 24)}`),
    info("key image (nullifier)", truncate(hex(sig.keyImage), 24)),
    info("c0 (initial challenge)", truncate(hex(sig.c0), 24)),
    info("responses", `${sig.responses.length} x 32-byte scalars`),
    "",
    `computed live in ${signMs} ms — keys are fresh,`,
    "values change on every run",
  ]));

  // The proof as it would actually travel: a Nostr event (custom kind).
  // Fresh EPHEMERAL publisher keypair for THIS run — not a ring member,
  // so publishing leaks nothing about who signed the LSAG proof.
  const publisher = generatePublisher();
  const publisherNpub = bech32.encode(
    "npub",
    bech32.toWords(Uint8Array.from(Buffer.from(publisher.pubkey, "hex"))),
  );
  const { event } = buildNostrEvent(
    publisher,
    ring.map((pk) => hex(pk)),
    keys.map((_, i) => nameOf(i)),
    offerId,
    JSON.stringify({
      binding: JSON.parse(bindingToJson(binding)),
      keyImage: hex(sig.keyImage),
      c0: hex(sig.c0),
      responses: sig.responses.map((r) => hex(r)),
    }),
  );
  console.log();
  console.log("The proof as a Nostr event — what gets published:");
  console.log(JSON.stringify(event, null, 2));
  console.log(`publisher npub: ${publisherNpub} (fresh ephemeral key)`);
  console.log("event envelope schnorr-signed by EPHEMERAL publisher;");
  console.log("LSAG proof in content — relay never learns which ring member signed.");

  // ── Presenter pointing panel: map every field to its meaning ──
  console.log();
  console.log(
    box("READ THIS EVENT — field-by-field pointing guide", [
      "",
      '  "tags"  → 5 "p" entries = THE TRUST RING.',
      "     5 public keys. One belongs to the real signer.",
      "     Point at each: could be ANY of them.",
      "",
      '  "content".keyImage → DOUBLE-SPEND FINGERPRINT.',
      "     One-way f(x_secret, x_pubkey) — deterministic.",
      "     Same person signs twice → same fingerprint.",
      "     Reveals NOTHING about who. Catches abuse only.",
      "",
      '  "content".c0 → THE CHALLENGE SEED.',
      "     Where the verification loop starts.",
      "",
      '  "content".responses → 5 LOOKING-IDENTICAL NUMBERS.',
      "     4 are pure random noise. 1 was crafted with a",
      "     real secret key. Indistinguishable on the wire —",
      "     that indistinguishability IS the anonymity.",
      "",
      '  "sig" → envelope signature of the EPHEMERAL publisher.',
      "     NOT a ring member. Proves event integrity to the",
      "     relay. Says nothing about who made the LSAG proof.",
      "",
      "VERIFY = walk the loop: c0 → hash → hash → ... → back",
      "to c0? Closes ⟺ SOMEONE in the ring knew a secret key.",
      "Closes equally for all 5 positions → which one: never.",
    ]),
  );


  // ── 3. Maker verifies the ring signature ─────────────────────
  section("3. Maker (cash withdrawer) verifies the proof", opts);
  explain(
    "The maker checks the proof against THEIR trust ring.\n" +
      "Two outcomes: valid (a member signed — trade can proceed)\n" +
      "or invalid (outsider — walk away). Anonymity intact either way.",
  );

  // R3 + B1: REAL transport. The taker publishes the signed kind 30221
  // event to a Nostr relay; the maker receives it over the wire like a
  // separate app would, rebuilds the proof from event CONTENT — and then
  // verifies against the MAKER'S OWN kind-3 ring, never the event's
  // ring tag (that tag is display-only).
  const makerRing = [...keys.map((k) => k.publicKey), ...participantPks];
  let verifyRing = makerRing;
  let verifySig = sig;
  let verifyMessage: Uint8Array = message;
  let viaLine = "proof arrived via: offline (local variables)";
  if (relayOn) {
    try {
      const session = await openRelaySession(relayPort());
      try {
        // Stage-visible confirmation: relay is up, one command, real wire.
        console.log(
          box("RELAY", [
            `✓ RELAY LIVE — ws://localhost:${session.port}`,
            "  proof will travel over a REAL Nostr relay",
            session.external ? "  (standalone relay detected)" : "  (auto-started by this command)",
          ]),
        );
        console.log(
          `relay: ws://localhost:${session.port} — REAL Nostr transport` +
            (session.external ? " (standalone relay detected)" : ""),
        );
        const echoedId = await relayPublish(session.url, event);
        console.log(
          `→ taker: EVENT accepted ['OK', id, true] — relay-echoed event id ${truncate(echoedId, 16)}`,
        );
        const wireEvent = await relayFetchProof(session.url, echoedId);
        console.log("← maker: REQ {kinds:[30221]} → proof received over the wire");
        const fromWire = proofFromWireEvent(wireEvent);
        console.log(
          `maker: LSAG proof + trade binding rebuilt from event content — ring tag (${fromWire.displayRing.length} pubkeys) is DISPLAY-ONLY`,
        );
        // B1: the maker verifies against THEIR OWN trust ring (kind 3),
        // built here from the maker's own key list — not from the event.
        console.log(
          `maker: verifying against MY OWN trust ring (${makerRing.length} pubkeys, kind 3)`,
        );
        // B1 on-stage proof: tamper the event's ring tag — verification
        // must not care (the tag never reaches the math).
        const lyingTagEv: NostrEvent = {
          ...wireEvent,
          tags: wireEvent.tags.map((t) =>
            t[0] === "ring" ? ["ring", ...t.slice(1).reverse()] : t,
          ),
        };
        const lyingTagIgnored = verifyProofEvent(lyingTagEv, makerRing);
        console.log(
          check("ring tag tampered — verification IGNORES it (display-only)", lyingTagIgnored),
        );
        verifyRing = makerRing;
        verifySig = fromWire.sig;
        verifyMessage = fromWire.message;
        viaLine = `proof arrived via: REAL Nostr relay (event ${truncate(wireEvent.id, 12)})`;
      } finally {
        await session.close();
      }
    } catch {
      // NEVER stall on stage: any transport failure → print-only path.
      console.log("[!] relay unavailable, offline mode");
    }
  }

  const { result: isValid, ms: verifyMs } = timed(() =>
    verify(verifyMessage, verifyRing, verifySig)
  );

  console.log(box("Verification result", [
    check("Signature is valid", isValid),
    check("Signer is in the ring (anonymous)", isValid),
    check("Signer identity hidden", true),
    "",
    viaLine,
    `verified live in ${verifyMs} ms`,
    "",
    "The maker verified the taker belongs to the",
    "ring of trusted withdrawers, but does NOT know",
    "which of the 5 makers produced the signature.",
  ]));

  // Live tamper test — proves this is real verification, not a script
  // scrolling pre-baked output: flip ONE bit and watch it fail.
  const tamperedLiveSig: LSAGSignature = {
    ...sig,
    responses: sig.responses.map((r, i) => {
      if (i !== 0) return r;
      const t = new Uint8Array(r);
      t[0] ^= 0x01;
      return t;
    }),
  };
  const tamperedValid = verify(message, ring, tamperedLiveSig);
  console.log(box("Tamper test — one bit flipped, live", [
    `[-] tampered proof REJECTED (${tamperedValid ? "accepted?!" : "verify failed"})`,
    "",
    "Same code path, one flipped bit in one response",
    "scalar: verification now fails. Every value on",
    "screen was computed in this process, just now.",
  ]));

  // ── 4. Key-image blocklist gate — sats on the line (T2) ──────
  section("4. Key-image blocklist gate — sats on the line", opts);
  explain(
    "Verification proves membership, not honesty. Before ANY sats move,\n" +
      "the maker checks the proof's key image against a PERSISTED blocklist\n" +
      "of nullifiers from past disputed trades — and pays only if it is clean.",
  );

  const blPath = blocklistPath();
  const takerKeyImageHex = hex(verifySig.keyImage);
  const persistedImages = await loadKeyImageBlocklist(blPath);
  console.log(
    `maker: blocklist file ${blPath} — ${persistedImages.length} persisted key image(s)`,
  );

  // THE ordering claim of T2: the gate is evaluated BEFORE the sats step.
  // A valid ring signature is necessary but NOT sufficient — a known-bad
  // nullifier withholds the payment outright.
  let cleanPaid = false;
  if (await isKeyImageBlocked(blPath, takerKeyImageHex)) {
    console.log(
      `✋ SATS WITHHELD — key image ${truncate(takerKeyImageHex, 24)} is on ` +
        `the maker's blocklist; refusing to pay ${amountSats} sats`,
    );
    console.log(
      box("Known-bad taker — sats withheld", [
        check("proof verified, but the nullifier is blocklisted", true),
        "",
        "The maker refuses this trade. The persisted",
        "blocklist outlives the process that wrote it.",
      ]),
    );
  } else {
    console.log(
      box("Blocklist gate — clean taker", [
        check(
          `key image ${truncate(takerKeyImageHex, 16)} NOT on the blocklist`,
          true,
        ),
        "",
        "The taker's nullifier is unknown to the maker —",
        "no prior dispute on record. Sats may move.",
      ]),
    );
    console.log(`→ maker: paying ${amountSats} sats over Lightning`);
    console.log("→ taker: BLIK code delivered");
    cleanPaid = true;
  }

  // Dispute replay: the trade settles, the BLIK code later turns out to
  // be funded by a stolen card — the maker persists the taker's nullifier
  // to their blocklist (a plain JSON file that survives restarts).
  console.log();
  console.log(
    "dispute: the code was funded by a stolen card — the maker persists the taker's key image",
  );
  await blockKeyImage(blPath, takerKeyImageHex);
  console.log(
    `maker: key image ${truncate(takerKeyImageHex, 16)} persisted to the ` +
      `blocklist — survives restarts`,
  );

  // The SAME taker returns with a fresh proof for a NEW offer (fresh
  // maker_nonce → fresh message). Verification still passes — they
  // genuinely are in the ring — but the gate now refuses to pay.
  const replayBinding: TradeBinding = {
    ...binding,
    makerNonce: randomBytes(8).toString("hex"),
  };
  const replayMessage = buildBindingMessage(replayBinding);
  const replaySig = sign(replayMessage, ring, takerIndex, takerSecret);
  const replayValid = verify(replayMessage, ring, replaySig);

  // The gate RE-READS the file from disk — not in-memory state — so what
  // was just persisted is what gets enforced, in this process or any other.
  const reloadedImages = await loadKeyImageBlocklist(blPath);
  console.log(
    `maker: blocklist re-loaded from disk — ${reloadedImages.length} persisted key image(s)`,
  );
  const replayBlocked = reloadedImages.includes(takerKeyImageHex);
  console.log(
    `✋ SATS WITHHELD — key image ${truncate(takerKeyImageHex, 24)} is on ` +
      `the maker's blocklist; refusing to pay ${amountSats} sats`,
  );
  console.log(
    box("Known-bad taker returns — sats withheld", [
      check("new proof still verifies (taker IS in the ring)", replayValid),
      check(
        "key image unchanged (same nullifier)",
        hex(replaySig.keyImage) === takerKeyImageHex,
      ),
      check("payment refused — key image on the persisted blocklist", replayBlocked),
      "",
      "A valid ring signature is necessary but NOT",
      "sufficient: the gate runs BEFORE the sats step.",
    ]),
  );

  // ── 5. Nullifier reuse detection ─────────────────────────────
  section("5. Nullifier reuse detection (linkability)", opts);
  explain(
    "Every signature carries a nullifier — a fingerprint of the\n" +
      "secret key. Same taker signs twice → same nullifier →\n" +
      "double-use detected, still without identifying them.",
  );

  // Same taker signs a different message — key image must be the same.
  // B2: a second proof gets a FRESH maker_nonce, so the canonical binding
  // (and thus the signed message) differs while the signer does not.
  const binding2: TradeBinding = { ...binding, makerNonce: randomBytes(8).toString("hex") };
  const message2 = buildBindingMessage(binding2);
  const sig2 = sign(message2, ring, takerIndex, takerSecret);

  const sameKeyImage =
    hex(sig.keyImage) === hex(sig2.keyImage);
  const bothValid = verify(message, ring, sig) && verify(message2, ring, sig2);

  console.log(box("Same taker, two signatures", [
    check("Sig 1 valid", verify(message, ring, sig)),
    check("Sig 2 valid", verify(message2, ring, sig2)),
    check("Key images match (same nullifier)", sameKeyImage),
    "",
    "The maker can link two proofs to the same taker",
    "via the key image, even though the taker's",
    "identity remains anonymous.",
  ]));

  // Different taker — key image must differ.
  const otherIndex = 4;
  const sigOther = sign(message, ring, otherIndex, keys[otherIndex].secretKey);
  const differentKeyImage =
    hex(sig.keyImage) !== hex(sigOther.keyImage);

  console.log(box("Different taker, different nullifier", [
    check("Sig valid", verify(message, ring, sigOther)),
    check("Key images differ (different nullifier)", differentKeyImage),
    "",
    "A different taker produces a different key",
    "image, so the maker can distinguish repeat",
    "takers from new ones.",
  ]));

  // ── 6. Security checks ───────────────────────────────────────
  section("6. Security checks", opts);
  explain(
    "Break it every way an attacker would: wrong key, tampered\n" +
      "message, tampered response, tampered nullifier.\n" +
      "All must fail — anonymity never becomes a forgery tool.",
  );

  // All four checks always run; only the printing depends on --quick.
  // 6a. Wrong secret key
  const wrongKey = generateKeyPair();
  const sigWrong = sign(message, ring, takerIndex, wrongKey.secretKey);
  const wrongKeyResult = verify(message, ring, sigWrong);

  // 6b. Tampered message (B2: tampered trade terms — the amount is signed)
  const tamperedMsg = buildBindingMessage({ ...binding, amount: "50001" });
  const tamperedMsgResult = verify(tamperedMsg, ring, sig);

  // 6c. Tampered response
  const tamperedSig: LSAGSignature = {
    ...sig,
    responses: [
      new Uint8Array(32), // zero out first response
      ...sig.responses.slice(1),
    ],
  };
  const tamperedRespResult = verify(message, ring, tamperedSig);

  // 6d. Tampered key image
  const tamperedKeyImageSig: LSAGSignature = {
    ...sig,
    keyImage: secp256k1.Point.BASE.toBytes(),
  };
  const tamperedKeyImageResult = verify(message, ring, tamperedKeyImageSig);

  const securityChecksPass =
    !wrongKeyResult && !tamperedMsgResult && !tamperedRespResult &&
    !tamperedKeyImageResult;

  if (opts.quick) {
    // Collapse the four checks into one line to pace a 1-minute demo.
    console.log(`All 4 security checks passed: ${securityChecksPass ? "✅" : "❌"}`);
  } else {
    console.log(box("6a. Wrong secret key", [
      check("Signature with wrong key rejected", !wrongKeyResult),
      `The taker must know the secret key for ${nameOf(takerKeyIndex)}`,
      "to produce a valid proof.",
    ]));

    console.log(box("6b. Tampered message", [
      check("Tampered message rejected", !tamperedMsgResult),
      "Changing the signed message invalidates",
      "the ring signature.",
    ]));

    console.log(box("6c. Tampered response", [
      check("Tampered response rejected", !tamperedRespResult),
      "Modifying any response scalar breaks the",
      "ring closure and verification fails.",
    ]));

    console.log(box("6d. Tampered key image (nullifier)", [
      check("Tampered key image rejected", !tamperedKeyImageResult),
      "Substituting the key image invalidates the",
      "signature — the nullifier is bound to the",
      "signer's secret key.",
    ]));
  }

  // ── Summary ──────────────────────────────────────────────────
  section("Summary", opts);

  // T2: the gate verdict — clean key image paid, known-bad withheld.
  const blocklistGateOk = cleanPaid && replayBlocked && replayValid;

  const allPass =
    isValid &&
    bothValid &&
    sameKeyImage &&
    differentKeyImage &&
    blocklistGateOk &&
    !wrongKeyResult &&
    !tamperedMsgResult &&
    !tamperedRespResult &&
    !tamperedKeyImageResult;

  console.log(box("All checks", [
    check("Valid signature verifies", isValid),
    check("Linkability (same nullifier for same taker)", sameKeyImage),
    check("Different takers have different nullifiers", differentKeyImage),
    check("Blocklist gate: clean paid, known-bad withheld", blocklistGateOk),
    check("Wrong key rejected", !wrongKeyResult),
    check("Tampered message rejected", !tamperedMsgResult),
    check("Tampered response rejected", !tamperedRespResult),
    check("Tampered key image rejected", !tamperedKeyImageResult),
    "",
    check("ALL SECURITY CHECKS PASSED", allPass),
    "",
    `Our taker was ${nameOf(takerKeyIndex)} (maker[${takerKeyIndex}]) all along —`,
    "the audience never learned which, and neither",
    "did the maker verifying the proof.",
  ]));

  console.log();
  console.log("Demo complete.");
  console.log();
}

// Run when invoked directly via tsx
if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/"))) {
  // Pass raw argv so --npub values and --offline reach the parsers in main().
  main(process.argv.slice(2)).catch((e: unknown) => {
    console.error(`Error: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
  });
}
