/**
 * Preflight smoke test — the presenter's one-line confidence check.
 *
 * Exercises the FULL demo stack in a fraction of a second:
 *
 *   LSAG sign → NIP-01 envelope (ephemeral publisher, schnorr sig)
 *     → start relay → publish over WS → REQ back over WS
 *     → verify: id recompute + schnorr envelope + LSAG proof from the wire
 *
 * The relay binds an EPHEMERAL port, so preflight never collides with a
 * standalone `npm run relay` or a running demo — it can be run at any
 * time, even mid-show from a third terminal.
 *
 * CLI:  npm run preflight
 *       → one line + exit 0 ("preflight OK … (NNN ms)") or exit 1.
 *       A hard watchdog guarantees the script NEVER hangs — worst case
 *       it fails loudly within a few seconds.
 *
 * API:  runPreflight() — resolves {ok, ms, port, eventId}, throws on any
 *       failed stage (the stage name is in the message) — used by tests.
 */

import { WebSocket } from "ws";
import { schnorr } from "@noble/curves/secp256k1";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { randomBytes } from "node:crypto";
import { startRelay, eventId, type NostrEvent } from "./relay.js";
import { generateKeyPair, sign, verify } from "./lsag.js";
import {
  generatePublisher,
  buildNostrEvent,
  proofFromWireEvent,
  buildBindingMessage,
  bindingToJson,
  ringHash,
  type TradeBinding,
} from "./demo.js";

/** Per-step deadline — every await is bounded so preflight can never hang. */
const STEP_DEADLINE_MS = 2_000;
/** Whole-script watchdog for the CLI path. */
const TOTAL_BUDGET_MS = 4_000;

export interface PreflightResult {
  ok: true;
  /** Wall-clock duration of the full roundtrip, fractional ms. */
  ms: number;
  /** The ephemeral port the throwaway relay listened on. */
  port: number;
  /** Event id that survived the whole publish → REQ → verify loop. */
  eventId: string;
}

/** Reject with `stage: what` if `p` does not settle within STEP_DEADLINE_MS. */
function step<T>(p: Promise<T>, stage: string, what: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`${stage}: ${what} (no reply within ${STEP_DEADLINE_MS}ms)`)),
      STEP_DEADLINE_MS,
    );
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

function wsOpen(ws: WebSocket): Promise<void> {
  return step(
    new Promise<void>((resolve, reject) => {
      ws.once("open", () => resolve());
      ws.once("error", (err: Error) => reject(err));
      ws.once("close", () => reject(new Error("socket closed before open")));
    }),
    "relay connect",
    "could not open the websocket",
  );
}

interface QueueWaiter {
  resolve: (m: unknown) => void;
  reject: (e: Error) => void;
}

/**
 * Buffered FIFO reader for one socket. The relay replies back-to-back
 * (e.g. EVENT replay + EOSE in a single TCP chunk) — both `message`
 * emissions fire in the SAME tick, so a freshly attached once() listener
 * would miss the second frame. A persistent listener feeds a queue
 * instead; `next()` pops or waits.
 */
function messageQueue(ws: WebSocket): { next: (stage: string) => Promise<unknown> } {
  const queue: unknown[] = [];
  const waiters: QueueWaiter[] = [];
  ws.on("message", (data: unknown) => {
    let msg: unknown;
    try {
      msg = JSON.parse(String(data));
    } catch {
      return; // not JSON — irrelevant for this protocol
    }
    const w = waiters.shift();
    if (w !== undefined) w.resolve(msg);
    else queue.push(msg);
  });
  const failAll = (e: Error): void => {
    while (waiters.length > 0) waiters.shift()?.reject(e);
  };
  ws.on("close", () => failAll(new Error("socket closed before reply")));
  ws.on("error", (err: Error) => failAll(err));

  return {
    next(stage: string): Promise<unknown> {
      if (queue.length > 0) return Promise.resolve(queue.shift());
      return step(
        new Promise<unknown>((resolve, reject) => waiters.push({ resolve, reject })),
        stage,
        "no relay reply",
      );
    },
  };
}

/**
 * Run the full smoke roundtrip. Every failure throws with the failing stage
 * as the first word of the message ("publish: …", "lsag: …", …).
 */
export async function runPreflight(): Promise<PreflightResult> {
  const t0 = performance.now();

  // 1. The demo's core crypto: a real LSAG proof over a 4-key ring
  //    (B4 minimum ring size). B2: the signed message is the canonical
  //    trade-binding digest.
  const keys = [
    generateKeyPair(),
    generateKeyPair(),
    generateKeyPair(),
    generateKeyPair(),
  ];
  const ring = keys.map((k) => k.publicKey);
  const binding: TradeBinding = {
    amount: "21000",
    makerNonce: randomBytes(8).toString("hex"),
    offerId: randomBytes(8).toString("hex"),
    ringHash: ringHash(ring),
  };
  const message = buildBindingMessage(binding);
  const lsagSig = sign(message, ring, 1, keys[1].secretKey);
  if (!verify(message, ring, lsagSig)) {
    throw new Error("lsag: freshly signed proof does not verify (local)");
  }

  // 2. The exact envelope the demo ships: ephemeral publisher + schnorr.
  const publisher = generatePublisher();
  const { event } = buildNostrEvent(
    publisher,
    ring.map((pk) => bytesToHex(pk)),
    ["pf-a", "pf-b", "pf-c", "pf-d"],
    binding.offerId,
    JSON.stringify({
      binding: JSON.parse(bindingToJson(binding)),
      keyImage: bytesToHex(lsagSig.keyImage),
      c0: bytesToHex(lsagSig.c0),
      responses: lsagSig.responses.map((r) => bytesToHex(r)),
    }),
  );

  // 3. Throwaway relay on an ephemeral port — never disturbs port 10547.
  const relay = await startRelay({ port: 0 });
  const ws = new WebSocket(`ws://127.0.0.1:${relay.port}`);
  ws.on("error", () => {}); // surfaced by the bounded awaits instead
  const replies = messageQueue(ws);
  try {
    await wsOpen(ws);

    // 4. Publish (taker side): relay must echo ['OK', id, true].
    ws.send(JSON.stringify(["EVENT", event]));
    const okReply = await replies.next("publish");
    if (
      !Array.isArray(okReply) || okReply[0] !== "OK" || okReply[2] !== true ||
      okReply[1] !== event.id
    ) {
      throw new Error(`publish: relay refused the event: ${JSON.stringify(okReply)}`);
    }

    // 5. REQ it back (maker side): EVENT with our id, then EOSE.
    ws.send(JSON.stringify(["REQ", "preflight", { kinds: [30221], ids: [event.id] }]));
    const evReply = await replies.next("req");
    const wireEvent = Array.isArray(evReply) && evReply[0] === "EVENT"
      ? (evReply[2] as NostrEvent)
      : undefined;
    if (wireEvent === undefined || wireEvent.id !== event.id) {
      throw new Error(`req: did not receive our event back: ${JSON.stringify(evReply)}`);
    }
    const eoseReply = await replies.next("eose");
    if (!Array.isArray(eoseReply) || eoseReply[0] !== "EOSE" || eoseReply[1] !== "preflight") {
      throw new Error(`eose: no EOSE after replay: ${JSON.stringify(eoseReply)}`);
    }

    // 6. Verify everything, strictly from what crossed the wire.
    if (eventId(wireEvent) !== wireEvent.id) {
      throw new Error("envelope: wire event id does not recompute");
    }
    if (!schnorr.verify(event.sig, hexToBytes(event.id), event.pubkey)) {
      throw new Error("schnorr: envelope signature does not verify");
    }
    const fromWire = proofFromWireEvent(wireEvent);
    if (!verify(fromWire.message, fromWire.ring, fromWire.sig)) {
      throw new Error("lsag: proof rebuilt from the wire does not verify");
    }
  } finally {
    ws.terminate();
    await relay.close();
  }

  return {
    ok: true,
    ms: performance.now() - t0,
    port: relay.port,
    eventId: event.id,
  };
}

// ─── CLI entry (npm run preflight) ─────────────────────────────

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/"))) {
  const watchdog = setTimeout(() => {
    console.error(`preflight FAIL — watchdog: not done within ${TOTAL_BUDGET_MS}ms`);
    process.exit(1);
  }, TOTAL_BUDGET_MS);
  runPreflight().then(
    ({ ms }) => {
      clearTimeout(watchdog);
      console.log(`preflight OK — relay publish → REQ → verify (id + schnorr + LSAG) green (${ms.toFixed(0)} ms)`);
    },
    (e: unknown) => {
      clearTimeout(watchdog);
      console.error(`preflight FAIL — ${e instanceof Error ? e.message : String(e)}`);
      process.exit(1);
    },
  );
}
