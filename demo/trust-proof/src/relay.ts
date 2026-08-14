/**
 * Minimal in-process Nostr relay (NIP-01 subset) for the trust-proof demo.
 *
 * Supported client messages:
 *   ["EVENT", event]          — id is recomputed over the canonical
 *                               serialization; mismatched ids are rejected,
 *                               valid events are stored and broadcast to
 *                               matching live subscriptions.
 *   ["REQ", subId, f, ...]    — filters are OR'd; `ids`, `kinds` and `limit`
 *                               are supported. Stored matches are replayed
 *                               (oldest first, most-recent `limit`), then a
 *                               mandatory ["EOSE", subId]. The sub goes live.
 *   ["CLOSE", subId]          — drop the subscription; unknown ids are a no-op.
 *
 * NOTE: no server-side schnorr signature verification. The publisher's
 * signature is verified in the R2 ring-proof tests; this relay is a demo
 * transport only, so the id check is sufficient here.
 */

import { WebSocket, WebSocketServer } from "ws";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";

// ─── Types ──────────────────────────────────────────────────────

export interface NostrEvent {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig?: string; // present but never verified here (see header note)
}

export interface ReqFilter {
  ids?: string[]; // full ids or prefixes (NIP-01)
  kinds?: number[];
  limit?: number; // replay only: keep the N most recent matches
}

export interface RelayHandle {
  /** The actual listening port (real port when started with port 0). */
  port: number;
  /** Terminate all clients and shut the server down. Resolves when closed. */
  close(): Promise<void>;
}

interface Subscription {
  subId: string;
  filters: ReqFilter[];
}

// ─── Event id (NIP-01 canonical) ────────────────────────────────

/** id = sha256 over [0, pubkey, created_at, kind, tags, content]. */
export function eventId(ev: NostrEvent): string {
  const serialized = JSON.stringify([
    0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content,
  ]);
  return bytesToHex(sha256(new TextEncoder().encode(serialized)));
}

// ─── Filter matching ────────────────────────────────────────────

function matchesFilter(ev: NostrEvent, f: ReqFilter): boolean {
  if (f.ids !== undefined && !f.ids.some((p) => ev.id.startsWith(p))) return false;
  if (f.kinds !== undefined && !f.kinds.includes(ev.kind)) return false;
  return true;
}

/** Multiple filters are OR'd: any single match qualifies the event. */
const matchesAny = (ev: NostrEvent, filters: ReqFilter[]): boolean =>
  filters.some((f) => matchesFilter(ev, f));

function isFilter(v: unknown): v is ReqFilter {
  return typeof v === "object" && v !== null;
}

function isNostrEvent(v: unknown): v is NostrEvent {
  if (typeof v !== "object" || v === null) return false;
  const e = v as Record<string, unknown>;
  return (
    typeof e.id === "string" &&
    typeof e.pubkey === "string" &&
    typeof e.created_at === "number" &&
    typeof e.kind === "number" &&
    Array.isArray(e.tags) &&
    typeof e.content === "string"
  );
}

// ─── Relay ──────────────────────────────────────────────────────

/**
 * Start the relay. `port: 0` binds an ephemeral port; the real port is read
 * from the server's address and returned on the handle.
 */
export async function startRelay(opts: { port: number }): Promise<RelayHandle> {
  const server = new WebSocketServer({ port: opts.port });
  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  const address = server.address();
  const port = typeof address === "object" && address !== null ? address.port : opts.port;

  const events = new Map<string, NostrEvent>();
  const subsBySocket = new Map<WebSocket, Subscription[]>();

  function handleEvent(sender: WebSocket, ev: unknown): void {
    if (!isNostrEvent(ev)) {
      const id = (ev as { id?: unknown } | null)?.id;
      sender.send(JSON.stringify(["OK", typeof id === "string" ? id : "", false, "invalid: malformed event"]));
      return;
    }
    if (eventId(ev) !== ev.id) {
      sender.send(JSON.stringify(["OK", ev.id, false, "invalid: id mismatch"]));
      return;
    }
    // Schnorr verification intentionally skipped — see header note (R2 verifies sigs).
    if (events.has(ev.id)) {
      sender.send(JSON.stringify(["OK", ev.id, true, "duplicate: already have this event"]));
      return;
    }
    events.set(ev.id, ev);

    // Broadcast to every matching live sub on every open connection.
    for (const [socket, subs] of subsBySocket) {
      if (socket.readyState !== WebSocket.OPEN) continue;
      for (const { subId, filters } of subs) {
        if (matchesAny(ev, filters)) {
          socket.send(JSON.stringify(["EVENT", subId, ev]));
        }
      }
    }
    sender.send(JSON.stringify(["OK", ev.id, true, ""]));
  }

  function handleReq(sender: WebSocket, subId: unknown, filterArgs: unknown[]): void {
    if (typeof subId !== "string" || !filterArgs.every(isFilter)) return;
    const filters = filterArgs as ReqFilter[];

    // A REQ with an existing sub id replaces that subscription (NIP-01).
    const subs = (subsBySocket.get(sender) ?? []).filter((s) => s.subId !== subId);
    subs.push({ subId, filters });
    subsBySocket.set(sender, subs);

    // Replay stored matches: per filter (each applying its own limit),
    // oldest first, deduped across the OR-union.
    const replay = new Map<string, NostrEvent>();
    for (const f of filters) {
      const matching = [...events.values()]
        .filter((ev) => matchesFilter(ev, f))
        .sort((a, b) => a.created_at - b.created_at);
      const recent =
        f.limit !== undefined && matching.length > f.limit
          ? matching.slice(matching.length - f.limit)
          : matching;
      for (const ev of recent) replay.set(ev.id, ev);
    }
    for (const ev of [...replay.values()].sort((a, b) => a.created_at - b.created_at)) {
      sender.send(JSON.stringify(["EVENT", subId, ev]));
    }
    sender.send(JSON.stringify(["EOSE", subId]));
  }

  function handleClose(sender: WebSocket, subId: unknown): void {
    if (typeof subId !== "string") return;
    const subs = subsBySocket.get(sender);
    if (subs === undefined) return; // unknown sub: no-op
    subsBySocket.set(sender, subs.filter((s) => s.subId !== subId));
  }

  server.on("connection", (ws) => {
    ws.on("message", (data: unknown) => {
      let msg: unknown;
      try {
        msg = JSON.parse(String(data));
      } catch {
        return; // ignore unparseable frames
      }
      if (!Array.isArray(msg) || msg.length === 0) return;
      const [type] = msg;
      if (type === "EVENT") handleEvent(ws, msg[1]);
      else if (type === "REQ") handleReq(ws, msg[1], msg.slice(2));
      else if (type === "CLOSE") handleClose(ws, msg[1]);
      // unknown message types are ignored
    });
    ws.on("close", () => subsBySocket.delete(ws));
  });

  return {
    port,
    async close(): Promise<void> {
      for (const socket of subsBySocket.keys()) socket.terminate();
      subsBySocket.clear();
      for (const client of server.clients) client.terminate();
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
    },
  };
}
