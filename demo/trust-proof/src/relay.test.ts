import { describe, it, expect, afterEach } from "vitest";
import { WebSocket } from "ws";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import { startRelay } from "./relay.js";

// ─── Test-side event builder (mirrors a real Nostr client) ──────

interface TestEvent {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
}

/** Build a well-formed event with a correctly computed NIP-01 id. */
function makeEvent(f: Partial<Omit<TestEvent, "id">> = {}): TestEvent {
  const ev = {
    pubkey: f.pubkey ?? "aa".repeat(32),
    created_at: f.created_at ?? 1_000,
    kind: f.kind ?? 1,
    tags: f.tags ?? [],
    content: f.content ?? "hello nostr",
    sig: f.sig ?? "ab".repeat(64), // relay never verifies sigs (see relay.ts)
  };
  // NIP-01: id = sha256 of [0,pubkey,created_at,kind,tags,content]
  const serialized = JSON.stringify([
    0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content,
  ]);
  return { ...ev, id: bytesToHex(sha256(new TextEncoder().encode(serialized))) };
}

// ─── Real ws client wrapper (no mocks anywhere) ─────────────────

type WireMsg = unknown[];

interface Waiter {
  pred: (m: WireMsg) => boolean;
  resolve: (m: WireMsg) => void;
  timer: ReturnType<typeof setTimeout>;
}

class Client {
  readonly ws: WebSocket;
  readonly received: WireMsg[] = [];
  private waiters: Waiter[] = [];

  constructor(port: number) {
    this.ws = new WebSocket(`ws://127.0.0.1:${port}`);
    this.ws.on("error", () => {}); // don't crash the process on hard closes
    this.ws.on("message", (data: unknown) => {
      const msg = JSON.parse(String(data)) as WireMsg;
      this.received.push(msg);
      const i = this.waiters.findIndex((w) => w.pred(msg));
      if (i >= 0) {
        const [w] = this.waiters.splice(i, 1);
        clearTimeout(w.timer);
        w.resolve(msg);
      }
    });
  }

  /** Resolve once the socket is open (ready to send). */
  static open(port: number): Promise<Client> {
    return new Promise((resolve, reject) => {
      const c = new Client(port);
      c.ws.once("open", () => resolve(c));
      c.ws.once("error", reject);
    });
  }

  send(msg: WireMsg): void {
    this.ws.send(JSON.stringify(msg));
  }

  /** First message (already seen or future) matching pred. */
  waitFor(pred: (m: WireMsg) => boolean, timeoutMs = 2_000): Promise<WireMsg> {
    const already = this.received.find(pred);
    if (already) return Promise.resolve(already);
    return new Promise((resolve, reject) => {
      const w: Waiter = {
        pred,
        resolve,
        timer: setTimeout(() => {
          this.waiters = this.waiters.filter((x) => x !== w);
          reject(new Error(
            `timeout waiting for message; received so far: ${JSON.stringify(this.received)}`,
          ));
        }, timeoutMs),
      };
      this.waiters.push(w);
    });
  }

  /** Assert no further messages arrive within ms. */
  async expectNoMoreMessages(ms = 150): Promise<void> {
    const seen = this.received.length;
    await new Promise((r) => setTimeout(r, ms));
    expect(this.received.length).toBe(seen);
  }
}

// ─── Fixture management (vitest hangs on dangling WS handles) ──

type Relay = Awaited<ReturnType<typeof startRelay>>;
let relay: Relay | undefined;
const clients: Client[] = [];

function track(c: Client): Client {
  clients.push(c);
  return c;
}

afterEach(async () => {
  for (const c of clients.splice(0)) c.ws.terminate();
  if (relay) {
    await relay.close();
    relay = undefined;
  }
});

const isOk = (m: WireMsg) => m[0] === "OK";
const isEvent = (m: WireMsg) => m[0] === "EVENT";
const eventIds = (c: Client): string[] =>
  c.received.filter(isEvent).map((m) => (m[2] as TestEvent).id);

/** Send REQ and wait for its EOSE — guarantees the sub is registered. */
async function subscribe(c: Client, sub: string, filters: unknown[]): Promise<void> {
  c.send(["REQ", sub, ...filters]);
  await c.waitFor((m) => m[0] === "EOSE" && m[1] === sub);
}

/** Publish an event and wait for its OK. */
async function publish(c: Client, ev: TestEvent): Promise<void> {
  c.send(["EVENT", ev]);
  await c.waitFor(isOk);
}

// ─── Tests ──────────────────────────────────────────────────────

describe("relay (NIP-01 subset)", () => {
  it("publish a valid event -> ['OK', id, true, '']", async () => {
    relay = await startRelay({ port: 0 });
    expect(relay.port).toBeGreaterThan(0); // port 0 = ephemeral, real port back

    const pub = track(await Client.open(relay.port));
    const ev = makeEvent();

    pub.send(["EVENT", ev]);
    const ok = await pub.waitFor(isOk);
    expect(ok).toEqual(["OK", ev.id, true, ""]);
  });

  it("tampered id -> ['OK', tamperedId, false, 'invalid: id mismatch'], not stored", async () => {
    relay = await startRelay({ port: 0 });
    const pub = track(await Client.open(relay.port));

    const ev = makeEvent({ kind: 1, content: "do not store me" });
    const tampered = { ...ev, id: "ff".repeat(32) }; // valid hex, wrong id
    pub.send(["EVENT", tampered]);

    const ok = await pub.waitFor(isOk);
    expect(ok).toEqual(["OK", "ff".repeat(32), false, "invalid: id mismatch"]);

    // rejected events must not be replayed to later subscribers
    await subscribe(pub, "check", [{ ids: [ev.id] }]);
    expect(pub.received.filter(isEvent)).toHaveLength(0);
    expect(pub.received.at(-1)).toEqual(["EOSE", "check"]);
  });

  it("REQ after publish replays stored events then EOSE", async () => {
    relay = await startRelay({ port: 0 });
    const pub = track(await Client.open(relay.port));
    const ev = makeEvent({ kind: 1, content: "stored" });
    await publish(pub, ev);

    const reader = track(await Client.open(relay.port));
    await subscribe(reader, "s1", [{ kinds: [1] }]);

    expect(reader.received).toEqual([
      ["EVENT", "s1", ev],
      ["EOSE", "s1"],
    ]);
  });

  it("REQ before publish receives live push (no second EOSE)", async () => {
    relay = await startRelay({ port: 0 });
    const subscriber = track(await Client.open(relay.port));
    await subscribe(subscriber, "live", [{ kinds: [7] }]);

    const publisher = track(await Client.open(relay.port));
    const ev = makeEvent({ kind: 7, content: "live push" });
    await publish(publisher, ev);

    const got = await subscriber.waitFor((m) => isEvent(m) && m[1] === "live");
    expect(got).toEqual(["EVENT", "live", ev]);

    await subscriber.expectNoMoreMessages(); // no EOSE after live events
    expect(publisher.received.filter(isOk)).toEqual([["OK", ev.id, true, ""]]);
  });

  it("CLOSE stops delivery for that sub", async () => {
    relay = await startRelay({ port: 0 });
    const a = track(await Client.open(relay.port));
    await subscribe(a, "s", [{ kinds: [1] }]);

    a.send(["CLOSE", "s"]);
    // No CLOSE ack exists — round-trip a probe REQ: per-connection message
    // ordering guarantees the CLOSE was handled once the probe EOSE arrives.
    await subscribe(a, "probe", [{ kinds: [99] }]);

    const b = track(await Client.open(relay.port));
    await publish(b, makeEvent({ kind: 1, content: "after close" }));

    await a.expectNoMoreMessages(); // nothing pushed to the closed sub
  });

  it("CLOSE for an unknown sub is a no-op (other subs keep working)", async () => {
    relay = await startRelay({ port: 0 });
    const a = track(await Client.open(relay.port));
    await subscribe(a, "s", [{ kinds: [1] }]);

    a.send(["CLOSE", "ghost"]);
    await subscribe(a, "probe", [{ kinds: [99] }]); // wait out the CLOSE

    const ev = makeEvent({ kind: 1, content: "still subscribed" });
    await publish(a, ev);

    const got = await a.waitFor((m) => isEvent(m) && m[1] === "s");
    expect(got).toEqual(["EVENT", "s", ev]);
  });

  it("REQ with multiple filters ORs them", async () => {
    relay = await startRelay({ port: 0 });
    const pub = track(await Client.open(relay.port));
    const note = makeEvent({ kind: 1, content: "a note" });
    const ring = makeEvent({ kind: 3, content: "contact list" });
    await publish(pub, note);
    await publish(pub, ring);

    const reader = track(await Client.open(relay.port));
    await subscribe(reader, "multi", [{ kinds: [3] }, { kinds: [1] }]);

    expect(eventIds(reader).sort()).toEqual([note.id, ring.id].sort());
    expect(reader.received.filter(isEvent)).toHaveLength(2);
    expect(reader.received.at(-1)).toEqual(["EOSE", "multi"]);
  });

  it("REQ limit replays only the N most recent events", async () => {
    relay = await startRelay({ port: 0 });
    const pub = track(await Client.open(relay.port));
    const e1 = makeEvent({ kind: 1, created_at: 100, content: "oldest" });
    const e2 = makeEvent({ kind: 1, created_at: 200, content: "middle" });
    const e3 = makeEvent({ kind: 1, created_at: 300, content: "newest" });
    await publish(pub, e1);
    await publish(pub, e2);
    await publish(pub, e3);

    const reader = track(await Client.open(relay.port));
    await subscribe(reader, "lim", [{ kinds: [1], limit: 2 }]);

    expect(eventIds(reader)).toEqual([e2.id, e3.id]); // oldest-first, most recent kept
    expect(reader.received.at(-1)).toEqual(["EOSE", "lim"]);
  });

  it("REQ ids filter replays only the matching event", async () => {
    relay = await startRelay({ port: 0 });
    const pub = track(await Client.open(relay.port));
    const e1 = makeEvent({ kind: 1, created_at: 100, content: "first" });
    const e2 = makeEvent({ kind: 1, created_at: 200, content: "second" });
    await publish(pub, e1);
    await publish(pub, e2);

    const reader = track(await Client.open(relay.port));
    await subscribe(reader, "byid", [{ ids: [e2.id] }]);

    expect(eventIds(reader)).toEqual([e2.id]);
    expect(reader.received.at(-1)).toEqual(["EOSE", "byid"]);
  });
});
