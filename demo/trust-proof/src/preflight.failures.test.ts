import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * Hostile-relay tests for preflight's FAILURE branches.
 *
 * runPreflight() is a happy-path smoke tool; its failure throws (publish
 * refusal, REQ replay mismatch, missing EOSE, envelope/schnorr/LSAG wire
 * failures, socket death) only fire against a misbehaving relay. Here the
 * relay is a scripted fake WebSocket plus targeted partial mocks, so every
 * "stage: …" error branch is exercised deterministically.
 *
 * The CLI entry block at the bottom of preflight.ts is intentionally NOT
 * covered here — it is exercised as a spawned process by the
 * "preflight CLI (npm run preflight)" test in preflight.test.ts.
 */

/** Mutable per-scenario state read by the hoisted mock factories. */
const M = vi.hoisted(() => {
  const defaultScript = {
    onEvent: (ev: { id: string }): unknown[][] => {
      state.lastEv = ev;
      return [["OK", ev.id, true]];
    },
    onReq: (sub: string): unknown[][] => [
      ["EVENT", sub, state.lastEv],
      ["EOSE", sub],
    ],
  };
  const state = {
    mode: "happy" as string,
    script: defaultScript,
    lastEv: null as { id: string } | null,
    defaultScript,
  };
  return state;
});

vi.mock("ws", async (importOriginal) => {
  const real = await importOriginal<typeof import("ws")>();
  class FakeWebSocket {
    private handlers = new Map<string, Array<(d?: unknown) => void>>();
    constructor(_url: string) {
      if (M.mode === "close-before-open") {
        queueMicrotask(() => this.emit("close"));
        return;
      }
      queueMicrotask(() => {
        this.emit("open");
        // A garbage non-JSON frame first: the queue must silently ignore it.
        this.emit("message", "<<<not json>>>");
      });
    }
    on(ev: string, fn: (d?: unknown) => void): void {
      const arr = this.handlers.get(ev) ?? [];
      arr.push(fn);
      this.handlers.set(ev, arr);
    }
    once(ev: string, fn: (d?: unknown) => void): void {
      const wrap = (d?: unknown): void => {
        this.off(ev, wrap);
        fn(d);
      };
      this.on(ev, wrap);
    }
    off(ev: string, fn: (d?: unknown) => void): void {
      const arr = this.handlers.get(ev);
      if (arr !== undefined) {
        const i = arr.indexOf(fn);
        if (i >= 0) arr.splice(i, 1);
      }
    }
    private emit(ev: string, d?: unknown): void {
      for (const fn of [...(this.handlers.get(ev) ?? [])]) fn(d);
    }
    send(raw: string): void {
      const msg = JSON.parse(raw) as unknown[];
      const frames =
        msg[0] === "EVENT"
          ? M.script.onEvent(msg[1] as { id: string })
          : msg[0] === "REQ"
            ? M.script.onReq(msg[1] as string)
            : [];
      queueMicrotask(() => {
        if (M.mode === "error-string") {
          // Relay dies with a NON-Error payload — preflight must still
          // reject with a proper Error (String() wrapping).
          this.emit("error", "boom");
          return;
        }
        for (const f of frames) this.emit("message", JSON.stringify(f));
      });
    }
    terminate(): void {
      this.emit("close");
    }
  }
  // Only the CLIENT socket is scripted; WebSocketServer stays real so
  // startRelay() (ephemeral port) keeps working unmodified.
  return { ...real, WebSocket: FakeWebSocket };
});

vi.mock("./relay.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("./relay.js")>();
  return {
    ...real,
    eventId: (ev: Parameters<typeof real.eventId>[0]) =>
      M.mode === "bad-event-id" ? "ff".repeat(32) : real.eventId(ev),
  };
});

vi.mock("./demo.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("./demo.js")>();
  return {
    ...real,
    verifyProofEvent: (...args: Parameters<typeof real.verifyProofEvent>) =>
      M.mode === "lsag-wire-fail" ? false : real.verifyProofEvent(...args),
    buildNostrEvent: (...args: Parameters<typeof real.buildNostrEvent>) => {
      const built = real.buildNostrEvent(...args);
      if (M.mode === "bad-schnorr") {
        // Envelope with a garbage schnorr sig: id still recomputes (id
        // covers the unsigned fields), but schnorr.verify must fail.
        return { event: { ...built.event, sig: "ff".repeat(64) } };
      }
      return built;
    },
  };
});

vi.mock("./lsag.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("./lsag.js")>();
  return {
    ...real,
    verify: (...args: Parameters<typeof real.verify>) =>
      M.mode === "local-verify-fail" ? false : real.verify(...args),
  };
});

import { runPreflight } from "./preflight.js";

beforeEach(() => {
  M.mode = "happy";
  M.script = M.defaultScript;
  M.lastEv = null;
});

describe("preflight failure branches (hostile relay)", () => {
  it("happy path still resolves when the relay prepends garbage frames", async () => {
    const r = await runPreflight();
    expect(r.ok).toBe(true);
  });

  it("throws 'publish:' when the relay refuses the event", async () => {
    M.script = {
      ...M.defaultScript,
      onEvent: (ev: { id: string }) => {
        M.lastEv = ev;
        return [["OK", ev.id, false]];
      },
    };
    await expect(runPreflight()).rejects.toThrow(/publish: relay refused the event/);
  });

  it("throws 'req:' when the replay is not our event", async () => {
    M.script = {
      ...M.defaultScript,
      onReq: () => [["NOTICE", "no such event"]],
    };
    await expect(runPreflight()).rejects.toThrow(/req: did not receive our event back/);
  });

  it("throws 'eose:' when no EOSE follows the replay", async () => {
    M.script = {
      ...M.defaultScript,
      onReq: (sub: string) => [
        ["EVENT", sub, M.lastEv],
        ["EOSE", "wrong-subscription"],
      ],
    };
    await expect(runPreflight()).rejects.toThrow(/eose: no EOSE after replay/);
  });

  it("throws 'envelope:' when the wire id does not recompute", async () => {
    M.mode = "bad-event-id";
    await expect(runPreflight()).rejects.toThrow(/envelope: wire event id does not recompute/);
  });

  it("throws 'schnorr:' when the envelope signature is garbage", async () => {
    M.mode = "bad-schnorr";
    await expect(runPreflight()).rejects.toThrow(/schnorr: envelope signature does not verify/);
  });

  it("throws 'lsag:' when the wire proof fails against OUR ring", async () => {
    M.mode = "lsag-wire-fail";
    await expect(runPreflight()).rejects.toThrow(
      /lsag: proof rebuilt from the wire does not verify against OUR ring/,
    );
  });

  it("throws 'lsag:' when even the freshly signed local proof fails", async () => {
    M.mode = "local-verify-fail";
    await expect(runPreflight()).rejects.toThrow(/lsag: freshly signed proof does not verify/);
  });

  it("throws 'relay connect:' when the socket closes before opening", async () => {
    M.mode = "close-before-open";
    await expect(runPreflight()).rejects.toThrow(/socket closed before open/);
  });

  it("rejects with a proper Error when the relay emits a non-Error failure mid-flight", async () => {
    M.mode = "error-string";
    await expect(runPreflight()).rejects.toThrow(/^boom$/);
  });
});
