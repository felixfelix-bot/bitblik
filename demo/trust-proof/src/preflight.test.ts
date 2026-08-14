import { describe, it, expect } from "vitest";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import net from "node:net";
import type { ChildProcessByStdio } from "node:child_process";
import { Readable } from "node:stream";
import { WebSocket } from "ws";
import { runPreflight } from "./preflight.js";
import { generatePublisher, buildNostrEvent } from "./demo.js";
import { generateKeyPair, sign } from "./lsag.js";

// ─── Helpers ───────────────────────────────────────────────────

const PKG_DIR = fileURLToPath(new URL("..", import.meta.url));
const TSX_BIN = path.join(PKG_DIR, "node_modules", ".bin", "tsx");

/** Grab a free TCP port (bind :0, read it, release). Tiny local race, fine. */
function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address() as net.AddressInfo;
      srv.close(() => resolve(port));
    });
  });
}

/** Spawned with stdio ["ignore","pipe","pipe"] — stdout/stderr piped, stdin gone. */
type Spawned = ChildProcessByStdio<null, Readable, Readable>;

/** Resolve once the child's stdout (so far) contains `needle`. */
function waitForStdout(child: Spawned, needle: string, timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    let buf = "";
    const timer = setTimeout(() => reject(new Error(`timeout waiting for stdout ${JSON.stringify(needle)}; got: ${buf}`)), timeoutMs);
    child.stdout.on("data", (d: Buffer) => {
      buf += d.toString();
      if (buf.includes(needle)) {
        clearTimeout(timer);
        resolve(buf);
      }
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`child exited (code ${code}) before stdout ${JSON.stringify(needle)}; got: ${buf}`));
    });
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}

/** Resolve when the child exits; pass exit code + collected output. */
function waitForExit(child: Spawned, timeoutMs: number): Promise<{ code: number | null; out: string; err: string }> {
  return new Promise((resolve, reject) => {
    let out = "";
    let err = "";
    const timer = setTimeout(() => reject(new Error("timeout waiting for child exit")), timeoutMs);
    child.stdout.on("data", (d: Buffer) => (out += d.toString()));
    child.stderr.on("data", (d: Buffer) => (err += d.toString()));
    child.on("exit", (code) => {
      clearTimeout(timer);
      resolve({ code, out, err });
    });
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}

// ─── runPreflight (in-process API) ─────────────────────────────

describe("preflight (in-process)", () => {
  it("resolves ok with the full stack green: LSAG → envelope → relay → publish → REQ → verify", async () => {
    const result = await runPreflight();
    expect(result.ok).toBe(true);
    expect(result.eventId).toMatch(/^[0-9a-f]{64}$/);
    expect(result.port).toBeGreaterThan(0);
  });

  it("completes well inside the 3s smoke budget (localhost, no artificial waits)", async () => {
    const { ms } = await runPreflight();
    expect(ms).toBeGreaterThan(0);
    expect(ms).toBeLessThan(3_000);
  }, 10_000);

  it("ignores TRUST_DEMO_RELAY_PORT entirely — always an ephemeral port of its own", async () => {
    // If preflight honored the env port, 65536 (out of TCP range) would make
    // the bind fail. It must bind its OWN ephemeral port instead, so it can
    // never collide with — or disturb — a standalone relay on the demo port
    // (whatever process owns it on this machine).
    process.env.TRUST_DEMO_RELAY_PORT = "65536";
    try {
      const result = await runPreflight();
      expect(result.ok).toBe(true);
      expect(result.port).toBeGreaterThan(0);
      expect(result.port).toBeLessThan(65_536);
    } finally {
      delete process.env.TRUST_DEMO_RELAY_PORT;
    }
  }, 10_000);
});

// ─── preflight CLI (npm run preflight) ─────────────────────────

describe("preflight CLI (npm run preflight)", () => {
  it("exit 0 and exactly ONE 'preflight OK' line with a ms reading", () => {
    const r = spawnSync(TSX_BIN, ["src/preflight.ts"], { cwd: PKG_DIR, encoding: "utf8", timeout: 30_000 });
    expect(r.status).toBe(0);
    const lines = (r.stdout ?? "").trim().split("\n");
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(/^preflight OK .+\(\d+ ms\)$/);
  }, 60_000);
});

// ─── standalone relay (npm run relay) ──────────────────────────

describe("standalone relay (npm run relay)", () => {
  it("banner + real client roundtrip + graceful SIGINT exit 0 — two-terminal showpiece", async () => {
    const port = await freePort();
    const child = spawn(TSX_BIN, ["src/relay-standalone.ts"], {
      cwd: PKG_DIR,
      env: { ...process.env, TRUST_DEMO_RELAY_PORT: String(port) },
      stdio: ["ignore", "pipe", "pipe"],
    });
    try {
      // 1. Banner announces the listening URL.
      const banner = await waitForStdout(child, `ws://127.0.0.1:${port}`, 20_000);
      expect(banner).toContain("standalone");

      // 2. A real external client (the "other terminal") can publish + REQ.
      const ok = await new Promise<unknown[]>((resolve, reject) => {
        const ws = new WebSocket(`ws://127.0.0.1:${port}`);
        const timer = setTimeout(() => reject(new Error("timeout waiting for OK")), 5_000);
        ws.on("error", (e: Error) => { clearTimeout(timer); reject(e); });
        ws.on("open", () => {
          const publisher = generatePublisher();
          const { event } = buildNostrEvent(
            publisher,
            ["02" + "11".repeat(32)],
            ["pf"],
            "preflight-standalone",
            JSON.stringify({ msg: "standalone roundtrip" }),
          );
          ws.send(JSON.stringify(["EVENT", event]));
          ws.on("message", (d: unknown) => {
            const msg = JSON.parse(String(d)) as unknown[];
            if (msg[0] === "OK" && msg[2] === true) {
              clearTimeout(timer);
              ws.send(JSON.stringify(["REQ", "pf", { kinds: [30221], ids: [event.id] }]));
              ws.on("message", (d2: unknown) => {
                const m2 = JSON.parse(String(d2)) as unknown[];
                if (m2[0] === "EOSE") {
                  ws.terminate();
                  resolve(m2);
                }
              });
            }
          });
        });
      });
      expect(ok[0]).toBe("EOSE");

      // 3. Ctrl+C → graceful close, exit 0.
      child.kill("SIGINT");
      const exited = await waitForExit(child, 10_000);
      expect(exited.code).toBe(0);
      expect(exited.out).toContain("closing");
    } finally {
      if (child.exitCode === null) child.kill("SIGKILL");
    }
  }, 60_000);

  it("port already in use: clear error message, exit 1 (never a stack trace)", async () => {
    const squatter = net.createServer(() => { /* hold the port */ });
    await new Promise<void>((res) => squatter.listen(0, "127.0.0.1", res));
    const { port } = squatter.address() as net.AddressInfo;
    try {
      const child = spawn(TSX_BIN, ["src/relay-standalone.ts"], {
        cwd: PKG_DIR,
        env: { ...process.env, TRUST_DEMO_RELAY_PORT: String(port) },
        stdio: ["ignore", "pipe", "pipe"],
      });
      const exited = await waitForExit(child, 20_000);
      expect(exited.code).toBe(1);
      expect(exited.err).toContain("already in use");
      expect(exited.err).not.toContain("    at "); // no stack-trace dump
    } finally {
      squatter.close();
    }
  }, 60_000);

  it("carries a REAL LSAG proof end-to-end (same payload the demo ships)", async () => {
    const port = await freePort();
    const child = spawn(TSX_BIN, ["src/relay-standalone.ts"], {
      cwd: PKG_DIR,
      env: { ...process.env, TRUST_DEMO_RELAY_PORT: String(port) },
      stdio: ["ignore", "pipe", "pipe"],
    });
    try {
      await waitForStdout(child, `ws://127.0.0.1:${port}`, 20_000);
      // Publish a demo-shaped event and REQ it back — the exact wire flow.
      const roundtrip = await new Promise<string>((resolve, reject) => {
        const ws = new WebSocket(`ws://127.0.0.1:${port}`);
        const timer = setTimeout(() => reject(new Error("timeout")), 5_000);
        ws.on("error", (e: Error) => { clearTimeout(timer); reject(e); });
        ws.on("open", () => {
          const keys = [generateKeyPair(), generateKeyPair(), generateKeyPair()];
          const lsagSig = sign(
            new TextEncoder().encode("preflight"),
            keys.map((k) => k.publicKey),
            0,
            keys[0].secretKey,
          );
          const hex = (b: Uint8Array) => Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
          const { event } = buildNostrEvent(
            generatePublisher(),
            keys.map((k) => hex(k.publicKey)),
            ["a", "b", "c"],
            "d-tag",
            JSON.stringify({
              msg: "preflight",
              keyImage: hex(lsagSig.keyImage),
              c0: hex(lsagSig.c0),
              responses: lsagSig.responses.map(hex),
            }),
          );
          ws.send(JSON.stringify(["EVENT", event]));
          ws.on("message", (d: unknown) => {
            const msg = JSON.parse(String(d)) as unknown[];
            if (msg[0] === "OK" && msg[2] === true) {
              ws.send(JSON.stringify(["REQ", "pf", { ids: [event.id] }]));
              ws.on("message", (d2: unknown) => {
                const m2 = JSON.parse(String(d2)) as unknown[];
                if (m2[0] === "EOSE") {
                  clearTimeout(timer);
                  ws.terminate();
                  resolve(String(msg[1]));
                }
              });
            }
          });
        });
      });
      expect(roundtrip).toMatch(/^[0-9a-f]{64}$/);
      child.kill("SIGINT");
      await waitForExit(child, 10_000);
    } finally {
      if (child.exitCode === null) child.kill("SIGKILL");
    }
  }, 60_000);
});
