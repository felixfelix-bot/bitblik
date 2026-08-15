import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { randomBytes } from "node:crypto";
import net from "node:net";
import { bech32 } from "@scure/base";
import { WebSocket } from "ws";
import { secp256k1, schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import {
  main,
  parseArgs,
  parseRelayMode,
  pause,
  decodeNpub,
  npubToRingPubkey,
  parseNpubArgs,
  generatePublisher,
  buildNostrEvent,
  proofFromWireEvent,
} from "./demo.js";
import { generateKeyPair, sign, verify } from "./lsag.js";
import { startRelay } from "./relay.js";

// ─── Helpers ───────────────────────────────────────────────────

const PKG_DIR = fileURLToPath(new URL("..", import.meta.url));
const TSX_BIN = path.join(PKG_DIR, "node_modules", ".bin", "tsx");

/** Build a valid npub string for any 32-byte x-only pubkey. */
function makeNpub(x32: Uint8Array): string {
  return bech32.encodeFromBytes("npub", x32);
}

/** Deterministically find an x that is NOT on secp256k1 (no valid y). */
function findOffCurveX32(): Uint8Array {
  for (let i = 1; i < 500; i++) {
    const x = new Uint8Array(32);
    new DataView(x.buffer).setBigUint64(24, BigInt(i), false);
    let ok = false;
    for (const parity of [0x02, 0x03]) {
      const cand = new Uint8Array(33);
      cand.set(x, 1);
      cand[0] = parity;
      try {
        secp256k1.Point.fromBytes(cand).assertValidity();
        ok = true;
      } catch {
        // not valid with this parity
      }
    }
    if (!ok) return x;
  }
  throw new Error("no off-curve x found in 500 tries?!");
}

/** main() is async since R3 (relay transport) — every caller awaits it. */
async function captureMainOutput(argv: string[]): Promise<string> {
  const logs: string[] = [];
  const spy = vi.spyOn(console, "log").mockImplementation((...a: unknown[]) => {
    logs.push(a.map(String).join(" "));
  });
  try {
    await main(argv);
  } finally {
    spy.mockRestore();
  }
  return logs.join("\n");
}

afterEach(() => {
  vi.restoreAllMocks();
});

// ─── Existing demo smoke test ──────────────────────────────────

describe("demo", () => {
  it("opens with an ASCII roles diagram (who is who)", async () => {
    const out = await captureMainOutput([]);
    expect(out).toContain("0. The roles");
    expect(out).toContain("TAKER");
    expect(out).toContain("MAKER");
    expect(out).toContain("trust ring");
    expect(out).toContain("BLIK code");
    expect(out.indexOf("0. The roles")).toBeLessThan(out.indexOf("1. Setup"));
  });

  it("roles diagram flow: proof BEFORE sats, BLIK code LAST", async () => {
    const out = await captureMainOutput([]);
    const iProof = out.indexOf("2) ring signature proof");
    const iSats = out.indexOf("3) sats over Lightning");
    const iCode = out.indexOf("4) BLIK code");
    expect(iProof).toBeGreaterThan(-1);
    expect(iSats).toBeGreaterThan(-1);
    expect(iCode).toBeGreaterThan(-1);
    expect(iProof).toBeLessThan(iSats);
    expect(iSats).toBeLessThan(iCode);
  });

  it("ring members have human names", async () => {
    const out = await captureMainOutput([]);
    for (const n of ["Alice", "Bob", "Carol", "Dave", "Erin"]) {
      expect(out).toContain(n);
    }
    // security check 5a names the real signer
    expect(out).toContain("secret key for Carol");
  });

  it("prints the proof as a Nostr event with computed id", async () => {
    const out = await captureMainOutput([]);
    expect(out).toContain("Nostr event");
    expect(out).toMatch(/"kind": 30221/);
    expect(out).toMatch(/"id": "[0-9a-f]{64}"/);
    expect(out).toContain("npub1");
  });

  it("shows live computation timing (ms) somewhere", async () => {
    const out = await captureMainOutput([]);
    expect(out).toMatch(/\d+\.\d+ ms/);
  });

  it("live tamper test inside section 3: valid then rejected", async () => {
    const out = await captureMainOutput([]);
    const iValid = out.indexOf("Signature is valid");
    const iTamper = out.indexOf("Tamper test");
    const iS4 = out.indexOf("4. Nullifier");
    expect(iValid).toBeGreaterThan(-1);
    expect(iTamper).toBeGreaterThan(iValid);
    expect(iTamper).toBeLessThan(iS4);
    expect(out).toContain("REJECTED");
  });

  it("explains THE PROBLEM before the roles", async () => {
    const out = await captureMainOutput([]);
    expect(out).toContain("The problem");
    expect(out).toContain("stolen card");
    expect(out.indexOf("The problem")).toBeLessThan(out.indexOf("0. The roles"));
  });

  it("each step carries a 'why this step' explanation line", async () => {
    const out = await captureMainOutput([]);
    const why = out.match(/>> /g)?.length ?? 0;
    expect(why).toBeGreaterThanOrEqual(5);
    expect(out).toContain("nobody can tell which");
    expect(out).toContain("reveals nothing about which one");
    expect(out).toContain("same nullifier");
  });

  it("main is an async function and resolves cleanly", async () => {
    expect(typeof main).toBe("function");
    await expect(main()).resolves.toBeUndefined();
  }, 30_000);
});

describe("flag parsing", () => {
  it("--interactive sets interactive=true", () => {
    expect(parseArgs(["--interactive"])).toEqual({
      interactive: true,
      quick: false,
    });
  });

  it("--quick sets quick=true", () => {
    expect(parseArgs(["--quick"])).toEqual({
      interactive: false,
      quick: true,
    });
  });

  it("no flags = default behavior unchanged", () => {
    expect(parseArgs([])).toEqual({ interactive: false, quick: false });
  });

  it("combined --interactive --quick works", () => {
    expect(parseArgs(["--interactive", "--quick"])).toEqual({
      interactive: true,
      quick: true,
    });
  });
});

describe("pause", () => {
  it("is a no-op when interactive=false — no prompt, no stdin read", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const waitForKey = vi.fn();
    pause({ interactive: false, waitForKey });
    expect(log).not.toHaveBeenCalled();
    expect(waitForKey).not.toHaveBeenCalled();
  });

  it("prints '[Enter] to continue...' and reads stdin when interactive=true", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const waitForKey = vi.fn();
    pause({ interactive: true, waitForKey });
    expect(log).toHaveBeenCalledWith("[Enter] to continue...");
    expect(waitForKey).toHaveBeenCalledTimes(1);
  });
});

describe("demo output flags", () => {
  // waitForKey is always injected so interactive runs never touch real stdin.
  async function captureMainOutput(opts: {
    interactive: boolean;
    quick: boolean;
  }): Promise<string> {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    await main({ ...opts, waitForKey: () => {} });
    return log.mock.calls.map((args) => args.join(" ")).join("\n");
  }

  it("no flags: full security check details shown, no pause prompt", async () => {
    const out = await captureMainOutput({ interactive: false, quick: false });
    expect(out).toContain("5. Security checks");
    expect(out).toContain("5a. Wrong secret key");
    expect(out).toContain("5b. Tampered message");
    expect(out).toContain("5c. Tampered response");
    expect(out).toContain("5d. Tampered key image");
    expect(out).not.toContain("[Enter] to continue...");
    expect(out).not.toContain("All 4 security checks passed");
  }, 30_000);

  it("--quick: security checks collapse to a single summary line", async () => {
    const out = await captureMainOutput({ interactive: false, quick: true });
    expect(out).toContain("All 4 security checks passed: ✅");
    expect(out).not.toContain("5a. Wrong secret key");
    expect(out).not.toContain("5b. Tampered message");
    expect(out).not.toContain("5c. Tampered response");
    expect(out).not.toContain("5d. Tampered key image");
  }, 30_000);

  it("--interactive: pause prompt after each of the 6 section headers", async () => {
    const out = await captureMainOutput({ interactive: true, quick: false });
    expect(out.match(/\[Enter\] to continue\.\.\./g)?.length).toBe(7);
  }, 30_000);

  it("--interactive: injected waitForKey is called once per section", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const waitForKey = vi.fn();
    await main({ interactive: true, quick: false, waitForKey });
    expect(waitForKey).toHaveBeenCalledTimes(7);
  }, 30_000);

  it("combined --interactive --quick works", async () => {
    const out = await captureMainOutput({ interactive: true, quick: true });
    expect(out).toContain("[Enter] to continue...");
    expect(out).toContain("All 4 security checks passed: ✅");
    expect(out).not.toContain("5a. Wrong secret key");
  }, 30_000);
});

// ─── npub decoding ─────────────────────────────────────────────

describe("decodeNpub", () => {
  it("valid npub decodes to the correct 32 bytes", () => {
    const k = generateKeyPair();
    const x32 = k.publicKey.slice(1); // strip compressed prefix
    const npub = makeNpub(x32);
    const decoded = decodeNpub(npub);
    expect(decoded.length).toBe(32);
    expect(Buffer.from(decoded).equals(Buffer.from(x32))).toBe(true);
  });

  it("round-trips the generator point x-coordinate", () => {
    const x32 = secp256k1.Point.BASE.toBytes().slice(1);
    const decoded = decodeNpub(makeNpub(x32));
    expect(Buffer.from(decoded).equals(Buffer.from(x32))).toBe(true);
  });
});

describe("npubToRingPubkey", () => {
  it("returns a valid 33-byte compressed secp256k1 point with same x", () => {
    const k = generateKeyPair();
    const npub = makeNpub(k.publicKey.slice(1));
    const pk = npubToRingPubkey(npub);
    expect(pk.length).toBe(33);
    expect(pk[0] === 0x02 || pk[0] === 0x03).toBe(true);
    expect(() =>
      secp256k1.Point.fromBytes(pk).assertValidity()
    ).not.toThrow();
    expect(Buffer.from(pk.slice(1)).equals(Buffer.from(k.publicKey.slice(1)))).toBe(true);
  });
});

// ─── invalid npub rejection ────────────────────────────────────

describe("invalid npub rejection", () => {
  const x32 = generateKeyPair().publicKey.slice(1);

  it("rejects garbage strings", () => {
    expect(() => decodeNpub("not-an-npub")).toThrow(/Invalid npub/i);
    expect(() => npubToRingPubkey("hello world")).toThrow(/Invalid npub/i);
  });

  it("rejects bad checksum", () => {
    const bad = makeNpub(x32).slice(0, -1) + "q";
    expect(() => decodeNpub(bad)).toThrow(/Invalid npub/i);
  });

  it("rejects wrong bech32 prefix (nsec)", () => {
    const nsec = bech32.encodeFromBytes("nsec", x32);
    expect(() => decodeNpub(nsec)).toThrow(/Invalid npub/i);
  });

  it("rejects wrong payload length (31 bytes)", () => {
    const short = bech32.encodeFromBytes("npub", x32.slice(1));
    expect(() => decodeNpub(short)).toThrow(/Invalid npub/i);
  });

  it("rejects valid bech32 whose x is not on the curve", () => {
    const offCurveNpub = makeNpub(findOffCurveX32());
    expect(() => npubToRingPubkey(offCurveNpub)).toThrow(/Invalid npub/i);
  });
});

// ─── --npub argument parsing ───────────────────────────────────

describe("parseNpubArgs", () => {
  const A = makeNpub(generateKeyPair().publicKey.slice(1));
  const B = makeNpub(generateKeyPair().publicKey.slice(1));

  it("no --npub flag yields empty list", () => {
    expect(parseNpubArgs([])).toEqual([]);
  });

  it("--npub with a single value", () => {
    expect(parseNpubArgs(["--npub", A])).toEqual([A]);
  });

  it("--npub with multiple values", () => {
    expect(parseNpubArgs(["--npub", A, B])).toEqual([A, B]);
  });

  it("flag can appear anywhere; stops at the next flag", () => {
    expect(parseNpubArgs(["--quick", "--npub", A])).toEqual([A]);
    expect(parseNpubArgs(["--npub", A, "--quick"])).toEqual([A]);
  });

  it("--npub with no value throws", () => {
    expect(() => parseNpubArgs(["--npub"])).toThrow();
    expect(() => parseNpubArgs(["--npub", "--quick"])).toThrow();
  });
});

// ─── ring integration ──────────────────────────────────────────

describe("ring with participant decoys", () => {
  const npubA = makeNpub(generateKeyPair().publicKey.slice(1));
  const npubB = makeNpub(generateKeyPair().publicKey.slice(1));

  it("participant npubs become ring members and the signature still verifies", () => {
    const keys = Array.from({ length: 5 }, () => generateKeyPair());
    const decoys = [npubA, npubB].map(npubToRingPubkey);
    const ring = [...keys.map((k) => k.publicKey), ...decoys];
    expect(ring.length).toBe(7); // ring size increments: 5 + 2

    const msg = new TextEncoder().encode("decoy test");
    const sig = sign(msg, ring, 2, keys[2].secretKey);
    expect(verify(msg, ring, sig)).toBe(true);

    // linkability preserved: same signer, same key image with/without decoys
    const sigSmall = sign(msg, keys.map((k) => k.publicKey), 2, keys[2].secretKey);
    expect(Buffer.from(sig.keyImage).equals(Buffer.from(sigSmall.keyImage))).toBe(true);
  });

  it("main output announces decoy count and grown ring size", async () => {
    const out = await captureMainOutput(["--npub", npubA, npubB]);
    expect(out).toContain("Participant npubs added as decoys: 2");
    expect(out).toContain("Ring size: 7");
  }, 30_000);

  it("without --npub the output is unchanged (no decoy section, ring of 5)", async () => {
    const out = await captureMainOutput([]);
    expect(out).not.toContain("Participant npubs");
    expect(out).toContain("Ring size: 5");
  }, 30_000);
});

// ─── CLI end-to-end ────────────────────────────────────────────

describe("CLI end-to-end (--npub)", () => {
  const validNpub = makeNpub(generateKeyPair().publicKey.slice(1));

  it("valid npub: exit 0 and decoy line in output", () => {
    const out = execFileSync(TSX_BIN, ["src/demo.ts", "--npub", validNpub], {
      cwd: PKG_DIR,
      encoding: "utf8",
      timeout: 60_000,
    });
    expect(out).toContain("Participant npubs added as decoys: 1");
    expect(out).toContain("Ring size: 6");
  }, 90_000);

  it("invalid npub: clear error on stderr, exit 1, demo does NOT partially run", () => {
    let err: Error & { status?: number; stderr?: string; stdout?: string };
    try {
      execFileSync(TSX_BIN, ["src/demo.ts", "--npub", "npub1garbage"], {
        cwd: PKG_DIR,
        encoding: "utf8",
        timeout: 60_000,
      });
      throw new Error("expected non-zero exit");
    } catch (e) {
      err = e as Error & { status?: number; stderr?: string; stdout?: string };
    }
    expect(err.status).toBe(1);
    expect(err.stderr ?? "").toMatch(/Invalid npub/i);
    expect(err.stdout ?? "").not.toContain("Trust Proof Demo");
  }, 90_000);
});

// ─── R2: real NIP-01 event envelope ────────────────────────────

describe("NIP-01 signed envelope (R2)", () => {
  // Static ring fixture: 5 maker keys, exactly like the demo's own ring.
  const keys = Array.from({ length: 5 }, () => generateKeyPair());
  const ringHex = keys.map((k) => bytesToHex(k.publicKey));
  const names = ["Alice", "Bob", "Carol", "Dave", "Erin"];
  const offerId = randomBytes(8).toString("hex");
  const content = JSON.stringify({ msg: "I am a trusted code provider for bitblik" });

  // Fresh ephemeral publisher per test — mirrors "per demo run".
  let publisher: ReturnType<typeof generatePublisher>;

  beforeEach(() => {
    publisher = generatePublisher();
  });

  function build() {
    return buildNostrEvent(publisher, ringHex, names, offerId, content);
  }

  it("sig is present (128 hex chars = 64 BIP-340 bytes) and schnorr.verify(sig, id, pubkey) passes", () => {
    const { event, id } = build();
    expect(event.sig).toMatch(/^[0-9a-f]{128}$/);
    expect(schnorr.verify(hexToBytes(event.sig), hexToBytes(id), event.pubkey)).toBe(true);
  });

  it("id equals canonical sha256 over [0,pubkey,created_at,kind,tags,content]", () => {
    const { event, id } = build();
    const serialized = JSON.stringify([
      0, event.pubkey, event.created_at, event.kind, event.tags, event.content,
    ]);
    expect(id).toBe(bytesToHex(sha256(new TextEncoder().encode(serialized))));
    expect(event.id).toBe(id);
  });

  it("d tag present: ['d', offerId] (kind 30221 is parameterized-replaceable)", () => {
    const { event } = build();
    expect(event.tags).toContainEqual(["d", offerId]);
  });

  it("pubkey is the EPHEMERAL publisher — not a ring member", () => {
    const { event } = build();
    expect(event.pubkey).toBe(publisher.pubkey);
    // Neither the full compressed hex nor the x-only form of any ring
    // member may appear as the event pubkey.
    for (const pk of ringHex) {
      expect(event.pubkey).not.toBe(pk);
      expect(event.pubkey).not.toBe(pk.slice(2));
    }
  });

  it("ring pubkeys carried as hex tag + names tag for display", () => {
    const { event } = build();
    expect(event.tags).toContainEqual(["ring", ...ringHex]);
    expect(event.tags).toContainEqual(["names", ...names]);
  });

  it("generatePublisher returns a fresh keypair on every call", () => {
    const a = generatePublisher();
    const b = generatePublisher();
    expect(a.pubkey).toMatch(/^[0-9a-f]{64}$/);
    expect(a.pubkey).not.toBe(b.pubkey);
    expect(bytesToHex(a.secretKey)).not.toBe(bytesToHex(b.secretKey));
  });

  it("demo narration: envelope schnorr-signed by EPHEMERAL publisher", async () => {
    const out = await captureMainOutput([]);
    expect(out).toContain("EPHEMERAL publisher");
    expect(out).toContain("relay never learns which ring member signed");
  }, 30_000);

  it("R1 relay accepts the signed event over a real socket: ['OK', id, true]", async () => {
    const { event } = build();
    const relay = await startRelay({ port: 0 });
    try {
      const ok = await new Promise<unknown[]>((resolve, reject) => {
        const ws = new WebSocket(`ws://127.0.0.1:${relay.port}`);
        const timer = setTimeout(
          () => reject(new Error("timeout waiting for OK")),
          5_000,
        );
        ws.once("open", () => ws.send(JSON.stringify(["EVENT", event])));
        ws.once("error", (err: Error) => {
          clearTimeout(timer);
          reject(err);
        });
        ws.on("message", (data: unknown) => {
          clearTimeout(timer);
          ws.terminate();
          resolve(JSON.parse(String(data)) as unknown[]);
        });
      });
      expect(ok[0]).toBe("OK");
      expect(ok[1]).toBe(event.id);
      expect(ok[2]).toBe(true);
    } finally {
      await relay.close();
    }
  }, 10_000);
});

// ─── R3: --relay mode (real WS transport, DEFAULT ON) ──────────

describe("relay mode flag parsing (R3)", () => {
  it("relay is DEFAULT ON: no flags → relay mode", () => {
    expect(parseRelayMode([])).toBe(true);
  });

  it("--offline disables the relay transport", () => {
    expect(parseRelayMode(["--offline"])).toBe(false);
  });

  it("--relay is explicit (same as the default)", () => {
    expect(parseRelayMode(["--relay", "--quick"])).toBe(true);
  });

  it("--offline wins when both flags are given", () => {
    expect(parseRelayMode(["--relay", "--offline"])).toBe(false);
  });
});

describe("relay transport (R3, in-process)", () => {
  it("default run: 'relay: ws://localhost:<port> — REAL Nostr transport' + relay-echoed id + all checks pass", async () => {
    const out = await captureMainOutput([]);
    expect(out).toMatch(/relay: ws:\/\/localhost:\d+ — REAL Nostr transport/);
    expect(out).toContain("relay-echoed event id");
    expect(out).toContain("ALL SECURITY CHECKS PASSED");
    expect(out).not.toContain("[!] relay unavailable");
  }, 30_000);

  it("maker verifies the proof rebuilt FROM EVENT TAGS received over the wire", async () => {
    const out = await captureMainOutput([]);
    expect(out).toContain("REQ {kinds:[30221]}");
    expect(out).toContain("over the wire");
    expect(out).toContain("ring rebuilt from event tags");
    expect(out).toContain("Signature is valid");
  }, 30_000);

  it("--offline: old print-only path — no relay lines, no fallback warning, demo completes", async () => {
    const out = await captureMainOutput(["--offline"]);
    expect(out).not.toContain("relay: ws://");
    expect(out).not.toContain("[!] relay unavailable");
    expect(out).toContain("0. The roles");
    expect(out).toContain("Demo complete.");
  }, 30_000);

  it("forced bad port (TRUST_DEMO_RELAY_PORT): '[!] relay unavailable, offline mode' + demo completes", async () => {
    // 65536 is outside the valid TCP port range → the bind fails fast and
    // deterministically (never a privilege-dependent error).
    process.env.TRUST_DEMO_RELAY_PORT = "65536";
    try {
      const out = await captureMainOutput([]);
      expect(out).toContain("[!] relay unavailable, offline mode");
      expect(out).not.toContain("relay: ws://localhost:");
      expect(out).toContain("Demo complete.");
    } finally {
      delete process.env.TRUST_DEMO_RELAY_PORT;
    }
  }, 30_000);

  it("port already held by a relay (EADDRINUSE) → demo connects to it externally", async () => {
    // Hold an ephemeral port with OUR relay, point the demo at it via the
    // env override, and check the demo treats it as a standalone relay.
    const external = await startRelay({ port: 0 });
    try {
      process.env.TRUST_DEMO_RELAY_PORT = String(external.port);
      const out = await captureMainOutput([]);
      expect(out).toContain(`relay: ws://localhost:${external.port} — REAL Nostr transport`);
      expect(out).toContain("relay-echoed event id");
      expect(out).not.toContain("[!] relay unavailable");
    } finally {
      delete process.env.TRUST_DEMO_RELAY_PORT;
      await external.close();
    }
  }, 30_000);

  it("port squatted by a non-WS server → 3s deadline → offline fallback, never stalls", async () => {
    const dumb = net.createServer(() => {
      /* accept TCP connections but never speak the WS handshake */
    });
    await new Promise<void>((res) => dumb.listen(0, "127.0.0.1", res));
    const squatPort = (dumb.address() as net.AddressInfo).port;
    try {
      process.env.TRUST_DEMO_RELAY_PORT = String(squatPort);
      const t0 = Date.now();
      const out = await captureMainOutput([]);
      expect(out).toContain("[!] relay unavailable, offline mode");
      expect(out).toContain("Demo complete.");
      // bounded: the 3s WS deadline plus the demo itself — never a hang
      expect(Date.now() - t0).toBeLessThan(15_000);
    } finally {
      delete process.env.TRUST_DEMO_RELAY_PORT;
      dumb.close();
    }
  }, 60_000);
});

describe("CLI end-to-end (R3 relay mode)", () => {
  it("default run (relay ON): exit 0 + 'relay:' line + relay-echoed id — REAL transport", () => {
    const out = execFileSync(TSX_BIN, ["src/demo.ts", "--quick"], {
      cwd: PKG_DIR,
      encoding: "utf8",
      timeout: 60_000,
    });
    expect(out).toMatch(/relay: ws:\/\/localhost:\d+ — REAL Nostr transport/);
    expect(out).toContain("relay-echoed event id");
    expect(out).not.toContain("[!] relay unavailable");
  }, 90_000);

  it("--offline run: exit 0, no relay lines, old print-only path", () => {
    const out = execFileSync(TSX_BIN, ["src/demo.ts", "--offline", "--quick"], {
      cwd: PKG_DIR,
      encoding: "utf8",
      timeout: 60_000,
    });
    expect(out).not.toContain("relay: ws://");
    expect(out).not.toContain("[!] relay unavailable");
    expect(out).toContain("Demo complete.");
  }, 90_000);
});

// ─── B2: canonical trade-binding message ───────────────────────

describe("B2: canonical trade-binding message", () => {
  const keys = Array.from({ length: 4 }, () => generateKeyPair());
  const ring = keys.map((k) => k.publicKey);
  const ringHashHex = bytesToHex(
    sha256(new Uint8Array(Buffer.concat(ring.map((pk) => Buffer.from(pk))))),
  );

  async function demoExports() {
    const mod = (await import("./demo.js")) as unknown as Record<string, unknown>;
    return mod;
  }

  it("demo exports ringHash(): sha256 over the ORDERED concat of ring pubkeys", async () => {
    const mod = await demoExports();
    expect(typeof mod.ringHash).toBe("function");
    const ringHash = mod.ringHash as (r: Uint8Array[]) => string;
    expect(ringHash(ring)).toBe(ringHashHex);
    // ring order is binding: swapping two members changes the hash
    const swapped = [ring[1], ring[0], ring[2], ring[3]];
    expect(ringHash(swapped)).not.toBe(ringHashHex);
  });

  it("buildBindingMessage(): sha256 over lexicographic canonical JSON, no whitespace", async () => {
    const mod = await demoExports();
    expect(typeof mod.buildBindingMessage).toBe("function");
    const buildBindingMessage = mod.buildBindingMessage as (b: {
      amount: string;
      makerNonce: string;
      offerId: string;
      ringHash: string;
    }) => Uint8Array;
    const canonical =
      `{"amount":"50000","maker_nonce":"aabbccddeeff0011",` +
      `"offer_id":"1122334455667788","ring_hash":"${ringHashHex}",` +
      `"type":"bitblik.trust-proof","v":1}`;
    const digest = buildBindingMessage({
      amount: "50000",
      makerNonce: "aabbccddeeff0011",
      offerId: "1122334455667788",
      ringHash: ringHashHex,
    });
    expect(digest).toHaveLength(32); // the message IS the sha256 digest
    expect(bytesToHex(digest)).toBe(
      bytesToHex(sha256(new TextEncoder().encode(canonical))),
    );
  });

  it("every binding field changes the message — each field is signed", async () => {
    const mod = await demoExports();
    const buildBindingMessage = mod.buildBindingMessage as (b: {
      amount: string;
      makerNonce: string;
      offerId: string;
      ringHash: string;
    }) => Uint8Array;
    const base = {
      amount: "50000",
      makerNonce: "aabbccddeeff0011",
      offerId: "1122334455667788",
      ringHash: ringHashHex,
    };
    const digest = bytesToHex(buildBindingMessage(base));
    for (const mutated of [
      { ...base, amount: "50001" },
      { ...base, makerNonce: "aabbccddeeff0012" },
      { ...base, offerId: "1122334455667789" },
      { ...base, ringHash: "00".repeat(32) },
    ]) {
      expect(bytesToHex(buildBindingMessage(mutated))).not.toBe(digest);
    }
  });

  it("demo output carries the binding (type bitblik.trust-proof) in the event", async () => {
    const out = await captureMainOutput([]);
    expect(out).toContain("bitblik.trust-proof");
  }, 30_000);

  it("demo output no longer claims tx_id binding — tx_id is a Phase-2 concept", async () => {
    const out = await captureMainOutput([]);
    expect(out).not.toContain("tx_id");
  }, 30_000);

  it("proofFromWireEvent rebuilds the message from the carried binding", async () => {
    const mod = await demoExports();
    const buildBindingMessage = mod.buildBindingMessage as (b: {
      amount: string;
      makerNonce: string;
      offerId: string;
      ringHash: string;
    }) => Uint8Array;

    const binding = {
      amount: "21000",
      makerNonce: randomBytes(8).toString("hex"),
      offerId: randomBytes(8).toString("hex"),
      ringHash: ringHashHex,
    };
    const message = buildBindingMessage(binding);
    const sig = sign(message, ring, 1, keys[1].secretKey);
    expect(verify(message, ring, sig)).toBe(true);

    const { event } = buildNostrEvent(
      generatePublisher(),
      ring.map((pk) => bytesToHex(pk)),
      ["a", "b", "c", "d"],
      binding.offerId,
      JSON.stringify({
        binding: {
          amount: binding.amount,
          maker_nonce: binding.makerNonce,
          offer_id: binding.offerId,
          ring_hash: binding.ringHash,
          type: "bitblik.trust-proof",
          v: 1,
        },
        keyImage: bytesToHex(sig.keyImage),
        c0: bytesToHex(sig.c0),
        responses: sig.responses.map((r) => bytesToHex(r)),
      }),
    );

    const parsed = proofFromWireEvent(event);
    expect(Buffer.from(parsed.message).toString("hex")).toBe(
      Buffer.from(message).toString("hex"),
    );
    expect(verify(parsed.message, parsed.ring, parsed.sig)).toBe(true);
  });
});
