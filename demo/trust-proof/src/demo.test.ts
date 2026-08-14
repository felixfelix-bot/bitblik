import { describe, it, expect, vi, afterEach } from "vitest";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { bech32 } from "@scure/base";
import { secp256k1 } from "@noble/curves/secp256k1";
import {
  main,
  parseArgs,
  pause,
  decodeNpub,
  npubToRingPubkey,
  parseNpubArgs,
} from "./demo.js";
import { generateKeyPair, sign, verify } from "./lsag.js";

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

function captureMainOutput(argv: string[]): string {
  const logs: string[] = [];
  const spy = vi.spyOn(console, "log").mockImplementation((...a: unknown[]) => {
    logs.push(a.map(String).join(" "));
  });
  try {
    main(argv);
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
  it("main is a function and does not throw", () => {
    expect(typeof main).toBe("function");
    expect(() => main()).not.toThrow();
  });
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
  function captureMainOutput(opts: {
    interactive: boolean;
    quick: boolean;
  }): string {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    main({ ...opts, waitForKey: () => {} });
    return log.mock.calls.map((args) => args.join(" ")).join("\n");
  }

  it("no flags: full security check details shown, no pause prompt", () => {
    const out = captureMainOutput({ interactive: false, quick: false });
    expect(out).toContain("5. Security checks");
    expect(out).toContain("5a. Wrong secret key");
    expect(out).toContain("5b. Tampered message");
    expect(out).toContain("5c. Tampered response");
    expect(out).toContain("5d. Tampered key image");
    expect(out).not.toContain("[Enter] to continue...");
    expect(out).not.toContain("All 4 security checks passed");
  });

  it("--quick: security checks collapse to a single summary line", () => {
    const out = captureMainOutput({ interactive: false, quick: true });
    expect(out).toContain("All 4 security checks passed: ✅");
    expect(out).not.toContain("5a. Wrong secret key");
    expect(out).not.toContain("5b. Tampered message");
    expect(out).not.toContain("5c. Tampered response");
    expect(out).not.toContain("5d. Tampered key image");
  });

  it("--interactive: pause prompt after each of the 6 section headers", () => {
    const out = captureMainOutput({ interactive: true, quick: false });
    expect(out.match(/\[Enter\] to continue\.\.\./g)?.length).toBe(6);
  });

  it("--interactive: injected waitForKey is called once per section", () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const waitForKey = vi.fn();
    main({ interactive: true, quick: false, waitForKey });
    expect(waitForKey).toHaveBeenCalledTimes(6);
  });

  it("combined --interactive --quick works", () => {
    const out = captureMainOutput({ interactive: true, quick: true });
    expect(out).toContain("[Enter] to continue...");
    expect(out).toContain("All 4 security checks passed: ✅");
    expect(out).not.toContain("5a. Wrong secret key");
  });
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

  it("main output announces decoy count and grown ring size", () => {
    const out = captureMainOutput(["--npub", npubA, npubB]);
    expect(out).toContain("Participant npubs added as decoys: 2");
    expect(out).toContain("Ring size: 7");
  });

  it("without --npub the output is unchanged (no decoy section, ring of 5)", () => {
    const out = captureMainOutput([]);
    expect(out).not.toContain("Participant npubs");
    expect(out).toContain("Ring size: 5");
  });
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
