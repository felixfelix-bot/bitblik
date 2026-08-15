import { describe, it, expect } from "vitest";
import { mkdtemp, readFile, writeFile, rm, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  BLOCKLIST_FILE_VERSION,
  isValidKeyImageHex,
  normalizeKeyImageHex,
  loadKeyImageBlocklist,
  isKeyImageBlocked,
  blockKeyImage,
} from "./blocklist.js";

// ─── Helpers ───────────────────────────────────────────────────

const PKG_DIR = fileURLToPath(new URL("..", import.meta.url));
const TSX_BIN = path.join(PKG_DIR, "node_modules", ".bin", "tsx");

/**
 * A random but perfectly valid key image — a 33-byte compressed secp256k1
 * point in hex, exactly like the demo's `hex(sig.keyImage)` produces.
 */
function fakeKeyImage(): string {
  const prefix = Math.random() < 0.5 ? "02" : "03";
  return prefix + randomBytes(32).toString("hex");
}

async function tmpBlocklistPath(): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), "blocklist-test-"));
  return path.join(dir, "blocklist.json");
}

// ─── key image hex validation ──────────────────────────────────

describe("isValidKeyImageHex", () => {
  it("accepts 66-char lowercase hex (compressed point)", () => {
    expect(isValidKeyImageHex(fakeKeyImage())).toBe(true);
  });

  it("accepts 66-char uppercase hex (case-insensitive input)", () => {
    expect(isValidKeyImageHex(fakeKeyImage().toUpperCase())).toBe(true);
  });

  it("rejects short, long, empty, non-hex, and non-point strings", () => {
    expect(isValidKeyImageHex("ab")).toBe(false);
    expect(isValidKeyImageHex(fakeKeyImage() + "ff")).toBe(false);
    expect(isValidKeyImageHex(fakeKeyImage().slice(0, 65))).toBe(false);
    expect(isValidKeyImageHex("")).toBe(false);
    expect(isValidKeyImageHex("g".repeat(66))).toBe(false);
    // 32-byte x-only (64 hex) is NOT a key image — the point is 33 bytes
    expect(isValidKeyImageHex(randomBytes(32).toString("hex"))).toBe(false);
    // uncompressed-point prefix 04 is not accepted either
    expect(isValidKeyImageHex("04" + "a".repeat(64))).toBe(false);
  });
});

describe("normalizeKeyImageHex", () => {
  it("lowercases valid input", () => {
    const k = fakeKeyImage();
    expect(normalizeKeyImageHex(k.toUpperCase())).toBe(k);
  });

  it("throws a clear error for invalid input", () => {
    expect(() => normalizeKeyImageHex("nothex")).toThrow(/Invalid key image/i);
  });

  it("empty string input is handled, not crashed on", () => {
    expect(() => normalizeKeyImageHex("")).toThrow(/Invalid key image \(empty\)/);
  });
});

// ─── persistence (JSON file) ───────────────────────────────────

describe("loadKeyImageBlocklist", () => {
  it("missing file → empty list, and does not create the file", async () => {
    const p = await tmpBlocklistPath();
    await expect(loadKeyImageBlocklist(p)).resolves.toEqual([]);
    await expect(readFile(p, "utf8")).rejects.toThrow(); // still absent
  });

  it("reads back what blockKeyImage persisted", async () => {
    const p = await tmpBlocklistPath();
    const k = fakeKeyImage();
    await blockKeyImage(p, k);
    await expect(loadKeyImageBlocklist(p)).resolves.toEqual([k]);
  });

  it("malformed JSON file → throws (fail loud, never silently empty)", async () => {
    const p = await tmpBlocklistPath();
    await writeFile(p, "{not json", "utf8");
    await expect(loadKeyImageBlocklist(p)).rejects.toThrow(/blocklist/i);
  });

  it("wrong schema version → throws", async () => {
    const p = await tmpBlocklistPath();
    await writeFile(p, JSON.stringify({ v: 99, blocked: [] }), "utf8");
    await expect(loadKeyImageBlocklist(p)).rejects.toThrow(/version/i);
  });

  it("corrupt entry (not a 66-hex point) inside the file → throws", async () => {
    const p = await tmpBlocklistPath();
    await writeFile(p, JSON.stringify({ v: 1, blocked: ["ab"] }), "utf8");
    await expect(loadKeyImageBlocklist(p)).rejects.toThrow(/blocklist/i);
  });

  it("non-array `blocked` field → throws", async () => {
    const p = await tmpBlocklistPath();
    await writeFile(p, JSON.stringify({ v: 1, blocked: "nope" }), "utf8");
    await expect(loadKeyImageBlocklist(p)).rejects.toThrow(/blocklist/i);
  });

  it("unreadable file (EACCES) → the read error propagates (not treated as empty)", async () => {
    const p = await tmpBlocklistPath();
    await writeFile(p, JSON.stringify({ v: 1, blocked: [] }), "utf8");
    await chmod(p, 0o000);
    try {
      await expect(loadKeyImageBlocklist(p)).rejects.toThrow();
    } finally {
      await chmod(p, 0o644);
    }
  });
});

describe("blockKeyImage", () => {
  it("persists the exact JSON document shape {v:1, blocked:[keyImage]}", async () => {
    const p = await tmpBlocklistPath();
    const k = fakeKeyImage();
    await blockKeyImage(p, k);
    const doc = JSON.parse(await readFile(p, "utf8")) as { v: number; blocked: string[] };
    expect(doc.v).toBe(BLOCKLIST_FILE_VERSION);
    expect(doc.v).toBe(1);
    expect(doc.blocked).toEqual([k]);
  });

  it("is idempotent — blocking the same key twice does not duplicate it", async () => {
    const p = await tmpBlocklistPath();
    const k = fakeKeyImage();
    await blockKeyImage(p, k);
    await blockKeyImage(p, k);
    await expect(loadKeyImageBlocklist(p)).resolves.toEqual([k]);
  });

  it("preserves previously persisted entries (load-merge-save)", async () => {
    const p = await tmpBlocklistPath();
    const a = fakeKeyImage();
    const b = fakeKeyImage();
    await blockKeyImage(p, a);
    await blockKeyImage(p, b);
    const entries = await loadKeyImageBlocklist(p);
    expect(entries).toEqual([a, b]);
  });

  it("normalizes input to lowercase before persisting", async () => {
    const p = await tmpBlocklistPath();
    const k = fakeKeyImage();
    await blockKeyImage(p, k.toUpperCase());
    await expect(loadKeyImageBlocklist(p)).resolves.toEqual([k]);
  });

  it("throws on invalid key image — never persists garbage", async () => {
    const p = await tmpBlocklistPath();
    await expect(blockKeyImage(p, "short")).rejects.toThrow(/Invalid key image/i);
    const entries = await loadKeyImageBlocklist(p);
    expect(entries).toEqual([]);
  });
});

describe("isKeyImageBlocked", () => {
  it("false for a fresh (empty) blocklist", async () => {
    const p = await tmpBlocklistPath();
    await expect(isKeyImageBlocked(p, fakeKeyImage())).resolves.toBe(false);
  });

  it("true only for the persisted key image", async () => {
    const p = await tmpBlocklistPath();
    const k = fakeKeyImage();
    await blockKeyImage(p, k);
    await expect(isKeyImageBlocked(p, k)).resolves.toBe(true);
    await expect(isKeyImageBlocked(p, fakeKeyImage())).resolves.toBe(false);
  });

  it("matches case-insensitively (same key image, uppercase query)", async () => {
    const p = await tmpBlocklistPath();
    const k = fakeKeyImage();
    await blockKeyImage(p, k);
    await expect(isKeyImageBlocked(p, k.toUpperCase())).resolves.toBe(true);
  });

  it("throws on invalid input key image", async () => {
    const p = await tmpBlocklistPath();
    await expect(isKeyImageBlocked(p, "zz")).rejects.toThrow(/Invalid key image/i);
  });
});

// ─── concurrent access (atomicity of the persist) ──────────────

describe("concurrent access", () => {
  it("parallel writers + a reader loop never observe a torn file", async () => {
    const p = await tmpBlocklistPath();
    const keys = Array.from({ length: 8 }, () => fakeKeyImage());

    // Reader hammer: for 500ms, load the file over and over. It must
    // NEVER throw — the file on disk is always a complete document
    // (old or new), never a partially-written one.
    const reader = (async () => {
      const deadline = Date.now() + 500;
      while (Date.now() < deadline) {
        await loadKeyImageBlocklist(p);
      }
    })();

    // Writers hammer: 8 concurrent blockKeyImage calls, exactly like
    // parallel demo runs sharing one blocklist file.
    await Promise.all([
      ...keys.map((k) => blockKeyImage(p, k)),
      reader,
    ]);

    const final = await loadKeyImageBlocklist(p);
    expect(final.length).toBeGreaterThanOrEqual(1);
    expect(final.length).toBeLessThanOrEqual(keys.length);
    for (const k of final) {
      expect(isValidKeyImageHex(k)).toBe(true);
    }
  }, 15_000);
});

// ─── cross-process persistence (T2 acceptance) ─────────────────

describe("persistence survives a fresh process", () => {
  it("a spawned process reading the file sees the blocked key image", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "blocklist-xproc-"));
    const p = path.join(dir, "blocklist.json");
    const known = fakeKeyImage();
    const other = fakeKeyImage();

    // Writer: THIS vitest worker process.
    await blockKeyImage(p, known);

    // Reader: a FRESH tsx process (new module registry, new everything)
    // that imports the real module and reads the same file.
    const blocklistUrl = pathToFileURL(
      path.join(PKG_DIR, "src", "blocklist.ts"),
    ).href;
    const readerPath = path.join(dir, "reader.mts");
    await writeFile(
      readerPath,
      [
        `import { loadKeyImageBlocklist, isKeyImageBlocked } from ${JSON.stringify(blocklistUrl)};`,
        "async function run() {",
        "  const [file, knownArg, otherArg] = process.argv.slice(2);",
        "  const entries = await loadKeyImageBlocklist(file);",
        '  console.log("entries=" + entries.length);',
        '  console.log("known=" + ((await isKeyImageBlocked(file, knownArg)) ? "BLOCKED" : "CLEAN"));',
        '  console.log("other=" + ((await isKeyImageBlocked(file, otherArg)) ? "BLOCKED" : "CLEAN"));',
        "}",
        "run();",
        "",
      ].join("\n"),
      "utf8",
    );

    const out = execFileSync(TSX_BIN, [readerPath, p, known, other], {
      cwd: PKG_DIR,
      encoding: "utf8",
      timeout: 60_000,
    });
    expect(out).toContain("entries=1");
    expect(out).toContain("known=BLOCKED");
    expect(out).toContain("other=CLEAN");

    await rm(dir, { recursive: true, force: true });
  }, 90_000);
});
