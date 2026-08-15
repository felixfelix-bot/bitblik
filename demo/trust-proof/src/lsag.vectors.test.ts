import { describe, it, expect } from "vitest";
import { readFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { verify, hashToCurve } from "./lsag.js";
import type { LSAGSignature } from "./lsag.js";
import { buildTsVectors, writeVectorsDoc } from "./lsag.emitVectors.js";
import type { VectorJson, VectorsDoc } from "./lsag.emitVectors.js";
import { secp256k1 } from "@noble/curves/secp256k1";
import { bytesToNumberBE } from "@noble/curves/abstract/utils";

/**
 * T3 cross-implementation test vectors.
 *
 * Direction 1 (Python → TS): tools/lsag_ref.py is an independent,
 * pure-stdlib Python reimplementation of LSAG/v2. It emits
 * vectors/lsag-vectors.json; this suite feeds every vector to the
 * TypeScript verify() and requires agreement with the `expected` field.
 *
 * Direction 2 (TS → Python): this suite signs fresh vectors with the
 * TypeScript sign() (see src/lsag.emitVectors.ts), writes them to a temp
 * JSON file, and requires `python3 tools/lsag_ref.py verify --file <tmp>`
 * to agree with every `expected` field. Both implementations were written
 * against the same spec but neither shares code with the other.
 */

const here = dirname(fileURLToPath(import.meta.url));
const VECTORS_PATH = join(here, "..", "vectors", "lsag-vectors.json");
const LSAG_REF = join(here, "..", "tools", "lsag_ref.py");

// ─── helpers ────────────────────────────────────────────────────

function bytesToHex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(h: string): Uint8Array {
  if (h.length % 2 !== 0) throw new Error(`odd-length hex: ${h}`);
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  }
  return out;
}

function sigFromVector(v: VectorJson): LSAGSignature {
  return {
    keyImage: hexToBytes(v.key_image_hex),
    c0: hexToBytes(v.c0_hex),
    responses: v.responses.map(hexToBytes),
  };
}

/** Lazily load + parse the python-generated vectors file (memoized). */
let cached: VectorsDoc | null = null;
function loadVectors(): VectorsDoc {
  if (cached === null) {
    cached = JSON.parse(readFileSync(VECTORS_PATH, "utf8")) as VectorsDoc;
  }
  return cached;
}

/** Flip one bit of the last byte of a hex scalar, keeping it 32 bytes. */
function flipLastBitHex(h: string): string {
  const b = hexToBytes(h);
  b[b.length - 1] ^= 0x01;
  return bytesToHex(b);
}

function runPythonRef(args: string[]): string {
  return execFileSync("python3", [LSAG_REF, ...args], { encoding: "utf8" });
}

// ─── direction 1: python-generated vectors → TS verify ─────────

describe("T3 vectors: python reference → TypeScript verify()", () => {
  it("vectors/lsag-vectors.json exists, parses, and declares LSAG/v2 v1", () => {
    expect(() => loadVectors()).not.toThrow();
    const doc = loadVectors();
    expect(doc.v).toBe(1);
    expect(doc.scheme).toBe("LSAG/v2");
  });

  it("contains >= 5 valid and >= 3 invalid vectors", () => {
    const doc = loadVectors();
    const valid = doc.vectors.filter((v) => v.expected === "valid");
    const invalid = doc.vectors.filter((v) => v.expected === "invalid");
    expect(valid.length).toBeGreaterThanOrEqual(5);
    expect(invalid.length).toBeGreaterThanOrEqual(3);
  });

  it("invalid vectors cover message, response, and keyImage tampering", () => {
    const tampers = new Set(
      loadVectors()
        .vectors.filter((v) => v.expected === "invalid")
        .map((v) => v.tamper),
    );
    expect(tampers.has("message")).toBe(true);
    expect(tampers.has("response")).toBe(true);
    expect(tampers.has("keyImage")).toBe(true);
  });

  it("every vector is structurally well-formed", () => {
    for (const v of loadVectors().vectors) {
      expect(v.id, `${v.id}: id`).toMatch(/^[a-z0-9-]+$/);
      expect(v.message_hex, `${v.id}: message_hex`).toMatch(/^([0-9a-f]{2})*$/);
      expect(v.ring.length, `${v.id}: ring size`).toBeGreaterThanOrEqual(4);
      for (const pk of v.ring) {
        expect(pk, `${v.id}: ring key`).toMatch(/^0[23][0-9a-f]{64}$/);
      }
      expect(v.signer_index, `${v.id}: signer_index`).toBeGreaterThanOrEqual(0);
      expect(v.signer_index, `${v.id}: signer_index`).toBeLessThan(v.ring.length);
      expect(v.secret_key_hex, `${v.id}: secret_key_hex`).toMatch(/^[0-9a-f]{64}$/);
      expect(v.key_image_hex, `${v.id}: key_image_hex`).toMatch(/^0[23][0-9a-f]{64}$/);
      expect(v.c0_hex, `${v.id}: c0_hex`).toMatch(/^[0-9a-f]{64}$/);
      expect(v.responses.length, `${v.id}: responses count`).toBe(v.ring.length);
      for (const r of v.responses) {
        expect(r, `${v.id}: response`).toMatch(/^[0-9a-f]{64}$/);
      }
      expect(["valid", "invalid"], `${v.id}: expected`).toContain(v.expected);
    }
  });

  it("TypeScript verify() agrees with every expected outcome", () => {
    for (const v of loadVectors().vectors) {
      const result = verify(
        hexToBytes(v.message_hex),
        v.ring.map(hexToBytes),
        sigFromVector(v),
      );
      expect(result, `vector ${v.id} (tamper=${v.tamper})`).toBe(v.expected === "valid");
    }
  });

  it("valid vectors are self-consistent: key image = x_s * H(P_s)", () => {
    for (const v of loadVectors().vectors.filter((x) => x.expected === "valid")) {
      const x_s = bytesToNumberBE(hexToBytes(v.secret_key_hex)) % secp256k1.CURVE.n;
      const pk = hexToBytes(v.ring[v.signer_index]);
      const expected = secp256k1.Point.fromBytes(hashToCurve(pk))
        .multiply(x_s)
        .toBytes();
      expect(bytesToHex(expected), `${v.id}: key image`).toBe(v.key_image_hex);
    }
  });
});

// ─── direction 2: TS-signed vectors → python reference ─────────

describe("T3 round-trip: TypeScript sign() → python reference verify", () => {
  it("python lsag_ref.py verifies the TS-generated vector file", () => {
    const vectors = buildTsVectors();
    const dir = mkdtempSync(join(tmpdir(), "bitblik-t3-"));
    const path = join(dir, "ts-emitted-vectors.json");
    writeVectorsDoc(path, vectors);

    const out = runPythonRef(["verify", "--file", path]);

    const total = vectors.length;
    const valid = vectors.filter((v) => v.expected === "valid").length;
    const invalid = total - valid;
    expect(out).toMatch(new RegExp(`${total}/${total} vectors OK`));
    expect(out).toContain(`${valid} valid`);
    expect(out).toContain(`${invalid} invalid`);
  });

  it("python verifier is not vacuous — a lying vector must fail", () => {
    const vectors = buildTsVectors();
    // Corrupt one response of a *valid* vector but keep expected:"valid".
    const victim = vectors.find((v) => v.expected === "valid")!;
    victim.responses[0] = flipLastBitHex(victim.responses[0]);

    const dir = mkdtempSync(join(tmpdir(), "bitblik-t3-"));
    const path = join(dir, "lying-vectors.json");
    writeVectorsDoc(path, vectors);

    let threw: unknown = null;
    try {
      runPythonRef(["verify", "--file", path]);
    } catch (e) {
      threw = e;
    }
    expect(threw).not.toBeNull();
    const err = threw as { status?: number; stdout?: string };
    expect(err.status).not.toBe(0);
    expect(err.stdout ?? "").toContain("MISMATCH");
  });
});
