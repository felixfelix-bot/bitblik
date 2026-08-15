import { describe, it, expect } from "vitest";
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { generateKeyPair, hashToCurve, sign, verify } from "./lsag.js";
import type { LSAGSignature } from "./lsag.js";
import { secp256k1 } from "@noble/curves/secp256k1";
import { bytesToNumberBE } from "@noble/curves/abstract/utils";
import { sha256 } from "@noble/hashes/sha256";

/**
 * T3 cross-implementation test vectors.
 *
 * Direction 1 (Python → TS): tools/lsag_ref.py is an independent,
 * pure-stdlib Python reimplementation of LSAG/v2. It emits
 * vectors/lsag-vectors.json; this suite feeds every vector to the
 * TypeScript verify() and requires agreement with the `expected` field.
 *
 * Direction 2 (TS → Python): this suite signs fresh vectors with the
 * TypeScript sign(), writes them to a temp JSON file, and requires
 * `python3 tools/lsag_ref.py verify --file <tmp>` to agree with every
 * `expected` field. Both implementations were written against the same
 * spec but neither shares code with the other.
 */

const enc = new TextEncoder();
const N = secp256k1.CURVE.n;
const here = dirname(fileURLToPath(import.meta.url));
const VECTORS_PATH = join(here, "..", "vectors", "lsag-vectors.json");
const LSAG_REF = join(here, "..", "tools", "lsag_ref.py");

type Tamper = "message" | "response" | "keyImage" | null;

interface VectorJson {
  id: string;
  message_hex: string;
  ring: string[]; // 33-byte compressed pubkeys, hex
  signer_index: number;
  secret_key_hex: string;
  key_image_hex: string;
  c0_hex: string;
  responses: string[]; // 32-byte scalars, hex
  expected: "valid" | "invalid";
  tamper: Tamper;
}

interface VectorsDoc {
  v: number;
  scheme: string;
  vectors: VectorJson[];
}

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

/** Deterministic key pair for the TS-emitted vectors (sha256-derived). */
function tsKey(i: number): { secretKey: Uint8Array; publicKey: Uint8Array } {
  const secretKey = sha256(enc.encode(`bitblik/t3-ts/key/${i}`));
  const publicKey = secp256k1.getPublicKey(secretKey, true);
  return { secretKey, publicKey };
}

/** Flip one bit of the last byte of a hex scalar, keeping it 32 bytes. */
function flipLastBitHex(h: string): string {
  const b = hexToBytes(h);
  b[b.length - 1] ^= 0x01;
  return bytesToHex(b);
}

/** Build the TS-signed vector set: 5 valid + 3 tampered invalid. */
function buildTsVectors(): VectorJson[] {
  const specs: Array<{ id: string; ringSize: number; signer: number; msg: string }> = [
    { id: "ts-ring4-s1", ringSize: 4, signer: 1, msg: "t3 ts vector 0: cross-impl round trip" },
    { id: "ts-ring5-s3", ringSize: 5, signer: 3, msg: "t3 ts vector 1: trust-proof" },
    { id: "ts-ring6-s0", ringSize: 6, signer: 0, msg: "t3 ts vector 2: LSAG/v2" },
    { id: "ts-ring8-s5", ringSize: 8, signer: 5, msg: "t3 ts vector 3: independence both directions" },
    { id: "ts-ring4-s3", ringSize: 4, signer: 3, msg: "t3 ts vector 4: final valid case" },
  ];

  const vectors: VectorJson[] = [];

  for (const spec of specs) {
    const keys = Array.from({ length: spec.ringSize }, (_, i) => tsKey(i + spec.ringSize * 7));
    const ring = keys.map((k) => k.publicKey);
    const message = enc.encode(spec.msg);
    const sig = sign(message, ring, spec.signer, keys[spec.signer].secretKey);
    vectors.push({
      id: spec.id,
      message_hex: bytesToHex(message),
      ring: ring.map(bytesToHex),
      signer_index: spec.signer,
      secret_key_hex: bytesToHex(keys[spec.signer].secretKey),
      key_image_hex: bytesToHex(sig.keyImage),
      c0_hex: bytesToHex(sig.c0),
      responses: sig.responses.map(bytesToHex),
      expected: "valid",
      tamper: null,
    });
  }

  // Tampered message: signature made on message A, verified against B.
  {
    const keys = Array.from({ length: 4 }, (_, i) => tsKey(100 + i));
    const ring = keys.map((k) => k.publicKey);
    const sig = sign(enc.encode("t3 ts tamper: original message"), ring, 2, keys[2].secretKey);
    vectors.push({
      id: "ts-ring4-s2-tampered-message",
      message_hex: bytesToHex(enc.encode("t3 ts tamper: TAMPERED message")),
      ring: ring.map(bytesToHex),
      signer_index: 2,
      secret_key_hex: bytesToHex(keys[2].secretKey),
      key_image_hex: bytesToHex(sig.keyImage),
      c0_hex: bytesToHex(sig.c0),
      responses: sig.responses.map(bytesToHex),
      expected: "invalid",
      tamper: "message",
    });
  }

  // Tampered response: one bit flipped in responses[signer_index].
  {
    const keys = Array.from({ length: 5 }, (_, i) => tsKey(200 + i));
    const ring = keys.map((k) => k.publicKey);
    const message = enc.encode("t3 ts tamper: response");
    const sig = sign(message, ring, 1, keys[1].secretKey);
    const responses = sig.responses.map(bytesToHex);
    responses[1] = flipLastBitHex(responses[1]);
    vectors.push({
      id: "ts-ring5-s1-tampered-response",
      message_hex: bytesToHex(message),
      ring: ring.map(bytesToHex),
      signer_index: 1,
      secret_key_hex: bytesToHex(keys[1].secretKey),
      key_image_hex: bytesToHex(sig.keyImage),
      c0_hex: bytesToHex(sig.c0),
      responses,
      expected: "invalid",
      tamper: "response",
    });
  }

  // Tampered key image: I' = (x_s + 1) * H(P_s) — a valid point, but wrong.
  {
    const keys = Array.from({ length: 6 }, (_, i) => tsKey(300 + i));
    const ring = keys.map((k) => k.publicKey);
    const message = enc.encode("t3 ts tamper: key image");
    const sig = sign(message, ring, 4, keys[4].secretKey);
    const x_s = bytesToNumberBE(keys[4].secretKey) % N;
    const wrongImage = secp256k1.Point.fromBytes(hashToCurve(ring[4]))
      .multiply((x_s + 1n) % N)
      .toBytes();
    vectors.push({
      id: "ts-ring6-s4-tampered-key-image",
      message_hex: bytesToHex(message),
      ring: ring.map(bytesToHex),
      signer_index: 4,
      secret_key_hex: bytesToHex(keys[4].secretKey),
      key_image_hex: bytesToHex(wrongImage),
      c0_hex: bytesToHex(sig.c0),
      responses: sig.responses.map(bytesToHex),
      expected: "invalid",
      tamper: "keyImage",
    });
  }

  return vectors;
}

function writeVectorsDoc(path: string, vectors: VectorJson[]): void {
  const doc: VectorsDoc = { v: 1, scheme: "LSAG/v2", vectors };
  writeFileSync(path, JSON.stringify(doc, null, 2) + "\n", "utf8");
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
      const x_s = bytesToNumberBE(hexToBytes(v.secret_key_hex)) % N;
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
