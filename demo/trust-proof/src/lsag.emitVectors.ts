/**
 * TS-side vector emitter for the T3 cross-implementation suite.
 *
 * buildTsVectors() signs a fixed set of LSAG/v2 vectors with src/lsag.ts
 * (5 valid + 3 tampered: message / response / key image). The suite in
 * src/lsag.vectors.test.ts writes these to a temp JSON file and requires
 * the independent pure-Python reference (tools/lsag_ref.py) to classify
 * every one of them correctly.
 *
 * Runnable standalone for manual cross-checks:
 *
 *   npm run vectors:emit            # writes vectors/ts-emitted-vectors.json
 *   npm run vectors:crosscheck      # emit + python3 tools/lsag_ref.py verify
 */

import { writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { sign, hashToCurve } from "./lsag.js";
import { secp256k1 } from "@noble/curves/secp256k1";
import { bytesToNumberBE } from "@noble/curves/abstract/utils";
import { sha256 } from "@noble/hashes/sha256";

const enc = new TextEncoder();
const N = secp256k1.CURVE.n;

export type Tamper = "message" | "response" | "keyImage" | null;

export interface VectorJson {
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

export interface VectorsDoc {
  v: number;
  scheme: string;
  vectors: VectorJson[];
}

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
export function buildTsVectors(): VectorJson[] {
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

export function writeVectorsDoc(path: string, vectors: VectorJson[]): void {
  const doc: VectorsDoc = { v: 1, scheme: "LSAG/v2", vectors };
  writeFileSync(path, JSON.stringify(doc, null, 2) + "\n", "utf8");
}

// CLI entry (tsx src/lsag.emitVectors.ts [out.json]) — inert under vitest.
const here = dirname(fileURLToPath(import.meta.url));
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const out = process.argv[2] ?? join(here, "..", "vectors", "ts-emitted-vectors.json");
  const vectors = buildTsVectors();
  writeVectorsDoc(out, vectors);
  const valid = vectors.filter((v) => v.expected === "valid").length;
  console.log(`emitted ${vectors.length} vectors (${valid} valid, ${vectors.length - valid} invalid) to ${out}`);
}
