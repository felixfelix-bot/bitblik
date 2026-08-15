import { describe, it, expect } from "vitest";
import { generateKeyPair, hashToCurve, sign, verify } from "./lsag.js";
import type { LSAGSignature } from "./lsag.js";
import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToNumberBE, numberToBytesBE } from "@noble/curves/abstract/utils";

const enc = new TextEncoder();
const N = secp256k1.CURVE.n;
const modN = (x: bigint): bigint => ((x % N) + N) % N;

// ─── B6 spec oracle: replica signer ────────────────────────────
// A self-contained reimplementation of LSAG signing, parameterized by the
// challenge-hash layout, used to pin the EXACT challenge construction:
//   domain = the hash's domain tag ("LSAG/v1" pre-hardening, "LSAG/v2" after)
//   fold   = whether every challenge (base + links) folds
//            (msg || ring || keyImage) ahead of the point components.
// If verify() accepts the ("LSAG/v2", fold=true) replica and rejects the
// ("LSAG/v1", fold=false) replica, the implementation matches the spec.

function replicaConcat(...arrays: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

/** sha256 over [domain, each item 4-byte-BE-length-prefixed], reduced mod n. */
function replicaHashToScalar(domain: string, items: Uint8Array[]): bigint {
  const parts: Uint8Array[] = [enc.encode(domain)];
  for (const it of items) {
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, it.length, false);
    parts.push(len, it);
  }
  return bytesToNumberBE(sha256(replicaConcat(...parts))) % N;
}

function replicaSign(
  message: Uint8Array,
  ring: Uint8Array[],
  s: number,
  secretKey: Uint8Array,
  opts: { domain: string; fold: boolean },
): LSAGSignature {
  const n = ring.length;
  const H = ring.map((pk) => hashToCurve(pk));
  const x_s = bytesToNumberBE(secretKey) % N;
  const I = secp256k1.Point.fromBytes(H[s]).multiply(x_s).toBytes();
  const ringBytes = replicaConcat(...ring);
  const challenge = (pts: Uint8Array[]): bigint =>
    opts.fold
      ? replicaHashToScalar(opts.domain, [message, ringBytes, I, ...pts])
      : replicaHashToScalar(opts.domain, [message, ...pts]);

  const responses: bigint[] = Array.from(
    { length: n },
    () => bytesToNumberBE(secp256k1.utils.randomSecretKey()) % N,
  );
  const r_s_random = responses[s];

  const challenges: bigint[] = new Array(n);
  let c = challenge([
    secp256k1.Point.BASE.multiply(r_s_random).toBytes(),
    secp256k1.Point.fromBytes(H[s]).multiply(r_s_random).toBytes(),
  ]);
  challenges[(s + 1) % n] = c;

  for (let step = 1; step < n; step++) {
    const i = (s + step) % n;
    const z1 = secp256k1.Point.BASE.multiply(responses[i])
      .add(secp256k1.Point.fromBytes(ring[i]).multiply(c));
    const z2 = secp256k1.Point.fromBytes(H[i]).multiply(responses[i])
      .add(secp256k1.Point.fromBytes(I).multiply(c));
    c = challenge([z1.toBytes(), z2.toBytes()]);
    challenges[(i + 1) % n] = c;
  }
  responses[s] = modN(r_s_random - x_s * c);

  return {
    keyImage: I,
    c0: numberToBytesBE(modN(challenges[0]), 32),
    responses: responses.map((r) => numberToBytesBE(modN(r), 32)),
  };
}

describe("generateKeyPair", () => {
  it("produces a 32-byte secret key and 33-byte compressed public key", () => {
    const { secretKey, publicKey } = generateKeyPair();
    expect(secretKey.length).toBe(32);
    expect(publicKey.length).toBe(33);
  });

  it("public key is a valid secp256k1 point", () => {
    const { publicKey } = generateKeyPair();
    expect(() => secp256k1.Point.fromBytes(publicKey).assertValidity()).not.toThrow();
  });

  it("generates different keys on each call", () => {
    const a = generateKeyPair();
    const b = generateKeyPair();
    expect(a.secretKey).not.toEqual(b.secretKey);
    expect(a.publicKey).not.toEqual(b.publicKey);
  });

  it("secret key corresponds to public key", () => {
    const { secretKey, publicKey } = generateKeyPair();
    const derived = secp256k1.getPublicKey(secretKey, true);
    expect(derived).toEqual(publicKey);
  });
});

describe("hashToCurve", () => {
  it("returns a valid curve point (33 bytes compressed)", () => {
    const point = hashToCurve(enc.encode("test"));
    expect(point.length).toBe(33);
    expect(() => secp256k1.Point.fromBytes(point).assertValidity()).not.toThrow();
  });

  it("is deterministic — same input produces same output", () => {
    const a = hashToCurve(enc.encode("hello"));
    const b = hashToCurve(enc.encode("hello"));
    expect(a).toEqual(b);
  });

  it("different inputs produce different outputs", () => {
    const a = hashToCurve(enc.encode("hello"));
    const b = hashToCurve(enc.encode("world"));
    expect(a).not.toEqual(b);
  });
});

describe("sign and verify", () => {
  it("verifies a valid signature (ring of 4)", () => {
    const keys = [
      generateKeyPair(),
      generateKeyPair(),
      generateKeyPair(),
      generateKeyPair(),
    ];
    const ring = keys.map((k) => k.publicKey);
    const message = enc.encode("test message");
    const sig = sign(message, ring, 1, keys[1].secretKey);
    expect(verify(message, ring, sig)).toBe(true);
  });

  it("verifies a valid signature regardless of signer position", () => {
    const keys = [
      generateKeyPair(),
      generateKeyPair(),
      generateKeyPair(),
      generateKeyPair(),
    ];
    const ring = keys.map((k) => k.publicKey);
    const message = enc.encode("test message");
    for (let i = 0; i < keys.length; i++) {
      const sig = sign(message, ring, i, keys[i].secretKey);
      expect(verify(message, ring, sig)).toBe(true);
    }
  });

  it("rejects a tampered message", () => {
    const keys = [
      generateKeyPair(),
      generateKeyPair(),
      generateKeyPair(),
      generateKeyPair(),
    ];
    const ring = keys.map((k) => k.publicKey);
    const message = enc.encode("original message");
    const sig = sign(message, ring, 0, keys[0].secretKey);
    expect(verify(enc.encode("tampered message"), ring, sig)).toBe(false);
  });

  it("rejects a tampered response", () => {
    const keys = [
      generateKeyPair(),
      generateKeyPair(),
      generateKeyPair(),
      generateKeyPair(),
    ];
    const ring = keys.map((k) => k.publicKey);
    const message = enc.encode("test message");
    const sig = sign(message, ring, 1, keys[1].secretKey);
    const tampered: LSAGSignature = {
      ...sig,
      responses: [new Uint8Array(32), ...sig.responses.slice(1)],
    };
    expect(verify(message, ring, tampered)).toBe(false);
  });

  it("rejects a tampered key image", () => {
    const keys = [
      generateKeyPair(),
      generateKeyPair(),
      generateKeyPair(),
      generateKeyPair(),
    ];
    const ring = keys.map((k) => k.publicKey);
    const message = enc.encode("test message");
    const sig = sign(message, ring, 1, keys[1].secretKey);
    const tampered: LSAGSignature = {
      ...sig,
      keyImage: secp256k1.Point.BASE.toBytes(),
    };
    expect(verify(message, ring, tampered)).toBe(false);
  });

  it("works with a larger ring (10 members)", () => {
    const n = 10;
    const keys = Array.from({ length: n }, () => generateKeyPair());
    const ring = keys.map((k) => k.publicKey);
    const message = enc.encode("test message");
    const idx = 5;
    const sig = sign(message, ring, idx, keys[idx].secretKey);
    expect(verify(message, ring, sig)).toBe(true);
  });

  it("rejects signature when wrong secret key is used", () => {
    const keys = [
      generateKeyPair(),
      generateKeyPair(),
      generateKeyPair(),
      generateKeyPair(),
    ];
    const ring = keys.map((k) => k.publicKey);
    const message = enc.encode("test message");
    const wrong = generateKeyPair();
    const sig = sign(message, ring, 1, wrong.secretKey);
    expect(verify(message, ring, sig)).toBe(false);
  });
});

describe("linkability (key image)", () => {
  it("same signer produces same key image", () => {
    const keys = [generateKeyPair(), generateKeyPair(), generateKeyPair()];
    const ring = keys.map((k) => k.publicKey);
    const message = enc.encode("test message");
    const sig1 = sign(message, ring, 1, keys[1].secretKey);
    const sig2 = sign(message, ring, 1, keys[1].secretKey);
    expect(sig1.keyImage).toEqual(sig2.keyImage);
  });

  it("different signers produce different key images", () => {
    const keys = [generateKeyPair(), generateKeyPair(), generateKeyPair()];
    const ring = keys.map((k) => k.publicKey);
    const message = enc.encode("test message");
    const sig0 = sign(message, ring, 0, keys[0].secretKey);
    const sig1 = sign(message, ring, 1, keys[1].secretKey);
    const sig2 = sign(message, ring, 2, keys[2].secretKey);
    expect(sig0.keyImage).not.toEqual(sig1.keyImage);
    expect(sig0.keyImage).not.toEqual(sig2.keyImage);
    expect(sig1.keyImage).not.toEqual(sig2.keyImage);
  });

  it("key image is the same across different messages for same signer", () => {
    const keys = [generateKeyPair(), generateKeyPair(), generateKeyPair()];
    const ring = keys.map((k) => k.publicKey);
    const sig1 = sign(enc.encode("message 1"), ring, 1, keys[1].secretKey);
    const sig2 = sign(enc.encode("message 2"), ring, 1, keys[1].secretKey);
    expect(sig1.keyImage).toEqual(sig2.keyImage);
  });

  it("key image equals x_s * H(P_s)", () => {
    const keys = [generateKeyPair(), generateKeyPair(), generateKeyPair()];
    const ring = keys.map((k) => k.publicKey);
    const message = enc.encode("test message");
    const idx = 1;
    const sig = sign(message, ring, idx, keys[idx].secretKey);

    const x_s = bytesToNumberBE(keys[idx].secretKey);
    const H_Ps = secp256k1.Point.fromBytes(hashToCurve(keys[idx].publicKey));
    const expected = H_Ps.multiply(x_s).toBytes();
    expect(sig.keyImage).toEqual(expected);
  });
});

describe("B6: challenge hash binds (msg || ring || keyImage) under LSAG/v2", () => {
  const keys = Array.from({ length: 4 }, () => generateKeyPair());
  const ring = keys.map((k) => k.publicKey);
  const message = enc.encode("B6 binding test");

  it("accepts a v2 replica signature whose challenges fold msg || ring || keyImage", () => {
    const sig = replicaSign(message, ring, 1, keys[1].secretKey, {
      domain: "LSAG/v2",
      fold: true,
    });
    expect(verify(message, ring, sig)).toBe(true);
  });

  it("rejects stale LSAG/v1 signatures — old proofs fail loudly after the domain bump", () => {
    const sig = replicaSign(message, ring, 2, keys[2].secretKey, {
      domain: "LSAG/v1",
      fold: false,
    });
    expect(verify(message, ring, sig)).toBe(false);
  });

  it("rejects a v2-domain signature that omits the (ring, keyImage) fold", () => {
    const sig = replicaSign(message, ring, 3, keys[3].secretKey, {
      domain: "LSAG/v2",
      fold: false,
    });
    expect(verify(message, ring, sig)).toBe(false);
  });

  it("rejects a v1-domain signature even with the fold — domain tag is part of the binding", () => {
    const sig = replicaSign(message, ring, 0, keys[0].secretKey, {
      domain: "LSAG/v1",
      fold: true,
    });
    expect(verify(message, ring, sig)).toBe(false);
  });

  it("rejects the same signature verified against a different ring (fold is enforced at verify time)", () => {
    const sig = sign(message, ring, 1, keys[1].secretKey);
    // same size, one member swapped — response count matches, so only the
    // challenge fold can (and must) break the ring walk
    const other = generateKeyPair();
    const ringB = [ring[0], ring[1], other.publicKey, ring[3]];
    expect(verify(message, ringB, sig)).toBe(false);
  });

  it("rejects the same signature verified against a reordered ring (ring order is binding)", () => {
    const sig = sign(message, ring, 1, keys[1].secretKey);
    const reordered = [ring[1], ring[0], ring[2], ring[3]];
    expect(verify(message, reordered, sig)).toBe(false);
  });
});

describe("B4: verify rejects degenerate rings", () => {
  const keys = Array.from({ length: 4 }, () => generateKeyPair());
  const ring = keys.map((k) => k.publicKey);
  const message = enc.encode("B4 degenerate ring test");

  it("rejects a ring of 3 pubkeys — minimum ring size is 4", () => {
    const three = ring.slice(0, 3);
    const sig = sign(message, three, 0, keys[0].secretKey);
    expect(sig.responses).toHaveLength(3); // well-formed signature…
    expect(verify(message, three, sig)).toBe(false); // …over a too-small ring
  });

  it("rejects a ring of 1 pubkey", () => {
    const one = [ring[0]];
    const sig = sign(message, one, 0, keys[0].secretKey);
    expect(verify(message, one, sig)).toBe(false);
  });

  it("rejects duplicate points in the ring (same pubkey listed twice)", () => {
    const dupRing = [ring[0], ring[1], ring[2], ring[0]];
    const sig = sign(message, dupRing, 1, keys[1].secretKey);
    expect(verify(message, dupRing, sig)).toBe(false);
  });

  it("rejects duplicate points listed under different encodings (compressed + uncompressed)", () => {
    const uncompressed = secp256k1.Point.fromBytes(ring[3]).toBytes(false);
    expect(uncompressed).toHaveLength(65); // valid point, non-canonical encoding
    const dupRing = [ring[0], ring[1], ring[2], uncompressed];
    const sig = sign(message, dupRing, 1, keys[1].secretKey);
    expect(verify(message, dupRing, sig)).toBe(false);
  });

  it("rejects non-canonical point encodings (uncompressed 65-byte entry)", () => {
    const uncompressed = secp256k1.Point.fromBytes(ring[2]).toBytes(false);
    const ringU = [ring[0], ring[1], uncompressed, ring[3]];
    const sig = sign(message, ringU, 1, keys[1].secretKey);
    expect(verify(message, ringU, sig)).toBe(false);
  });

  it("rejects wrong-size encodings (32-byte entry) without throwing", () => {
    const bad = [ring[0], ring[1], ring[2], ring[3].slice(1)] as Uint8Array[];
    const sig = sign(message, ring, 1, keys[1].secretKey);
    expect(verify(message, bad, sig)).toBe(false);
  });
});
