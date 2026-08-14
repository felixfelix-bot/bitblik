import { describe, it, expect } from "vitest";
import { generateKeyPair, hashToCurve, sign, verify } from "./lsag.js";
import type { LSAGSignature } from "./lsag.js";
import { secp256k1 } from "@noble/curves/secp256k1";
import { bytesToNumberBE } from "@noble/curves/abstract/utils";

const enc = new TextEncoder();

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
  it("verifies a valid signature (ring of 3)", () => {
    const keys = [generateKeyPair(), generateKeyPair(), generateKeyPair()];
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
    const keys = [generateKeyPair(), generateKeyPair(), generateKeyPair()];
    const ring = keys.map((k) => k.publicKey);
    const message = enc.encode("original message");
    const sig = sign(message, ring, 0, keys[0].secretKey);
    expect(verify(enc.encode("tampered message"), ring, sig)).toBe(false);
  });

  it("rejects a tampered response", () => {
    const keys = [generateKeyPair(), generateKeyPair(), generateKeyPair()];
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
    const keys = [generateKeyPair(), generateKeyPair(), generateKeyPair()];
    const ring = keys.map((k) => k.publicKey);
    const message = enc.encode("test message");
    const sig = sign(message, ring, 1, keys[1].secretKey);
    const tampered: LSAGSignature = {
      ...sig,
      keyImage: secp256k1.Point.BASE.toBytes(),
    };
    expect(verify(message, ring, tampered)).toBe(false);
  });

  it("works with a ring of 1", () => {
    const keys = [generateKeyPair()];
    const ring = keys.map((k) => k.publicKey);
    const message = enc.encode("test");
    const sig = sign(message, ring, 0, keys[0].secretKey);
    expect(verify(message, ring, sig)).toBe(true);
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
    const keys = [generateKeyPair(), generateKeyPair(), generateKeyPair()];
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
