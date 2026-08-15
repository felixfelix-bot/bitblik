/**
 * LSAG (Linkable Spontaneous Anonymous Group) ring signatures on secp256k1.
 *
 * Reference: Liu, Wei, Wong — "Linkable Spontaneous Anonymous Group Signature
 * for Ad Hoc Groups" (2004).
 *
 * Notation:
 *   G      — base point of secp256k1
 *   P_i    — public key of ring member i  (P_i = x_i * G)
 *   H(.)   — hash-to-curve (deterministic map from bytes to a curve point)
 *   I      — key image of the signer: I = x_s * H(P_s)
 *   c_i    — challenge at position i
 *   r_i    — response at position i
 *
 * Sign (signer index s, secret key x_s, ring P_0..P_{n-1}, message m):
 *   1. I = x_s * H(P_s)
 *   2. pick random r_s;  c_{s+1} = H(m, ring, I, r_s*G, r_s*H(P_s))
 *   3. for i = s+1, s+2, ..., s-1 (wrapping mod n), i != s:
 *        pick random r_i;  c_{i+1} = H(m, ring, I, r_i*G + c_i*P_i, r_i*H(P_i) + c_i*I)
 *   4. close the ring: set r_s = r_s_random - x_s * c_s  (mod n)
 *
 * Verify (message m, ring P_0..P_{n-1}, signature (I, c_0, r_0..r_{n-1})):
 *   for each i:  c_{i+1} = H(m, ring, I, r_i*G + c_i*P_i, r_i*H(P_i) + c_i*I)
 *   accept iff c_n == c_0  and I is a valid non-identity point.
 *
 * B6: every challenge folds (m || ring || I) and hashes under the LSAG/v2
 * domain tag, so signatures are bound to their exact verification context
 * and stale LSAG/v1 proofs fail loudly.
 *
 * CRITICAL: r_i multiplies the generators (G, H(P_i)); c_i multiplies the
 * public keys (P_i, I). Swapping these roles breaks ring closure.
 */

import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToNumberBE, numberToBytesBE } from "@noble/curves/abstract/utils";

const { Point } = secp256k1;
const CURVE_ORDER = secp256k1.CURVE.n; // group order q
const ZERO = BigInt(0);

/** 32-byte scalar as Uint8Array (big-endian, fixed width). */
function scalarToBytes(s: bigint): Uint8Array {
  return numberToBytesBE(((s % CURVE_ORDER) + CURVE_ORDER) % CURVE_ORDER, 32);
}

/** Concatenate byte arrays. */
function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

/**
 * Hash a set of byte items to a scalar mod n. Each item is length-prefixed
 * by a 4-byte big-endian length so concatenation is unambiguous.
 *
 * Domain tag is LSAG/v2 (B6): bumped from LSAG/v1 so signatures made under
 * the old challenge construction fail loudly instead of verifying.
 */
function hashToScalar(...items: Uint8Array[]): bigint {
  const parts: Uint8Array[] = [new TextEncoder().encode("LSAG/v2")];
  for (const it of items) {
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, it.length, false);
    parts.push(len, it);
  }
  return bytesToNumberBE(sha256(concatBytes(...parts))) % CURVE_ORDER;
}

/**
 * Ordered concat of the ring's pubkey encodings (B6). Ring ORDER is part of
 * the binding: folding these bytes into every challenge means a signature
 * can never be re-targeted to a differently-ordered or different ring.
 */
function ringBytes(ring: Uint8Array[]): Uint8Array {
  return concatBytes(...ring);
}

/** Reduce a bigint mod n into the canonical range [0, n). */
function modN(x: bigint): bigint {
  const r = x % CURVE_ORDER;
  return r < ZERO ? r + CURVE_ORDER : r;
}

/**
 * Deterministic hash-to-curve: map arbitrary bytes to a secp256k1 point.
 * try-and-increment with a counter. ~1/2 success per try, so terminates fast.
 */
export function hashToCurve(input: Uint8Array): Uint8Array {
  for (let counter = 0; ; counter++) {
    const ctr = new Uint8Array(4);
    new DataView(ctr.buffer).setUint32(0, counter, false);
    const digest = sha256(
      concatBytes(new TextEncoder().encode("LSAG/H2C"), input, ctr),
    );
    const candidate = new Uint8Array(33);
    candidate.set(digest.subarray(0, 33));
    candidate[0] = (candidate[0] & 0x01) === 0 ? 0x02 : 0x03;
    try {
      const p = Point.fromBytes(candidate);
      p.assertValidity();
      return p.toBytes();
    } catch {
      // not a valid point, try next counter
    }
  }
}

export interface KeyPair {
  secretKey: Uint8Array; // 32 bytes
  publicKey: Uint8Array; // 33 bytes (compressed)
}

/** Generate a fresh secp256k1 key pair. */
export function generateKeyPair(): KeyPair {
  const secretKey = secp256k1.utils.randomSecretKey();
  const publicKey = secp256k1.getPublicKey(secretKey, true);
  return { secretKey, publicKey };
}

export interface LSAGSignature {
  /** Key image I = x_s * H(P_s), 33 bytes compressed. */
  keyImage: Uint8Array;
  /** c0 — the starting challenge, 32 bytes. */
  c0: Uint8Array;
  /** Responses r_0..r_{n-1}, each 32 bytes. */
  responses: Uint8Array[];
}

/**
 * Per-link challenge: c_{i+1} = H(m, ring, I, r_i*G + c_i*P_i, r_i*H(P_i) + c_i*I)
 *
 * B6: every challenge — this one and the base challenge in sign() — folds
 * (message || ring || keyImage) ahead of the point components, so the whole
 * chain is bound to the exact verification context. The domain tag is
 * LSAG/v2 (bumped from LSAG/v1): stale v1 signatures fail loudly.
 *
 * r_i multiplies the generators (G, H(P_i)); c_i multiplies the public
 * keys (P_i, I). This ordering is what makes the ring close: at the signer
 * index s, with r_s = r_s_random - c_s*x_s and P_s = x_s*G, I = x_s*H(P_s),
 * the c_s*x_s terms cancel and verify recomputes c_{s+1} = H(m, ring, I,
 * r_s_random*G, r_s_random*H(P_s)) — exactly what the signer stored.
 */
function linkChallenge(
  message: Uint8Array,
  ring: Uint8Array,
  keyImage: Uint8Array,
  c: bigint,
  r: bigint,
  Pi: Uint8Array,
  Hi: Uint8Array,
): bigint {
  const I = Point.fromBytes(keyImage);
  const z1 = Point.BASE.multiply(r).add(Point.fromBytes(Pi).multiply(c));
  const z2 = Point.fromBytes(Hi).multiply(r).add(I.multiply(c));
  return hashToScalar(message, ring, keyImage, z1.toBytes(), z2.toBytes());
}

/**
 * Produce an LSAG signature on `message` as the signer at `signerIndex`
 * within `ring`, using `secretKey`.
 *
 * If `secretKey` does not correspond to `ring[signerIndex]`, the resulting
 * signature will fail verification (rather than throwing) — this lets callers
 * build "wrong key" tests and adversarial cases without try/catch.
 */
export function sign(
  message: Uint8Array,
  ring: Uint8Array[],
  signerIndex: number,
  secretKey: Uint8Array,
): LSAGSignature {
  if (ring.length === 0) throw new Error("ring must have at least one member");
  if (signerIndex < 0 || signerIndex >= ring.length)
    throw new Error("signerIndex out of range");

  const n = ring.length;
  const s = signerIndex;
  const x_s = bytesToNumberBE(secretKey) % CURVE_ORDER;

  // Precompute H(P_i) for every ring member.
  const H = ring.map((pk) => hashToCurve(pk));

  // Key image: I = x_s * H(P_s)
  const I = Point.fromBytes(H[s]).multiply(x_s).toBytes();

  // B6: the ring encoding is folded into every challenge below.
  const R = ringBytes(ring);

  // Random responses for all non-signer positions.
  const responses: bigint[] = new Array(n);
  for (let i = 0; i < n; i++) {
    responses[i] = bytesToNumberBE(secp256k1.utils.randomSecretKey()) % CURVE_ORDER;
  }
  const r_s_random = responses[s];

  // Walk the ring forward from s, computing challenges c_{s+1}, c_{s+2}, ...
  // Store each challenge in an array indexed by ring position.
  const challenges: bigint[] = new Array(n);

  // Base challenge (B6): c_{s+1} = H(m, ring, I, r_s*G, r_s*H(P_s))
  // (uses the *random* r_s, not the final one; folds msg || ring || keyImage)
  let c = hashToScalar(
    message,
    R,
    I,
    Point.BASE.multiply(r_s_random).toBytes(),
    Point.fromBytes(H[s]).multiply(r_s_random).toBytes(),
  );
  challenges[(s + 1) % n] = c;

  for (let step = 1; step < n; step++) {
    const i = (s + step) % n;
    c = linkChallenge(message, R, I, c, responses[i], ring[i], H[i]);
    challenges[(i + 1) % n] = c;
  }
  // `c` is now c_s — the challenge arriving back at the signer index.

  // Close the ring: choose the real r_s so the signer's link holds.
  //   r_s = r_s_random - x_s * c_s  (mod n)
  // This makes verify's recomputed c_{s+1} equal the one we stored.
  const c_s = c;
  responses[s] = modN(r_s_random - x_s * c_s);

  return {
    keyImage: I,
    c0: scalarToBytes(challenges[0]),
    responses: responses.map((r) => scalarToBytes(r)),
  };
}

/**
 * Verify an LSAG signature.
 *
 * B4 hardening: the ring must be well-formed before any math runs —
 * at least 4 pubkeys, no duplicate points (in any encoding), and every
 * entry in canonical form (exactly 33 bytes, prefix 0x02 or 0x03 —
 * compressed). Uncompressed/hybrid encodings of otherwise-valid points
 * are rejected, so a point can only appear once and only one way.
 */
export function verify(
  message: Uint8Array,
  ring: Uint8Array[],
  sig: LSAGSignature,
): boolean {
  const n = ring.length;
  if (n < 4) return false;
  if (sig.responses.length !== n) return false;

  // Key image must be a valid, non-identity point.
  let I: ReturnType<typeof Point.fromBytes>;
  try {
    I = Point.fromBytes(sig.keyImage);
    I.assertValidity();
  } catch {
    return false;
  }
  if (I.is0?.() ?? false) return false;

  // Precompute H(P_i); each ring member must be a canonical, valid,
  // non-duplicate point.
  const H: Uint8Array[] = [];
  const seen = new Set<string>();
  for (let i = 0; i < n; i++) {
    const pk = ring[i];
    // Canonical encoding check FIRST: 33 bytes, compressed prefix only.
    // (Point.fromBytes would happily accept a 65-byte uncompressed
    // encoding of a valid point — that must not slip through.)
    if (pk.length !== 33 || (pk[0] !== 0x02 && pk[0] !== 0x03)) return false;
    try {
      Point.fromBytes(pk).assertValidity();
      H.push(hashToCurve(pk));
    } catch {
      return false;
    }
    // With canonical encodings enforced, byte equality ⟺ point equality.
    const canonical = Array.from(pk)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    if (seen.has(canonical)) return false; // duplicate point
    seen.add(canonical);
  }

  // B6: challenges fold (message || ring || keyImage) under LSAG/v2 —
  // the same construction sign() used, so re-targeted or stale (v1)
  // signatures cannot close the ring.
  const R = ringBytes(ring);

  let c = bytesToNumberBE(sig.c0) % CURVE_ORDER;
  for (let i = 0; i < n; i++) {
    const r = bytesToNumberBE(sig.responses[i]) % CURVE_ORDER;
    try {
      c = linkChallenge(message, R, sig.keyImage, c, r, ring[i], H[i]);
    } catch {
      return false;
    }
  }
  return c === (bytesToNumberBE(sig.c0) % CURVE_ORDER);
}
