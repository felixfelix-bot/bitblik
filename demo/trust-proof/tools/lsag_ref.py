#!/usr/bin/env python3
"""Independent LSAG/v2 reference implementation — pure Python stdlib.

T3 cross-impl test vectors for the bitblik trust-proof demo. This module
re-implements the LSAG/v2 scheme exactly as specified by src/lsag.ts
(Liu–Wei–Wong 2004; B4/B6 hardening) WITHOUT sharing any code with the
TypeScript side:

  * challenges fold (message || ring || keyImage) under the "LSAG/v2"
    domain tag, items length-prefixed with a 4-byte big-endian length,
    hashed with SHA-256 and reduced mod n;
  * hash-to-curve is try-and-increment under the "LSAG/H2C" tag;
  * verification enforces the B4 ring rules (>= 4 members, canonical
    33-byte compressed encodings only, no duplicate points, valid
    non-identity key image).

No third-party dependencies (coincurve etc. are deliberately NOT used);
EC arithmetic is implemented from scratch below and MUST pass the
self-check against published secp256k1 constants before this tool will
emit or verify anything.

Usage:
    python3 tools/lsag_ref.py selfcheck
    python3 tools/lsag_ref.py generate --out vectors/lsag-vectors.json
    python3 tools/lsag_ref.py verify --file <vectors.json>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from typing import Optional, Sequence, Tuple

# ─── secp256k1 domain parameters ──────────────────────────────────

P = 2**256 - 2**32 - 977  # field prime
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # group order
B = 7  # y^2 = x^3 + 7
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G: Optional[Tuple[int, int]] = (GX, GY)

# Published multiples of G (x-coordinates) used by the self-check.
X_1G = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
X_2G = 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5
X_3G = 0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9

Point = Optional[Tuple[int, int]]  # None is the point at infinity


class ECError(ValueError):
    """Invalid point encoding / not on curve."""


# ─── elliptic-curve arithmetic (affine, from scratch) ─────────────


def _on_curve(pt: Tuple[int, int]) -> bool:
    x, y = pt
    if not (0 <= x < P and 0 <= y < P):
        return False
    return (y * y - (x * x * x + B)) % P == 0


def add(p: Point, q: Point) -> Point:
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % P == 0:
        return None  # p + (-p) = infinity
    if p == q:
        lam = (3 * x1 * x1) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def neg(p: Point) -> Point:
    if p is None:
        return None
    x, y = p
    return (x, (P - y) % P)


def mul(k: int, p: Point) -> Point:
    """Scalar multiplication via double-and-add (k reduced mod n)."""
    k %= N
    if p is None or k == 0:
        return None
    result: Point = None
    addend = p
    while k > 0:
        if k & 1:
            result = add(result, addend)
        addend = add(addend, addend)
        k >>= 1
    return result


def compress(p: Point) -> bytes:
    if p is None:
        raise ECError("cannot encode the point at infinity")
    x, y = p
    return bytes([0x02 | (y & 1)]) + x.to_bytes(32, "big")


def decompress(data: bytes) -> Tuple[int, int]:
    """Strict canonical parse: 33 bytes, prefix 0x02/0x03, on-curve.

    Raises ECError instead of ever returning the point at infinity.
    """
    if len(data) != 33 or data[0] not in (0x02, 0x03):
        raise ECError("expected 33-byte compressed encoding")
    x = int.from_bytes(data[1:33], "big")
    if x >= P:
        raise ECError("x coordinate out of field range")
    y2 = (x * x * x + B) % P
    y = pow(y2, (P + 1) // 4, P)  # p ≡ 3 (mod 4)
    if (y * y) % P != y2:
        raise ECError("point is not on the curve")
    if (y & 1) != (data[0] & 1):
        y = P - y
    return (x, y)


# ─── hashing (mirrors the LSAG/v2 constructions in lsag.ts) ───────


def hash_to_scalar(*items: bytes) -> int:
    """sha256 over "LSAG/v2" + 4-byte-BE-length-prefixed items, mod n."""
    parts = [b"LSAG/v2"]
    for it in items:
        parts.append(len(it).to_bytes(4, "big"))
        parts.append(it)
    digest = hashlib.sha256(b"".join(parts)).digest()
    return int.from_bytes(digest, "big") % N


def hash_to_curve(data: bytes) -> bytes:
    """Deterministic try-and-increment H2C under the "LSAG/H2C" tag.

    Wire-format note (pinned by cross-impl testing): the TypeScript side
    builds its 33-byte candidate as `candidate.set(digest.subarray(0, 33))`
    — but sha256 digests are 32 bytes, so only candidate[0..31] are filled
    and candidate[32] keeps its default 0x00. The effective x-coordinate
    is therefore digest[1:32] || 0x00 (always < 2^248). Reproduced here
    exactly; diverging from it breaks key-image agreement.
    """
    counter = 0
    while True:
        digest = hashlib.sha256(
            b"LSAG/H2C" + data + counter.to_bytes(4, "big")
        ).digest()
        prefix = 0x02 if (digest[0] & 0x01) == 0 else 0x03
        x = int.from_bytes(digest[1:32] + b"\x00", "big")
        if x < P:
            y2 = (x * x * x + B) % P
            y = pow(y2, (P + 1) // 4, P)
            if (y * y) % P == y2:
                if (y & 1) != (prefix & 1):
                    y = P - y
                return compress((x, y))
        counter += 1


_h2c_cache: dict = {}


def h2c_point(data: bytes) -> Tuple[int, int]:
    cached = _h2c_cache.get(data)
    if cached is None:
        cached = decompress(hash_to_curve(data))
        _h2c_cache[data] = cached
    return cached


# ─── LSAG sign / verify ───────────────────────────────────────────


def _link_challenge(
    message: bytes,
    ring_enc: bytes,
    key_image: bytes,
    c: int,
    r: int,
    pk: bytes,
    h_i: Tuple[int, int],
) -> int:
    i_pt = decompress(key_image)
    z1 = add(mul(r, G), mul(c, decompress(pk)))
    z2 = add(mul(r, h_i), mul(c, i_pt))
    if z1 is None or z2 is None:
        raise RuntimeError("identity point in challenge (astronomically unlikely)")
    return hash_to_scalar(message, ring_enc, key_image, compress(z1), compress(z2))


def sign(
    message: bytes, ring: Sequence[bytes], signer_index: int, secret_key: bytes
) -> dict:
    """Sign as ring member `signer_index`; mirrors lsag.ts sign()."""
    if len(ring) == 0:
        raise ValueError("ring must have at least one member")
    if not 0 <= signer_index < len(ring):
        raise ValueError("signerIndex out of range")

    n = len(ring)
    s = signer_index
    x_s = int.from_bytes(secret_key, "big") % N

    h_pts = [h2c_point(pk) for pk in ring]

    key_image = compress(mul(x_s, h_pts[s]))
    ring_enc = b"".join(ring)

    responses = [
        int.from_bytes(
            hashlib.sha256(
                b"bitblik/t3/resp/" + str(s).encode() + b"/" + i.to_bytes(4, "big")
            ).digest(),
            "big",
        )
        % N
        for i in range(n)
    ]
    r_s_random = responses[s]

    challenges: list = [None] * n
    c = hash_to_scalar(
        message,
        ring_enc,
        key_image,
        compress(mul(r_s_random, G)),
        compress(mul(r_s_random, h_pts[s])),
    )
    challenges[(s + 1) % n] = c

    for step in range(1, n):
        i = (s + step) % n
        c = _link_challenge(
            message, ring_enc, key_image, c, responses[i], ring[i], h_pts[i]
        )
        challenges[(i + 1) % n] = c

    responses[s] = (r_s_random - x_s * c) % N

    return {
        "key_image": key_image,
        "c0": challenges[0] % N,
        "responses": list(responses),
    }


def verify(
    message: bytes, ring: Sequence[bytes], key_image: bytes, c0: bytes, responses: Sequence[bytes]
) -> bool:
    """Verify a signature; mirrors lsag.ts verify() incl. B4 ring rules."""
    n = len(ring)
    if n < 4:
        return False
    if len(responses) != n:
        return False

    try:
        decompress(key_image)
    except ECError:
        return False

    h_pts = []
    seen = set()
    for pk in ring:
        if len(pk) != 33 or pk[0] not in (0x02, 0x03):
            return False
        try:
            pt = decompress(pk)
        except ECError:
            return False
        if not _on_curve(pt):
            return False
        if pk in seen:
            return False  # duplicate point
        seen.add(pk)
        h_pts.append(h2c_point(pk))

    ring_enc = b"".join(ring)
    c = int.from_bytes(c0, "big") % N
    try:
        for i in range(n):
            r = int.from_bytes(responses[i], "big") % N
            c = _link_challenge(message, ring_enc, key_image, c, r, ring[i], h_pts[i])
    except (ECError, RuntimeError):
        return False
    return c == int.from_bytes(c0, "big") % N


# ─── self-check against published secp256k1 vectors ───────────────


def selfcheck() -> None:
    """Abort on any mismatch with known EC constants — mandatory gate."""
    failures = []

    def check(label: str, ok: bool) -> None:
        if not ok:
            failures.append(label)

    g1 = mul(1, G)
    g2 = mul(2, G)
    g3 = add(g1, g2)  # 1*G + 2*G must equal 3*G

    check("1*G is on the curve", g1 is not None and _on_curve(g1))
    check("2*G is on the curve", g2 is not None and _on_curve(g2))
    check("3*G = 1*G + 2*G is on the curve", g3 is not None and _on_curve(g3))
    check("x(1*G) matches published constant", g1 is not None and g1[0] == X_1G)
    check("x(2*G) matches published constant", g2 is not None and g2[0] == X_2G)
    check("x(3*G) matches published constant", g3 is not None and g3[0] == X_3G)
    check("1*G == G", g1 == G)
    check("G + (-G) = infinity", add(G, neg(G)) is None)
    check("n*G = infinity", mul(N, G) is None)
    check("0*G = infinity", mul(0, G) is None)
    check("compress/decompress round-trips G", decompress(compress(G)) == G)
    check("compress/decompress round-trips 2*G", decompress(compress(g2)) == g2)
    check(
        "decompress rejects bad prefix",
        _raises(lambda: decompress(bytes([0x04]) + compress(G)[1:])),
    )
    # x = 5: y^2 = 5^3 + 7 = 132 is a non-residue mod p (proven below by
    # Euler's criterion, so the constant carries its own justification).
    nonsquare_x = 5
    y2 = (nonsquare_x**3 + B) % P
    check("self-check constant 132 is a genuine non-residue", pow(y2, (P - 1) // 2, P) == P - 1)
    check(
        "decompress rejects non-square x",
        _raises(lambda: decompress(bytes([0x02]) + nonsquare_x.to_bytes(32, "big"))),
    )
    check("scalar mul consistent: 6*G == 2*(3*G)", mul(6, G) == mul(2, g3))
    check(
        "hash_to_curve deterministic",
        hash_to_curve(b"selfcheck") == hash_to_curve(b"selfcheck"),
    )

    if failures:
        for f in failures:
            print(f"SELF-CHECK FAILED: {f}", file=sys.stderr)
        sys.exit("EC self-check failed — refusing to emit or verify vectors")
    print("selfcheck: all EC arithmetic checks passed (1G, 2G, 3G, nG, encodings)")


def _raises(fn) -> bool:
    try:
        fn()
        return False
    except ECError:
        return True


# ─── vector generation ────────────────────────────────────────────


def _key(i: int) -> bytes:
    return hashlib.sha256(f"bitblik/t3/key/{i}".encode()).digest()


def _pub(i: int) -> bytes:
    return compress(mul(int.from_bytes(_key(i), "big") % N, G))


def _flip_last_bit_hex(h: str) -> str:
    b = bytearray(bytes.fromhex(h))
    b[-1] ^= 0x01
    return b.hex()


def build_vectors() -> list:
    """5 valid + 3 tampered vectors (>= 5 / >= 3 per the T3 spec)."""
    vectors = []

    valid_specs = [
        ("ring4-s0-valid", 4, 0, "t3 vector 0: cross-impl python reference"),
        ("ring5-s2-valid", 5, 2, "t3 vector 1: ring of five"),
        ("ring6-s5-valid", 6, 5, "t3 vector 2: signer at the end"),
        ("ring8-s4-valid", 8, 4, "t3 vector 3: larger ring"),
        ("ring4-s3-valid", 4, 3, "t3 vector 4: wrap-around signer"),
    ]
    for vid, size, s, msg in valid_specs:
        ring = [_pub(i) for i in range(size)]
        sig = sign(msg.encode(), ring, s, _key(s))
        vectors.append(_vector(vid, msg.encode(), ring, s, _key(s), sig, "valid", None))

    # Tampered message: signature made on A, presented against B.
    ring = [_pub(i) for i in range(4)]
    sig = sign(b"t3 tamper: original message", ring, 0, _key(0))
    vectors.append(
        _vector(
            "ring4-s0-tampered-message",
            b"t3 tamper: TAMPERED message",
            ring,
            0,
            _key(0),
            sig,
            "invalid",
            "message",
        )
    )

    # Tampered response: flip one bit of responses[signer_index].
    ring = [_pub(i) for i in range(5)]
    msg = b"t3 tamper: response"
    sig = sign(msg, ring, 2, _key(2))
    sig["responses"][2] = sig["responses"][2] ^ 0x01
    vectors.append(
        _vector("ring5-s2-tampered-response", msg, ring, 2, _key(2), sig, "invalid", "response")
    )

    # Tampered key image: I' = (x_s + 1) * H(P_s) — valid point, wrong image.
    ring = [_pub(i) for i in range(6)]
    msg = b"t3 tamper: key image"
    s = 5
    sig = sign(msg, ring, s, _key(s))
    x_s = int.from_bytes(_key(s), "big") % N
    wrong_image = compress(mul((x_s + 1) % N, h2c_point(ring[s])))
    sig["key_image"] = wrong_image
    vectors.append(
        _vector("ring6-s5-tampered-key-image", msg, ring, s, _key(s), sig, "invalid", "keyImage")
    )

    return vectors


def _vector(vid, message, ring, s, secret_key, sig, expected, tamper) -> dict:
    return {
        "id": vid,
        "message_hex": message.hex(),
        "ring": [pk.hex() for pk in ring],
        "signer_index": s,
        "secret_key_hex": secret_key.hex(),
        "key_image_hex": sig["key_image"].hex(),
        "c0_hex": (sig["c0"] % N).to_bytes(32, "big").hex(),
        "responses": [r.to_bytes(32, "big").hex() for r in sig["responses"]],
        "expected": expected,
        "tamper": tamper,
    }


def cmd_generate(out_path: str) -> None:
    selfcheck()
    vectors = build_vectors()

    # Self-consistency gate: our own verify() must classify every vector
    # exactly as labelled, or we abort without writing anything.
    for v in vectors:
        result = _verify_vector(v)
        if result != (v["expected"] == "valid"):
            sys.exit(f"self-consistency failed for {v['id']}: labeled {v['expected']}, got {result}")

    n_valid = sum(1 for v in vectors if v["expected"] == "valid")
    n_invalid = len(vectors) - n_valid
    if n_valid < 5 or n_invalid < 3:
        sys.exit(f"vector quota not met: {n_valid} valid, {n_invalid} invalid")

    doc = {"v": 1, "scheme": "LSAG/v2", "vectors": vectors}
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    print(f"generate: wrote {len(vectors)} vectors ({n_valid} valid, {n_invalid} invalid) to {out_path}")


# ─── vector verification (used on TS-emitted files too) ───────────


def _verify_vector(v: dict) -> bool:
    return verify(
        bytes.fromhex(v["message_hex"]),
        [bytes.fromhex(pk) for pk in v["ring"]],
        bytes.fromhex(v["key_image_hex"]),
        bytes.fromhex(v["c0_hex"]),
        [bytes.fromhex(r) for r in v["responses"]],
    )


def cmd_verify(file_path: str) -> None:
    selfcheck()
    with open(file_path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)

    if doc.get("v") != 1 or doc.get("scheme") != "LSAG/v2":
        sys.exit(f"unsupported vectors file: v={doc.get('v')!r} scheme={doc.get('scheme')!r}")

    ok = 0
    n_valid = n_invalid = 0
    for v in doc["vectors"]:
        result = _verify_vector(v)
        expected_valid = v["expected"] == "valid"
        if result:
            n_valid += 1
        else:
            n_invalid += 1
        if result == expected_valid:
            ok += 1
            print(f"[ok] {v['id']}: expected={v['expected']} result={'valid' if result else 'invalid'}")
        else:
            print(
                f"[FAIL] {v['id']}: expected={v['expected']} "
                f"result={'valid' if result else 'invalid'} — MISMATCH"
            )
    total = len(doc["vectors"])
    print(f"python-ref: {ok}/{total} vectors OK ({n_valid} valid, {n_invalid} invalid)")
    if ok != total:
        sys.exit(1)


# ─── CLI ──────────────────────────────────────────────────────────


def main(argv: Optional[Sequence[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        description="independent pure-Python LSAG/v2 reference (T3 cross-impl vectors)"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("selfcheck", help="run the EC arithmetic self-check")

    gen = sub.add_parser("generate", help="emit vectors/lsag-vectors.json")
    gen.add_argument("--out", required=True, help="output JSON path")

    ver = sub.add_parser("verify", help="verify a vectors JSON file (any producer)")
    ver.add_argument("--file", required=True, help="vectors JSON path")

    args = parser.parse_args(argv)
    if args.cmd == "selfcheck":
        selfcheck()
    elif args.cmd == "generate":
        cmd_generate(args.out)
    elif args.cmd == "verify":
        cmd_verify(args.file)


if __name__ == "__main__":
    main()
