/**
 * Trust proof demo — LSAG ring signature for bitblik.
 *
 * Scenario:
 *   A "taker" (code provider) wants to prove they are a trusted member of a
 *   ring of known cash withdrawers ("makers") WITHOUT revealing *which* one.
 *   The proof is a Linkable Spontaneous Anonymous Group (LSAG) ring signature.
 *
 *   The maker (cash withdrawer) who receives the proof can verify it was
 *   produced by someone in the ring, and can detect if the same taker tries
 *   to reuse a proof (via the key image / nullifier).
 *
 * Flow:
 *   1. Setup 5 keypairs (the ring of makers).
 *   2. Taker (one of the makers, acting as code provider) signs a message.
 *   3. Maker (cash withdrawer) verifies the ring signature.
 *   4. Nullifier reuse detection — same taker signs twice, key image matches.
 *   5. Security checks — wrong key, tampered message, tampered response.
 *
 * Terminology:
 *   maker  = cash withdrawer (member of the ring of trusted withdrawers)
 *   taker  = code provider (the one who proves membership via ring sig)
 *
 * Run:  npx tsx src/demo.ts [--interactive] [--quick]
 *
 * Flags:
 *   --interactive  pause after each section header ("[Enter] to continue...")
 *   --quick        collapse the security checks into one summary line
 */

import {
  generateKeyPair,
  sign,
  verify,
  type LSAGSignature,
} from "./lsag.js";
import { secp256k1 } from "@noble/curves/secp256k1";
import { readSync } from "node:fs";

// ─── ASCII helpers ──────────────────────────────────────────────

const BOX_WIDTH = 64;

function box(title: string, lines: string[]): string {
  const inner = BOX_WIDTH - 2;
  const top = "+" + "-".repeat(inner) + "+";
  const titleLine = "| " + title.padEnd(inner - 2) + " |";
  const sep = "|" + "-".repeat(inner) + "|";
  const body = lines.map((l) => "| " + l.padEnd(inner - 2) + " |");
  const bot = "+" + "-".repeat(inner) + "+";
  return [top, titleLine, sep, ...body, bot].join("\n");
}

function section(title: string, opts?: PauseOptions): void {
  const inner = BOX_WIDTH - 2;
  const pad = Math.floor((inner - title.length) / 2);
  const bar = "=".repeat(inner);
  console.log();
  console.log("+" + bar + "+");
  console.log("|" + " ".repeat(pad) + title + " ".repeat(inner - pad - title.length) + "|");
  console.log("+" + bar + "+");
  pause(opts ?? { interactive: false });
}

function check(label: string, ok: boolean): string {
  return `${ok ? "[+]" : "[-]"} ${label}`;
}

function info(label: string, value: string): string {
  return `    ${label}: ${value}`;
}

function truncate(s: string, max = 16): string {
  return s.length <= max ? s : s.slice(0, max) + "...";
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ─── CLI flags ─────────────────────────────────────────────────

export interface DemoOptions {
  /** Pause after each section header ("[Enter] to continue..."). */
  interactive: boolean;
  /** Collapse the security checks into a single summary line. */
  quick: boolean;
}

export interface PauseOptions {
  interactive: boolean;
  /** Injected Enter-key reader — lets tests pause without touching stdin. */
  waitForKey?: () => void;
}

export interface MainOptions extends DemoOptions, PauseOptions {}

export function parseArgs(argv: string[]): DemoOptions {
  return {
    interactive: argv.includes("--interactive"),
    quick: argv.includes("--quick"),
  };
}

/** Read a single keypress (Enter) from stdin; never stalls if stdin is gone. */
function readEnterKey(): void {
  const buf = Buffer.alloc(1);
  try {
    readSync(0, buf, 0, 1, null);
  } catch {
    // stdin closed or non-blocking (e.g. piped) — continue the demo.
  }
}

/** Pause for the user when interactive; strict no-op otherwise. */
export function pause(opts: PauseOptions): void {
  if (!opts.interactive) return;
  console.log("[Enter] to continue...");
  if (opts.waitForKey) {
    opts.waitForKey();
    return;
  }
  readEnterKey();
}

// ─── Demo ───────────────────────────────────────────────────────

export function main(opts: MainOptions = parseArgs(process.argv.slice(2))): void {
  const enc = new TextEncoder();

  console.log();
  console.log("=".repeat(BOX_WIDTH));
  console.log("  bitblik Trust Proof Demo — LSAG Ring Signatures");
  console.log("  maker = cash withdrawer    taker = code provider");
  console.log("=".repeat(BOX_WIDTH));

  // ── 1. Setup: generate 5 keypairs (the ring of makers) ───────
  section("1. Setup — Generate 5 maker keypairs", opts);

  const RING_SIZE = 5;
  const keys = Array.from({ length: RING_SIZE }, () => generateKeyPair());
  const ring = keys.map((k) => k.publicKey);

  console.log(box("Ring of makers (public keys)", [
    `Ring size: ${RING_SIZE}`,
    "",
    ...keys.map((k, i) =>
      info(`maker[${i}]`, truncate(hex(k.publicKey), 24))
    ),
  ]));

  // The taker is maker[2] — they will prove membership without revealing which.
  const takerIndex = 2;
  const takerSecret = keys[takerIndex].secretKey;

  console.log();
  console.log(box("Taker (code provider)", [
    `Acting as: maker[${takerIndex}] (secret identity)`,
    info("secret key", truncate(hex(takerSecret), 24)),
    "The taker knows they are maker[2], but the",
    "verifier cannot learn this from the signature.",
  ]));

  // ── 2. Taker generates ring signature ────────────────────────
  section("2. Taker generates ring signature", opts);

  const message = enc.encode("I am a trusted code provider for bitblik");
  const sig: LSAGSignature = sign(message, ring, takerIndex, takerSecret);

  console.log(box("Ring signature produced", [
    info("message", '"I am a trusted code provider for bitblik"'),
    info("key image (nullifier)", truncate(hex(sig.keyImage), 24)),
    info("c0 (initial challenge)", truncate(hex(sig.c0), 24)),
    info("responses", `${sig.responses.length} x 32-byte scalars`),
  ]));

  // ── 3. Maker verifies the ring signature ─────────────────────
  section("3. Maker (cash withdrawer) verifies the proof", opts);

  const isValid = verify(message, ring, sig);

  console.log(box("Verification result", [
    check("Signature is valid", isValid),
    check("Signer is in the ring (anonymous)", isValid),
    check("Signer identity hidden", true),
    "",
    "The maker verified the taker belongs to the",
    "ring of trusted withdrawers, but does NOT know",
    "which of the 5 makers produced the signature.",
  ]));

  // ── 4. Nullifier reuse detection ─────────────────────────────
  section("4. Nullifier reuse detection (linkability)", opts);

  // Same taker signs a different message — key image must be the same.
  const message2 = enc.encode("Second proof from the same taker");
  const sig2 = sign(message2, ring, takerIndex, takerSecret);

  const sameKeyImage =
    hex(sig.keyImage) === hex(sig2.keyImage);
  const bothValid = verify(message, ring, sig) && verify(message2, ring, sig2);

  console.log(box("Same taker, two signatures", [
    check("Sig 1 valid", verify(message, ring, sig)),
    check("Sig 2 valid", verify(message2, ring, sig2)),
    check("Key images match (same nullifier)", sameKeyImage),
    "",
    "The maker can link two proofs to the same taker",
    "via the key image, even though the taker's",
    "identity remains anonymous.",
  ]));

  // Different taker — key image must differ.
  const otherIndex = 4;
  const sigOther = sign(message, ring, otherIndex, keys[otherIndex].secretKey);
  const differentKeyImage =
    hex(sig.keyImage) !== hex(sigOther.keyImage);

  console.log(box("Different taker, different nullifier", [
    check("Sig valid", verify(message, ring, sigOther)),
    check("Key images differ (different nullifier)", differentKeyImage),
    "",
    "A different taker produces a different key",
    "image, so the maker can distinguish repeat",
    "takers from new ones.",
  ]));

  // ── 5. Security checks ───────────────────────────────────────
  section("5. Security checks", opts);

  // All four checks always run; only the printing depends on --quick.
  // 5a. Wrong secret key
  const wrongKey = generateKeyPair();
  const sigWrong = sign(message, ring, takerIndex, wrongKey.secretKey);
  const wrongKeyResult = verify(message, ring, sigWrong);

  // 5b. Tampered message
  const tamperedMsg = enc.encode("I am NOT a trusted provider");
  const tamperedMsgResult = verify(tamperedMsg, ring, sig);

  // 5c. Tampered response
  const tamperedSig: LSAGSignature = {
    ...sig,
    responses: [
      new Uint8Array(32), // zero out first response
      ...sig.responses.slice(1),
    ],
  };
  const tamperedRespResult = verify(message, ring, tamperedSig);

  // 5d. Tampered key image
  const tamperedKeyImageSig: LSAGSignature = {
    ...sig,
    keyImage: secp256k1.Point.BASE.toBytes(),
  };
  const tamperedKeyImageResult = verify(message, ring, tamperedKeyImageSig);

  const securityChecksPass =
    !wrongKeyResult && !tamperedMsgResult && !tamperedRespResult &&
    !tamperedKeyImageResult;

  if (opts.quick) {
    // Collapse the four checks into one line to pace a 1-minute demo.
    console.log(`All 4 security checks passed: ${securityChecksPass ? "✅" : "❌"}`);
  } else {
    console.log(box("5a. Wrong secret key", [
      check("Signature with wrong key rejected", !wrongKeyResult),
      "The taker must know the secret key for",
      `maker[${takerIndex}] to produce a valid proof.`,
    ]));

    console.log(box("5b. Tampered message", [
      check("Tampered message rejected", !tamperedMsgResult),
      "Changing the signed message invalidates",
      "the ring signature.",
    ]));

    console.log(box("5c. Tampered response", [
      check("Tampered response rejected", !tamperedRespResult),
      "Modifying any response scalar breaks the",
      "ring closure and verification fails.",
    ]));

    console.log(box("5d. Tampered key image (nullifier)", [
      check("Tampered key image rejected", !tamperedKeyImageResult),
      "Substituting the key image invalidates the",
      "signature — the nullifier is bound to the",
      "signer's secret key.",
    ]));
  }

  // ── Summary ──────────────────────────────────────────────────
  section("Summary", opts);

  const allPass =
    isValid &&
    bothValid &&
    sameKeyImage &&
    differentKeyImage &&
    !wrongKeyResult &&
    !tamperedMsgResult &&
    !tamperedRespResult &&
    !tamperedKeyImageResult;

  console.log(box("All checks", [
    check("Valid signature verifies", isValid),
    check("Linkability (same nullifier for same taker)", sameKeyImage),
    check("Different takers have different nullifiers", differentKeyImage),
    check("Wrong key rejected", !wrongKeyResult),
    check("Tampered message rejected", !tamperedMsgResult),
    check("Tampered response rejected", !tamperedRespResult),
    check("Tampered key image rejected", !tamperedKeyImageResult),
    "",
    check("ALL SECURITY CHECKS PASSED", allPass),
  ]));

  console.log();
  console.log("Demo complete.");
  console.log();
}

// Run when invoked directly via tsx
if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/"))) {
  main();
}
