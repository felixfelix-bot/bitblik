/**
 * Persisted key-image blocklist (T2) — the maker's local deny list of
 * LSAG nullifiers.
 *
 * Verification proves ring MEMBERSHIP, not honesty: a taker whose proof
 * verifies can still have burned this maker before (stolen-card-funded
 * BLIK code, chargeback). The key image `I = x_s · H(P_s)` is constant
 * per signer and reveals nothing about WHO they are — exactly the right
 * handle for a deny list. Before any sats move, the maker checks the
 * proof's key image against this blocklist; a known-bad nullifier
 * withholds the payment.
 *
 * Persistence is a plain JSON file:
 *   {"v": 1, "blocked": ["<66 lowercase hex key image>", ...]}
 *
 * Design rules:
 *   - dependency-free (node builtins only) so any process — including
 *     freshly spawned ones — can read the list with zero setup;
 *   - fail LOUD: a corrupt file throws (a silently-empty blocklist would
 *     silently UN-block known-bad takers — the worst failure mode);
 *   - entries are canonical lowercase 66-hex compressed points; input
 *     matching is case-insensitive and normalized before comparison;
 *   - writes are load-merge-save and ATOMIC (temp file + rename): existing
 *     entries are preserved, re-blocking a known image is a no-op, and a
 *     concurrent reader never sees a partially-written file.
 */

import { readFile, writeFile, rename } from "node:fs/promises";
import { randomBytes } from "node:crypto";

/** On-disk schema version. Bump on breaking format changes. */
export const BLOCKLIST_FILE_VERSION = 1;

/** A key image is a 33-byte COMPRESSED secp256k1 point: "02"/"03" + 64 hex. */
const KEY_IMAGE_HEX_RE = /^(02|03)[0-9a-fA-F]{64}$/;
/** Entries INSIDE the file must be canonical (lowercase). */
const CANONICAL_KEY_IMAGE_RE = /^(02|03)[0-9a-f]{64}$/;

/** Is this a plausible key image (66 hex chars encoding a compressed point)? */
export function isValidKeyImageHex(keyImageHex: string): boolean {
  return typeof keyImageHex === "string" && KEY_IMAGE_HEX_RE.test(keyImageHex);
}

/**
 * Validate and canonicalize a key image to lowercase hex. Throws a clear
 * error for anything that is not a 33-byte compressed point in hex.
 */
export function normalizeKeyImageHex(keyImageHex: string): string {
  if (!isValidKeyImageHex(keyImageHex)) {
    const shown =
      typeof keyImageHex === "string" && keyImageHex.length > 0
        ? `"${keyImageHex.slice(0, 16)}${keyImageHex.length > 16 ? "..." : ""}"`
        : "(empty)";
    throw new Error(
      `Invalid key image ${shown}: expected 66 hex characters ` +
        `(33-byte compressed point, "02"/"03" prefix)`,
    );
  }
  return keyImageHex.toLowerCase();
}

/** The on-disk document (before validation). */
interface BlocklistDocument {
  v?: unknown;
  blocked?: unknown;
}

/**
 * Read and validate the blocklist file at `path`.
 *   - File missing (ENOENT)  → `[]` (a fresh maker has an empty list).
 *   - Malformed JSON, wrong version, non-array `blocked`, or any
 *     non-canonical entry → throws. Never returns a silently-truncated
 *     or silently-empty list for a file that EXISTS but is corrupt.
 */
async function readBlocklistEntries(path: string): Promise<string[]> {
  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException)?.code === "ENOENT") return [];
    throw e;
  }

  let doc: BlocklistDocument;
  try {
    doc = JSON.parse(raw) as BlocklistDocument;
  } catch (e) {
    const reason = e instanceof Error ? e.message : String(e);
    throw new Error(`blocklist file ${path} is not valid JSON: ${reason}`);
  }

  if (doc === null || typeof doc !== "object" || Array.isArray(doc) ||
      !Array.isArray(doc.blocked)) {
    throw new Error(
      `blocklist file ${path}: "blocked" must be an array of key images`,
    );
  }
  if (doc.v !== BLOCKLIST_FILE_VERSION) {
    throw new Error(
      `blocklist file ${path}: unsupported version ${String(doc.v)} ` +
        `(expected ${BLOCKLIST_FILE_VERSION})`,
    );
  }
  for (const entry of doc.blocked) {
    if (typeof entry !== "string" || !CANONICAL_KEY_IMAGE_RE.test(entry)) {
      throw new Error(
        `blocklist file ${path}: corrupt entry — every blocked key image ` +
          `must be 66 lowercase hex characters (33-byte compressed point)`,
      );
    }
  }
  return [...(doc.blocked as string[])];
}

/**
 * Load the persisted blocklist. Missing file → empty list (nothing
 * blocklisted yet). A corrupt EXISTING file throws — see
 * {@link readBlocklistEntries}.
 */
export async function loadKeyImageBlocklist(path: string): Promise<string[]> {
  return readBlocklistEntries(path);
}

/**
 * Is this key image on the persisted blocklist? Input is validated and
 * matched case-insensitively (canonical lowercase comparison).
 */
export async function isKeyImageBlocked(
  path: string,
  keyImageHex: string,
): Promise<boolean> {
  const keyImage = normalizeKeyImageHex(keyImageHex);
  const entries = await readBlocklistEntries(path);
  return entries.includes(keyImage);
}

/**
 * Persist the blocklist ATOMICALLY: write a uniquely-named sibling temp
 * file, then rename(2) it over the target. rename is atomic on POSIX, so
 * a concurrent reader (another demo run, a spawned process, a parallel
 * test worker) always sees either the old or the new COMPLETE document —
 * never a truncated or partially-written file. Non-atomic writeFile was
 * observed to tear under parallel test workers sharing the default file.
 */
async function persistBlocklist(path: string, entries: string[]): Promise<void> {
  const tmp =
    `${path}.tmp-${process.pid}-${Date.now().toString(36)}` +
    `-${randomBytes(6).toString("hex")}`;
  const doc = { v: BLOCKLIST_FILE_VERSION, blocked: entries };
  await writeFile(tmp, JSON.stringify(doc, null, 2) + "\n", "utf8");
  await rename(tmp, path);
}

/**
 * Persist a key image to the blocklist (idempotent load-merge-save).
 * Existing entries survive; blocking a known image is a no-op. Returns
 * the full persisted entry list.
 */
export async function blockKeyImage(
  path: string,
  keyImageHex: string,
): Promise<string[]> {
  const keyImage = normalizeKeyImageHex(keyImageHex);
  const entries = await readBlocklistEntries(path);
  if (!entries.includes(keyImage)) {
    entries.push(keyImage);
  }
  await persistBlocklist(path, entries);
  return entries;
}
