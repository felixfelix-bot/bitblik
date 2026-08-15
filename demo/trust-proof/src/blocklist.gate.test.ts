import { describe, it, expect, afterEach } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { main } from "./demo.js";

// ─── Helpers ───────────────────────────────────────────────────

const PKG_DIR = fileURLToPath(new URL("..", import.meta.url));
const TSX_BIN = path.join(PKG_DIR, "node_modules", ".bin", "tsx");

/** Every test points the demo at its own throwaway blocklist file. */
async function freshBlocklistFile(): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), "blocklist-gate-"));
  return path.join(dir, "blocklist.json");
}

async function captureMainOutput(argv: string[]): Promise<string> {
  const logs: string[] = [];
  const orig = console.log;
  const spy = orig.bind(console);
  console.log = (...a: unknown[]) => {
    logs.push(a.map(String).join(" "));
  };
  try {
    await main(argv);
  } finally {
    console.log = spy;
  }
  return logs.join("\n");
}

const ENV_KEY = "TRUST_DEMO_BLOCKLIST_FILE";
let savedEnv: string | undefined;

afterEach(() => {
  if (savedEnv === undefined) delete process.env[ENV_KEY];
  else process.env[ENV_KEY] = savedEnv;
  savedEnv = undefined;
});

function pointDemoAt(file: string): void {
  savedEnv = process.env[ENV_KEY];
  process.env[ENV_KEY] = file;
}

// ─── Section wiring ────────────────────────────────────────────

describe("demo: key-image blocklist gate (T2)", () => {
  it("has a blocklist gate section between verification and nullifier reuse", async () => {
    const file = await freshBlocklistFile();
    pointDemoAt(file);
    const out = await captureMainOutput(["--offline"]);
    const iVerify = out.indexOf("3. Maker");
    const iGate = out.indexOf("4. Key-image blocklist gate");
    const iNullifier = out.indexOf("5. Nullifier reuse detection");
    expect(iVerify).toBeGreaterThan(-1);
    expect(iGate).toBeGreaterThan(iVerify);
    expect(iNullifier).toBeGreaterThan(iGate);
  }, 30_000);

  it("clean key image → trade proceeds: check runs BEFORE the sats step, then pays", async () => {
    const file = await freshBlocklistFile();
    pointDemoAt(file);
    const out = await captureMainOutput(["--offline"]);
    const iCheck = out.indexOf("NOT on the blocklist");
    const iPay = out.indexOf("→ maker: paying 50000 sats over Lightning");
    expect(iCheck).toBeGreaterThan(-1);
    expect(iPay).toBeGreaterThan(-1);
    // THE ordering claim of T2: the gate is evaluated BEFORE sats move.
    expect(iCheck).toBeLessThan(iPay);
    expect(out).toContain("→ taker: BLIK code delivered");
  }, 30_000);

  it("known keyImage → SATS WITHHELD with an explicit message naming the key image", async () => {
    const file = await freshBlocklistFile();
    pointDemoAt(file);
    const out = await captureMainOutput(["--offline"]);

    const iPay = out.indexOf("→ maker: paying 50000 sats over Lightning");
    const iWithheld = out.search(/SATS WITHHELD — key image [0-9a-f]+\.\.\./);
    expect(iWithheld).toBeGreaterThan(-1);
    // The explicit refusal message:
    expect(out).toMatch(
      /SATS WITHHELD — key image [0-9a-f.]+ is on the maker's blocklist; refusing to pay 50000 sats/,
    );
    // Exactly ONE payment in the whole run: the clean trade. The known-bad
    // offer must never pay — no payment line may appear after the withhold.
    expect(out.match(/paying \d+ sats over Lightning/g)).toEqual([
      "paying 50000 sats over Lightning",
    ]);
    expect(iPay).toBeGreaterThan(-1);
    expect(iWithheld).toBeGreaterThan(iPay);
    const after = out.slice(iWithheld);
    expect(after).not.toMatch(/paying \d+ sats/);
  }, 30_000);

  it("the withheld trade's proof still verifies — the gate is separate from verification", async () => {
    const file = await freshBlocklistFile();
    pointDemoAt(file);
    const out = await captureMainOutput(["--offline"]);
    expect(out).toContain("new proof still verifies");
    expect(out).toContain("SATS WITHHELD");
  }, 30_000);

  it("persistence: the disputed key image is written to the blocklist file", async () => {
    const file = await freshBlocklistFile();
    pointDemoAt(file);
    await captureMainOutput(["--offline"]);
    const doc = JSON.parse(await readFile(file, "utf8")) as {
      v: number;
      blocked: string[];
    };
    expect(doc.v).toBe(1);
    expect(doc.blocked.length).toBeGreaterThanOrEqual(1);
    for (const k of doc.blocked) {
      expect(k).toMatch(/^(02|03)[0-9a-f]{64}$/);
    }
  }, 30_000);

  it("the gate re-loads the blocklist from disk after persisting (not in-memory state)", async () => {
    const file = await freshBlocklistFile();
    pointDemoAt(file);
    const out = await captureMainOutput(["--offline"]);
    expect(out).toContain("re-loaded from disk");
    expect(out).toMatch(/1 persisted key image/);
  }, 30_000);

  it("summary includes the blocklist gate verdict", async () => {
    const file = await freshBlocklistFile();
    pointDemoAt(file);
    const out = await captureMainOutput(["--offline"]);
    expect(out).toContain("Blocklist gate: clean paid, known-bad withheld");
  }, 30_000);

  it("stale entries from an earlier run never false-positive a fresh taker", async () => {
    const file = await freshBlocklistFile();
    pointDemoAt(file);
    await captureMainOutput(["--offline"]); // run 1 persists its (now stale) key image
    const out2 = await captureMainOutput(["--offline"]); // run 2: fresh taker, same file
    expect(out2).toContain("NOT on the blocklist");
    expect(out2).toContain("→ maker: paying 50000 sats over Lightning");
  }, 60_000);
});

// ─── CLI end-to-end (fresh process, real file on disk) ─────────

describe("CLI end-to-end: blocklist gate (T2)", () => {
  it("fresh process: clean trade pays, disputed taker withheld, file persisted", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "blocklist-cli-"));
    const file = path.join(dir, "blocklist.json");
    const out = execFileSync(
      TSX_BIN,
      ["src/demo.ts", "--quick", "--offline"],
      {
        cwd: PKG_DIR,
        encoding: "utf8",
        timeout: 60_000,
        env: { ...process.env, TRUST_DEMO_BLOCKLIST_FILE: file },
      },
    );
    expect(out).toContain("→ maker: paying 50000 sats over Lightning");
    expect(out).toMatch(/SATS WITHHELD — key image [0-9a-f]+\.\.\./);
    // …and the file the process wrote is a valid persisted blocklist
    const doc = JSON.parse(await readFile(file, "utf8")) as {
      v: number;
      blocked: string[];
    };
    expect(doc.v).toBe(1);
    expect(doc.blocked.length).toBeGreaterThanOrEqual(1);
  }, 90_000);
});
