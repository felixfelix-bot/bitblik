import { describe, it, expect, vi, afterEach } from "vitest";
import { main, parseArgs, pause } from "./demo.js";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("demo", () => {
  it("main is a function and does not throw", () => {
    expect(typeof main).toBe("function");
    expect(() => main()).not.toThrow();
  });
});

describe("flag parsing", () => {
  it("--interactive sets interactive=true", () => {
    expect(parseArgs(["--interactive"])).toEqual({
      interactive: true,
      quick: false,
    });
  });

  it("--quick sets quick=true", () => {
    expect(parseArgs(["--quick"])).toEqual({
      interactive: false,
      quick: true,
    });
  });

  it("no flags = default behavior unchanged", () => {
    expect(parseArgs([])).toEqual({ interactive: false, quick: false });
  });

  it("combined --interactive --quick works", () => {
    expect(parseArgs(["--interactive", "--quick"])).toEqual({
      interactive: true,
      quick: true,
    });
  });
});

describe("pause", () => {
  it("is a no-op when interactive=false — no prompt, no stdin read", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const waitForKey = vi.fn();
    pause({ interactive: false, waitForKey });
    expect(log).not.toHaveBeenCalled();
    expect(waitForKey).not.toHaveBeenCalled();
  });

  it("prints '[Enter] to continue...' and reads stdin when interactive=true", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const waitForKey = vi.fn();
    pause({ interactive: true, waitForKey });
    expect(log).toHaveBeenCalledWith("[Enter] to continue...");
    expect(waitForKey).toHaveBeenCalledTimes(1);
  });
});

describe("demo output flags", () => {
  // waitForKey is always injected so interactive runs never touch real stdin.
  function captureMainOutput(opts: {
    interactive: boolean;
    quick: boolean;
  }): string {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    main({ ...opts, waitForKey: () => {} });
    return log.mock.calls.map((args) => args.join(" ")).join("\n");
  }

  it("no flags: full security check details shown, no pause prompt", () => {
    const out = captureMainOutput({ interactive: false, quick: false });
    expect(out).toContain("5. Security checks");
    expect(out).toContain("5a. Wrong secret key");
    expect(out).toContain("5b. Tampered message");
    expect(out).toContain("5c. Tampered response");
    expect(out).toContain("5d. Tampered key image");
    expect(out).not.toContain("[Enter] to continue...");
    expect(out).not.toContain("All 4 security checks passed");
  });

  it("--quick: security checks collapse to a single summary line", () => {
    const out = captureMainOutput({ interactive: false, quick: true });
    expect(out).toContain("All 4 security checks passed: ✅");
    expect(out).not.toContain("5a. Wrong secret key");
    expect(out).not.toContain("5b. Tampered message");
    expect(out).not.toContain("5c. Tampered response");
    expect(out).not.toContain("5d. Tampered key image");
  });

  it("--interactive: pause prompt after each of the 6 section headers", () => {
    const out = captureMainOutput({ interactive: true, quick: false });
    expect(out.match(/\[Enter\] to continue\.\.\./g)?.length).toBe(6);
  });

  it("--interactive: injected waitForKey is called once per section", () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const waitForKey = vi.fn();
    main({ interactive: true, quick: false, waitForKey });
    expect(waitForKey).toHaveBeenCalledTimes(6);
  });

  it("combined --interactive --quick works", () => {
    const out = captureMainOutput({ interactive: true, quick: true });
    expect(out).toContain("[Enter] to continue...");
    expect(out).toContain("All 4 security checks passed: ✅");
    expect(out).not.toContain("5a. Wrong secret key");
  });
});
