import { describe, it, expect } from "vitest";
import { main } from "./demo.js";

describe("demo", () => {
  it("main is a function and does not throw", () => {
    expect(typeof main).toBe("function");
    expect(() => main()).not.toThrow();
  });
});
