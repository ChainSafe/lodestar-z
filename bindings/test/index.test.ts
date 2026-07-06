import {describe, expect, it} from "vitest";

describe("sanity", () => {
  it("should load bindings", async () => {
    const bindings = await import("../src/index.js");
    expect(bindings).toBeDefined();
  });

  it("metrics exposes validator monitor registration", async () => {
    const bindings = await import("../src/index.js");
    expect(typeof bindings.default.metrics.registerLocalValidator).toBe("function");
  });
});
