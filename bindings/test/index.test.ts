import {describe, expect, it} from "vitest";

describe("sanity", () => {
  it("should load bindings", async () => {
    const bindings = await import("../src/index.ts");
    expect(bindings).toBeDefined();
  });
});

describe("pool bindings", () => {
  it("should initialize and deinitialize the pool", async () => {
    const bindings = (await import("../src/index.ts")).default;
    bindings.pool.init(4);
    bindings.pool.deinit();
  });
});
