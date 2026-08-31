import {spawnSync} from "node:child_process";
import {join} from "node:path";
import {describe, expect, it} from "vitest";

const capacityVariable = "LODESTAR_Z_NODE_POOL_CAPACITY";
const projectRoot = join(import.meta.dirname, "../..");
const loadDefaultPool = `
import bindings from "./bindings/src/index.js";
bindings.pool.ensureCapacity(10_000_000);
console.log("loaded");
`;
const exceedConfiguredPool = `
import bindings from "./bindings/src/index.js";
try {
  bindings.pool.ensureCapacity(1_000);
  console.log("unexpected success");
} catch (error) {
  console.log(String(error));
}
`;

function runWithCapacity(source: string, capacity?: string) {
  const env = {...process.env};
  if (capacity === undefined) {
    delete env[capacityVariable];
  } else {
    env[capacityVariable] = capacity;
  }
  return spawnSync(process.execPath, ["--input-type=module", "--eval", source], {
    cwd: projectRoot,
    encoding: "utf-8",
    env,
    timeout: 60_000,
  });
}

describe("node pool initialization", () => {
  it("uses the default fixed capacity", () => {
    const result = runWithCapacity(loadDefaultPool);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout.trim()).toBe("loaded");
  });

  it("uses the capacity from the process environment", () => {
    const result = runWithCapacity(exceedConfiguredPool, "17");
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("PoolExhausted");
  });

  it.each(["", "abc", "2147483647", "4294967296"])("rejects invalid capacity %j", (capacity) => {
    const result = runWithCapacity(loadDefaultPool, capacity);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("InvalidPoolCapacity");
  });
});
