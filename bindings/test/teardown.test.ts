import {spawnSync} from "node:child_process";
import {writeFileSync, unlinkSync} from "node:fs";
import {join} from "node:path";
import {describe, expect, it} from "vitest";

describe("BeaconStateView teardown", () => {
  it("creates view at module scope and exits cleanly", () => {
    const projectRoot = join(import.meta.dirname, "../..");
    // Fixture must live under the project root so Node resolves its
    // node_modules from there (workspace packages like @lodestar/config).
    const fixturePath = join(projectRoot, `bindings/test/.tmp-teardown-${process.pid}.mjs`);

    // Module-scope `const seedState = ...` mirrors how perf bench files
    // hold native objects. Without the Pool refcount fix, NAPI env cleanup
    // frees the pool before this view's finalizer runs, and the chained
    // pool.unref calls panic with "incorrect alignment" on process exit
    // (exit code 134 / SIGABRT).
    writeFileSync(
      fixturePath,
      `
import {config} from "@lodestar/config/default";
import * as era from "@lodestar/era";
import bindings from "../src/index.js";
import {getFirstEraFilePath} from "./eraFiles.ts";

const reader = await era.era.EraReader.open(config, getFirstEraFilePath());
const stateBytes = await reader.readSerializedState();
await reader.close();

bindings.pool.ensureCapacity(10_000_000);
bindings.pubkeys.ensureCapacity(2_000_000);

const seedState = bindings.BeaconStateView.createFromBytes(stateBytes);
console.log("slot=" + seedState.slot);
`,
    );

    try {
      const result = spawnSync(
        process.execPath,
        ["--experimental-strip-types", fixturePath],
        {encoding: "utf-8", cwd: projectRoot, timeout: 60_000},
      );
      expect(result.status, `stdout=${result.stdout} stderr=${result.stderr}`).toBe(0);
      expect(result.stderr, "no panic on stderr").not.toContain("panic:");
    } finally {
      try {
        unlinkSync(fixturePath);
      } catch (_e) {
        // ignore
      }
    }
  }, 90_000);
});
