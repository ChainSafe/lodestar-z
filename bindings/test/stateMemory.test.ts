import {spawnSync} from "node:child_process";
import {expect, it} from "vitest";

it("reclaims discarded native states under memory pressure without explicit GC", {timeout: 40_000}, () => {
  const result = spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      `
      import assert from "node:assert/strict";
      import {ssz} from "@lodestar/types";
      import bindings from "./bindings/src/index.js";
      import {createStfState, stfConfig} from "./bindings/test/stfFixture.ts";
      assert.equal(typeof global.gc, "undefined");
      const setup = new bindings.StateTransition(stfConfig, new Uint8Array(32));
      bindings.pubkeys.ensureCapacity(16);
      const bytes = ssz.fulu.BeaconState.serialize(createStfState());
      const seed = setup.createFromBytes(bytes);
      const seedRoot = seed.hashTreeRoot();
      for (let i = 0; i < 500; i++) {
        assert.equal(setup.createFromBytes(bytes).forkSeq, 6, "iteration " + i);
        assert.equal(seed.processSlots(seed.slot).slot, seed.slot, "clone " + i);
        await new Promise((resolve) => setImmediate(resolve));
      }
      assert.deepEqual(seed.hashTreeRoot(), seedRoot);
      console.log("completed");
      `,
    ],
    {
      cwd: new URL("../../", import.meta.url),
      encoding: "utf8",
      env: {...process.env, LODESTAR_Z_NODE_POOL_CAPACITY: "10000000", NODE_OPTIONS: ""},
      timeout: 30_000,
    }
  );
  expect(result.error).toBeUndefined();
  expect(result.status, result.stderr).toBe(0);
  expect(result.stdout.trim()).toBe("completed");
});
