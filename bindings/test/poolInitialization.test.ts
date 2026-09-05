import {spawnSync} from "node:child_process";
import {expect, it} from "vitest";

it("keeps BLS and configuration-only environments below the unused pool allocation", {timeout: 30_000}, () => {
  const workerSource = `
    import assert from "node:assert/strict";
    import {parentPort} from "node:worker_threads";
    import {mainnetChainConfig} from "@lodestar/config/configs";
    import bindings from "./bindings/src/index.js";
    import {SecretKey} from "./bindings/src/blst.js";
    globalThis.setup = new bindings.StateTransition(mainnetChainConfig, new Uint8Array(32));
    assert.equal(SecretKey.fromKeygen(new Uint8Array(32).fill(1)).toPublicKey().toBytes().length, 48);
    parentPort.on("message", () => {});
    parentPort.postMessage("ready");
  `;
  runProcess(`
    import assert from "node:assert/strict";
    import {Worker} from "node:worker_threads";
    import {mainnetChainConfig} from "@lodestar/config/configs";
    const beforeImport = process.memoryUsage.rss();
    const {SecretKey} = await import("./bindings/src/blst.js");
    const {default: bindings} = await import("./bindings/src/index.js");
    globalThis.setup = new bindings.StateTransition(mainnetChainConfig, new Uint8Array(32));
    assert.equal(SecretKey.fromKeygen(new Uint8Array(32).fill(1)).toPublicKey().toBytes().length, 48);
    const afterImport = process.memoryUsage.rss();
    const budget = 128 * 1024 * 1024;
    assert.ok(afterImport - beforeImport < budget, "idle main environment reserved a tree pool");
    const worker = new Worker(${JSON.stringify(workerSource)}, {eval: true});
    try {
      await new Promise((resolve, reject) => {
        worker.once("message", resolve);
        worker.once("error", reject);
      });
      assert.ok(process.memoryUsage.rss() - afterImport < budget, "idle worker reserved a tree pool");
    } finally {
      await worker.terminate();
    }
  `);
});

it("defers invalid capacity until state creation and retries failed pool initialization", {timeout: 30_000}, () => {
  runProcess(
    `
    import assert from "node:assert/strict";
    import {ssz} from "@lodestar/types";
    import bindings from "./bindings/src/index.js";
    import {createStfState, stfConfig} from "./bindings/test/stfFixture.ts";
    const setup = new bindings.StateTransition(stfConfig, new Uint8Array(32));
    bindings.pubkeys.ensureCapacity(16);
    const value = createStfState();
    const bytes = ssz.fulu.BeaconState.serialize(value);
    assert.throws(() => setup.createFromBytes(bytes.subarray(0, 47)), {code: "InvalidStateBytes"});
    for (const capacity of ["invalid", "2147483647"]) {
      process.env.LODESTAR_Z_NODE_POOL_CAPACITY = capacity;
      for (let i = 0; i < 10; i++) {
        assert.throws(() => setup.createFromBytes(bytes), {code: "InvalidPoolCapacity"}, capacity + ": " + i);
      }
    }
    process.env.LODESTAR_Z_NODE_POOL_CAPACITY = "1000000";
    const state = setup.createFromBytes(bytes);
    assert.equal(state.slot, value.slot);
    assert.equal(state.processSlots(state.slot + 1).slot, state.slot + 1);
    `,
    "invalid"
  );
});

function runProcess(source: string, capacity = "10000000"): void {
  const result = spawnSync(process.execPath, ["--input-type=module", "-e", `${source}\nconsole.log("completed");`], {
    cwd: new URL("../../", import.meta.url),
    encoding: "utf8",
    env: {...process.env, LODESTAR_Z_NODE_POOL_CAPACITY: capacity, NODE_OPTIONS: ""},
    timeout: 20_000,
  });
  expect(result.error).toBeUndefined();
  expect(result.status, result.stderr).toBe(0);
  expect(result.stdout.trim()).toBe("completed");
}
