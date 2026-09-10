import {spawnSync} from "node:child_process";
import {expect, it} from "vitest";

it("reclaims released states while their wrappers remain reachable without GC", {timeout: 40_000}, () => {
  runProcess(`
    assert.equal(typeof global.gc, "undefined");
    const setup = new bindings.StateTransition(stfConfig, new Uint8Array(32));
    const retained = [];
    const expectedRoot = ssz.fulu.BeaconState.hashTreeRoot(value);
    for (let i = 0; i < 100; i++) {
      const state = setup.createFromBytes(bytes);
      const clone = state.processSlots(state.slot);
      state.release();
      assert.throws(() => state.slot, {code: "InvalidState"}, "released state " + i);
      assert.deepEqual(clone.hashTreeRoot(), expectedRoot, "retained clone " + i);
      clone.release();
      state.release();
      clone.release();
      assert.throws(() => clone.hashTreeRoot(), {code: "InvalidState"}, "released clone " + i);
      retained.push(state, clone);
    }
    assert.equal(retained.length, 200);
  `);
});

it("keeps descendants usable after release and finalization of their owners", {timeout: 40_000}, () => {
  runProcess(
    `
    let setup = new bindings.StateTransition(stfConfig, new Uint8Array(32));
    let state = setup.createFromBytes(bytes);
    const descendant = state.processSlots(state.slot);
    const expectedRoot = descendant.hashTreeRoot();
    setup = undefined;
    state.release();
    state = undefined;
    global.gc();
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(descendant.hashTreeRoot(), expectedRoot);
    const advanced = descendant.processSlots(descendant.slot + 1);
    descendant.release();
    descendant.release();
    assert.equal(advanced.slot, value.slot + 1);
    globalThis.retainedAtExit = {advanced, descendant};
    `,
    true
  );
});

it.each([
  [
    "slot options getter",
    `
    const slot = state.slot;
    const descendant = state.processSlots(slot, {
      get dontTransferCache() {
        state.release();
        assert.throws(() => state.slot, {code: "InvalidState"});
        return true;
      }
    });
    assert.equal(descendant.slot, slot);
    assert.deepEqual(descendant.hashTreeRoot(), ssz.fulu.BeaconState.hashTreeRoot(value));
    descendant.release();
    `,
  ],
  [
    "transition options getter",
    `
    const block = ssz.fulu.SignedBeaconBlock.defaultValue();
    block.message.slot = state.slot + 1;
    block.message.proposerIndex = state.getBeaconProposer(block.message.slot);
    assert.throws(() => state.stateTransition(ssz.fulu.SignedBeaconBlock.serialize(block), false, {
      get verifyStateRoot() { state.release(); return false; },
      verifyProposer: false,
      verifySignatures: false
    }), {code: "BlockParentRootMismatch"});
    `,
  ],
  [
    "Map construction and set callbacks",
    `
    const NativeMap = Map;
    globalThis.Map = class extends NativeMap {
      constructor() { super(); state.release(); }
      set(key, value) { state.release(); return super.set(key, value); }
    };
    let committee;
    try { committee = state.currentSyncCommitteeIndexed; }
    finally { globalThis.Map = NativeMap; }
    assert.equal(committee.validatorIndices.length, 512);
    assert.deepEqual(committee.validatorIndexMap.get(0), Array.from({length: 512}, (_, i) => i));
    `,
  ],
  [
    "Set membership callback",
    `
    const epoch = state.epoch;
    const statuses = new Set();
    statuses.has = () => { state.release(); return true; };
    assert.equal(state.getValidatorsByStatus(statuses, epoch).length, value.validators.length);
    `,
  ],
  [
    "inherited output setter",
    `
    Object.defineProperty(Object.prototype, "depositRoot", {
      configurable: true,
      set(root) {
        state.release();
        Object.defineProperty(this, "depositRoot", {value: root, enumerable: true});
      }
    });
    let result;
    try { result = state.eth1Data; }
    finally { Reflect.deleteProperty(Object.prototype, "depositRoot"); }
    assert.deepEqual(result.depositRoot, value.eth1Data.depositRoot);
    assert.equal(result.depositCount, value.eth1Data.depositCount);
    `,
  ],
  [
    "nested output setter",
    `
    let nested = false;
    Object.defineProperty(Object.prototype, "depositRoot", {
      configurable: true,
      set(root) {
        if (nested) {
          state.release();
        } else {
          nested = true;
          assert.equal(state.eth1Data.depositCount, value.eth1Data.depositCount);
        }
        Object.defineProperty(this, "depositRoot", {value: root, enumerable: true});
      }
    });
    let result;
    try { result = state.eth1Data; }
    finally { Reflect.deleteProperty(Object.prototype, "depositRoot"); }
    assert.deepEqual(result.depositRoot, value.eth1Data.depositRoot);
    assert.equal(result.depositCount, value.eth1Data.depositCount);
    `,
  ],
  [
    "throwing options getter",
    `
    const slot = state.slot;
    assert.throws(() => state.processSlots(slot, {
      get dontTransferCache() {
        state.release();
        throw new Error("options failed");
      }
    }), {message: "options failed"});
    `,
  ],
])("retains the active state through release in a %s", {timeout: 40_000}, (_name, source) => {
  runProcess(`
    const state = new bindings.StateTransition(stfConfig, new Uint8Array(32)).createFromBytes(bytes);
    ${source}
    assert.throws(() => state.slot, {code: "InvalidState"});
    state.release();
  `);
});

function runProcess(source: string, exposeGc = false): void {
  const result = spawnSync(
    process.execPath,
    [
      ...(exposeGc ? ["--expose-gc"] : []),
      "--input-type=module",
      "-e",
      `
      import assert from "node:assert/strict";
      import {ssz} from "@lodestar/types";
      import bindings from "./bindings/src/index.js";
      import {pubkeyCache} from "./bindings/src/pubkeys.js";
      import {createStfState, stfConfig} from "./bindings/test/stfFixture.ts";
      const value = createStfState();
      const bytes = ssz.fulu.BeaconState.serialize(value);
      pubkeyCache.ensureCapacity(value.validators.length);
      ${source}
      console.log("completed");
      `,
    ],
    {
      cwd: new URL("../../", import.meta.url),
      encoding: "utf8",
      env: {...process.env, LODESTAR_Z_NODE_POOL_CAPACITY: "500000", NODE_OPTIONS: ""},
      timeout: 30_000,
    }
  );
  expect(result.error).toBeUndefined();
  expect(result.status, result.stderr).toBe(0);
  expect(result.stdout.trim()).toBe("completed");
}
