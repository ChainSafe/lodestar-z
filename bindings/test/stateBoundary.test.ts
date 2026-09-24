import {spawnSync} from "node:child_process";
import {describe, expect, it} from "vitest";

const bindingsPath = new URL("../src/index.js", import.meta.url).href;
const fixturePath = new URL("./stfFixture.ts", import.meta.url).href;

describe("native state transition boundaries", () => {
  it.each([
    [
      "missing config",
      "bindings.BeaconStateView.createFromBytes(new Uint8Array(47))",
      "Method expects at least 2 arguments",
    ],
    ...["undefined", "null", "{}", "Object.create(bindings.BeaconConfig.prototype)", "state"].map((config) => [
      `invalid config ${config}`,
      `bindings.BeaconStateView.createFromBytes(new Uint8Array(47), ${config})`,
      config === "undefined" || config === "null"
        ? "Cannot convert undefined or null to object"
        : "Argument 2 must be an instance of BeaconConfig",
    ]),
    ["truncated state", "bindings.BeaconStateView.createFromBytes(new Uint8Array(47), config)", "InvalidStateBytes"],
    ["truncated block", "state.stateTransition(new Uint8Array(107), false)", "InvalidSignedBlockBytes"],
    [
      "invalid signed block offset",
      "state.stateTransition(new Uint8Array(108).fill(255), false)",
      "InvalidSignedBlockBytes",
    ],
    [
      "noncanonical signed block offset",
      "state.stateTransition(new Uint8Array(108), false)",
      "InvalidSignedBlockBytes",
    ],
    ["Gloas slots", "state.processSlots(state.slot + 1)", "UnsupportedFork"],
    ["negative slot", "state.processSlots(-1)", "InvalidSlot"],
    ["fractional slot", "state.processSlots(1.5)", "InvalidSlot"],
    ["negative block-root slot", "state.getBlockRootAtSlot(-1)", "InvalidSlot"],
    ["negative validator index", "state.getValidator(-1)", "InvalidUnsignedInteger"],
    ["fractional committee epoch", "state.getBeaconCommitteeCountPerSlot(0.5)", "InvalidUnsignedInteger"],
    ["zero proof index", "state.getSingleProof(0n)", "Failed to get single proof"],
    ["truncated loaded state", "state.loadOtherState(new Uint8Array(47))", "InvalidStateBytes"],
    [
      "Gloas loaded state",
      "state.loadOtherState(ssz.fulu.BeaconState.serialize({...createStfState(), slot: state.slot + 1}))",
      "UnsupportedFork",
    ],
    [
      "Gloas block",
      `state.stateTransition(ssz.fulu.SignedBeaconBlock.serialize({
        ...ssz.fulu.SignedBeaconBlock.defaultValue(),
        message: {...ssz.fulu.BeaconBlock.defaultValue(), slot: state.slot + 1}
      }), false)`,
      "UnsupportedFork",
    ],
    [
      "Gloas state",
      `bindings.BeaconStateView.createFromBytes(ssz.fulu.BeaconState.serialize({
        ...createStfState(), slot: state.slot + 1
      }), config)`,
      "UnsupportedFork",
    ],
  ])("rejects %s without aborting", (_name, operation, error) => {
    const result = spawnSync(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        `
      import assert from "node:assert/strict";
      import {ssz} from "@lodestar/types";
      import bindings from ${JSON.stringify(bindingsPath)};
      import {createStfState, stfConfig} from ${JSON.stringify(fixturePath)};
      const config = new bindings.BeaconConfig({...stfConfig, GLOAS_FORK_EPOCH: stfConfig.FULU_FORK_EPOCH + 1}, new Uint8Array(32));
      bindings.pubkeys.ensureCapacity(16);
      const state = bindings.BeaconStateView.createFromBytes(ssz.fulu.BeaconState.serialize(createStfState()), config);
      assert.throws(() => { ${operation}; }, {message: ${JSON.stringify(error)}});
    `,
      ],
      {cwd: new URL("../..", import.meta.url), encoding: "utf8", timeout: 30_000}
    );
    expect(result.signal, result.stderr).toBeNull();
    expect(result.status, result.stderr).toBe(0);
  });
});
