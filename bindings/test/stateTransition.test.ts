import {ssz} from "@lodestar/types";
import {beforeAll, describe, expect, it} from "vitest";
import bindings from "../src/index.js";
import {createStfState, stfConfig} from "./stfFixture.js";

describe("serialized state transition", () => {
  let state: InstanceType<typeof bindings.BeaconStateView>;

  beforeAll(() => {
    bindings.config.set(stfConfig, new Uint8Array(32));
    bindings.pubkeys.ensureCapacity(16);
    state = bindings.BeaconStateView.createFromBytes(ssz.fulu.BeaconState.serialize(createStfState()));
  });

  it.each([false, true])("decodes a block with isBlinded=%s before checking its parent", (isBlinded) => {
    const type = isBlinded ? ssz.fulu.SignedBlindedBeaconBlock : ssz.fulu.SignedBeaconBlock;
    const block = type.defaultValue();
    block.message.slot = state.slot + 1;
    block.message.proposerIndex = state.getBeaconProposer(block.message.slot);
    const before = state.hashTreeRoot();

    expect(() =>
      state.stateTransition(type.serialize(block), isBlinded, {
        verifyProposer: false,
        verifySignatures: false,
        verifyStateRoot: false,
      })
    ).toThrow("BlockParentRootMismatch");
    expect(state.hashTreeRoot()).toEqual(before);
  });

  it("exports the fork sequence used by Lodestar", () => {
    expect(state.forkSeq).toBe(6);
    expect(state.forkName).toBe("fulu");
  });
});
