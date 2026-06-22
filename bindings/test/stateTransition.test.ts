import {describe, expect, it} from "vitest";
import type {BeaconStateView, TransitionOpts} from "../src/index.js";
import bindings from "../src/index.js";
import {deinitStateTransition, stateTransition} from "../src/state-transition.js";

function stateViewWithTransition(
  stateTransition: (signedBlockBytes: Uint8Array, options?: TransitionOpts) => unknown
): BeaconStateView {
  return {stateTransition} as unknown as BeaconStateView;
}

describe("stateTransition export", () => {
  it("delegates the root export to BeaconStateView.stateTransition", () => {
    const signedBlockBytes = new Uint8Array([1, 2, 3]);
    const options = {verifyStateRoot: false};
    const postState = {};
    const preState = stateViewWithTransition((receivedBytes, receivedOptions) => {
      expect(receivedBytes).toBe(signedBlockBytes);
      expect(receivedOptions).toBe(options);
      return postState;
    });

    expect(bindings.stateTransition(preState, signedBlockBytes, options)).toBe(postState);
  });

  it("delegates the state-transition subpath export to BeaconStateView.stateTransition", () => {
    const signedBlockBytes = new Uint8Array([4, 5, 6]);
    const options = {verifyProposer: false};
    const postState = {};
    const preState = stateViewWithTransition((receivedBytes, receivedOptions) => {
      expect(receivedBytes).toBe(signedBlockBytes);
      expect(receivedOptions).toBe(options);
      return postState;
    });

    expect(stateTransition(preState, signedBlockBytes, options)).toBe(postState);
  });

  it("exposes the state transition cache reset", () => {
    expect(bindings.stateTransition.deinitStateTransition).toBeTypeOf("function");
    expect(deinitStateTransition).toBeTypeOf("function");
  });
});
