import bindings from "./bindings.js";

export const BeaconStateView = bindings.BeaconStateView;

export const stateTransition = (preState, signedBlockBytes, options) =>
  preState.stateTransition(signedBlockBytes, options);
