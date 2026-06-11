import bindings from "./bindings.js";

const native = bindings.stateTransition;

export const BeaconStateView = bindings.BeaconStateView;
export const stateTransition = native.stateTransition;
