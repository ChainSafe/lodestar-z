import type {BeaconStateView, TransitionOpts} from "./index.js";

export {BeaconStateView, ProcessSlotsOpts, TransitionOpts} from "./index.js";

export declare function stateTransition(
  preState: BeaconStateView,
  signedBlockBytes: Uint8Array,
  options?: TransitionOpts
): BeaconStateView;
