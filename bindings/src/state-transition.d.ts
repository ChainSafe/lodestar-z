export {BeaconStateView} from "./index.js";
export type {
  ProcessSlotsOpts,
  SignedVoluntaryExit,
  TransitionOpts,
  VoluntaryExit,
  VoluntaryExitValidity,
} from "./index.js";

import type {BeaconStateView, TransitionOpts} from "./index.js";

export declare function stateTransition(
  preState: BeaconStateView,
  signedBlockBytes: Uint8Array,
  options?: TransitionOpts
): BeaconStateView;

export declare function deinitStateTransition(): void;
