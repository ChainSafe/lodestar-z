export {BeaconStateView, StateTransition} from "./index.js";
export type {
  ProcessSlotsOpts,
  SignedVoluntaryExit,
  TransitionOpts,
  VoluntaryExit,
  VoluntaryExitValidity,
} from "./index.js";

/** Callers must exclude STF operations in this thread until teardown returns. */
export declare function deinitReusedEpochTransitionCache(): void;
