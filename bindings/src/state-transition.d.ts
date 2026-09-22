export {BeaconStateView} from "./index.js";
export type {
  ProcessSlotsOpts,
  SignedVoluntaryExit,
  TransitionOpts,
  VoluntaryExit,
  VoluntaryExitValidity,
} from "./index.js";

/** Callers must exclude STF operations across all workers until teardown returns. */
export declare function deinitReusedEpochTransitionCache(): void;
