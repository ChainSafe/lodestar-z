export {BeaconStateView} from "./index.js";
export type {
  ProcessSlotsOpts,
  SignedVoluntaryExit,
  TransitionOpts,
  VoluntaryExit,
  VoluntaryExitValidity,
} from "./index.js";

/**
 * Free the process-wide epoch cache.
 * Callers must wait for all `processSlots()`, `stateTransition()`, and phase0
 * `computeUnrealizedCheckpoints()` calls across all views and workers to finish,
 * then prevent new calls until teardown returns.
 */
export declare function deinitReusedEpochTransitionCache(): void;
