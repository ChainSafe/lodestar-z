import nativeBindings from "./bindings.js";

const stateTransition = (preState, signedBlockBytes, options) =>
  preState.stateTransition(signedBlockBytes, options);

stateTransition.deinitReusedEpochTransitionCache =
  nativeBindings.stateTransition.deinitReusedEpochTransitionCache;

const bindings = {
  ...nativeBindings,
  stateTransition,
};

export default bindings;
