import nativeBindings from "./bindings.js";

const stateTransition = (preState, signedBlockBytes, options) =>
  preState.stateTransition(signedBlockBytes, options);

const bindings = {
  ...nativeBindings,
  stateTransition,
};

export default bindings;
