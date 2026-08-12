import bindings from "./bindings.js";

/** @type {typeof import("./bls-verifier.d.ts").BLS_VERIFIER_SET_TYPE} */
export const BLS_VERIFIER_SET_TYPE = {
  indexed: bindings.blsVerifier.indexedSetType(),
  aggregate: bindings.blsVerifier.aggregateSetType(),
  single: bindings.blsVerifier.singleSetType(),
};

export const BLS_VERIFIER_MAX_BATCH_SIZE = bindings.blsVerifier.maxBatchSize();
export const BLS_VERIFIER_MAX_SAME_MESSAGE_BATCH_SIZE = bindings.blsVerifier.maxSameMessageBatchSize();

export const verifySignatureSets = bindings.blsVerifier.verifySignatureSets;
export const verifySignatureSetsSameMessage = bindings.blsVerifier.verifySignatureSetsSameMessage;
