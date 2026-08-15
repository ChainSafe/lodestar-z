import bindings from "./bindings.js";

const blsVerifier = bindings.blsVerifier;

/** @type {typeof import("./bls-verifier.d.ts").BLS_VERIFIER_SET_TYPE} */
export const BLS_VERIFIER_SET_TYPE = {
  indexed: blsVerifier.indexedSetType(),
  aggregate: blsVerifier.aggregateSetType(),
  single: blsVerifier.singleSetType(),
};

export const BLS_VERIFIER_MAX_BATCH_SIZE = blsVerifier.maxBatchSize();
export const BLS_VERIFIER_MAX_SAME_MESSAGE_BATCH_SIZE = blsVerifier.maxSameMessageBatchSize();
export const BLS_VERIFIER_EXECUTOR_CONCURRENCY = blsVerifier.executorConcurrency();

export const verifySignatureSets = blsVerifier.verifySignatureSets;
export const verifySignatureSetsAsync = blsVerifier.verifySignatureSetsAsync;
export const verifySignatureSetsSameMessage = blsVerifier.verifySignatureSetsSameMessage;
export const verifySignatureSetsSameMessageAsync = blsVerifier.verifySignatureSetsSameMessageAsync;
