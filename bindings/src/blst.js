import bindings from "./bindings.js";

const blst = bindings.blst;

export const PublicKey = blst.PublicKey;
export const SecretKey = blst.SecretKey;
export const Signature = blst.Signature;

export const verify = blst.verify;
export const aggregateVerify = blst.aggregateVerify;
export const fastAggregateVerify = blst.fastAggregateVerify;
export const verifyMultipleAggregateSignatures = blst.verifyMultipleAggregateSignatures;
export const aggregateSignatures = blst.aggregateSignatures;
export const aggregatePublicKeys = blst.aggregatePublicKeys;
export const aggregateSerializedPublicKeys = blst.aggregateSerializedPublicKeys;
export const aggregateWithRandomness = blst.aggregateWithRandomness;
export const asyncAggregateWithRandomness = blst.asyncAggregateWithRandomness;

/**
 * Verify signature sets that reference validators by index, resolving keys
 * from the process-wide pubkey cache (populate via pubkeyCache.syncPubkeys
 * before verification traffic starts). Blocks the calling thread while the
 * native pool verifies; intended for BLS worker threads.
 */
export const verifyIndexedSignatureSets = bindings.verify.verifyIndexedSignatureSets;

/**
 * Same-message batch: randomness-aggregate (pk_i, sig_i) pairs by validator
 * index and verify the aggregate against one message, fused in native code.
 * One boolean for the batch; retry per set for ordered attribution.
 */
export const verifySameMessageSetsByIndex = bindings.verify.verifySameMessageSetsByIndex;
