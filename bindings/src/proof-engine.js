import bindings from "./bindings.js";

const proofEngine = bindings.proofEngine;

/** @type {typeof import("./proof-engine.d.ts").ZKVM_KIND} */
export const ZKVM_KIND = proofEngine.ZkvmKind;

export const EXECUTION_PROOF_VERIFIER_AVAILABLE = proofEngine.available;
export const EXECUTION_PROOF_MAX_SIZE = proofEngine.MAX_PROOF_SIZE;

export const registerExecutionProofVerifier = proofEngine.registerVerifier;
export const hasExecutionProofVerifier = proofEngine.hasVerifier;

/** @type {typeof import("./proof-engine.d.ts").verifyExecutionProof} */
export async function verifyExecutionProof(proofType, proofData) {
  return proofEngine.verifyExecutionProof(proofType, proofData);
}
