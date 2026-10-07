export declare const ZKVM_KIND: {
  readonly openvm: 0;
  readonly sp1: 1;
  readonly zisk: 2;
  readonly lambdavm: 3;
};

export type ZkvmKindValue = (typeof ZKVM_KIND)[keyof typeof ZKVM_KIND];

/** False on targets without a prebuilt ere verifier library; registration then throws. */
export declare const EXECUTION_PROOF_VERIFIER_AVAILABLE: boolean;

/** EIP-8025 `MAX_PROOF_SIZE` in bytes. */
export declare const EXECUTION_PROOF_MAX_SIZE: 4194304;

/**
 * Binds `proofType` to an ere verifier for `zkvmKind` and `programVk`, once per process.
 * Throws when the proof type is already registered, the kind is unknown, or the key does not decode.
 */
export declare function registerExecutionProofVerifier(
  proofType: number,
  zkvmKind: ZkvmKindValue,
  programVk: Uint8Array
): void;

export declare function hasExecutionProofVerifier(proofType: number): boolean;

/**
 * Verifies `proofData` off the JS thread with the verifier registered for `proofType`.
 * Resolves with the public values the proof commits to, or null when the proof is malformed or
 * does not verify. Rejects for an unregistered proof type, an oversized proof, or an internal
 * verifier failure.
 */
export declare function verifyExecutionProof(proofType: number, proofData: Uint8Array): Promise<Uint8Array | null>;
