export declare const BLS_VERIFIER_SET_TYPE: {
  readonly indexed: 0;
  readonly aggregate: 1;
  readonly single: 2;
};

export declare const BLS_VERIFIER_MAX_BATCH_SIZE: 256;
export declare const BLS_VERIFIER_MAX_SAME_MESSAGE_BATCH_SIZE: 128;

export type BlsVerifierSetTypeValue = (typeof BLS_VERIFIER_SET_TYPE)[keyof typeof BLS_VERIFIER_SET_TYPE];

export type IndexedSignatureSet = {
  type: typeof BLS_VERIFIER_SET_TYPE.indexed;
  index: number;
  message: Uint8Array;
  signature: Uint8Array;
};

export type AggregateSignatureSet = {
  type: typeof BLS_VERIFIER_SET_TYPE.aggregate;
  indices: Uint32Array;
  message: Uint8Array;
  signature: Uint8Array;
};

export type SingleSignatureSet = {
  type: typeof BLS_VERIFIER_SET_TYPE.single;
  pubkey: Uint8Array;
  message: Uint8Array;
  signature: Uint8Array;
};

export type BlsSignatureSet = IndexedSignatureSet | AggregateSignatureSet | SingleSignatureSet;

export type SameMessageSignatureSet = {
  index: number;
  signature: Uint8Array;
};

/**
 * Verify signature sets using cached pubkeys for indexed and aggregate sets.
 * Returns false as soon as a cryptographically invalid set is encountered.
 * Evaluation short-circuits, so later sets are not inspected. Cache and
 * interface errors throw only when encountered before the result is known.
 */
export declare function verifySignatureSets(sets: BlsSignatureSet[]): boolean;

/**
 * Asynchronously verify signature sets using the native BLS executor.
 * Input bytes are copied before this function returns.
 * Set `critical` for latency-sensitive consensus work.
 */
export declare function verifySignatureSetsAsync(sets: BlsSignatureSet[], critical?: boolean): Promise<boolean>;

/**
 * Randomly aggregate and verify cached pubkeys and signatures over one message.
 * Returns one result per input; invalid interface state throws.
 */
export declare function verifySignatureSetsSameMessage(sets: SameMessageSignatureSet[], message: Uint8Array): boolean[];

/**
 * Asynchronously verify cached signatures over one message using the native
 * BLS executor. Input bytes are copied before this function returns.
 * Set `critical` for latency-sensitive consensus work.
 */
export declare function verifySignatureSetsSameMessageAsync(
  sets: SameMessageSignatureSet[],
  message: Uint8Array,
  critical?: boolean
): Promise<boolean[]>;
