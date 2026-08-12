export class PublicKey {
  /** Size of a compressed public key in bytes (48). */
  static readonly COMPRESS_SIZE: number;
  /** Size of an uncompressed public key in bytes (96). */
  static readonly SERIALIZE_SIZE: number;
  /**
   * Deserialize a public key from a byte array.
   *
   * If `pkValidate` is `true`, the public key will be infinity and group checked.
   */
  static fromBytes(bytes: Uint8Array, pkValidate?: boolean): PublicKey;
  /**
   * Deserialize a public key from a hex string.
   *
   * If `pk_validate` is `true`, the public key will be infinity and group checked.
   */
  static fromHex(hex: string, pkValidate?: boolean | undefined | null): PublicKey;
  validate(): void;
  /**
   * Serialize a public key to a byte array.
   *
   * If `compress` is `false`, the public key will be serialized in uncompressed form.
   */
  toBytes(compress?: boolean): Uint8Array;
  /**
   * Serialize a public key to a 0x-prefixed hex string.
   *
   * If `compress` is `false`, the public key will be serialized in uncompressed form.
   */
  toHex(compress?: boolean): string;
}

export class SecretKey {
  static fromBytes(bytes: Uint8Array): SecretKey;
  static fromHex(hex: string): SecretKey;
  static fromKeygen(ikm: Uint8Array, keyInfo?: Uint8Array): SecretKey;
  /** Sign an exact 32-byte Ethereum consensus signing root. */
  sign(msg: Uint8Array): Signature;
  toPublicKey(): PublicKey;
  toBytes(): Uint8Array;
  /**
   * Serialize a secret key to a 0x-prefixed hex string.
   */
  toHex(): string;
}

export class Signature {
  /** Size of a compressed signature in bytes (96). */
  static readonly COMPRESS_SIZE: number;
  /** Size of an uncompressed signature in bytes (192). */
  static readonly SERIALIZE_SIZE: number;
  /**
   * Deserialize a signature from a byte array.
   *
   * If `sigValidate` is `true`, the public key will be infinity and group checked.
   *
   * If `sigInfcheck` is `false`, the infinity check will be skipped.
   */
  static fromBytes(bytes: Uint8Array, sigValidate?: boolean, sigInfcheck?: boolean): Signature;
  /**
   * Deserialize a signature from a hex string.
   *
   * If `sig_validate` is `true`, the public key will be infinity and group checked.
   *
   * If `sig_infcheck` is `false`, the infinity check will be skipped.
   */
  static fromHex(
    hex: string,
    sigValidate?: boolean | undefined | null,
    sigInfcheck?: boolean | undefined | null
  ): Signature;
  static aggregate(sigs: Signature[], sigsGroupcheck: boolean): Signature;
  /**
   * Serialize a signature to a byte array.
   *
   * If `compress` is `false`, the signature will be serialized in uncompressed form.
   */
  toBytes(compress?: boolean): Uint8Array;
  /**
   * Serialize a signature to a 0x-prefixed hex string.
   *
   * If `compress` is `false`, the signature will be serialized in uncompressed form.
   */
  toHex(compress?: boolean): string;
  validate(sigInfcheck: boolean): void;
}

export interface SignatureSet {
  /** Exact 32-byte Ethereum consensus signing root. */
  msg: Uint8Array;
  pk: PublicKey;
  sig: Signature;
}

export interface PkAndSerializedSig {
  pk: PublicKey;
  sig: Uint8Array;
}

export interface PkAndSig {
  pk: PublicKey;
  sig: Signature;
}

/**
 * Verify a signature against an exact 32-byte Ethereum consensus signing root and public key.
 *
 * If `pkValidate` is `true`, the public key will be infinity and group checked.
 *
 * If `sigGroupcheck` is `true`, the signature will be group checked.
 */
export function verify(
  msg: Uint8Array,
  pk: PublicKey,
  sig: Signature,
  pkValidate?: boolean,
  sigGroupcheck?: boolean
): boolean;

/**
 * Verify an aggregated signature against exact 32-byte Ethereum consensus signing roots and multiple public keys.
 *
 * If `pksValidate` is `true`, the public keys will be infinity and group checked.
 *
 * If `sigGroupcheck` is `true`, the signatures will be group checked.
 */
export function aggregateVerify(
  msgs: Uint8Array[],
  pks: PublicKey[],
  sig: Signature,
  pksValidate?: boolean,
  sigGroupcheck?: boolean
): boolean;

/**
 * Verify an aggregated signature against a single exact 32-byte Ethereum consensus signing root and multiple public keys.
 *
 * Proof-of-possession is required for public keys.
 *
 * If `sigsGroupcheck` is `true`, the signatures will be group checked.
 */
export function fastAggregateVerify(
  msg: Uint8Array,
  pks: PublicKey[],
  sig: Signature,
  sigsGroupcheck?: boolean
): boolean;

/**
 * Verify multiple aggregated signatures against exact 32-byte Ethereum consensus signing roots and multiple public keys.
 *
 * If `pksValidate` is `true`, the public keys will be infinity and group checked.
 *
 * If `sigsGroupcheck` is `true`, the signatures will be group checked.
 *
 * See https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407
 */
export function verifyMultipleAggregateSignatures(
  sets: SignatureSet[],
  pksValidate?: boolean,
  sigsGroupcheck?: boolean
): boolean;

/**
 * Aggregate multiple public keys and multiple serialized signatures into a single blinded public key and blinded signature.
 *
 * Signatures are deserialized and validated with infinity and group checks before aggregation.
 */
export declare function aggregateWithRandomness(sets: PkAndSerializedSig[]): PkAndSig;

/**
 * Same as `aggregateWithRandomness`, but the multi-scalar multiplications run on the
 * native thread pool and the call returns a Promise instead of blocking the JS thread.
 */
export declare function asyncAggregateWithRandomness(sets: PkAndSerializedSig[]): Promise<PkAndSig>;

/**
 * Aggregate multiple signatures into a single signature.
 *
 * If `sigsGroupcheck` is `true`, the signatures will be group checked.
 */
export function aggregateSignatures(signatures: Signature[], sigsGroupcheck?: boolean): Signature;

/**
 * Aggregate multiple public keys into a single public key.
 *
 * If `pksValidate` is `true`, the public keys will be infinity and group checked.
 */
export function aggregatePublicKeys(pks: PublicKey[], pksValidate?: boolean): PublicKey;

/**
 * Aggregate multiple serialized public keys into a single public key.
 *
 * If `pksValidate` is `true`, the public keys will be infinity and group checked.
 */
export function aggregateSerializedPublicKeys(serializedPublicKeys: Uint8Array[], pksValidate?: boolean): PublicKey;

/** Discriminated signature-set descriptor for verification by validator index. */
export type NativeVerifySet =
  | {type: "single"; publicKey: Uint8Array | PublicKey; message: Uint8Array; signature: Uint8Array}
  | {type: "indexed"; index: number; message: Uint8Array; signature: Uint8Array}
  | {type: "aggregate"; indices: Uint32Array; message: Uint8Array; signature: Uint8Array};

/**
 * Batch-verify signature sets that reference validators by index, resolving
 * keys from the process-wide pubkey cache (populate via
 * pubkeyCache.syncPubkeys before verification traffic starts; reset() is
 * test-only). One boolean for the whole batch. Semantic failures (unknown
 * index, malformed signature or key, failed verification, empty input)
 * return false; caller bugs (wrong message length, unknown type) and
 * infrastructure failures throw. Blocks the calling thread while the native
 * pool verifies — intended for BLS worker threads.
 */
export declare function verifyIndexedSignatureSets(sets: NativeVerifySet[]): boolean;

/**
 * Same-message batch, fused: randomness-aggregate (pk_i, sig_i) pairs by
 * validator index and verify the aggregate against one 32-byte message in a
 * single native call. Same error contract as verifyIndexedSignatureSets.
 * On false, retry per set (batches of one) for ordered attribution.
 */
export declare function verifySameMessageSetsByIndex(
  message: Uint8Array,
  sets: {index: number; signature: Uint8Array}[]
): boolean;
