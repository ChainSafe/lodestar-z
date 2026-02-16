export class PublicKey {
  /**
   * Deserialize a public key from a byte array.
   *
   * If `pkValidate` is `true`, the public key will be infinity and group checked.
   */
  static fromBytes(bytes: Uint8Array, pkValidate?: boolean): PublicKey;
  validate(): void;
  toBytes(): Uint8Array;
  toBytesCompress(): Uint8Array;
}

export class SecretKey {
  static fromBytes(bytes: Uint8Array): SecretKey;
  static fromKeygen(ikm: Uint8Array, keyInfo?: Uint8Array): SecretKey;
  sign(msg: Uint8Array): Signature;
  toPublicKey(): PublicKey;
  toBytes(): Uint8Array;
}

export class Signature {
  /**
   * Deserialize a signature from a byte array.
   *
   * If `sigValidate` is `true`, the public key will be infinity and group checked.
   *
   * If `sigInfcheck` is `false`, the infinity check will be skipped.
   */
  static fromBytes(bytes: Uint8Array, sigValidate?: boolean, sigInfcheck?: boolean): Signature;
  static aggregate(sigs: Signature[], sigsGroupcheck: boolean): Signature;
  toBytes(): Uint8Array;
  toBytesCompress(): Uint8Array;
  validate(sigInfcheck: boolean): void;
}

export interface SignatureSet {
  msg: Uint8Array;
  pk: PublicKey;
  sig: Signature;
}

export function verify(
  msg: Uint8Array,
  pk: PublicKey,
  sig: Signature,
  pkValidate?: boolean,
  sigGroupcheck?: boolean
): boolean;

export function fastAggregateVerify(msg: Uint8Array, pks: PublicKey[], sig: Signature, sigGroupcheck: boolean): boolean;

export function verifyMultipleAggregateSignatures(
  sets: SignatureSet[],
  sigsGroupcheck?: boolean,
  pksValidate?: boolean
): boolean;

export function aggregateSignatures(signatures: Signature[], sigsGroupcheck?: boolean): Signature;

export function aggregatePublicKeys(pks: PublicKey[], pksValidate?: boolean): PublicKey;

export function aggregateSerializedPublicKeys(serializedPublicKeys: Uint8Array[], pksValidate: boolean): PublicKey;
