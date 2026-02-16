export class PublicKey {
  static fromBytes(bytes: Uint8Array): PublicKey;
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
  static fromBytes(bytes: Uint8Array): Signature;
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

export function verify(msg: Uint8Array, pk: PublicKey, sig: Signature, pkValidate?: boolean, sigGroupcheck?: boolean): boolean;

export function fastAggregateVerify(msg: Uint8Array, pks: PublicKey[], sig: Signature, sigGroupcheck: boolean): boolean;

export function verifyMultipleAggregateSignatures(sets: SignatureSet[], sigsGroupcheck?: boolean, pksValidate?: boolean): boolean;

export function aggregateSignatures(signatures: Signature[], sigsGroupcheck?: boolean): Signature;

export function aggregatePublicKeys(pks: PublicKey[], pksValidate?: boolean): PublicKey;

export function aggregateSerializedPublicKeys(serializedPublicKeys: Uint8Array[], pksValidate: boolean): PublicKey;
