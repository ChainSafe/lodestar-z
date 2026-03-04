import type {PublicKey, SecretKey, Signature, SignatureSet} from "../../src/blst.js";

export type BufferLike = string | Uint8Array | Buffer | PublicKey | Signature;

export interface TestSet {
  msg: Uint8Array;
  sk: SecretKey;
  pk: PublicKey;
  sig: Signature;
}

export interface SameMessageTestSets {
  msg: Uint8Array;
  sets: {
    sk: SecretKey;
    pk: PublicKey;
    sig: Signature;
  }[];
}

export type SerializedSet = Record<keyof TestSet, Uint8Array>;

export type SignatureSetArray = SignatureSet[];

/**
 * Enforce tests for all instance methods
 */
export type InstanceTestCases<InstanceType extends {[key: string]: any}> = {
  [P in keyof Omit<InstanceType, "type">]: {
    id?: string;
    instance?: InstanceType;
    args: Parameters<InstanceType[P]>;
    res?: ReturnType<InstanceType[P]>;
  }[];
};

export type CodeError = {
  code: string;
  message: string;
};
