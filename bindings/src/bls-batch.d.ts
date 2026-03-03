export interface IndexedSet {
  index: number;
  message: Uint8Array;
  signature: Uint8Array;
}

export interface AggregateSet {
  indices: number[];
  message: Uint8Array;
  signature: Uint8Array;
}

export interface SingleSet {
  publicKey: Uint8Array;
  message: Uint8Array;
  signature: Uint8Array;
}

export interface SameMessageSet {
  index: number;
  signature: Uint8Array;
}

export interface BlsBatch {
  readonly indexed: 0;
  readonly aggregate: 1;
  readonly single: 2;

  verify(kind: 0, sets: IndexedSet[]): boolean;
  verify(kind: 1, sets: AggregateSet[]): boolean;
  verify(kind: 2, sets: SingleSet[]): boolean;

  asyncVerify(kind: 0, sets: IndexedSet[]): Promise<boolean>;
  asyncVerify(kind: 1, sets: AggregateSet[]): Promise<boolean>;
  asyncVerify(kind: 2, sets: SingleSet[]): Promise<boolean>;

  asyncVerifySameMessage(sets: SameMessageSet[], message: Uint8Array): Promise<boolean>;

  init(maxJobs: number): void;
  canAcceptWork(): boolean;
}

export declare const blsBatch: BlsBatch;
