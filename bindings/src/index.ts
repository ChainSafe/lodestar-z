// TODO make robust for production use ala bun-ffi-z

import {createRequire} from "node:module";
import {join} from "node:path";

const require = createRequire(import.meta.url);

interface BeaconBlockHeader {
  slot: number;
  proposerIndex: number;
  parentRoot: Uint8Array;
  stateRoot: Uint8Array;
  bodyRoot: Uint8Array;
}

interface Checkpoint {
  epoch: number;
  root: Uint8Array;
}

interface SyncCommittee {
  pubkeys: Uint8Array;
  aggregatePubkey: Uint8Array;
}

// reference: https://github.com/ChainSafe/lodestar/blob/b6d377a93c39aa17d19408e119208a0733dcba3c/packages/state-transition/src/cache/syncCommitteeCache.ts#L8-L20
interface SyncCommitteeCache {
  validatorIndices: Uint32Array;
  validatorIndexMap: Map<number, number[]>;
}

declare class BeaconStateView {
  static createFromBytes(fork: string, bytes: Uint8Array): BeaconStateView;
  slot: number;
  root: Uint8Array;
  epoch: number;
  genesisTime: number;
  genesisValidatorsRoot: Uint8Array;
  latestBlockHeader: BeaconBlockHeader;
  previousJustifiedCheckpoint: Checkpoint;
  currentJustifiedCheckpoint: Checkpoint;
  finalizedCheckpoint: Checkpoint;
  proposers: number[];
  proposersNextEpoch: number[] | null;
  proposersPrevEpoch: number[] | null;
  currentSyncCommittee: SyncCommittee;
  nextSyncCommittee: SyncCommittee;
  currentSyncCommitteeIndexed: SyncCommitteeCache;
  getBalance(index: number): bigint;
  isExecutionEnabled(fork: string, signedBlockBytes: Uint8Array): boolean;
  isExecutionStateType(): boolean;
  getEffectiveBalanceIncrementsZeroInactive(): Uint16Array;
  getFinalizedRootProof(): Uint8Array[];
  computeUnrealizedCheckpoints(): {
    justifiedCheckpoint: Checkpoint;
    finalizedCheckpoint: Checkpoint;
  };
  hashTreeRoot(): Uint8Array;
}

type Bindings = {
  pool: {
    ensureCapacity: (capacity: number) => void;
  };
  pubkeys: {
    load(filepath: string): void;
    save(filepath: string): void;
    ensureCapacity: (capacity: number) => void;
    pubkey2index: {
      get: (pubkey: Uint8Array) => number | undefined;
    };
    index2pubkey: {
      get: (index: number) => Uint8Array | undefined;
    };
  };
  config: {
    set: (chainConfig: object, genesisValidatorsRoot: Uint8Array) => void;
  };
  shuffle: {
    innerShuffleList: (out: Uint32Array, seed: Uint8Array, rounds: number, forwards: boolean) => void;
  };
  computeProposerIndex: (
    fork: "phase0" | "altair" | "bellatrix" | "capella" | "deneb" | "electra" | "fulu",
    effectiveBalanceIncrements: Uint16Array,
    indices: Uint32Array,
    seed: Uint8Array
  ) => number;
  BeaconStateView: typeof BeaconStateView;
  deinit: () => void;
};

export default require(join(import.meta.dirname, "../../zig-out/lib/bindings.node")) as Bindings;
