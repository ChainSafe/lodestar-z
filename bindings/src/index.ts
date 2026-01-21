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
    }
    index2pubkey: {
      get: (index: number) => Uint8Array | undefined;
    };
  };
  config: {
    set: (chainConfig: object, genesisValidatorsRoot: Uint8Array) => void;
  };
  BeaconStateView: typeof BeaconStateView;
  deinit: () => void;
};

export default require(join(import.meta.dirname, "../../zig-out/lib/bindings.node")) as Bindings;
