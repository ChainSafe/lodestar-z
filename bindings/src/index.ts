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

interface ProcessSlotsOpts {
  dontTransferCache?: boolean;
}

interface ProposerRewards {
  attestations: bigint;
  syncAggregate: bigint;
  slashing: bigint;
}

interface Validator {
  pubkey: Uint8Array;
  withdrawalCredentials: Uint8Array;
  effectiveBalance: bigint;
  slashed: boolean;
  activationEligibilityEpoch: bigint;
  activationEpoch: bigint;
  exitEpoch: bigint;
  withdrawableEpoch: bigint;
}

type ValidatorStatus =
  | "pending_initialized"
  | "pending_queued"
  | "active_ongoing"
  | "active_exiting"
  | "active_slashed"
  | "exited_unslashed"
  | "exited_slashed"
  | "withdrawal_possible"
  | "withdrawal_done";

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
  proposerRewards: ProposerRewards;
  getBalance(index: number): bigint;
  getValidator(index: number): Validator;
  getValidatorStatus(index: number): ValidatorStatus;
  validatorCount: number;
  isExecutionEnabled(fork: string, signedBlockBytes: Uint8Array): boolean;
  isExecutionStateType(): boolean;
  getEffectiveBalanceIncrementsZeroInactive(): Uint16Array;
  getFinalizedRootProof(): Uint8Array[];
  computeUnrealizedCheckpoints(): {
    justifiedCheckpoint: Checkpoint;
    finalizedCheckpoint: Checkpoint;
  };
  processSlots(slot: number, options?: ProcessSlotsOpts): BeaconStateView;
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
