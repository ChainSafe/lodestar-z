// TODO make robust for production use ala bun-ffi-z

import { createRequire } from "node:module";
import { join } from "node:path";

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

interface Eth1Data {
  depositRoot: Uint8Array;
  depositCount: number;
  blockHash: Uint8Array;
}

interface ExecutionPayloadHeader {
  parentHash: Uint8Array;
  feeRecipient: Uint8Array;
  stateRoot: Uint8Array;
  receiptsRoot: Uint8Array;
  logsBloom: Uint8Array;
  prevRandao: Uint8Array;
  blockNumber: number;
  gasLimit: number;
  gasUsed: number;
  timestamp: number;
  extraData: Uint8Array;
  baseFeePerGas: number;
  blockHash: Uint8Array;
  transactionsRoot: Uint8Array;
  withdrawalsRoot?: Uint8Array; // capella+
  blobGasUsed?: number; // deneb+
  excessBlobGas?: number; // deneb+
}

interface Fork {
  previousVersion: Uint8Array;
  currentVersion: Uint8Array;
  epoch: number;
}

interface SyncCommittee {
  pubkeys: Uint8Array;
  aggregatePubkey: Uint8Array;
}

interface ProcessSlotsOpts {
  dontTransferCache?: boolean;
}

interface ProposerRewards {
  attestations: bigint;
  syncAggregate: bigint;
  slashing: bigint;
}

interface SyncCommitteeCache {
  validatorIndices: number[];
}

interface HistoricalSummary {
  blockSummaryRoot: Uint8Array;
  stateSummaryRoot: Uint8Array;
}

interface PendingConsolidation {
  sourceIndex: number;
  targetIndex: number;
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

type VoluntaryExitValidity =
  | "valid"
  | "inactive"
  | "already_exited"
  | "early_epoch"
  | "short_time_active"
  | "pending_withdrawals"
  | "invalid_signature";

declare class BeaconStateView {
  static createFromBytes(fork: string, bytes: Uint8Array): BeaconStateView;
  slot: number;
  fork: Fork;
  root: Uint8Array;
  epoch: number;
  genesisTime: number;
  genesisValidatorsRoot: Uint8Array;
  eth1Data: Eth1Data;
  latestBlockHeader: BeaconBlockHeader;
  latestExecutionPayloadHeader: ExecutionPayloadHeader;
  previousJustifiedCheckpoint: Checkpoint;
  currentJustifiedCheckpoint: Checkpoint;
  finalizedCheckpoint: Checkpoint;
  previousDecisionRoot: Uint8Array;
  currentDecisionRoot: Uint8Array;
  nextDecisionRoot: Uint8Array;
  getShufflingDecisionRoot(epoch: number): Uint8Array;
  proposers: number[];
  proposersNextEpoch: number[] | null;
  proposersPrevEpoch: number[] | null;
  currentSyncCommittee: SyncCommittee;
  nextSyncCommittee: SyncCommittee;
  currentSyncCommitteeIndexed: SyncCommitteeCache;
  effectiveBalanceIncrements: Uint16Array;
  syncProposerReward: number;
  previousEpochParticipation: number[];
  currentEpochParticipation: number[];
  proposerRewards: ProposerRewards;
  clonedCount: number;
  clonedCountWithTransferCache: number;
  createdWithTransferCache: boolean;
  pendingDepositsLength: number;
  pendingPartialWithdrawalsLength: number;
  pendingConsolidationsLength: number;
  serializeValidators(): Uint8Array;
  serializedValidatorsSize(): number;
  serializeValidatorsToBytes(output: Uint8Array, offset: number): number;
  getBalance(index: number): bigint;
  getValidator(index: number): Validator;
  getValidatorStatus(index: number): ValidatorStatus;
  validatorCount: number;
  activeValidatorCount: number;
  getBeaconProposer(slot: number): number;
  getBeaconProposers(): number[];
  getBeaconProposersPrevEpoch(): number[] | null;
  getBeaconProposersNextEpoch(): number[] | null;
  getIndexedSyncCommitteeAtEpoch(epoch: number): SyncCommitteeCache;
  getBlockRootAtSlot(slot: number): Uint8Array;
  getBlockRoot(epoch: number): Uint8Array;
  isMergeTransitionComplete(): boolean;
  getRandaoMix(epoch: number): Uint8Array;
  getHistoricalSummaries(): HistoricalSummary[];
  getPendingDeposits(): Uint8Array;
  getPendingPartialWithdrawals(): Uint8Array;
  getPendingConsolidations(): PendingConsolidation[];
  getProposerLookahead(): Uint32Array;
  getSingleProof(gindex: number): Uint8Array[];
  isValidVoluntaryExit(signedVoluntaryExitBytes: Uint8Array, verifySignature: boolean): boolean;
  getVoluntaryExitValidity(signedVoluntaryExitBytes: Uint8Array, verifySignature: boolean): VoluntaryExitValidity;
  isExecutionEnabled(fork: string, signedBlockBytes: Uint8Array): boolean;
  isExecutionStateType(): boolean;
  getEffectiveBalanceIncrementsZeroInactive(): Uint16Array;
  getFinalizedRootProof(): Uint8Array[];
  computeUnrealizedCheckpoints(): {
    justifiedCheckpoint: Checkpoint;
    finalizedCheckpoint: Checkpoint;
  };
  serialize(): Uint8Array;
  serializedSize(): number;
  serializeToBytes(output: Uint8Array, offset: number): number;
  hashTreeRoot(): Uint8Array;
  processSlots(slot: number, options?: ProcessSlotsOpts): BeaconStateView;
}

declare class PublicKey {
  static fromBytes(bytes: Uint8Array): PublicKey;
  toBytesCompress(): Uint8Array;
  toBytes(): Uint8Array;
}

declare class Signature {
  static fromBytes(bytes: Uint8Array): Signature;
  toBytesCompress(): Uint8Array;
  toBytes(): Uint8Array;
}

interface Blst {
  PublicKey: typeof PublicKey;
  Signature: typeof Signature;
  verify(msg: Uint8Array, pk: PublicKey, sig: Signature): boolean;
  fastAggregateVerify(msg: Uint8Array, pks: PublicKey[], sig: Signature): boolean;
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
  blst: Blst;
  deinit: () => void;
};

export default require(join(import.meta.dirname, "../../zig-out/lib/bindings.node")) as Bindings;
