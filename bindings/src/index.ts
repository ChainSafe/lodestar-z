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
  epoch: number;
  genesisTime: number;
  genesisValidatorsRoot: Uint8Array;
  eth1Data: Eth1Data;
  latestBlockHeader: BeaconBlockHeader;
  previousJustifiedCheckpoint: Checkpoint;
  currentJustifiedCheckpoint: Checkpoint;
  finalizedCheckpoint: Checkpoint;
  getBlockRoot(slot: number): Uint8Array;
  getRandaoMix(epoch: number): Uint8Array;
  previousEpochParticipation: number[];
  currentEpochParticipation: number[];
  latestExecutionPayloadHeader: ExecutionPayloadHeader;
  historicalSummaries: HistoricalSummary[];
  pendingDeposits: Uint8Array;
  pendingDepositsCount: number;
  pendingPartialWithdrawals: Uint8Array;
  pendingPartialWithdrawalsCount: number;
  pendingConsolidations: PendingConsolidation[];
  pendingConsolidationsCount: number;
  proposerLookahead: Uint32Array;
  // executionPayloadAvailability: boolean[];

  // getShufflingAtEpoch(epoch: number): EpochShuffling;
  previousDecisionRoot: Uint8Array;
  currentDecisionRoot: Uint8Array;
  nextDecisionRoot: Uint8Array;
  // TODO wrong return type
  getShufflingDecisionRoot(epoch: number): Uint8Array;
  previousProposers: number[] | null;
  currentProposers: number[];
  nextProposers: number[];
  getBeaconProposer(slot: number): number;
  currentSyncCommittee: SyncCommittee;
  nextSyncCommittee: SyncCommittee;
  currentSyncCommitteeIndexed: SyncCommitteeCache;
  syncProposerReward: number;
  getIndexedSyncCommitteeAtEpoch(epoch: number): SyncCommitteeCache;

  effectiveBalanceIncrements: Uint16Array;
  getEffectiveBalanceIncrementsZeroInactive(): Uint16Array;
  getBalance(index: number): bigint;
  getValidator(index: number): Validator;
  // TODO wrong function
  getValidatorStatus(index: number): ValidatorStatus;
  validatorCount: number;
  activeValidatorCount: number;

  isExecutionStateType: boolean;
  isMergeTransitionComplete: boolean;
  // TODO remove
  isExecutionEnabled(fork: string, signedBlockBytes: Uint8Array): boolean;

  // getExpectedWithdrawals(): ExpectedWithdrawals;

  proposerRewards: ProposerRewards;
  // computeBlockRewards(block: BeaconBlock, proposerRewards: RewardsCache): BlockRewards;
  // computeAttestationRewards(validatorIds?: (number | string)[]): AttestationRewards;
  // computeSyncCommitteeRewards(block: BeaconBlock, validatorIds?: (number | string)[]): SyncCommitteeRewards;
  // getLatestWeakSubjectivityCheckpointEpoch(): number;

  getVoluntaryExitValidity(signedVoluntaryExitBytes: Uint8Array, verifySignature: boolean): VoluntaryExitValidity;
  isValidVoluntaryExit(signedVoluntaryExitBytes: Uint8Array, verifySignature: boolean): boolean;

  getFinalizedRootProof(): Uint8Array[];
  // getSyncCommitteesWitness(): SyncCommitteeWitness;
  getSingleProof(gindex: number): Uint8Array[];
  // createMultiProof(descriptor: Uint8Array): CompactMultiProof;

  computeUnrealizedCheckpoints(): {
    justifiedCheckpoint: Checkpoint;
    finalizedCheckpoint: Checkpoint;
  };

  clonedCount: number;
  clonedCountWithTransferCache: number;
  createdWithTransferCache: boolean;
  // isStateValidatorsNodesPopulated(): boolean;

  // loadOtherState(stateBytes: Uint8Array, seedValidatorsBytes?: Uint8Array): void;
  serialize(): Uint8Array;
  serializedSize(): number;
  serializeToBytes(output: Uint8Array, offset: number): number;
  serializeValidators(): Uint8Array;
  serializedValidatorsSize(): number;
  serializeValidatorsToBytes(output: Uint8Array, offset: number): number;
  hashTreeRoot(): Uint8Array;

  // stateTransition(signedBlockBytes: Uint8Array): BeaconStateView;
  processSlots(slot: number, options?: ProcessSlotsOpts): BeaconStateView;
}

declare class PublicKey {
  static fromBytes(bytes: Uint8Array): PublicKey;
  validate(): void;
  toBytes(): Uint8Array;
  toBytesCompress(): Uint8Array;
}

declare class SecretKey {
  static fromBytes(bytes: Uint8Array): SecretKey;
  static fromKeygen(ikm: Uint8Array, keyInfo?: Uint8Array): SecretKey;
  sign(msg: Uint8Array): Signature;
  toPublicKey(): PublicKey;
  toBytes(): Uint8Array;
}

declare class Signature {
  static fromBytes(bytes: Uint8Array): Signature;
  static aggregate(sigs: Signature[], sigsGroupcheck: boolean): Signature;
  toBytes(): Uint8Array;
  toBytesCompress(): Uint8Array;
  sigValidate(sigInfcheck: boolean): void;
}

interface SignatureSet {
  msg: Uint8Array;
  pk: PublicKey;
  sig: Signature;
}

interface Blst {
  PublicKey: typeof PublicKey;
  SecretKey: typeof SecretKey;
  Signature: typeof Signature;
  verify(msg: Uint8Array, pk: PublicKey, sig: Signature, pkValidate: boolean, sigGroupcheck: boolean): boolean;
  fastAggregateVerify(msg: Uint8Array, pks: PublicKey[], sig: Signature, pksValidate: boolean, sigGroupcheck: boolean): boolean;
  verifyMultipleAggregateSignatures(sets: SignatureSet[], sigsGroupcheck: boolean, pksValidate: boolean): boolean;
  aggregateSignatures(signatures: Signature[], sigsGroupcheck: boolean): Signature;
  aggregatePublicKeys(pks: PublicKey[], pksValidate: boolean): PublicKey;
  aggregateSerializedPublicKeys(serializedPublicKeys: Uint8Array[], pksValidate: boolean): PublicKey;
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
