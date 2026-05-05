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

enum ForkName {
  phase0 = "phase0",
  altair = "altair",
  bellatrix = "bellatrix",
  capella = "capella",
  deneb = "deneb",
  electra = "electra",
  fulu = "fulu",
  gloas = "gloas",
}

interface SyncCommittee {
  pubkeys: Uint8Array;
  aggregatePubkey: Uint8Array;
}

interface ProcessSlotsOpts {
  /** Default: false (cache is transferred). Set to true to opt out of cache transfer. */
  dontTransferCache?: boolean;
}

interface CompactMultiProof {
  // biome-ignore lint/suspicious/noExplicitAny: native returns string literal "compactMulti", IBeaconStateView uses @chainsafe/persistent-merkle-tree's ProofType enum nominally
  type: any;
  leaves: Uint8Array[];
  descriptor: Uint8Array;
}

/**
 * Options to control how state transition is run.
 *
 * Note: Fields used by TS `StateTransitionOpts` but ignored by the Zig binding (e.g.
 * `executionPayloadStatus`) are silently dropped - they are declared here to pass type checks.
 */
interface TransitionOpts {
  /** Verify the post-state root matches the block's state root. Default: true. */
  verifyStateRoot?: boolean;
  /** Verify the proposer signature on the signed block. Default: true. */
  verifyProposer?: boolean;
  /** Verify BLS signatures during block processing. Default: true. */
  verifySignatures?: boolean;
  /** Default: false (cache is transferred). Set to true to opt out of cache transfer. */
  dontTransferCache?: boolean;
}

interface ProposerRewards {
  attestations: number;
  syncAggregate: number;
  slashing: number;
}

interface SyncCommitteeCache {
  validatorIndices: number[];
}

interface EpochShuffling {
  epoch: number;
  activeIndices: Uint32Array;
  shuffling: Uint32Array;
  /** committees[slotInEpoch][committeeIndex] -> validator indices */
  committees: Uint32Array[][];
  committeesPerSlot: number;
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
  effectiveBalance: number;
  slashed: boolean;
  activationEligibilityEpoch: number;
  activationEpoch: number;
  exitEpoch: number;
  withdrawableEpoch: number;
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
  static createFromBytes(bytes: Uint8Array): BeaconStateView;

  slot: number;
  fork: Fork;
  forkName: ForkName;
  epoch: number;
  genesisTime: number;
  genesisValidatorsRoot: Uint8Array;
  eth1Data: Eth1Data;
  latestBlockHeader: BeaconBlockHeader;
  previousJustifiedCheckpoint: Checkpoint;
  currentJustifiedCheckpoint: Checkpoint;
  finalizedCheckpoint: Checkpoint;
  getBlockRoot(epoch: number): Uint8Array;
  getBlockRootAtSlot(slot: number): Uint8Array;
  getBlockRootAtEpoch(epoch: number): Uint8Array;
  getStateRootAtSlot(slot: number): Uint8Array;
  getRandaoMix(epoch: number): Uint8Array;
  previousEpochParticipation: Uint8Array;
  currentEpochParticipation: Uint8Array;
  getPreviousEpochParticipation(index: number): number;
  getCurrentEpochParticipation(index: number): number;
  latestExecutionPayloadHeader: ExecutionPayloadHeader;
  payloadBlockNumber: number;
  historicalSummaries: HistoricalSummary[];
  pendingDeposits: Uint8Array;
  pendingDepositsCount: number;
  pendingPartialWithdrawals: Uint8Array;
  pendingPartialWithdrawalsCount: number;
  pendingConsolidations: PendingConsolidation[];
  pendingConsolidationsCount: number;
  proposerLookahead: Uint32Array;
  // executionPayloadAvailability: boolean[];

  // Gloas-only — throw "not available before Gloas" when called pre-Gloas.
  latestBlockHash: Uint8Array;
  // TODO(bing): type this once we support gloas
  // biome-ignore lint/suspicious/noExplicitAny: gloas stub
  executionPayloadAvailability: any;
  // TODO(bing): type this once we support gloas
  // biome-ignore lint/suspicious/noExplicitAny: gloas stub
  latestExecutionPayloadBid: any;
  // TODO(bing): type this once we support gloas
  // biome-ignore lint/suspicious/noExplicitAny: gloas stub
  payloadExpectedWithdrawals: any[];
  // TODO(bing): type this once we support gloas
  // biome-ignore lint/suspicious/noExplicitAny: gloas stub
  getBuilder(index: number): any;
  canBuilderCoverBid(builderIndex: number, bidAmount: number): boolean;
  getEpochPTCs(epoch: number): Uint32Array[];
  getIndexInPayloadTimelinessCommittee(validatorIndex: number, slot: number): number;
  // TODO(bing): type this once we support gloas
  // biome-ignore lint/suspicious/noExplicitAny: gloas stub
  getExpectedWithdrawalsForFullParent(executionRequests: any): any[];

  getShufflingAtEpoch(epoch: number): EpochShuffling;
  getPreviousShuffling(): EpochShuffling;
  getCurrentShuffling(): EpochShuffling;
  getNextShuffling(): EpochShuffling;
  previousDecisionRoot: string;
  currentDecisionRoot: string;
  nextDecisionRoot: string;
  getShufflingDecisionRoot(epoch: number): string;
  previousProposers: number[] | null;
  currentProposers: number[];
  nextProposers: number[];
  getBeaconProposer(slot: number): number;
  currentSyncCommittee: SyncCommittee;
  nextSyncCommittee: SyncCommittee;
  currentSyncCommitteeIndexed: SyncCommitteeCache;
  syncProposerReward: number;
  getIndexedSyncCommitteeAtEpoch(epoch: number): SyncCommitteeCache;
  getIndexedSyncCommittee(slot: number): SyncCommitteeCache;

  effectiveBalanceIncrements: Uint16Array;
  getEffectiveBalanceIncrementsZeroInactive(): Uint16Array;
  getBalance(index: number): number;
  getValidator(index: number): Validator;
  getAllValidators(): Validator[];
  getAllBalances(): number[];
  getValidatorsByStatus(statuses: Set<string>, currentEpoch: number): Validator[];
  // TODO wrong function
  getValidatorStatus(index: number): ValidatorStatus;
  validatorCount: number;
  activeValidatorCount: number;

  isExecutionStateType: boolean;
  isMergeTransitionComplete: boolean;
  /** True iff state is pre-merge AND the given block carries a non-default execution payload. Bellatrix-only. */
  isMergeTransitionBlock(signedBlockBytes: Uint8Array): boolean;
  /**
   * Check whether execution is enabled for the given block at this state.
   *
   * Check if 1) merge transition is complete, or 2) is a merge transition block
   * Note that this does not call native `isExecutionEnabled` directly because we can save on deserializing
   * `signed_block` if 1) holds. We only deserialize in the event that it's a pre-merge bellatrix block
   */
  isExecutionEnabled(signedBlockBytes: Uint8Array): boolean;

  proposerRewards: ProposerRewards;
  // biome-ignore lint/suspicious/noExplicitAny: stub
  // TODO(bing): This is stubbed and untyped until we implement the beacon node rewards endpoints
  computeBlockRewards(block: any, proposerRewards?: any): Promise<any>;
  // biome-ignore lint/suspicious/noExplicitAny: stub
  // TODO(bing): This is stubbed and untyped until we implement the beacon node rewards endpoints
  computeAttestationsRewards(validatorIds?: (number | string)[]): Promise<any>;
  // TODO(bing): This is stubbed and untyped until we implement the beacon node rewards endpoints
  // biome-ignore lint/suspicious/noExplicitAny: stub
  computeSyncCommitteeRewards(block: any, validatorIds: (number | string)[]): Promise<any>;
  getLatestWeakSubjectivityCheckpointEpoch(): number;

  getVoluntaryExitValidity(signedVoluntaryExitBytes: Uint8Array, verifySignature: boolean): VoluntaryExitValidity;
  isValidVoluntaryExit(signedVoluntaryExitBytes: Uint8Array, verifySignature: boolean): boolean;

  getFinalizedRootProof(): Uint8Array[];
  // biome-ignore lint/suspicious/noExplicitAny: stub
  getSyncCommitteesWitness(): any;
  // biome-ignore lint/suspicious/noExplicitAny: stub
  getExpectedWithdrawals(): any;
  getSingleProof(gindex: bigint): Uint8Array[];
  // createMultiProof(descriptor: Uint8Array): CompactMultiProof;

  computeUnrealizedCheckpoints(): {
    justifiedCheckpoint: Checkpoint;
    finalizedCheckpoint: Checkpoint;
  };
  computeAnchorCheckpoint(): {
    checkpoint: Checkpoint;
    blockHeader: BeaconBlockHeader;
  };

  clonedCount: number;
  clonedCountWithTransferCache: number;
  createdWithTransferCache: boolean;
  isStateValidatorsNodesPopulated(): boolean;

  // biome-ignore lint/suspicious/noExplicitAny: stub
  loadOtherState(
    stateBytes: Uint8Array,
    seedValidatorsBytes?: Uint8Array,
    opts?: {preloadValidatorsAndBalances?: boolean}
  ): any;
  // biome-ignore lint/suspicious/noExplicitAny: stub
  toValue(): any;
  serialize(): Uint8Array;
  serializedSize(): number;
  /** Takes a `@chainsafe/ssz` ByteViews `{uint8Array, dataView}`; native uses `uint8Array` only. */
  serializeToBytes(output: {uint8Array: Uint8Array; dataView: DataView}, offset: number): number;
  serializeValidators(): Uint8Array;
  serializedValidatorsSize(): number;
  /** Same shape as `serializeToBytes`. */
  serializeValidatorsToBytes(output: {uint8Array: Uint8Array; dataView: DataView}, offset: number): number;
  hashTreeRoot(): Uint8Array;
  createMultiProof(descriptor: Uint8Array): CompactMultiProof;

  // biome-ignore lint/suspicious/noExplicitAny: signed block bytes are passed as Uint8Array at runtime; signature is loosened so it satisfies `IBeaconStateView.stateTransition(block, opts, modules)` structurally.
  stateTransition(signedBlock: any, options?: any, modules?: any): BeaconStateView;
  processSlots(slot: number, options?: ProcessSlotsOpts): BeaconStateView;
}

declare const bindings: {
  pool: {
    ensureCapacity: (capacity: number) => void;
  };
  config: {
    set: (chainConfig: object, genesisValidatorsRoot: Uint8Array) => void;
  };
  shuffle: {
    innerShuffleList: (out: Uint32Array, seed: Uint8Array, rounds: number, forwards: boolean) => void;
  };
  stateTransition: {
    stateTransition: (
      preState: BeaconStateView,
      signedBlockBytes: Uint8Array,
      options?: TransitionOpts
    ) => BeaconStateView;
  };
  metrics: {
    init: () => void;
    scrapeMetrics: () => string;
  };
  BeaconStateView: typeof BeaconStateView;
};

export default bindings;
