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
  transferCache?: boolean;
}

interface CompactMultiProof {
  type: "compactMulti";
  leaves: Uint8Array[];
  descriptor: Uint8Array;
}

type PeerManagerDirection = "inbound" | "outbound";

type PeerManagerForkName =
  | "phase0"
  | "altair"
  | "bellatrix"
  | "capella"
  | "deneb"
  | "electra"
  | "fulu"
  | "gloas"
  | "heze";

type PeerManagerReportPeerAction =
  | "Fatal"
  | "LowToleranceError"
  | "MidToleranceError"
  | "HighToleranceError"
  | "fatal"
  | "low_tolerance"
  | "mid_tolerance"
  | "high_tolerance";

interface PeerManagerConfig {
  targetPeers: number;
  maxPeers: number;
  targetGroupPeers: number;
  pingIntervalInboundMs: number;
  pingIntervalOutboundMs: number;
  statusIntervalMs: number;
  statusInboundGracePeriodMs: number;
  gossipsubNegativeScoreWeight: number;
  gossipsubPositiveScoreWeight: number;
  negativeGossipScoreIgnoreThreshold: number;
  disablePeerScoring: boolean;
  initialForkName: PeerManagerForkName;
  numberOfCustodyGroups: number;
  custodyRequirement: number;
  samplesPerSlot: number;
  slotsPerEpoch: number;
}

interface PeerManagerStatus {
  forkDigest: Uint8Array;
  finalizedRoot: Uint8Array;
  finalizedEpoch: number;
  headRoot: Uint8Array;
  headSlot: number;
  earliestAvailableSlot?: number | null;
}

interface PeerManagerMetadata {
  seqNumber: number;
  attnets: Uint8Array;
  syncnets: Uint8Array;
  custodyGroupCount: number;
  custodyGroups?: number[] | null;
  samplingGroups?: number[] | null;
}

interface PeerManagerRequestedSubnet {
  subnet: number;
  toSlot: number;
}

interface PeerManagerGossipScoreUpdate {
  peerId: string;
  score: number;
}

interface PeerManagerDiscoveryQuery {
  subnet: number;
  toSlot: number;
  maxPeersToDiscover: number;
}

interface PeerManagerCustodyGroupQuery {
  group: number;
  maxPeersToDiscover: number;
}

type PeerManagerAction =
  | {type: "send_ping"; peerId: string}
  | {type: "send_status"; peerId: string}
  | {type: "send_goodbye"; peerId: string; reason: number}
  | {type: "request_metadata"; peerId: string}
  | {type: "disconnect_peer"; peerId: string}
  | {
      type: "request_discovery";
      peersToConnect: number;
      attnetQueries: PeerManagerDiscoveryQuery[];
      syncnetQueries: PeerManagerDiscoveryQuery[];
      custodyGroupQueries: PeerManagerCustodyGroupQuery[];
    }
  | {type: "tag_peer_relevant"; peerId: string}
  | {type: "emit_peer_connected"; peerId: string; direction: PeerManagerDirection}
  | {type: "emit_peer_disconnected"; peerId: string};

interface PeerManagerPeerData {
  peerId: string;
  direction: PeerManagerDirection;
  relevantStatus: "unknown" | "relevant" | "irrelevant";
  connectedUnixTsMs: number;
  lastReceivedMsgUnixTsMs: number;
  lastStatusUnixTsMs: number;
  agentVersion: string | null;
  agentClient: string | null;
  encodingPreference: string | null;
}

interface PeerManagerApi {
  init: (config: PeerManagerConfig) => void;
  close: () => void;
  heartbeat: (currentSlot: number, localStatus: PeerManagerStatus) => PeerManagerAction[];
  checkPingAndStatus: () => PeerManagerAction[];
  onConnectionOpen: (peerId: string, direction: PeerManagerDirection) => PeerManagerAction[];
  onConnectionClose: (peerId: string) => PeerManagerAction[];
  onStatusReceived: (
    peerId: string,
    remoteStatus: PeerManagerStatus,
    localStatus: PeerManagerStatus,
    currentSlot: number
  ) => PeerManagerAction[];
  onMetadataReceived: (peerId: string, metadata: PeerManagerMetadata) => void;
  onMessageReceived: (peerId: string) => void;
  onGoodbye: (peerId: string, reason: number) => PeerManagerAction[];
  onPing: (peerId: string, seqNumber: number) => PeerManagerAction[];
  reportPeer: (peerId: string, action: PeerManagerReportPeerAction) => void;
  updateGossipScores: (scores: PeerManagerGossipScoreUpdate[]) => void;
  setSubnetRequirements: (
    attnets: PeerManagerRequestedSubnet[],
    syncnets: PeerManagerRequestedSubnet[]
  ) => void;
  setForkName: (forkName: PeerManagerForkName) => void;
  setSamplingGroups: (groups: number[]) => void;
  getConnectedPeerCount: () => number;
  getConnectedPeers: () => string[];
  getPeerData: (peerId: string) => PeerManagerPeerData | null;
  getEncodingPreference: (peerId: string) => string | null;
  getPeerKind: (peerId: string) => string | null;
  getAgentVersion: (peerId: string) => string | null;
  getPeerScore: (peerId: string) => number;
}

/** Options to control how state transition is run */
interface TransitionOpts {
  /** Verify the post-state root matches the block's state root. Default: true. */
  verifyStateRoot?: boolean;
  /** Verify the proposer signature on the signed block. Default: true. */
  verifyProposer?: boolean;
  /** Verify BLS signatures during block processing. Default: true. */
  verifySignatures?: boolean;
  /** Clone the state with transfer cache for memory efficiency. Default: true. */
  transferCache?: boolean;
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
  createMultiProof(descriptor: Uint8Array): CompactMultiProof;

  // stateTransition(signedBlockBytes: Uint8Array): BeaconStateView;
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
  peerManager: PeerManagerApi;
  BeaconStateView: typeof BeaconStateView;
};

export default bindings;
