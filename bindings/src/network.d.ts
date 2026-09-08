export type NetworkFork = "phase0" | "altair" | "bellatrix" | "capella" | "deneb" | "electra" | "fulu" | "gloas";

export type IpEndpoint =
  | {family: 4; address: Uint8Array; port: number}
  | {family: 6; address: Uint8Array; port: number};

export interface AdvertisedEndpoints {
  ip4?: Uint8Array;
  ip6?: Uint8Array;
  udp?: number;
  udp6?: number;
  quic?: number;
  quic6?: number;
}

export interface NetworkStatus {
  forkDigest: Uint8Array;
  finalizedRoot: Uint8Array;
  finalizedEpoch: bigint;
  headRoot: Uint8Array;
  headSlot: bigint;
  earliestAvailableSlot: bigint | null;
}

export interface NetworkMetadata {
  sequenceNumber: bigint;
  attnets: Uint8Array;
  syncnets: number;
  custodyGroupCount: bigint | null;
}

export interface NativeForkContext {
  fork: NetworkFork;
  digest: Uint8Array;
  custodyGroups: number;
  minimumSamplingGroups: number;
}

export interface NativeLocalState {
  status: NetworkStatus;
  metadata: NetworkMetadata;
  fork: NativeForkContext;
}

export interface NativeForkSchedule {
  fuluScheduled: boolean;
  nextVersion: Uint8Array;
  nextEpoch: bigint;
  nextDigest: Uint8Array;
}

export interface NativeForkEntry {
  digest: Uint8Array;
  fork: NetworkFork;
}

export interface NativeDiscoveryConfig {
  bind: IpEndpoint;
  sequenceNumber: bigint;
  bootstrapEnrs: readonly Uint8Array[];
  advertisement: AdvertisedEndpoints | null;
}

export interface NativeTopicScoreParams {
  weight: number;
  timeInMeshWeight: number;
  timeInMeshCap: number;
  timeInMeshQuantumMs: bigint;
  firstDeliveryWeight: number;
  firstDeliveryCap: number;
  firstDeliveryDecay: number;
  meshDeliveryWeight: number;
  meshDeliveryThreshold: number;
  meshDeliveryCap: number;
  meshDeliveryDecay: number;
  meshDeliveryActivationMs: bigint;
  meshDeliveryWindowMs: bigint;
  meshFailureWeight: number;
  meshFailureDecay: number;
  invalidWeight: number;
  invalidDecay: number;
}

export interface NativeGlobalScoreParams {
  appWeight: number;
  ipColocationWeight: number;
  ipColocationThreshold: number;
  behaviourWeight: number;
  behaviourThreshold: number;
  behaviourDecay: number;
  topicCap: number;
  decayIntervalMs: bigint;
  decayToZero: number;
  gossipThreshold: number;
  publishThreshold: number;
  graylistThreshold: number;
  opportunisticGraftThreshold: number;
  defaultTopic: NativeTopicScoreParams;
}

export interface NativeGossipStartupPolicy {
  phase0Digest: Uint8Array | null;
  heartbeatIntervalMs: bigint;
  iwantFollowupMs: bigint;
  idontwantMinDataSize: number;
  validationTimeoutMs: bigint;
  validationTombstoneMs: bigint;
  pressureTimeoutMs: bigint;
  txTimeoutMs: bigint;
  largeFrameTimeoutMs: bigint;
  seenTtlMs: bigint;
  retainedScoreMs: bigint;
  opportunisticGraftIntervalMs: bigint;
  gossipFactor: number;
  ipAllowlist: readonly Uint8Array[];
  score: NativeGlobalScoreParams;
}

export type NativeTopicKind =
  | "beacon_block"
  | "beacon_aggregate_and_proof"
  | "beacon_attestation"
  | "proposer_slashing"
  | "attester_slashing"
  | "voluntary_exit"
  | "sync_committee_contribution_and_proof"
  | "sync_committee"
  | "light_client_finality_update"
  | "light_client_optimistic_update"
  | "bls_to_execution_change"
  | "blob_sidecar"
  | "data_column_sidecar";

export interface NativeTopicRule {
  count: number;
  sszMin: number;
  sszMax: number;
}

export interface NativeTopicBoundary {
  digest: Uint8Array;
  rules: Readonly<Record<NativeTopicKind, NativeTopicRule>>;
}

export interface NativeRuntimeConfig {
  profile: "small" | "beaconNode";
  identitySecretKey: Uint8Array;
  bind: IpEndpoint;
  local: NativeLocalState;
  forkSchedule: NativeForkSchedule;
  requestForks: readonly NativeForkEntry[];
  discovery: NativeDiscoveryConfig | null;
  initialSlot: bigint;
  gossipPolicy: NativeGossipStartupPolicy;
  /** Immutable copied chain namespace. Null explicitly selects generic raw topic behavior. */
  topicPolicy: readonly NativeTopicBoundary[] | null;
}

export interface NativeIdentity {
  session: bigint;
  peerId: Uint8Array;
  localEndpoint: IpEndpoint;
  localMultiaddr: Uint8Array;
  localEnr: Uint8Array | null;
}

export type NativeRuntimeState = "starting" | "prepared" | "running" | "stopping" | "closed" | "failed";

export interface NativeRuntimeDiagnostics {
  state: NativeRuntimeState;
  terminalErrorCode: string | null;
  session: bigint;
  currentSlot: bigint;
  clockRevision: bigint;
  ownerTurns: bigint;
  lastMonotonicMs: bigint;
  peerCount: number;
  readyPeerCount: number;
  queuedEvents: number;
  queueCapacity: number;
  queueHighWater: number;
  observationsDropped: bigint;
  operationalFailures: bigint;
  operationCapacity: number;
  operationOccupied: number;
  operationHighWater: number;
  operationRefusals: bigint;
  connectCapacity: number;
  connectOccupied: number;
  intentCapacity: number;
  intentOccupied: number;
  snapshotCapacity: number;
  snapshotOccupied: number;
  targetListCapacity: number;
  targetListOccupied: number;
  preparingPins: number;
  copyingPins: number;
  peerLaneCapacity: number;
  peerLaneOccupied: number;
  peerLaneHighWater: number;
  ownerSequence: bigint;
  liveNativeRequestedBytes: number;
  liveBridgeRequestedBytes: number;
  operationBytes: number;
  typedStoreBytes: number;
  peerLaneBytes: number;
  ownerShellBytes: number;
  ownerAllocationBytes: number;
  nativeAllocationCount: number;
  resolvedCapacities: NativeResolvedCapacities;
  connectHighWater: number;
  connectRefusals: bigint;
  intentHighWater: number;
  intentRefusals: bigint;
  snapshotHighWater: number;
  snapshotRefusals: bigint;
  targetListHighWater: number;
  targetListRefusals: bigint;
  nativeRequestedBytes: number;
  bridgeRequestedBytes: number;
}

export type NativeRuntimeEvent =
  | {type: "peerReady"; peerIndex: number; peerGeneration: bigint; peerId: Uint8Array}
  | {type: "peerUpdated"; peerIndex: number; peerGeneration: bigint; peerId: Uint8Array}
  | {type: "peerClosed"; peerIndex: number; peerGeneration: bigint; peerId: Uint8Array; reason: string}
  | {type: "operationalError"; code: string; count: bigint};

export interface NativeDrainBatch {
  events: NativeRuntimeEvent[];
  more: boolean;
  dropped: bigint;
}

export interface NativeRuntimeCloseResult {
  reason: "requested" | "startupCancelled" | "failed";
}

export interface NativeNetworkRuntime {
  readonly ready: Promise<NativeIdentity>;
  readonly state: NativeRuntimeState;
  setCurrentSlot(slot: bigint): bigint;
  diagnostics(): NativeRuntimeDiagnostics;
  drain(maxEvents: number): NativeDrainBatch;
  close(): Promise<NativeRuntimeCloseResult>;
}

export function createNativeNetworkRuntime(config: NativeRuntimeConfig, onReadable: () => void): NativeNetworkRuntime;

export interface NativeResources {
  peerCapacity: number;
  targetPeers: number;
  maxPeers: number;
  minOutbound: number;
  outboundReserve: number;
  connectionCapacity: number;
  handshakingCapacity: number;
  dialingCapacity: number;
  receiveBudgetBytes: number;
  nativeBudgetBytes: number;
  bridgeBudgetBytes: number;
}

export interface NativeRequestPolicy {
  denebStartSlot: bigint | null;
  blocksPreDeneb: number;
  blocksDeneb: number;
  blobIdentifiersDeneb: number;
  blobIdentifiersElectra: number;
  numberOfColumns: number;
  columnChunks: number;
  blobSchedule: readonly {startSlot: bigint; maxBlobs: number}[];
  hostIntegerMax: bigint | null;
}

export interface NativeCapabilities {
  receive: readonly NativeProtocolId[];
  request: readonly NativeProtocolId[];
}

export interface NativeApplicationConfig extends NativeRuntimeConfig {
  topicPolicy: readonly NativeTopicBoundary[];
  resources: NativeResources;
  requestPolicy: NativeRequestPolicy;
  identify: {agentVersion: string; protocolVersion: string};
  capabilities: NativeCapabilities;
}

export interface NativeDemand {
  attnets: Uint8Array;
  syncnets: number;
  groupTargets: readonly number[];
  attestationTarget: number;
  syncTarget: number;
  expiresAtSlot: bigint;
}

export interface NativeLocalIntent {
  update: {
    local: NativeLocalState;
    schedule: NativeForkSchedule;
    endpoints: AdvertisedEndpoints | null;
    capabilities: NativeCapabilities;
  };
  demand: NativeDemand;
  subscriptions: readonly {name: string; params: NativeTopicScoreParams}[];
}

export interface NativeIntentResult {
  changed: boolean;
  slot: bigint;
  ownerSequence: bigint;
}

export interface NativeIdentitySnapshot extends NativeIdentity {
  ownerSequence: bigint;
}

export interface NativeDirectSnapshot {
  identities: Uint8Array[];
  ownerSequence: bigint;
}

export interface NativePeerSnapshot {
  peers: NativePeerState[];
  occupiedCount: number;
  capacity: number;
  counts: {connected: number; relevant: number; outboundRelevant: number};
  ownerSequence: bigint;
}

export interface NativePeerBatch {
  events: NativePeerObservation[];
  more: boolean;
  ownerSequence: bigint;
  updatesReplaceState: true;
}

export interface NativeNetworkApplicationRuntime {
  readonly ready: Promise<NativeIdentity>;
  readonly state: NativeRuntimeState;
  diagnostics(): NativeRuntimeDiagnostics;
  drain(maxEvents: number): NativeDrainBatch;
  applyIntent(intent: NativeLocalIntent, slot: bigint): Promise<NativeIntentResult>;
  getIdentity(): Promise<NativeIdentitySnapshot>;
  getPeers(): Promise<NativePeerSnapshot>;
  connect(peerId: Uint8Array, addresses: readonly IpEndpoint[], timeoutMs: bigint): Promise<void>;
  disconnect(peerId: Uint8Array): Promise<void>;
  reStatusPeers(peerIds: readonly Uint8Array[]): Promise<void>;
  addDirectPeer(peerId: Uint8Array, addresses: readonly IpEndpoint[]): Promise<void>;
  removeDirectPeer(peerId: Uint8Array): Promise<boolean>;
  getDirectPeers(): Promise<NativeDirectSnapshot>;
  reportPeer(peerId: Uint8Array, action: NativePeerAction): void;
  drainPeers(maxEvents: number): NativePeerBatch;
  close(): Promise<NativeRuntimeCloseResult>;
}

export function createNativeNetworkApplicationRuntime(
  config: NativeApplicationConfig,
  onReadable: () => void
): NativeNetworkApplicationRuntime;

export type NativeProtocolId =
  | "/ipfs/id/1.0.0"
  | "/meshsub/1.2.0"
  | "/meshsub/1.1.0"
  | "/meshsub/1.0.0"
  | "/eth2/beacon_chain/req/status/1/ssz_snappy"
  | "/eth2/beacon_chain/req/status/2/ssz_snappy"
  | "/eth2/beacon_chain/req/goodbye/1/ssz_snappy"
  | "/eth2/beacon_chain/req/ping/1/ssz_snappy"
  | "/eth2/beacon_chain/req/metadata/1/ssz_snappy"
  | "/eth2/beacon_chain/req/metadata/2/ssz_snappy"
  | "/eth2/beacon_chain/req/metadata/3/ssz_snappy"
  | "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy"
  | "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy"
  | "/eth2/beacon_chain/req/blob_sidecars_by_range/1/ssz_snappy"
  | "/eth2/beacon_chain/req/blob_sidecars_by_root/1/ssz_snappy"
  | "/eth2/beacon_chain/req/data_column_sidecars_by_range/1/ssz_snappy"
  | "/eth2/beacon_chain/req/data_column_sidecars_by_root/1/ssz_snappy"
  | "/eth2/beacon_chain/req/beacon_blocks_by_head/1/ssz_snappy"
  | "/eth2/beacon_chain/req/light_client_bootstrap/1/ssz_snappy"
  | "/eth2/beacon_chain/req/light_client_updates_by_range/1/ssz_snappy"
  | "/eth2/beacon_chain/req/light_client_finality_update/1/ssz_snappy"
  | "/eth2/beacon_chain/req/light_client_optimistic_update/1/ssz_snappy";

export type NativePeerAction = "fatal" | "low_tolerance" | "mid_tolerance" | "high_tolerance";
export type NativeDisconnectReason =
  | "host"
  | "shutdown"
  | "transport_closed"
  | "duplicate"
  | "capacity"
  | "incompatible_fork"
  | "future_head"
  | "finalized_mismatch"
  | "missing_availability"
  | "invalid_status"
  | "invalid_metadata"
  | "remote_goodbye"
  | "health_timeout"
  | "reputation"
  | "banned"
  | "count_pruning";
export interface NativePeerRef {
  index: number;
  generation: bigint;
}
export interface NativeConnection {
  index: number;
  generation: number;
}
export interface NativePeerState {
  session: bigint;
  peer: NativePeerRef;
  identity: Uint8Array;
  connection: NativeConnection | null;
  direction: "inbound" | "outbound";
  endpoint: IpEndpoint;
  relevant: boolean;
  disconnectReason: NativeDisconnectReason | null;
  status: NetworkStatus | null;
  metadata: NetworkMetadata | null;
  identify: {agent: string | null; protocolVersion: string | null; protocols: NativeProtocolId[]} | null;
  statusAtMs: bigint;
  metadataAtMs: bigint;
  custodyGroups: number[] | null;
  samplingGroups: number[] | null;
  connectedAtMs: bigint;
  direct: boolean;
  score: number;
  banUntilMs: bigint;
  goodbyeUntilMs: bigint;
}
export type NativePeerObservation =
  | {type: "ready" | "updated"; state: NativePeerState; ownerSequence: bigint}
  | {
      type: "closed";
      session: bigint;
      peer: NativePeerRef;
      connection: NativeConnection;
      identity: Uint8Array;
      reason: NativeDisconnectReason;
      ownerSequence: bigint;
    };

export interface NativeResolvedCapacities {
  peerCapacity: number;
  targetPeers: number;
  maxPeers: number;
  minOutbound: number;
  outboundReserve: number;
  connectionCapacity: number;
  handshakingCapacity: number;
  dialingCapacity: number;
  requestPeerCapacity: number;
  admissionIdentityCapacity: number;
  gossipConnectedCapacity: number;
  gossipRetainedCapacity: number;
  dialEngineCapacity: number;
}
