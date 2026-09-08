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

export type NativeRuntimeState = "starting" | "running" | "stopping" | "closed" | "failed";

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
