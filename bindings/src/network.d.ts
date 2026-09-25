/** Canonical unprefixed base58btc secp256k1 identity multihash, equal to libp2p PeerId.toString(). */
export type PeerIdStr = string;

export type NetworkFork = "phase0" | "altair" | "bellatrix" | "capella" | "deneb" | "electra" | "fulu" | "gloas";

/** IPv4 uses four address bytes; IPv6 uses sixteen and excludes IPv4-mapped addresses. */
export type IpEndpoint =
  | {family: 4; address: Uint8Array; port: number}
  | {family: 6; address: Uint8Array; port: number};

export interface AdvertisedEndpoints {
  ip4?: Uint8Array;
  /** Sixteen IPv6 address bytes; IPv4-mapped addresses are invalid. */
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

export type NetworkStatusUpdate = Omit<NetworkStatus, "forkDigest">;

export interface NativeLocalState {
  status: NetworkStatusUpdate;
  metadata: NetworkMetadata & {custodyGroupCount: bigint};
}

export interface NativeForkEntry {
  digest: Uint8Array;
  fork: NetworkFork;
}

export interface NativeDiscoveryConfig {
  /** IPv6 listeners accept only IPv6; IPv4 and IPv6 listeners may share a port. */
  bind: IpEndpoint | readonly IpEndpoint[];
  sequenceNumber: bigint;
  bootstrapEnrs: readonly Uint8Array[];
  /** Initial IP/UDP hints do not disable learning. QUIC uses its fixed or bound port. */
  advertisement: Pick<AdvertisedEndpoints, "ip4" | "ip6" | "udp" | "udp6"> | null;
  /** Explicit operator overrides. An IP also fixes UDP to the supplied or bound port. */
  fixed: AdvertisedEndpoints;
}

export interface NativeTopicScoreParams {
  /** First accepted slot with mesh-delivery penalties enabled. */
  meshDeliveryStartSlot: bigint;
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
  topics: Readonly<Record<NativeTopicKind, NativeTopicScoreParams>>;
}

export interface NativeGossipProcessorLimit {
  items: number;
  bytes: number;
}

export interface NativeGossipStartupPolicy {
  /** Fixed limits in NativeTopicKind declaration order. */
  processor: readonly NativeGossipProcessorLimit[];
  /** Outstanding decoded payloads and messages, held until host completion. Requires processor. */
  execution?: readonly NativeGossipProcessorLimit[];
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

export interface NativeRuntimeConfig {
  profile: "small" | "beaconNode";
  identitySecretKey: Uint8Array;
  /** IPv6 listeners accept only IPv6; IPv4 and IPv6 listeners may share a port. */
  bind: IpEndpoint | readonly IpEndpoint[];
  local: NativeLocalState;
  discovery: NativeDiscoveryConfig | null;
  initialSlot: bigint;
  gossipPolicy: NativeGossipStartupPolicy;
}

export interface NativeIdentity {
  peerId: PeerIdStr;
  localEndpoint: IpEndpoint;
  localEndpoints: readonly IpEndpoint[];
  localMultiaddr: Uint8Array;
  localEnr: Uint8Array | null;
  metadata: NativeLocalState["metadata"];
}

export type NativeRuntimeState = "running" | "stopping" | "closed" | "failed";

export interface NativeRuntimeDiagnostics {
  payloadBudget: {
    limitBytes: number;
    usedBytes: number;
    incomingMinimumBytes: number;
    outgoingMinimumBytes: number;
    publicationMinimumBytes: number;
  };
  publications: NativePublicationDiagnostics;
  requests: NativeRequestDiagnostics;
  incoming: NativeIncomingDiagnostics;
  gossip: NativeGossipDiagnostics;
  state: NativeRuntimeState;
  terminalErrorCode: string | null;
  currentSlot: bigint;
  ownerTurns: bigint;
  operationalFailures: bigint;
  operationOccupied: number;
  peerReportsIgnored: bigint;
  connectOccupied: number;
  preparingPins: number;
  copyingPins: number;
  peerLaneOccupied: number;
  ownerSequence: bigint;
  liveNativeRequestedBytes: number;
  liveBridgeRequestedBytes: number;
  typedStoreBytes: number;
  metricsExportBytes: number;
  peerLaneBytes: number;
  ownerShellBytes: number;
  nativeAllocationCount: number;
  /** Configured QUIC flow-control ceilings, separate from the native allocation ledger. */
  quicReceiveWindowBytes: bigint;
  quicConnectionWindowBytes: bigint;
  quicStreamWindowBytes: bigint;
  resolvedCapacities: NativeResolvedCapacities;
  nativeRequestedBytes: number;
  bridgeRequestedBytes: number;
}

export interface NativeRuntimeCloseResult {
  reason: "requested" | "failed";
}

export type NativeLogLevel = "error" | "warn" | "info" | "debug" | "off";

export interface NativeLogRecord {
  level: Exclude<NativeLogLevel, "off">;
  scope: string;
  message: string;
  sequence: bigint;
  timestampMs: bigint;
  monotonicMs: bigint;
  truncated: boolean;
}

export interface NativeLogBatch {
  records: NativeLogRecord[];
  more: boolean;
  dropped: bigint;
  suppressed: bigint;
  truncated: bigint;
}

export interface NativeResources {
  /** Retained peer records, at most 512. */
  peerCapacity: number;
  /** Steady peer target, strictly below maxPeers to admit locally selected trials. */
  targetPeers: number;
  maxPeers: number;
  minOutbound: number;
  outboundReserve: number;
  connectionCapacity: number;
  handshakingCapacity: number;
  /** Concurrent outbound QUIC dials, at most 64, independent of maxPeers - targetPeers. */
  dialingCapacity: number;
  receiveBudgetBytes: number;
  nativeBudgetBytes: number;
  bridgeBudgetBytes: number;
}

/** A peer that served a connection native dialed, remembered so a restart can redial it. */
export interface NativeRememberedPeer {
  peerId: PeerIdStr;
  /** The QUIC endpoint native dialed, never an inbound source. */
  endpoint: IpEndpoint;
  /** Unix time in seconds at which the peer last qualified. */
  qualifiedAtUnixS: number;
}

/** At most 256 peers of the network with `genesisValidatorsRoot`. */
export interface NativeRememberedPeers {
  genesisValidatorsRoot: Uint8Array;
  peers: readonly NativeRememberedPeer[];
}

export interface NativeRememberedPeersSnapshot extends NativeRememberedPeers {
  peers: NativeRememberedPeer[];
  ownerSequence: bigint;
}

/** Configure the shared BeaconConfig before constructing a network runtime. */
export interface NativeApplicationConfig extends NativeRuntimeConfig {
  resources: NativeResources;
  identify: {agentVersion: string; protocolVersion: string};
  serveLightClients: boolean;
  /**
   * Peers an earlier run remembered, replayed as paced automatic candidates. Another network's root, more than 256
   * peers or a malformed peer rejects the configuration; native drops expired and duplicate peers.
   */
  rememberedPeers?: NativeRememberedPeers | null;
}

/** Desired coverage persists until replacement; the host owns validator duty expiry. */
export interface NativeDemand {
  attnets: Uint8Array;
  syncnets: number;
  /** At most 128 targets; omitted trailing entries are zero. Each target is bounded by maxPeers. */
  groupTargets: Uint16Array;
  /** Same bounds as groupTargets. Standing custody service targets; request consumers still check slot availability. */
  custodyGroupTargets: Uint16Array;
  attestationTarget: number;
  syncTarget: number;
}

export interface NativeSubscriptionSet {
  digest: Uint8Array;
  /** Bit i selects subnet i; singleton kinds use bit 0. Missing kinds are unsubscribed. */
  subnets: Partial<Record<NativeTopicKind, Uint8Array>>;
}

export interface NativeLocalIntent {
  update: {
    local: NativeLocalState;
  };
  demand: NativeDemand;
  /** One set per configured boundary; omitted boundaries are unsubscribed. */
  subscriptions: readonly NativeSubscriptionSet[];
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
  identities: PeerIdStr[];
  ownerSequence: bigint;
}

export interface NativePeerSnapshot {
  peers: NativePeerState[];
  occupiedCount: number;
  capacity: number;
  counts: {connected: number; relevant: number; outboundRelevant: number};
  ownerSequence: bigint;
}

/**
 * One exchange's quotas, where zero disables a service, and the host's standing capacities. Completions settle per
 * table (1..256); up to `peers` (0..64), `checks` (0..64) and `servingStarts` (0..8) are delivered, and one job batch
 * of `messages` (0..64) and `bytes` (0..16 MiB, a larger first message comes alone), with ordinary jobs only under
 * `claimOrdinary` and ordinary capacity.
 */
export interface NativeExchangeDemand {
  settleCells: number;
  peers: number;
  checks: number;
  servingStarts: number;
  messages: number;
  bytes: number;
  claimOrdinary: boolean;
  /** Serving starts the host can take (0..32), counted down by delivered starts, and ordinary execution. Null keeps them. */
  capacity: {serving: number; ordinary: boolean} | null;
}

/**
 * Applied before the exchange selects its delivery: one verdict per delivered message, one classification per
 * delivered check, imported blocks, a recheck of every waiting message, and coalesced peer penalties (1..100).
 */
export type NativeAction =
  | {type: "verdict"; handle: NativeGossipHandle; verdict: NativeGossipVerdict}
  | {type: "classify"; handle: NativeGossipHandle; available: boolean}
  | {type: "block"; root: Uint8Array}
  | {type: "recheck"}
  | {type: "dropQueued"}
  | {type: "reportPeer"; peerId: PeerIdStr; action: NativePeerAction; count: number};

/** One exchange's delivery, which the host owns; frozen when it delivers nothing. */
export interface NativeExchange {
  /** Updates replace the previous state of the same peer. */
  readonly peers: readonly NativePeerObservation[];
  readonly serving: readonly NativeIncomingRequest[];
  readonly checks: readonly NativeGossipDependencyCheck[];
  readonly gossip: NativeGossipBatch | null;
  /** Another exchange with the same enablement would make progress. */
  readonly more: boolean;
  /** Work waits for capacity the host reported as zero, or for a service this demand disabled. */
  readonly parked: {readonly serving: boolean; readonly ordinary: boolean};
  readonly disabledWaiting: boolean;
  /** Null, or why a serving start could not be handed over; it was cancelled and released, and `more` is true. */
  readonly failure: unknown;
}

/** An escalation trigger: 1, an exchange refused a generated batch; 3, the host's demand kept failing. */
export type NativeEscalation = 1 | 3;

export interface NativePublicationDiagnostics {
  capacity: number;
  urgentReserved: number;
  occupied: number;
  highWater: number;
  refusals: bigint;
  byteRefusals: bigint;
  reservedBytes: number;
  reservedBytesHighWater: number;
  payloadBytes: number;
  copies: bigint;
  bytesCopied: bigint;
  queued: bigint;
  pressured: bigint;
  selected: bigint;
  unavailable: bigint;
  duplicates: bigint;
  latencyCount: bigint;
  /** Upper histogram bucket bounds, in milliseconds. */
  latencyMsP50: bigint;
  latencyMsP99: bigint;
}

export interface NativeNetworkApplicationRuntime {
  drainLogs(maxRecords?: number): NativeLogBatch;
  setLogLevel(level: NativeLogLevel): void;
  /** Prometheus text rendered by the network owner once per second. Counters survive close. */
  getMetrics(): string;
  /** A failed runtime cannot restart. The host must shut down the beacon node on terminal failure. */
  readonly closed: Promise<NativeRuntimeCloseResult>;
  /** Copies admitted input. Admission pressure rejects with admission_full before any publication. */
  publishGossip(
    topic: string,
    data: Uint8Array,
    options?: NativeGossipPublishOptions
  ): Promise<NativeGossipPublishResult>;
  request(
    peerId: PeerIdStr,
    protocol: string,
    data: Uint8Array,
    options?: NativeRequestOptions
  ): AsyncIterableIterator<NativeResponseChunk>;
  readonly identity: NativeIdentity;
  readonly state: NativeRuntimeState;
  diagnostics(): NativeRuntimeDiagnostics;
  applyIntent(intent: NativeLocalIntent, slot: bigint): Promise<NativeIntentResult>;
  /** Updates Status for the active fork; preserves clock, subscriptions, Metadata, ENR and demand. */
  updateStatus(status: NetworkStatusUpdate): Promise<void>;
  getIdentity(): Promise<NativeIdentitySnapshot>;
  getGossipDiagnostics(cursor?: number): Promise<NativeGossipDiagnosticsPage>;
  getPeers(): Promise<NativePeerSnapshot>;
  /** One-shot connection attempt, retired on success or timeout. Use addDirectPeer for persistent membership. */
  connect(peerId: PeerIdStr, addresses: readonly IpEndpoint[], timeoutMs: bigint): Promise<void>;
  /** Closes the connection and rejects pending connects with NetworkConnectCancelled. Direct membership remains. */
  disconnect(peerId: PeerIdStr): Promise<void>;
  reStatusPeers(peerIds: readonly PeerIdStr[]): Promise<void>;
  addDirectPeer(peerId: PeerIdStr, addresses: readonly IpEndpoint[]): Promise<void>;
  removeDirectPeer(peerId: PeerIdStr): Promise<boolean>;
  getDirectPeers(): Promise<NativeDirectSnapshot>;
  /**
   * Remembered peers for the host to persist: every unexpired record, refreshed for connections that qualify now.
   * Take the final snapshot before close, which refuses it.
   */
  getRememberedPeers(): Promise<NativeRememberedPeersSnapshot>;
  /**
   * One host turn: applies up to 256 `actions`, settles up to `demand.settleCells` completed publications, commands,
   * request pulls and retirements, and incoming acknowledgements per table, then the close result once nothing else
   * awaits settlement, and delivers the payload `demand` asks for. It throws only for invalid input or a nested call,
   * before applying anything. Actions after close are ignored; unknown penalized identities count in
   * peerReportsIgnored.
   */
  exchange(actions: readonly NativeAction[], demand: NativeExchangeDemand): NativeExchange;
  /** Terminates the process for an escalated bridge contract failure. */
  fail(trigger: NativeEscalation, reason: string): never;
  close(): Promise<NativeRuntimeCloseResult>;
}

/**
 * Initialize from the owning thread, after configuring BeaconConfig. One runtime is live per process;
 * another initializes only after the previous one is garbage collected.
 * Copies configuration and returns a running runtime; failure is terminal.
 * Calls onWorkAvailable on that thread when results, peer events, incoming requests, or gossip work arrive after
 * an exchange found nothing queued, and from request and incoming calls that leave results to settle.
 * onWorkAvailable must only schedule an exchange in a later macrotask. No further notification arrives while work
 * stays queued, so the host exchanges again while one returns `more`, retries on a timer while it returns
 * `disabledWaiting` or `parked` work it can take later, and never cancels a scheduled exchange, also after the
 * runtime closes.
 */
export function initializeNativeNetworkRuntime(
  config: NativeApplicationConfig,
  onWorkAvailable: () => void
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
  | "count_pruning"
  | "gossip_unavailable"
  | "health_error";
export interface NativeConnection {
  index: number;
  generation: number;
}
export interface NativePeerState {
  identity: PeerIdStr;
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
  scoreAtMs: bigint;
  banUntilMs: bigint;
  goodbyeUntilMs: bigint;
  redialUntilMs: bigint;
}
export type NativePeerObservation =
  | {type: "ready" | "updated"; state: NativePeerState; ownerSequence: bigint}
  | {
      type: "closed";
      connection: NativeConnection;
      identity: PeerIdStr;
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

export interface NativeRequestOptions {
  expectedChunks?: number;
  negotiationTimeoutMs?: number;
  requestTimeoutMs?: number;
  responseTimeoutMs?: number;
}
export interface NativeResponseChunk {
  data: Uint8Array;
  fork: NetworkFork | null;
  protocol: string;
}
export type NativeRequestPhase = "negotiation" | "request" | "response";
export type NativeRequestRejection =
  | "disconnected"
  | "protocol_disabled"
  | "invalid_request"
  | "invalid_request_options"
  | "too_many_requests"
  | "slots_exhausted"
  | "negotiation_table_full"
  | "transport";
export type NativeRequestFailure =
  | "timeout"
  | "host_timeout"
  | "quota_timeout"
  | "cancelled"
  | "negotiation_rejected"
  | "negotiation_failed"
  | "invalid_response"
  | "too_many_chunks"
  | "empty_response"
  | "unknown_context"
  | "peer_error"
  | "connection_closed"
  | "stream_closed"
  | "transport";
export type NativeRequestError = Error &
  (
    | {code: "NetworkRequestRejected"; reason: NativeRequestRejection}
    | {
        code: "NetworkRequestFailed";
        reason: NativeRequestFailure;
        phase: NativeRequestPhase | null;
        detail: string | null;
        context: Uint8Array | null;
        peerStatus: number | null;
        peerMessage: Uint8Array | null;
      }
    | {code: "NetworkClosed"}
    | {code: "NetworkRequestBusy"}
  );
export interface NativeRequestDiagnostics {
  capacity: number;
  occupied: number;
  highWater: number;
  pendingPulls: number;
  terminalCells: number;
  reservedBytes: number;
  reservedBytesHighWater: number;
  inputBytes: number;
  sinkBytes: number;
  copyingBytes: number;
  chunksCopied: bigint;
  bytesCopied: bigint;
  requestFull: bigint;
  busyPulls: bigint;
}

export interface NativeIncomingRequest {
  readonly peerId: PeerIdStr;
  readonly connection: NativeConnection;
  readonly protocol: string;
  readonly data: Uint8Array;
  /** Resolves once the stream and pending responses have retired. Retained host work may still be running. */
  readonly closed: Promise<void>;
  /** Call once before serving to retain capacity until asynchronous host work actually retires. */
  retainUntil(retired: Promise<void>): void;
  /** Wait for response quota and capacity for one maximum chunk before producing it. */
  ready(): Promise<void>;
  respond(data: Uint8Array, context: NativeForkEntry | null): Promise<void>;
  finish(): Promise<void>;
  /** Accepts standard error codes 1–3 or custom codes 128–255, with at most 256 message bytes. */
  fail(status: number, message: Uint8Array): Promise<void>;
  /** Applies cancellation at the owner's next servicing opportunity; intervening native completion remains authoritative. */
  cancel(): Promise<void>;
}

export type NativeIncomingFailure =
  | "timeout"
  | "host_timeout"
  | "quota_timeout"
  | "cancelled"
  | "connection_closed"
  | "stream_closed"
  | "transport";

/** Operational request errors. Malformed arguments and allocation failures retain their existing specific errors. */
export type NativeIncomingError = Error &
  (
    | {code: "NetworkIncomingBusy"}
    | {code: "NetworkIncomingClosed"}
    | {
        code: "NetworkIncomingRejected";
        reason:
          | "invalid_context"
          | "unknown_fork"
          | "chunk_too_large"
          | "chunk_too_small"
          | "too_many_chunks"
          | "invalid_error";
      }
    | {code: "NetworkIncomingFailed"; failure: NativeIncomingFailure}
    | {code: "NetworkClosed"}
  );

export interface NativeIncomingDiagnostics {
  retiring: number;
  pendingPermissions: number;
  capacity: number;
  occupied: number;
  queued: number;
  highWater: number;
  pendingResponses: number;
  closedPromises: number;
  reservedBytes: number;
  reservedBytesHighWater: number;
  requestBytes: number;
  responseBytes: number;
  copyingBytes: number;
  requestsTaken: bigint;
  responseBytesCopied: bigint;
  chunksWritten: bigint;
  bytesWritten: bigint;
  capacityRefusals: bigint;
  byteRefusals: bigint;
}

export interface NativeGossipHandle {
  index: number;
  generation: bigint;
}
export type NativeGossipVerdict = "accept" | "reject" | "ignore";
export interface NativeGossipDependencyCheck {
  handle: NativeGossipHandle;
  root: Uint8Array;
  slot: bigint;
  peerId: PeerIdStr;
  topic: string;
}
export interface NativeGossipMessage {
  attestationData: string | null;
  slot: bigint | null;
  handle: NativeGossipHandle;
  peerId: PeerIdStr;
  connection: NativeConnection;
  topic: string;
  id: Uint8Array;
  data: Uint8Array;
  receivedAtUnixMs: number;
}
export interface NativeGossipJob {
  kind: NativeTopicKind;
  start: number;
  length: number;
  grouped: boolean;
  /** A block, blob sidecar or data column job, which ordinary gating never withholds. */
  urgent: boolean;
}
export interface NativeGossipBatch {
  /** Non-attestation jobs contain one message; attestation jobs contain one compatible group. */
  jobs: NativeGossipJob[];
  messages: NativeGossipMessage[];
}
export interface NativeGossipPublishOptions {
  allowZeroPeers?: boolean;
  ignoreDuplicate?: boolean;
  flood?: boolean;
}
export interface NativeGossipPublishResult {
  queued: number;
  pressured: number;
  selected: number;
  unavailable: number;
  duplicate: boolean;
}

export interface NativeGossipDiagnostics {
  waiting: number;
  checking: number;
  executing: number;
  executingBytes: number;
  copying: number;
  expiredExecuting: number;
  /** Milliseconds past the earliest verdict deadline among delivered validations awaiting host completion; zero when none. */
  oldestExpiredExecutionAgeMs: bigint;
  slotRefusals: bigint;
  capacity: number;
  occupied: number;
  highWater: number;
  queued: number;
  pendingVerdicts: number;
  reservedBytes: number;
  reservedBytesHighWater: number;
  payloadBytes: number;
  copyingBytes: number;
  publicationBytes: number;
  messagesCopied: bigint;
  bytesCopied: bigint;
  capacityRefusals: bigint;
  byteRefusals: bigint;
  queuedExpired: bigint;
  deliveredExpired: bigint;
  reportsAccepted: bigint;
  reportsAppliedAccept: bigint;
  reportsAppliedReject: bigint;
  reportsAppliedIgnore: bigint;
  publicationCopies: bigint;
  publicationQueued: bigint;
  publicationSelected: bigint;
  publicationDuplicates: bigint;
}

export type NetworkGossipPublishFailed = Error & {
  code: "NetworkGossipPublishFailed";
  reason:
    | "unknown_topic"
    | "payload_too_small"
    | "payload_too_large"
    | "compress_failed"
    | "admission_full"
    | "resource_exhausted"
    | "duplicate"
    | "no_peers_subscribed_to_topic";
};

export interface NativeGossipTopicDiagnostic {
  index: number;
  topic: string;
  subscribed: boolean;
  weight: number;
  meshDeliveryActivationMs: bigint;
}
export interface NativeGossipTopicScoreDiagnostic {
  index: number;
  inMesh: boolean;
  meshMember: boolean;
  graftTimeMs: bigint;
  meshTimeMs: bigint;
  firstMessageDeliveries: number;
  meshMessageDeliveries: number;
  meshFailurePenalty: number;
  invalidMessageDeliveries: number;
  weights: {p1: number; p2: number; p3: number; p3b: number; p4: number};
}
export interface NativeGossipPeerDiagnostic {
  identity: PeerIdStr;
  ip: Uint8Array;
  connected: boolean;
  outboundReady: boolean;
  expireAtMs: bigint;
  score: number;
  appScore: number;
  behaviourPenalty: number;
  weights: {p5: number; p6: number; p7: number};
  topics: NativeGossipTopicScoreDiagnostic[];
}
/** Each page is copied from one owner turn. Cursors traverse at most 512 retained peer slots. */
export interface NativeGossipDiagnosticsPage {
  ownerSequence: bigint;
  observedMonoMs: bigint;
  observedUnixMs: bigint;
  nextCursor: number | null;
  topics: NativeGossipTopicDiagnostic[];
  peers: NativeGossipPeerDiagnostic[];
}
