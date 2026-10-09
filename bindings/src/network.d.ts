import type {BeaconConfig} from "./state-transition.js";

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
  processor: Readonly<Record<NativeTopicKind, NativeGossipProcessorLimit>>;
  /** Outstanding decoded payloads and messages, held until host completion. Requires processor. */
  execution?: Readonly<Record<NativeTopicKind, NativeGossipProcessorLimit>>;
  heartbeatIntervalMs: bigint;
  iwantFollowupMs: bigint;
  idontwantMinDataSize: number;
  validationTimeoutMs: bigint;
  validationTombstoneMs: bigint;
  pressureTimeoutMs: bigint;
  txTimeoutMs: bigint;
  /** Absolute active-frame lifetime. Large payloads share their first recipient's deadline; progress never extends it. */
  activeSendTimeoutMs: bigint;
  /** Distinct large payloads per kind, shared across recipients. */
  activeSendItems: Readonly<Record<NativeTopicKind, number>>;
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

/** Native log records lost since the last report: past capacity, over the rate limits, or cut to fit. */
export interface NativeLogLoss {
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

export interface NativeApplicationConfig extends NativeRuntimeConfig {
  /** Startup copies the derived network settings; this instance need not outlive initialization. */
  beaconConfig: BeaconConfig;
  resources: NativeResources;
  identify: {agentVersion: string; protocolVersion: string};
  serveLightClients: boolean;
  /** The threshold native records are kept at from initialization, until setLogLevel selects another. */
  logLevel: NativeLogLevel;
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
  | NativeRequestProtocolId;

export type NativeRequestProtocolId =
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
  | "gossip_send_timeout"
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

export interface NativeRequestOptions {
  expectedChunks?: number;
  /** Integer milliseconds, 1..60000. Default: 5000. */
  negotiationTimeoutMs?: number;
  /** Integer milliseconds, 1..60000. Default: 5000. */
  requestTimeoutMs?: number;
  /** Integer milliseconds, 1..60000. Default: 10000. */
  responseTimeoutMs?: number;
}
export interface NativeResponseChunk {
  data: Uint8Array;
  fork: NetworkFork | null;
  protocol: NativeRequestProtocolId;
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
        /** Native already recorded this fault against the peer. */
        peerFault: "protocol" | "non_completion" | null;
        detail: string | null;
        context: Uint8Array | null;
        peerStatus: number | null;
        peerMessage: Uint8Array | null;
      }
    | {code: "NetworkClosed"}
    | {code: "NetworkRequestBusy"}
  );
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
    | {code: "NetworkBridgeFull"}
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

export interface NativeGossipPublishOptions {
  allowZeroPeers?: boolean;
  ignoreDuplicate?: boolean;
  flood?: boolean;
}
export interface NativeGossipPublishResult {
  /** Recipients whose send queues accepted the message. */
  queued: number;
  /** Recipients whose send queues refused the message. */
  pressured: number;
  /** Selected recipients: queued + pressured + unavailable. */
  selected: number;
  /** Selected recipients without an available gossip stream. */
  unavailable: number;
  duplicate: boolean;
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

export type Verdict = "accept" | "reject" | "ignore";

/**
 * A failed close carries the first failure, a delivery failure the host's `failed` received or the owner's terminal
 * error, also when a requested close was already underway.
 */
export type CloseResult = {readonly reason: "requested"} | {readonly reason: "failed"; readonly error: Error};

/** Resolved at initialization: peer records the network retains, and incoming requests it serves at once. */
export interface NativeResolvedLimits {
  readonly peerCapacity: number;
  readonly incomingCapacity: number;
}

export interface GossipMessage {
  readonly attestationData: string | null;
  readonly slot: bigint | null;
  readonly peerId: PeerIdStr;
  readonly connection: NativeConnection;
  readonly topic: string;
  readonly id: Uint8Array;
  readonly data: Uint8Array;
  readonly receivedAtUnixMs: number;
}

/** One message, or one compatible attestation group validated together. */
export interface GossipJob {
  readonly kind: NativeTopicKind;
  readonly grouped: boolean;
  readonly messages: readonly GossipMessage[];
  /**
   * Resolves after the owner disposes of every returned verdict: eligible accepts have undergone forwarding admission,
   * and expired or already resolved messages are retired. Rejects with NetworkClosed if shutdown prevents it.
   */
  readonly reported: Promise<void>;
}

export interface DependencyCheck {
  readonly root: Uint8Array;
  readonly slot: bigint;
  readonly peerId: PeerIdStr;
  readonly topic: string;
}

/**
 * A serving start. Its serving capacity stays charged until the stream closes and the promise `serve` returned
 * settles. At most one ready() or respond() call may be pending.
 */
export interface IncomingRequest {
  readonly peerId: PeerIdStr;
  readonly connection: NativeConnection;
  readonly protocol: NativeRequestProtocolId;
  readonly data: Uint8Array;
  /** Stream and response obligations ended; host work may remain. */
  readonly closed: Promise<void>;
  /** Before producing the first chunk, wait for native readiness and bridge capacity for a maximum-sized chunk. */
  ready(): Promise<void>;
  /** Copies the chunk. Resolves when native stops borrowing it and reserves capacity for the next chunk. */
  respond(data: Uint8Array, context: NativeForkEntry | null): Promise<void>;
  finish(): Promise<void>;
  /** Accepts standard error codes 1–3 or custom codes 128–255, with at most 256 message bytes. */
  fail(status: number, message: Uint8Array): Promise<void>;
  cancel(): Promise<void>;
}

/** Current additional host capacity. Native applies its own gossip priority and execution limits. */
export interface HostCapacity {
  /** Native still delivers urgent gossip while validation is backpressured. */
  gossipValidation: "ready" | "backpressured";
  /** Excludes active requests. Finite; the binding floors and clamps it to 0..32. */
  incomingRequestSlots: number;
}

/** The consumer of one network's delivered work. The binding calls it only from later macrotasks. */
export interface NativeHost {
  /** A throw or an invalid value fails the host and stops payload delivery. */
  capacity(): HostCapacity;
  /**
   * Notify whenever capacity can have increased. Notifications may coalesce and carry no reservation.
   * The binding subscribes before its first capacity read and unsubscribes when delivery stops.
   * Return an idempotent unsubscribe function. A throw or invalid return fails the host.
   */
  subscribeCapacity(wake: () => void): () => void;
  /**
   * One verdict per message, in order. Must not await job.reported. A throw, a rejection or the wrong verdicts ignore
   * every message of the job.
   */
  validate(job: GossipJob): Promise<readonly Verdict[]>;
  /** One classification per check, in order. A throw or the wrong count classifies every check unavailable. */
  checkDependencies(checks: readonly DependencyCheck[]): readonly boolean[];
  /**
   * Ends the stream with finish(), fail() or cancel(), and settles only after the source and its child work retire.
   * A throw or rejection fails the stream.
   */
  serve(request: IncomingRequest): Promise<void>;
  /** Updates replace the previous state of the same peer. A throw fails the network. */
  peers(events: readonly NativePeerObservation[]): void;
  /**
   * A host capacity or peer callback failed the network with `error`, which the close result reports first. Payload delivery
   * has stopped and settlement continues: finish bounded cleanup, such as the final remembered-peer snapshot, then
   * close the network. A throw closes it at once.
   * An owner failure arrives through `closed` with reason `failed`.
   */
  failed(error: Error): void;
  /**
   * Native log records at or above the configured level, up to 256 every 100 ms and up to 2,048 after close, with the
   * records native lost since the last report when that grew, at most every 30 s while running. A throw counts the
   * delivery's records in lodestar_network_log_delivery_errors_total and never fails the network. Failed native drains count
   * separately in lodestar_network_log_drain_errors_total.
   */
  logs(records: readonly NativeLogRecord[], lost: NativeLogLoss | null): void;
  /** A failure the binding recovered from: one of the above that threw, rejected or broke its contract. */
  error?(error: unknown): void;
}

/** Promise-returning operations reject both admission errors and admitted operation failures. */
export interface NativeNetwork {
  readonly limits: NativeResolvedLimits;
  /** Native shutdown and its promised completions finished. A failed network cannot restart. */
  readonly closed: Promise<CloseResult>;
  /** Shares reserved admission with updateStatus; one state operation at a time avoids ordinary command pressure. */
  applyIntent(intent: NativeLocalIntent, slot: bigint): Promise<NativeIntentResult>;
  /** Updates Status for the active fork; preserves clock, subscriptions, Metadata, ENR and demand. */
  updateStatus(status: NetworkStatusUpdate): Promise<void>;
  /** Copies `root` before returning. Throws InvalidNetworkBytes unless it is a 32-byte Uint8Array. */
  blockImported(root: Uint8Array): void;
  /**
   * Coalesces up to 512 distinct peer/action pairs between exchanges. Reports for additional pairs are dropped and
   * counted in lodestar_peers_report_peer_dropped_total. Throws, queueing nothing, for a malformed peer id or unknown action.
   */
  reportPeer(peerId: PeerIdStr, action: NativePeerAction): void;
  dropQueuedGossip(): void;
  /**
   * Stops delivery of peer observations, dependency checks, serving starts and gossip. Irreversible and idempotent.
   * Completions and administrative operations continue; already started host tasks must still retire.
   */
  stopDelivery(): void;
  /** Copies admitted input. Admission pressure rejects with admission_full before any publication. */
  publish(topic: string, data: Uint8Array, options?: NativeGossipPublishOptions): Promise<NativeGossipPublishResult>;
  /** Throws synchronously for invalid input, admission refusal or a closed network; admitted failures reject next(). */
  request(
    peerId: PeerIdStr,
    protocol: NativeRequestProtocolId,
    data: Uint8Array,
    options?: NativeRequestOptions
  ): AsyncIterableIterator<NativeResponseChunk>;
  /** One-shot connection attempt, retired on success or timeout (10 s by default). */
  connect(peerId: PeerIdStr, endpoints: readonly IpEndpoint[], timeoutMs?: bigint): Promise<void>;
  /** Closes the connection and rejects pending connects with NetworkConnectCancelled. Direct membership remains. */
  disconnect(peerId: PeerIdStr): Promise<void>;
  /** Adds persistent direct membership, or with null removes it and reports whether it existed. */
  setDirectPeer(peerId: PeerIdStr, endpoints: readonly IpEndpoint[]): Promise<void>;
  setDirectPeer(peerId: PeerIdStr, endpoints: null): Promise<boolean>;
  reStatus(peerIds: readonly PeerIdStr[]): Promise<void>;
  getIdentity(): Promise<NativeIdentitySnapshot>;
  getPeers(): Promise<NativePeerSnapshot>;
  getDirectPeers(): Promise<NativeDirectSnapshot>;
  getGossipDiagnostics(cursor?: number): Promise<NativeGossipDiagnosticsPage>;
  /** Remembered peers for the host to persist. Take the final snapshot before close, which refuses it. */
  getRememberedPeers(): Promise<NativeRememberedPeersSnapshot>;
  /**
   * Prometheus text: the owner's families, rendered once per second, the drain burst histogram, dropped peer reports
   * and log delivery errors.
   */
  metrics(): string;
  /** Selects the threshold native records are kept at from now on. */
  setLogLevel(level: NativeLogLevel): void;
  /**
   * Stops delivery and completes native shutdown and outstanding operations. The binding finishes shutdown even if
   * only the returned promise remains reachable. Host serving and validation tasks may finish later.
   */
  close(): Promise<CloseResult>;
}

/**
 * Initialize from the owning thread using config.beaconConfig. One native runtime is live per process; a replacement
 * requires the previous runtime to be fully released, including garbage collection after close.
 * Copies configuration and returns a running network drained for `host`. Failure is terminal.
 * The application must call close(); dropping references does not request shutdown. Environment teardown stops
 * native work even when JavaScript cannot run. Invokes no host callback synchronously.
 */
export function createNativeNetwork(config: NativeApplicationConfig, host: NativeHost): NativeNetwork;
