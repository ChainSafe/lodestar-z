/**
 * The low-level runtime the binding pump drains through `exchange`, with its diagnostics and controls. Private: the
 * package exports only `createNativeNetwork`, and binding ownership tests import this module directly.
 */
import type {
  IpEndpoint,
  NativeApplicationConfig,
  NativeConnection,
  NativeDirectSnapshot,
  NativeForkEntry,
  NativeGossipDiagnosticsPage,
  NativeGossipPublishOptions,
  NativeGossipPublishResult,
  NativeIdentity,
  NativeIdentitySnapshot,
  NativeIntentResult,
  NativeLocalIntent,
  NativeLogLevel,
  NativeLogRecord,
  NativeNetwork,
  NativePeerAction,
  NativePeerObservation,
  NativePeerSnapshot,
  NativeRememberedPeersSnapshot,
  NativeRequestOptions,
  NativeResolvedLimits,
  NativeResponseChunk,
  NativeTopicKind,
  NetworkStatusUpdate,
  PeerIdStr,
} from "./network.js";

/**
 * One exchange's quotas, where zero disables a service, and the host's standing capacities. Completions settle or
 * arrive per family (1..256), whatever the rest of the demand; up to `peers` (0..64), `checks` (0..64) and
 * `servingStarts` (0..8) are delivered, and one job batch of `messages` (0..64) and `bytes` (0..16 MiB, a larger first
 * message comes alone), with ordinary jobs only under `claimOrdinary` and ordinary capacity.
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
  /**
   * Delivered messages the owner has disposed of, whatever the demand: it applied their verdicts, found them already
   * resolved or expired them. Each handle arrives once; close drops the rest. Not a peer penalty.
   */
  readonly acknowledged: readonly NativeGossipHandle[];
  /** Another exchange with the same enablement would make progress. */
  readonly more: boolean;
  /** Work waits for capacity the host reported as zero, or for a service this demand disabled. */
  readonly parked: {readonly serving: boolean; readonly ordinary: boolean};
  readonly disabledWaiting: boolean;
  /** Null, or why a serving start could not be handed over; it was cancelled and released, and `more` is true. */
  readonly failure: unknown;
  /** Completed publications and commands, which the exchange retired; each settles its operation's promise. */
  readonly completions: readonly NativeCompletion[];
  /** The close result, in the one exchange that settled it; otherwise null. */
  readonly closed: NativeRuntimeCloseResult | null;
}

/** An operation cell's handle, scoped to one runtime and family. */
export interface NativeCellHandle {
  index: number;
  generation: bigint;
}

/** An operation's error, whose `code` names it. */
export type NativeOperationError = Error & {code: string};

/** One completed operation cell: the value its promise resolves with, or the error it rejects with. */
export type NativeCompletion =
  | ({family: "publication"; handle: NativeCellHandle; kind?: undefined} & (
      | {value: NativeGossipPublishResult}
      | {error: NativeOperationError}
    ))
  | ({family: "command"; handle: NativeCellHandle; kind: NativeCommandKind} & (
      | {value: NativeCommandResult}
      | {error: NativeOperationError}
    ));

/** The command a completion answers, named as the runtime method that admitted it. */
export type NativeCommandKind =
  | "applyIntent"
  | "updateStatus"
  | "getIdentity"
  | "getPeers"
  | "getGossipDiagnostics"
  | "connect"
  | "disconnect"
  | "reStatusPeers"
  | "addDirectPeer"
  | "removeDirectPeer"
  | "getDirectPeers"
  | "getRememberedPeers";

/** What a command's promise resolves with: a snapshot or intent result, removeDirectPeer's boolean, or nothing. */
export type NativeCommandResult =
  | NativeIntentResult
  | NativeIdentitySnapshot
  | NativePeerSnapshot
  | NativeGossipDiagnosticsPage
  | NativeDirectSnapshot
  | NativeRememberedPeersSnapshot
  | boolean
  | undefined;

/**
 * A fatal site JavaScript raises: `generated_batch`, an exchange refused a batch or demand the pump generated;
 * `failed_turns`, a third consecutive turn failed; `completion_contract`, a completion matched no record the
 * completion owner installed, or native closed with promised completions missing.
 */
export type NativeEscalation = "generated_batch" | "failed_turns" | "completion_contract";

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
  readonly limits: NativeResolvedLimits;
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
   * One host turn: applies up to 256 `actions`, settles up to `demand.settleCells` request pulls and retirements and
   * incoming acknowledgements per table, delivers as many completed publications and commands per family in
   * `completions`, then the close result once nothing else awaits settlement or delivery, and delivers the payload
   * `demand` asks for. It throws only for invalid input or a nested call, before applying anything. Actions after
   * close are ignored; unknown penalized identities count in peerReportsIgnored.
   */
  exchange(actions: readonly NativeAction[], demand: NativeExchangeDemand): NativeExchange;
  /** Terminates the process at a fatal site. `reason` is at most 64 printable ASCII characters. */
  fail(site: NativeEscalation, reason: string): never;
  /** Throws what an exchange would for `action`, applying nothing. */
  checkAction(action: NativeAction): void;
  /**
   * Private control for binding ownership tests: while held, the owner leaves reported verdicts unapplied. Expiry
   * still disposes of them.
   */
  holdVerdicts(held: boolean): void;
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
 * runtime closes. A runtime collected without close stops at once, and its admitted operations still settle.
 */
export function initializeNativeNetworkRuntime(
  config: NativeApplicationConfig,
  onWorkAvailable: () => void
): NativeNetworkApplicationRuntime;

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

/** A facade's runtime, for binding ownership tests. */
export function runtimeOf(network: NativeNetwork): NativeNetworkApplicationRuntime | undefined;

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

/** A failed close names the owner's first terminal error, also when it followed a requested close. */
export type NativeRuntimeCloseResult = {reason: "requested"} | {reason: "failed"; error: Error & {code: string}};

export interface NativeLogBatch {
  records: NativeLogRecord[];
  more: boolean;
  dropped: bigint;
  suppressed: bigint;
  truncated: bigint;
}

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
  /** Owner dispositions of delivered messages awaiting an exchange's acknowledgement. */
  acknowledging: number;
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
