/**
 * The low-level runtime the binding pump drains through `exchange`, and its controls. Private: the
 * package exports only `createNativeNetwork`, and binding ownership tests import this module directly.
 */
import type {
  HostCapacity,
  IpEndpoint,
  NativeConnection,
  NativeForkEntry,
  NativeIdentity,
  NativeLogRecord,
  NativeNetwork,
  NativePeerAction,
  NativePeerReportContext,
  NativePeerObservation,
  NativeRequestProtocolId,
  NativeTopicKind,
  PeerIdStr,
} from "./network.js";

/** One exchange's delivery, which the host owns. */
export interface NativeExchange {
  readonly identity: NativeIdentity | null;
  /** Updates replace the previous state of the same peer. */
  readonly peers: readonly NativePeerObservation[];
  readonly serving: readonly NativeIncomingRequest[];
  readonly checks: readonly NativeGossipDependencyCheck[];
  readonly gossip: NativeGossipBatch | null;
  /** Deliverable work remains, including work deferred by this turn's allowance. */
  readonly needsAnotherExchange: boolean;
}

export interface NativeDelivery extends Omit<NativeExchange, "serving"> {
  readonly serving: readonly NativeIncomingDescriptor[];
}

export interface NativeIncomingDescriptor
  extends Pick<NativeIncomingRequest, "peerId" | "connection" | "protocol" | "data" | "closed"> {
  readonly handle: {index: number; generation: bigint};
}

export interface NativeNetworkApplicationRuntime
  extends Pick<
    NativeNetwork,
    | "limits"
    | "setLogLevel"
    | "request"
    | "applyIntent"
    | "updateStatus"
    | "getGossipDiagnostics"
    | "getPeerScores"
    | "disconnect"
  > {
  drainLogs(maxRecords?: number): NativeLogBatch;
  /** Prometheus text rendered on demand by the owner. Rejects with NetworkClosed once the owner stops. */
  getMetrics: NativeNetwork["metrics"];
  publishGossip: NativeNetwork["publish"];
  /** A failed runtime cannot restart. The host must shut down the beacon node on terminal failure. */
  readonly closed: Promise<NativeRuntimeCloseResult>;
  readonly identity: NativeIdentity;
  /** One-shot connection attempt, retired on success or timeout. Use addDirectPeer for persistent membership. */
  connect(peerId: PeerIdStr, addresses: readonly IpEndpoint[], timeoutMs: bigint): Promise<void>;
  reStatusPeers: NativeNetwork["reStatus"];
  addDirectPeer(peerId: PeerIdStr, addresses: readonly IpEndpoint[]): Promise<void>;
  removeDirectPeer(peerId: PeerIdStr): Promise<boolean>;
  /** Settles bounded completions and delivers payloads under standing host capacity. */
  exchange(): NativeExchange;
  /** Replenishes the host allowance without scheduling delivery; call exchange when capacity recovers. */
  setCapacity(capacity: HostCapacity | null): void;
  reportGossip(handle: NativeGossipHandle, verdict: NativeGossipVerdict): void;
  classifyGossip(handle: NativeGossipHandle, available: boolean): void;
  notifyBlock(root: Uint8Array): void;
  dropQueuedGossip(): void;
  reportPeer(peerId: PeerIdStr, action: NativePeerAction, context?: NativePeerReportContext): void;
  close(): Promise<NativeRuntimeCloseResult>;
}

export interface NativeIncomingRequest {
  readonly peerId: PeerIdStr;
  readonly connection: NativeConnection;
  readonly protocol: NativeRequestProtocolId;
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
  endpoint: IpEndpoint | null;
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
}

export interface NativeGossipBatch {
  /** Non-attestation jobs contain one message; attestation jobs contain one compatible group. */
  jobs: NativeGossipJob[];
  messages: NativeGossipMessage[];
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
