import {publicKeyFromProtobuf} from "@libp2p/crypto/keys";
import {peerIdFromPublicKey} from "@libp2p/peer-id";
import {testChain} from "../../../test/interop/network_chain.mjs";
import {initializeNativeNetworkRuntime} from "../../src/network-runtime.js";
export {testChain};

import {type ChainConfig, createBeaconConfig} from "@lodestar/config";
import bindings from "../../src/index.js";
import type {
  IpEndpoint,
  NativeApplicationConfig,
  NativeDiscoveryConfig,
  NativeGossipProcessorLimit,
  NativeLocalIntent,
  NativeRuntimeConfig,
  NativeSubscriptionSet,
  NativeTopicKind,
  NativeTopicScoreParams,
} from "../../src/network.js";
import type {
  NativeAction,
  NativeExchange,
  NativeExchangeDemand,
  NativeIncomingRequest,
  NativeNetworkApplicationRuntime,
} from "../../src/network-runtime.js";

const MIB = 1024 * 1024;

/** An exchange that only settles results, as a closed host's does; tests add the payload they take. */
export const settleOnly: NativeExchangeDemand = {
  bytes: 0,
  capacity: null,
  checks: 0,
  claimOrdinary: false,
  messages: 0,
  peers: 0,
  servingStarts: 0,
  settleCells: 32,
};
/** A host that serves every start and executes ordinary gossip. */
export const capacity = {ordinary: true, serving: 32};
/** Dependency checks and every claimable gossip job, as one exchange takes them. */
export const gossipAll: NativeExchangeDemand = {
  ...settleOnly,
  bytes: 16 * MIB,
  capacity,
  checks: 64,
  claimOrdinary: true,
  messages: 64,
};
/** Dependency checks without a gossip claim. */
export const checksOnly: NativeExchangeDemand = {...settleOnly, capacity, checks: 64};

export function exchange(
  runtime: Pick<NativeNetworkApplicationRuntime, "exchange">,
  demand: NativeExchangeDemand,
  actions: readonly NativeAction[] = []
): NativeExchange {
  return runtime.exchange(actions, demand);
}

/** The oldest queued incoming request, as one serving start of an exchange. */
export function nextIncoming<T = NativeIncomingRequest>(runtime: {
  exchange(actions: readonly NativeAction[], demand: NativeExchangeDemand): {serving: readonly T[]};
}): T | null {
  return runtime.exchange([], {...settleOnly, capacity, servingStarts: 1}).serving[0] ?? null;
}

/**
 * Lodestar's processor plan for a small validator set, in topicKinds order. Each kind's byte weight exceeds its
 * largest compressed message on the test chain, so the weight sets the bytes.
 */
function gossipProcessor(): NativeGossipProcessorLimit[] {
  const items = [8, 2048, 128, 32, 32, 128, 128, 1024, 8, 8, 128, 256, 256];
  const byteWeights = [24, 8, 8, 1, 4, 1, 2, 2, 2, 2, 1, 8, 16];
  return topicKinds.map((_, i) => ({bytes: byteWeights[i] * MIB, items: items[i]}));
}

/** Lodestar's default host execution limits, capped by the processor items. */
function gossipExecution(processor: readonly NativeGossipProcessorLimit[]): NativeGossipProcessorLimit[] {
  const byteWeights = [32, 4, 8, 1, 4, 1, 2, 2, 2, 2, 1, 8, 24];
  const itemWeights = [1, 8, 32, 1, 1, 1, 2, 4, 1, 1, 1, 4, 8];
  const byteTotal = byteWeights.reduce((sum, weight) => sum + weight, 0);
  const itemTotal = itemWeights.reduce((sum, weight) => sum + weight, 0);
  const itemBudget = 4096;
  const byteBudget = 64 * MIB;
  return topicKinds.map((_, i) => ({
    bytes: Math.floor((byteBudget * byteWeights[i]) / byteTotal),
    items: Math.min(Math.floor((itemBudget * itemWeights[i]) / itemTotal), processor[i].items),
  }));
}

export function networkConfig(): NativeRuntimeConfig {
  const key = new Uint8Array(32);
  key[31] = 1;
  const processor = gossipProcessor();
  return {
    bind: {address: Uint8Array.of(127, 0, 0, 1), family: 4, port: 0},
    discovery: null,
    gossipPolicy: {
      execution: gossipExecution(processor),
      gossipFactor: 0.25,
      heartbeatIntervalMs: 1000n,
      idontwantMinDataSize: 16829,
      ipAllowlist: [],
      iwantFollowupMs: 12000n,
      largeFrameTimeoutMs: 30000n,
      opportunisticGraftIntervalMs: 60000n,
      pressureTimeoutMs: 30000n,
      processor,
      retainedScoreMs: 38400000n,
      score: {
        behaviourDecay: 0.9,
        behaviourThreshold: 6,
        behaviourWeight: -10,
        decayIntervalMs: 12000n,
        decayToZero: 0.01,
        gossipThreshold: -4000,
        graylistThreshold: -16000,
        ipColocationThreshold: 3,
        ipColocationWeight: 0,
        opportunisticGraftThreshold: 5,
        publishThreshold: -8000,
        topicCap: 3200,
        topics: topicScores({
          firstDeliveryCap: 100,
          firstDeliveryDecay: 0.9,
          firstDeliveryWeight: 1,
          invalidDecay: 0.9,
          invalidWeight: -100,
          meshDeliveryActivationMs: 30000n,
          meshDeliveryCap: 50,
          meshDeliveryDecay: 0.9,
          meshDeliveryStartSlot: 0n,
          meshDeliveryThreshold: 5,
          meshDeliveryWeight: -1,
          meshDeliveryWindowMs: 10n,
          meshFailureDecay: 0.9,
          meshFailureWeight: -1,
          timeInMeshCap: 300,
          timeInMeshQuantumMs: 1000n,
          timeInMeshWeight: 0.03,
          weight: 1,
        }),
      },
      seenTtlMs: 384000n,
      txTimeoutMs: 30000n,
      validationTimeoutMs: 30000n,
      validationTombstoneMs: 30000n,
    },
    identitySecretKey: key,
    initialSlot: 100n,
    local: {
      metadata: {attnets: new Uint8Array(8), custodyGroupCount: 1n, sequenceNumber: 1n, syncnets: 0},
      status: {
        earliestAvailableSlot: null,
        finalizedEpoch: 0n,
        finalizedRoot: new Uint8Array(32),
        headRoot: new Uint8Array(32),
        headSlot: 100n,
      },
    },
    profile: "small",
  };
}

export function discoveryConfig(): NativeApplicationConfig & {
  discovery: NativeDiscoveryConfig & {advertisement: NonNullable<NativeDiscoveryConfig["advertisement"]>};
} {
  return {
    ...applicationConfig(),
    discovery: {
      advertisement: {ip4: Uint8Array.of(127, 0, 0, 1), udp: 40404},
      bind: {address: Uint8Array.of(127, 0, 0, 1), family: 4, port: 0},
      bootstrapEnrs: [],
      fixed: {ip4: Uint8Array.of(127, 0, 0, 1), quic: 443, udp: 40404},
      sequenceNumber: 7n,
    },
  };
}

let chainOverrides: Partial<ChainConfig> = {};

export function configuredChain() {
  return {
    ...Object.fromEntries(Object.entries(testChain).filter(([key]) => key.toUpperCase() === key)),
    ...chainOverrides,
    genesisValidatorsRoot: testChain.genesisValidatorsRoot,
  };
}

export function configureChain(overrides: Partial<ChainConfig> = {}) {
  chainOverrides = overrides;
  const chain = createBeaconConfig({...testChain, ...overrides}, testChain.genesisValidatorsRoot);
  bindings.config.set(chain, chain.genesisValidatorsRoot);
  return chain;
}

export const requestForks = testChain.forkBoundariesAscendingEpochOrder
  .filter((boundary, index, all) => boundary.epoch !== Infinity && boundary.epoch !== all[index + 1]?.epoch)
  .map((boundary) => ({digest: testChain.forkBoundary2ForkDigest(boundary), fork: boundary.fork}));

export function topicName(kind = "beacon_block", boundary = 0): string {
  return `/eth2/${Buffer.from(requestForks[boundary].digest).toString("hex")}/${kind}/ssz_snappy`;
}

export function applicationConfig(): NativeApplicationConfig {
  const config = networkConfig();
  configureChain();
  return {
    ...config,
    identify: {agentVersion: "lodestar-z/application-test", protocolVersion: "eth2/1.0.0"},
    logLevel: "info",
    resources: {
      bridgeBudgetBytes: 512 * MIB,
      connectionCapacity: 16,
      dialingCapacity: 4,
      handshakingCapacity: 8,
      maxPeers: 12,
      minOutbound: 2,
      nativeBudgetBytes: 512 * MIB,
      outboundReserve: 4,
      peerCapacity: 64,
      receiveBudgetBytes: 64 * 1024 * 1024,
      targetPeers: 8,
    },
    serveLightClients: false,
  };
}

export function localIntent(config: NativeApplicationConfig): NativeLocalIntent {
  return {
    demand: {
      attestationTarget: 1,
      attnets: new Uint8Array(8),
      custodyGroupTargets: new Uint16Array(128),
      groupTargets: new Uint16Array(128),
      syncTarget: 1,
      syncnets: 0,
    },
    subscriptions: [],
    update: {
      local: structuredClone(config.local),
    },
  };
}

/**
 * The least a host does: each notification schedules settle-only exchanges in later macrotasks while they report
 * more, and retries on a timer while payload waits for a service it disables. Peers, serving starts and gossip stay
 * with the test, which can also hold the host to take every exchange's results itself.
 */
function settlingHost(onWorkAvailable: () => void = () => undefined) {
  // Weak, so a pending retry never keeps the facade alive.
  let runtime: WeakRef<Pick<NativeNetworkApplicationRuntime, "exchange">> | undefined;
  let scheduled = false;
  let held = false;
  let timer: NodeJS.Timeout | undefined;
  const drain = () => {
    scheduled = false;
    if (held) return;
    const result = runtime?.deref()?.exchange([], settleOnly);
    if (result?.more) schedule();
    else if (result?.disabledWaiting && !timer) {
      timer = setTimeout(() => {
        timer = undefined;
        schedule();
      }, 25);
      timer.unref();
    }
  };
  const schedule = () => {
    if (scheduled) return;
    scheduled = true;
    setImmediate(drain);
  };
  return {
    attach(value: Pick<NativeNetworkApplicationRuntime, "exchange">) {
      runtime = new WeakRef(value);
    },
    hold(value: boolean) {
      held = value;
      // A notification the held host skipped leaves its work queued.
      if (!held) schedule();
    },
    onWorkAvailable() {
      schedule();
      onWorkAvailable();
    },
  };
}

const settlingHosts = new WeakMap<object, ReturnType<typeof settlingHost>>();

export function startRuntime(config: NativeApplicationConfig, onWorkAvailable: () => void = () => undefined) {
  const host = settlingHost(onWorkAvailable);
  const runtime = initializeNativeNetworkRuntime(config, host.onWorkAvailable);
  host.attach(runtime);
  settlingHosts.set(runtime, host);
  return runtime;
}

/** While held, a started runtime's settling host exchanges nothing, so the test's own exchanges take every result. */
export function holdSettling(runtime: object, held: boolean): void {
  const host = settlingHosts.get(runtime);
  if (!host) throw Error("Not a started runtime");
  host.hold(held);
}

/** Collects released runtimes until the process may initialize another one. */
export async function runtimeReleased(): Promise<void> {
  for (let i = 0; i < 200; i++) {
    global.gc?.();
    await new Promise((resolve) => setTimeout(resolve, 5));
    try {
      startRuntime({} as NativeApplicationConfig);
    } catch (error) {
      if (!(error instanceof Error) || !error.message.includes("NetworkAlreadyInitialized")) return;
    }
  }
  throw Error("A native network runtime is still live");
}

export const topicKinds: readonly NativeTopicKind[] = [
  "beacon_block",
  "beacon_aggregate_and_proof",
  "beacon_attestation",
  "proposer_slashing",
  "attester_slashing",
  "voluntary_exit",
  "sync_committee_contribution_and_proof",
  "sync_committee",
  "light_client_finality_update",
  "light_client_optimistic_update",
  "bls_to_execution_change",
  "blob_sidecar",
  "data_column_sidecar",
];

export function topicScores(params: NativeTopicScoreParams): Record<NativeTopicKind, NativeTopicScoreParams> {
  return Object.fromEntries(topicKinds.map((kind) => [kind, {...params}])) as Record<
    NativeTopicKind,
    NativeTopicScoreParams
  >;
}

export function subscriptions(...names: string[]): NativeSubscriptionSet[] {
  const sets = new Map<string, NativeSubscriptionSet>();
  for (const name of names) {
    const match = /^\/eth2\/([0-9a-f]{8})\/([a-z_]+?)(?:_(\d+))?\/ssz_snappy$/.exec(name);
    if (!match) throw Error(`Invalid fixture topic: ${name}`);
    const [, digest, type, index] = match;
    const kind = topicKinds.find((kind) => kind === type);
    if (!kind) throw Error(`Invalid fixture kind: ${type}`);
    const subnet = Number(index ?? 0);
    if (subnet >= 128) throw Error(`Invalid fixture subnet: ${subnet}`);
    let set = sets.get(digest);
    if (!set) {
      set = {digest: Uint8Array.from(Buffer.from(digest, "hex")), subnets: {}};
      sets.set(digest, set);
    }
    const prior = set.subnets[kind];
    const mask = new Uint8Array(Math.max(prior?.length ?? 0, (subnet >> 3) + 1));
    if (prior) mask.set(prior);
    mask[subnet >> 3] |= 1 << (subnet % 8);
    set.subnets[kind] = mask;
  }
  return [...sets.values()];
}

export function peerIdFromHex(hex: string): string {
  return peerIdFromPublicKey(publicKeyFromProtobuf(Buffer.from(hex, "hex").subarray(2))).toString();
}

/** A connect target that never answers, so the command stays pending until close. */
export function unreachableConnect(): [string, IpEndpoint[], bigint] {
  return [
    peerIdFromHex("00250802122102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
    [{address: Uint8Array.of(127, 0, 0, 1), family: 4, port: 9}],
    60000n,
  ];
}

/** Counts each watched operation's settlements and records its outcome; a synchronous throw is its settlement. */
export class Settlements {
  readonly counts: number[] = [];
  readonly outcomes: string[] = [];
  private readonly pending: Promise<void>[] = [];

  watch(start: () => Promise<unknown>): void {
    const index = this.counts.push(0) - 1;
    const record = (outcome: string) => {
      this.counts[index]++;
      this.outcomes[index] = outcome;
    };
    const failed = (error: unknown) => record(String((error as {code?: unknown}).code ?? error));
    try {
      this.pending.push(start().then(() => record("resolved"), failed));
    } catch (error) {
      failed(error);
    }
  }

  /** Rejects if a watched operation is still pending after `timeoutMs`. */
  async settled(timeoutMs = 10000): Promise<void> {
    let timer: NodeJS.Timeout | undefined;
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(Error(`Unsettled operations: ${this.unsettled(this.counts.length)}`)), timeoutMs);
    });
    try {
      await Promise.race([Promise.all(this.pending), deadline]);
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * The operations started before `closed` settled that are still pending once the microtasks its settlement
   * enabled have run. Call before starting any operation.
   */
  unsettledAtClose(closed: Promise<unknown>): Promise<number[]> {
    return closed.then(async () => {
      const started = this.counts.length;
      for (let i = 0; i < 8; i++) await undefined;
      return this.unsettled(started);
    });
  }

  private unsettled(started: number): number[] {
    return this.counts.slice(0, started).flatMap((count, index) => (count === 0 ? [index] : []));
  }
}
