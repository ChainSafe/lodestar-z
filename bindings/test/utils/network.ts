import {testChain} from "../../../test/interop/network_chain.mjs";
import {initializeNativeNetworkRuntime} from "../../src/network.js";
export {testChain};

import {type ChainConfig, createBeaconConfig} from "@lodestar/config";
import bindings from "../../src/index.js";
import type {
  NativeApplicationConfig,
  NativeDiscoveryConfig,
  NativeLocalIntent,
  NativeRuntimeConfig,
} from "../../src/network.js";

export function networkConfig(): NativeRuntimeConfig {
  const key = new Uint8Array(32);
  key[31] = 1;
  return {
    bind: {address: Uint8Array.of(127, 0, 0, 1), family: 4, port: 0},
    discovery: null,
    gossipPolicy: {
      gossipFactor: 0.25,
      heartbeatIntervalMs: 1000n,
      idontwantMinDataSize: 16829,
      ipAllowlist: [],
      iwantFollowupMs: 12000n,
      largeFrameTimeoutMs: 30000n,
      opportunisticGraftIntervalMs: 60000n,
      pressureTimeoutMs: 30000n,
      retainedScoreMs: 38400000n,
      score: {
        appWeight: 1,
        behaviourDecay: 0.9,
        behaviourThreshold: 6,
        behaviourWeight: -10,
        decayIntervalMs: 12000n,
        decayToZero: 0.01,
        defaultTopic: {
          firstDeliveryCap: 100,
          firstDeliveryDecay: 0.9,
          firstDeliveryWeight: 1,
          invalidDecay: 0.9,
          invalidWeight: -100,
          meshDeliveryActivationMs: 30000n,
          meshDeliveryCap: 50,
          meshDeliveryDecay: 0.9,
          meshDeliveryThreshold: 5,
          meshDeliveryWeight: -1,
          meshDeliveryWindowMs: 10n,
          meshFailureDecay: 0.9,
          meshFailureWeight: -1,
          timeInMeshCap: 300,
          timeInMeshQuantumMs: 1000n,
          timeInMeshWeight: 0.03,
          weight: 1,
        },
        gossipThreshold: -4000,
        graylistThreshold: -16000,
        ipColocationThreshold: 3,
        ipColocationWeight: 0,
        opportunisticGraftThreshold: 5,
        publishThreshold: -8000,
        topicCap: 3200,
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
      advertisement: {ip4: Uint8Array.of(127, 0, 0, 1), quic: 443, udp: 40404},
      bind: {address: Uint8Array.of(127, 0, 0, 1), family: 4, port: 0},
      bootstrapEnrs: [],
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
    resources: {
      bridgeBudgetBytes: 32 * 1024 * 1024,
      connectionCapacity: 16,
      dialingCapacity: 4,
      handshakingCapacity: 8,
      maxPeers: 12,
      minOutbound: 2,
      nativeBudgetBytes: 96 * 1024 * 1024,
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
      custodyGroupTargets: Array<number>(128).fill(0),
      expiresAtSlot: config.initialSlot + 100n,
      groupTargets: Array<number>(128).fill(0),
      syncTarget: 1,
      syncnets: 0,
    },
    subscriptions: [],
    update: {
      endpoints: config.discovery?.advertisement ?? null,
      local: structuredClone(config.local),
    },
  };
}

export function startRuntime(config: NativeApplicationConfig, onWorkAvailable: () => void = () => undefined) {
  return initializeNativeNetworkRuntime(config, onWorkAvailable);
}
