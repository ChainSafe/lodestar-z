import type {NativeDiscoveryConfig, NativeRuntimeConfig, NativeTopicBoundary} from "../../src/network.js";

export function networkConfig(): NativeRuntimeConfig {
  const digest = Uint8Array.of(1, 2, 3, 4);
  const key = new Uint8Array(32);
  key[31] = 1;
  return {
    bind: {address: Uint8Array.of(127, 0, 0, 1), family: 4, port: 0},
    discovery: null,
    forkSchedule: {
      fuluScheduled: false,
      nextDigest: new Uint8Array(4),
      nextEpoch: 18446744073709551615n,
      nextVersion: new Uint8Array(4),
    },
    gossipPolicy: {
      gossipFactor: 0.25,
      heartbeatIntervalMs: 1000n,
      idontwantMinDataSize: 16829,
      ipAllowlist: [],
      iwantFollowupMs: 12000n,
      largeFrameTimeoutMs: 30000n,
      opportunisticGraftIntervalMs: 60000n,
      phase0Digest: null,
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
      fork: {custodyGroups: 1, digest: digest.slice(), fork: "deneb", minimumSamplingGroups: 0},
      metadata: {attnets: new Uint8Array(8), custodyGroupCount: null, sequenceNumber: 1n, syncnets: 0},
      status: {
        earliestAvailableSlot: null,
        finalizedEpoch: 0n,
        finalizedRoot: new Uint8Array(32),
        forkDigest: digest.slice(),
        headRoot: new Uint8Array(32),
        headSlot: 100n,
      },
    },
    profile: "small",
    requestForks: [{digest: digest.slice(), fork: "deneb"}],
    topicPolicy: null,
  };
}

export function discoveryConfig(): NativeRuntimeConfig & {discovery: NativeDiscoveryConfig} {
  return {
    ...networkConfig(),
    discovery: {
      advertisement: {ip4: Uint8Array.of(127, 0, 0, 1), quic: 443, udp: 40404},
      bind: {address: Uint8Array.of(127, 0, 0, 1), family: 4, port: 0},
      bootstrapEnrs: [],
      sequenceNumber: 7n,
    },
  };
}

export function topicBoundary(): NativeTopicBoundary {
  const disabled = () => ({count: 0, sszMax: 0, sszMin: 0});
  return {
    digest: Uint8Array.of(1, 2, 3, 4),
    // biome-ignore-start lint/style/useNamingConvention: The namespace uses canonical protocol kind names.
    rules: {
      attester_slashing: disabled(),
      beacon_aggregate_and_proof: disabled(),
      beacon_attestation: {count: 64, sszMax: 131304, sszMin: 228},
      beacon_block: {count: 1, sszMax: 20, sszMin: 10},
      blob_sidecar: disabled(),
      bls_to_execution_change: disabled(),
      data_column_sidecar: disabled(),
      light_client_finality_update: disabled(),
      light_client_optimistic_update: disabled(),
      proposer_slashing: disabled(),
      sync_committee: disabled(),
      sync_committee_contribution_and_proof: disabled(),
      voluntary_exit: disabled(),
    },
    // biome-ignore-end lint/style/useNamingConvention: Canonical protocol names end here.
  };
}
