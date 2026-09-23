import {execFileSync} from "node:child_process";
import {setTimeout as delay} from "node:timers/promises";
import {describe, expect, it} from "vitest";
import {
  applicationConfig,
  configureChain,
  discoveryConfig,
  requestForks,
  startRuntime,
  topicScores,
} from "./utils/network.js";
import {networkBindings as bindings} from "./utils/network-bindings.js";
import {startPeer} from "./utils/network-peer.js";

async function collected() {
  for (let i = 0; i < 100; i++) {
    await delay(10);
    global.gc?.();
    const stats = bindings.networkTestStats();
    if (stats.runtimes === 0 && stats.notifications === 0 && stats.owners === 0) return;
  }
  expect(bindings.networkTestStats()).toEqual({notifications: 0, owners: 0, runtimes: 0});
}

describe.skipIf(process.env.LODESTAR_Z_NETWORK_TEST_FAILURES !== "1")("test-build resource failure prefixes", () => {
  it.each([
    "runtime_alloc",
    "wake",
    "notify",
    "hook",
    "close_promise",
    "copy_error_ref",
    "requested_ref",
    "failed_ref",
    "promise_holder",
    "spawn",
  ])("unwinds synchronous %s", async (stage) => {
    bindings.networkTestFail(stage);
    expect(() => startRuntime(applicationConfig(), () => undefined)).toThrow("InjectedNetworkFailure");
    await collected();
  });

  it.each(["entropy", "key", "core", "wake_attach"])("unwinds owner %s", async (stage) => {
    bindings.networkTestFail(stage);
    expect(() => startRuntime(applicationConfig(), () => undefined)).toThrow("InjectedNetworkFailure");
    await collected();
  });

  it("unwinds an ENR acquisition with a canonical signed bootstrap", async () => {
    const source = await startPeer(discoveryConfig());
    const enr = (await source.identity).localEnr;
    expect(enr).toBeInstanceOf(Uint8Array);
    if (!enr) throw new Error("Missing signed ENR");
    await source.close();
    await collected();
    const config = discoveryConfig();
    if (!config.discovery) throw new Error("Missing discovery config");
    config.discovery.bootstrapEnrs = [enr];
    bindings.networkTestFail("enr");
    expect(() => startRuntime(config, () => undefined)).toThrow("InjectedNetworkFailure");
    await collected();
  });

  it("unwinds identity projection before exposing the runtime", async () => {
    bindings.networkTestFail("identity_copy");
    expect(() => startRuntime(applicationConfig())).toThrow("InjectedNetworkFailure");
    await collected();
  });

  it("settles close from its startup result after physical join", async () => {
    let runtime: ReturnType<typeof startRuntime> | null = startRuntime(applicationConfig(), () => undefined);
    await runtime.identity;
    expect(await runtime.close()).toEqual({reason: "requested"});
    runtime = null;
    await collected();
  });

  it("a command result allocation failure leaves later commands usable", async () => {
    const runtime = startRuntime(applicationConfig());
    try {
      bindings.networkTestFail("operation_copy");
      await expect(runtime.getIdentity()).rejects.toMatchObject({code: "NetworkResultAllocationFailed"});
      expect(runtime.state).toBe("running");
      await expect(runtime.getIdentity()).resolves.toMatchObject({peerId: runtime.identity.peerId});
      expect(runtime.diagnostics()).toMatchObject({copyingPins: 0, operationOccupied: 0});
    } finally {
      await runtime.close();
    }
  });

  it("does not reopen initialization after failure", async () => {
    bindings.networkTestFail("spawn");
    expect(() => startRuntime(applicationConfig())).toThrow("InjectedNetworkFailure");
    await collected();
    expect(() => startRuntime(applicationConfig())).toThrow("NetworkAlreadyInitialized");
  });

  it("joins a running owner after its close wake signal fails", async () => {
    const runtime = startRuntime(applicationConfig(), () => undefined);
    await runtime.identity;
    expect(runtime.state).toBe("running");
    bindings.networkTestFail("wake_signal");
    expect(await runtime.close()).toEqual({reason: "failed"});
    expect(runtime.diagnostics()).toMatchObject({state: "failed", terminalErrorCode: "NetworkWakeFailed"});
  });

  it("keeps queued records and closes after an ordinary callback exception", () => {
    const output = execFileSync(
      process.execPath,
      [
        "--import",
        "tsx",
        "--expose-gc",
        "--force-node-api-uncaught-exceptions-policy",
        "bindings/test/fixtures/network-lifecycle.mjs",
        "callback",
      ],
      {encoding: "utf8", timeout: 10000}
    );
    expect(output).toContain("callback-closed");
  });

  it.each([
    16829, 1462,
  ])("forwards immutable gossip policy with host threshold %i into the actual resolved owner", async (idontwantMinDataSize) => {
    const config = applicationConfig();
    config.gossipPolicy = {
      gossipFactor: 0.3,
      heartbeatIntervalMs: 1100n,
      idontwantMinDataSize,
      ipAllowlist: [Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1)],
      iwantFollowupMs: 12000n,
      largeFrameTimeoutMs: 35000n,
      opportunisticGraftIntervalMs: 61000n,
      pressureTimeoutMs: 33000n,
      retainedScoreMs: 19200000n,
      score: {
        behaviourDecay: 0.8,
        behaviourThreshold: 7,
        behaviourWeight: -11,
        decayIntervalMs: 6000n,
        decayToZero: 0.02,
        gossipThreshold: -4001,
        graylistThreshold: -16001,
        ipColocationThreshold: 4,
        ipColocationWeight: -2,
        opportunisticGraftThreshold: 6,
        publishThreshold: -8001,
        topicCap: 3300,
        topics: topicScores({
          firstDeliveryCap: 101,
          firstDeliveryDecay: 0.8,
          firstDeliveryWeight: 2,
          invalidDecay: 0.8,
          invalidWeight: -101,
          meshDeliveryActivationMs: 31000n,
          meshDeliveryCap: 51,
          meshDeliveryDecay: 0.8,
          meshDeliveryStartSlot: 0n,
          meshDeliveryThreshold: 6,
          meshDeliveryWeight: -2,
          meshDeliveryWindowMs: 11n,
          meshFailureDecay: 0.8,
          meshFailureWeight: -2,
          timeInMeshCap: 301,
          timeInMeshQuantumMs: 900n,
          timeInMeshWeight: 0.04,
          weight: 2,
        }),
      },
      seenTtlMs: 192000n,
      txTimeoutMs: 34000n,
      validationTimeoutMs: 31000n,
      validationTombstoneMs: 32000n,
    };
    bindings.networkTestScenario("gossip");
    const runtime = startRuntime(config, () => undefined);
    config.gossipPolicy.ipAllowlist[0].fill(0);
    config.gossipPolicy.score.decayIntervalMs = 12000n;
    config.gossipPolicy.iwantFollowupMs = 1n;
    config.gossipPolicy.idontwantMinDataSize = 0;
    try {
      await runtime.identity;
      // biome-ignore-start lint/style/useNamingConvention: The copied snapshot preserves native names to verify JS-to-native field mapping.
      expect(bindings.networkTestGossip()).toMatchObject({
        ipAllowlist: [Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1)],
        options: {
          connected_capacity: 12,
          gossip_factor: 0.3,
          heartbeat_interval_ms: 1100n,
          idontwant_min_data_size: idontwantMinDataSize,
          iwant_followup_ms: 12000n,
          large_frame_timeout_ms: 35000n,
          mcache_capacity: 256,
          opportunistic_graft_interval_ms: 61000n,
          pressure_timeout_ms: 33000n,
          retained_score_ms: 19200000n,
          seen_capacity: 4096,
          seen_ttl_ms: 192000n,
          tx_timeout_ms: 34000n,
          validation_timeout_ms: 31000n,
          validation_tombstone_ms: 32000n,
        },
        score: {
          behaviour_decay: 0.8,
          behaviour_threshold: 7,
          behaviour_weight: -11,
          decay_interval_ms: 6000n,
          decay_to_zero: 0.02,
          gossip_threshold: -4001,
          graylist_threshold: -16001,
          ip_colocation_threshold: 4,
          ip_colocation_weight: -2,
          opportunistic_graft_threshold: 6,
          publish_threshold: -8001,
          topic_cap: 3300,
        },
        topic: {
          first_delivery_cap: 101,
          first_delivery_decay: 0.8,
          first_delivery_weight: 2,
          invalid_decay: 0.8,
          invalid_weight: -101,
          mesh_delivery_activation_ms: 31000n,
          mesh_delivery_cap: 51,
          mesh_delivery_decay: 0.8,
          mesh_delivery_threshold: 6,
          mesh_delivery_weight: -2,
          mesh_delivery_window_ms: 11n,
          mesh_failure_decay: 0.8,
          mesh_failure_weight: -2,
          time_in_mesh_cap: 301,
          time_in_mesh_quantum_ms: 900n,
          time_in_mesh_weight: 0.04,
          weight: 2,
        },
      });
      // biome-ignore-end lint/style/useNamingConvention: Native snapshot field mapping ends here.
    } finally {
      await runtime.close();
    }
  });
  it("derives the chain sampling minimum into the actual local context", async () => {
    const config = applicationConfig();
    configureChain({ELECTRA_FORK_EPOCH: 0, FULU_FORK_EPOCH: 0, SAMPLES_PER_SLOT: 8});
    config.local.status.earliestAvailableSlot = 0n;
    bindings.networkTestScenario("gossip");
    const runtime = startRuntime(config, () => undefined);
    configureChain();
    try {
      await runtime.identity;
      expect(bindings.networkTestGossip()).toMatchObject({minimumSamplingGroups: 8});
    } finally {
      await runtime.close();
    }
  });
  it("forwards immutable topic namespace into the actual native owner", async () => {
    const config = applicationConfig();
    bindings.networkTestScenario("gossip");
    const runtime = startRuntime(config, () => undefined);
    configureChain({ELECTRA_FORK_EPOCH: 0});
    try {
      await runtime.identity;
      const snapshot = bindings.networkTestGossip();
      expect(snapshot).toMatchObject({
        topicPolicy: expect.arrayContaining([{digest: requestForks[0].digest, rules: expect.any(Array)}]),
      });
    } finally {
      await runtime.close();
    }
  });
});
