import {execFileSync} from "node:child_process";
import {setTimeout as delay} from "node:timers/promises";
import {describe, expect, it} from "vitest";
import bindings from "../src/bindings.js";
import {createNativeNetworkRuntime} from "../src/network.js";
import {discoveryConfig, networkConfig} from "./utils/network.js";

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
    "ready_promise",
    "close_promise",
    "copy_error_ref",
    "requested_ref",
    "cancelled_ref",
    "failed_ref",
    "promise_holder",
    "spawn",
  ])("unwinds synchronous %s", async (stage) => {
    bindings.networkTestFail(stage);
    expect(() => createNativeNetworkRuntime(networkConfig(), () => undefined)).toThrow("InjectedNetworkFailure");
    await collected();
  });

  it.each(["entropy", "key", "core", "wake_attach"])("unwinds owner %s", async (stage) => {
    bindings.networkTestFail(stage);
    let runtime: ReturnType<typeof createNativeNetworkRuntime> | null = createNativeNetworkRuntime(
      networkConfig(),
      () => undefined
    );
    await expect(runtime.ready).rejects.toThrow("InjectedNetworkFailure");
    expect(await runtime.close()).toEqual({reason: "failed"});
    expect(runtime.diagnostics().terminalErrorCode).toBe("InjectedNetworkFailure");
    runtime = null;
    await collected();
  });

  it("unwinds an ENR acquisition with a canonical signed bootstrap", async () => {
    let source: ReturnType<typeof createNativeNetworkRuntime> | null = createNativeNetworkRuntime(
      discoveryConfig(),
      () => undefined
    );
    const enr = (await source.ready).localEnr;
    expect(enr).toBeInstanceOf(Uint8Array);
    if (!enr) throw new Error("Missing signed ENR");
    await source.close();
    source = null;
    await collected();
    const config = discoveryConfig();
    if (!config.discovery) throw new Error("Missing discovery config");
    config.discovery.bootstrapEnrs = [enr];
    bindings.networkTestFail("enr");
    let runtime: ReturnType<typeof createNativeNetworkRuntime> | null = createNativeNetworkRuntime(
      config,
      () => undefined
    );
    await expect(runtime.ready).rejects.toThrow("InjectedNetworkFailure");
    expect(await runtime.close()).toEqual({reason: "failed"});
    expect(runtime.diagnostics().terminalErrorCode).toBe("InjectedNetworkFailure");
    runtime = null;
    await collected();
  });

  it.each(["startup_copy", "identity_copy"])("settles ready and closes after %s", async (stage) => {
    bindings.networkTestFail(stage);
    let runtime: ReturnType<typeof createNativeNetworkRuntime> | null = createNativeNetworkRuntime(
      networkConfig(),
      () => undefined
    );
    await expect(runtime.ready).rejects.toThrow("InjectedNetworkFailure");
    expect(await runtime.close()).toEqual({reason: "failed"});
    runtime = null;
    await collected();
  });

  it("retries a terminal scalar copy once after physical join", async () => {
    let runtime: ReturnType<typeof createNativeNetworkRuntime> | null = createNativeNetworkRuntime(
      networkConfig(),
      () => undefined
    );
    await runtime.ready;
    bindings.networkTestFail("close_copy");
    expect(await runtime.close()).toEqual({reason: "requested"});
    runtime = null;
    await collected();
  });

  it("keeps spawned instance credits until stopped owners are joined", async () => {
    const runtimes = Array.from({length: 4}, () => createNativeNetworkRuntime(networkConfig(), () => undefined));
    const readiness = runtimes.map((runtime) => runtime.ready.catch((error: Error) => error.message));
    const closing = runtimes.map((runtime) => runtime.close());
    try {
      const wait = new Int32Array(new SharedArrayBuffer(4));
      for (let i = 0; i < 500 && bindings.networkTestStats().owners !== 0; i++) Atomics.wait(wait, 0, 0, 10);
      expect(bindings.networkTestStats().owners).toBe(0);
      expect(() => createNativeNetworkRuntime(networkConfig(), () => undefined)).toThrow("NetworkInstanceLimit");
    } finally {
      await Promise.all(readiness);
      await Promise.all(closing);
    }
    const replacement = createNativeNetworkRuntime(networkConfig(), () => undefined);
    await replacement.ready;
    await replacement.close();
  });

  it.each(["entry", "key_ready", "before_ready"])("cancels a held actual owner at %s", async (stage) => {
    bindings.networkTestScenario(stage);
    let runtime: ReturnType<typeof createNativeNetworkRuntime> | null = createNativeNetworkRuntime(
      networkConfig(),
      () => undefined
    );
    let settlements = 0;
    const ready = runtime.ready.then(
      () => {
        settlements++;
        return "ready";
      },
      (error: Error) => {
        settlements++;
        return error.message;
      }
    );
    try {
      for (let i = 0; i < 500 && bindings.networkTestStage() !== stage; i++) await delay(10);
      expect(bindings.networkTestStage()).toBe(stage);
      expect(runtime.state).toBe("starting");
      const closing = runtime.close();
      expect(runtime.close()).toBe(closing);
      expect(await ready).toBe("AbortError");
      expect(await closing).toEqual({reason: "startupCancelled"});
      expect(settlements).toBe(1);
      expect(runtime.state).toBe("closed");
    } finally {
      await runtime.close();
      runtime = null;
      await collected();
    }
  });

  it("preserves a committed wake failure when held startup is cancelled", async () => {
    bindings.networkTestScenario("before_ready");
    let runtime: ReturnType<typeof createNativeNetworkRuntime> | null = createNativeNetworkRuntime(
      networkConfig(),
      () => undefined
    );
    const ready = runtime.ready.catch((error: Error) => error.message);
    try {
      for (let i = 0; i < 500 && bindings.networkTestStage() !== "before_ready"; i++) await delay(10);
      expect(bindings.networkTestStage()).toBe("before_ready");
      bindings.networkTestFail("wake_signal");
      const closing = runtime.close();
      expect(await ready).toBe("NetworkWakeFailed");
      expect(await closing).toEqual({reason: "failed"});
      expect(runtime.diagnostics()).toMatchObject({state: "failed", terminalErrorCode: "NetworkWakeFailed"});
    } finally {
      await runtime.close();
      runtime = null;
      await collected();
    }
  });

  it.each([false, true])("settles lifecycle with saturated observations, drain=%s", async (drain) => {
    bindings.networkTestScenario("observations");
    let notifications = 0;
    let runtime: ReturnType<typeof createNativeNetworkRuntime> | null = createNativeNetworkRuntime(
      networkConfig(),
      () => {
        notifications++;
      }
    );
    try {
      const identity = await runtime.ready;
      const saturated = runtime.diagnostics();
      expect(saturated).toMatchObject({
        observationsDropped: 3n,
        queueCapacity: 64,
        queueHighWater: 64,
        queuedEvents: 64,
      });
      await delay(200);
      expect(notifications).toBe(1);
      expect(runtime.diagnostics().bridgeRequestedBytes).toBe(saturated.bridgeRequestedBytes);
      expect(runtime.diagnostics().ownerTurns).toBeGreaterThan(saturated.ownerTurns);
      if (drain) {
        bindings.networkTestFail("drain_copy");
        expect(() => runtime?.drain(1)).toThrow("InjectedNetworkFailure");
        expect(runtime.diagnostics().queuedEvents).toBe(64);
        const first = runtime.drain(1);
        const events = [...first.events, ...runtime.drain(32).events, ...runtime.drain(32).events];
        expect(first.more).toBe(true);
        expect(events).toHaveLength(65);
        for (let i = 0; i < 64; i++) {
          expect(events[i]).toEqual({
            peerGeneration: (1n << 64n) - 1n - BigInt(i),
            peerId: identity.peerId,
            peerIndex: i,
            type: "peerReady",
          });
        }
        expect(events[64]).toEqual({code: "InjectedNetworkFailure", count: 2n, type: "operationalError"});
        expect(runtime.drain(32)).toEqual({dropped: 3n, events: [], more: false});
      }
      const closing = runtime.close();
      expect(runtime.close()).toBe(closing);
      expect(runtime.close()).toBe(closing);
      expect(await closing).toEqual({reason: "requested"});
      await delay(50);
      expect(notifications).toBe(1);
    } finally {
      await runtime.close();
      runtime = null;
      await collected();
    }
  });

  it("notifies retained owner publication after drain snapshots no more work", async () => {
    bindings.networkTestScenario("drain_publish");
    let notifications = 0;
    let runtime: ReturnType<typeof createNativeNetworkRuntime> | null = createNativeNetworkRuntime(
      networkConfig(),
      () => {
        notifications++;
      }
    );
    try {
      const identity = await runtime.ready;
      expect(notifications).toBe(1);
      const first = runtime.drain(32);
      expect(first).toEqual({
        dropped: 0n,
        events: [{peerGeneration: 1n, peerId: identity.peerId, peerIndex: 0, type: "peerReady"}],
        more: false,
      });
      expect(runtime.diagnostics().queuedEvents).toBe(1);
      for (let i = 0; i < 100 && notifications < 2; i++) await delay(10);
      expect(notifications).toBe(2);
      await delay(100);
      expect(notifications).toBe(2);
      expect(runtime.drain(32)).toEqual({
        dropped: 0n,
        events: [{peerGeneration: 1n, peerId: identity.peerId, peerIndex: 0, type: "peerUpdated"}],
        more: false,
      });
      expect(runtime.diagnostics().queuedEvents).toBe(0);
    } finally {
      await runtime.close();
      runtime = null;
      await collected();
    }
  });

  it("keeps queued records and closes after an ordinary callback exception", () => {
    const output = execFileSync(
      process.execPath,
      [
        "--expose-gc",
        "--force-node-api-uncaught-exceptions-policy",
        "bindings/test/fixtures/network-lifecycle.mjs",
        "callback",
      ],
      {encoding: "utf8", timeout: 10000}
    );
    expect(output).toContain("callback-closed");
  });

  it("forwards every immutable gossip policy into the actual resolved owner", async () => {
    const config = networkConfig();
    config.gossipPolicy = {
      gossipFactor: 0.3,
      heartbeatIntervalMs: 1100n,
      ipAllowlist: [Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1)],
      largeFrameTimeoutMs: 35000n,
      opportunisticGraftIntervalMs: 61000n,
      phase0Digest: Uint8Array.of(9, 8, 7, 6),
      pressureTimeoutMs: 33000n,
      retainedScoreMs: 19200000n,
      score: {
        appWeight: 2,
        behaviourDecay: 0.8,
        behaviourThreshold: 7,
        behaviourWeight: -11,
        decayIntervalMs: 6000n,
        decayToZero: 0.02,
        defaultTopic: {
          firstDeliveryCap: 101,
          firstDeliveryDecay: 0.8,
          firstDeliveryWeight: 2,
          invalidDecay: 0.8,
          invalidWeight: -101,
          meshDeliveryActivationMs: 31000n,
          meshDeliveryCap: 51,
          meshDeliveryDecay: 0.8,
          meshDeliveryThreshold: 6,
          meshDeliveryWeight: -2,
          meshDeliveryWindowMs: 11n,
          meshFailureDecay: 0.8,
          meshFailureWeight: -2,
          timeInMeshCap: 301,
          timeInMeshQuantumMs: 900n,
          timeInMeshWeight: 0.04,
          weight: 2,
        },
        gossipThreshold: -4001,
        graylistThreshold: -16001,
        ipColocationThreshold: 4,
        ipColocationWeight: -2,
        opportunisticGraftThreshold: 6,
        publishThreshold: -8001,
        topicCap: 3300,
      },
      seenTtlMs: 192000n,
      txTimeoutMs: 34000n,
      validationTimeoutMs: 31000n,
      validationTombstoneMs: 32000n,
    };
    bindings.networkTestScenario("gossip");
    const runtime = createNativeNetworkRuntime(config, () => undefined);
    config.gossipPolicy.phase0Digest?.fill(0);
    config.gossipPolicy.ipAllowlist[0].fill(0);
    config.gossipPolicy.score.decayIntervalMs = 12000n;
    try {
      await runtime.ready;
      // biome-ignore-start lint/style/useNamingConvention: The copied snapshot preserves native names to verify JS-to-native field mapping.
      expect(bindings.networkTestGossip()).toMatchObject({
        ipAllowlist: [Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1)],
        options: {
          connected_capacity: 12,
          gossip_factor: 0.3,
          heartbeat_interval_ms: 1100n,
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
        phase0Digest: Uint8Array.of(9, 8, 7, 6),
        score: {
          app_weight: 2,
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
});
