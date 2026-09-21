import {execFileSync} from "node:child_process";
import {createSocket} from "node:dgram";
import {once} from "node:events";
import {setTimeout as delay} from "node:timers/promises";
import {privateKeyFromRaw} from "@libp2p/crypto/keys";
import {expect, test} from "vitest";
import type {NativeNetworkApplicationRuntime, NativePeerObservation} from "../src/network.js";
import {
  applicationConfig,
  configureChain,
  discoveryConfig,
  localIntent,
  startRuntime,
  subscriptions,
  testChain,
  topicName,
} from "./utils/network.js";
import {networkBindings as bindings} from "./utils/network-bindings.js";
import {startPeer} from "./utils/network-peer.js";

test("running application advances fork state only when the host updates intent", async () => {
  const config = applicationConfig();
  const boundarySlot = 128n;
  const slotsPerEpoch = process.env.LODESTAR_PRESET === "minimal" ? 8n : 32n;
  config.initialSlot = boundarySlot - 1n;
  config.local.status.headSlot = config.initialSlot;
  config.discovery = discoveryConfig().discovery;
  configureChain({ELECTRA_FORK_EPOCH: Number(boundarySlot / slotsPerEpoch)});
  const runtime = startRuntime(config, () => undefined);
  try {
    const identity = await runtime.identity;
    let hostSlot = config.initialSlot;
    expect(hostSlot).toBeLessThan(boundarySlot);
    await delay(40);
    hostSlot = boundarySlot;
    const slot = hostSlot;
    expect(slot).toBeGreaterThanOrEqual(boundarySlot);
    expect(runtime.state).toBe("running");
    expect(runtime.diagnostics().currentSlot).toBe(config.initialSlot);
    const fresh = localIntent(config);
    const result = await runtime.applyIntent(fresh, slot);
    expect(result).toMatchObject({changed: true, slot});
    expect(runtime.state).toBe("running");
    expect(runtime.diagnostics().currentSlot).toBe(slot);
    expect((await runtime.getIdentity()).localEnr).not.toEqual(identity.localEnr);
    expect((await runtime.applyIntent(fresh, slot)).changed).toBe(false);
  } finally {
    await runtime.close();
  }
});

test("owned chain plan follows Fulu and BPO with Lodestar topics and fixed native storage", async () => {
  const config = discoveryConfig();
  const runtime = startRuntime(config, () => undefined);
  try {
    let identity = await runtime.identity;
    const before = runtime.diagnostics();
    configureChain({BLOB_SCHEDULE: [], ELECTRA_FORK_EPOCH: Infinity, FULU_FORK_EPOCH: Infinity});
    const epochs = [testChain.FULU_FORK_EPOCH, testChain.BLOB_SCHEDULE[0].EPOCH];
    for (const [i, epoch] of epochs.entries()) {
      const slot = BigInt(epoch * (process.env.LODESTAR_PRESET === "minimal" ? 8 : 32));
      const intent = localIntent(config);
      intent.update.local.status.headSlot = 1n;
      intent.update.local.status.earliestAvailableSlot = 0n;
      intent.update.local.metadata.custodyGroupCount = 8n;
      intent.subscriptions = subscriptions(topicName("beacon_block", i + 2), topicName("data_column_sidecar_0", i + 2));
      await runtime.applyIntent(intent, slot);
      const current = await runtime.getIdentity();
      expect(current.localEnr).not.toEqual(identity.localEnr);
      expect(runtime.diagnostics()).toMatchObject({
        currentSlot: slot,
        liveNativeRequestedBytes: before.liveNativeRequestedBytes,
        nativeAllocationCount: before.nativeAllocationCount,
      });
      identity = current;
    }
  } finally {
    await runtime.close();
  }
});

test("failed intent leaves running state and clock unchanged", async () => {
  const config = applicationConfig();
  const runtime = startRuntime(config, () => undefined);
  const terminal = runtime.closed;
  try {
    await runtime.identity;
    expect((await runtime.getPeers()).peers).toEqual([]);
    await runtime.updateStatus(config.local.status);
    const intent = localIntent(config);
    intent.subscriptions = [{digest: new Uint8Array(4).fill(255), subnets: {}}];
    await expect(runtime.applyIntent(intent, 101n)).rejects.toThrow();
    expect(runtime.state).toBe("running");
    expect(runtime.diagnostics().currentSlot).toBe(100n);
    const first = await runtime.applyIntent(localIntent(config), 102n);
    expect(first.slot).toBe(102n);
    const next = await runtime.applyIntent(localIntent(config), 103n);
    expect(next.changed).toBe(false);
    expect(next.ownerSequence).toBeGreaterThan(first.ownerSequence);
    await expect(runtime.applyIntent(localIntent(config), 101n)).rejects.toThrow("ClockRegression");
    expect(runtime.diagnostics().currentSlot).toBe(103n);
    expect("setCurrentSlot" in runtime).toBe(false);
  } finally {
    expect(runtime.close()).toBe(terminal);
    await expect(terminal).resolves.toEqual({reason: "requested"});
  }
});

test("Status-only updates copy inputs and preserve advertisement and subscriptions across a head regression", async () => {
  const config = discoveryConfig();
  config.discovery.sequenceNumber = 18446744073709551615n;
  config.local.metadata.sequenceNumber = 18446744073709551615n;
  const other = applicationConfig();
  other.identitySecretKey[31] = 2;
  const a = startRuntime(config, () => undefined);
  const b = await startPeer(other);
  try {
    const [identity] = await Promise.all([a.identity, b.identity]);
    const intent = localIntent(config);
    intent.subscriptions = subscriptions(topicName());
    intent.demand.attnets[0] = 5;
    await Promise.all([a.applyIntent(intent, 100n), b.applyIntent(localIntent(other), 100n)]);
    const topics = (await a.getGossipDiagnostics()).topics;
    const status = structuredClone(config.local.status);
    status.headSlot = 95n;
    status.headRoot.fill(7);
    const updated = a.updateStatus(status);
    status.headRoot.fill(9);
    await updated;
    await b.connect(identity.peerId, [identity.localEndpoint], 5000n);
    for (const headSlot of [95n, 90n]) {
      if (headSlot === 90n) {
        await a.updateStatus({...config.local.status, headRoot: new Uint8Array(32).fill(7), headSlot});
        await b.reStatusPeers([identity.peerId]);
      }
      let observed: Awaited<ReturnType<typeof b.getPeers>>["peers"][number]["status"] = null;
      for (let i = 0; i < 200; i++) {
        observed =
          (await b.getPeers()).peers.find((peer) => peer.identity.every((byte, j) => byte === identity.peerId[j]))
            ?.status ?? null;
        if (observed?.headSlot === headSlot) break;
        await delay(10);
      }
      expect(observed?.headSlot).toBe(headSlot);
      expect(observed?.headRoot).toEqual(new Uint8Array(32).fill(7));
      expect(a.diagnostics().currentSlot).toBe(100n);
      expect((await a.getGossipDiagnostics()).topics).toEqual(topics);
      const current = await a.getIdentity();
      expect(current.metadata).toEqual(identity.metadata);
      expect(current.localEnr).toEqual(identity.localEnr);
    }
  } finally {
    await Promise.all([a.close(), b.close()]);
  }
}, 15000);

test("Status-only validation uses the active fork and leaves rejected updates unpublished", async () => {
  const config = applicationConfig();
  configureChain({ELECTRA_FORK_EPOCH: 0, FULU_FORK_EPOCH: 0});
  config.local.status.earliestAvailableSlot = 0n;
  const runtime = startRuntime(config, () => undefined);
  try {
    await runtime.identity;
    const intent = localIntent(config);
    await runtime.applyIntent(intent, 100n);
    for (const [field, value] of [
      ["headSlot", -1n],
      ["headSlot", 1n << 64n],
      ["headSlot", 100],
      ["headRoot", new Uint8Array(31)],
      ["forkDigest", new Uint8Array(5)],
      ["extra", true],
    ] as const) {
      const invalid = structuredClone(config.local.status);
      Reflect.set(invalid, field, value);
      expect(() => runtime.updateStatus(invalid)).toThrow();
    }
    await expect(runtime.updateStatus({...config.local.status, earliestAvailableSlot: null})).rejects.toThrow(
      "MissingAvailability"
    );
    expect((await runtime.applyIntent(intent, 100n)).changed).toBe(false);
    const first = runtime.updateStatus({...config.local.status, headSlot: 120n});
    const second = structuredClone(intent);
    second.update.local.status.headSlot = 80n;
    const coordinated = runtime.applyIntent(second, 100n);
    const last = runtime.updateStatus({...config.local.status, headSlot: 90n});
    await Promise.all([first, coordinated, last]);
    second.update.local.status.headSlot = 90n;
    expect((await runtime.applyIntent(second, 100n)).changed).toBe(false);
    expect(runtime.diagnostics().currentSlot).toBe(100n);
  } finally {
    await runtime.close();
  }
});

test("reentrant close during Status copying retires its command without publication", async () => {
  const config = applicationConfig();
  const runtime = startRuntime(config, () => undefined);
  await runtime.identity;
  await runtime.applyIntent(localIntent(config), 100n);
  const status = structuredClone(config.local.status);
  Object.defineProperty(status, "headRoot", {
    enumerable: true,
    get() {
      runtime.close();
      return config.local.status.headRoot;
    },
  });
  expect(() => runtime.updateStatus(status)).toThrow("NetworkClosed");
  await runtime.closed;
  expect(runtime.diagnostics().operationOccupied).toBe(0);
  expect(runtime.diagnostics().currentSlot).toBe(100n);
});

test("identity metadata belongs to its owner snapshot across queued intent updates", async () => {
  const config = applicationConfig();
  const runtime = startRuntime(config, () => undefined);
  try {
    const ready = await runtime.identity;
    expect(ready.metadata).toEqual(config.local.metadata);
    const first = localIntent(config);
    first.update.local.metadata.sequenceNumber = ready.metadata.sequenceNumber + 1n;
    first.update.local.metadata.attnets[0] = 1;
    const second = structuredClone(first);
    second.update.local.metadata.sequenceNumber = ready.metadata.sequenceNumber + 2n;
    second.update.local.metadata.attnets[0] = 2;
    const operations = [
      runtime.applyIntent(first, 100n),
      runtime.getIdentity(),
      runtime.applyIntent(second, 100n),
      runtime.getIdentity(),
    ] as const;
    const [appliedFirst, identityFirst, appliedSecond, identitySecond] = await Promise.all(operations);
    expect(identityFirst.metadata).toEqual(first.update.local.metadata);
    expect(identitySecond.metadata).toEqual(second.update.local.metadata);
    expect(identityFirst.ownerSequence).toBeGreaterThan(appliedFirst.ownerSequence);
    expect(identityFirst.ownerSequence).toBeLessThan(appliedSecond.ownerSequence);
    identityFirst.metadata.attnets.fill(255);
    expect((await runtime.getIdentity()).metadata).toEqual(second.update.local.metadata);
  } finally {
    await runtime.close();
  }
});

test("complete getters, membership and command results survive a throwing notifier", async () => {
  const config = applicationConfig();
  let notifierCalls = 0;
  let callbackCommand: Promise<unknown> | undefined;
  const runtime = startRuntime(config, () => {
    notifierCalls++;
    callbackCommand ??= runtime.getIdentity();
    throw Error("notifier");
  });
  const other = applicationConfig();
  other.identitySecretKey[31] = 8;
  const remote = await startPeer(other);
  try {
    const ready = await runtime.identity;
    const identity = await runtime.getIdentity();
    expect(identity.peerId).toEqual(ready.peerId);
    await runtime.applyIntent(localIntent(config), 100n);
    const snapshot = await runtime.getPeers();
    expect(snapshot).toMatchObject({
      capacity: 64,
      counts: {connected: 0, outboundRelevant: 0, relevant: 0},
      occupiedCount: 0,
      peers: [],
    });
    expect((await runtime.getDirectPeers()).identities).toEqual([]);
    expect(await runtime.removeDirectPeer(ready.peerId)).toBe(false);
    await runtime.disconnect(ready.peerId);
    await runtime.reStatusPeers([]);
    expect(runtime.drainPeers(64)).toMatchObject({events: [], more: false, updatesReplaceState: true});
    const remoteIdentity = await remote.identity;
    await remote.applyIntent(localIntent(other), 100n);
    const connected = runtime.connect(remoteIdentity.peerId, [remoteIdentity.localEndpoint], 5000n);
    const accepted = [runtime.getIdentity(), runtime.getDirectPeers()];
    await connected;
    for (let i = 0; i < 200 && notifierCalls === 0; i++) await delay(10);
    expect(notifierCalls).toBeGreaterThan(0);
    expect(callbackCommand).toBeDefined();
    await expect(callbackCommand).resolves.toMatchObject({peerId: ready.peerId});
    await Promise.all(accepted);
  } finally {
    const close = runtime.close();
    expect(runtime.close()).toBe(close);
    await Promise.all([close, remote.close()]);
  }
});

test("bounded typed stores refuse the third intent and unwind malformed input", async () => {
  const config = applicationConfig();
  const runtime = startRuntime(config, () => undefined);
  try {
    await runtime.identity;
    const one = runtime.applyIntent(localIntent(config), 100n);
    const two = runtime.applyIntent(localIntent(config), 101n);
    await expect(runtime.applyIntent(localIntent(config), 102n)).rejects.toThrow("NetworkCommandFull");
    await Promise.all([one, two]);
    const invalid = localIntent(config);
    Reflect.set(invalid.demand.groupTargets, 127, config.resources.maxPeers + 1);
    await expect(runtime.applyIntent(invalid, 103n)).rejects.toThrow();
    for (const targets of [new Uint16Array(129), new Uint16Array(128).fill(config.resources.maxPeers + 1)]) {
      const malformed = localIntent(config);
      malformed.demand.custodyGroupTargets = targets;
      await expect(runtime.applyIntent(malformed, 103n)).rejects.toThrow();
    }
    await runtime.applyIntent(localIntent(config), 103n);
    const pending = Array.from({length: 32}, () => runtime.getIdentity());
    expect(() => runtime.getIdentity()).toThrow("NetworkCommandFull");
    await Promise.all(pending);
  } finally {
    await runtime.close();
  }
});

test("reentrant close during input copying cancels publication", async () => {
  const config = applicationConfig();
  const runtime = startRuntime(config, () => undefined);
  await runtime.identity;
  const intent = localIntent(config);
  Object.defineProperty(intent, "update", {
    enumerable: true,
    get() {
      runtime.close();
      return localIntent(config).update;
    },
  });
  await expect(runtime.applyIntent(intent, 101n)).rejects.toThrow("NetworkClosed");
  await runtime.close();
  expect(runtime.diagnostics().currentSlot).toBe(100n);
});

test("actual 200/210 resources resolve and publish complete capacity", async () => {
  const config = applicationConfig();
  config.profile = "beaconNode";
  config.resources = {
    bridgeBudgetBytes: 80 * 1024 * 1024,
    connectionCapacity: 256,
    dialingCapacity: 16,
    handshakingCapacity: 32,
    maxPeers: 210,
    minOutbound: 16,
    nativeBudgetBytes: 512 * 1024 * 1024,
    outboundReserve: 32,
    peerCapacity: 512,
    receiveBudgetBytes: 512 * 1024 * 1024,
    targetPeers: 200,
  };
  const runtime = startRuntime(config, () => undefined);
  try {
    await runtime.identity;
    await runtime.applyIntent(localIntent(config), 100n);
    expect((await runtime.getPeers()).capacity).toBe(512);
    expect(runtime.diagnostics().resolvedCapacities).toEqual({
      admissionIdentityCapacity: 512,
      connectionCapacity: 256,
      dialEngineCapacity: 16,
      dialingCapacity: 16,
      gossipConnectedCapacity: 210,
      gossipRetainedCapacity: 512,
      handshakingCapacity: 32,
      maxPeers: 210,
      minOutbound: 16,
      outboundReserve: 32,
      peerCapacity: 512,
      requestPeerCapacity: 256,
      targetPeers: 200,
    });
    console.log("application 200/210 memory", runtime.diagnostics());
  } finally {
    await runtime.close();
  }
});

test("real authenticated connect, direct membership and generation-preserving immediate disconnect", async () => {
  const config = applicationConfig();
  const other = applicationConfig();
  other.identitySecretKey[31] = 2;
  const a = startRuntime(config, () => undefined);
  const b = await startPeer(other);
  try {
    const [identityA, identityB] = await Promise.all([a.identity, b.identity]);
    await Promise.all([a.applyIntent(localIntent(config), 100n), b.applyIntent(localIntent(other), 100n)]);
    await a.connect(identityB.peerId, [identityB.localEndpoint], 5000n);
    await a.connect(identityB.peerId, [identityB.localEndpoint], 5000n);
    await a.addDirectPeer(identityB.peerId, [identityB.localEndpoint]);
    expect((await a.getDirectPeers()).identities).toEqual([identityB.peerId]);
    await a.reStatusPeers([identityB.peerId]);
    const before = await a.getPeers();
    expect(before.counts.connected).toBe(1);
    expect(before.peers[0].connection).not.toBeNull();
    expect(before.peers[0].redialUntilMs).toBe(0n);
    expect(before.peers[0].goodbyeUntilMs).toBe(0n);
    await a.disconnect(identityB.peerId);
    expect((await a.getDirectPeers()).identities).toEqual([identityB.peerId]);
    expect(await a.removeDirectPeer(identityB.peerId)).toBe(true);
    expect(await a.removeDirectPeer(identityB.peerId)).toBe(false);
    const events = a.drainPeers(64).events;
    const closed = events.filter((event) => event.type === "closed");
    expect(closed).toHaveLength(1);
    expect(closed[0].connection).toEqual(before.peers[0].connection);
    expect(closed[0].peer).toEqual(before.peers[0].peer);
    expect(closed[0].reason).toBe("host");
    expect(identityA.peerId).not.toEqual(identityB.peerId);
  } finally {
    await Promise.all([a.close(), b.close()]);
  }
}, 15000);

test("connect timeout retains independently wanted direct membership", async () => {
  const config = applicationConfig();
  const other = applicationConfig();
  other.identitySecretKey[31] = 3;
  const a = startRuntime(config, () => undefined);
  const b = await silentPeer(other.identitySecretKey);
  try {
    await a.identity;
    const identity = await b.identity;
    await a.applyIntent(localIntent(config), 100n);
    await a.addDirectPeer(identity.peerId, [identity.localEndpoint]);
    await expect(a.connect(identity.peerId, [identity.localEndpoint], 30n)).rejects.toThrow("NetworkConnectTimeout");
    expect((await a.getDirectPeers()).identities).toEqual([identity.peerId]);
  } finally {
    await Promise.all([a.close(), b.close()]);
  }
});

test("peer penalties accumulate while the command lane is full", async () => {
  const first = applicationConfig();
  const second = applicationConfig();
  second.identitySecretKey[31] = 2;
  const a = startRuntime(first, () => undefined);
  const b = await startPeer(second);
  try {
    const [, remote] = await Promise.all([a.identity, b.identity]);
    await Promise.all([a.applyIntent(localIntent(first), 100n), b.applyIntent(localIntent(second), 100n)]);
    await a.connect(remote.peerId, [remote.localEndpoint], 5000n);
    const pending = Array.from({length: 32}, () => a.getIdentity());
    expect(() => a.getIdentity()).toThrow("NetworkCommandFull");
    for (let i = 0; i < 3; i++) a.reportPeer(remote.peerId, "high_tolerance");
    await Promise.all(pending);
    let score = 0;
    for (let i = 0; i < 100; i++) {
      score = (await a.getPeers()).peers[0].score;
      if (score < -2.9) break;
      await delay(10);
    }
    expect(score).toBeLessThan(-2.9);
    expect(score).toBeGreaterThanOrEqual(-3);
    a.reportPeer((await a.getIdentity()).peerId, "fatal");
    expect(a.diagnostics().peerReportsIgnored).toBe(1n);
  } finally {
    await Promise.all([a.close(), b.close()]);
  }
});

test("disconnect cancels pending one-shot connects and releases their dial intent", async () => {
  const config = applicationConfig();
  const other = applicationConfig();
  other.identitySecretKey[31] = 3;
  const a = startRuntime(config, () => undefined);
  const b = await startPeer(other);
  try {
    await a.identity;
    const identity = await b.identity;
    await a.applyIntent(localIntent(config), 100n);
    const pending = a.connect(identity.peerId, [identity.localEndpoint], 60000n).catch((error: Error) => error.message);
    await a.disconnect(identity.peerId);
    expect(await pending).toContain("NetworkConnectCancelled");
    await b.applyIntent(localIntent(other), 100n);
    await a.connect(identity.peerId, [identity.localEndpoint], 5000n);
    expect((await a.getPeers()).counts.connected).toBe(1);
    await a.disconnect(identity.peerId);
    expect((await a.getPeers()).counts.connected).toBe(0);
  } finally {
    await Promise.all([a.close(), b.close()]);
  }
}, 15000);

test("closed facade releases heavy native and typed storage", async () => {
  const config = applicationConfig();
  const runtime = startRuntime(config, () => undefined);
  await runtime.identity;
  await runtime.applyIntent(localIntent(config), 100n);
  const before = runtime.diagnostics();
  await runtime.close();
  const after = runtime.diagnostics();
  expect(after.liveNativeRequestedBytes).toBe(0);
  expect(after.typedStoreBytes).toBe(0);
  expect(after.operationOccupied).toBe(0);
  expect(after.metricsExportBytes).toBe(before.metricsExportBytes / 2);
  expect(Buffer.byteLength(runtime.getMetrics())).toBeLessThan(after.metricsExportBytes);
  expect(after.liveBridgeRequestedBytes).toBe(after.ownerShellBytes + after.peerLaneBytes + after.metricsExportBytes);
  expect(after.liveBridgeRequestedBytes).toBeLessThan(before.liveBridgeRequestedBytes);
  console.log("application small memory", {after, before});
});

test("all typed stores and the connect allowance reject without partial admission", async () => {
  const config = applicationConfig();
  const remoteConfig = applicationConfig();
  remoteConfig.identitySecretKey[31] = 9;
  const runtime = startRuntime(config, () => undefined);
  const remote = await silentPeer(remoteConfig.identitySecretKey);
  try {
    await runtime.identity;
    const identity = await remote.identity;
    await runtime.applyIntent(localIntent(config), 100n);
    const snapshots = [runtime.getPeers(), runtime.getPeers()];
    expect(() => runtime.getPeers()).toThrow("NetworkCommandFull");
    await Promise.all(snapshots);
    const targets = [runtime.reStatusPeers([]), runtime.reStatusPeers([])];
    expect(() => runtime.reStatusPeers([])).toThrow("NetworkCommandFull");
    await Promise.all(targets);
    const connections = Array.from({length: 16}, () =>
      runtime.connect(identity.peerId, [identity.localEndpoint], 60000n).catch((error: Error) => error.message)
    );
    expect(() => runtime.connect(identity.peerId, [identity.localEndpoint], 60000n)).toThrow("NetworkCommandFull");
    expect(runtime.diagnostics().connectOccupied).toBe(16);
    const identityCommand = runtime.getIdentity();
    await identityCommand;
    await runtime.close();
    expect(await Promise.all(connections)).toEqual(Array(16).fill("NetworkClosed"));
    expect(runtime.diagnostics().operationOccupied).toBe(0);
  } finally {
    await Promise.all([runtime.close(), remote.close()]);
  }
});

test.each(["gc", "exit"])("application lifecycle subprocess %s", (mode) => {
  const output = execFileSync(
    process.execPath,
    [
      "--import",
      "tsx",
      "--expose-gc",
      "--import",
      "tsx",
      "bindings/test/fixtures/network-application-lifecycle.mjs",
      mode,
    ],
    {encoding: "utf8", timeout: 15000}
  );
  expect(output).toContain(mode === "exit" ? "application-ready-exit" : "application-command-settled NetworkClosed");
});

test.skipIf(process.env.LODESTAR_Z_NETWORK_TEST_FAILURES !== "1")(
  "allowed result-copy fault still settles a facade-independent command",
  () => {
    const output = execFileSync(
      process.execPath,
      [
        "--import",
        "tsx",
        "--expose-gc",
        "--import",
        "tsx",
        "bindings/test/fixtures/network-application-lifecycle.mjs",
        "copy-failure",
      ],
      {encoding: "utf8", timeout: 15000}
    );
    expect(output).toContain("application-command-settled NetworkResultAllocationFailed");
  }
);

test("identity reads the current signed ENR and copied intent ignores later input mutation", async () => {
  const config = applicationConfig();
  config.discovery = discoveryConfig().discovery;
  const runtime = startRuntime(config, () => undefined);
  try {
    const ready = await runtime.identity;
    expect(ready.localEnr).not.toBeNull();
    const intent = localIntent(config);
    intent.update.local.metadata.attnets[0] = 1;
    const applied = runtime.applyIntent(intent, 101n);
    intent.update.local.metadata.attnets[0] = 2;
    await applied;
    const first = await runtime.getIdentity();
    expect(first.localEnr).not.toEqual(ready.localEnr);
    const repeated = localIntent(config);
    repeated.update.local.metadata.attnets[0] = 1;
    expect((await runtime.applyIntent(repeated, 102n)).changed).toBe(false);
    expect((await runtime.getIdentity()).localEnr).toEqual(first.localEnr);
  } finally {
    await runtime.close();
  }
});

test("incomplete early metadata rejects the whole intent without publishing local state", async () => {
  const config = applicationConfig();
  config.discovery = discoveryConfig().discovery;
  configureChain({BLOB_SCHEDULE: [], FULU_FORK_EPOCH: Infinity});
  const runtime = startRuntime(config, () => undefined);
  try {
    await runtime.identity;
    await runtime.applyIntent(localIntent(config), 100n);
    const before = await runtime.getIdentity();
    const intent = localIntent(config);
    intent.update.local.metadata.attnets[0] = 1;
    Reflect.set(intent.update.local.metadata, "custodyGroupCount", null);
    await expect(runtime.applyIntent(intent, 101n)).rejects.toThrow("MissingCustodyAdvertisement");
    const after = await runtime.getIdentity();
    expect(after.metadata).toEqual(before.metadata);
    expect(after.localEnr).toEqual(before.localEnr);
    expect(runtime.diagnostics().currentSlot).toBe(100n);
    intent.update.local.metadata.custodyGroupCount = 1n;
    expect((await runtime.applyIntent(intent, 101n)).changed).toBe(true);
  } finally {
    await runtime.close();
  }
});

test("graceful physical shutdown progresses while host callbacks are stalled", async () => {
  const config = applicationConfig();
  const other = applicationConfig();
  other.identitySecretKey[31] = 21;
  const a = startRuntime(config, () => undefined);
  const b = await startPeer(other);
  try {
    const [, identity] = await Promise.all([a.identity, b.identity]);
    await Promise.all([a.applyIntent(localIntent(config), 100n), b.applyIntent(localIntent(other), 100n)]);
    await a.connect(identity.peerId, [identity.localEndpoint], 5000n);
    const closed = a.close();
    const wait = new Int32Array(new SharedArrayBuffer(4));
    for (let i = 0; i < 250 && a.state !== "closed"; i++) Atomics.wait(wait, 0, 0, 10);
    expect(a.state).toBe("closed");
    expect(a.diagnostics().liveNativeRequestedBytes).toBe(0);
    expect(await closed).toEqual({reason: "requested"});
  } finally {
    await Promise.all([a.close(), b.close()]);
  }
});

test.skipIf(process.env.LODESTAR_Z_NETWORK_TEST_FAILURES !== "1")(
  "global close ends a full-lane session and retains already copied generations",
  async () => {
    const config = applicationConfig();
    const other = applicationConfig();
    other.identitySecretKey[31] = 22;
    bindings.networkTestScenario("application_peer_lane");
    const a = startRuntime(config, () => undefined);
    const b = await startPeer(other);
    try {
      const remote = b.identity;
      expect(a.diagnostics().peerLaneOccupied).toBe(64);
      await Promise.all([a.applyIntent(localIntent(config), 100n), b.applyIntent(localIntent(other), 100n)]);
      await a.connect(remote.peerId, [remote.localEndpoint], 5000n);
      expect((await a.getPeers()).counts.connected).toBe(1);
      expect(a.diagnostics().peerLaneOccupied).toBe(64);
      await a.close();
      expect(a.state).toBe("closed");
      expect(a.diagnostics().liveNativeRequestedBytes).toBe(0);
      expect(a.diagnostics().typedStoreBytes).toBe(0);
      const batch = a.drainPeers(64);
      expect(batch.events).toHaveLength(64);
      for (let i = 0; i < batch.events.length; i++) {
        expect(batch.events[i]).toMatchObject({
          connection: {generation: 4294967295 - i, index: i % 16},
          ownerSequence: 0n,
          peer: {generation: 18446744073709551615n - BigInt(i), index: i},
          type: "closed",
        });
      }
      expect(a.drainPeers(64).events).toEqual([]);
    } finally {
      await Promise.all([a.close(), b.close()]);
    }
  }
);

async function drainUntil(
  runtime: NativeNetworkApplicationRuntime,
  done: (events: NativePeerObservation[]) => boolean
) {
  const events: NativePeerObservation[] = [];
  for (let i = 0; i < 300; i++) {
    events.push(...runtime.drainPeers(64).events);
    if (done(events)) return events;
    await delay(10);
  }
  throw Error("peer observations did not reach the required transition");
}

test.skipIf(process.env.LODESTAR_Z_NETWORK_TEST_FAILURES !== "1")(
  "live full lane preserves close before reconnect and settles commands while drainage is paused",
  async () => {
    const config = applicationConfig();
    const other = applicationConfig();
    other.identitySecretKey[31] = 23;
    bindings.networkTestScenario("application_peer_lane");
    const a = startRuntime(config, () => undefined);
    const b = await startPeer(other);
    try {
      const [local, remote] = await Promise.all([a.identity, b.identity]);
      await Promise.all([a.applyIntent(localIntent(config), 100n), b.applyIntent(localIntent(other), 100n)]);
      await a.connect(remote.peerId, [remote.localEndpoint], 5000n);
      const old = (await a.getPeers()).peers[0];
      expect(old.connection).not.toBeNull();
      expect(a.diagnostics().peerLaneOccupied).toBe(64);
      await a.disconnect(remote.peerId);
      const reconnect = a.connect(remote.peerId, [remote.localEndpoint], 5000n);
      expect((await a.getIdentity()).peerId).toEqual(local.peerId);
      expect((await a.getPeers()).counts.connected).toBe(0);
      expect(a.diagnostics().peerLaneOccupied).toBe(64);
      const background = a.drainPeers(64).events;
      expect(background).toHaveLength(64);
      expect(background.every((event) => event.ownerSequence === 0n && event.type === "closed")).toBe(true);
      const events = await drainUntil(a, (batch) => batch.some((event) => event.type === "ready"));
      await reconnect;
      const closed = events.filter((event) => event.type === "closed");
      expect(closed).toHaveLength(1);
      expect(events[0]).toEqual(closed[0]);
      expect(closed[0]).toMatchObject({connection: old.connection, peer: old.peer});
      const ready = events.find((event) => event.type === "ready");
      expect(ready?.type).toBe("ready");
      if (ready?.type !== "ready") throw Error("missing reconnect ready");
      expect(ready.state.peer).toEqual(old.peer);
      expect(ready.state.connection).not.toEqual(old.connection);
      expect(ready.state.connection).toEqual((await a.getPeers()).peers[0].connection);
      expect(events.filter((event) => event.type === "ready")).toHaveLength(1);
      expect(ready.state.identity).toEqual(remote.peerId);
      expect(ready.ownerSequence).toBeGreaterThanOrEqual(closed[0].ownerSequence);
      expect(a.state).toBe("running");
    } finally {
      await Promise.all([a.close(), b.close()]);
    }
  },
  15000
);

test.skipIf(process.env.LODESTAR_Z_NETWORK_TEST_FAILURES !== "1")(
  "live full lane coalesces a real preferred replacement into canonical current state",
  async () => {
    const config = applicationConfig();
    config.identitySecretKey[31] = 2;
    const other = applicationConfig();
    bindings.networkTestScenario("application_peer_lane");
    const a = startRuntime(config, () => undefined);
    const b = await startPeer(other);
    const replacement = await startPeer(other);
    try {
      const [local, remote, duplicate] = await Promise.all([a.identity, b.identity, replacement.identity]);
      expect(Buffer.compare(local.peerId, remote.peerId)).toBeGreaterThan(0);
      expect(duplicate.peerId).toEqual(remote.peerId);
      await Promise.all([
        a.applyIntent(localIntent(config), 100n),
        b.applyIntent(localIntent(other), 100n),
        replacement.applyIntent(localIntent(other), 100n),
      ]);
      await a.connect(remote.peerId, [remote.localEndpoint], 5000n);
      const old = (await a.getPeers()).peers[0];
      expect(old.direction).toBe("outbound");
      expect(a.diagnostics().peerLaneOccupied).toBe(64);
      await replacement.connect(local.peerId, [local.localEndpoint], 5000n);
      let current = await a.getPeers();
      for (let i = 0; i < 300 && (current.peers[0].direction !== "inbound" || !current.peers[0].relevant); i++) {
        await delay(10);
        current = await a.getPeers();
      }
      expect(current.counts.connected).toBe(1);
      expect(current.peers[0]).toMatchObject({direction: "inbound", peer: old.peer, relevant: true});
      expect(current.peers[0].connection).not.toEqual(old.connection);
      let displaced = await b.getPeers();
      for (let i = 0; i < 200 && displaced.counts.connected !== 0; i++) {
        await delay(10);
        displaced = await b.getPeers();
      }
      expect(displaced.counts.connected).toBe(0);
      expect((await a.getIdentity()).peerId).toEqual(local.peerId);
      expect(a.diagnostics().peerLaneOccupied).toBe(64);
      const background = a.drainPeers(64).events;
      expect(background).toHaveLength(64);
      expect(background.every((event) => event.ownerSequence === 0n)).toBe(true);
      const events = await drainUntil(a, (batch) => batch.some((event) => event.type === "ready"));
      expect(events.some((event) => event.type === "closed")).toBe(false);
      const ready = events[0];
      if (ready.type !== "ready") throw Error("replacement must first publish ready");
      expect(ready.state).toMatchObject({
        connection: current.peers[0].connection,
        direction: "inbound",
        identity: remote.peerId,
        peer: old.peer,
      });
      expect(ready.ownerSequence).toBeGreaterThan(0n);
      for (let i = 1; i < events.length; i++) {
        const update = events[i];
        expect(update.type).toBe("updated");
        if (update.type !== "updated") throw Error("unexpected replacement transition");
        expect(update.state.connection).toEqual(ready.state.connection);
        expect(update.ownerSequence).toBeGreaterThanOrEqual(events[i - 1].ownerSequence);
      }
      expect(a.state).toBe("running");
    } finally {
      await Promise.all([a.close(), b.close(), replacement.close()]);
    }
  },
  15000
);

async function silentPeer(secret: Uint8Array) {
  const socket = createSocket("udp4");
  try {
    const listening = once(socket, "listening");
    socket.bind(0, "127.0.0.1");
    await listening;
    return {
      close: () => new Promise<void>((resolve) => socket.close(() => resolve())),
      identity: {
        localEndpoint: {address: Uint8Array.of(127, 0, 0, 1), family: 4 as const, port: socket.address().port},
        peerId: privateKeyFromRaw(secret).publicKey.toMultihash().bytes,
      },
    };
  } catch (error) {
    socket.close();
    throw error;
  }
}
