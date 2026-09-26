import {execFileSync} from "node:child_process";
import {createSocket} from "node:dgram";
import {once} from "node:events";
import {setTimeout as delay} from "node:timers/promises";
import {privateKeyFromRaw} from "@libp2p/crypto/keys";
import {peerIdFromPublicKey} from "@libp2p/peer-id";
import {expect, test} from "vitest";
import {
  applicationConfig,
  configureChain,
  discoveryConfig,
  exchange,
  localIntent,
  settleOnly,
  startRuntime,
  subscriptions,
  testChain,
  topicName,
} from "./utils/network.js";
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
        observed = (await b.getPeers()).peers.find((peer) => peer.identity === identity.peerId)?.status ?? null;
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
    expect(exchange(runtime, {...settleOnly, peers: 64}).peers).toEqual([]);
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
}, 15000);

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

test("actual 200/210 resources resolve and publish complete capacity", async () => {
  const config = applicationConfig();
  config.profile = "beaconNode";
  config.resources = {
    bridgeBudgetBytes: 512 * 1024 * 1024,
    connectionCapacity: 256,
    dialingCapacity: 16,
    handshakingCapacity: 32,
    maxPeers: 210,
    minOutbound: 16,
    nativeBudgetBytes: 768 * 1024 * 1024,
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
    const events = exchange(a, {...settleOnly, peers: 64}).peers;
    const closed = events.filter((event) => event.type === "closed");
    expect(closed).toHaveLength(1);
    expect(closed[0].connection).toEqual(before.peers[0].connection);
    expect(closed[0].identity).toEqual(before.peers[0].identity);
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
    // Reports coalesce per identity and action, as the host's ledger batches them into one action.
    exchange(a, settleOnly, [{action: "high_tolerance", count: 3, peerId: remote.peerId, type: "reportPeer"}]);
    await Promise.all(pending);
    let score = 0;
    for (let i = 0; i < 100; i++) {
      score = (await a.getPeers()).peers[0].score;
      if (score < -2.9) break;
      await delay(10);
    }
    expect(score).toBeLessThan(-2.9);
    expect(score).toBeGreaterThanOrEqual(-3);
    exchange(a, settleOnly, [{action: "fatal", count: 1, peerId: (await a.getIdentity()).peerId, type: "reportPeer"}]);
    for (let i = 0; i < 100 && a.diagnostics().peerReportsIgnored === 0n; i++) await delay(10);
    expect(a.diagnostics().peerReportsIgnored).toBe(1n);
    await a.disconnect(remote.peerId);
    exchange(a, settleOnly, [{action: "low_tolerance", count: 1, peerId: remote.peerId, type: "reportPeer"}]);
    for (let i = 0; i < 100; i++) {
      const retained = (await a.getPeers()).peers.find((peer) => peer.identity === remote.peerId);
      if (retained && retained.score < -12.9) break;
      await delay(10);
    }
    const retained = (await a.getPeers()).peers.find((peer) => peer.identity === remote.peerId);
    expect(retained?.connection).toBeNull();
    expect(retained?.score).toBeLessThan(-12.9);
  } finally {
    await Promise.all([a.close(), b.close()]);
  }
}, 15000);

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
}, 20000);

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
}, 15000);

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
        peerId: peerIdFromPublicKey(privateKeyFromRaw(secret).publicKey).toString(),
      },
    };
  } catch (error) {
    socket.close();
    throw error;
  }
}
