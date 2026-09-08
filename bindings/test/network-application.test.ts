import {execFileSync} from "node:child_process";
import {setTimeout as delay} from "node:timers/promises";
import {expect, test} from "vitest";
import bindings from "../src/bindings.js";
import type {NativeNetworkApplicationRuntime, NativePeerObservation} from "../src/network.js";
import {createNativeNetworkApplicationRuntime} from "../src/network.js";
import {applicationConfig, discoveryConfig, localIntent} from "./utils/network.js";

test("application stays prepared across the host clock fork boundary and activates fresh intent", async () => {
  const config = applicationConfig();
  const boundarySlot = 128n;
  const slotsPerEpoch = process.env.LODESTAR_PRESET === "minimal" ? 8n : 32n;
  const nextDigest = Uint8Array.of(5, 6, 7, 8);
  config.initialSlot = boundarySlot - 1n;
  config.local.status.headSlot = config.initialSlot;
  config.forkSchedule.nextEpoch = boundarySlot / slotsPerEpoch;
  config.forkSchedule.nextDigest = nextDigest;
  config.forkSchedule.nextVersion = Uint8Array.of(5, 0, 0, 0);
  config.requestForks = [...config.requestForks, {digest: nextDigest, fork: "electra"}];
  config.topicPolicy = [...config.topicPolicy, {...structuredClone(config.topicPolicy[0]), digest: nextDigest}];
  config.discovery = discoveryConfig().discovery;
  const runtime = createNativeNetworkApplicationRuntime(config, () => undefined);
  try {
    const identity = await runtime.ready;
    const epochStart = performance.now();
    const hostSlot = () => config.initialSlot + BigInt(Math.floor((performance.now() - epochStart) / 20));
    expect(hostSlot()).toBeLessThan(boundarySlot);
    await delay(40);
    const slot = hostSlot();
    expect(slot).toBeGreaterThanOrEqual(config.forkSchedule.nextEpoch * slotsPerEpoch);
    expect(runtime.state).toBe("prepared");
    expect(runtime.diagnostics().ownerTurns).toBe(0n);
    expect(runtime.diagnostics().currentSlot).toBe(config.initialSlot);
    const fresh = localIntent(config);
    fresh.update.local.fork.fork = "electra";
    fresh.update.local.fork.digest = nextDigest;
    fresh.update.local.status.forkDigest = nextDigest;
    fresh.update.local.status.headSlot = slot;
    fresh.update.schedule = applicationConfig().forkSchedule;
    fresh.demand.expiresAtSlot = slot + 100n;
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

test("failed intent does not activate or advance the clock", async () => {
  const config = applicationConfig();
  const runtime = createNativeNetworkApplicationRuntime(config, () => undefined);
  try {
    await runtime.ready;
    expect(() => runtime.getPeers()).toThrow("NetworkNotActive");
    const intent = localIntent(config);
    intent.subscriptions = [{name: "/invalid", params: config.gossipPolicy.score.defaultTopic}];
    await expect(runtime.applyIntent(intent, 101n)).rejects.toThrow();
    expect(runtime.state).toBe("prepared");
    expect(runtime.diagnostics().currentSlot).toBe(100n);
    expect(runtime.diagnostics().ownerTurns).toBe(0n);
    const first = await runtime.applyIntent(localIntent(config), 102n);
    expect(first.slot).toBe(102n);
    const next = await runtime.applyIntent(localIntent(config), 103n);
    expect(next.changed).toBe(false);
    expect(next.ownerSequence).toBeGreaterThan(first.ownerSequence);
    await expect(runtime.applyIntent(localIntent(config), 101n)).rejects.toThrow("ClockRegression");
    expect(runtime.diagnostics().currentSlot).toBe(103n);
    expect("setCurrentSlot" in runtime).toBe(false);
  } finally {
    await runtime.close();
  }
});

test("complete getters, membership and command results survive a throwing notifier", async () => {
  const config = applicationConfig();
  let notifierCalls = 0;
  let callbackCommand: Promise<unknown> | undefined;
  const runtime = createNativeNetworkApplicationRuntime(config, () => {
    notifierCalls++;
    callbackCommand ??= runtime.getIdentity();
    throw Error("notifier");
  });
  const other = applicationConfig();
  other.identitySecretKey[31] = 8;
  const remote = createNativeNetworkApplicationRuntime(other, () => undefined);
  try {
    const ready = await runtime.ready;
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
    const remoteIdentity = await remote.ready;
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
  const runtime = createNativeNetworkApplicationRuntime(config, () => undefined);
  try {
    await runtime.ready;
    const one = runtime.applyIntent(localIntent(config), 100n);
    const two = runtime.applyIntent(localIntent(config), 101n);
    expect(() => runtime.applyIntent(localIntent(config), 102n)).toThrow("NetworkCommandFull");
    await Promise.all([one, two]);
    const invalid = localIntent(config);
    Reflect.set(invalid.demand.groupTargets, 127, 1.5);
    expect(() => runtime.applyIntent(invalid, 103n)).toThrow();
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
  const runtime = createNativeNetworkApplicationRuntime(config, () => undefined);
  await runtime.ready;
  const intent = localIntent(config);
  Object.defineProperty(intent, "update", {
    enumerable: true,
    get() {
      runtime.close();
      return localIntent(config).update;
    },
  });
  expect(() => runtime.applyIntent(intent, 101n)).toThrow("NetworkClosed");
  await runtime.close();
  expect(runtime.diagnostics().currentSlot).toBe(100n);
});

test("actual 200/210 resources resolve and publish complete capacity", async () => {
  const config = applicationConfig();
  config.profile = "beaconNode";
  config.resources = {
    bridgeBudgetBytes: 16 * 1024 * 1024,
    connectionCapacity: 256,
    dialingCapacity: 16,
    handshakingCapacity: 32,
    maxPeers: 210,
    minOutbound: 16,
    nativeBudgetBytes: 256 * 1024 * 1024,
    outboundReserve: 32,
    peerCapacity: 512,
    receiveBudgetBytes: 512 * 1024 * 1024,
    targetPeers: 200,
  };
  const runtime = createNativeNetworkApplicationRuntime(config, () => undefined);
  try {
    await runtime.ready;
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
  const a = createNativeNetworkApplicationRuntime(config, () => undefined);
  const b = createNativeNetworkApplicationRuntime(other, () => undefined);
  try {
    const [identityA, identityB] = await Promise.all([a.ready, b.ready]);
    await Promise.all([a.applyIntent(localIntent(config), 100n), b.applyIntent(localIntent(other), 100n)]);
    await a.connect(identityB.peerId, [identityB.localEndpoint], 5000n);
    await a.connect(identityB.peerId, [identityB.localEndpoint], 5000n);
    await a.addDirectPeer(identityB.peerId, [identityB.localEndpoint]);
    expect((await a.getDirectPeers()).identities).toEqual([identityB.peerId]);
    await a.reStatusPeers([identityB.peerId]);
    const before = await a.getPeers();
    expect(before.counts.connected).toBe(1);
    expect(before.peers[0].connection).not.toBeNull();
    await a.disconnect(identityB.peerId);
    expect((await a.getDirectPeers()).identities).toEqual([identityB.peerId]);
    expect(await a.removeDirectPeer(identityB.peerId)).toBe(true);
    expect(await a.removeDirectPeer(identityB.peerId)).toBe(false);
    const events = a.drainPeers(64).events;
    const closed = events.filter((event) => event.type === "closed");
    expect(closed).toHaveLength(1);
    expect(closed[0].connection).toEqual(before.peers[0].connection);
    expect(closed[0].peer).toEqual(before.peers[0].peer);
    expect(identityA.peerId).not.toEqual(identityB.peerId);
  } finally {
    await Promise.all([a.close(), b.close()]);
  }
}, 15000);

test("connect timeout retains independently wanted direct membership", async () => {
  const config = applicationConfig();
  const other = applicationConfig();
  other.identitySecretKey[31] = 3;
  const a = createNativeNetworkApplicationRuntime(config, () => undefined);
  const b = createNativeNetworkApplicationRuntime(other, () => undefined);
  try {
    await a.ready;
    const identity = await b.ready;
    await a.applyIntent(localIntent(config), 100n);
    await a.addDirectPeer(identity.peerId, [identity.localEndpoint]);
    await expect(a.connect(identity.peerId, [identity.localEndpoint], 30n)).rejects.toThrow("NetworkConnectTimeout");
    expect((await a.getDirectPeers()).identities).toEqual([identity.peerId]);
  } finally {
    await Promise.all([a.close(), b.close()]);
  }
});

test("closed facade releases heavy native and typed storage", async () => {
  const config = applicationConfig();
  const runtime = createNativeNetworkApplicationRuntime(config, () => undefined);
  await runtime.ready;
  await runtime.applyIntent(localIntent(config), 100n);
  const before = runtime.diagnostics();
  await runtime.close();
  const after = runtime.diagnostics();
  expect(after.liveNativeRequestedBytes).toBe(0);
  expect(after.typedStoreBytes).toBe(0);
  expect(after.operationOccupied).toBe(0);
  expect(after.liveBridgeRequestedBytes).toBe(after.ownerShellBytes + after.peerLaneBytes);
  expect(after.liveBridgeRequestedBytes).toBeLessThan(before.liveBridgeRequestedBytes);
  console.log("application small memory", {after, before});
});

test("all typed stores and the connect allowance reject without partial admission", async () => {
  const config = applicationConfig();
  const remoteConfig = applicationConfig();
  remoteConfig.identitySecretKey[31] = 9;
  const runtime = createNativeNetworkApplicationRuntime(config, () => undefined);
  const remote = createNativeNetworkApplicationRuntime(remoteConfig, () => undefined);
  try {
    await runtime.ready;
    const identity = await remote.ready;
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
    ["--expose-gc", "--import", "tsx", "bindings/test/fixtures/network-application-lifecycle.mjs", mode],
    {encoding: "utf8", timeout: 15000}
  );
  expect(output).toContain(mode === "exit" ? "application-ready-exit" : "application-command-settled NetworkClosed");
});

test.skipIf(process.env.LODESTAR_Z_NETWORK_TEST_FAILURES !== "1")(
  "allowed result-copy fault still settles a facade-independent command",
  () => {
    const output = execFileSync(
      process.execPath,
      ["--expose-gc", "--import", "tsx", "bindings/test/fixtures/network-application-lifecycle.mjs", "copy-failure"],
      {encoding: "utf8", timeout: 15000}
    );
    expect(output).toContain("application-command-settled NetworkResultAllocationFailed");
  }
);

test("identity reads the current signed ENR and copied intent ignores later input mutation", async () => {
  const config = applicationConfig();
  config.discovery = discoveryConfig().discovery;
  const runtime = createNativeNetworkApplicationRuntime(config, () => undefined);
  try {
    const ready = await runtime.ready;
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

test("graceful physical shutdown progresses while host callbacks are stalled", async () => {
  const config = applicationConfig();
  const other = applicationConfig();
  other.identitySecretKey[31] = 21;
  const a = createNativeNetworkApplicationRuntime(config, () => undefined);
  const b = createNativeNetworkApplicationRuntime(other, () => undefined);
  try {
    const [, identity] = await Promise.all([a.ready, b.ready]);
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
    const a = createNativeNetworkApplicationRuntime(config, () => undefined);
    const b = createNativeNetworkApplicationRuntime(other, () => undefined);
    try {
      const [local, remote] = await Promise.all([a.ready, b.ready]);
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
          session: local.session,
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
    const a = createNativeNetworkApplicationRuntime(config, () => undefined);
    const b = createNativeNetworkApplicationRuntime(other, () => undefined);
    try {
      const [local, remote] = await Promise.all([a.ready, b.ready]);
      await Promise.all([a.applyIntent(localIntent(config), 100n), b.applyIntent(localIntent(other), 100n)]);
      await a.connect(remote.peerId, [remote.localEndpoint], 5000n);
      const old = (await a.getPeers()).peers[0];
      expect(old.connection).not.toBeNull();
      expect(a.diagnostics().peerLaneOccupied).toBe(64);
      await a.disconnect(remote.peerId);
      let settled = false;
      const reconnect = a.connect(remote.peerId, [remote.localEndpoint], 5000n).then(() => {
        settled = true;
      });
      expect((await a.getIdentity()).peerId).toEqual(local.peerId);
      expect((await a.getPeers()).counts.connected).toBe(0);
      expect(settled).toBe(false);
      expect(a.diagnostics().peerLaneOccupied).toBe(64);
      const background = a.drainPeers(64).events;
      expect(background).toHaveLength(64);
      expect(background.every((event) => event.ownerSequence === 0n && event.type === "closed")).toBe(true);
      const events = await drainUntil(a, (batch) => batch.some((event) => event.type === "ready"));
      await reconnect;
      const closed = events.filter((event) => event.type === "closed");
      expect(closed).toHaveLength(1);
      expect(events[0]).toEqual(closed[0]);
      expect(closed[0]).toMatchObject({connection: old.connection, peer: old.peer, session: local.session});
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
    const a = createNativeNetworkApplicationRuntime(config, () => undefined);
    const b = createNativeNetworkApplicationRuntime(other, () => undefined);
    const replacement = createNativeNetworkApplicationRuntime(other, () => undefined);
    try {
      const [local, remote, duplicate] = await Promise.all([a.ready, b.ready, replacement.ready]);
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
        session: local.session,
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
