import {execFileSync} from "node:child_process";
import {privateKeyFromRaw} from "@libp2p/crypto/keys";
import {peerIdFromPublicKey} from "@libp2p/peer-id";
import {expect, it} from "vitest";
import {initializeNativeNetworkRuntime} from "../src/network.js";
import {
  applicationConfig,
  configureChain,
  discoveryConfig,
  localIntent,
  requestForks,
  startRuntime,
  subscriptions,
  topicName,
} from "./utils/network.js";
import {startPeer} from "./utils/network-peer.js";

it("owns a real native socket and releases it on idempotent close", async () => {
  const config = applicationConfig();
  const expectedPeerId = peerIdFromPublicKey(privateKeyFromRaw(config.identitySecretKey).publicKey).toString();
  const runtime = startRuntime(config, () => undefined);
  const terminal = runtime.closed;
  try {
    const identity = await runtime.identity;
    expect(identity.peerId).toEqual(expectedPeerId);
    expect(typeof identity.peerId).toBe("string");
    for (const invalid of [
      "",
      "1".repeat(56),
      "x".repeat(4096),
      "not-a-peer",
      `z${identity.peerId}`,
      `${identity.peerId}\0`,
      `${identity.peerId}é`,
    ]) {
      expect(() => runtime.reportPeer(invalid, "fatal")).toThrow("InvalidNetworkPeerId");
      expect(() => runtime.connect(invalid, [identity.localEndpoint], 1000n)).toThrow("InvalidNetworkPeerId");
      expect(() => runtime.reStatusPeers([invalid])).toThrow("InvalidNetworkPeerId");
      expect(() => runtime.trackGossipSearch(new Uint8Array(32), invalid)).toThrow("InvalidNetworkPeerId");
      expect(() =>
        runtime.request(invalid, "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy", new Uint8Array(0))
      ).toThrow("InvalidNetworkPeerId");
    }
    for (const invalid of [null, 1, new Uint8Array(39), {toString: () => identity.peerId}]) {
      expect(() => Reflect.apply(runtime.reportPeer, runtime, [invalid, "fatal"])).toThrow("InvalidNetworkPeerId");
    }
    expect(identity.localEndpoint.port).toBeGreaterThan(0);
    expect(runtime.state).toBe("running");
    const diagnostics = runtime.diagnostics();
    expect(diagnostics.nativeRequestedBytes).toBeGreaterThan(0);
    expect(diagnostics.quicReceiveWindowBytes).toBe(
      diagnostics.quicConnectionWindowBytes * BigInt(diagnostics.resolvedCapacities.connectionCapacity)
    );
    expect(diagnostics.quicStreamWindowBytes).toBeGreaterThan(0n);
    expect(diagnostics.quicStreamWindowBytes).toBeLessThanOrEqual(diagnostics.quicConnectionWindowBytes);
    expect((await runtime.applyIntent(localIntent(config), 101n)).slot).toBe(101n);
    const closing = runtime.close();
    expect(terminal).toBe(closing);
    expect(runtime.close()).toBe(closing);
    await closing;
    expect(runtime.state).toBe("closed");
    execFileSync(
      process.execPath,
      [
        "--import",
        "tsx",
        "--input-type=module",
        "-e",
        `import {createSocket} from 'node:dgram'; const socket = createSocket('udp4'); socket.on('error', () => process.exit(1)); socket.bind(${identity.localEndpoint.port}, '127.0.0.1', () => socket.close());`,
      ],
      {timeout: 5000}
    );
  } finally {
    await runtime.close();
  }
}, 20000);

it("copies inputs before returning and advances the clock only through intents", async () => {
  const config = applicationConfig();
  const expected = peerIdFromPublicKey(privateKeyFromRaw(config.identitySecretKey).publicKey).toString();
  config.local.metadata.syncnets = 2;
  const runtime = initializeNativeNetworkRuntime(config, () => undefined);
  expect(runtime.identity.metadata.syncnets).toBe(2);
  config.local.metadata.syncnets = 4;
  expect(runtime.identity.metadata.syncnets).toBe(2);
  const intent = localIntent(config);
  config.identitySecretKey.fill(0);
  if (!("address" in config.bind)) throw new Error("Expected a single bind address");
  config.bind.address.fill(0);
  config.local.status.headRoot.fill(99);
  try {
    const identity = await runtime.identity;
    expect(identity.peerId).toEqual(expected);
    expect(await runtime.applyIntent(intent, 101n)).toMatchObject({slot: 101n});
    expect((await runtime.getIdentity()).metadata.syncnets).toBe(4);
    await expect(runtime.applyIntent(intent, 100n)).rejects.toThrow("ClockRegression");
    await expect(runtime.applyIntent(intent, -1n)).rejects.toThrow("InvalidNetworkInteger");
    await expect(runtime.applyIntent(intent, 1n << 64n)).rejects.toThrow("InvalidNetworkInteger");
    expect(identity.peerId).toEqual(expected);
  } finally {
    await runtime.close();
  }
  await expect(runtime.applyIntent(intent, 102n)).rejects.toThrow("NetworkClosed");
}, 20000);

it("starts without subscriptions and accepts ordinary updates after rejecting an invalid intent", async () => {
  const config = applicationConfig();
  const runtime = initializeNativeNetworkRuntime(config, () => undefined);
  try {
    expect(runtime.state).toBe("running");
    expect((await runtime.getGossipDiagnostics()).topics.some((topic) => topic.subscribed)).toBe(false);
    expect(runtime.drainGossip()).toEqual({jobs: [], messages: [], more: false});
    expect(runtime.takeIncomingRequest()).toBeNull();
    const intent = localIntent(config);
    intent.subscriptions = [{digest: new Uint8Array(4).fill(255), subnets: {}}];
    await expect(runtime.applyIntent(intent, config.initialSlot)).rejects.toThrow("InvalidTopic");
    expect(runtime.state).toBe("running");
    const topic = topicName();
    intent.subscriptions = subscriptions(topic);
    await runtime.applyIntent(intent, config.initialSlot);
    expect((await runtime.getGossipDiagnostics()).topics).toContainEqual(
      expect.objectContaining({subscribed: true, topic})
    );
  } finally {
    await runtime.close();
  }
});

it.each([
  [
    "key length",
    (c: ReturnType<typeof applicationConfig>) => {
      c.identitySecretKey = new Uint8Array(31);
    },
    "InvalidNetworkBytes",
  ],
  [
    "fractional port",
    (c: ReturnType<typeof applicationConfig>) => {
      if (!("port" in c.bind)) throw new Error("Expected a single bind address");
      c.bind.port = 0.5;
    },
    "InvalidNetworkInteger",
  ],
  [
    "infinite score",
    (c: ReturnType<typeof applicationConfig>) => {
      c.gossipPolicy.score.behaviourWeight = Number.NEGATIVE_INFINITY;
    },
    "InvalidNetworkConfig",
  ],
  [
    "unknown timer",
    (c: ReturnType<typeof applicationConfig>) => {
      Object.assign(c.gossipPolicy, {unknown: 1});
    },
    "InvalidNetworkConfig",
  ],
  [
    "missing timer",
    (c: ReturnType<typeof applicationConfig>) => {
      Reflect.deleteProperty(c.gossipPolicy, "txTimeoutMs");
    },
    "InvalidNetworkInteger",
  ],
  [
    "negative bigint",
    (c: ReturnType<typeof applicationConfig>) => {
      c.initialSlot = -1n;
    },
    "InvalidNetworkInteger",
  ],
  [
    "overflow bigint",
    (c: ReturnType<typeof applicationConfig>) => {
      c.initialSlot = 1n << 64n;
    },
    "InvalidNetworkInteger",
  ],
  [
    "reserved syncnet",
    (c: ReturnType<typeof applicationConfig>) => {
      c.local.metadata.syncnets = 16;
    },
    "InvalidNetworkInteger",
  ],
] as const)("rejects %s before startup", (_name, mutate, code) => {
  const config = applicationConfig();
  mutate(config);
  expect(() => startRuntime(config, () => undefined)).toThrow(code);
});

it("rejects another initialization during operation and after close", async () => {
  const runtime = startRuntime(applicationConfig());
  expect(runtime.state).toBe("running");
  expect(typeof runtime.identity.peerId).toBe("string");
  expect(() => startRuntime(applicationConfig())).toThrow("NetworkAlreadyInitialized");
  expect((await runtime.getIdentity()).peerId).toEqual(runtime.identity.peerId);
  await runtime.close();
  expect(() => startRuntime(applicationConfig())).toThrow("NetworkAlreadyInitialized");
});

it("joins immediately after initialization and closes idempotently", async () => {
  const runtime = startRuntime(applicationConfig());
  const closing = runtime.close();
  expect(runtime.close()).toBe(closing);
  expect(await closing).toEqual({reason: "requested"});
  expect(runtime.state).toBe("closed");
  expect(runtime.diagnostics().liveNativeRequestedBytes).toBe(0);
});

it("rejects every invalid drain limit", async () => {
  const runtime = startRuntime(applicationConfig(), () => undefined);
  try {
    await runtime.identity;
    for (const limit of [0, -1, 0.5, 65, Number.NaN, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 1]) {
      expect(() => runtime.drainPeers(limit)).toThrow("InvalidDrainLimit");
    }
    expect(runtime.drainPeers(1)).toMatchObject({events: [], more: false});
    expect(runtime.drainPeers(32)).toMatchObject({events: [], more: false});
  } finally {
    await runtime.close();
  }
}, 20000);

it.each(["gc", "exit", "promises"])("finishes bounded %s subprocess lifecycle", (mode) => {
  const output = execFileSync(
    process.execPath,
    ["--import", "tsx", "--expose-gc", "bindings/test/fixtures/network-lifecycle.mjs", mode],
    {
      encoding: "utf8",
      timeout: 10000,
    }
  );
  expect(output).toContain(mode === "gc" ? "gc-rebound" : mode === "exit" ? "ready-exit" : "promises-settled");
}, 15000);

it("releases live requests, incoming cells and gossip batches on worker termination", () => {
  const output = execFileSync(
    process.execPath,
    ["--import", "tsx", "bindings/test/fixtures/network-worker-resources.mjs"],
    {
      encoding: "utf8",
      timeout: 20000,
    }
  );
  expect(output).toContain("live-worker-resources-released");
}, 25000);

it("rejects initialization from another Node environment", async () => {
  const {Worker} = await import("node:worker_threads");
  const runtime = startRuntime(applicationConfig());
  const worker = new Worker(new URL("./fixtures/network-worker.mjs", import.meta.url), {execArgv: ["--import", "tsx"]});
  try {
    const failure = await new Promise<Error>((resolve) => worker.once("error", resolve));
    expect(failure.message).toContain("NetworkAlreadyInitialized");
    expect((await runtime.getIdentity()).peerId).toEqual(runtime.identity.peerId);
  } finally {
    await worker.terminate();
    await runtime.close();
  }
});

it("memory_safety: terminates workers while publication and command results are pending", () => {
  for (let i = 0; i < 8; i++) {
    const output = execFileSync(
      process.execPath,
      ["--import", "tsx", "bindings/test/fixtures/network-worker-settlement.mjs"],
      {
        encoding: "utf8",
        timeout: 10000,
      }
    );
    expect(output, `worker termination ${i}`).toContain("worker-settlement-released");
  }
}, 90000);

it("gates raw reentrant initialization and close before config getters execute", async () => {
  const {networkBindings: addon} = await import("./utils/network-bindings.js");
  const raw = new addon.NativeNetworkRuntime();
  const config = applicationConfig();
  Object.defineProperty(config, "profile", {
    enumerable: true,
    get() {
      expect(() => raw.initialize(applicationConfig(), () => undefined)).toThrow("NetworkAlreadyInitialized");
      raw.close();
      return "small";
    },
  });
  expect(() => raw.initialize(config, () => undefined)).toThrow("NetworkClosed");
  expect(() => raw.initialize(applicationConfig(), () => undefined)).toThrow("NetworkAlreadyInitialized");
}, 20000);

it("initializes signed discovery without waiting for bootstrap reachability", async () => {
  const config = applicationConfig();
  config.discovery = {
    advertisement: {ip4: Uint8Array.of(127, 0, 0, 1), udp: 40404},
    bind: {address: Uint8Array.of(127, 0, 0, 1), family: 4, port: 0},
    bootstrapEnrs: [],
    fixed: {ip4: Uint8Array.of(127, 0, 0, 1), quic: 443, udp: 40404},
    sequenceNumber: 7n,
  };
  const first = startRuntime(config, () => undefined);
  try {
    const identity = await first.identity;
    expect(identity.localEnr).toBeInstanceOf(Uint8Array);
    const enr = identity.localEnr;
    if (!enr) throw new Error("Missing ENR");
    expect(Buffer.from(enr).includes(Buffer.from([0x84, 0x71, 0x75, 0x69, 0x63, 0x82, 0x01, 0xbb]))).toBe(true);
    const secondConfig = applicationConfig();
    secondConfig.identitySecretKey[31] = 2;
    secondConfig.discovery = {...config.discovery, bootstrapEnrs: [enr.slice()]};
    const second = await startPeer(secondConfig);
    secondConfig.discovery.bootstrapEnrs[0].fill(0);
    try {
      const secondIdentity = await second.identity;
      expect(secondIdentity.localEnr).toBeInstanceOf(Uint8Array);
    } finally {
      await second.close();
    }
  } finally {
    await first.close();
  }
}, 20000);

it.each([17, 64])("accepts a bounded discovery bootstrap list of %i entries", async (count) => {
  const source = await startPeer(discoveryConfig());
  const enr = source.identity.localEnr;
  await source.stop();
  if (!enr) throw new Error("Missing ENR");
  const config = discoveryConfig();
  config.identitySecretKey[31] = 2;
  config.discovery.bootstrapEnrs = Array.from({length: count}, () => enr.slice());
  const runtime = startRuntime(config);
  try {
    expect(runtime.state).toBe("running");
    expect(runtime.identity.localEnr).toBeInstanceOf(Uint8Array);
  } finally {
    await runtime.close();
  }
  expect(runtime.diagnostics().liveNativeRequestedBytes).toBe(0);
}, 20000);

it("starts wildcard discovery without advertised addresses", async () => {
  const config = applicationConfig();
  if (!("address" in config.bind)) throw new Error("Expected a single bind address");
  config.bind.address.fill(0);
  config.discovery = {
    advertisement: null,
    bind: {address: new Uint8Array(4), family: 4, port: 0},
    bootstrapEnrs: [],
    fixed: {},
    sequenceNumber: 1n,
  };
  const runtime = startRuntime(config);
  try {
    const identity = await runtime.getIdentity();
    expect(identity.localEnr).toBeInstanceOf(Uint8Array);
    const intent = localIntent(config);
    intent.update.local.metadata.attnets[0] = 1;
    await runtime.applyIntent(intent, config.initialSlot);
    expect((await runtime.getIdentity()).localEnr).not.toEqual(identity.localEnr);
  } finally {
    await runtime.close();
  }
}, 20000);

it("publishes copied peer observations without repeating unread notifications", async () => {
  const {Child} = await import("../../test/interop/child.mjs");
  const {multiaddr} = await import("@multiformats/multiaddr");
  const {setTimeout: delay} = await import("node:timers/promises");
  const config = applicationConfig();
  config.initialSlot = 0x08070605n;
  configureChain({BLOB_SCHEDULE: [], ELECTRA_FORK_EPOCH: Infinity, FULU_FORK_EPOCH: Infinity});
  config.local.status.headSlot = config.initialSlot;
  config.local.status.finalizedEpoch = 0x01020304n;
  config.local.status.finalizedRoot = Uint8Array.from({length: 32}, (_, i) => i);
  config.local.status.headRoot = Uint8Array.from({length: 32}, (_, i) => 255 - i);
  let notifications = 0;
  let workAvailable: () => void = () => undefined;
  const pending = new Promise<void>((resolve) => {
    workAvailable = resolve;
  });
  const runtime = startRuntime(config, () => {
    notifications++;
    workAvailable();
  });
  const remote = new Child("native-runtime-peer", process.execPath, [
    "--import",
    "tsx",
    "test/interop/libp2p_peer.mjs",
    "v12",
    "managed",
    Buffer.from(requestForks[0].digest).toString("hex"),
  ]);
  try {
    const identity = await runtime.identity;
    const address = multiaddr(identity.localMultiaddr).toString();
    await remote.command("dial", {address});
    await remote.command("control", {address, protocol: "/eth2/beacon_chain/req/status/1/ssz_snappy"});
    await Promise.race([
      pending,
      delay(3000).then(async () => {
        throw new Error(
          `Peer observation timeout ${JSON.stringify(runtime.diagnostics(), (_, value) => (typeof value === "bigint" ? value.toString() : value))} remote=${JSON.stringify(await remote.command("managedSnapshot"))}`
        );
      }),
    ]);
    const before = notifications;
    await delay(250);
    expect(notifications).toBe(before);
    const {networkBindings: addon} = await import("./utils/network-bindings.js");
    if (typeof addon.networkTestFail === "function") {
      const queued = runtime.diagnostics().peerLaneOccupied;
      addon.networkTestFail("drain_copy");
      expect(() => runtime.drainPeers(32)).toThrow("NetworkResultAllocationFailed");
      expect(runtime.diagnostics().peerLaneOccupied).toBeGreaterThanOrEqual(queued);
    }
    const batch = runtime.drainPeers(32);
    expect(Object.getOwnPropertyDescriptor(batch, "events")).toMatchObject({
      configurable: true,
      enumerable: true,
      value: batch.events,
      writable: true,
    });
    expect(Object.getOwnPropertyDescriptor(batch.events, "0")?.value).toBe(batch.events[0]);
    expect(Object.getOwnPropertyDescriptor(batch.events[0], "type")?.value).toBe(batch.events[0].type);
    const ready = batch.events.find((event) => event.type === "ready");
    expect(ready).toBeDefined();
    if (!ready || ready.type !== "ready") throw new Error("Missing peerReady");
    expect(ready.state).not.toHaveProperty("peer");
    expect(typeof ready.state.identity).toBe("string");
    const retained = ready.state.identity.slice();
    await runtime.close();
    expect(ready.state.identity).toEqual(retained);
  } finally {
    await remote.stop();
    await runtime.close();
  }
}, 20000);

it("rejects a bootstrap with an invalid signature before starting", async () => {
  const config = discoveryConfig();
  const source = await startPeer(config);
  const corrupt = source.identity.localEnr;
  await source.stop();
  if (!corrupt) throw new Error("Missing ENR");
  corrupt[6] ^= 1;
  config.discovery.bootstrapEnrs = [corrupt];
  expect(() => startRuntime(config)).toThrow("InvalidSignature");
});
