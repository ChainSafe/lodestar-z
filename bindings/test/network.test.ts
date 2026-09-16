import {execFileSync} from "node:child_process";
import {privateKeyFromRaw} from "@libp2p/crypto/keys";
import {expect, it} from "vitest";
import {createNativeNetworkApplicationRuntime} from "../src/network.js";
import {applicationConfig, localIntent} from "./utils/network.js";

it("owns a real native socket and releases it on idempotent close", async () => {
  const config = applicationConfig();
  const expectedPeerId = privateKeyFromRaw(config.identitySecretKey).publicKey.toMultihash().bytes;
  const runtime = createNativeNetworkApplicationRuntime(config, () => undefined);
  const terminal = runtime.closed;
  try {
    const identity = await runtime.ready;
    expect(identity.peerId).toEqual(expectedPeerId);
    expect(identity.localEndpoint.port).toBeGreaterThan(0);
    expect(runtime.state).toBe("prepared");
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
  const expected = privateKeyFromRaw(config.identitySecretKey).publicKey.toMultihash().bytes;
  const intent = localIntent(config);
  const runtime = createNativeNetworkApplicationRuntime(config, () => undefined);
  config.identitySecretKey.fill(0);
  if (!("address" in config.bind)) throw new Error("Expected a single bind address");
  config.bind.address.fill(0);
  config.local.status.forkDigest.fill(99);
  config.local.fork.digest.fill(99);
  config.requestForks[0].digest.fill(99);
  try {
    const identity = await runtime.ready;
    expect(identity.peerId).toEqual(expected);
    expect(await runtime.applyIntent(intent, 101n)).toMatchObject({slot: 101n});
    await expect(runtime.applyIntent(intent, 100n)).rejects.toThrow("ClockRegression");
    expect(() => runtime.applyIntent(intent, -1n)).toThrow("InvalidNetworkInteger");
    expect(() => runtime.applyIntent(intent, 1n << 64n)).toThrow("InvalidNetworkInteger");
    expect(identity.peerId).toEqual(expected);
  } finally {
    await runtime.close();
  }
  expect(() => runtime.applyIntent(intent, 102n)).toThrow("NetworkClosed");
}, 20000);

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
      c.gossipPolicy.score.appWeight = Number.POSITIVE_INFINITY;
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
  [
    "duplicate fork",
    (c: ReturnType<typeof applicationConfig>) => {
      c.requestForks = [...c.requestForks, c.requestForks[0]];
    },
    "InvalidNetworkConfig",
  ],
] as const)("rejects %s before startup", (_name, mutate, code) => {
  const config = applicationConfig();
  mutate(config);
  expect(() => createNativeNetworkApplicationRuntime(config, () => undefined)).toThrow(code);
});

it("reserves only four active owners and releases capacity on close", async () => {
  const runtimes = Array.from({length: 4}, () =>
    createNativeNetworkApplicationRuntime(applicationConfig(), () => undefined)
  );
  try {
    await Promise.all(runtimes.map((runtime) => runtime.ready));
    expect(() => createNativeNetworkApplicationRuntime(applicationConfig(), () => undefined)).toThrow(
      "NetworkInstanceLimit"
    );
    await runtimes[0].close();
    const replacement = createNativeNetworkApplicationRuntime(applicationConfig(), () => undefined);
    try {
      await replacement.ready;
    } finally {
      await replacement.close();
    }
    expect((await runtimes[1].getIdentity()).peerId).toHaveLength(39);
  } finally {
    await Promise.all(runtimes.map((runtime) => runtime.close()));
  }
}, 30000);

it("settles immediate close coherently whichever startup outcome wins", async () => {
  const runtime = createNativeNetworkApplicationRuntime(applicationConfig(), () => undefined);
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
  const closing = runtime.close();
  expect(runtime.close()).toBe(closing);
  const outcome = await ready;
  expect(["ready", "AbortError"]).toContain(outcome);
  expect(await closing).toEqual({reason: outcome === "ready" ? "requested" : "startupCancelled"});
  expect(settlements).toBe(1);
  expect(runtime.state).toBe("closed");
}, 20000);

it("rejects every invalid drain limit", async () => {
  const runtime = createNativeNetworkApplicationRuntime(applicationConfig(), () => undefined);
  try {
    await runtime.ready;
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
  const output = execFileSync(process.execPath, ["--expose-gc", "bindings/test/fixtures/network-lifecycle.mjs", mode], {
    encoding: "utf8",
    timeout: 10000,
  });
  expect(output).toContain(mode === "gc" ? "gc-rebound" : mode === "exit" ? "ready-exit" : "promises-settled");
}, 15000);

it("releases live requests, incoming cells and gossip batches on worker termination", () => {
  const output = execFileSync(process.execPath, ["bindings/test/fixtures/network-worker-resources.mjs"], {
    encoding: "utf8",
    timeout: 20000,
  });
  expect(output).toContain("live-worker-resources-released");
}, 25000);

it("survives abrupt teardown of a second Node environment", async () => {
  const {Worker} = await import("node:worker_threads");
  const runtime = createNativeNetworkApplicationRuntime(applicationConfig(), () => undefined);
  const worker = new Worker(new URL("./fixtures/network-worker.mjs", import.meta.url));
  try {
    await runtime.ready;
    const port = await new Promise<number>((resolve, reject) => {
      worker.once("message", resolve);
      worker.once("error", reject);
    });
    await worker.terminate();
    expect((await runtime.getIdentity()).peerId).toHaveLength(39);
    execFileSync(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        `import {createSocket} from 'node:dgram'; const socket = createSocket('udp4'); socket.on('error', () => process.exit(1)); socket.bind(${port}, '127.0.0.1', () => socket.close());`,
      ],
      {timeout: 5000}
    );
  } finally {
    await worker.terminate();
    await runtime.close();
  }
}, 20000);

it("gates raw reentrant prepare and close before config getters execute", async () => {
  const {networkBindings: addon} = await import("./utils/network-bindings.js");
  const raw = new addon.NativeNetworkRuntime();
  const config = applicationConfig();
  Object.defineProperty(config, "profile", {
    enumerable: true,
    get() {
      expect(() => raw.prepare(applicationConfig(), () => undefined)).toThrow("NetworkAlreadyStarted");
      raw.close();
      return "small";
    },
  });
  expect(() => raw.prepare(config, () => undefined)).toThrow("NetworkClosed");
  expect(() => raw.prepare(applicationConfig(), () => undefined)).toThrow("NetworkAlreadyStarted");
  const runtime = createNativeNetworkApplicationRuntime(applicationConfig(), () => undefined);
  try {
    await runtime.ready;
  } finally {
    await runtime.close();
  }
}, 20000);

it("initializes signed discovery without waiting for bootstrap reachability", async () => {
  const config = applicationConfig();
  config.discovery = {
    advertisement: {ip4: Uint8Array.of(127, 0, 0, 1), quic: 443, udp: 40404},
    bind: {address: Uint8Array.of(127, 0, 0, 1), family: 4, port: 0},
    bootstrapEnrs: [],
    sequenceNumber: 7n,
  };
  const first = createNativeNetworkApplicationRuntime(config, () => undefined);
  try {
    const identity = await first.ready;
    expect(identity.localEnr).toBeInstanceOf(Uint8Array);
    const enr = identity.localEnr;
    if (!enr) throw new Error("Missing ENR");
    expect(Buffer.from(enr).includes(Buffer.from([0x84, 0x71, 0x75, 0x69, 0x63, 0x82, 0x01, 0xbb]))).toBe(true);
    const secondConfig = applicationConfig();
    secondConfig.identitySecretKey[31] = 2;
    secondConfig.discovery = {...config.discovery, bootstrapEnrs: [enr.slice()]};
    const second = createNativeNetworkApplicationRuntime(secondConfig, () => undefined);
    secondConfig.discovery.bootstrapEnrs[0].fill(0);
    try {
      const secondIdentity = await second.ready;
      expect(secondIdentity.localEnr).toBeInstanceOf(Uint8Array);
    } finally {
      await second.close();
    }
    const bad = applicationConfig();
    const corrupt = enr.slice();
    corrupt[6] ^= 1;
    bad.discovery = {...config.discovery, bootstrapEnrs: [corrupt]};
    expect(() => createNativeNetworkApplicationRuntime(bad, () => undefined)).toThrow("InvalidSignature");
  } finally {
    await first.close();
  }
}, 20000);

it("fails wildcard discovery advertisement omissions cleanly", async () => {
  const config = applicationConfig();
  if (!("address" in config.bind)) throw new Error("Expected a single bind address");
  config.bind.address.fill(0);
  config.discovery = {
    advertisement: null,
    bind: {address: new Uint8Array(4), family: 4, port: 0},
    bootstrapEnrs: [],
    sequenceNumber: 1n,
  };
  expect(() => createNativeNetworkApplicationRuntime(config, () => undefined)).toThrow("InvalidAdvertisement");
}, 20000);

it("publishes copied peer observations without repeating unread notifications", async () => {
  const {Child} = await import("../../test/interop/child.mjs");
  const {multiaddr} = await import("@multiformats/multiaddr");
  const {setTimeout: delay} = await import("node:timers/promises");
  const config = applicationConfig();
  config.initialSlot = 0x08070605n;
  config.local.status.headSlot = config.initialSlot;
  config.local.status.finalizedEpoch = 0x01020304n;
  config.local.status.finalizedRoot = Uint8Array.from({length: 32}, (_, i) => i);
  config.local.status.headRoot = Uint8Array.from({length: 32}, (_, i) => 255 - i);
  let notifications = 0;
  let readable: () => void = () => undefined;
  const pending = new Promise<void>((resolve) => {
    readable = resolve;
  });
  const runtime = createNativeNetworkApplicationRuntime(config, () => {
    notifications++;
    readable();
  });
  const remote = new Child("native-runtime-peer", process.execPath, ["test/interop/libp2p_peer.mjs", "v12", "managed"]);
  try {
    const identity = await runtime.ready;
    await runtime.applyIntent(localIntent(config), config.initialSlot);
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
      expect(() => runtime.drainPeers(32)).toThrow("InjectedNetworkFailure");
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
    expect(ready.state.peer.generation).toBeGreaterThan(0n);
    expect(ready.state.identity.length).toBe(39);
    const retained = ready.state.identity.slice();
    await runtime.close();
    expect(ready.state.identity).toEqual(retained);
  } finally {
    await remote.stop();
    await runtime.close();
  }
}, 20000);
