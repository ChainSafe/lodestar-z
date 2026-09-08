import {execFileSync} from "node:child_process";
import {privateKeyFromRaw} from "@libp2p/crypto/keys";
import {expect, it} from "vitest";
import {createNativeNetworkRuntime} from "../src/network.js";
import {networkConfig} from "./utils/network.js";

it("owns a real native socket and releases it on idempotent close", async () => {
  const config = networkConfig();
  const expectedPeerId = privateKeyFromRaw(config.identitySecretKey).publicKey.toMultihash().bytes;
  const runtime = createNativeNetworkRuntime(config, () => undefined);
  const terminal = runtime.closed;
  try {
    const identity = await runtime.ready;
    expect(identity.peerId).toEqual(expectedPeerId);
    expect(identity.localEndpoint.port).toBeGreaterThan(0);
    expect(runtime.state).toBe("running");
    expect(runtime.diagnostics().nativeRequestedBytes).toBeGreaterThan(0);
    expect(runtime.setCurrentSlot(101n)).toBeGreaterThan(0n);
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

it("copies inputs before returning and accepts exact slot revisions", async () => {
  const config = networkConfig();
  const expected = privateKeyFromRaw(config.identitySecretKey).publicKey.toMultihash().bytes;
  const runtime = createNativeNetworkRuntime(config, () => undefined);
  config.identitySecretKey.fill(0);
  config.bind.address.fill(0);
  config.local.status.forkDigest.fill(99);
  config.local.fork.digest.fill(99);
  config.requestForks[0].digest.fill(99);
  try {
    const identity = await runtime.ready;
    expect(identity.peerId).toEqual(expected);
    for (let i = 1; i <= 10000; i++) expect(runtime.setCurrentSlot(100n + BigInt(i))).toBe(BigInt(i));
    expect(() => runtime.setCurrentSlot(100n)).toThrow("ClockRegression");
    expect(() => runtime.setCurrentSlot(-1n)).toThrow("InvalidNetworkInteger");
    expect(() => runtime.setCurrentSlot(1n << 64n)).toThrow("InvalidNetworkInteger");
    expect(runtime.setCurrentSlot((1n << 64n) - 1n)).toBe(10001n);
    expect(identity.peerId).toEqual(expected);
  } finally {
    await runtime.close();
  }
  expect(() => runtime.setCurrentSlot((1n << 64n) - 1n)).toThrow("NetworkClosed");
}, 20000);

it.each([
  [
    "key length",
    (c: ReturnType<typeof networkConfig>) => {
      c.identitySecretKey = new Uint8Array(31);
    },
    "InvalidNetworkBytes",
  ],
  [
    "fractional port",
    (c: ReturnType<typeof networkConfig>) => {
      c.bind.port = 0.5;
    },
    "InvalidNetworkInteger",
  ],
  [
    "infinite score",
    (c: ReturnType<typeof networkConfig>) => {
      c.gossipPolicy.score.appWeight = Number.POSITIVE_INFINITY;
    },
    "InvalidNetworkConfig",
  ],
  [
    "unknown timer",
    (c: ReturnType<typeof networkConfig>) => {
      Object.assign(c.gossipPolicy, {unknown: 1});
    },
    "InvalidNetworkConfig",
  ],
  [
    "missing timer",
    (c: ReturnType<typeof networkConfig>) => {
      Reflect.deleteProperty(c.gossipPolicy, "txTimeoutMs");
    },
    "InvalidNetworkInteger",
  ],
  [
    "negative bigint",
    (c: ReturnType<typeof networkConfig>) => {
      c.initialSlot = -1n;
    },
    "InvalidNetworkInteger",
  ],
  [
    "overflow bigint",
    (c: ReturnType<typeof networkConfig>) => {
      c.initialSlot = 1n << 64n;
    },
    "InvalidNetworkInteger",
  ],
  [
    "reserved syncnet",
    (c: ReturnType<typeof networkConfig>) => {
      c.local.metadata.syncnets = 16;
    },
    "InvalidNetworkInteger",
  ],
  [
    "duplicate fork",
    (c: ReturnType<typeof networkConfig>) => {
      c.requestForks = [...c.requestForks, c.requestForks[0]];
    },
    "InvalidNetworkConfig",
  ],
] as const)("rejects %s before startup", (_name, mutate, code) => {
  const config = networkConfig();
  mutate(config);
  expect(() => createNativeNetworkRuntime(config, () => undefined)).toThrow(code);
});

it("reserves only four active owners and releases capacity on close", async () => {
  const runtimes = Array.from({length: 4}, () => createNativeNetworkRuntime(networkConfig(), () => undefined));
  try {
    await Promise.all(runtimes.map((runtime) => runtime.ready));
    expect(() => createNativeNetworkRuntime(networkConfig(), () => undefined)).toThrow("NetworkInstanceLimit");
    await runtimes[0].close();
    const replacement = createNativeNetworkRuntime(networkConfig(), () => undefined);
    try {
      await replacement.ready;
    } finally {
      await replacement.close();
    }
    expect(runtimes[1].setCurrentSlot(102n)).toBe(1n);
  } finally {
    await Promise.all(runtimes.map((runtime) => runtime.close()));
  }
}, 30000);

it("settles immediate close coherently whichever startup outcome wins", async () => {
  const runtime = createNativeNetworkRuntime(networkConfig(), () => undefined);
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
  const runtime = createNativeNetworkRuntime(networkConfig(), () => undefined);
  try {
    await runtime.ready;
    for (const limit of [0, -1, 0.5, 33, Number.NaN, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 1]) {
      expect(() => runtime.drain(limit)).toThrow("InvalidDrainLimit");
    }
    expect(runtime.drain(1)).toEqual({dropped: 0n, events: [], more: false});
    expect(runtime.drain(32)).toEqual({dropped: 0n, events: [], more: false});
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

it("survives abrupt teardown of a second Node environment", async () => {
  const {Worker} = await import("node:worker_threads");
  const runtime = createNativeNetworkRuntime(networkConfig(), () => undefined);
  const worker = new Worker(new URL("./fixtures/network-worker.mjs", import.meta.url));
  try {
    await runtime.ready;
    const port = await new Promise<number>((resolve, reject) => {
      worker.once("message", resolve);
      worker.once("error", reject);
    });
    await worker.terminate();
    expect(runtime.setCurrentSlot(101n)).toBe(1n);
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

it("gates raw reentrant start and close before config getters execute", async () => {
  const {default: addon} = await import("../src/bindings.js");
  const raw = new addon.NativeNetworkRuntime();
  const config = networkConfig();
  Object.defineProperty(config, "profile", {
    enumerable: true,
    get() {
      expect(() => raw.start(networkConfig(), () => undefined)).toThrow("NetworkAlreadyStarted");
      raw.close();
      return "small";
    },
  });
  expect(() => raw.start(config, () => undefined)).toThrow("NetworkClosed");
  expect(() => raw.start(networkConfig(), () => undefined)).toThrow("NetworkAlreadyStarted");
  const runtime = createNativeNetworkRuntime(networkConfig(), () => undefined);
  try {
    await runtime.ready;
  } finally {
    await runtime.close();
  }
}, 20000);

it("initializes signed discovery without waiting for bootstrap reachability", async () => {
  const config = networkConfig();
  config.discovery = {
    advertisement: {ip4: Uint8Array.of(127, 0, 0, 1), quic: 443, udp: 40404},
    bind: {address: Uint8Array.of(127, 0, 0, 1), family: 4, port: 0},
    bootstrapEnrs: [],
    sequenceNumber: 7n,
  };
  const first = createNativeNetworkRuntime(config, () => undefined);
  try {
    const identity = await first.ready;
    expect(identity.localEnr).toBeInstanceOf(Uint8Array);
    const enr = identity.localEnr;
    if (!enr) throw new Error("Missing ENR");
    expect(Buffer.from(enr).includes(Buffer.from([0x84, 0x71, 0x75, 0x69, 0x63, 0x82, 0x01, 0xbb]))).toBe(true);
    const secondConfig = networkConfig();
    secondConfig.identitySecretKey[31] = 2;
    secondConfig.discovery = {...config.discovery, bootstrapEnrs: [enr.slice()]};
    const second = createNativeNetworkRuntime(secondConfig, () => undefined);
    secondConfig.discovery.bootstrapEnrs[0].fill(0);
    try {
      const secondIdentity = await second.ready;
      expect(secondIdentity.localEnr).toBeInstanceOf(Uint8Array);
    } finally {
      await second.close();
    }
    const bad = networkConfig();
    const corrupt = enr.slice();
    corrupt[6] ^= 1;
    bad.discovery = {...config.discovery, bootstrapEnrs: [corrupt]};
    const rejected = createNativeNetworkRuntime(bad, () => undefined);
    await expect(rejected.ready).rejects.toThrow("InvalidSignature");
    expect(await rejected.close()).toEqual({reason: "failed"});
  } finally {
    await first.close();
  }
}, 20000);

it("fails wildcard discovery advertisement omissions cleanly", async () => {
  const config = networkConfig();
  config.bind.address.fill(0);
  config.discovery = {
    advertisement: null,
    bind: {address: new Uint8Array(4), family: 4, port: 0},
    bootstrapEnrs: [],
    sequenceNumber: 1n,
  };
  const runtime = createNativeNetworkRuntime(config, () => undefined);
  await expect(runtime.ready).rejects.toThrow("InvalidAdvertisement");
  expect(await runtime.close()).toEqual({reason: "failed"});
}, 20000);

it("publishes copied peer observations without repeating unread notifications", async () => {
  const {Child} = await import("../../test/interop/child.mjs");
  const {multiaddr} = await import("@multiformats/multiaddr");
  const {setTimeout: delay} = await import("node:timers/promises");
  const config = networkConfig();
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
  const runtime = createNativeNetworkRuntime(config, () => {
    notifications++;
    readable();
  });
  const remote = new Child("native-runtime-peer", process.execPath, ["test/interop/libp2p_peer.mjs", "v12", "managed"]);
  try {
    const identity = await runtime.ready;
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
    const {default: addon} = await import("../src/bindings.js");
    if (typeof addon.networkTestFail === "function") {
      const queued = runtime.diagnostics().queuedEvents;
      addon.networkTestFail("drain_copy");
      expect(() => runtime.drain(32)).toThrow("InjectedNetworkFailure");
      expect(runtime.diagnostics().queuedEvents).toBeGreaterThanOrEqual(queued);
    }
    const batch = runtime.drain(32);
    expect(Object.getOwnPropertyDescriptor(batch, "events")).toMatchObject({
      configurable: true,
      enumerable: true,
      value: batch.events,
      writable: true,
    });
    expect(Object.getOwnPropertyDescriptor(batch.events, "0")?.value).toBe(batch.events[0]);
    expect(Object.getOwnPropertyDescriptor(batch.events[0], "type")?.value).toBe(batch.events[0].type);
    const ready = batch.events.find((event) => event.type === "peerReady");
    expect(ready).toBeDefined();
    if (!ready || ready.type !== "peerReady") throw new Error("Missing peerReady");
    expect(ready.peerGeneration).toBeGreaterThan(0n);
    expect(ready.peerId.length).toBe(39);
    const retained = ready.peerId.slice();
    await runtime.close();
    expect(ready.peerId).toEqual(retained);
  } finally {
    await remote.stop();
    await runtime.close();
  }
}, 20000);
