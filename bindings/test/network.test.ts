import {execFileSync} from "node:child_process";
import {setTimeout as delay} from "node:timers/promises";
import {privateKeyFromRaw} from "@libp2p/crypto/keys";
import {peerIdFromPublicKey} from "@libp2p/peer-id";
import {expect, it, vi} from "vitest";
import {type NativeAction, type NativeExchangeDemand, initializeNativeNetworkRuntime} from "../src/network.js";
import {
  applicationConfig,
  capacity,
  configureChain,
  discoveryConfig,
  exchange,
  gossipAll,
  localIntent,
  requestForks,
  runtimeReleased,
  settleOnly,
  startRuntime,
  subscriptions,
  topicName,
} from "./utils/network.js";
import {BLOCKS} from "./utils/network-incoming.js";
import {startPeer} from "./utils/network-peer.js";

function report(peerId: string): NativeAction {
  return {action: "fatal", count: 1, peerId, type: "reportPeer"};
}

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
      expect(() => runtime.exchange([report(invalid)], settleOnly)).toThrow("InvalidNetworkPeerId");
      expect(() => runtime.connect(invalid, [identity.localEndpoint], 1000n)).toThrow("InvalidNetworkPeerId");
      expect(() => runtime.reStatusPeers([invalid])).toThrow("InvalidNetworkPeerId");
      expect(() =>
        runtime.request(invalid, "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy", new Uint8Array(0))
      ).toThrow("InvalidNetworkPeerId");
    }
    for (const invalid of [null, 1, new Uint8Array(39), {toString: () => identity.peerId}]) {
      expect(() => runtime.exchange([report(invalid as unknown as string)], settleOnly)).toThrow(
        "InvalidNetworkPeerId"
      );
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
  const runtime = startRuntime(config);
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
  const runtime = startRuntime(config);
  try {
    expect(runtime.state).toBe("running");
    expect((await runtime.getGossipDiagnostics()).topics.some((topic) => topic.subscribed)).toBe(false);
    expect(exchange(runtime, {...gossipAll, servingStarts: 8})).toMatchObject({
      checks: [],
      gossip: null,
      serving: [],
    });
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

it("rejects another initialization while one is live and accepts one after release", async () => {
  let runtime: ReturnType<typeof startRuntime> | null = startRuntime(applicationConfig());
  expect(runtime.state).toBe("running");
  expect(typeof runtime.identity.peerId).toBe("string");
  expect(() => startRuntime(applicationConfig())).toThrow("NetworkAlreadyInitialized");
  expect((await runtime.getIdentity()).peerId).toEqual(runtime.identity.peerId);
  await runtime.close();
  runtime = null;
  await runtimeReleased();
  const next = startRuntime(applicationConfig());
  expect(next.state).toBe("running");
  await next.close();
});

it("joins immediately after initialization and closes idempotently", async () => {
  const runtime = startRuntime(applicationConfig());
  const closing = runtime.close();
  expect(runtime.close()).toBe(closing);
  expect(await closing).toEqual({reason: "requested"});
  expect(runtime.state).toBe("closed");
  expect(runtime.diagnostics().liveNativeRequestedBytes).toBe(0);
});

it("rejects every invalid exchange demand, oversized batch and nested exchange before applying anything", async () => {
  let notifications = 0;
  const runtime = startRuntime(applicationConfig(), () => {
    notifications++;
  });
  try {
    await runtime.identity;
    expect(exchange(runtime, settleOnly).more).toBe(false);
    const invalid: [Partial<Record<keyof NativeExchangeDemand, unknown>>, string][] = [
      ...[-1, 0.5, 65, Number.NaN, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 1].map(
        (peers): [Partial<Record<keyof NativeExchangeDemand, unknown>>, string] => [{peers}, "InvalidNetworkInteger"]
      ),
      ...[0, -1, 0.5, 257, Number.NaN].map(
        (settleCells): [Partial<Record<keyof NativeExchangeDemand, unknown>>, string] => [
          {settleCells},
          "InvalidNetworkInteger",
        ]
      ),
      [{servingStarts: 9}, "InvalidNetworkInteger"],
      [{checks: 65}, "InvalidNetworkInteger"],
      [{messages: 65}, "InvalidNetworkInteger"],
      [{bytes: 16 * 1024 * 1024 + 1}, "InvalidNetworkInteger"],
      [{claimOrdinary: 1}, "InvalidNetworkConfig"],
      [{capacity: {ordinary: true, serving: 33}}, "InvalidNetworkInteger"],
      [{capacity: {ordinary: "yes", serving: 1}}, "InvalidNetworkConfig"],
      [{capacity: []}, "InvalidNetworkConfig"],
    ];
    for (const [fields, code] of invalid)
      expect(() => runtime.exchange([], {...settleOnly, ...fields} as NativeExchangeDemand)).toThrow(code);
    const recheck: NativeAction = {type: "recheck"};
    expect(() =>
      runtime.exchange(
        Array.from({length: 257}, () => recheck),
        settleOnly
      )
    ).toThrow("InvalidNetworkActions");
    expect(() => runtime.exchange({} as NativeAction[], settleOnly)).toThrow("InvalidNetworkActions");
    const nested = {
      ...settleOnly,
      get peers() {
        runtime.exchange([], settleOnly);
        return 0;
      },
    };
    expect(() => runtime.exchange([], nested)).toThrow("NetworkExchangeReentered");
    // The rejections left native armed, so the next completion notifies.
    const before = notifications;
    await runtime.getIdentity();
    expect(notifications).toBe(before + 1);
    // A full batch applies, and the caller stays usable after every rejection.
    expect(
      exchange(
        runtime,
        {...settleOnly, capacity, peers: 64},
        Array.from({length: 256}, () => recheck)
      )
    ).toMatchObject({
      more: false,
      peers: [],
    });
    expect(Object.isFrozen(exchange(runtime, settleOnly))).toBe(true);
  } finally {
    await runtime.close();
  }
}, 20000);

it.each([1, 3] as const)("escalation trigger %i terminates the process through fatalError", (trigger) => {
  const script = `import {initializeNativeNetworkRuntime} from "./bindings/src/network.js";
    import {applicationConfig} from "./bindings/test/utils/network.ts";
    const runtime = initializeNativeNetworkRuntime(applicationConfig(), () => undefined);
    runtime.fail(${trigger}, "test");
    console.log("survived");`;
  let failure: {status: number | null; signal: string | null; stdout: string; stderr: string} | undefined;
  try {
    execFileSync(process.execPath, ["--import", "tsx", "--input-type=module", "-e", script], {
      encoding: "utf8",
      stdio: "pipe",
      timeout: 20000,
    });
  } catch (error) {
    failure = error as typeof failure;
  }
  expect(failure?.signal).toBe("SIGABRT");
  expect(failure?.stdout).not.toContain("survived");
  expect(failure?.stderr).toContain(`native network bridge escalation trigger ${trigger}: test`);
}, 30000);

it.each([
  ["gc", "gc-rebound"],
  ["exit", "ready-exit"],
  ["promises", "promises-settled"],
  ["await-close", "close-awaited"],
])(
  "finishes bounded %s subprocess lifecycle",
  (mode, expected) => {
    const output = execFileSync(
      process.execPath,
      ["--import", "tsx", "--expose-gc", "bindings/test/fixtures/network-lifecycle.mjs", mode],
      {
        encoding: "utf8",
        timeout: 10000,
      }
    );
    expect(output).toContain(expected);
  },
  15000
);

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
  expect(() => raw.initialize(applicationConfig(), () => undefined)).toThrow("NetworkClosed");
  const runtime = startRuntime(applicationConfig());
  expect(runtime.state).toBe("running");
  await runtime.close();
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
    const result = exchange(runtime, {...settleOnly, peers: 32});
    expect(Object.getOwnPropertyDescriptor(result, "peers")).toMatchObject({
      configurable: true,
      enumerable: true,
      value: result.peers,
      writable: true,
    });
    expect(Object.getOwnPropertyDescriptor(result.peers, "0")?.value).toBe(result.peers[0]);
    expect(Object.getOwnPropertyDescriptor(result.peers[0], "type")?.value).toBe(result.peers[0].type);
    const ready = result.peers.find((event) => event.type === "ready");
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

it("settles results only in an exchange and notifies once until an exchange finds nothing queued", async () => {
  const config = applicationConfig();
  let notifications = 0;
  const runtime = initializeNativeNetworkRuntime(config, () => {
    notifications++;
  });
  const drain = () => runtime.exchange([], settleOnly).more;
  const watch = (promise: Promise<unknown>) => {
    let settled = false;
    promise.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      }
    );
    return () => settled;
  };
  const closing = watch(runtime.closed);
  try {
    const intent = runtime.applyIntent(localIntent(config), config.initialSlot);
    const intentSettled = watch(intent);
    await vi.waitFor(() => expect(notifications).toBe(1));
    const identity = runtime.getIdentity();
    await delay(100);
    expect(notifications).toBe(1);
    expect(intentSettled()).toBe(false);
    const identitySettled = watch(identity);
    expect(runtime.exchange([], settleOnly).more).toBe(false);
    await delay(0);
    expect([intentSettled(), identitySettled()]).toEqual([true, true]);
    expect(Object.isFrozen(runtime.exchange([], settleOnly))).toBe(true);
    expect((await intent).slot).toBe(config.initialSlot);
    expect((await identity).peerId).toBe(runtime.identity.peerId);
    const pull = runtime.request(runtime.identity.peerId, BLOCKS, new Uint8Array(32)).next();
    const pullSettled = watch(pull);
    await vi.waitFor(() => expect(notifications).toBe(3));
    await delay(20);
    expect(pullSettled()).toBe(false);
    for (let pass = 0; pass < 8 && drain(); pass++);
    await expect(pull).rejects.toMatchObject({reason: "disconnected"});
  } finally {
    runtime.close();
    for (let i = 0; i < 400 && !closing(); i++) {
      await delay(5);
      drain();
    }
  }
  expect(await runtime.closed).toEqual({reason: "requested"});
  expect(runtime.exchange([], settleOnly)).toMatchObject({more: false});
}, 20000);
