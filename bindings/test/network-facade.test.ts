import {setTimeout as delay} from "node:timers/promises";
import {expect, test, vi} from "vitest";
import type {
  GossipJob,
  IncomingRequest,
  NativeApplicationConfig,
  NativeHost,
  NativeLogRecord,
  NativeNetwork,
  Verdict,
} from "../src/network.js";
import {createNativeNetwork} from "../src/network.js";
import {runtimeOf} from "../src/network-runtime.js";
import {
  applicationConfig,
  childTestTimeout,
  gossipAll,
  localIntent,
  metricValue,
  runChild,
  subscriptions,
  topicName,
  unreachableConnect,
  waitForGossipReady,
} from "./utils/network.js";
import {BLOCKS} from "./utils/network-incoming.js";
import {type PeerRuntime, startPeer} from "./utils/network-peer.js";

const TOPIC = topicName();

function blockPayload(byte: number): Uint8Array {
  const bytes = new Uint8Array(4000).fill(byte);
  new DataView(bytes.buffer).setBigUint64(100, 100n, true);
  return bytes;
}

/** A host that takes nothing but what a test overrides. */
function host(overrides: Partial<NativeHost> = {}): NativeHost {
  return {
    capacity: () => ({ordinary: true, serving: 32}),
    checkDependencies: (checks) => checks.map(() => false),
    failed: () => undefined,
    logs: () => undefined,
    peers: () => undefined,
    serve: (request) => request.cancel(),
    validate: (job) => Promise.resolve(job.messages.map(() => "ignore" as const)),
    ...overrides,
  };
}

/**
 * Starts the facade under test and `count` subprocess peers, each connected to the facade alone as a direct peer, all
 * subscribed to the block topic.
 */
async function facadeWithPeers(
  networkHost: NativeHost,
  count: number,
  configure: (config: NativeApplicationConfig, index: number) => void = () => undefined
) {
  const configs = Array.from({length: count + 1}, (_, index) => {
    const config = applicationConfig();
    config.identitySecretKey[31] = index + 1;
    configure(config, index);
    return config;
  });
  const peers: PeerRuntime[] = [];
  let network: NativeNetwork | undefined;
  try {
    for (const config of configs.slice(1)) peers.push(await startPeer(config));
    network = createNativeNetwork(configs[0], networkHost);
    const remote = await network.getIdentity();
    const intent = (config: NativeApplicationConfig) => ({...localIntent(config), subscriptions: subscriptions(TOPIC)});
    await network.applyIntent(intent(configs[0]), configs[0].initialSlot);
    for (const [i, peer] of peers.entries()) {
      const identity = await peer.identity;
      await peer.applyIntent(intent(configs[i + 1]), configs[i + 1].initialSlot);
      await peer.connect(remote.peerId, [remote.localEndpoint], 5000n);
      await Promise.all([
        peer.addDirectPeer(remote.peerId, [remote.localEndpoint]),
        network.setDirectPeer(identity.peerId, [identity.localEndpoint]),
      ]);
    }
    const identities = await Promise.all(peers.map((peer) => peer.identity));
    await Promise.all([
      waitForGossipReady(
        network,
        identities.map(({peerId}) => peerId),
        [TOPIC],
        network.metrics.bind(network)
      ),
      ...peers.map((peer) => waitForGossipReady(peer, [remote.peerId], [TOPIC], () => peer.getMetrics())),
    ]);
    return {network, peers, remote};
  } catch (error) {
    await Promise.allSettled([network?.close(), ...peers.map((peer) => peer.stop())]);
    throw error;
  }
}

/** Takes the next gossip messages a subprocess peer received, ignoring each, until `count` arrived. */
async function received(peer: PeerRuntime, count: number): Promise<number[]> {
  const bytes: number[] = [];
  let verdicts: {handle: {index: number; generation: bigint}; type: "verdict"; verdict: "ignore"}[] = [];
  for (let i = 0; i < 1000 && bytes.length < count; i++) {
    const {gossip} = await peer.exchange(verdicts, gossipAll);
    verdicts = (gossip?.messages ?? []).map(({handle}) => ({handle, type: "verdict", verdict: "ignore"}));
    bytes.push(...(gossip?.messages ?? []).map(({data}) => data[0]));
    if (!gossip) await delay(5);
  }
  await peer.exchange(verdicts, gossipAll);
  return bytes;
}

test("a job's deferred handler runs only after the owner applied its verdicts, admitting forwarding", async () => {
  // More than one owner turn's 64 verdicts, and fewer rejects than a graylist costs.
  const COUNT = 80;
  const verdictOf = (byte: number): Verdict =>
    byte === 5 || byte === 45 ? "reject" : byte % 10 === 3 ? "ignore" : "accept";
  const accepted = [...Array(COUNT).keys()].filter((byte) => verdictOf(byte) === "accept");
  let network: NativeNetwork | undefined;
  const validated: number[] = [];
  const handled: number[] = [];
  const failures: {byte: number; code: unknown}[] = [];
  // Promises derived from the last job's report, which the test holds instead of the report.
  let closing: Promise<unknown>[] = [];
  const networkHost = host({
    validate(job: GossipJob) {
      const byte = job.messages[0].data[0];
      validated.push(byte);
      if (byte === COUNT) {
        const outcome = (promise: Promise<unknown>) =>
          promise.then(
            () => "resolved",
            (error: {code?: unknown}) => error.code
          );
        closing = [outcome(job.reported), outcome(Promise.all([delay(0), job.reported]))];
      }
      // As #9990 defers a handler to a later macrotask, and here also until the owner disposed of the job.
      void Promise.all([delay(0), job.reported]).then(
        () => handled.push(byte),
        (error) => failures.push({byte, code: (error as {code?: unknown}).code})
      );
      return Promise.resolve(job.messages.map(({data}) => verdictOf(data[0])));
    },
  });
  // The first peer publishes; the second receives what the facade forwards.
  const {network: facade, peers} = await facadeWithPeers(networkHost, 2, (config) => {
    config.gossipPolicy.processor.beacon_block.items = 256;
  });
  network = facade;
  const [publisher, receiver] = peers;
  try {
    const runtime = runtimeOf(network);
    if (!runtime) throw Error("Not a facade");
    runtime.holdVerdicts(true);
    for (let byte = 0; byte < COUNT; byte++)
      await publisher.publishGossip(TOPIC, blockPayload(byte), {allowZeroPeers: false});
    await vi.waitFor(() => expect(validated).toHaveLength(COUNT), {timeout: 10000});
    // Every verdict was reported and every handler's timer is due, but the owner holds the verdicts.
    await delay(50);
    expect(validated.slice().sort((a, b) => a - b)).toEqual([...Array(COUNT).keys()]);
    expect(handled).toEqual([]);
    runtime.holdVerdicts(false);
    await vi.waitFor(() => expect(handled).toHaveLength(COUNT), {timeout: 10000});
    expect(handled.slice().sort((a, b) => a - b)).toEqual([...Array(COUNT).keys()]);
    expect(failures).toEqual([]);
    // Application admitted each accepted message, and no other, for forwarding.
    expect((await received(receiver, accepted.length)).sort((a, b) => a - b)).toEqual(accepted);

    // Close prevents the owner from disposing of a held verdict: its report rejects and its handler never runs.
    runtime.holdVerdicts(true);
    await publisher.publishGossip(TOPIC, blockPayload(COUNT), {allowZeroPeers: false});
    await vi.waitFor(() => expect(closing).toHaveLength(2), {timeout: 5000});
    global.gc?.();
    // The facade stays reachable until close completes, so derivatives of the report settle as it does.
    expect(await network.close()).toEqual({reason: "requested"});
    expect(await Promise.all(closing)).toEqual(["NetworkClosed", "NetworkClosed"]);
    await vi.waitFor(() => expect(failures).toEqual([{byte: COUNT, code: "NetworkClosed"}]));
    expect(handled).toHaveLength(COUNT);
  } finally {
    await Promise.allSettled([network.close(), ...peers.map((peer) => peer.stop())]);
  }
}, 60000);

test("reports resolve through expiry and cell reuse", async () => {
  const handled: number[] = [];
  const failures: {byte: number; code: unknown}[] = [];
  const networkHost = host({
    async validate(job: GossipJob) {
      const byte = job.messages[0].data[0];
      void Promise.all([delay(0), job.reported]).then(
        () => handled.push(byte),
        (error) => failures.push({byte, code: (error as {code?: unknown}).code})
      );
      // Past the validation timeout, the owner expires the message and disposes of the late verdict.
      if (byte === 200) await delay(1300);
      return job.messages.map(() => "accept" as const);
    },
  });
  const {network, peers} = await facadeWithPeers(networkHost, 1, (config) => {
    config.gossipPolicy.validationTimeoutMs = 1000n;
  });
  const [publisher] = peers;
  try {
    // The block kind's eight cells are reused in order, so the ninth and tenth messages reuse cells with new
    // generations while earlier handles have been acknowledged.
    for (let byte = 1; byte <= 10; byte++) {
      await publisher.publishGossip(TOPIC, blockPayload(byte), {allowZeroPeers: false});
      await vi.waitFor(() => expect(handled).toContain(byte), {timeout: 5000});
    }
    expect(handled).toEqual([...Array(10).keys()].map((i) => i + 1));
    const accepted = () => metricValue(network.metrics(), 'gossipsub_accepted_messages_total{topic="beacon_block"}');
    await expect.poll(accepted, {timeout: 5000}).toBe(10);

    await publisher.publishGossip(TOPIC, blockPayload(200), {allowZeroPeers: false});
    await vi.waitFor(() => expect(handled).toContain(200), {timeout: 5000});
    // Close renders the owner's final counters, including disposition of the late verdict.
    await network.close();
    expect(accepted()).toBe(10);
    expect(failures).toEqual([]);
  } finally {
    await Promise.allSettled([network.close(), publisher.stop()]);
  }
}, 60000);

test("serving capacity stays charged after the stream closes until serve settles", async () => {
  let retire: () => void = () => undefined;
  const retired = new Promise<void>((resolve) => {
    retire = resolve;
  });
  let started: IncomingRequest | undefined;
  const networkHost = host({
    async serve(request) {
      started = request;
      await request.cancel();
      // Child work that outlives the stream.
      await retired;
    },
  });
  const {network, peers, remote} = await facadeWithPeers(networkHost, 1);
  const [client] = peers;
  try {
    const stream = client.request(remote.peerId, BLOCKS, new Uint8Array(32));
    const pending = stream.next().catch(() => undefined);
    await vi.waitFor(() => expect(started).toBeDefined(), {timeout: 5000});
    await pending;
    const retiring = () => metricValue(network.metrics(), "lodestar_native_reqresp_resources_retiring");
    await expect.poll(retiring, {timeout: 5000}).toBe(1);
    retire();
    await expect.poll(retiring, {timeout: 5000}).toBe(0);
  } finally {
    retire();
    await Promise.allSettled([network.close(), client.stop()]);
  }
}, 30000);

test("a serve that outlives the network's close retires quietly after it", async () => {
  let retire: () => void = () => undefined;
  const retired = new Promise<void>((resolve) => {
    retire = resolve;
  });
  let started: IncomingRequest | undefined;
  const errors: unknown[] = [];
  const networkHost = host({
    error: (error) => void errors.push(error),
    async serve(request) {
      started = request;
      await retired;
    },
  });
  const {network, peers, remote} = await facadeWithPeers(networkHost, 1);
  const [client] = peers;
  try {
    const stream = client.request(remote.peerId, BLOCKS, new Uint8Array(32));
    const pending = stream.next().catch(() => undefined);
    await vi.waitFor(() => expect(started).toBeDefined(), {timeout: 5000});
    // Close does not wait for the host's work, whose stream it ends.
    expect(await network.close()).toEqual({reason: "requested"});
    expect(await started?.closed).toBeUndefined();

    retire();
    await delay(20);
    expect(errors).toEqual([]);
    await pending;
  } finally {
    retire();
    await Promise.allSettled([network.close(), client.stop()]);
  }
}, 30000);

test.each([
  "after the host's cleanup",
  "racing a requested close",
])("a throwing peer handler fails the network %s", async (mode) => {
  const failure = new Error("peer handler failed");
  const config = applicationConfig();
  const peerConfig = applicationConfig();
  peerConfig.identitySecretKey[31] = 2;
  let network: NativeNetwork | undefined;
  let cleanup: Promise<unknown> | undefined;
  const networkHost = host({
    failed(error) {
      expect(error).toBe(failure);
      // Settlement continues, so the final remembered-peer snapshot still succeeds before the host closes.
      if (mode === "after the host's cleanup") cleanup = network?.getRememberedPeers().finally(() => network?.close());
    },
    peers() {
      if (mode === "racing a requested close") void network?.close();
      throw failure;
    },
  });
  const peer = await startPeer(peerConfig);
  try {
    network = createNativeNetwork(config, networkHost);
    const remote = await network.getIdentity();
    await network.applyIntent(localIntent(config), config.initialSlot);
    await peer.applyIntent(localIntent(peerConfig), peerConfig.initialSlot);
    // The connection's first peer event reaches the throwing handler.
    await peer.connect(remote.peerId, [remote.localEndpoint], 5000n).catch(() => undefined);
    expect(await network.closed).toEqual({error: failure, reason: "failed"});
    if (mode === "after the host's cleanup") await expect(cleanup).resolves.toMatchObject({peers: expect.any(Array)});
  } finally {
    await Promise.allSettled([network?.close(), peer.stop()]);
  }
}, 30000);

test.each([
  ["info", "info"],
  ["warn", "info"],
] as const)(
  "delivers native records at level %s, then at the level setLogLevel selects, through close",
  async (initial, selected) => {
    const config = applicationConfig();
    config.logLevel = initial;
    const records: NativeLogRecord[] = [];
    const network = createNativeNetwork(config, host({logs: (delivered) => void records.push(...delivered)}));
    let closedAt = -1;
    void network.closed.then(() => {
      closedAt = records.length;
    });
    try {
      await network.applyIntent(localIntent(config), config.initialSlot);
      await vi.waitFor(() => expect(records.length > 0 || initial !== "info").toBe(true), {timeout: 2000});
      await delay(300);
      const levels = new Set(records.map(({level}) => level));
      if (initial === "info") expect(records.some(({message}) => message.startsWith("owner_initialized "))).toBe(true);
      else expect([...levels].every((level) => level === "error" || level === "warn")).toBe(true);
      network.setLogLevel(selected);
    } finally {
      expect(await network.close()).toEqual({reason: "requested"});
    }
    // The last records, the owner's shutdown included, arrive before the close result.
    expect(records.slice(0, closedAt).some(({message}) => message.startsWith("owner_stopped reason=requested "))).toBe(
      true
    );
    const sequences = records.map(({sequence}) => sequence);
    expect(sequences).toEqual([...sequences].sort((a, b) => (a < b ? -1 : 1)));
  },
  15000
);

test("refuses an invalid peer report or imported root with an ordinary throw before queueing it", async () => {
  const config = applicationConfig();
  const network = createNativeNetwork(config, host());
  try {
    const self = (await network.getIdentity()).peerId;
    const [peer] = unreachableConnect();
    for (const [report, code] of [
      [() => network.reportPeer("not-a-peer", "fatal"), "InvalidNetworkPeerId"],
      [() => network.reportPeer(`${peer}\0`, "fatal"), "InvalidNetworkPeerId"],
      [() => network.reportPeer(peer, "severe" as "fatal"), "InvalidNetworkAction"],
      [() => network.blockImported(new Uint8Array(31)), "InvalidNetworkBytes"],
      [() => network.blockImported([...new Uint8Array(32)] as unknown as Uint8Array), "InvalidNetworkBytes"],
    ] as const)
      expect(report).toThrow(code);
    // Valid input still reaches native, which ignores a penalty for an identity it does not know.
    network.reportPeer(peer, "fatal");
    network.blockImported(new Uint8Array(32));
    expect((await network.getIdentity()).peerId).toBe(self);
  } finally {
    expect(await network.close()).toEqual({reason: "requested"});
  }
});

test("queued block roots survive caller buffer reuse and transfer", childTestTimeout(), () => {
  const output = runChild(["--import", "tsx", "bindings/test/fixtures/network-block-imported.mjs"]);
  expect(output).toContain("queued roots survived buffer reuse and transfer");
});

test("the facade validates its host, starts without host callbacks and hides the exchange", async () => {
  expect(() => createNativeNetwork(applicationConfig(), {} as NativeHost)).toThrow(
    "NativeHost.capacity must be a function"
  );
  const calls: string[] = [];
  const recorded = host();
  for (const name of ["capacity", "validate", "checkDependencies", "serve", "peers", "failed", "logs"] as const) {
    const callback = recorded[name] as (...args: unknown[]) => unknown;
    (recorded as unknown as Record<string, unknown>)[name] = (...args: unknown[]) => {
      calls.push(name);
      return callback(...args);
    };
  }
  const config = applicationConfig();
  const network = createNativeNetwork(config, recorded);
  try {
    expect(calls).toEqual([]);
    expect(network.limits.peerCapacity).toBe(config.resources.peerCapacity);
    expect(network.limits.incomingCapacity).toBeGreaterThan(0);
    expect(Object.isFrozen(network.limits)).toBe(true);
    for (const name of ["exchange", "fail", "holdVerdicts", "identity", "state"]) expect(name in network).toBe(false);
    await network.applyIntent(localIntent(config), config.initialSlot);
    const peer = (await network.getIdentity()).peerId;
    const endpoint = {address: Uint8Array.of(127, 0, 0, 1), family: 4 as const, port: 9};
    const [direct] = unreachableConnect();
    expect(peer).not.toBe(direct);
    await network.setDirectPeer(direct, [endpoint]);
    expect((await network.getDirectPeers()).identities).toEqual([direct]);
    expect(await network.setDirectPeer(direct, null)).toBe(true);
    expect(await network.setDirectPeer(direct, null)).toBe(false);
    // The native registry's families and the binding's families, each exactly once.
    const families = (text: string) => [...text.matchAll(/^# TYPE (\S+) /gm)].map(([, name]) => name);
    const native = families(runtimeOf(network)?.getMetrics() ?? "");
    const rendered = families(network.metrics());
    expect(native.length).toBeGreaterThan(0);
    expect(rendered).toEqual([
      ...native,
      "lodestar_native_drain_burst_seconds",
      "lodestar_native_log_delivery_errors_total",
      "lodestar_native_log_drain_errors_total",
    ]);
    expect(new Set(rendered).size).toBe(rendered.length);
  } finally {
    expect(await network.close()).toEqual({reason: "requested"});
  }
  expect(await network.closed).toEqual({reason: "requested"});
});

test.each(["close-reports", "close-batches"])("explicit close lifecycle: %s", childTestTimeout(), (mode) => {
  const output = runChild(["--import", "tsx", "--expose-gc", "bindings/test/fixtures/network-lifecycle.mjs", mode]);
  expect(output).toContain(`${mode}-settled`);
});
