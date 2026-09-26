import {execFileSync} from "node:child_process";
import {setTimeout as delay} from "node:timers/promises";
import {expect, test, vi} from "vitest";
import type {
  GossipJob,
  IncomingRequest,
  NativeApplicationConfig,
  NativeHost,
  NativeNetwork,
  Verdict,
} from "../src/network.js";
import {createNativeNetwork} from "../src/network.js";
import {runtimeOf} from "../src/network-runtime.js";
import {
  applicationConfig,
  gossipAll,
  localIntent,
  subscriptions,
  topicKinds,
  topicName,
  unreachableConnect,
} from "./utils/network.js";
import {BLOCKS} from "./utils/network-incoming.js";
import {type PeerRuntime, startPeer} from "./utils/network-peer.js";

const TOPIC = topicName();
const BLOCK = topicKinds.indexOf("beacon_block");

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
    await delay(1250);
    return {network, peers, remote};
  } catch (error) {
    await Promise.allSettled([network?.close(), ...peers.map((peer) => peer.close())]);
    throw error;
  }
}

function gossipCounts(network: NativeNetwork) {
  const gossip = runtimeOf(network)?.diagnostics().gossip;
  if (!gossip) throw Error("Not a facade");
  return gossip;
}

function applied(network: NativeNetwork): bigint {
  const gossip = gossipCounts(network);
  return gossip.reportsAppliedAccept + gossip.reportsAppliedReject + gossip.reportsAppliedIgnore;
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
  const handled: {byte: number; applied: bigint}[] = [];
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
        () => handled.push({applied: network ? applied(network) : -1n, byte}),
        (error) => failures.push({byte, code: (error as {code?: unknown}).code})
      );
      return Promise.resolve(job.messages.map(({data}) => verdictOf(data[0])));
    },
  });
  // The first peer publishes; the second receives what the facade forwards.
  const {network: facade, peers} = await facadeWithPeers(networkHost, 2, (config) => {
    config.gossipPolicy.processor[BLOCK].items = 256;
  });
  network = facade;
  const [publisher, receiver] = peers;
  try {
    const runtime = runtimeOf(network);
    if (!runtime) throw Error("Not a facade");
    runtime.holdVerdicts(true);
    const before = gossipCounts(network);
    const appliedBefore = applied(network);
    for (let byte = 0; byte < COUNT; byte++)
      await publisher.publishGossip(TOPIC, blockPayload(byte), {allowZeroPeers: false});
    await vi.waitFor(() => expect(gossipCounts(facade).pendingVerdicts).toBe(COUNT), {timeout: 10000});
    // Every verdict was reported and every handler's timer is due, but the owner holds the verdicts.
    await delay(50);
    expect(validated.slice().sort((a, b) => a - b)).toEqual([...Array(COUNT).keys()]);
    expect(handled).toEqual([]);
    expect(applied(network)).toBe(appliedBefore);
    runtime.holdVerdicts(false);
    await vi.waitFor(() => expect(handled).toHaveLength(COUNT), {timeout: 10000});
    // Each handler ran once the owner had applied its job's verdict, and every earlier handled job's.
    for (const [i, entry] of handled.entries())
      expect(entry.applied - appliedBefore).toBeGreaterThanOrEqual(BigInt(i + 1));
    const after = gossipCounts(network);
    expect(after.reportsAppliedAccept - before.reportsAppliedAccept).toBe(BigInt(accepted.length));
    expect(after.reportsAppliedReject - before.reportsAppliedReject).toBe(2n);
    expect(after.reportsAppliedIgnore - before.reportsAppliedIgnore).toBe(BigInt(COUNT - accepted.length - 2));
    expect(after).toMatchObject({acknowledging: 0, pendingVerdicts: 0});
    expect(failures).toEqual([]);
    // Application admitted each accepted message, and no other, for forwarding.
    expect((await received(receiver, accepted.length)).sort((a, b) => a - b)).toEqual(accepted);

    // Close prevents the owner from disposing of a held verdict: its report rejects and its handler never runs.
    runtime.holdVerdicts(true);
    await publisher.publishGossip(TOPIC, blockPayload(COUNT), {allowZeroPeers: false});
    await vi.waitFor(() => expect(gossipCounts(facade).pendingVerdicts).toBe(1), {timeout: 5000});
    global.gc?.();
    // The facade stays reachable until close completes, so derivatives of the report settle as it does.
    expect(await network.close()).toEqual({reason: "requested"});
    expect(await Promise.all(closing)).toEqual(["NetworkClosed", "NetworkClosed"]);
    await vi.waitFor(() => expect(failures).toEqual([{byte: COUNT, code: "NetworkClosed"}]));
    expect(handled).toHaveLength(COUNT);
  } finally {
    await Promise.allSettled([network.close(), ...peers.map((peer) => peer.close())]);
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
    const before = gossipCounts(network);
    // The block kind's eight cells are reused in order, so the ninth and tenth messages reuse cells with new
    // generations while earlier handles have been acknowledged.
    for (let byte = 1; byte <= 10; byte++) {
      await publisher.publishGossip(TOPIC, blockPayload(byte), {allowZeroPeers: false});
      await vi.waitFor(() => expect(handled).toContain(byte), {timeout: 5000});
    }
    expect(handled).toEqual([...Array(10).keys()].map((i) => i + 1));
    expect(gossipCounts(network).reportsAppliedAccept - before.reportsAppliedAccept).toBe(10n);

    await publisher.publishGossip(TOPIC, blockPayload(200), {allowZeroPeers: false});
    await vi.waitFor(() => expect(handled).toContain(200), {timeout: 5000});
    expect(gossipCounts(network)).toMatchObject({
      deliveredExpired: before.deliveredExpired + 1n,
      reportsAppliedAccept: before.reportsAppliedAccept + 10n,
    });
    expect(failures).toEqual([]);
  } finally {
    await Promise.allSettled([network.close(), publisher.close()]);
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
    const incoming = () => runtimeOf(network)?.diagnostics().incoming;
    await vi.waitFor(() => expect(incoming()).toMatchObject({occupied: 1, retiring: 1}));
    await delay(50);
    expect(incoming()).toMatchObject({occupied: 1, retiring: 1});
    retire();
    await vi.waitFor(() => expect(incoming()).toMatchObject({occupied: 0, retiring: 0}));
  } finally {
    retire();
    await Promise.allSettled([network.close(), client.close()]);
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
    await Promise.allSettled([network?.close(), peer.close()]);
  }
}, 30000);

test("the facade validates its host, starts without host callbacks and hides the exchange", async () => {
  expect(() => createNativeNetwork(applicationConfig(), {} as NativeHost)).toThrow(
    "NativeHost.capacity must be a function"
  );
  const calls: string[] = [];
  const recorded = host();
  for (const name of ["capacity", "validate", "checkDependencies", "serve", "peers", "failed"] as const) {
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
    // Resolved by native at initialization, as its private diagnostics report them.
    const diagnostics = runtimeOf(network)?.diagnostics();
    expect(network.limits).toEqual({
      incomingCapacity: diagnostics?.incoming.capacity,
      peerCapacity: config.resources.peerCapacity,
    });
    expect(Object.isFrozen(network.limits)).toBe(true);
    for (const name of ["exchange", "fail", "holdVerdicts", "diagnostics", "identity", "state"])
      expect(name in network).toBe(false);
    await network.applyIntent(localIntent(config), config.initialSlot);
    const peer = (await network.getIdentity()).peerId;
    const endpoint = {address: Uint8Array.of(127, 0, 0, 1), family: 4 as const, port: 9};
    const [direct] = unreachableConnect();
    expect(peer).not.toBe(direct);
    await network.setDirectPeer(direct, [endpoint]);
    expect((await network.getDirectPeers()).identities).toEqual([direct]);
    expect(await network.setDirectPeer(direct, null)).toBe(true);
    expect(await network.setDirectPeer(direct, null)).toBe(false);
    expect(network.metrics()).toContain("# TYPE lodestar_native_drain_burst_seconds histogram\n");
  } finally {
    expect(await network.close()).toEqual({reason: "requested"});
  }
  expect(await network.closed).toEqual({reason: "requested"});
});

test.each([
  ["a job's report retained elsewhere", "facade-gc"],
  ["a report reaction that captures the host", "facade-gc-reaction"],
  ["promises only derived from a report", "facade-gc-derived"],
])(
  "drops the facade and host without close, with %s",
  (_, mode) => {
    const output = execFileSync(
      process.execPath,
      ["--import", "tsx", "--expose-gc", "bindings/test/fixtures/network-lifecycle.mjs", mode],
      {encoding: "utf8", timeout: 20000}
    );
    expect(output).toContain("facade-collected");
  },
  25000
);
