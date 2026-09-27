import {expect, test} from "vitest";
import type {NativeNetworkApplicationRuntime} from "../src/network-runtime.js";
import {
  applicationConfig,
  holdSettling,
  localIntent,
  peerIdFromHex,
  requestForks,
  settleOnly,
  startRuntime,
} from "./utils/network.js";
import {incomingPair, takeIncoming} from "./utils/network-incoming.js";
import {startPeer} from "./utils/network-peer.js";

test("application request rejects control protocols at the exported boundary", async () => {
  const config = applicationConfig();
  const runtime = startRuntime(config, () => undefined);
  try {
    const identity = await runtime.identity;
    await runtime.applyIntent(localIntent(config), config.initialSlot);
    expect(() =>
      runtime.request(identity.peerId, "/eth2/beacon_chain/req/ping/1/ssz_snappy", new Uint8Array(8))
    ).toThrow("ControlProtocol");
  } finally {
    await runtime.close();
  }
});

test("request admission owns terminal state and a bounded single pull", async () => {
  const config = applicationConfig();
  config.resources.bridgeBudgetBytes = 512 * 1024 * 1024;
  const runtime = startRuntime(config, () => undefined);
  try {
    const identity = await runtime.identity;
    await runtime.applyIntent(localIntent(config), config.initialSlot);
    const stream = runtime.request(
      identity.peerId,
      "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy",
      new Uint8Array(0)
    );
    const pending = stream.next();
    await expect(stream.next()).rejects.toMatchObject({code: "NetworkRequestBusy"});
    await expect(pending).rejects.toMatchObject({code: "NetworkRequestRejected", reason: "disconnected"});
    expect(await stream.next()).toEqual({done: true, value: undefined});
    expect(runtime.diagnostics().requests).toMatchObject({
      capacity: 6,
      inputBytes: 0,
      occupied: 0,
      reservedBytes: 0,
      sinkBytes: 0,
    });
  } finally {
    await runtime.close();
  }
});

const BLOCKS = "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy";
const HOST = process.env.LODESTAR_Z_NETWORK_STOCK_HOST;
const HOODI = process.env.LODESTAR_Z_NETWORK_HOODI_FIXTURE;
const NATIVE_PEER = process.env.LODESTAR_Z_NETWORK_NATIVE_PEER;
const stockTest = test.skipIf(!HOST);

async function connected() {
  if (!HOST) throw Error("LODESTAR_Z_NETWORK_STOCK_HOST is required");
  const {Child} = await import("../../test/interop/child.mjs");
  const peer = new Child("request-stock", process.execPath, [
    "--import",
    "tsx",
    "test/interop/request_responder.mjs",
    HOST,
    ...(HOODI ? [HOODI] : []),
  ]);
  let runtime: ReturnType<typeof startRuntime> | undefined;
  try {
    const info = await peer.command("ready");
    const config = applicationConfig();
    config.resources.bridgeBudgetBytes = 512 * 1024 * 1024;
    runtime = startRuntime(config, () => undefined);
    await runtime.identity;
    await runtime.applyIntent(localIntent(config), config.initialSlot);
    const id = peerIdFromHex(info.peer);
    await runtime.connect(
      id,
      [{address: Uint8Array.of(127, 0, 0, 1), family: 4, port: Number(info.address.split("/")[4])}],
      5000n
    );
    return {config, id, peer, runtime};
  } catch (error) {
    try {
      await runtime?.close();
    } finally {
      await peer.stop();
    }
    throw error;
  }
}

stockTest(
  "real stock chunks copy once and wait for the subsequent consuming pull",
  async () => {
    const {runtime, peer, id} = await connected();
    try {
      const {payload} = await import("../../test/interop/codec.mjs");
      const input = new Uint8Array(64);
      const stream = runtime.request(id, BLOCKS, input);
      input.fill(255);
      const pending = stream.next();
      await expect(stream.next()).rejects.toMatchObject({code: "NetworkRequestBusy"});
      const first = await pending;
      expect(first.done).toBe(false);
      expect(first.value).toMatchObject({fork: "deneb", protocol: BLOCKS});
      expect(first.value.data).toEqual(Uint8Array.from(payload(4000, 71)));
      expect(runtime.diagnostics().requests.chunksCopied).toBe(1n);
      await new Promise((resolve) => setTimeout(resolve, 30));
      expect(runtime.diagnostics().requests.chunksCopied).toBe(1n);
      const second = await stream.next();
      expect(second.value.data).toEqual(Uint8Array.from(payload(4000, 72)));
      expect(await stream.next()).toEqual({done: true, value: undefined});
      expect((await peer.command("stats")).lastRequest).toBe("00".repeat(64));
      expect(first.value.data).toEqual(Uint8Array.from(payload(4000, 71)));
      expect(runtime.diagnostics().requests).toMatchObject({
        bytesCopied: 8000n,
        chunksCopied: 2n,
        inputBytes: 0,
        occupied: 0,
        reservedBytes: 0,
        sinkBytes: 0,
      });
    } finally {
      await runtime.close();
      await peer.stop();
    }
  },
  20000
);

stockTest(
  "real stock peer errors preserve decoded non-ASCII bytes and empty responses complete",
  async () => {
    const {runtime, peer, id} = await connected();
    try {
      await peer.command("scenario", {scenario: "peer-error"});
      const stream = runtime.request(id, BLOCKS, new Uint8Array(32));
      await expect(stream.next()).rejects.toMatchObject({
        code: "NetworkRequestFailed",
        context: null,
        detail: null,
        peerMessage: Uint8Array.of(0, 255, 195, 40, 128),
        peerStatus: 3,
        phase: "response",
        reason: "peer_error",
      });
      await peer.command("scenario", {scenario: "empty"});
      const empty = runtime.request(id, BLOCKS, new Uint8Array(0), {expectedChunks: 0});
      expect(await empty.next()).toEqual({done: true, value: undefined});
      expect(runtime.diagnostics().requests.reservedBytes).toBe(0);
    } finally {
      await runtime.close();
      await peer.stop();
    }
  },
  20000
);

stockTest(
  "cancel retirement bypasses a saturated administrative queue and shares one Promise",
  async () => {
    const {runtime, peer, id} = await connected();
    try {
      await peer.command("scenario", {scenario: "hold"});
      const stream = runtime.request(id, BLOCKS, new Uint8Array(32));
      const pending = stream.next();
      const {waitFor} = await import("../../test/interop/child.mjs");
      await waitFor(async () => (await peer.command("stats")).lastRequest === "00".repeat(32));
      const cancelled = expect(pending).rejects.toMatchObject({
        code: "NetworkRequestFailed",
        phase: "response",
        reason: "cancelled",
      });
      const commands = Array.from({length: 32}, () => runtime.getIdentity());
      const retired = stream.return?.();
      expect(stream.throw?.(Error("ignored"))).toBe(retired);
      expect(stream.return?.()).toBe(retired);
      await retired;
      await cancelled;
      expect(await stream.next()).toEqual({done: true, value: undefined});
      await Promise.all(commands);
      expect(runtime.diagnostics().requests).toMatchObject({occupied: 0, reservedBytes: 0});
    } finally {
      await runtime.close();
      await peer.stop();
    }
  },
  20000
);

test("request validation rejects malformed options and detached input without retained ownership", async () => {
  const config = applicationConfig();
  const runtime = startRuntime(config, () => undefined);
  try {
    const identity = await runtime.identity;
    await runtime.applyIntent(localIntent(config), config.initialSlot);
    for (const options of [
      {responseTimeoutMs: 0},
      {responseTimeoutMs: 60001},
      {expectedChunks: 2 ** 32},
      {requestTimeoutMs: 1.5},
    ]) {
      expect(() => runtime.request(identity.peerId, BLOCKS, new Uint8Array(32), options)).toThrow(
        "InvalidNetworkInteger"
      );
    }
    const detached = new Uint8Array(32);
    structuredClone(detached.buffer, {transfer: [detached.buffer]});
    expect(() => runtime.request(identity.peerId, BLOCKS, detached)).toThrow("InvalidNetworkBytes");
    expect(runtime.diagnostics().requests).toMatchObject({occupied: 0, reservedBytes: 0});
    expect(runtime.diagnostics().operationOccupied).toBe(0);
  } finally {
    await runtime.close();
  }
});

stockTest(
  "terminal timeout releases copied sinks and queued chunks survive native slot reuse",
  async () => {
    const {runtime, peer, id} = await connected();
    try {
      const {payload} = await import("../../test/interop/codec.mjs");
      const copied = runtime.request(id, BLOCKS, new Uint8Array(64), {responseTimeoutMs: 100});
      const held = await copied.next();
      await new Promise((resolve) => setTimeout(resolve, 180));
      expect(runtime.diagnostics().requests.sinkBytes).toBe(0);
      await expect(copied.next()).rejects.toMatchObject({
        code: "NetworkRequestFailed",
        phase: "response",
        reason: "host_timeout",
      });
      expect(held.value.data).toEqual(Uint8Array.from(payload(4000, 71)));
      const queued = runtime.request(id, BLOCKS, new Uint8Array(64), {responseTimeoutMs: 100});
      await new Promise((resolve) => setTimeout(resolve, 180));
      const replacement = runtime.request(id, BLOCKS, new Uint8Array(64));
      expect((await replacement.next()).value.data).toEqual(Uint8Array.from(payload(4000, 71)));
      await replacement.return?.();
      expect((await queued.next()).value.data).toEqual(Uint8Array.from(payload(4000, 71)));
      await expect(queued.next()).rejects.toMatchObject({phase: "response", reason: "host_timeout"});
      expect(runtime.diagnostics().requests).toMatchObject({occupied: 0, reservedBytes: 0, sinkBytes: 0});
    } finally {
      await runtime.close();
      await peer.stop();
    }
  },
  20000
);

stockTest(
  "real stock response projects multiple contexts and one maximum supported payload",
  async () => {
    const {runtime, peer, id} = await connected();
    try {
      const {payload, summary} = await import("../../test/interop/codec.mjs");
      for (const [digest, fork, length] of [
        [Buffer.from(requestForks[1].digest).toString("hex"), "electra", 4000],
        [Buffer.from(requestForks[0].digest).toString("hex"), "deneb", 10 * 1024 * 1024],
      ] as const) {
        await peer.command("scenario", {count: 1, digest, length, scenario: "chunks"});
        const stream = runtime.request(id, BLOCKS, new Uint8Array(32), {responseTimeoutMs: 60000});
        const response = await stream.next();
        expect(response.value.fork).toBe(fork);
        expect(summary(response.value.data)).toEqual(summary(payload(length, 71)));
        expect((await stream.next()).done).toBe(true);
      }
    } finally {
      await runtime.close();
      await peer.stop();
    }
  },
  30000
);

stockTest(
  "accepted local refusals preserve canonical policy and capacity reasons",
  async () => {
    const {runtime, peer, id} = await connected();
    try {
      const {waitFor} = await import("../../test/interop/child.mjs");
      await waitFor(async () => (await runtime.getPeers()).counts.relevant === 1);
      expect((await peer.command("stats")).control.status).toBe(1);
      await expect(runtime.request(id, BLOCKS, new Uint8Array(32), {expectedChunks: 2}).next()).rejects.toMatchObject({
        code: "NetworkRequestRejected",
        reason: "invalid_request_options",
      });
      await expect(runtime.request(id, BLOCKS, new Uint8Array(1)).next()).rejects.toMatchObject({
        code: "NetworkRequestRejected",
        reason: "invalid_request",
      });
      await peer.command("scenario", {scenario: "hold"});
      const streams = Array.from({length: 6}, () => runtime.request(id, BLOCKS, new Uint8Array(32)));
      expect(() => runtime.request(id, BLOCKS, new Uint8Array(32))).toThrow(
        expect.objectContaining({code: "NetworkRequestRejected", reason: "slots_exhausted"})
      );
      await expect(streams[2].next()).rejects.toMatchObject({
        code: "NetworkRequestRejected",
        reason: "too_many_requests",
      });
      const {multiaddr} = await import("@multiformats/multiaddr");
      const identity = await runtime.getIdentity();
      expect((await peer.command("ping", {address: multiaddr(identity.localMultiaddr).toString()})).length).toBe(8);
      await runtime.reStatusPeers([id]);
      await waitFor(async () => (await peer.command("stats")).control.status >= 2);
      expect((await runtime.getPeers()).peers[0].metadata?.sequenceNumber).toBe(1n);
      await Promise.all(streams.map((stream) => stream.return?.()));
      const commands = Array.from({length: 32}, () => runtime.getIdentity());
      const independent = runtime.request(id, BLOCKS, new Uint8Array(32));
      await Promise.all(commands);
      await independent.return?.();
      expect(runtime.diagnostics().requests).toMatchObject({
        occupied: 0,
        requestFull: 1n,
        reservedBytes: 0,
      });
    } finally {
      await runtime.close();
      await peer.stop();
    }
  },
  20000
);

test.each([
  "iterator-gc",
  "pull-gc",
  "facade-gc",
  "exit",
  "closed-terminal",
  "closed-facade-gc",
  "closed-facade-gc-early",
])("request lifecycle settles independently of facade and notifier: %s", async (mode) => {
  const {execFileSync} = await import("node:child_process");
  const output = execFileSync(
    process.execPath,
    ["--import", "tsx", "--expose-gc", "--import", "tsx", "bindings/test/fixtures/network-request-lifecycle.mjs", mode],
    {encoding: "utf8", timeout: 20000}
  );
  expect(output).toContain(`request-lifecycle ${mode} ok`);
}, 25000);

stockTest(
  "close discards queued payloads and frees heavy request storage with held iterators",
  async () => {
    const {runtime, peer, id} = await connected();
    try {
      const streams = [
        runtime.request(id, BLOCKS, new Uint8Array(64)),
        runtime.request(id, BLOCKS, new Uint8Array(64)),
      ];
      const pending = streams[0].next();
      const settled = pending.then(
        () => "chunk",
        (error) => error.code
      );
      await runtime.close();
      expect(["chunk", "NetworkClosed"]).toContain(await settled);
      expect(runtime.diagnostics().requests).toMatchObject({
        copyingBytes: 0,
        inputBytes: 0,
        reservedBytes: 0,
        sinkBytes: 0,
      });
      await expect(streams[1].next()).rejects.toMatchObject({code: "NetworkClosed"});
      await streams[0].return?.();
      expect(runtime.diagnostics().requests.occupied).toBe(0);
    } finally {
      await runtime.close();
      await peer.stop();
    }
  },
  20000
);

stockTest(
  "throw retirement preserves the first supplied value and completed iterators settle locally",
  async () => {
    const {runtime, peer, id} = await connected();
    try {
      await peer.command("scenario", {scenario: "hold"});
      const stream = runtime.request(id, BLOCKS, new Uint8Array(32));
      const value = {sentinel: 71};
      const thrown = stream.throw?.(value);
      expect(stream.return?.()).toBe(thrown);
      await expect(thrown).rejects.toBe(value);
      expect(await stream.next()).toEqual({done: true, value: undefined});
      await peer.command("scenario", {scenario: "empty"});
      const complete = runtime.request(id, BLOCKS, new Uint8Array(0));
      expect((await complete.next()).done).toBe(true);
      await expect(complete.throw?.(value)).rejects.toBe(value);
      expect(runtime.diagnostics().requests.occupied).toBe(0);
    } finally {
      await runtime.close();
      await peer.stop();
    }
  },
  20000
);

test.each([0, -1])("application startup requires RPC and publication progress capacity at delta %s", async (delta) => {
  const config = applicationConfig();
  const probe = await startPeer(config);
  const budget = (await probe.diagnostics()).payloadBudget;
  await probe.stop();
  config.resources.bridgeBudgetBytes +=
    budget.incomingMinimumBytes +
    budget.outgoingMinimumBytes +
    budget.publicationMinimumBytes -
    budget.limitBytes +
    delta;
  if (delta < 0) {
    expect(() => startRuntime(config)).toThrow("NetworkBridgeBudgetExceeded");
    return;
  }
  const runtime = startRuntime(config);
  try {
    await expect(runtime.request(runtime.identity.peerId, BLOCKS, new Uint8Array(32)).next()).rejects.toMatchObject({
      reason: "disconnected",
    });
    expect(runtime.diagnostics().requests).toMatchObject({inputBytes: 0, occupied: 0, reservedBytes: 0, sinkBytes: 0});
  } finally {
    await runtime.close();
  }
}, 20000);

test.skipIf(!HOST || !HOODI)(
  "retained Hoodi bytes round-trip with a supported Fulu response context",
  async () => {
    const {runtime, peer, id} = await connected();
    try {
      const {readFile} = await import("node:fs/promises");
      const {summary} = await import("../../test/interop/codec.mjs");
      await peer.command("scenario", {
        count: 1,
        digest: Buffer.from(requestForks[2].digest).toString("hex"),
        scenario: "hoodi",
      });
      const stream = runtime.request(id, BLOCKS, new Uint8Array(32));
      const response = await stream.next();
      expect(response.value.fork).toBe("fulu");
      expect(summary(response.value.data)).toEqual(summary(await readFile(HOODI ?? "")));
      expect((await stream.next()).done).toBe(true);
    } finally {
      await runtime.close();
      await peer.stop();
    }
  },
  20000
);

test("native bridge validates full handles and stale retirement", async () => {
  const {commandCompleted, completed, networkBindings: bindings} = await import("./utils/network-bindings.js");
  const config = applicationConfig();
  const native = new bindings.NativeNetworkRuntime();
  const lifecycle = native.initialize(config, () => undefined);
  try {
    const identity = await lifecycle.identity;
    await commandCompleted(native, native.applyIntent(localIntent(config), config.initialSlot), settleOnly);
    const handle = native.requestStart(identity.peerId, BLOCKS, new Uint8Array(32), undefined);
    expect(() => native.requestPull({...handle, generation: 0n})).toThrow("InvalidRequestHandle");
    expect(() => native.requestPull({...handle, generation: handle.generation + 1n})).toThrow("InvalidRequestHandle");
    native.requestPull(handle);
    expect(() => native.requestPull(handle)).toThrow("NetworkRequestBusy");
    expect(await completed(native, "request", handle, settleOnly)).toMatchObject({error: {reason: "disconnected"}});
    expect(() => native.requestPull(handle)).toThrow("InvalidRequestHandle");
    expect(native.requestRetire(handle, true)).toBeUndefined();
  } finally {
    native.close();
    await lifecycle.closed;
  }
});

stockTest(
  "zero expected chunks and unknown response context preserve exact failures",
  async () => {
    const {runtime, peer, id} = await connected();
    try {
      const surplus = runtime.request(id, BLOCKS, new Uint8Array(32), {expectedChunks: 0});
      await expect(surplus.next()).rejects.toMatchObject({
        code: "NetworkRequestFailed",
        phase: "response",
        reason: "too_many_chunks",
      });
      await peer.command("scenario", {count: 1, digest: "deadbeef", scenario: "chunks"});
      await expect(runtime.request(id, BLOCKS, new Uint8Array(32)).next()).rejects.toMatchObject({
        context: Uint8Array.of(222, 173, 190, 239),
        phase: "response",
        reason: "unknown_context",
      });
    } finally {
      await runtime.close();
      await peer.stop();
    }
  },
  20000
);

test.skipIf(!NATIVE_PEER)(
  "ordinary addon consumes an independently owned native responder payload",
  async () => {
    const {Child} = await import("../../test/interop/child.mjs");
    const {payload, rangeRequest} = await import("../../test/interop/codec.mjs");
    const peer = new Child("request-native", NATIVE_PEER ?? "", ["--application"]);
    const config = applicationConfig();
    const runtime = startRuntime(config, () => undefined);
    try {
      const remote = await peer.command("listen");
      await peer.command("respond", {seed: 71, size: 4000});
      await runtime.identity;
      await runtime.applyIntent(localIntent(config), config.initialSlot);
      const parts = remote.address.split("/");
      const id = peerIdFromHex(remote.peer);
      await runtime.connect(id, [{address: Uint8Array.of(127, 0, 0, 1), family: 4, port: Number(parts[4])}], 5000n);
      // The peer must serve the control exchange, not only the request below.
      for (let i = 0; i < 500 && !(await runtime.getPeers()).peers[0]?.metadata; i++)
        await new Promise((resolve) => setTimeout(resolve, 10));
      expect((await runtime.getPeers()).peers[0]?.metadata).not.toBeNull();
      const stream = runtime.request(id, "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy", rangeRequest());
      const first = await stream.next();
      expect(first.value.fork).toBe("deneb");
      expect(first.value.data).toEqual(Uint8Array.from(payload(4000, 71)));
      expect((await stream.next()).done).toBe(true);
    } finally {
      await runtime.close();
      await peer.stop();
    }
  },
  15000
);

stockTest(
  "direct native calls allow exactly one pending pull",
  async () => {
    const {completed, native, peer, id, stop} = await connectedNative();
    try {
      await peer.command("scenario", {scenario: "hold"});
      const handle = native.requestStart(id, BLOCKS, new Uint8Array(32), undefined);
      native.requestPull(handle);
      expect(() => native.requestPull(handle)).toThrow("NetworkRequestBusy");
      expect(native.diagnostics().requests.busyPulls).toBe(1n);
      const {waitFor} = await import("../../test/interop/child.mjs");
      await waitFor(async () => (await peer.command("stats")).lastRequest === "00".repeat(32));
      native.requestRetire(handle, false);
      expect(await completed(native, "request", handle, settleOnly)).toMatchObject({
        error: {code: "NetworkRequestFailed", phase: "response", reason: "cancelled"},
      });
    } finally {
      await stop();
    }
  },
  20000
);

async function connectedNative() {
  if (!HOST) throw Error("LODESTAR_Z_NETWORK_STOCK_HOST is required");
  const {Child} = await import("../../test/interop/child.mjs");
  const {commandCompleted, completed, networkBindings: bindings} = await import("./utils/network-bindings.js");
  const peer = new Child("request-phase-stock", process.execPath, [
    "--import",
    "tsx",
    "test/interop/request_responder.mjs",
    HOST,
  ]);
  let native: InstanceType<typeof bindings.NativeNetworkRuntime> | undefined;
  let closed: Promise<unknown> | undefined;
  const stop = async () => {
    try {
      native?.close();
      await closed;
    } finally {
      await peer.stop();
    }
  };
  try {
    const remote = await peer.command("ready");
    const config = applicationConfig();
    native = new bindings.NativeNetworkRuntime();
    const prepared = native.initialize(config, () => undefined);
    closed = prepared.closed;
    await prepared.identity;
    await commandCompleted(native, native.applyIntent(localIntent(config), config.initialSlot), settleOnly);
    const id = peerIdFromHex(remote.peer);
    await commandCompleted(
      native,
      native.connect(
        id,
        [{address: Uint8Array.of(127, 0, 0, 1), family: 4, port: Number(remote.address.split("/")[4])}],
        5000n
      ),
      settleOnly
    );
    return {bindings, closed, completed, id, native, peer, stop};
  } catch (error) {
    await stop();
    throw error;
  }
}
stockTest(
  "native terminal scoring does not wait for a JavaScript iterator pull",
  async () => {
    const {runtime, peer, id} = await connected();
    try {
      await peer.command("scenario", {count: 1, digest: "deadbeef", scenario: "chunks"});
      const stream = runtime.request(id, BLOCKS, new Uint8Array(32));
      let score = 0;
      for (let attempt = 0; attempt < 100; attempt++) {
        score = (await runtime.getPeers()).peers[0].score;
        if (score < -9) break;
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      expect(score).toBeGreaterThanOrEqual(-10);
      expect(score).toBeLessThan(-9);
      await expect(stream.next()).rejects.toMatchObject({reason: "unknown_context"});
      expect((await runtime.getPeers()).peers[0].score).toBeGreaterThanOrEqual(score);
    } finally {
      await runtime.close();
      await peer.stop();
    }
  },
  20000
);

/** A pair whose in-process runtime requests from a child peer, which serves each request the test takes from it. */
async function servedPair() {
  const pair = await incomingPair();
  const {waitFor} = await import("../../test/interop/child.mjs");
  await waitFor(async () => (await pair.right.getPeers()).peers[0]?.status != null);
  return {...pair, peer: pair.identity.peerId};
}

/**
 * Exchanges until one delivers a request completion, as a held runtime's own host would, then runs `then` in the same
 * job, before any reaction to what the exchange settled.
 */
async function requestCompleted(runtime: NativeNetworkApplicationRuntime, then?: () => void): Promise<void> {
  for (let i = 0; i < 2000; i++) {
    if (runtime.exchange([], settleOnly).completions.some(({family}) => family === "request")) return then?.();
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw Error("No request completion arrived");
}

const chunk = (fill: number) => new Uint8Array(4000).fill(fill);
const done = {done: true, value: undefined};

test("a final chunk waits for a delayed pull, and an outcome that arrives with no pull waits for the next", async () => {
  const {left, peer, right} = await servedPair();
  try {
    const finished = right.request(peer, BLOCKS, new Uint8Array(32));
    const first = finished.next();
    const served = await takeIncoming(left);
    await served.respond(chunk(7), requestForks[0]);
    await served.finish();
    expect((await first).value?.data).toEqual(chunk(7));
    // The stream ends only once the next pull consumes its chunk, so meanwhile it keeps its cell and awaits nothing.
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(right.diagnostics().requests).toMatchObject({chunksCopied: 1n, occupied: 1, pendingPulls: 0});
    expect(await finished.next()).toEqual(done);

    // Held past its response deadline, a delivered chunk ends its stream while no pull waits.
    const timed = right.request(peer, BLOCKS, new Uint8Array(32), {responseTimeoutMs: 1000});
    const held = timed.next();
    const incoming = await takeIncoming(left);
    await incoming.respond(chunk(9), requestForks[0]);
    const value = (await held).value;
    await expect
      .poll(() => right.diagnostics().requests, {timeout: 5000})
      .toMatchObject({occupied: 1, pendingPulls: 0, sinkBytes: 0, terminalCells: 1});
    await expect(timed.next()).rejects.toMatchObject({
      code: "NetworkRequestFailed",
      phase: "response",
      reason: "host_timeout",
    });
    expect(await timed.next()).toEqual(done);
    expect(value?.data).toEqual(chunk(9));
    expect(right.diagnostics().requests).toMatchObject({occupied: 0, reservedBytes: 0});
  } finally {
    await Promise.all([left.close(), right.close()]);
  }
}, 20000);

test("a return racing a delivered chunk or a pending pull settles the pull first and delivers no later chunk", async () => {
  const {left, peer, right} = await servedPair();
  holdSettling(right, true);
  try {
    // The pull took its chunk in an exchange whose reactions have not run when the return arrives.
    const order: string[] = [];
    const first = right.request(peer, BLOCKS, new Uint8Array(32));
    const pulled = first.next();
    void pulled.then(() => order.push("pull"));
    await (await takeIncoming(left)).respond(chunk(5), requestForks[0]);
    let retired: Promise<unknown> | undefined;
    await requestCompleted(right, () => {
      expect(order).toEqual([]);
      retired = first.return?.();
      void retired?.then(() => order.push("return"));
    });
    await requestCompleted(right);
    expect((await pulled).value?.data).toEqual(chunk(5));
    expect(await retired).toEqual(done);
    expect(order).toEqual(["pull", "return"]);
    expect(await first.next()).toEqual(done);

    // With the peer's chunk sent but undelivered, the return cancels the stream, whose pull takes the cancellation.
    const settled: string[] = [];
    const second = right.request(peer, BLOCKS, new Uint8Array(32));
    const pending = second.next();
    const cancelled = expect(pending).rejects.toMatchObject({
      code: "NetworkRequestFailed",
      phase: "response",
      reason: "cancelled",
    });
    void pending.catch(() => settled.push("pull"));
    await (await takeIncoming(left)).respond(chunk(6), requestForks[0]);
    const retiring = second.return?.();
    void retiring?.then(() => settled.push("return"));
    await requestCompleted(right);
    await cancelled;
    expect(await retiring).toEqual(done);
    expect(settled).toEqual(["pull", "return"]);
    expect(right.diagnostics().requests).toMatchObject({chunksCopied: 1n, occupied: 0, reservedBytes: 0});
  } finally {
    holdSettling(right, false);
    await Promise.all([left.close(), right.close()]);
  }
}, 20000);

test("every return or throw shares the first retirement, which settles after the pull with the first value", async () => {
  const {left, peer, right} = await servedPair();
  try {
    const stream = right.request(peer, BLOCKS, new Uint8Array(32));
    const pending = stream.next();
    const cancelled = expect(pending).rejects.toMatchObject({code: "NetworkRequestFailed", reason: "cancelled"});
    await takeIncoming(left);
    const retired = stream.return?.();
    expect(stream.throw?.(Error("ignored"))).toBe(retired);
    expect(stream.return?.()).toBe(retired);
    expect(await retired).toEqual(done);
    await cancelled;
    expect(await stream.next()).toEqual(done);

    const value = {sentinel: 71};
    const thrown = right.request(peer, BLOCKS, new Uint8Array(32));
    const threw = thrown.throw?.(value);
    expect(thrown.return?.()).toBe(threw);
    await expect(threw).rejects.toBe(value);
    expect(await thrown.next()).toEqual(done);

    // Once its outcome was taken, a retirement settles at once.
    const ended = right.request(right.identity.peerId, BLOCKS, new Uint8Array(32));
    await expect(ended.next()).rejects.toMatchObject({reason: "disconnected"});
    await expect(ended.throw?.(value)).rejects.toBe(value);
    await expect
      .poll(() => right.diagnostics().requests)
      .toMatchObject({occupied: 0, pendingPulls: 0, reservedBytes: 0});
  } finally {
    await Promise.all([left.close(), right.close()]);
  }
}, 20000);

test("close hands each unpulled request's outcome to its iterator, whose next pull takes it", async () => {
  const {left, peer, right} = await servedPair();
  try {
    const delivered = right.request(peer, BLOCKS, new Uint8Array(32));
    const first = delivered.next();
    await (await takeIncoming(left)).respond(chunk(3), requestForks[0]);
    await first;
    const held = right.request(peer, BLOCKS, new Uint8Array(32));
    await takeIncoming(left);
    const refused = right.request(right.identity.peerId, BLOCKS, new Uint8Array(32));
    await expect.poll(() => right.diagnostics().requests.terminalCells).toBe(1);
    expect(await right.close()).toEqual({reason: "requested"});
    // No request outlives the close.
    expect(right.diagnostics().requests).toMatchObject({
      occupied: 0,
      pendingPulls: 0,
      reservedBytes: 0,
      terminalCells: 0,
    });
    for (const stream of [delivered, held, refused]) {
      await expect(stream.next()).rejects.toMatchObject({code: "NetworkClosed"});
      expect(await stream.next()).toEqual(done);
      expect(await stream.return?.()).toEqual(done);
    }
  } finally {
    await Promise.all([left.close(), right.close()]);
  }
}, 20000);

test("a full request table delivers every outcome and reuses each cell with the next generation", async () => {
  const {commandCompleted, networkBindings: bindings} = await import("./utils/network-bindings.js");
  const config = applicationConfig();
  const native = new bindings.NativeNetworkRuntime();
  const lifecycle = native.initialize(config, () => undefined);
  try {
    const self = lifecycle.identity.peerId;
    await commandCompleted(native, native.applyIntent(localIntent(config), config.initialSlot), settleOnly);
    const capacity = native.diagnostics().requests.capacity;
    for (const generation of [1n, 2n]) {
      const handles = Array.from({length: capacity}, () =>
        native.requestStart(self, BLOCKS, new Uint8Array(32), undefined)
      );
      expect(handles.map((handle) => handle.generation)).toEqual(handles.map(() => generation));
      expect(() => native.requestStart(self, BLOCKS, new Uint8Array(32), undefined)).toThrow(
        expect.objectContaining({code: "NetworkRequestRejected", reason: "slots_exhausted"})
      );
      for (const handle of handles) native.requestPull(handle);
      const outcomes = new Map<number, unknown>();
      for (let i = 0; i < 2000 && outcomes.size < capacity; i++) {
        for (const completion of native.exchange([], settleOnly).completions)
          if (completion.family === "request") outcomes.set(completion.handle.index, completion);
        await new Promise((resolve) => setTimeout(resolve, 5));
      }
      expect([...outcomes.values()]).toEqual(
        handles.map(() => expect.objectContaining({error: expect.objectContaining({reason: "disconnected"})}))
      );
      for (const handle of handles) expect(() => native.requestPull(handle)).toThrow("InvalidRequestHandle");
    }
    expect(native.diagnostics().requests).toMatchObject({occupied: 0, requestFull: 2n, reservedBytes: 0});
  } finally {
    native.close();
    await lifecycle.closed;
  }
});

test("requests start in their admission order among commands", async () => {
  const runtime = startRuntime(applicationConfig());
  try {
    runtime.holdOperations(true);
    const outcome = () =>
      runtime
        .request(runtime.identity.peerId, BLOCKS, new Uint8Array(32))
        .next()
        .catch(() => undefined);
    const first = outcome();
    const before = runtime.getIdentity();
    const second = outcome();
    const after = runtime.getIdentity();
    // Released together, each starts in one pass that advances the owner's sequence once per operation.
    runtime.holdOperations(false);
    const [a, b] = await Promise.all([before, after]);
    await Promise.all([first, second]);
    expect(b.ownerSequence - a.ownerSequence).toBe(2n);
  } finally {
    await runtime.close();
  }
});
