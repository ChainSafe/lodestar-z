import {expect, test} from "vitest";
import {applicationConfig, localIntent, peerIdFromHex, requestForks, startRuntime} from "./utils/network.js";
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

test("request validation rejects late malformed options and detached backing without retained ownership", async () => {
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
    const input = new Uint8Array(32);
    expect(() =>
      runtime.request(identity.peerId, BLOCKS, input, {
        get responseTimeoutMs() {
          structuredClone(input.buffer, {transfer: [input.buffer]});
          return 5000;
        },
      })
    ).toThrow("InvalidNetworkBytes");
    expect(runtime.diagnostics().requests).toMatchObject({occupied: 0, reservedBytes: 0});
    expect(runtime.diagnostics().operationOccupied).toBe(0);
    expect(() =>
      runtime.request(identity.peerId, BLOCKS, new Uint8Array(32), {
        get responseTimeoutMs() {
          void runtime.close();
          return 5000;
        },
      })
    ).toThrow("NetworkClosed");
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
  ...(HOST ? ["iterator-gc", "facade-gc"] : []),
  "exit",
  "closed-terminal",
  "closed-facade-gc",
  "closed-facade-gc-early",
  ...(process.env.LODESTAR_Z_NETWORK_TEST_FAILURES === "1" ? ["closed-terminal-fault"] : []),
])("request lifecycle settles independently of facade and notifier: %s", async (mode) => {
  const {execFileSync} = await import("node:child_process");
  const output = execFileSync(
    process.execPath,
    ["--import", "tsx", "--expose-gc", "--import", "tsx", "bindings/test/fixtures/network-request-lifecycle.mjs", mode],
    {encoding: "utf8", timeout: 20000}
  );
  expect(output).toContain(`request-lifecycle ${mode} ok`);
}, 25000);

test("native peers refuse requests without bridge bytes while managed control remains live", async () => {
  const leftConfig = applicationConfig();
  const rightConfig = applicationConfig();
  leftConfig.resources.bridgeBudgetBytes = 128 * 1024 * 1024;
  const baseline = await startPeer(rightConfig);
  await baseline.identity;
  rightConfig.resources.bridgeBudgetBytes = (await baseline.diagnostics()).bridgeRequestedBytes;
  await baseline.stop();
  rightConfig.identitySecretKey[31] = 2;
  const left = startRuntime(leftConfig, () => undefined);
  const right = await startPeer(rightConfig);
  try {
    const [identity, remote] = await Promise.all([left.identity, right.identity]);
    await Promise.all([
      left.applyIntent(localIntent(leftConfig), leftConfig.initialSlot),
      right.applyIntent(localIntent(rightConfig), rightConfig.initialSlot),
    ]);
    await left.connect(remote.peerId, [remote.localEndpoint], 5000n);
    await expect(left.request(remote.peerId, BLOCKS, new Uint8Array(32)).next()).rejects.toMatchObject({
      code: "NetworkRequestFailed",
      peerMessage: new TextEncoder().encode("application capacity exhausted"),
      peerStatus: 2,
      reason: "peer_error",
    });
    await left.reStatusPeers([remote.peerId]);
    expect((await left.getIdentity()).peerId).toEqual(identity.peerId);
    expect((await right.getIdentity()).peerId).toEqual(remote.peerId);
    expect(left.diagnostics().requests.reservedBytes).toBe(0);
  } finally {
    await Promise.all([left.close(), right.close()]);
  }
}, 15000);

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

test.each([0, -1])("application request byte admission at delta %s", async (delta) => {
  const config = applicationConfig();
  const probe = await startPeer(config);
  const fixed = (await probe.diagnostics()).bridgeRequestedBytes;
  await probe.stop();
  config.resources.bridgeBudgetBytes = fixed + 32 + 2 * 10 * 1024 * 1024 + delta;
  const runtime = startRuntime(config);
  try {
    if (delta === 0)
      await expect(runtime.request(runtime.identity.peerId, BLOCKS, new Uint8Array(32)).next()).rejects.toMatchObject({
        reason: "disconnected",
      });
    else
      expect(() => runtime.request(runtime.identity.peerId, BLOCKS, new Uint8Array(32))).toThrow(
        expect.objectContaining({code: "NetworkRequestRejected", reason: "slots_exhausted"})
      );
    expect(runtime.diagnostics().requests).toMatchObject({inputBytes: 0, occupied: 0, reservedBytes: 0, sinkBytes: 0});
  } finally {
    await runtime.close();
  }
});

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
  const {networkBindings: bindings} = await import("./utils/network-bindings.js");
  const config = applicationConfig();
  config.resources.bridgeBudgetBytes = 128 * 1024 * 1024;
  const native = new bindings.NativeNetworkRuntime();
  const lifecycle = native.initialize(config, () => undefined);
  try {
    const identity = await lifecycle.identity;
    await native.applyIntent(localIntent(config), config.initialSlot);
    const handle = native.requestStart(identity.peerId, BLOCKS, new Uint8Array(32), undefined);
    expect(() => native.requestPull({...handle, generation: 0n})).toThrow("InvalidRequestHandle");
    expect(() => native.requestPull({...handle, generation: handle.generation + 1n})).toThrow("InvalidRequestHandle");
    const pending = native.requestPull(handle);
    await expect(pending).rejects.toMatchObject({reason: "disconnected"});
    expect(() => native.requestPull(handle)).toThrow("InvalidRequestHandle");
    expect(native.requestRetire(handle, true)).toBeUndefined();
  } finally {
    native.close();
    await lifecycle.closed;
  }
});

test.skipIf(!HOST || process.env.LODESTAR_Z_NETWORK_TEST_FAILURES !== "1")(
  "a fault after final chunk allocation releases its pin and native sink",
  async () => {
    const {networkBindings: bindings} = await import("./utils/network-bindings.js");
    const {runtime, peer, id} = await connected();
    try {
      bindings.networkTestFail("operation_copy");
      const stream = runtime.request(id, BLOCKS, new Uint8Array(64));
      await expect(stream.next()).rejects.toMatchObject({code: "NetworkResultAllocationFailed"});
      await runtime.close();
      expect(runtime.diagnostics().requests).toMatchObject({
        copyingBytes: 0,
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
    config.resources.bridgeBudgetBytes = 128 * 1024 * 1024;
    const runtime = startRuntime(config, () => undefined);
    try {
      const remote = await peer.command("listen");
      await peer.command("respond", {seed: 71, size: 4000});
      await runtime.identity;
      await runtime.applyIntent(localIntent(config), config.initialSlot);
      const parts = remote.address.split("/");
      const id = peerIdFromHex(remote.peer);
      await runtime.connect(id, [{address: Uint8Array.of(127, 0, 0, 1), family: 4, port: Number(parts[4])}], 5000n);
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
    const {native, peer, id, stop} = await connectedNative();
    try {
      await peer.command("scenario", {scenario: "hold"});
      const handle = native.requestStart(id, BLOCKS, new Uint8Array(32), undefined);
      const pending = native.requestPull(handle);
      await expect(native.requestPull(handle)).rejects.toMatchObject({code: "NetworkRequestBusy"});
      expect(native.diagnostics().requests.busyPulls).toBe(1n);
      const {waitFor} = await import("../../test/interop/child.mjs");
      await waitFor(async () => (await peer.command("stats")).lastRequest === "00".repeat(32));
      const cancelled = expect(pending).rejects.toMatchObject({
        code: "NetworkRequestFailed",
        phase: "response",
        reason: "cancelled",
      });
      await native.requestRetire(handle, false);
      await cancelled;
    } finally {
      await stop();
    }
  },
  20000
);

async function connectedNative(scenario?: string) {
  if (!HOST) throw Error("LODESTAR_Z_NETWORK_STOCK_HOST is required");
  const {Child} = await import("../../test/interop/child.mjs");
  const {networkBindings: bindings} = await import("./utils/network-bindings.js");
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
    config.resources.bridgeBudgetBytes = 128 * 1024 * 1024;
    if (scenario) bindings.networkTestScenario(scenario);
    native = new bindings.NativeNetworkRuntime();
    const prepared = native.initialize(config, () => undefined);
    closed = prepared.closed;
    await prepared.identity;
    await native.applyIntent(localIntent(config), config.initialSlot);
    const id = peerIdFromHex(remote.peer);
    await native.connect(
      id,
      [{address: Uint8Array.of(127, 0, 0, 1), family: 4, port: Number(remote.address.split("/")[4])}],
      5000n
    );
    return {bindings, closed, id, native, peer, stop};
  } catch (error) {
    await stop();
    throw error;
  }
}

const phaseTest = test.skipIf(!HOST || process.env.LODESTAR_Z_NETWORK_TEST_FAILURES !== "1");
phaseTest.each([
  ["request_queued", null],
  ["request_negotiation", "negotiation"],
] as const)(
  "request cancellation establishes %s ownership and isolates the replacement generation",
  async (scenario, phase) => {
    const {bindings, native, peer, id, stop} = await connectedNative(scenario);
    try {
      const {waitFor} = await import("../../test/interop/child.mjs");
      await peer.command("scenario", {scenario: "hold"});
      const old = native.requestStart(id, BLOCKS, new Uint8Array(32), undefined);
      const pending = native.requestPull(old);
      const failed = expect(pending).rejects.toMatchObject({code: "NetworkRequestFailed", phase, reason: "cancelled"});
      await waitFor(() => bindings.networkTestStage() === scenario);
      if (process.env.LODESTAR_Z_NETWORK_REQUEST_EVIDENCE === "1") console.log(scenario, bindings.networkTestRequest());
      expect(bindings.networkTestRequest()).toMatchObject({
        bridgeGeneration: old.generation,
        copying: false,
        coreLive: true,
        destinationBytes: 0,
        inputBytes: 32,
        nativeOwned: phase !== null,
        negotiatorMatched: phase !== null,
        phase,
        quiescent: false,
        reservedBytes: 20971552,
        sinkBytes: 10485760,
      });
      expect(native.diagnostics().requests).toMatchObject({
        inputBytes: 32,
        occupied: 1,
        pendingPulls: 1,
        reservedBytes: 20971552,
        sinkBytes: 10485760,
      });
      expect((await peer.command("stats")).requests).toBe(0);
      const retired = native.requestRetire(old, false);
      await retired;
      await failed;
      expect(native.diagnostics().requests).toMatchObject({
        inputBytes: 0,
        occupied: 0,
        pendingPulls: 0,
        reservedBytes: 0,
        sinkBytes: 0,
      });
      const replacementInput = new Uint8Array(32).fill(7);
      const replacement = native.requestStart(id, BLOCKS, replacementInput, undefined);
      expect(replacement.index).toBe(old.index);
      expect(replacement.generation).toBe(old.generation + 1n);
      const next = native.requestPull(replacement);
      const cancelled = expect(next).rejects.toMatchObject({
        code: "NetworkRequestFailed",
        phase: "response",
        reason: "cancelled",
      });
      await waitFor(async () => (await peer.command("stats")).lastRequest === "07".repeat(32));
      expect(native.requestRetire(old, true)).toBeUndefined();
      expect(() => native.requestPull(old)).toThrow("InvalidRequestHandle");
      expect(native.diagnostics().requests).toMatchObject({
        occupied: 1,
        pendingPulls: 1,
        reservedBytes: 20971552,
        terminalCells: 0,
      });
      await native.requestRetire(replacement, false);
      await cancelled;
      expect(native.diagnostics().requests).toMatchObject({inputBytes: 0, occupied: 0, reservedBytes: 0, sinkBytes: 0});
    } finally {
      await stop();
    }
  },
  20000
);

phaseTest.each([false, true])(
  "physical close overlaps a pinned final JS destination (copy fault: %s)",
  async (failCopy) => {
    const {bindings, closed, native, peer, id, stop} = await connectedNative("request_copy_close");
    try {
      const {payload} = await import("../../test/interop/codec.mjs");
      await peer.command("scenario", {count: 1, scenario: "chunks"});
      const handle = native.requestStart(id, BLOCKS, new Uint8Array(32), undefined);
      if (failCopy) bindings.networkTestFail("operation_copy");
      const pull = native.requestPull(handle);
      if (failCopy) await expect(pull).rejects.toMatchObject({code: "NetworkResultAllocationFailed"});
      else {
        const first = await pull;
        expect(first).toMatchObject({done: false, value: {fork: "deneb", protocol: BLOCKS}});
        if (first.done) throw new Error("Expected a response chunk");
        expect(first.value.data).toEqual(Uint8Array.from(payload(4000, 71)));
      }
      expect(bindings.networkTestStage()).toBe("request_copy_closed");
      if (process.env.LODESTAR_Z_NETWORK_REQUEST_EVIDENCE === "1")
        console.log("request_copy_closed", bindings.networkTestRequest());
      expect(bindings.networkTestRequest()).toMatchObject({
        bridgeGeneration: handle.generation,
        copying: true,
        coreLive: false,
        destinationBytes: 4000,
        inputBytes: 32,
        nativeOwned: false,
        quiescent: true,
        reservedBytes: 20971552,
        sinkBytes: 10485760,
      });
      expect(native.diagnostics()).toMatchObject({
        copyingPins: 0,
        liveNativeRequestedBytes: 0,
      });
      expect(native.diagnostics().requests).toMatchObject({
        bytesCopied: failCopy ? 0n : 4000n,
        chunksCopied: failCopy ? 0n : 1n,
        copyingBytes: 0,
        inputBytes: 0,
        reservedBytes: 0,
        sinkBytes: 0,
      });
      await closed;
      expect(native.diagnostics().requests.occupied).toBe(failCopy ? 0 : 1);
      if (!failCopy) await expect(native.requestPull(handle)).rejects.toMatchObject({code: "NetworkClosed"});
      await stop();
      const {waitFor} = await import("../../test/interop/child.mjs");
      await waitFor(() => native.diagnostics().requests.occupied === 0);
      const after = native.diagnostics();
      expect(after.requests.occupied).toBe(0);
      expect(after.liveBridgeRequestedBytes).toBe(
        after.ownerShellBytes + after.peerLaneBytes + after.metricsExportBytes
      );
    } finally {
      await stop();
    }
  },
  20000
);

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
