import {expect, test} from "vitest";
import {createNativeNetworkApplicationRuntime} from "../src/network.js";
import {applicationConfig, localIntent} from "./utils/network.js";

test("application request rejects control protocols at the exported boundary", async () => {
  const config = applicationConfig();
  const runtime = createNativeNetworkApplicationRuntime(config, () => undefined);
  try {
    const identity = await runtime.ready;
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
  const runtime = createNativeNetworkApplicationRuntime(config, () => undefined);
  try {
    const identity = await runtime.ready;
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
    "test/interop/request_responder.mjs",
    HOST,
    ...(HOODI ? [HOODI] : []),
  ]);
  let runtime: ReturnType<typeof createNativeNetworkApplicationRuntime> | undefined;
  try {
    const info = await peer.command("ready");
    const config = applicationConfig();
    config.resources.bridgeBudgetBytes = 512 * 1024 * 1024;
    config.requestForks.push({digest: Uint8Array.of(5, 6, 7, 8), fork: "electra"});
    config.requestForks.push({digest: Uint8Array.of(9, 10, 11, 12), fork: "fulu"});
    runtime = createNativeNetworkApplicationRuntime(config, () => undefined);
    await runtime.ready;
    await runtime.applyIntent(localIntent(config), config.initialSlot);
    const id = Uint8Array.from(Buffer.from(info.peer, "hex"));
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
      const cancelled = expect(pending).rejects.toMatchObject({code: "NetworkRequestFailed", reason: "cancelled"});
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
  const runtime = createNativeNetworkApplicationRuntime(config, () => undefined);
  try {
    const identity = await runtime.ready;
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
        ["05060708", "electra", 4000],
        ["01020304", "deneb", 10 * 1024 * 1024],
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
    const {runtime, peer, id, config} = await connected();
    try {
      await expect(runtime.request(id, BLOCKS, new Uint8Array(32), {expectedChunks: 2}).next()).rejects.toMatchObject({
        code: "NetworkRequestRejected",
        reason: "invalid_request_options",
      });
      await expect(runtime.request(id, BLOCKS, new Uint8Array(1)).next()).rejects.toMatchObject({
        code: "NetworkRequestRejected",
        reason: "invalid_request",
      });
      const intent = localIntent(config);
      intent.update.capabilities.request = intent.update.capabilities.request.filter((protocol) => protocol !== BLOCKS);
      const update = runtime.applyIntent(intent, config.initialSlot);
      const disabled = runtime.request(id, BLOCKS, new Uint8Array(32));
      await update;
      await expect(disabled.next()).rejects.toMatchObject({
        code: "NetworkRequestRejected",
        reason: "protocol_disabled",
      });
      await runtime.applyIntent(localIntent(config), config.initialSlot);
      await peer.command("scenario", {scenario: "hold"});
      const streams = Array.from({length: 6}, () => runtime.request(id, BLOCKS, new Uint8Array(32)));
      expect(() => runtime.request(id, BLOCKS, new Uint8Array(32))).toThrow("NetworkRequestFull");
      await expect(streams[2].next()).rejects.toMatchObject({
        code: "NetworkRequestRejected",
        reason: "too_many_requests",
      });
      const {multiaddr} = await import("@multiformats/multiaddr");
      const identity = await runtime.getIdentity();
      expect((await peer.command("ping", {address: multiaddr(identity.localMultiaddr).toString()})).length).toBe(8);
      await runtime.reStatusPeers([id]);
      const {waitFor} = await import("../../test/interop/child.mjs");
      await waitFor(async () => (await peer.command("stats")).control.status >= 2);
      await Promise.all(streams.map((stream) => stream.return?.()));
      const commands = Array.from({length: 32}, () => runtime.getIdentity());
      expect(() => runtime.request(id, BLOCKS, new Uint8Array(32))).toThrow("NetworkCommandFull");
      await Promise.all(commands);
      expect(runtime.diagnostics().requests).toMatchObject({
        commandFull: 1n,
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
    ["--expose-gc", "--import", "tsx", "bindings/test/fixtures/network-request-lifecycle.mjs", mode],
    {encoding: "utf8", timeout: 20000}
  );
  expect(output).toContain(`request-lifecycle ${mode} ok`);
}, 25000);

test("native peers refuse new application requests while managed control remains live", async () => {
  const leftConfig = applicationConfig();
  const rightConfig = applicationConfig();
  leftConfig.resources.bridgeBudgetBytes = 128 * 1024 * 1024;
  rightConfig.identitySecretKey[31] = 2;
  const left = createNativeNetworkApplicationRuntime(leftConfig, () => undefined);
  const right = createNativeNetworkApplicationRuntime(rightConfig, () => undefined);
  try {
    const [identity, remote] = await Promise.all([left.ready, right.ready]);
    await Promise.all([
      left.applyIntent(localIntent(leftConfig), leftConfig.initialSlot),
      right.applyIntent(localIntent(rightConfig), rightConfig.initialSlot),
    ]);
    await left.connect(remote.peerId, [remote.localEndpoint], 5000n);
    await expect(left.request(remote.peerId, BLOCKS, new Uint8Array(32)).next()).rejects.toMatchObject({
      code: "NetworkRequestFailed",
      peerMessage: new TextEncoder().encode("application handlers unavailable"),
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

test("application request byte admission is exact and raw runtimes expose zero capacity", async () => {
  const config = applicationConfig();
  const probe = createNativeNetworkApplicationRuntime(config, () => undefined);
  await probe.ready;
  const fixed = probe.diagnostics().bridgeRequestedBytes;
  await probe.close();
  for (const delta of [0, -1]) {
    const nextConfig = applicationConfig();
    nextConfig.resources.bridgeBudgetBytes = fixed + 32 + 2 * 10 * 1024 * 1024 + delta;
    const runtime = createNativeNetworkApplicationRuntime(nextConfig, () => undefined);
    try {
      const identity = await runtime.ready;
      await runtime.applyIntent(localIntent(nextConfig), nextConfig.initialSlot);
      if (delta === 0) {
        const stream = runtime.request(identity.peerId, BLOCKS, new Uint8Array(32));
        await expect(stream.next()).rejects.toMatchObject({reason: "disconnected"});
      } else expect(() => runtime.request(identity.peerId, BLOCKS, new Uint8Array(32))).toThrow("NetworkBridgeFull");
      expect(runtime.diagnostics().requests).toMatchObject({
        inputBytes: 0,
        occupied: 0,
        reservedBytes: 0,
        sinkBytes: 0,
      });
    } finally {
      await runtime.close();
    }
  }
  const {createNativeNetworkRuntime} = await import("../src/network.js");
  const {networkConfig} = await import("./utils/network.js");
  const raw = createNativeNetworkRuntime(networkConfig(), () => undefined);
  try {
    await raw.ready;
    expect(raw.diagnostics().requests).toMatchObject({capacity: 0, occupied: 0, reservedBytes: 0});
  } finally {
    await raw.close();
  }
});

test.skipIf(!HOST || !HOODI)(
  "retained Hoodi bytes round-trip with a supported Fulu response context",
  async () => {
    const {runtime, peer, id} = await connected();
    try {
      const {readFile} = await import("node:fs/promises");
      const {summary} = await import("../../test/interop/codec.mjs");
      await peer.command("scenario", {count: 1, digest: "090a0b0c", scenario: "hoodi"});
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
  const {default: bindings} = await import("../src/bindings.js");
  const config = applicationConfig();
  config.resources.bridgeBudgetBytes = 128 * 1024 * 1024;
  const native = new bindings.NativeNetworkRuntime();
  const lifecycle = native.prepare(config, () => undefined);
  try {
    const identity = await lifecycle.ready;
    await native.applyIntent(localIntent(config), config.initialSlot);
    const handle = native.requestStart(identity.peerId, BLOCKS, new Uint8Array(32), undefined);
    expect(() => native.requestPull({...handle, session: handle.session + 1n})).toThrow("InvalidRequestHandle");
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
    const {default: bindings} = await import("../src/bindings.js");
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
    config.requestForks.push({digest: Uint8Array.of(1, 0, 0, 0), fork: "deneb"});
    const runtime = createNativeNetworkApplicationRuntime(config, () => undefined);
    try {
      const remote = await peer.command("listen");
      await peer.command("respond", {seed: 71, size: 4000});
      await runtime.ready;
      await runtime.applyIntent(localIntent(config), config.initialSlot);
      const parts = remote.address.split("/");
      const id = Uint8Array.from(Buffer.from(remote.peer, "hex"));
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
    const {runtime, peer, id, config} = await connected();
    const {default: bindings} = await import("../src/bindings.js");
    const native = new bindings.NativeNetworkRuntime();
    let closed: Promise<unknown> | undefined;
    try {
      await runtime.close();
      await peer.command("scenario", {scenario: "hold"});
      const prepared = native.prepare(config, () => undefined);
      closed = prepared.closed;
      await prepared.ready;
      await native.applyIntent(localIntent(config), config.initialSlot);
      const remote = await peer.command("ready");
      await native.connect(
        id,
        [{address: Uint8Array.of(127, 0, 0, 1), family: 4, port: Number(remote.address.split("/")[4])}],
        5000n
      );
      const handle = native.requestStart(id, BLOCKS, new Uint8Array(32), undefined);
      const pending = native.requestPull(handle);
      await expect(native.requestPull(handle)).rejects.toMatchObject({code: "NetworkRequestBusy"});
      expect(native.diagnostics().requests.busyPulls).toBe(1n);
      const cancelled = expect(pending).rejects.toMatchObject({code: "NetworkRequestFailed", reason: "cancelled"});
      await native.requestRetire(handle, false);
      await cancelled;
    } finally {
      native.close();
      await closed;
      await runtime.close();
      await peer.stop();
    }
  },
  20000
);
