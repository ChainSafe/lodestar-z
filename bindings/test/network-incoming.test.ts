import {expect, test} from "vitest";
import {type NativeIncomingRequest, initializeNativeNetworkRuntime} from "../src/network.js";
import {
  applicationConfig,
  capacity,
  localIntent,
  nextIncoming,
  requestForks,
  settleOnly,
  startRuntime,
  unreachableConnect,
} from "./utils/network.js";
import {startPeer} from "./utils/network-peer.js";

test("incoming request take is empty on an active application", async () => {
  const config = applicationConfig();
  config.resources.bridgeBudgetBytes = 512 * 1024 * 1024;
  const runtime = startRuntime(config, () => undefined);
  try {
    await runtime.identity;
    await runtime.applyIntent(localIntent(config), config.initialSlot);
    expect(nextIncoming(runtime)).toBeNull();
    const diagnostics = runtime.diagnostics().incoming;
    for (const field of [
      "requestsTaken",
      "responseBytesCopied",
      "chunksWritten",
      "bytesWritten",
      "capacityRefusals",
      "byteRefusals",
    ] as const) {
      expect(typeof diagnostics[field]).toBe("bigint");
    }
    for (const field of [
      "capacity",
      "occupied",
      "queued",
      "highWater",
      "pendingResponses",
      "closedPromises",
      "reservedBytes",
      "reservedBytesHighWater",
      "requestBytes",
      "responseBytes",
      "copyingBytes",
    ] as const) {
      expect(typeof diagnostics[field]).toBe("number");
    }
    expect(runtime.diagnostics().incoming).toMatchObject({
      capacity: 6,
      copyingBytes: 0,
      occupied: 0,
      queued: 0,
      requestBytes: 0,
      requestsTaken: 0n,
      reservedBytes: 0,
      responseBytes: 0,
    });
  } finally {
    await runtime.close();
  }
});

import {BLOCKS, incomingPair, takeIncoming} from "./utils/network-incoming.js";

test("incoming cancellation retains execution until host work retires", async () => {
  const pair = await incomingPair();
  let retire: () => void = () => undefined;
  const retired = new Promise<void>((resolve) => {
    retire = resolve;
  });
  try {
    const stream = pair.left.request(pair.remote.peerId, BLOCKS, new Uint8Array(32));
    const pending = stream.next().catch(() => undefined);
    const incoming = await takeIncoming(pair.right);
    incoming.retainUntil(retired);
    expect(() => incoming.retainUntil(retired)).toThrow("NetworkIncomingRetentionInvalid");
    await incoming.cancel();
    await pending;
    expect(pair.right.diagnostics().incoming).toMatchObject({
      occupied: 1,
      pendingPermissions: 0,
      pendingResponses: 0,
      requestBytes: 0,
      responseBytes: 0,
      retiring: 1,
    });
    retire();
    await expect.poll(() => pair.right.diagnostics().incoming.occupied).toBe(0);
    expect(pair.right.diagnostics().incoming.retiring).toBe(0);
  } finally {
    retire();
    await Promise.all([pair.left.close(), pair.right.close()]);
  }
}, 15000);

test("incoming response permission reserves quota before payload production", async () => {
  const pair = await incomingPair();
  try {
    const stream = pair.left.request(pair.remote.peerId, BLOCKS, new Uint8Array(32));
    const pending = stream.next();
    void pending.catch(() => undefined);
    const incoming = await takeIncoming(pair.right);
    const permission = incoming.ready();
    await expect(incoming.ready()).rejects.toMatchObject({code: "NetworkIncomingBusy"});
    await permission;
    expect(pair.right.diagnostics().incoming.responseBytes).toBe(0);
    const payload = new Uint8Array(4000).fill(17);
    await incoming.respond(payload, requestForks[0]);
    expect(await pending).toMatchObject({done: false, value: {data: payload}});
    await incoming.finish();
    await expect(incoming.ready()).rejects.toMatchObject({code: "NetworkIncomingClosed"});
  } finally {
    await Promise.all([pair.left.close(), pair.right.close()]);
  }
}, 15000);

test("incoming copied metadata and acknowledged multiple contexts preserve wire bytes", async () => {
  const pair = await incomingPair();
  try {
    // Leave room below the client chunk limit so this test observes server EOF, not client cancellation.
    const query = new Uint8Array(3 * 32).fill(7);
    const stream = pair.left.request(pair.remote.peerId, BLOCKS, query);
    const pending = stream.next();
    void pending.catch(() => undefined);
    const incoming = await takeIncoming(pair.right);
    expect(incoming.data).toEqual(query);
    expect(incoming.protocol).toBe(BLOCKS);
    expect(incoming.peerId).toEqual(pair.identity.peerId);
    const peers = await pair.right.getPeers();
    expect(incoming.connection).toEqual(peers.peers[0].connection);

    incoming.connection.generation++;
    incoming.data.fill(0);
    const payload = new Uint8Array(4000).fill(31);
    const ack = incoming.respond(payload, requestForks[0]);
    payload.fill(99);
    await expect(incoming.respond(payload, null)).rejects.toMatchObject({code: "NetworkIncomingBusy"});
    await expect(incoming.finish()).rejects.toMatchObject({code: "NetworkIncomingBusy"});
    await ack;
    expect(await pending).toMatchObject({
      done: false,
      value: {data: new Uint8Array(4000).fill(31), fork: "deneb", protocol: BLOCKS},
    });
    const second = stream.next();
    await incoming.respond(new Uint8Array(4000).fill(42), requestForks[1]);
    expect(await second).toMatchObject({done: false, value: {data: new Uint8Array(4000).fill(42)}});
    const done = stream.next();
    expect(incoming.finish()).toBe(incoming.closed);
    expect(incoming.fail(139, new Uint8Array())).toBe(incoming.closed);
    expect(await incoming.closed).toBeUndefined();
    expect(await done).toEqual({done: true, value: undefined});
    await expect(incoming.respond(payload, null)).rejects.toMatchObject({code: "NetworkIncomingClosed"});
    await expect.poll(() => pair.right.diagnostics().incoming.occupied).toBe(0);
    expect(pair.right.diagnostics().incoming).toMatchObject({
      bytesWritten: 8000n,
      chunksWritten: 2n,
      occupied: 0,
      requestBytes: 0,
      requestsTaken: 1n,
      reservedBytes: 0,
      responseBytes: 0,
    });
  } finally {
    await Promise.all([pair.left.close(), pair.right.close()]);
  }
}, 15000);

test.each([1, 2, 3, 128, 139, 255])("incoming error status %s preserves exact encoded bytes", async (status) => {
  const pair = await incomingPair();
  try {
    const stream = pair.left.request(pair.remote.peerId, BLOCKS, new Uint8Array(32));
    const pending = stream.next();
    void pending.catch(() => undefined);
    const rejection = expect(pending).rejects.toMatchObject({
      code: "NetworkRequestFailed",
      peerMessage: new TextEncoder().encode("limité 超"),
      peerStatus: status,
      reason: "peer_error",
    });
    const incoming = await takeIncoming(pair.right);
    expect(incoming.fail(status, new TextEncoder().encode("limité 超"))).toBe(incoming.closed);
    expect(await incoming.closed).toBeUndefined();
    await rejection;
  } finally {
    await Promise.all([pair.left.close(), pair.right.close()]);
  }
}, 15000);

test("incoming invalid context keeps the serving slot and empty finish reaches wire EOF", async () => {
  const pair = await incomingPair();
  try {
    const stream = pair.left.request(pair.remote.peerId, BLOCKS, new Uint8Array(32));
    const pending = stream.next();
    void pending.catch(() => undefined);
    const incoming = await takeIncoming(pair.right);
    await expect(incoming.respond(new Uint8Array(4000), null)).rejects.toMatchObject({
      code: "NetworkIncomingRejected",
      reason: "unknown_fork",
    });
    await expect(
      incoming.respond(new Uint8Array(4000), {digest: requestForks[0].digest, fork: "electra"})
    ).rejects.toMatchObject({code: "NetworkIncomingRejected", reason: "unknown_fork"});
    await expect(incoming.respond(new Uint8Array(1), requestForks[0])).rejects.toMatchObject({
      code: "NetworkIncomingRejected",
      reason: "chunk_too_small",
    });
    expect(incoming.finish()).toBe(incoming.closed);
    expect(await incoming.closed).toBeUndefined();
    expect(await pending).toEqual({done: true, value: undefined});
  } finally {
    await Promise.all([pair.left.close(), pair.right.close()]);
  }
}, 15000);

test("incoming input validation rolls back before a later valid response", async () => {
  const pair = await incomingPair();
  try {
    const stream = pair.left.request(pair.remote.peerId, BLOCKS, new Uint8Array(32));
    const pending = stream.next();
    void pending.catch(() => undefined);
    const incoming = await takeIncoming(pair.right);
    for (const status of [0, -1, 4, 5, 127, 256, 1.5, Number.NaN, Number.MAX_SAFE_INTEGER + 1]) {
      await expect(incoming.fail(status, new Uint8Array())).rejects.toMatchObject({
        code: "NetworkIncomingRejected",
        reason: "invalid_error",
      });
    }
    const extraContext = {...requestForks[0], unexpected: true};
    await expect(incoming.respond(new Uint8Array(4000), extraContext)).rejects.toMatchObject({
      code: "InvalidNetworkConfig",
    });
    await expect(
      incoming.respond(new Uint8Array(4000), {digest: new Uint8Array(3), fork: "deneb"})
    ).rejects.toMatchObject({
      code: "InvalidNetworkBytes",
    });
    await expect(incoming.fail(2, new Uint8Array(257))).rejects.toMatchObject({
      code: "NetworkIncomingRejected",
      reason: "invalid_error",
    });
    const oversized = new Uint8Array(10 * 1024 * 1024 + 1);
    await expect(incoming.respond(oversized, requestForks[0])).rejects.toMatchObject({
      code: "NetworkIncomingRejected",
      reason: "chunk_too_large",
    });
    const data = new Uint8Array(4000);
    const context = {
      digest: requestForks[0].digest,
      get fork() {
        structuredClone(data.buffer, {transfer: [data.buffer]});
        return "deneb" as const;
      },
    };
    await expect(incoming.respond(data, context)).rejects.toMatchObject({code: "InvalidNetworkBytes"});
    expect(pair.right.diagnostics().incoming).toMatchObject({
      pendingResponses: 0,
      responseBytes: 0,
      responseBytesCopied: 0n,
    });
    await incoming.respond(new Uint8Array(4000), requestForks[0]);
    expect((await pending).done).toBe(false);
    await incoming.finish();
    expect((await stream.next()).done).toBe(true);
  } finally {
    await Promise.all([pair.left.close(), pair.right.close()]);
  }
}, 15000);

test("incoming chunk ceiling rejects an extra response without losing finish", async () => {
  const pair = await incomingPair();
  try {
    const stream = pair.left.request(pair.remote.peerId, BLOCKS, new Uint8Array(32));
    const first = stream.next();
    void first.catch(() => undefined);
    const incoming = await takeIncoming(pair.right);
    await incoming.respond(new Uint8Array(4000), requestForks[0]);
    expect((await first).done).toBe(false);
    await expect(incoming.respond(new Uint8Array(4000), requestForks[0])).rejects.toMatchObject({
      code: "NetworkIncomingRejected",
      reason: "too_many_chunks",
    });
    // Consuming the final chunk closes the client stream; finish the server first.
    expect(await incoming.finish()).toBeUndefined();
    expect((await stream.next()).done).toBe(true);
  } finally {
    await Promise.all([pair.left.close(), pair.right.close()]);
  }
}, 15000);
const stock = test.skipIf(!process.env.LODESTAR_Z_NETWORK_STOCK_HOST);
stock(
  "pinned stock decoder receives native responses, contexts, full payload and error statuses",
  async () => {
    const {Child} = await import("../../test/interop/child.mjs");
    const {payload, summary} = await import("../../test/interop/codec.mjs");
    let peer: InstanceType<typeof Child> | undefined;
    let runtime: ReturnType<typeof startRuntime> | undefined;
    try {
      const host = process.env.LODESTAR_Z_NETWORK_STOCK_HOST;
      if (!host) throw Error("stock host path required");
      peer = new Child("incoming-stock", process.execPath, [
        "--import",
        "tsx",
        "test/interop/request_responder.mjs",
        host,
      ]);
      await peer.command("ready");
      const config = applicationConfig();
      config.resources.bridgeBudgetBytes = 512 * 1024 * 1024;
      runtime = startRuntime(config, () => undefined);
      const identity = await runtime.identity;
      await runtime.applyIntent(localIntent(config), config.initialSlot);
      const addressBytes = Buffer.from(identity.localMultiaddr).toString("hex");
      for (const status of [0, 1, 2, 3, 139]) {
        const reply = peer.command("request", {addressBytes});
        const incoming = await takeIncoming(runtime);
        if (status === 0) {
          const first = payload(4000, 18);
          const second = payload(10 * 1024 * 1024, 19);
          await incoming.respond(first, requestForks[0]);
          await incoming.respond(second, requestForks[1]);
          await incoming.finish();
          expect(await reply).toMatchObject({
            chunks: [
              {...summary(first), fork: "deneb"},
              {...summary(second), fork: "electra"},
            ],
            contexts: requestForks.slice(0, 2).map(({digest}) => Buffer.from(digest).toString("hex")),
          });
        } else {
          await incoming.fail(status, new TextEncoder().encode("limit reached"));
          expect(await reply).toMatchObject({chunks: [], message: "limit reached", status});
        }
      }
      const empty = peer.command("request", {addressBytes});
      await (await takeIncoming(runtime)).finish();
      expect(await empty).toMatchObject({chunks: []});
    } finally {
      await Promise.allSettled([runtime?.close(), peer?.stop()]).then((results) => {
        for (const result of results) if (result.status === "rejected") throw result.reason;
      });
    }
  },
  60000
);

test("terminal before take never exposes a retired request", async () => {
  const pair = await incomingPair();
  try {
    const stream = pair.left.request(pair.remote.peerId, BLOCKS, new Uint8Array(32));
    const pending = stream.next().catch(() => undefined);
    await expect.poll(() => pair.right.diagnostics().incoming.queued).toBe(1);
    await stream.return?.();
    await pair.left.disconnect(pair.remote.peerId);
    await pending;
    await expect.poll(() => pair.right.diagnostics().incoming.occupied, {timeout: 5000}).toBe(0);
    expect(nextIncoming(pair.right)).toBeNull();
  } finally {
    await Promise.all([pair.left.close(), pair.right.close()]);
  }
}, 15000);

/** Runs `run` while inherited `failure` accessors and array iteration throw, as a hostile realm could arrange. */
function trapped<T>(run: () => T): T {
  const iterator = Array.prototype[Symbol.iterator];
  const trap = () => {
    throw Error("inherited trap");
  };
  Object.defineProperty(Object.prototype, "failure", {configurable: true, get: trap, set: trap});
  Array.prototype[Symbol.iterator] = trap;
  try {
    return run();
  } finally {
    Array.prototype[Symbol.iterator] = iterator;
    Reflect.deleteProperty(Object.prototype, "failure");
  }
}

test("a serving start the binding cannot wrap is cancelled alone while the drain continues and close settles", async () => {
  const [leftConfig, rightConfig] = [applicationConfig(), applicationConfig()];
  rightConfig.identitySecretKey[31] = 2;
  const left = await startPeer(leftConfig);
  const served: NativeIncomingRequest[] = [];
  const turns: {more: boolean; failure: unknown}[] = [];
  let serving = 0;
  let hostile = false;
  let scheduled = false;
  const schedule = () => {
    if (scheduled) return;
    scheduled = true;
    setImmediate(() => {
      scheduled = false;
      const exchange = () => right.exchange([], {...settleOnly, capacity, servingStarts: serving});
      const {more, failure, serving: starts, disabledWaiting} = hostile ? trapped(exchange) : exchange();
      hostile = false;
      turns.push({failure, more});
      served.push(...starts);
      if (more) schedule();
      else if (disabledWaiting) setTimeout(schedule, 25).unref();
    });
  };
  const right = initializeNativeNetworkRuntime(rightConfig, schedule);
  // The binding registers each serving facade for finalization; the first registration fails.
  const registry = FinalizationRegistry.prototype as {register(...args: unknown[]): void};
  const register = registry.register;
  const injected = new Error("facade construction failed");
  try {
    const identity = await right.identity;
    await Promise.all([
      left.applyIntent(localIntent(leftConfig), leftConfig.initialSlot),
      right.applyIntent(localIntent(rightConfig), rightConfig.initialSlot),
    ]);
    await left.connect(identity.peerId, [identity.localEndpoint], 5000n);
    const outcomes = [0, 1].map(() =>
      left
        .request(identity.peerId, BLOCKS, new Uint8Array(32))
        .next()
        .then(
          () => "served",
          () => "cancelled"
        )
    );
    await expect.poll(() => right.diagnostics().incoming.queued).toBe(2);
    registry.register = function (this: unknown, ...args: unknown[]) {
      if (!(args[1] instanceof Object && "route" in args[1])) return register.apply(this, args);
      registry.register = register;
      throw injected;
    };
    serving = 8;
    hostile = true;
    schedule();
    await expect.poll(() => served.length + turns.filter(({failure}) => failure).length).toBe(2);
    registry.register = register;
    const failed = turns.findIndex(({failure}) => failure === injected);
    expect(turns[failed].more).toBe(true);
    await expect.poll(() => turns.length).toBeGreaterThan(failed + 1);
    expect(served).toHaveLength(1);
    await served[0].finish();
    expect((await Promise.all(outcomes)).sort()).toEqual(["cancelled", "served"]);
    expect(await right.close()).toEqual({reason: "requested"});
    expect(right.diagnostics().incoming.occupied).toBe(0);
  } finally {
    registry.register = register;
    await Promise.allSettled([left.close(), right.close()]);
  }
}, 20000);

test("settlement leaves Error to the host and drops each settled error's stack", async () => {
  // Notifications schedule nothing, so completions wait for the test's exchanges.
  let notified = 0;
  const runtime = initializeNativeNetworkRuntime(applicationConfig(), () => {
    notified++;
  });
  const original = Error;
  const limit = Object.getOwnPropertyDescriptor(original, "stackTraceLimit");
  const seen: unknown[] = [];
  let closed = false;
  void runtime.closed.then(() => {
    closed = true;
  });
  const connect = runtime.connect(...unreachableConnect()).catch((error: unknown) => error);
  try {
    const identity = runtime.getIdentity();
    await expect.poll(() => notified).toBe(1);
    // Resolving the identity looks up its `then`: the getter sees the host's limit, freezes it and replaces Error.
    // biome-ignore lint/suspicious/noThenProperty: an inherited `then` getter is how settlement runs host code.
    Object.defineProperty(Object.prototype, "then", {
      configurable: true,
      get() {
        seen.push(original.stackTraceLimit);
        Object.defineProperty(original, "stackTraceLimit", {configurable: true, value: 7, writable: false});
        Object.defineProperty(globalThis, "Error", {configurable: true, value: class extends original {}});
        return undefined;
      },
    });
    let result: ReturnType<typeof runtime.exchange> | undefined;
    try {
      result = runtime.exchange([], settleOnly);
    } finally {
      Reflect.deleteProperty(Object.prototype, "then");
      Object.defineProperty(globalThis, "Error", {configurable: true, value: original});
    }
    expect(result).toMatchObject({failure: null, more: false});
    expect(seen).toEqual([limit?.value]);
    expect(original.stackTraceLimit).toBe(7);
    expect((await identity).peerId).toBe(runtime.identity.peerId);
  } finally {
    if (limit) Object.defineProperty(original, "stackTraceLimit", limit);
    void runtime.close();
    for (let i = 0; i < 400 && !closed; i++) {
      await new Promise((resolve) => setTimeout(resolve, 5));
      runtime.exchange([], settleOnly);
    }
  }
  expect(closed).toBe(true);
  expect(await connect).toMatchObject({code: "NetworkClosed", stack: "Error: NetworkClosed"});
});

/** Closes a runtime and settles its pending connect under an inherited `code` setter that installs a stack setter. */
async function settleUnderCodeSetter(setters: unknown[]) {
  const runtime = initializeNativeNetworkRuntime(applicationConfig(), () => undefined);
  const connect = runtime.connect(...unreachableConnect()).catch((error: unknown) => error);
  let closed = false;
  void runtime.close().then(() => {
    closed = true;
  });
  for (let i = 0; i < 400 && runtime.state !== "closed"; i++) await new Promise((resolve) => setTimeout(resolve, 5));
  Object.defineProperty(Error.prototype, "code", {
    configurable: true,
    set(this: object, value: unknown) {
      setters.push(value);
      Object.defineProperty(this, "stack", {configurable: true, set: () => setters.push("stack")});
    },
  });
  let settled = false;
  void connect.then(() => {
    settled = true;
  });
  try {
    runtime.exchange([], settleOnly);
  } finally {
    Reflect.deleteProperty(Error.prototype, "code");
  }
  // Nothing else settles here, so the connect settled in that exchange.
  await new Promise(setImmediate);
  for (let i = 0; i < 400 && !closed; i++) {
    await new Promise((resolve) => setTimeout(resolve, 5));
    runtime.exchange([], settleOnly);
  }
  return {error: await connect, facade: new WeakRef(runtime), settled};
}

test("settled errors run no inherited code setter and keep no frames that retain the facade", async () => {
  const setters: unknown[] = [];
  const {facade, error, settled} = await settleUnderCodeSetter(setters);
  expect(settled).toBe(true);
  expect(setters).toEqual([]);
  expect(error).toBeInstanceOf(Error);
  expect(Object.getOwnPropertyDescriptor(error, "code")?.value).toBe("NetworkClosed");
  expect(error).toMatchObject({message: "NetworkClosed", name: "Error", stack: "Error: NetworkClosed"});
  // Dereferencing keeps the target alive for the rest of the job, so each collection runs in a later one.
  for (let i = 0; i < 100; i++) {
    await new Promise((resolve) => setTimeout(resolve, 10));
    global.gc?.();
    if (!facade.deref()) break;
  }
  expect(facade.deref()).toBeUndefined();
});

test.each([
  "exit",
  "facade-gc",
  "object-gc",
  "held-ack",
  "held-closed",
  "notifier",
])("incoming lifecycle subprocess %s", async (mode) => {
  const {execFileSync} = await import("node:child_process");
  const output = execFileSync(
    process.execPath,
    [
      "--import",
      "tsx",
      "--expose-gc",
      "--import",
      "tsx",
      "bindings/test/fixtures/network-incoming-lifecycle.mjs",
      mode,
    ],
    {encoding: "utf8", timeout: 20000}
  );
  expect(output).toContain(`incoming-lifecycle ${mode} ok`);
}, 25000);

test("incoming response bytes are acquired at readiness and released after the chunk", async () => {
  const pair = await incomingPair();
  try {
    const pending = pair.left.request(pair.remote.peerId, BLOCKS, new Uint8Array(32)).next();
    void pending.catch(() => undefined);
    const incoming = await takeIncoming(pair.right);
    expect(pair.right.diagnostics().incoming).toMatchObject({
      occupied: 1,
      requestBytes: 0,
      reservedBytes: 0,
      reservedBytesHighWater: 64,
    });
    await incoming.ready();
    expect(pair.right.diagnostics().incoming.reservedBytes).toBe(10 * 1024 * 1024);
    const data = new Uint8Array(4000).fill(42);
    await incoming.respond(data, requestForks[0]);
    expect((await pending).value?.data).toEqual(data);
    expect(pair.right.diagnostics().incoming.reservedBytes).toBe(0);
    await incoming.finish();
    await pair.right.reStatusPeers([pair.identity.peerId]);
    expect((await pair.right.getIdentity()).peerId).toEqual(pair.remote.peerId);
  } finally {
    await Promise.all([pair.left.close(), pair.right.close()]);
  }
}, 20000);

interface IncomingHandle {
  index: number;
  generation: bigint;
}
interface IncomingDescriptor {
  handle: IncomingHandle;
  closed: Promise<void>;
}
interface DirectIncomingBridge {
  initialize(
    config: ReturnType<typeof applicationConfig>,
    onWorkAvailable: () => void
  ): {identity: import("../src/network.js").NativeIdentity; closed: Promise<unknown>};
  applyIntent(intent: ReturnType<typeof localIntent>, slot: bigint): Promise<unknown>;
  exchange(
    actions: readonly import("../src/network.js").NativeAction[],
    demand: import("../src/network.js").NativeExchangeDemand
  ): {serving: IncomingDescriptor[]};
  incomingTerminal(handle: IncomingHandle, action: number, status?: number, message?: Uint8Array): void;
  incomingRelease(handle: IncomingHandle): void;
  incomingRespond(
    handle: IncomingHandle,
    data: Uint8Array,
    context: import("../src/network.js").NativeForkEntry
  ): Promise<void>;
  requestPull(handle: IncomingHandle): Promise<unknown>;
  close(): void;
}

test("incoming tokens reject malformed handles and stale slot generations", async () => {
  const {networkBindings: exports} = await import("./utils/network-bindings.js");
  const {NativeNetworkRuntime} = exports as unknown as {NativeNetworkRuntime: new () => DirectIncomingBridge};
  const config = applicationConfig();
  config.resources.bridgeBudgetBytes = 512 * 1024 * 1024;
  config.identitySecretKey[31] = 2;
  const clientConfig = applicationConfig();
  clientConfig.resources.bridgeBudgetBytes = 512 * 1024 * 1024;
  const client = await startPeer(clientConfig);
  const native = new NativeNetworkRuntime();
  let closed: Promise<unknown> | undefined;
  try {
    const promises = native.initialize(config, () => undefined);
    closed = promises.closed;
    const [, identity] = await Promise.all([client.identity, promises.identity]);
    await Promise.all([
      client.applyIntent(localIntent(clientConfig), clientConfig.initialSlot),
      native.applyIntent(localIntent(config), config.initialSlot),
    ]);
    await client.connect(identity.peerId, [identity.localEndpoint], 5000n);
    let previous: IncomingHandle | undefined;
    for (let i = 0; i < 2; i++) {
      const stream = client.request(identity.peerId, BLOCKS, new Uint8Array(32));
      const pending = stream.next();
      void pending.catch(() => undefined);
      let incoming: IncomingDescriptor | null = null;
      await expect
        .poll(
          () => {
            // Peer events are taken too, so nothing waits and the declining notifier settles completions.
            incoming = native.exchange([], {...settleOnly, capacity, peers: 64, servingStarts: 1}).serving[0] ?? null;
            return incoming !== null;
          },
          {timeout: 5000}
        )
        .toBe(true);
      if (!incoming) throw Error("missing incoming descriptor");
      const descriptor = incoming as IncomingDescriptor;
      const handle = descriptor.handle;
      for (const invalid of [{...handle, index: -1}])
        expect(() => native.incomingTerminal(invalid, 2, undefined, undefined)).toThrow("InvalidNetworkInteger");
      expect(() => native.requestPull(handle)).toThrow();
      if (previous) {
        const ack = native.incomingRespond(handle, new Uint8Array(4000), requestForks[0]);
        expect(handle.index).toBe(previous.index);
        expect(handle.generation).toBe(previous.generation + 1n);
        const stale = previous;
        expect(() => native.incomingTerminal(stale, 2, undefined, undefined)).toThrow("NetworkIncomingClosed");
        await ack;
        expect((await pending).done).toBe(false);
      }
      native.incomingTerminal(handle, 0, undefined, undefined);
      expect(await descriptor.closed).toBeUndefined();
      native.incomingRelease(handle);
      await expect
        .poll(() => {
          try {
            native.incomingRelease(handle);
            return null;
          } catch (error) {
            return error;
          }
        })
        .toMatchObject({code: "NetworkIncomingClosed"});
      const done = previous ? stream.next() : pending;
      expect((await done).done).toBe(true);
      previous = handle;
    }
  } finally {
    native.close();
    await Promise.all([client.close(), closed]);
  }
}, 15000);
