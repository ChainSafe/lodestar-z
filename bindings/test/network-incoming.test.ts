import {expect, test} from "vitest";
import {createNativeNetworkApplicationRuntime} from "../src/network.js";
import {applicationConfig, localIntent} from "./utils/network.js";

test("incoming request take is empty on an active application", async () => {
  const config = applicationConfig();
  config.resources.bridgeBudgetBytes = 512 * 1024 * 1024;
  const runtime = createNativeNetworkApplicationRuntime(config, () => undefined);
  try {
    await runtime.ready;
    await runtime.applyIntent(localIntent(config), config.initialSlot);
    expect(runtime.takeIncomingRequest()).toBeNull();
    const diagnostics = runtime.diagnostics().incoming;
    for (const field of [
      "requestsTaken",
      "requestBytesCopied",
      "responseBytesCopied",
      "chunksWritten",
      "bytesWritten",
      "capacityRefusals",
      "byteRefusals",
      "busyResponses",
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

test("incoming copied metadata and acknowledged multiple contexts preserve wire bytes", async () => {
  const pair = await incomingPair();
  try {
    const query = new Uint8Array(64).fill(7);
    const stream = pair.left.request(pair.remote.peerId, BLOCKS, query);
    const pending = stream.next();
    void pending.catch(() => undefined);
    const incoming = await takeIncoming(pair.right);
    expect(incoming.data).toEqual(query);
    expect(incoming.protocol).toBe(BLOCKS);
    expect(incoming.peerId).toEqual(pair.identity.peerId);
    const peers = await pair.right.getPeers();
    expect(incoming.connection).toEqual(peers.peers[0].connection);
    incoming.peerId.fill(0);
    incoming.connection.generation++;
    incoming.data.fill(0);
    const payload = new Uint8Array(4000).fill(31);
    const ack = incoming.respond(payload, pair.rightConfig.requestForks[0]);
    payload.fill(99);
    await expect(incoming.respond(payload, null)).rejects.toMatchObject({code: "NetworkIncomingBusy"});
    await expect(incoming.finish()).rejects.toMatchObject({code: "NetworkIncomingBusy"});
    await ack;
    expect(await pending).toMatchObject({
      done: false,
      value: {data: new Uint8Array(4000).fill(31), fork: "deneb", protocol: BLOCKS},
    });
    const second = stream.next();
    await incoming.respond(new Uint8Array(4000).fill(42), pair.rightConfig.requestForks[1]);
    expect(await second).toMatchObject({done: false, value: {data: new Uint8Array(4000).fill(42)}});
    const done = stream.next();
    expect(incoming.finish()).toBe(incoming.closed);
    expect(incoming.fail(139, new Uint8Array())).toBe(incoming.closed);
    expect(await incoming.closed).toEqual({chunks: 2, reason: "served"});
    expect(await done).toEqual({done: true, value: undefined});
    await expect(incoming.respond(payload, null)).rejects.toMatchObject({code: "NetworkIncomingClosed"});
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

test.each([1, 2, 3, 139])("incoming error status %s preserves exact encoded bytes", async (status) => {
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
    expect(await incoming.closed).toEqual({chunks: 0, reason: "served"});
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
      incoming.respond(new Uint8Array(4000), {digest: pair.rightConfig.requestForks[0].digest, fork: "electra"})
    ).rejects.toMatchObject({code: "NetworkIncomingRejected", reason: "unknown_fork"});
    await expect(incoming.respond(new Uint8Array(1), pair.rightConfig.requestForks[0])).rejects.toMatchObject({
      code: "NetworkIncomingRejected",
      reason: "chunk_too_small",
    });
    expect(incoming.finish()).toBe(incoming.closed);
    expect(await incoming.closed).toEqual({chunks: 0, reason: "served"});
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
    for (const status of [0, -1, 256, 1.5, Number.NaN, Number.MAX_SAFE_INTEGER + 1]) {
      await expect(incoming.fail(status, new Uint8Array())).rejects.toMatchObject({
        code: "NetworkIncomingRejected",
        reason: "invalid_error",
      });
    }
    const extraContext = {...pair.rightConfig.requestForks[0], unexpected: true};
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
    await expect(incoming.respond(oversized, pair.rightConfig.requestForks[0])).rejects.toMatchObject({
      code: "NetworkIncomingRejected",
      reason: "chunk_too_large",
    });
    const data = new Uint8Array(4000);
    const context = {
      digest: pair.rightConfig.requestForks[0].digest,
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
    await incoming.respond(new Uint8Array(4000), pair.rightConfig.requestForks[0]);
    expect((await pending).done).toBe(false);
    const done = stream.next();
    await incoming.finish();
    expect((await done).done).toBe(true);
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
    await incoming.respond(new Uint8Array(4000), pair.rightConfig.requestForks[0]);
    expect((await first).done).toBe(false);
    await expect(incoming.respond(new Uint8Array(4000), pair.rightConfig.requestForks[0])).rejects.toMatchObject({
      code: "NetworkIncomingRejected",
      reason: "too_many_chunks",
    });
    const done = stream.next();
    expect(await incoming.finish()).toEqual({chunks: 1, reason: "served"});
    expect((await done).done).toBe(true);
  } finally {
    await Promise.all([pair.left.close(), pair.right.close()]);
  }
}, 15000);

const instrumented = test.skipIf(process.env.LODESTAR_Z_NETWORK_TEST_FAILURES !== "1");
interface IncomingFaults {
  networkTestScenario(value: string): void;
  networkTestFail(value: string): void;
  networkTestStats(): {owners: number; runtimes: number; notifications: number};
  networkTestIncomingRelease(): void;
  networkTestIncoming(): {
    nativeOwned: boolean;
    nativeBorrowed: boolean;
    writing: boolean;
    withheld: boolean;
    copying: boolean;
    quiescent: boolean;
    acknowledged: boolean;
    requestBytes: number;
    responseBytes: number;
    destinationBytes: number;
    nativeInbound: number;
  };
}
async function faults() {
  const {default: bindings} = await import("../src/bindings.js");
  return bindings as unknown as IncomingFaults;
}

instrumented.each(["incoming_ack_close", "incoming_response_close"])(
  "incoming %s establishes acknowledgement order before close",
  async (scenario) => {
    const hooks = await faults();
    const pair = await incomingPair(() => hooks.networkTestScenario(scenario));
    try {
      const stream = pair.left.request(pair.remote.peerId, BLOCKS, new Uint8Array(32));
      const pending = stream.next().catch(() => undefined);
      const incoming = await takeIncoming(pair.right);
      const ack = incoming.respond(new Uint8Array(4000), pair.rightConfig.requestForks[0]);
      if (scenario === "incoming_ack_close") await ack;
      else await expect(ack).rejects.toMatchObject({code: "NetworkClosed"});
      const result = await incoming.closed;
      expect(result).toEqual({chunks: scenario === "incoming_ack_close" ? 1 : 0, reason: "closed"});
      expect(hooks.networkTestIncoming()).toMatchObject({
        acknowledged: scenario === "incoming_ack_close",
        nativeOwned: true,
        responseBytes: 4000,
      });
      expect(pair.right.diagnostics().incoming).toMatchObject({occupied: 0, reservedBytes: 0, responseBytes: 0});
      await pending;
    } finally {
      await Promise.all([pair.left.close(), pair.right.close()]);
    }
  },
  15000
);

instrumented.each([false, true])(
  "incoming copy pin survives physical close (copy fault %s)",
  async (copyFault) => {
    const hooks = await faults();
    const pair = await incomingPair(() => hooks.networkTestScenario("incoming_copy_close"));
    try {
      const stream = pair.left.request(pair.remote.peerId, BLOCKS, new Uint8Array(32).fill(19));
      const pending = stream.next().catch(() => undefined);
      if (copyFault) hooks.networkTestFail("operation_copy");
      if (copyFault) await expect(takeIncoming(pair.right)).rejects.toThrow("InjectedNetworkFailure");
      else {
        const incoming = await takeIncoming(pair.right);
        expect(incoming.data).toEqual(new Uint8Array(32).fill(19));
        expect(await incoming.closed).toEqual({chunks: 0, reason: "closed"});
      }
      expect(hooks.networkTestIncoming()).toMatchObject({
        copying: true,
        destinationBytes: 32,
        nativeOwned: false,
        quiescent: true,
        requestBytes: 32,
      });
      await pair.right.close();
      expect(pair.right.diagnostics().incoming).toMatchObject({
        occupied: 0,
        requestBytes: 0,
        reservedBytes: 0,
        responseBytes: 0,
      });
      await pending;
    } finally {
      await Promise.all([pair.left.close(), pair.right.close()]);
    }
  },
  15000
);

const stock = test.skipIf(!process.env.LODESTAR_Z_NETWORK_STOCK_HOST);
stock(
  "pinned stock decoder receives native responses, contexts, full payload and error statuses",
  async () => {
    const {Child} = await import("../../test/interop/child.mjs");
    const {payload, summary} = await import("../../test/interop/codec.mjs");
    let peer: InstanceType<typeof Child> | undefined;
    let runtime: ReturnType<typeof createNativeNetworkApplicationRuntime> | undefined;
    try {
      const host = process.env.LODESTAR_Z_NETWORK_STOCK_HOST;
      if (!host) throw Error("stock host path required");
      peer = new Child("incoming-stock", process.execPath, ["test/interop/request_responder.mjs", host]);
      await peer.command("ready");
      const config = applicationConfig();
      config.resources.bridgeBudgetBytes = 512 * 1024 * 1024;
      config.requestForks.push({digest: Uint8Array.of(5, 6, 7, 8), fork: "deneb"});
      runtime = createNativeNetworkApplicationRuntime(config, () => undefined);
      const identity = await runtime.ready;
      await runtime.applyIntent(localIntent(config), config.initialSlot);
      const addressBytes = Buffer.from(identity.localMultiaddr).toString("hex");
      for (const status of [0, 1, 2, 3, 139]) {
        const reply = peer.command("request", {addressBytes});
        const incoming = await takeIncoming(runtime);
        if (status === 0) {
          const first = payload(4000, 18);
          const second = payload(10 * 1024 * 1024, 19);
          await incoming.respond(first, config.requestForks[0]);
          await incoming.respond(second, config.requestForks[1]);
          await incoming.finish();
          expect(await reply).toMatchObject({
            chunks: [
              {...summary(first), fork: "deneb"},
              {...summary(second), fork: "deneb"},
            ],
            contexts: ["01020304", "05060708"],
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

instrumented(
  "incoming bridge cell pressure preserves native output and independent command progress",
  async () => {
    const hooks = await faults();
    const pair = await incomingPair(() => hooks.networkTestScenario("incoming_hold"));
    try {
      const held = [];
      for (let i = 0; i < 6; i++) {
        const pending = pair.left.request(pair.remote.peerId, BLOCKS, new Uint8Array(32)).next();
        void pending.catch(() => undefined);
        const incoming = await takeIncoming(pair.right);
        held.push(incoming);
        expect(incoming.finish()).toBe(incoming.closed);
        expect((await pending).done).toBe(true);
      }
      expect(pair.right.diagnostics().incoming).toMatchObject({
        capacity: 6,
        closedPromises: 6,
        occupied: 6,
        requestBytes: 0,
        reservedBytes: 0,
        responseBytes: 0,
      });
      await expect.poll(() => hooks.networkTestIncoming().nativeInbound).toBe(0);
      await expect(pair.left.request(pair.remote.peerId, BLOCKS, new Uint8Array(32)).next()).rejects.toMatchObject({
        peerMessage: new TextEncoder().encode("application capacity exhausted"),
        peerStatus: 2,
        reason: "peer_error",
      });
      expect(pair.right.takeIncomingRequest()).toBeNull();
      expect(pair.right.diagnostics().incoming.capacityRefusals).toBe(1n);
      await pair.right.reStatusPeers([pair.identity.peerId]);
      expect((await pair.right.getIdentity()).peerId).toEqual(pair.remote.peerId);
      const outgoing = pair.right.request(pair.identity.peerId, BLOCKS, new Uint8Array(32)).next();
      await (await takeIncoming(pair.left)).finish();
      expect((await outgoing).done).toBe(true);
      hooks.networkTestIncomingRelease();
      await pair.right.getIdentity();
      expect(await Promise.all(held.map((incoming) => incoming.closed))).toEqual(
        Array.from({length: 6}, () => ({chunks: 0, reason: "served"}))
      );
      expect(pair.right.diagnostics().incoming.occupied).toBe(0);
    } finally {
      hooks.networkTestIncomingRelease();
      await Promise.all([pair.left.close(), pair.right.close()]);
    }
  },
  15000
);

instrumented.each(["incoming_response", "operation_copy"])(
  "incoming allowed %s failure releases every acquired allocation",
  async (stage) => {
    const hooks = await faults();
    const pair = await incomingPair();
    try {
      const stream = pair.left.request(pair.remote.peerId, BLOCKS, new Uint8Array(32));
      const pending = stream.next().catch(() => undefined);
      if (stage === "operation_copy") {
        hooks.networkTestFail(stage);
        await expect(takeIncoming(pair.right)).rejects.toThrow("InjectedNetworkFailure");
        await pair.right.close();
      } else {
        const incoming = await takeIncoming(pair.right);
        hooks.networkTestFail(stage);
        await expect(incoming.respond(new Uint8Array(4000), pair.rightConfig.requestForks[0])).rejects.toThrow(
          "InjectedNetworkFailure"
        );
        expect(pair.right.diagnostics().incoming.pendingResponses).toBe(0);
        await incoming.finish();
      }
      await pending;
      expect(pair.right.diagnostics().incoming).toMatchObject({
        occupied: 0,
        requestBytes: 0,
        reservedBytes: 0,
        responseBytes: 0,
      });
    } finally {
      await Promise.all([pair.left.close(), pair.right.close()]);
    }
  },
  15000
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
    expect(pair.right.takeIncomingRequest()).toBeNull();
  } finally {
    await Promise.all([pair.left.close(), pair.right.close()]);
  }
}, 15000);

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
    ["--expose-gc", "--import", "tsx", "bindings/test/fixtures/network-incoming-lifecycle.mjs", mode],
    {encoding: "utf8", timeout: 20000}
  );
  expect(output).toContain(`incoming-lifecycle ${mode} ok`);
}, 25000);

test("incoming exact byte admission includes fixed metadata and shares outbound credit", async () => {
  const baseline = await incomingPair();
  const fixed = baseline.right.diagnostics().bridgeRequestedBytes;
  await Promise.all([baseline.left.close(), baseline.right.close()]);
  for (const extra of [63, 64]) {
    const pair = await incomingPair(undefined, fixed + 10 * 1024 * 1024 + extra);
    try {
      const pending = pair.left.request(pair.remote.peerId, BLOCKS, new Uint8Array(32)).next();
      void pending.catch(() => undefined);
      if (extra === 63) {
        await expect(pending).rejects.toMatchObject({
          peerMessage: new TextEncoder().encode("application capacity exhausted"),
          peerStatus: 2,
          reason: "peer_error",
        });
        expect(pair.right.diagnostics().incoming).toMatchObject({byteRefusals: 1n, occupied: 0, reservedBytes: 0});
      } else {
        const incoming = await takeIncoming(pair.right);
        expect(pair.right.diagnostics().incoming).toMatchObject({
          occupied: 1,
          requestBytes: 0,
          reservedBytes: 10 * 1024 * 1024,
          reservedBytesHighWater: 10 * 1024 * 1024 + 64,
        });
        expect(() => pair.right.request(pair.identity.peerId, BLOCKS, new Uint8Array(32))).toThrow("NetworkBridgeFull");
        await incoming.finish();
        expect((await pending).done).toBe(true);
      }
      await pair.right.reStatusPeers([pair.identity.peerId]);
      expect((await pair.right.getIdentity()).peerId).toEqual(pair.remote.peerId);
    } finally {
      await Promise.all([pair.left.close(), pair.right.close()]);
    }
  }
}, 20000);

interface IncomingHandle {
  session: bigint;
  direction: string;
  index: number;
  generation: bigint;
  nativeIndex: number;
  nativeGeneration: number;
  connection: {index: number; generation: number};
}
interface IncomingDescriptor {
  handle: IncomingHandle;
  closed: Promise<import("../src/network.js").NativeIncomingResult>;
}
interface DirectIncomingBridge {
  prepare(
    config: ReturnType<typeof applicationConfig>,
    notifier: () => void
  ): {ready: Promise<import("../src/network.js").NativeIdentity>; closed: Promise<unknown>};
  applyIntent(intent: ReturnType<typeof localIntent>, slot: bigint): Promise<unknown>;
  takeIncomingRequest(): IncomingDescriptor | null;
  incomingTerminal(handle: IncomingHandle, action: number, status?: number, message?: Uint8Array): void;
  incomingRespond(
    handle: IncomingHandle,
    data: Uint8Array,
    context: import("../src/network.js").NativeForkEntry
  ): Promise<void>;
  requestPull(handle: IncomingHandle): Promise<unknown>;
  close(): void;
}

test("incoming complete handles isolate direction, connection and replacement generations", async () => {
  const {default: exports} = await import("../src/bindings.js");
  const {NativeNetworkRuntime} = exports as unknown as {NativeNetworkRuntime: new () => DirectIncomingBridge};
  const config = applicationConfig();
  config.resources.bridgeBudgetBytes = 512 * 1024 * 1024;
  config.identitySecretKey[31] = 2;
  const clientConfig = applicationConfig();
  clientConfig.resources.bridgeBudgetBytes = 512 * 1024 * 1024;
  const client = createNativeNetworkApplicationRuntime(clientConfig, () => undefined);
  const native = new NativeNetworkRuntime();
  let closed: Promise<unknown> | undefined;
  try {
    const promises = native.prepare(config, () => undefined);
    closed = promises.closed;
    const [, identity] = await Promise.all([client.ready, promises.ready]);
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
            incoming = native.takeIncomingRequest();
            return incoming !== null;
          },
          {timeout: 5000}
        )
        .toBe(true);
      if (!incoming) throw Error("missing incoming descriptor");
      const descriptor = incoming as IncomingDescriptor;
      const handle = descriptor.handle;
      for (const invalid of [
        {...handle, direction: "outbound"},
        {...handle, session: handle.session + 1n},
        {...handle, nativeGeneration: handle.nativeGeneration + 1},
        {...handle, connection: {...handle.connection, generation: handle.connection.generation + 1}},
      ])
        expect(() => native.incomingTerminal(invalid, 2, undefined, undefined)).toThrow("InvalidIncomingHandle");
      expect(() => native.requestPull(handle)).toThrow();
      if (previous) {
        const ack = native.incomingRespond(handle, new Uint8Array(4000), config.requestForks[0]);
        expect(handle.index).toBe(previous.index);
        expect(handle.generation).toBe(previous.generation + 1n);
        const stale = previous;
        expect(() => native.incomingTerminal(stale, 2, undefined, undefined)).toThrow("NetworkIncomingClosed");
        await ack;
        expect((await pending).done).toBe(false);
      }
      const done = previous ? stream.next() : pending;
      native.incomingTerminal(handle, 0, undefined, undefined);
      expect(await descriptor.closed).toEqual({chunks: previous ? 1 : 0, reason: "served"});
      expect((await done).done).toBe(true);
      previous = handle;
    }
  } finally {
    native.close();
    await Promise.all([client.close(), closed]);
  }
}, 15000);

instrumented.each(Array.from({length: 9}, (_, i) => `incoming_result_${i}`))(
  "incoming prepared result prefix %s rolls back before publication",
  async (stage) => {
    const hooks = await faults();
    const pair = await incomingPair();
    try {
      const pending = pair.left
        .request(pair.remote.peerId, BLOCKS, new Uint8Array(32), {responseTimeoutMs: 100})
        .next()
        .catch(() => undefined);
      hooks.networkTestFail(stage);
      await expect(takeIncoming(pair.right)).rejects.toThrow("InjectedNetworkFailure");
      await pair.right.close();
      await pending;
      expect(pair.right.diagnostics().incoming).toMatchObject({
        occupied: 0,
        requestBytes: 0,
        reservedBytes: 0,
        responseBytes: 0,
      });
    } finally {
      await Promise.all([pair.left.close(), pair.right.close()]);
    }
  },
  15000
);

instrumented(
  "incoming cancellation retires a real stalled native response with all command cells occupied",
  async () => {
    const hooks = await faults();
    const pair = await incomingPair(() => hooks.networkTestScenario("incoming_observe"));
    try {
      const stream = pair.left.request(pair.remote.peerId, BLOCKS, new Uint8Array(64), {responseTimeoutMs: 60000});
      const first = stream.next();
      const incoming = await takeIncoming(pair.right);
      await incoming.respond(new Uint8Array(4000), pair.rightConfig.requestForks[0]);
      expect((await first).done).toBe(false);
      const {payload} = await import("../../test/interop/codec.mjs");
      let completed = false;
      const pending = incoming.respond(payload(10 * 1024 * 1024, 72), pair.rightConfig.requestForks[0]).then(
        () => {
          completed = true;
          return "sent";
        },
        (error) => {
          completed = true;
          return error;
        }
      );
      await expect.poll(() => hooks.networkTestIncoming().responseBytes, {timeout: 5000}).toBe(10 * 1024 * 1024);
      expect(hooks.networkTestIncoming().nativeBorrowed).toBe(true);
      await new Promise((resolve) => setTimeout(resolve, 150));
      expect(completed).toBe(false);
      expect(pair.right.diagnostics().incoming.responseBytes).toBe(10 * 1024 * 1024);
      const commands = Array.from({length: 64}, () => {
        try {
          return pair.right.getIdentity().catch((error: Error) => error);
        } catch (error) {
          return Promise.resolve(error);
        }
      });
      expect(pair.right.diagnostics().operationOccupied).toBe(32);
      expect(incoming.cancel()).toBe(incoming.closed);
      expect(incoming.finish()).toBe(incoming.closed);
      expect(await incoming.closed).toEqual({chunks: 1, failure: "cancelled", reason: "failed"});
      expect(await pending).toMatchObject({code: "NetworkIncomingFailed", failure: "cancelled"});
      await Promise.all(commands);
      expect(pair.right.diagnostics().incoming).toMatchObject({occupied: 0, reservedBytes: 0, responseBytes: 0});
      await stream.return?.();
    } finally {
      await Promise.all([pair.left.close(), pair.right.close()]);
    }
  },
  20000
);

instrumented.each(Array.from({length: 9}, (_, i) => `incoming_result_${i}`))(
  "incoming next result prefix %s preserves the current result and serving owner",
  async (stage) => {
    const hooks = await faults();
    const pair = await incomingPair();
    try {
      const stream = pair.left.request(pair.remote.peerId, BLOCKS, new Uint8Array(32));
      const pending = stream.next();
      void pending.catch(() => undefined);
      const incoming = await takeIncoming(pair.right);
      hooks.networkTestFail(stage);
      await expect(incoming.respond(new Uint8Array(4000), pair.rightConfig.requestForks[0])).rejects.toThrow(
        "InjectedNetworkFailure"
      );
      expect(pair.right.diagnostics().incoming).toMatchObject({
        chunksWritten: 0n,
        closedPromises: 1,
        occupied: 1,
        pendingResponses: 0,
        reservedBytes: 10 * 1024 * 1024,
        responseBytes: 0,
      });
      await incoming.respond(new Uint8Array(4000), pair.rightConfig.requestForks[0]);
      expect((await pending).done).toBe(false);
      const done = stream.next();
      expect(await incoming.finish()).toEqual({chunks: 1, reason: "served"});
      expect((await done).done).toBe(true);
      expect(pair.right.diagnostics().incoming).toMatchObject({occupied: 0, reservedBytes: 0, responseBytes: 0});
    } finally {
      await Promise.all([pair.left.close(), pair.right.close()]);
    }
  },
  15000
);

instrumented("incoming table allocation failure unwinds startup before publication", async () => {
  const hooks = await faults();
  const config = applicationConfig();
  config.resources.bridgeBudgetBytes = 512 * 1024 * 1024;
  hooks.networkTestFail("incoming_table");
  expect(() => createNativeNetworkApplicationRuntime(config, () => undefined)).toThrow("InjectedNetworkFailure");
  await expect
    .poll(() => {
      global.gc?.();
      return hooks.networkTestStats();
    })
    .toEqual({notifications: 0, owners: 0, runtimes: 0});
});

instrumented(
  "incoming input allocation failure releases reservation and closes the owner",
  async () => {
    const hooks = await faults();
    const pair = await incomingPair();
    try {
      hooks.networkTestFail("incoming_input");
      const pending = pair.left
        .request(pair.remote.peerId, BLOCKS, new Uint8Array(32))
        .next()
        .catch(() => undefined);
      await expect.poll(() => pair.right.diagnostics().terminalErrorCode).toBe("InjectedNetworkFailure");
      await pair.right.close();
      expect(pair.right.diagnostics().incoming).toMatchObject({
        occupied: 0,
        requestBytes: 0,
        reservedBytes: 0,
        responseBytes: 0,
      });
      await pending;
    } finally {
      await Promise.all([pair.left.close(), pair.right.close()]);
    }
  },
  15000
);
