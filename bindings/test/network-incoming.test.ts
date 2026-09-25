import {expect, test} from "vitest";
import {applicationConfig, localIntent, nextIncoming, requestForks, startRuntime} from "./utils/network.js";
import {BLOCKS, incomingPair, takeIncoming} from "./utils/network-incoming.js";

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
