import {expect, test, vi} from "vitest";
import {
  applicationConfig,
  checksOnly,
  gossipAll,
  localIntent,
  peerIdFromHex,
  requestForks,
  settleOnly,
  startRuntime,
  subscriptions,
  topicKinds,
  topicName,
} from "./utils/network.js";
import {startPeer} from "./utils/network-peer.js";

test("gossip drain and stale verdict on an activated application", async () => {
  const config = applicationConfig();
  const runtime = startRuntime(config, () => undefined);
  try {
    await runtime.identity;
    await runtime.applyIntent(localIntent(config), config.initialSlot);
    expect(runtime.exchange(gossipAll).gossip).toBeNull();
    expect(runtime.reportGossip({generation: 1n, index: 0}, "ignore")).toBe(false);
  } finally {
    await runtime.close();
  }
});

import {setTimeout as delay} from "node:timers/promises";
import type {NativeApplicationConfig, NativeGossipMessage, NativeNetworkApplicationRuntime} from "../src/network.js";
import {BLOCKS, incomingPair, takeIncoming} from "./utils/network-incoming.js";

const TOPIC = topicName();

function blockPayload(size: number, byte = 0): Uint8Array {
  const bytes = new Uint8Array(size).fill(byte);
  new DataView(bytes.buffer).setBigUint64(100, 100n, true);
  return bytes;
}

/** Classifies every dependency as available, as a host that already holds each parent block does. */
function answerChecks(runtime: NativeNetworkApplicationRuntime, demand = checksOnly) {
  const {checks, gossip} = runtime.exchange(demand);
  if (checks.length) runtime.classifyGossip(checks.map(({handle}) => ({available: true, handle})));
  return gossip;
}

async function nextGossip(runtime: NativeNetworkApplicationRuntime): Promise<NativeGossipMessage> {
  for (let i = 0; i < 1000; i++) {
    const gossip = answerChecks(runtime, gossipAll);
    if (gossip?.messages.length) {
      expect(gossip.messages).toHaveLength(1);
      return gossip.messages[0];
    }
    await delay(5);
  }
  throw Error("Gossip delivery deadline");
}
async function gossipPair(timeoutMs = 30000n, budget?: number, configure?: (config: NativeApplicationConfig) => void) {
  const pair = await incomingPair(budget, undefined, (left, right) => {
    right.gossipPolicy.validationTimeoutMs = timeoutMs;
    configure?.(left);
    configure?.(right);
  });
  try {
    for (const [runtime, config] of [
      [pair.left, pair.leftConfig],
      [pair.right, pair.rightConfig],
    ] as const) {
      const intent = localIntent(config);
      intent.subscriptions = subscriptions(TOPIC);
      await runtime.applyIntent(intent, config.initialSlot);
    }
    await Promise.all([
      pair.left.addDirectPeer(pair.remote.peerId, [pair.remote.localEndpoint]),
      pair.right.addDirectPeer(pair.identity.peerId, [pair.identity.localEndpoint]),
    ]);
    await delay(1250);
    return pair;
  } catch (error) {
    await Promise.allSettled([pair.left.close(), pair.right.close()]);
    throw error;
  }
}

test("gossip lifecycle, strict representations and canonical publication refusals", async () => {
  const config = applicationConfig();
  const runtime = startRuntime(config, () => undefined);
  const handle = {generation: 1n, index: 0};
  try {
    await runtime.identity;
    expect(runtime.exchange(gossipAll).gossip).toBeNull();
    await runtime.applyIntent(localIntent(config), config.initialSlot);
    for (const malformed of [
      {...handle, extra: 1},
      {...handle, generation: 0n},
      {...handle, generation: 1n << 64n},
      {...handle, index: -1},
      {...handle, index: 0.5},
      {...handle, extra: true},
    ])
      expect(() => runtime.reportGossip(malformed, "ignore")).toThrow();
    expect(() => runtime.reportGossip(handle, "ACCEPT" as "accept")).toThrow();
    expect(runtime.reportGossip({...handle}, "ignore")).toBe(false);
    expect(runtime.reportGossip({...handle, index: Number.MAX_SAFE_INTEGER}, "ignore")).toBe(false);
    await expect(
      runtime.publishGossip(TOPIC, new Uint8Array(4000), {flood: 0} as unknown as {flood: boolean})
    ).rejects.toThrow();
    await expect(
      runtime.publishGossip(TOPIC, new Uint8Array(4000), {unknown: true} as unknown as {flood: boolean})
    ).rejects.toThrow();
    await expect(runtime.publishGossip(TOPIC, new Uint16Array(10) as unknown as Uint8Array)).rejects.toThrow();
    const detached = new Uint8Array(4000);
    structuredClone(detached, {transfer: [detached.buffer]});
    await expect(runtime.publishGossip(TOPIC, detached)).rejects.toThrow();
    await expect(runtime.publishGossip("/invalid", new Uint8Array(4000))).rejects.toMatchObject({
      code: "NetworkGossipPublishFailed",
      reason: "unknown_topic",
    });
    await expect(runtime.publishGossip(TOPIC, new Uint8Array(9))).rejects.toMatchObject({
      code: "NetworkGossipPublishFailed",
      reason: "payload_too_small",
    });
    await expect(runtime.publishGossip(TOPIC, new Uint8Array(10 * 1024 * 1024 + 1))).rejects.toThrow("PayloadTooLarge");
    await expect(runtime.publishGossip(TOPIC, new Uint8Array(4000), {allowZeroPeers: false})).rejects.toMatchObject({
      code: "NetworkGossipPublishFailed",
      reason: "no_peers_subscribed_to_topic",
    });
    expect(
      await runtime.publishGossip(TOPIC, new Uint8Array(4000), {
        allowZeroPeers: true,
        flood: false,
        ignoreDuplicate: false,
      })
    ).toEqual({duplicate: false, pressured: 0, queued: 0, selected: 0, unavailable: 0});
    await expect(runtime.publishGossip(TOPIC, new Uint8Array(4000), {ignoreDuplicate: false})).rejects.toMatchObject({
      code: "NetworkGossipPublishFailed",
      reason: "duplicate",
    });
    expect(await runtime.publishGossip(TOPIC, new Uint8Array(4000), {ignoreDuplicate: true})).toEqual({
      duplicate: true,
      pressured: 0,
      queued: 0,
      selected: 0,
      unavailable: 0,
    });
  } finally {
    await runtime.close();
  }
  expect(runtime.exchange(gossipAll).gossip).toBeNull();
  expect(runtime.reportGossip(handle, "ignore")).toBe(false);
  await expect(runtime.publishGossip(TOPIC, new Uint8Array(4000))).rejects.toThrow("NetworkClosed");
  expect(runtime.diagnostics().gossip).toMatchObject({
    capacity: config.gossipPolicy.processor?.reduce((sum, limit) => sum + limit.items, 0),
    occupied: 0,
    payloadBytes: 0,
    publicationBytes: 0,
    publicationDuplicates: 1n,
    reservedBytes: 0,
  });
});

test.each([
  "accept",
  "reject",
  "ignore",
] as const)("real gossip %s preserves wire identity and exact-once verdict admission", async (verdict) => {
  const pair = await gossipPair();
  try {
    const input = blockPayload(4000, 7);
    const before = Date.now();
    const published = pair.left.publishGossip(TOPIC, input, {allowZeroPeers: false});
    input.fill(99);
    expect(await published).toEqual({duplicate: false, pressured: 0, queued: 1, selected: 1, unavailable: 0});
    await delay(40);
    const message = await nextGossip(pair.right);
    await vi.waitFor(
      async () => {
        expect(await pair.left.getMetrics()).toContain('gossipsub_msg_publish_count_total{topic="beacon_block"} 1\n');
        expect(pair.right.getMetrics()).toContain('gossipsub_pre_validation_valid_total{topic="beacon_block"} 1\n');
        expect(pair.right.getMetrics()).toContain(
          'gossipsub_msg_received_prevalidation_total{topic="beacon_block"} 1\n'
        );
        expect(pair.right.getMetrics()).toContain("gossipsub_rpc_recv_message_total 1\n");
        expect(await pair.left.getMetrics()).toContain("gossipsub_rpc_sent_message_total 1\n");
        expect(await pair.left.getMetrics()).toContain("gossipsub_rpc_recv_message_total 0\n");
        expect(await pair.left.getMetrics()).toMatch(/gossipsub_rpc_sent_bytes_total [1-9][0-9]*\n/);
        expect(pair.right.getMetrics()).toMatch(/gossipsub_rpc_recv_bytes_total [1-9][0-9]*\n/);
        expect(await pair.left.getMetrics()).toMatch(
          /gossipsub_msg_publish_bytes_total\{topic="beacon_block"\} [1-9][0-9]*\n/
        );
        expect(await pair.left.getMetrics()).toContain(
          `lodestar_gossip_topic_peers_by_type_count{type="beacon_block",boundary="${requestForks[0].fork}_0"} 1\n`
        );
      },
      {timeout: 5000}
    );
    expect(message.topic).toBe(TOPIC);
    expect(message.data).toEqual(blockPayload(4000, 7));
    expect(message.peerId).toEqual(pair.identity.peerId);
    expect(message.connection).toEqual((await pair.right.getPeers()).peers[0].connection);
    const {messageId} = await import("../../test/interop/codec.mjs");
    expect(Buffer.from(message.id)).toEqual(messageId(TOPIC, blockPayload(4000, 7)));
    expect(message.receivedAtUnixMs).toBeGreaterThanOrEqual(before);
    expect(message.receivedAtUnixMs).toBeLessThan(Date.now());
    expect(Number.isSafeInteger(message.receivedAtUnixMs)).toBe(true);

    message.connection.generation++;
    message.data.fill(0);
    expect(pair.right.reportGossip(message.handle, verdict)).toBe(true);
    expect(pair.right.reportGossip(message.handle, verdict)).toBe(false);
    const verdictMetric = {accept: "accepted", ignore: "ignored", reject: "rejected"}[verdict];
    await vi.waitFor(
      async () => {
        const metrics = pair.right.getMetrics();
        expect(metrics).toContain(`gossipsub_${verdictMetric}_messages_total{topic="beacon_block"} 1\n`);
        expect(metrics).toContain("gossipsub_async_validation_delay_from_first_seen_count 1\n");
        expect(metrics).toContain("lodestar_native_gossip_scored_peers 1\n");
      },
      {timeout: 5000}
    );
    const page = await pair.right.getGossipDiagnostics();
    expect(page.ownerSequence).toBeGreaterThan(0n);
    expect(page.observedUnixMs).toBeGreaterThanOrEqual(BigInt(before - 1000));
    expect(page.observedMonoMs).toBeGreaterThan(0n);
    expect(page.nextCursor).toBeNull();
    expect(page.topics).toHaveLength(1);
    expect(page.topics[0]).toMatchObject({subscribed: true, topic: TOPIC});
    expect(page.peers).toHaveLength(1);
    const scored = page.peers[0];
    expect(scored.identity).toEqual(pair.identity.peerId);
    expect(scored.connected).toBe(true);
    expect(scored.outboundReady).toBe(true);
    expect(Number.isFinite(scored.score)).toBe(true);
    expect(scored.appScore).toBe(0);
    expect(scored.weights.p5).toBe(0);
    if (verdict === "reject") {
      expect(scored.topics[0].invalidMessageDeliveries).toBeGreaterThan(0);
      expect(scored.topics[0].weights.p4).toBeLessThan(0);
    }

    scored.ip.fill(0);
    scored.topics.length = 0;
    expect((await pair.right.getGossipDiagnostics()).peers[0].identity).toEqual(pair.identity.peerId);
    const counter = {
      accept: "reportsAppliedAccept",
      ignore: "reportsAppliedIgnore",
      reject: "reportsAppliedReject",
    } as const;
    for (let i = 0; i < 1000 && pair.right.diagnostics().gossip[counter[verdict]] === 0n; i++) await delay(5);
    expect(pair.right.diagnostics().gossip).toMatchObject({
      occupied: 0,
      payloadBytes: 0,
      reportsAccepted: 1n,
      reservedBytes: 0,
      [counter[verdict]]: 1n,
      bytesCopied: 4000n,
      messagesCopied: 1n,
    });
  } finally {
    await Promise.all([pair.left.close(), pair.right.close()]);
  }
  expect(await pair.left.getMetrics()).toContain("gossipsub_rpc_sent_message_total 1\n");
  expect(pair.right.getMetrics()).toContain("gossipsub_rpc_recv_message_total 1\n");
  expect(pair.right.getMetrics()).toContain('gossipsub_cache_size{cache="seenCache"} 0\n');
  expect(pair.right.getMetrics()).toContain('gossipsub_cache_size{cache="gossipTracer.promises"} 0\n');
  expect(pair.right.getMetrics()).toContain("gossipsub_mcache_size 0\n");
}, 15000);

test("gossip payload credit retires on close while descriptors remain held", async () => {
  const pair = await gossipPair();
  try {
    await pair.left.publishGossip(TOPIC, blockPayload(4000, 2), {allowZeroPeers: false});
    const message = await nextGossip(pair.right);
    await pair.right.close();
    expect(message.data).toEqual(blockPayload(4000, 2));
    expect(pair.right.reportGossip(message.handle, "accept")).toBe(false);
    const diagnostics = pair.right.diagnostics();
    expect(diagnostics.liveNativeRequestedBytes).toBe(0);
    expect(diagnostics.gossip).toMatchObject({copyingBytes: 0, occupied: 0, payloadBytes: 0, reservedBytes: 0});
  } finally {
    await Promise.all([pair.left.close(), pair.right.close()]);
  }
}, 15000);
test("gossip and both request directions retain independent payload capacity", async () => {
  const pair = await gossipPair(30000n, 192 * 1024 * 1024);
  try {
    const outgoing = pair.right.request(pair.identity.peerId, BLOCKS, new Uint8Array(32));
    const outboundPull = outgoing.next();
    void outboundPull.catch(() => undefined);
    const inbound = await takeIncoming(pair.left);
    const reverse = pair.left.request(pair.remote.peerId, BLOCKS, new Uint8Array(32));
    const inboundPull = reverse.next();
    void inboundPull.catch(() => undefined);
    const serving = await takeIncoming(pair.right);
    expect(pair.right.diagnostics().requests.occupied).toBe(1);
    expect(pair.right.diagnostics().incoming.occupied).toBe(1);
    await pair.left.publishGossip(TOPIC, blockPayload(10 * 1024 * 1024, 17), {allowZeroPeers: false});
    const message = await nextGossip(pair.right);
    expect(Buffer.from(message.data).equals(blockPayload(10 * 1024 * 1024, 17))).toBe(true);
    expect(pair.right.reportGossip(message.handle, "ignore")).toBe(true);
    await expect.poll(() => pair.right.diagnostics().gossip.reservedBytes).toBe(0);
    await Promise.all([
      inbound.respond(new Uint8Array(4000).fill(1), requestForks[0]),
      serving.respond(new Uint8Array(4000).fill(2), requestForks[0]),
    ]);
    expect(await outboundPull).toMatchObject({value: {data: new Uint8Array(4000).fill(1)}});
    expect(await inboundPull).toMatchObject({value: {data: new Uint8Array(4000).fill(2)}});
    const done = [outgoing.next(), reverse.next()];
    await Promise.all([inbound.finish(), serving.finish()]);
    expect(await Promise.all(done)).toEqual([
      {done: true, value: undefined},
      {done: true, value: undefined},
    ]);
    const statusAt = (await pair.right.getPeers()).peers[0].statusAtMs;
    await pair.right.reStatusPeers([pair.identity.peerId]);
    let statusUpdated = false;
    for (let i = 0; i < 1000; i++) {
      if ((await pair.right.getPeers()).peers[0].statusAtMs > statusAt) {
        statusUpdated = true;
        break;
      }
      await delay(5);
    }
    expect(statusUpdated).toBe(true);
  } finally {
    await Promise.all([pair.left.close(), pair.right.close()]);
  }
}, 20000);

test.each([
  false,
  true,
])("native gossip expiry %s releases queued payloads but retains outstanding host work", async (delivered) => {
  const pair = await gossipPair(150n);
  try {
    await pair.left.publishGossip(TOPIC, blockPayload(4000, 5), {allowZeroPeers: false});
    let message: NativeGossipMessage | undefined;
    if (delivered) message = await nextGossip(pair.right);
    for (let i = 0; i < 1000; i++) {
      answerChecks(pair.right);
      const diag = pair.right.diagnostics().gossip;
      if (diag.queuedExpired + diag.deliveredExpired > 0n) break;
      await delay(5);
    }
    expect(pair.right.diagnostics().gossip).toMatchObject({
      deliveredExpired: delivered ? 1n : 0n,
      occupied: delivered ? 1 : 0,
      payloadBytes: 0,
      queuedExpired: delivered ? 0n : 1n,
      reservedBytes: 0,
    });
    expect(pair.right.exchange(gossipAll).gossip?.messages ?? []).toEqual([]);
    if (message) expect(pair.right.reportGossip(message.handle, "accept")).toBe(false);
    expect(pair.right.diagnostics().gossip.occupied).toBe(0);
  } finally {
    await Promise.all([pair.left.close(), pair.right.close()]);
  }
}, 15000);

import {readFile} from "node:fs/promises";

const HOST = process.env.LODESTAR_Z_NETWORK_STOCK_HOST;
const HOODI = process.env.LODESTAR_Z_NETWORK_HOODI_FIXTURE;
for (const hoodi of [false, true]) {
  test.skipIf(!HOST || (hoodi && !HOODI))(
    `pinned stock gossip ${hoodi ? "Hoodi sample" : "wire IDs and same-fork BPO topics"}`,
    async () => {
      const {Child} = await import("../../test/interop/child.mjs");
      const {messageId, payload, summary} = await import("../../test/interop/codec.mjs");
      const peer = new Child("gossip-stock", process.execPath, [
        "--import",
        "tsx",
        "test/interop/request_responder.mjs",
        HOST ?? "",
        HOODI ?? "",
        "gossip",
      ]);
      let runtime: NativeNetworkApplicationRuntime | undefined;
      try {
        const info = await peer.command("ready");
        const config = applicationConfig();
        const firstTopic = topicName("beacon_block", 2);
        const secondTopic = topicName("beacon_block", 3);
        runtime = startRuntime(config, () => undefined);
        const identity = await runtime.identity;
        const intent = localIntent(config);
        intent.subscriptions = subscriptions(firstTopic, secondTopic);
        await runtime.applyIntent(intent, config.initialSlot);
        await peer.command("gossipSubscribe", {topic: firstTopic});
        await peer.command("gossipSubscribe", {topic: secondTopic});
        const remote = peerIdFromHex(info.peer);
        const endpoint = {
          address: Uint8Array.of(127, 0, 0, 1),
          family: 4 as const,
          port: Number(info.address.split("/")[4]),
        };
        await runtime.addDirectPeer(remote, [endpoint]);
        await runtime.connect(remote, [endpoint], 5000n);
        for (let i = 0; i < 100; i++) {
          const state = await peer.command("gossipStats");
          if (state.subscribers.every((entry: {count: number}) => entry.count === 1)) break;
          await delay(25);
        }
        for (const [index, topic] of [firstTopic, secondTopic].entries()) {
          const sent = await peer.command("gossipPublish", {length: 4000, seed: 71 + index, slot: 100, topic});
          const message = await nextGossip(runtime);
          expect(message.topic).toBe(topic);
          expect(Buffer.from(message.id).toString("hex")).toBe(sent.messageId);
          expect(message.peerId).toEqual(remote);
          const expected = payload(4000, 71 + index);
          expected.writeBigUInt64LE(100n, 100);
          expect(summary(message.data)).toEqual(summary(expected));
          expect(runtime.reportGossip(message.handle, index === 0 ? "accept" : "ignore")).toBe(true);
          const data = payload(4000, 81 + index);
          data.writeBigUInt64LE(100n, 100);
          expect(await runtime.publishGossip(topic, data, {allowZeroPeers: false})).toMatchObject({
            queued: 1,
            selected: 1,
          });
          for (let i = 0; i < 100; i++) {
            const state = await peer.command("gossipStats");
            if (state.messages.length > index) break;
            await delay(10);
          }
          const state = await peer.command("gossipStats");
          expect(state.messages[index]).toMatchObject({
            ...summary(data),
            messageId: messageId(topic, data).toString("hex"),
            topic,
          });
        }
        // One peer holds at most half of a kind's processor items pending validation.
        const held = config.gossipPolicy.processor[topicKinds.indexOf("beacon_block")].items / 2;
        if (!hoodi) {
          for (let i = 0; i < 64; i++)
            await peer.command("gossipPublish", {length: 4000, seed: 900 + i, slot: 100, topic: firstTopic});
          for (let i = 0; i < 1000 && runtime.diagnostics().gossip.checking !== held; i++) await delay(5);
          expect(runtime.diagnostics().gossip).toMatchObject({
            checking: held,
            occupied: held,
            payloadBytes: held * 4000,
            queued: 0,
            reservedBytes: 0,
          });
        }
        expect(
          await peer.command("ping", {addressBytes: Buffer.from(identity.localMultiaddr).toString("hex")})
        ).toMatchObject({length: 8});
        if (!hoodi) {
          answerChecks(runtime);
          for (let i = 0; i < 1000 && runtime.diagnostics().gossip.queued !== held; i++) await delay(5);
          const messages = runtime.exchange(gossipAll).gossip?.messages ?? [];
          expect(messages).toHaveLength(held);
          for (const message of messages) expect(runtime.reportGossip(message.handle, "ignore")).toBe(true);
        }
        if (hoodi && HOODI) {
          const data = await readFile(HOODI);
          expect(data.length).toBe(17569);
          const sent = await peer.command("gossipPublish", {hoodi: true, length: data.length, topic: firstTopic});
          const message = await nextGossip(runtime);
          expect(message.data).toEqual(new Uint8Array(data));
          expect(Buffer.from(message.id).toString("hex")).toBe(sent.messageId);
          expect(runtime.reportGossip(message.handle, "reject")).toBe(true);
        }
      } finally {
        await Promise.allSettled([runtime?.close(), peer.stop()]);
      }
    },
    20000
  );
}

import {execFileSync} from "node:child_process";

test("gossip operation promises and weak notifier permit facade collection", () => {
  const output = execFileSync(
    process.execPath,
    [
      "--import",
      "tsx",
      "--expose-gc",
      "--force-node-api-uncaught-exceptions-policy",
      "bindings/test/fixtures/network-gossip-lifecycle.mjs",
    ],
    {encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 15000}
  );
  const result = JSON.parse(output.trim());
  expect(result).toMatchObject({collected: true});
  expect(result.accepted).toBeGreaterThan(0);
  expect(result.accepted).toBe(result.settled);
}, 20000);

test("gossip publication rechecks a detached view and rolls back reentrant close", async () => {
  const config = applicationConfig();
  const runtime = startRuntime(config, () => undefined);
  try {
    await runtime.identity;
    await runtime.applyIntent(localIntent(config), config.initialSlot);
    const data = new Uint8Array(4000);
    await expect(
      runtime.publishGossip(TOPIC, data, {
        get flood() {
          structuredClone(data, {transfer: [data.buffer]});
          return false;
        },
      })
    ).rejects.toThrow("InvalidNetworkBytes");
    expect(runtime.diagnostics()).toMatchObject({
      gossip: {publicationBytes: 0, reservedBytes: 0},
      operationOccupied: 0,
    });
    await expect(
      runtime.publishGossip(TOPIC, new Uint8Array(4000), {
        get flood() {
          void runtime.close();
          return false;
        },
      })
    ).rejects.toThrow("NetworkClosed");
  } finally {
    await runtime.close();
  }
  expect(runtime.diagnostics()).toMatchObject({gossip: {publicationBytes: 0, reservedBytes: 0}, operationOccupied: 0});
});

test("closed runtime rejects a retained verdict", async () => {
  const pair = await gossipPair();
  try {
    await pair.left.publishGossip(TOPIC, blockPayload(4000));
    const old = await nextGossip(pair.right);
    await pair.right.close();
    expect(pair.right.reportGossip(old.handle, "accept")).toBe(false);
  } finally {
    await Promise.all([pair.left.close(), pair.right.close()]);
  }
});

test("gossip diagnostics validate cursors and share bounded snapshot admission", async () => {
  const config = applicationConfig();
  const runtime = startRuntime(config, () => undefined);
  try {
    await runtime.identity;
    await runtime.applyIntent(localIntent(config), config.initialSlot);
    for (const cursor of [-1, 0.5, 513, Number.NaN]) {
      expect(() => runtime.getGossipDiagnostics(cursor)).toThrow();
    }
    const snapshots = [runtime.getGossipDiagnostics(), runtime.getPeers()];
    expect(() => runtime.getGossipDiagnostics()).toThrow("NetworkCommandFull");
    const [page] = await Promise.all(snapshots);
    expect(page).toMatchObject({nextCursor: null, peers: []});
    await expect(runtime.getGossipDiagnostics(512)).rejects.toThrow("InvalidDiagnosticsCursor");
    expect(runtime.diagnostics().operationOccupied).toBe(0);
  } finally {
    await runtime.close();
  }
  expect(() => runtime.getGossipDiagnostics()).toThrow("NetworkClosed");
});

test("gossip diagnostics paginate retained peers and peer drains expose remaining events", async () => {
  const config = applicationConfig();
  const runtime = startRuntime(config, () => undefined);
  const identities = new Set<string>();
  try {
    await runtime.identity;
    await runtime.applyIntent(localIntent(config), config.initialSlot);
    for (let i = 0; i < 9; i++) {
      const remoteConfig = applicationConfig();
      remoteConfig.identitySecretKey[31] = 70 + i;
      const remote = await startPeer(remoteConfig);
      try {
        const identity = await remote.identity;
        identities.add(identity.peerId);
        await remote.applyIntent(localIntent(remoteConfig), remoteConfig.initialSlot);
        await runtime.connect(identity.peerId, [identity.localEndpoint], 5000n);
        await vi.waitFor(
          async () => {
            const page = await remote.getGossipDiagnostics();
            expect(page.peers).toHaveLength(1);
            expect(page.peers[0].outboundReady).toBe(true);
          },
          {timeout: 5000}
        );
        await runtime.disconnect(identity.peerId);
      } finally {
        await remote.close();
      }
    }
    const first = await runtime.getGossipDiagnostics();
    expect(first.peers).toHaveLength(8);
    expect(first.nextCursor).not.toBeNull();
    const second = await runtime.getGossipDiagnostics(first.nextCursor ?? 0);
    expect(second.peers).toHaveLength(1);
    expect(second.nextCursor).toBeNull();
    expect(second.ownerSequence).toBeGreaterThanOrEqual(first.ownerSequence);
    expect(new Set([...first.peers, ...second.peers].map((peer) => peer.identity))).toEqual(identities);
    expect([...first.peers, ...second.peers].every((peer) => !peer.connected)).toBe(true);
    const head = runtime.exchange({...settleOnly, peers: 1});
    expect(head.peers).toHaveLength(1);
    expect(head.more).toBe(true);
    const remaining = runtime.exchange({...settleOnly, peers: 64}).peers;
    expect(remaining.length).toBeGreaterThan(0);
    expect(remaining.filter((event) => event.type === "closed").every((event) => event.reason === "host")).toBe(true);
  } finally {
    await runtime.close();
  }
}, 45000);
