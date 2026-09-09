import {expect, test, vi} from "vitest";
import {createNativeNetworkApplicationRuntime} from "../src/network.js";
import {applicationConfig, localIntent} from "./utils/network.js";

test("gossip drain and stale verdict on an activated application", async () => {
  const config = applicationConfig();
  const runtime = createNativeNetworkApplicationRuntime(config, () => undefined);
  try {
    await runtime.ready;
    await runtime.applyIntent(localIntent(config), config.initialSlot);
    expect(runtime.drainGossip()).toEqual({messages: [], more: false});
    expect(runtime.reportGossip({generation: 1n, index: 0, session: runtime.diagnostics().session}, "ignore")).toBe(
      false
    );
  } finally {
    await runtime.close();
  }
});

import {setTimeout as delay} from "node:timers/promises";
import bindings from "../src/bindings.js";
import type {NativeGossipMessage, NativeNetworkApplicationRuntime} from "../src/network.js";
import {BLOCKS, incomingPair, takeIncoming} from "./utils/network-incoming.js";

const TOPIC = "/eth2/01020304/beacon_block/ssz_snappy";

async function nextGossip(runtime: NativeNetworkApplicationRuntime): Promise<NativeGossipMessage> {
  for (let i = 0; i < 1000; i++) {
    const batch = runtime.drainGossip();
    if (batch.messages.length) {
      expect(batch.messages).toHaveLength(1);
      return batch.messages[0];
    }
    await delay(5);
  }
  throw Error("Gossip delivery deadline");
}
async function gossipPair(timeoutMs = 30000n, budget?: number, beforeServer?: () => void) {
  const pair = await incomingPair(beforeServer, budget, undefined, (left, right) => {
    right.gossipPolicy.validationTimeoutMs = timeoutMs;
    for (const config of [left, right]) config.topicPolicy[0].rules.beacon_block.sszMax = 10 * 1024 * 1024;
  });
  try {
    for (const [runtime, config] of [
      [pair.left, pair.leftConfig],
      [pair.right, pair.rightConfig],
    ] as const) {
      const intent = localIntent(config);
      intent.subscriptions = [{name: TOPIC, params: config.gossipPolicy.score.defaultTopic}];
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
  const runtime = createNativeNetworkApplicationRuntime(config, () => undefined);
  const handle = {generation: 1n, index: 0, session: runtime.diagnostics().session};
  try {
    await runtime.ready;
    expect(() => runtime.drainGossip()).toThrow("NetworkNotActive");
    expect(() => runtime.publishGossip(TOPIC, new Uint8Array(10))).toThrow("NetworkNotActive");
    await runtime.applyIntent(localIntent(config), config.initialSlot);
    for (const malformed of [
      {...handle, session: 0n},
      {...handle, generation: 0n},
      {...handle, generation: 1n << 64n},
      {...handle, index: -1},
      {...handle, index: 0.5},
      {...handle, extra: true},
    ])
      expect(() => runtime.reportGossip(malformed, "ignore")).toThrow();
    expect(() => runtime.reportGossip(handle, "ACCEPT" as "accept")).toThrow();
    expect(runtime.reportGossip({...handle, session: handle.session + 1n}, "ignore")).toBe(false);
    expect(runtime.reportGossip({...handle, index: Number.MAX_SAFE_INTEGER}, "ignore")).toBe(false);
    expect(() => runtime.publishGossip(TOPIC, new Uint8Array(10), {flood: 0} as unknown as {flood: boolean})).toThrow();
    expect(() => runtime.publishGossip(TOPIC, new Uint8Array(10), {unknown: true} as {flood: boolean})).toThrow();
    expect(() => runtime.publishGossip(TOPIC, new Uint16Array(10) as unknown as Uint8Array)).toThrow();
    const detached = new Uint8Array(10);
    structuredClone(detached, {transfer: [detached.buffer]});
    expect(() => runtime.publishGossip(TOPIC, detached)).toThrow();
    await expect(runtime.publishGossip("/invalid", new Uint8Array(10))).rejects.toMatchObject({
      code: "NetworkGossipPublishFailed",
      reason: "unknown_topic",
    });
    await expect(runtime.publishGossip(TOPIC, new Uint8Array(9))).rejects.toMatchObject({
      code: "NetworkGossipPublishFailed",
      reason: "payload_too_small",
    });
    await expect(runtime.publishGossip(TOPIC, new Uint8Array(21))).rejects.toMatchObject({
      code: "NetworkGossipPublishFailed",
      reason: "payload_too_large",
    });
    await expect(runtime.publishGossip(TOPIC, new Uint8Array(10), {allowZeroPeers: false})).rejects.toMatchObject({
      code: "NetworkGossipPublishFailed",
      reason: "no_peers_subscribed_to_topic",
    });
    expect(
      await runtime.publishGossip(TOPIC, new Uint8Array(10), {
        allowZeroPeers: true,
        flood: false,
        ignoreDuplicate: false,
      })
    ).toEqual({duplicate: false, pressured: 0, queued: 0, selected: 0, unavailable: 0});
    await expect(runtime.publishGossip(TOPIC, new Uint8Array(10), {ignoreDuplicate: false})).rejects.toMatchObject({
      code: "NetworkGossipPublishFailed",
      reason: "duplicate",
    });
    expect(await runtime.publishGossip(TOPIC, new Uint8Array(10), {ignoreDuplicate: true})).toEqual({
      duplicate: true,
      pressured: 0,
      queued: 0,
      selected: 0,
      unavailable: 0,
    });
  } finally {
    await runtime.close();
  }
  expect(runtime.drainGossip()).toEqual({messages: [], more: false});
  expect(runtime.reportGossip(handle, "ignore")).toBe(false);
  expect(() => runtime.publishGossip(TOPIC, new Uint8Array(10))).toThrow("NetworkClosed");
  expect(runtime.diagnostics().gossip).toMatchObject({
    capacity: 64,
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
    const input = new Uint8Array(10).fill(7);
    const before = Date.now();
    const published = pair.left.publishGossip(TOPIC, input, {allowZeroPeers: false});
    input.fill(99);
    expect(await published).toEqual({duplicate: false, pressured: 0, queued: 1, selected: 1, unavailable: 0});
    await delay(40);
    const message = await nextGossip(pair.right);
    await vi.waitFor(
      () => {
        expect(pair.left.getMetrics()).toContain('gossipsub_msg_publish_count_total{topic="beacon_block"} 1\n');
        expect(pair.right.getMetrics()).toContain('gossipsub_pre_validation_valid_total{topic="beacon_block"} 1\n');
        expect(pair.left.getMetrics()).toContain(
          'lodestar_gossip_topic_peers_by_type_count{type="beacon_block",boundary="01020304"} 1\n'
        );
      },
      {timeout: 5000}
    );
    expect(message.topic).toBe(TOPIC);
    expect(message.data).toEqual(new Uint8Array(10).fill(7));
    expect(message.peerId).toEqual(pair.identity.peerId);
    expect(message.connection).toEqual((await pair.right.getPeers()).peers[0].connection);
    const {messageId} = await import("../../test/interop/codec.mjs");
    expect(Buffer.from(message.id)).toEqual(messageId(TOPIC, new Uint8Array(10).fill(7)));
    expect(message.receivedAtUnixMs).toBeGreaterThanOrEqual(before);
    expect(message.receivedAtUnixMs).toBeLessThan(Date.now());
    expect(Number.isSafeInteger(message.receivedAtUnixMs)).toBe(true);
    message.peerId.fill(0);
    message.connection.generation++;
    message.data.fill(0);
    expect(pair.right.reportGossip(message.handle, verdict)).toBe(true);
    expect(pair.right.reportGossip(message.handle, verdict)).toBe(false);
    const verdictMetric = {accept: "accepted", ignore: "ignored", reject: "rejected"}[verdict];
    await vi.waitFor(
      () => {
        const metrics = pair.right.getMetrics();
        expect(metrics).toContain(`gossipsub_${verdictMetric}_messages_total{topic="beacon_block"} 1\n`);
        expect(metrics).toContain("gossipsub_async_validation_delay_from_first_seen_count 1\n");
        expect(metrics).toContain("lodestar_native_gossip_scored_peers 1\n");
      },
      {timeout: 5000}
    );
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
      bytesCopied: 10n,
      messagesCopied: 1n,
    });
  } finally {
    await Promise.all([pair.left.close(), pair.right.close()]);
  }
}, 15000);

test("gossip payload credit retires on close while descriptors remain held", async () => {
  const pair = await gossipPair();
  try {
    await pair.left.publishGossip(TOPIC, new Uint8Array(10).fill(2), {allowZeroPeers: false});
    const message = await nextGossip(pair.right);
    await pair.right.close();
    expect(message.data).toEqual(new Uint8Array(10).fill(2));
    expect(pair.right.reportGossip(message.handle, "accept")).toBe(false);
    const diagnostics = pair.right.diagnostics();
    expect(diagnostics.liveNativeRequestedBytes).toBe(0);
    expect(diagnostics.gossip).toMatchObject({copyingBytes: 0, occupied: 0, payloadBytes: 0, reservedBytes: 0});
  } finally {
    await Promise.all([pair.left.close(), pair.right.close()]);
  }
}, 15000);

const faultApi = bindings as unknown as {
  networkTestFail?: (stage: string) => void;
  networkTestScenario?: (stage: string) => void;
  networkTestStage?: () => string;
  networkTestGossipRelease?: () => void;
};
test.skipIf(!faultApi.networkTestFail)(
  "gossip copy failure publishes no batch and preserves a retry",
  async () => {
    const pair = await gossipPair();
    try {
      await pair.left.publishGossip(TOPIC, new Uint8Array(10).fill(3), {allowZeroPeers: false});
      for (let i = 0; i < 1000 && pair.right.diagnostics().gossip.queued === 0; i++) await delay(5);
      faultApi.networkTestFail?.("gossip_copy");
      expect(() => pair.right.drainGossip()).toThrow("InjectedNetworkFailure");
      expect(pair.right.diagnostics().gossip).toMatchObject({
        copyingBytes: 0,
        messagesCopied: 0n,
        payloadBytes: 10,
        queued: 1,
        reservedBytes: 20,
      });
      const message = await nextGossip(pair.right);
      expect(pair.right.reportGossip(message.handle, "ignore")).toBe(true);
    } finally {
      await Promise.all([pair.left.close(), pair.right.close()]);
    }
  },
  15000
);

test.skipIf(!faultApi.networkTestFail)(
  "gossip publication result failure preserves native queued outcome and closes",
  async () => {
    const pair = await gossipPair();
    try {
      faultApi.networkTestFail?.("operation_copy");
      await expect(
        pair.left.publishGossip(TOPIC, new Uint8Array(10).fill(4), {allowZeroPeers: false})
      ).rejects.toMatchObject({code: "NetworkResultAllocationFailed"});
      await pair.left.close();
      expect(pair.left.diagnostics()).toMatchObject({
        liveNativeRequestedBytes: 0,
        operationOccupied: 0,
        state: "failed",
        terminalErrorCode: "NetworkResultAllocationFailed",
      });
      expect(pair.left.diagnostics().gossip).toMatchObject({
        publicationBytes: 0,
        publicationCopies: 1n,
        publicationQueued: 1n,
        publicationSelected: 1n,
        reservedBytes: 0,
      });
    } finally {
      await Promise.all([pair.left.close(), pair.right.close()]);
    }
  },
  15000
);

test("gossip byte refusal preserves both accepted request directions and real control progress", async () => {
  const pair = await gossipPair(30000n, 34 * 1024 * 1024);
  try {
    const outgoing = pair.right.request(pair.identity.peerId, BLOCKS, new Uint8Array(32));
    const outboundPull = outgoing.next();
    const inbound = await takeIncoming(pair.left);
    const reverse = pair.left.request(pair.remote.peerId, BLOCKS, new Uint8Array(32));
    const inboundPull = reverse.next();
    const serving = await takeIncoming(pair.right);
    expect(pair.right.diagnostics().requests.occupied).toBe(1);
    expect(pair.right.diagnostics().incoming.occupied).toBe(1);
    await pair.left.publishGossip(TOPIC, new Uint8Array(10 * 1024 * 1024).fill(17), {allowZeroPeers: false});
    for (let i = 0; i < 2000 && pair.right.diagnostics().gossip.byteRefusals === 0n; i++) await delay(5);
    expect(pair.right.diagnostics().gossip).toMatchObject({
      byteRefusals: 1n,
      occupied: 0,
      reportsAccepted: 0n,
      reportsAppliedIgnore: 1n,
      reservedBytes: 0,
    });
    await Promise.all([
      inbound.respond(new Uint8Array(4000).fill(1), pair.leftConfig.requestForks[0]),
      serving.respond(new Uint8Array(4000).fill(2), pair.rightConfig.requestForks[0]),
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
])("native gossip expiry %s before/after delivery retires without a host report", async (delivered) => {
  const pair = await gossipPair(150n);
  try {
    await pair.left.publishGossip(TOPIC, new Uint8Array(10).fill(5), {allowZeroPeers: false});
    let message: NativeGossipMessage | undefined;
    if (delivered) message = await nextGossip(pair.right);
    for (let i = 0; i < 1000; i++) {
      const diag = pair.right.diagnostics().gossip;
      if (diag.queuedExpired + diag.deliveredExpired > 0n) break;
      await delay(5);
    }
    expect(pair.right.diagnostics().gossip).toMatchObject({
      deliveredExpired: delivered ? 1n : 0n,
      occupied: 0,
      payloadBytes: 0,
      queuedExpired: delivered ? 0n : 1n,
      reservedBytes: 0,
    });
    expect(pair.right.drainGossip()).toEqual({messages: [], more: false});
    if (message) expect(pair.right.reportGossip(message.handle, "accept")).toBe(false);
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
        "test/interop/request_responder.mjs",
        HOST ?? "",
        HOODI ?? "",
        "gossip",
      ]);
      let runtime: NativeNetworkApplicationRuntime | undefined;
      try {
        const info = await peer.command("ready");
        const config = applicationConfig();
        config.resources.bridgeBudgetBytes = 128 * 1024 * 1024;
        config.topicPolicy[0].rules.beacon_block.sszMax = 10 * 1024 * 1024;
        const secondTopic = "/eth2/05060708/beacon_block/ssz_snappy";
        config.topicPolicy.push({...structuredClone(config.topicPolicy[0]), digest: Uint8Array.of(5, 6, 7, 8)});
        runtime = createNativeNetworkApplicationRuntime(config, () => undefined);
        const identity = await runtime.ready;
        const intent = localIntent(config);
        intent.subscriptions = [TOPIC, secondTopic].map((name) => ({
          name,
          params: config.gossipPolicy.score.defaultTopic,
        }));
        await runtime.applyIntent(intent, config.initialSlot);
        await peer.command("gossipSubscribe", {topic: TOPIC});
        await peer.command("gossipSubscribe", {topic: secondTopic});
        const remote = Uint8Array.from(Buffer.from(info.peer, "hex"));
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
        for (const [index, topic] of [TOPIC, secondTopic].entries()) {
          const sent = await peer.command("gossipPublish", {length: 64, seed: 71 + index, topic});
          const message = await nextGossip(runtime);
          expect(message.topic).toBe(topic);
          expect(Buffer.from(message.id).toString("hex")).toBe(sent.messageId);
          expect(message.peerId).toEqual(remote);
          expect(summary(message.data)).toEqual(summary(payload(64, 71 + index)));
          expect(runtime.reportGossip(message.handle, index === 0 ? "accept" : "ignore")).toBe(true);
          const data = payload(64, 81 + index);
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
        if (!hoodi) {
          for (let i = 0; i < 64; i++) await peer.command("gossipPublish", {length: 64, seed: 900 + i, topic: TOPIC});
          for (let i = 0; i < 1000 && runtime.diagnostics().gossip.queued !== 64; i++) await delay(5);
          expect(runtime.diagnostics().gossip).toMatchObject({
            occupied: 64,
            payloadBytes: 4096,
            queued: 64,
            reservedBytes: 8192,
          });
        }
        expect(
          await peer.command("ping", {addressBytes: Buffer.from(identity.localMultiaddr).toString("hex")})
        ).toMatchObject({length: 8});
        if (!hoodi) {
          const batch = runtime.drainGossip();
          expect(batch.messages).toHaveLength(64);
          expect(batch.more).toBe(false);
          for (const message of batch.messages) expect(runtime.reportGossip(message.handle, "ignore")).toBe(true);
        }
        if (hoodi && HOODI) {
          const data = await readFile(HOODI);
          expect(data.length).toBe(17569);
          const sent = await peer.command("gossipPublish", {hoodi: true, length: data.length, topic: TOPIC});
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

for (const scenario of [
  "gossip_copy_close",
  "gossip_copy_close_fail",
  "gossip_copy_expire",
  "gossip_second_copy_fail",
]) {
  test.skipIf(!faultApi.networkTestScenario)(
    `gossip complete batch claim survives ${scenario}`,
    async () => {
      const pair = await gossipPair(scenario === "gossip_copy_expire" ? 250n : 30000n, undefined, () =>
        faultApi.networkTestScenario?.(scenario)
      );
      try {
        await pair.left.publishGossip(TOPIC, new Uint8Array(10).fill(21), {allowZeroPeers: false});
        await pair.left.publishGossip(TOPIC, new Uint8Array(10).fill(22), {allowZeroPeers: false});
        for (let i = 0; i < 1000 && pair.right.diagnostics().gossip.queued !== 2; i++) await delay(5);
        expect(pair.right.diagnostics().gossip.queued).toBe(2);
        if (scenario.includes("fail")) {
          expect(() => pair.right.drainGossip()).toThrow("InjectedNetworkFailure");
          expect(pair.right.diagnostics().gossip.messagesCopied).toBe(0n);
          expect(pair.right.diagnostics().gossip.copyingBytes).toBe(0);
          expect(pair.right.diagnostics().gossip.queued).toBe(scenario === "gossip_second_copy_fail" ? 2 : 0);
        } else {
          const batch = pair.right.drainGossip();
          expect(batch.messages.map((message) => [...message.data])).toEqual([Array(10).fill(21), Array(10).fill(22)]);
          expect(batch.more).toBe(false);
          for (const message of batch.messages) expect(pair.right.reportGossip(message.handle, "accept")).toBe(false);
          expect(faultApi.networkTestStage?.()).toBe(
            scenario === "gossip_copy_expire" ? "gossip_copy_expired" : "gossip_copy_closed"
          );
          expect(pair.right.diagnostics().gossip).toMatchObject({
            bytesCopied: 20n,
            copyingBytes: 0,
            messagesCopied: 2n,
            occupied: 0,
            payloadBytes: 0,
            reservedBytes: 0,
          });
        }
      } finally {
        await Promise.all([pair.left.close(), pair.right.close()]);
      }
    },
    15000
  );
}

import {execFileSync} from "node:child_process";

test("gossip operation promises and weak notifier permit facade collection", () => {
  const output = execFileSync(
    process.execPath,
    [
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

test("one maximum native gossip payload owns exactly two copy allowances until drain", async () => {
  const pair = await gossipPair();
  try {
    const input = new Uint8Array(10 * 1024 * 1024).fill(37);
    await pair.left.publishGossip(TOPIC, input, {allowZeroPeers: false});
    for (let i = 0; i < 2000 && pair.right.diagnostics().gossip.queued === 0; i++) await delay(5);
    expect(pair.right.diagnostics().gossip).toMatchObject({
      payloadBytes: input.length,
      queued: 1,
      reservedBytes: input.length * 2,
    });
    const message = await nextGossip(pair.right);
    expect(Buffer.from(message.data).equals(Buffer.from(input))).toBe(true);
    expect(pair.right.diagnostics().gossip).toMatchObject({
      bytesCopied: BigInt(input.length),
      messagesCopied: 1n,
      payloadBytes: 0,
      reservedBytes: 0,
    });
    expect(pair.right.reportGossip(message.handle, "ignore")).toBe(true);
  } finally {
    await Promise.all([pair.left.close(), pair.right.close()]);
  }
}, 20000);

test("gossip publication rechecks a detached view and rolls back reentrant close", async () => {
  const config = applicationConfig();
  const runtime = createNativeNetworkApplicationRuntime(config, () => undefined);
  try {
    await runtime.ready;
    await runtime.applyIntent(localIntent(config), config.initialSlot);
    const data = new Uint8Array(10);
    expect(() =>
      runtime.publishGossip(TOPIC, data, {
        get flood() {
          structuredClone(data, {transfer: [data.buffer]});
          return false;
        },
      })
    ).toThrow("InvalidNetworkBytes");
    expect(runtime.diagnostics()).toMatchObject({
      gossip: {publicationBytes: 0, reservedBytes: 0},
      operationOccupied: 0,
    });
    expect(() =>
      runtime.publishGossip(TOPIC, new Uint8Array(10), {
        get flood() {
          void runtime.close();
          return false;
        },
      })
    ).toThrow("NetworkClosed");
  } finally {
    await runtime.close();
  }
  expect(runtime.diagnostics()).toMatchObject({gossip: {publicationBytes: 0, reservedBytes: 0}, operationOccupied: 0});
});

test.skipIf(!faultApi.networkTestFail)(
  "gossip publication allocation refusal unwinds shared bytes and operation",
  async () => {
    const config = applicationConfig();
    const runtime = createNativeNetworkApplicationRuntime(config, () => undefined);
    try {
      await runtime.ready;
      await runtime.applyIntent(localIntent(config), config.initialSlot);
      faultApi.networkTestFail?.("gossip_publication");
      expect(() => runtime.publishGossip(TOPIC, new Uint8Array(10))).toThrow("InjectedNetworkFailure");
      expect(runtime.diagnostics()).toMatchObject({
        gossip: {publicationBytes: 0, publicationCopies: 0n, reservedBytes: 0},
        operationOccupied: 0,
      });
      expect(await runtime.publishGossip(TOPIC, new Uint8Array(10))).toMatchObject({queued: 0});
    } finally {
      await runtime.close();
    }
  }
);

test.skipIf(!faultApi.networkTestFail)("gossip table allocation failure unwinds application startup", async () => {
  faultApi.networkTestFail?.("gossip_table");
  expect(() => createNativeNetworkApplicationRuntime(applicationConfig(), () => undefined)).toThrow(
    "InjectedNetworkFailure"
  );
  const runtime = createNativeNetworkApplicationRuntime(applicationConfig(), () => undefined);
  await runtime.ready;
  await runtime.close();
});

test.skipIf(!faultApi.networkTestGossipRelease)(
  "gossip verdict uses its flag while all 32 real command cells are queued",
  async () => {
    const pair = await gossipPair(30000n, undefined, () => faultApi.networkTestScenario?.("gossip_owner_hold"));
    try {
      await pair.left.publishGossip(TOPIC, new Uint8Array(10).fill(45), {allowZeroPeers: false});
      const message = await nextGossip(pair.right);
      for (let i = 0; i < 1000 && faultApi.networkTestStage?.() !== "gossip_owner_held"; i++) await delay(5);
      expect(faultApi.networkTestStage?.()).toBe("gossip_owner_held");
      const commands = Array.from({length: 32}, () => pair.right.getIdentity());
      expect(pair.right.diagnostics().operationOccupied).toBe(32);
      expect(() => pair.right.getIdentity()).toThrow("NetworkCommandFull");
      expect(pair.right.reportGossip(message.handle, "ignore")).toBe(true);
      expect(pair.right.diagnostics().gossip.pendingVerdicts).toBe(1);
      faultApi.networkTestGossipRelease?.();
      await Promise.all(commands);
      for (let i = 0; i < 1000 && pair.right.diagnostics().gossip.reportsAppliedIgnore !== 1n; i++) await delay(5);
      expect(pair.right.diagnostics().gossip).toMatchObject({
        occupied: 0,
        reportsAccepted: 1n,
        reportsAppliedIgnore: 1n,
      });
    } finally {
      faultApi.networkTestGossipRelease?.();
      await Promise.all([pair.left.close(), pair.right.close()]);
    }
  },
  15000
);

test("gossip session restart cannot report against a replacement cell with the same index", async () => {
  const first = await gossipPair();
  let old: NativeGossipMessage;
  try {
    await first.left.publishGossip(TOPIC, new Uint8Array(10).fill(61), {allowZeroPeers: false});
    old = await nextGossip(first.right);
  } finally {
    await Promise.all([first.left.close(), first.right.close()]);
  }
  const second = await gossipPair();
  try {
    await second.left.publishGossip(TOPIC, new Uint8Array(10).fill(62), {allowZeroPeers: false});
    const current = await nextGossip(second.right);
    expect(current.handle.index).toBe(old.handle.index);
    expect(current.handle.session).not.toBe(old.handle.session);
    expect(second.right.reportGossip(old.handle, "reject")).toBe(false);
    expect(second.right.reportGossip(current.handle, "accept")).toBe(true);
  } finally {
    await Promise.all([second.left.close(), second.right.close()]);
  }
}, 15000);
