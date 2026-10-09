import {setTimeout as delay} from "node:timers/promises";
import {expect, test} from "vitest";
import type {NativeGossipProcessorLimit, NativeTopicKind} from "../src/network.js";
import type {
  NativeAction,
  NativeGossipDependencyCheck,
  NativeGossipHandle,
  NativeGossipMessage,
  NativeGossipVerdict,
  NativeNetworkApplicationRuntime,
} from "../src/network-runtime.js";
import {
  applicationConfig,
  exchange,
  gossipAll,
  gossipUrgent,
  localIntent,
  metricValue,
  settleOnly,
  startRuntime,
  subscriptions,
  topicKinds,
  topicName,
  waitForGossipReady,
} from "./utils/network.js";
import {incomingPair} from "./utils/network-incoming.js";

const BLOCK = topicName();
const ATTESTATION = topicName("beacon_attestation_0");

function limits(
  make: (index: number) => NativeGossipProcessorLimit,
  length = topicKinds.length
): Record<NativeTopicKind, NativeGossipProcessorLimit> {
  return Object.fromEntries(topicKinds.slice(0, length).map((kind, index) => [kind, make(index)])) as Record<
    NativeTopicKind,
    NativeGossipProcessorLimit
  >;
}

function classify(handle: NativeGossipHandle, available: boolean): NativeAction {
  return {available, handle, type: "classify"};
}
function verdict(handle: NativeGossipHandle, value: NativeGossipVerdict): NativeAction {
  return {handle, type: "verdict", verdict: value};
}

test.each([
  {bytes: 4096, items: 8, length: 12},
  {bytes: 4096, items: 1, length: 13},
  {bytes: 4097, items: 8, length: 13},
  {bytes: 4096, items: 65535, length: 13},
  {bytes: 32 * 1024 * 1024, items: 8, length: 13},
])("rejects incompatible processor plan %j before allocation", ({length, items, bytes}) => {
  const config = applicationConfig();
  config.gossipPolicy.processor = limits(() => ({bytes, items}), length);
  expect(() => startRuntime(config, () => undefined)).toThrow("InvalidGossipProcessorLimits");
});

test.each([
  {bytes: 16 * 1024 * 1024, items: 0},
  {bytes: 16 * 1024 * 1024, items: 9},
  {bytes: 1, items: 1},
])("rejects unusable execution limits %j before starting the owner", (limit) => {
  const config = applicationConfig();
  config.resources.nativeBudgetBytes = 512 * 1024 * 1024;
  config.gossipPolicy.processor = limits(() => ({bytes: 16 * 1024 * 1024, items: 8}));
  config.gossipPolicy.execution = limits(() => limit);
  expect(() => startRuntime(config, () => undefined)).toThrow();
});

test("exchange actions validate roots, handles and verdicts, and stale handles apply as no-ops", async () => {
  const config = applicationConfig();
  const runtime = startRuntime(config, () => undefined);
  try {
    await runtime.identity;
    await runtime.applyIntent(localIntent(config), config.initialSlot);
    expect(exchange(runtime, gossipUrgent)).toMatchObject({checks: [], gossip: null});
    const handle = {generation: 1n, index: 0};
    for (const [invalid, code] of [
      [{root: new Uint8Array(31), type: "block"}, "InvalidNetworkBytes"],
      [classify({...handle, generation: 0n}, true), "InvalidGossipHandle"],
      [classify({...handle, index: 65535}, true), "InvalidNetworkInteger"],
      [{...verdict(handle, "accept"), verdict: "ACCEPT"}, "InvalidGossipVerdict"],
      [{type: "unknown"}, "InvalidNetworkAction"],
      [{action: "fatal", count: 0, peerId: runtime.identity.peerId, type: "reportPeer"}, "InvalidNetworkInteger"],
      [{action: "fatal", count: 101, peerId: runtime.identity.peerId, type: "reportPeer"}, "InvalidNetworkInteger"],
      [{action: "bad", count: 1, peerId: runtime.identity.peerId, type: "reportPeer"}, "InvalidNetworkAction"],
    ] as const)
      expect(() => runtime.exchange([classify(handle, true), invalid as NativeAction], settleOnly)).toThrow(code);
    expect(
      exchange(runtime, settleOnly, [classify(handle, true), verdict(handle, "ignore")]).needsAnotherExchange
    ).toBe(false);
  } finally {
    await runtime.close();
  }
});

async function checks(runtime: NativeNetworkApplicationRuntime, count: number) {
  const result: NativeGossipDependencyCheck[] = [];
  for (let i = 0; i < 1000 && result.length < count; i++) {
    const delivery = exchange(runtime, gossipUrgent);
    expect(delivery.gossip).toBeNull();
    expect(delivery.serving).toEqual([]);
    result.push(...delivery.checks);
    if (result.length < count) await delay(5);
  }
  expect(result).toHaveLength(count);
  return result;
}

test("native processor retains dependencies, protects blocks, batches ready work and bounds future slots", async () => {
  const pair = await incomingPair(undefined, undefined, (left, right) => {
    for (const config of [left, right]) {
      config.gossipPolicy.processor = limits((kind) => ({
        bytes: (kind === 0 || kind === 12 ? 16 : kind === 4 ? 4 : 1) * 1024 * 1024,
        items: 8,
      }));
      config.gossipPolicy.execution = undefined;
    }
  });
  try {
    for (const [runtime, config] of [
      [pair.left, pair.leftConfig],
      [pair.right, pair.rightConfig],
    ] as const) {
      const intent = localIntent(config);
      intent.subscriptions = subscriptions(BLOCK, ATTESTATION);
      await runtime.applyIntent(intent, config.initialSlot);
    }
    await Promise.all([
      pair.left.addDirectPeer(pair.remote.peerId, [pair.remote.localEndpoint]),
      pair.right.addDirectPeer(pair.identity.peerId, [pair.identity.localEndpoint]),
    ]);
    await Promise.all([
      waitForGossipReady(pair.left, [pair.remote.peerId], [BLOCK, ATTESTATION], () => pair.left.getMetrics()),
      waitForGossipReady(pair.right, [pair.identity.peerId], [BLOCK, ATTESTATION], () => pair.right.getMetrics()),
    ]);
    const data = new Uint8Array(229);
    const view = new DataView(data.buffer);
    view.setUint32(0, 228, true);
    view.setBigUint64(4, pair.rightConfig.initialSlot, true);
    data.fill(7, 20, 52);
    data[228] = 1;
    const root = data.slice(20, 52);
    exchange(pair.right, {...gossipAll});
    for (const signature of [1, 2]) {
      data[132] = signature;
      await pair.left.publishGossip(ATTESTATION, data);
    }
    const waiting = await checks(pair.right, 2);
    for (const check of waiting) expect(check.root).toEqual(root);
    // A batch with an invalid action applies none of it.
    expect(() =>
      pair.right.exchange(
        [classify(waiting[0].handle, false), classify({...waiting[1].handle, generation: 0n}, false)],
        settleOnly
      )
    ).toThrow("InvalidGossipHandle");

    exchange(pair.right, settleOnly, [
      classify({generation: 1n, index: 65534}, false),
      ...waiting.map(({handle}) => classify(handle, false)),
    ]);

    const blockBytes = new Uint8Array(4000);
    new DataView(blockBytes.buffer).setBigUint64(100, pair.rightConfig.initialSlot, true);
    await pair.left.publishGossip(BLOCK, blockBytes);
    const urgent = {...gossipUrgent};
    let block;
    for (let i = 0; i < 1000 && !block; i++) {
      // Waiting attestations are neither checkable nor claimable. The block queues without a check of its parent,
      // which the host's validator checks.
      const {checks: pending, gossip} = exchange(pair.right, urgent);
      expect(pending).toEqual([]);
      if (!gossip) await delay(5);
      else {
        expect(gossip.jobs).toEqual([{grouped: false, kind: "beacon_block", length: 1, start: 0, urgent: true}]);
        block = gossip.messages[0];
      }
    }
    expect(block?.topic).toBe(BLOCK);
    if (!block) throw Error("Block dispatch deadline");
    expect(exchange(pair.right, urgent).gossip).toBeNull();
    exchange(pair.right, settleOnly, [verdict(block.handle, "accept"), {root, type: "block"}]);

    exchange(
      pair.right,
      settleOnly,
      (await checks(pair.right, 2)).map(({handle}) => classify(handle, true))
    );
    // The owner readies the attestation group at its deadline; claims before it find none.
    const ordinary = {...gossipAll};
    let batch = exchange(pair.right, ordinary).gossip;
    for (let i = 0; i < 200 && !batch?.messages.length; i++) {
      await delay(5);
      const result = exchange(pair.right, ordinary);
      expect(result.checks).toEqual([]);
      batch = result.gossip;
    }
    if (!batch) throw Error("Attestation group deadline");
    expect(batch.jobs).toEqual([
      {grouped: true, kind: "beacon_attestation", length: batch.messages.length, start: 0, urgent: false},
    ]);
    expect(exchange(pair.right, ordinary).gossip).toBeNull();
    expect(batch.messages).toHaveLength(2);
    expect(batch.messages.map((message) => message.attestationData)).toEqual([
      Buffer.from(data.subarray(4, 132)).toString("base64"),
      Buffer.from(data.subarray(4, 132)).toString("base64"),
    ]);
    exchange(
      pair.right,
      settleOnly,
      batch.messages.map(({handle}) => verdict(handle, "ignore"))
    );

    view.setBigUint64(4, 999999999n, true);
    await pair.left.publishGossip(ATTESTATION, data);
    await expect
      .poll(
        () =>
          metricValue(
            pair.right.getMetrics(),
            'lodestar_gossip_validation_refusals_total{topic="beacon_attestation",reason="ineligible"}'
          ),
        {timeout: 5000}
      )
      .toBe(1);
    expect(exchange(pair.right, {...gossipUrgent}).checks).toEqual([]);
  } finally {
    await Promise.allSettled([pair.left.stop(), pair.right.close()]);
  }
}, 30000);

test("expired validation execution remains visible until late host completion", async () => {
  const pair = await incomingPair(undefined, undefined, (left, right) => {
    for (const config of [left, right]) {
      config.gossipPolicy.processor = limits((kind) => ({
        bytes: (kind === 0 || kind === 12 ? 16 : kind === 4 ? 4 : 1) * 1024 * 1024,
        items: 8,
      }));
      config.gossipPolicy.execution = undefined;
      config.gossipPolicy.validationTimeoutMs = 2000n;
    }
  });
  try {
    for (const [runtime, config] of [
      [pair.left, pair.leftConfig],
      [pair.right, pair.rightConfig],
    ] as const) {
      const intent = localIntent(config);
      intent.subscriptions = subscriptions(BLOCK);
      await runtime.applyIntent(intent, config.initialSlot);
    }
    await Promise.all([
      pair.left.addDirectPeer(pair.remote.peerId, [pair.remote.localEndpoint]),
      pair.right.addDirectPeer(pair.identity.peerId, [pair.identity.localEndpoint]),
    ]);
    await Promise.all([
      waitForGossipReady(pair.left, [pair.remote.peerId], [BLOCK], () => pair.left.getMetrics()),
      waitForGossipReady(pair.right, [pair.identity.peerId], [BLOCK], () => pair.right.getMetrics()),
    ]);
    const block = new Uint8Array(4000);
    new DataView(block.buffer).setBigUint64(100, pair.rightConfig.initialSlot, true);
    await pair.left.publishGossip(BLOCK, block);
    let message: NativeGossipMessage | undefined;
    for (let i = 0; i < 1000 && !message; i++) {
      message = exchange(pair.right, gossipAll).gossip?.messages[0];
      if (!message) await delay(5);
    }
    if (!message) throw Error("Block dispatch deadline");

    const expiredSample = "lodestar_gossip_validation_expired_executing_count 1\n";
    for (let i = 0; i < 1000 && !pair.right.getMetrics().includes(expiredSample); i++) await delay(5);
    expect(pair.right.getMetrics()).toContain(expiredSample);

    // A late verdict retires the message without applying it.
    exchange(pair.right, settleOnly, [verdict(message.handle, "accept"), verdict(message.handle, "reject")]);

    for (let i = 0; i < 1000 && pair.right.getMetrics().includes(expiredSample); i++) await delay(5);
    expect(pair.right.getMetrics()).toContain("lodestar_gossip_validation_expired_executing_count 0\n");
  } finally {
    await Promise.all([pair.left.stop(), pair.right.close()]);
  }
}, 20000);
