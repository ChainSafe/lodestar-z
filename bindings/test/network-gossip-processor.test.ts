import {setTimeout as delay} from "node:timers/promises";
import {expect, test} from "vitest";
import type {
  NativeAction,
  NativeGossipDependencyCheck,
  NativeGossipHandle,
  NativeGossipMessage,
  NativeGossipVerdict,
  NativeNetworkApplicationRuntime,
} from "../src/network.js";
import {
  applicationConfig,
  capacity,
  checksOnly,
  exchange,
  localIntent,
  settleOnly,
  startRuntime,
  subscriptions,
  topicName,
} from "./utils/network.js";
import {incomingPair} from "./utils/network-incoming.js";

const BLOCK = topicName();
const ATTESTATION = topicName("beacon_attestation_0");

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
  config.gossipPolicy.processor = Array.from({length}, () => ({bytes, items}));
  expect(() => startRuntime(config, () => undefined)).toThrow("InvalidGossipProcessorLimits");
});

test.each([
  {bytes: 16 * 1024 * 1024, items: 0},
  {bytes: 16 * 1024 * 1024, items: 9},
  {bytes: 1, items: 1},
])("rejects unusable execution limits %j before starting the owner", (limit) => {
  const config = applicationConfig();
  config.resources.nativeBudgetBytes = 512 * 1024 * 1024;
  config.gossipPolicy.processor = Array.from({length: 13}, () => ({bytes: 16 * 1024 * 1024, items: 8}));
  config.gossipPolicy.execution = Array.from({length: 13}, () => limit);
  expect(() => startRuntime(config, () => undefined)).toThrow();
});

test("exchange actions validate roots, handles and verdicts, and stale handles apply as no-ops", async () => {
  const config = applicationConfig();
  const runtime = startRuntime(config, () => undefined);
  try {
    await runtime.identity;
    await runtime.applyIntent(localIntent(config), config.initialSlot);
    expect(exchange(runtime, checksOnly)).toMatchObject({checks: [], gossip: null});
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
    expect(exchange(runtime, settleOnly, [classify(handle, true), verdict(handle, "ignore")]).more).toBe(false);
    expect(runtime.diagnostics().gossip).toMatchObject({checking: 0, reportsAccepted: 0n, waiting: 0});
  } finally {
    await runtime.close();
  }
});

async function checks(runtime: NativeNetworkApplicationRuntime, count: number) {
  const result: NativeGossipDependencyCheck[] = [];
  for (let i = 0; i < 1000 && result.length < count; i++) {
    result.push(...exchange(runtime, checksOnly).checks);
    if (result.length < count) await delay(5);
  }
  expect(result).toHaveLength(count);
  return result;
}

test("native processor retains dependencies, protects blocks, batches ready work and bounds future slots", async () => {
  const pair = await incomingPair(undefined, undefined, (left, right) => {
    for (const config of [left, right]) {
      config.gossipPolicy.processor = Array.from({length: 13}, (_, kind) => ({
        bytes: (kind === 0 || kind === 12 ? 16 : kind === 4 ? 4 : 1) * 1024 * 1024,
        items: 8,
      }));
      config.gossipPolicy.execution = undefined;
      config.resources.nativeBudgetBytes = 256 * 1024 * 1024;
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
    await delay(1250);
    const data = new Uint8Array(229);
    const view = new DataView(data.buffer);
    view.setUint32(0, 228, true);
    view.setBigUint64(4, pair.rightConfig.initialSlot, true);
    data.fill(7, 20, 52);
    data[228] = 1;
    const root = data.slice(20, 52);
    exchange(pair.right, {...settleOnly, peers: 64});
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
    expect(pair.right.diagnostics().gossip).toMatchObject({checking: 2, waiting: 0});
    exchange(pair.right, settleOnly, [
      classify({generation: 1n, index: 65534}, false),
      ...waiting.map(({handle}) => classify(handle, false)),
    ]);
    expect(pair.right.diagnostics().gossip).toMatchObject({messagesCopied: 0n, payloadBytes: 458, waiting: 2});
    const blockBytes = new Uint8Array(4000);
    new DataView(blockBytes.buffer).setBigUint64(100, pair.rightConfig.initialSlot, true);
    await pair.left.publishGossip(BLOCK, blockBytes);
    const urgent = {...settleOnly, bytes: 4096, capacity, checks: 64, messages: 1};
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
    expect(pair.right.diagnostics().gossip.reportsAccepted).toBe(1n);
    exchange(
      pair.right,
      settleOnly,
      (await checks(pair.right, 2)).map(({handle}) => classify(handle, true))
    );
    // The owner readies the attestation group at its deadline; claims before it find none.
    const ordinary = {...settleOnly, bytes: 1024, capacity, checks: 64, claimOrdinary: true, messages: 64};
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
    expect(pair.right.diagnostics().gossip.reportsAccepted).toBe(3n);
    view.setBigUint64(4, 999999999n, true);
    await pair.left.publishGossip(ATTESTATION, data);
    for (let i = 0; i < 1000 && pair.right.diagnostics().gossip.slotRefusals === 0n; i++) await delay(5);
    expect(pair.right.diagnostics().gossip).toMatchObject({checking: 0, executing: 0, slotRefusals: 1n, waiting: 0});
  } finally {
    await Promise.allSettled([pair.left.close(), pair.right.close()]);
  }
}, 30000);

test("expired validation execution remains visible until late host completion", async () => {
  const pair = await incomingPair(undefined, undefined, (left, right) => {
    for (const config of [left, right]) {
      config.gossipPolicy.processor = Array.from({length: 13}, (_, kind) => ({
        bytes: (kind === 0 || kind === 12 ? 16 : kind === 4 ? 4 : 1) * 1024 * 1024,
        items: 8,
      }));
      config.gossipPolicy.execution = undefined;
      config.gossipPolicy.validationTimeoutMs = 2000n;
      config.resources.nativeBudgetBytes = 256 * 1024 * 1024;
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
    await delay(1250);
    const block = new Uint8Array(4000);
    new DataView(block.buffer).setBigUint64(100, pair.rightConfig.initialSlot, true);
    await pair.left.publishGossip(BLOCK, block);
    let message: NativeGossipMessage | undefined;
    for (let i = 0; i < 1000 && !message; i++) {
      message = exchange(pair.right, {...settleOnly, bytes: 4096, capacity, claimOrdinary: true, messages: 1}).gossip
        ?.messages[0];
      if (!message) await delay(5);
    }
    if (!message) throw Error("Block dispatch deadline");
    expect(pair.right.diagnostics().gossip).toMatchObject({executing: 1, expiredExecuting: 0, payloadBytes: 0});
    const expiredSample = "lodestar_native_gossip_expired_executing 1\n";
    for (let i = 0; i < 1000 && !pair.right.getMetrics().includes(expiredSample); i++) await delay(5);
    expect(pair.right.getMetrics()).toContain(expiredSample);
    const expired = pair.right.diagnostics().gossip;
    expect(expired).toMatchObject({executing: 1, expiredExecuting: 1, occupied: 1, payloadBytes: 0});
    expect(expired.oldestExpiredExecutionAgeMs).toBeGreaterThanOrEqual(0n);
    await delay(25);
    expect(pair.right.diagnostics().gossip.oldestExpiredExecutionAgeMs).toBeGreaterThan(
      expired.oldestExpiredExecutionAgeMs
    );
    // A late verdict retires the message without applying it.
    exchange(pair.right, settleOnly, [verdict(message.handle, "accept"), verdict(message.handle, "reject")]);
    expect(pair.right.diagnostics().gossip).toMatchObject({
      executing: 0,
      expiredExecuting: 0,
      occupied: 0,
      oldestExpiredExecutionAgeMs: 0n,
      reportsAccepted: 0n,
      reportsAppliedAccept: 0n,
      reportsAppliedReject: 0n,
    });
    for (let i = 0; i < 1000 && pair.right.getMetrics().includes(expiredSample); i++) await delay(5);
    expect(pair.right.getMetrics()).toContain("lodestar_native_gossip_expired_executing 0\n");
  } finally {
    await Promise.all([pair.left.close(), pair.right.close()]);
  }
}, 20000);
