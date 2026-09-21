import {setTimeout as delay} from "node:timers/promises";
import {expect, test} from "vitest";
import type {
  NativeGossipDependencyCheck,
  NativeGossipMessage,
  NativeNetworkApplicationRuntime,
} from "../src/network.js";
import {applicationConfig, localIntent, startRuntime, subscriptions, topicName} from "./utils/network.js";
import {incomingPair} from "./utils/network-incoming.js";

const BLOCK = topicName();
const ATTESTATION = topicName("beacon_attestation_0");

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

test("processor commands validate credits, roots and generation-bound handles", async () => {
  const config = applicationConfig();
  const runtime = startRuntime(config, () => undefined);
  try {
    await runtime.identity;
    await runtime.applyIntent(localIntent(config), config.initialSlot);
    expect(() => runtime.drainGossip({bytes: 1, items: 65, ordinary: true})).toThrow("InvalidNetworkInteger");
    expect(() => runtime.drainGossip({bytes: 16 * 1024 * 1024 + 1, items: 1, ordinary: true})).toThrow(
      "InvalidNetworkInteger"
    );
    expect(runtime.drainGossip({bytes: 0, items: 0, ordinary: false}).messages).toEqual([]);
    expect(() => runtime.notifyGossipBlock(new Uint8Array(31))).toThrow();
    expect(() => runtime.trackGossipSearch(new Uint8Array(33), null)).toThrow();
    expect(() => runtime.trackGossipSearch(new Uint8Array(32), "not-a-peer")).toThrow();
    const handle = {generation: 1n, index: 0};
    expect(runtime.classifyGossip(handle, true)).toBe(false);
    expect(runtime.classifyGossip({...handle}, false)).toBe(false);
    expect(() => runtime.classifyGossip({...handle, generation: 0n}, true)).toThrow("InvalidGossipHandle");
    expect(runtime.trackGossipSearch(new Uint8Array(32), null)).toBe(true);
    expect(runtime.trackGossipSearch(new Uint8Array(32), null)).toBe(false);
  } finally {
    await runtime.close();
  }
});

async function checks(runtime: NativeNetworkApplicationRuntime, count: number) {
  const result: NativeGossipDependencyCheck[] = [];
  for (let i = 0; i < 1000 && result.length < count; i++) {
    result.push(...runtime.drainGossipChecks());
    if (result.length < count) await delay(5);
  }
  expect(result).toHaveLength(count);
  return result;
}

test("native processor retains dependencies, protects blocks, batches ready work and bounds future slots", async () => {
  const pair = await incomingPair(undefined, undefined, undefined, (left, right) => {
    for (const config of [left, right]) {
      config.gossipPolicy.processor = Array.from({length: 13}, (_, kind) => ({
        bytes: (kind === 0 || kind === 12 ? 16 : kind === 4 ? 4 : 1) * 1024 * 1024,
        items: 8,
      }));
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
    for (const signature of [1, 2]) {
      data[132] = signature;
      await pair.left.publishGossip(ATTESTATION, data);
    }
    const waiting = await checks(pair.right, 2);
    for (const check of waiting) {
      expect(check.root).toEqual(root);
      expect(pair.right.classifyGossip(check.handle, false)).toBe(true);
    }
    expect(pair.right.diagnostics().gossip).toMatchObject({messagesCopied: 0n, payloadBytes: 458, waiting: 2});
    const blockBytes = new Uint8Array(4000);
    new DataView(blockBytes.buffer).setBigUint64(100, pair.rightConfig.initialSlot, true);
    await pair.left.publishGossip(BLOCK, blockBytes);
    for (const check of await checks(pair.right, 1)) expect(pair.right.classifyGossip(check.handle, false)).toBe(true);
    let block;
    for (let i = 0; i < 1000; i++) {
      const batch = pair.right.drainGossip({bytes: 4096, items: 1, kind: "beacon_block", ordinary: false});
      if (batch.messages.length) {
        block = batch.messages[0];
        break;
      }
      await delay(5);
    }
    expect(block?.topic).toBe(BLOCK);
    if (!block) throw Error("Block dispatch deadline");
    expect(pair.right.reportGossip(block.handle, "accept")).toBe(true);
    pair.right.notifyGossipBlock(root);
    for (const check of await checks(pair.right, 2)) expect(pair.right.classifyGossip(check.handle, true)).toBe(true);
    await delay(50);
    const batch = pair.right.drainGossip({bytes: 1024, items: 64, kind: "beacon_attestation", ordinary: true});
    expect(batch.grouped).toBe(true);
    expect(batch.messages).toHaveLength(2);
    expect(batch.messages.map((message) => message.attestationData)).toEqual([
      Buffer.from(data.subarray(4, 132)).toString("base64"),
      Buffer.from(data.subarray(4, 132)).toString("base64"),
    ]);
    for (const message of batch.messages) expect(pair.right.reportGossip(message.handle, "ignore")).toBe(true);
    view.setBigUint64(4, 999999999n, true);
    await pair.left.publishGossip(ATTESTATION, data);
    for (let i = 0; i < 1000 && pair.right.diagnostics().gossip.slotRefusals === 0n; i++) await delay(5);
    expect(pair.right.diagnostics().gossip).toMatchObject({checking: 0, executing: 0, slotRefusals: 1n, waiting: 0});
  } finally {
    await Promise.allSettled([pair.left.close(), pair.right.close()]);
  }
}, 30000);

test("expired validation execution remains visible until late host completion", async () => {
  const pair = await incomingPair(undefined, undefined, undefined, (left, right) => {
    for (const config of [left, right]) {
      config.gossipPolicy.processor = Array.from({length: 13}, (_, kind) => ({
        bytes: (kind === 0 || kind === 12 ? 16 : kind === 4 ? 4 : 1) * 1024 * 1024,
        items: 8,
      }));
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
    for (const check of await checks(pair.right, 1)) expect(pair.right.classifyGossip(check.handle, true)).toBe(true);
    let message: NativeGossipMessage | undefined;
    for (let i = 0; i < 1000 && !message; i++) {
      message = pair.right.drainGossip({bytes: 4096, items: 1, kind: "beacon_block", ordinary: true}).messages[0];
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
    expect(pair.right.reportGossip(message.handle, "accept")).toBe(false);
    expect(pair.right.reportGossip(message.handle, "reject")).toBe(false);
    expect(pair.right.diagnostics().gossip).toMatchObject({
      executing: 0,
      expiredExecuting: 0,
      occupied: 0,
      oldestExpiredExecutionAgeMs: 0n,
      reportsAppliedAccept: 0n,
      reportsAppliedReject: 0n,
    });
    for (let i = 0; i < 1000 && pair.right.getMetrics().includes(expiredSample); i++) await delay(5);
    expect(pair.right.getMetrics()).toContain("lodestar_native_gossip_expired_executing 0\n");
    expect(pair.right.getMetrics()).toContain("lodestar_native_gossip_oldest_expired_execution_age_seconds 0\n");
  } finally {
    await Promise.all([pair.left.close(), pair.right.close()]);
  }
}, 20000);
