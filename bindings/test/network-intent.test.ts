// biome-ignore-all lint/style/useNamingConvention: Subscription masks use protocol topic names.
import {expect, test} from "vitest";
import type {NativeSubscriptionSet} from "../src/network.js";
import {
  applicationConfig,
  configureChain,
  discoveryConfig,
  localIntent,
  requestForks,
  startRuntime,
  subscriptions,
  topicKinds,
  topicName,
} from "./utils/network.js";

test.each(topicKinds)("startup requires a score policy for %s", (kind) => {
  const config = applicationConfig();
  Reflect.deleteProperty(config.gossipPolicy.score.topics, kind);
  expect(() => startRuntime(config)).toThrow("InvalidNetworkConfig");
});

test("startup rejects an invalid kind score policy", () => {
  const config = applicationConfig();
  config.gossipPolicy.score.topics.beacon_attestation.weight = Number.NaN;
  expect(() => startRuntime(config)).toThrow("InvalidNetworkConfig");
});

test("compact subscriptions reject invalid boundaries and masks atomically", async () => {
  const config = applicationConfig();
  const runtime = startRuntime(config);
  const intent = localIntent(config);
  intent.subscriptions = subscriptions(topicName());
  try {
    await runtime.applyIntent(intent, config.initialSlot);
    const invalid: {sets: NativeSubscriptionSet[]; error: string}[] = [
      {error: "DuplicateBoundary", sets: [intent.subscriptions[0], intent.subscriptions[0]]},
      {error: "InvalidTopic", sets: [{digest: new Uint8Array(4).fill(255), subnets: {}}]},
      {error: "InvalidTopic", sets: [{digest: requestForks[0].digest, subnets: {beacon_block: Uint8Array.of(2)}}]},
      {
        error: "InvalidNetworkBytes",
        sets: [{digest: requestForks[0].digest, subnets: {beacon_attestation: new Uint8Array(9)}}],
      },
      {
        error: "InvalidTopic",
        sets: [{digest: requestForks[0].digest, subnets: {data_column_sidecar: Uint8Array.of(0)}}],
      },
    ];
    for (const {sets, error} of invalid) {
      const next = structuredClone(intent);
      next.subscriptions = sets;
      next.update.local.status.headSlot++;
      await expect(runtime.applyIntent(next, config.initialSlot + 1n)).rejects.toThrow(error);
      expect(runtime.diagnostics().currentSlot).toBe(config.initialSlot);
      expect(
        (await runtime.getGossipDiagnostics()).topics.filter((topic) => topic.subscribed).map((topic) => topic.topic)
      ).toEqual([topicName()]);
      expect((await runtime.applyIntent(intent, config.initialSlot)).changed).toBe(false);
    }
  } finally {
    await runtime.close();
  }
});

test("demand validates fields and target array bounds, offsets and zero padding atomically", async () => {
  const config = applicationConfig();
  const runtime = startRuntime(config);
  const intent = localIntent(config);
  try {
    intent.demand.attnets[0] = 3;
    const backing = Uint16Array.of(65535, 0, 0, 65535);
    intent.demand.groupTargets = backing.subarray(1, 3);
    intent.demand.custodyGroupTargets = new Uint16Array(0);
    await runtime.applyIntent(intent, config.initialSlot);
    const same = structuredClone(intent);
    same.demand.groupTargets = new Uint16Array(128);
    same.demand.custodyGroupTargets = new Uint16Array(128);
    expect((await runtime.applyIntent(same, config.initialSlot)).changed).toBe(false);
    const expiring = {...same, demand: {...same.demand, expiresAtSlot: config.initialSlot + 2n}};
    await expect(runtime.applyIntent(expiring, config.initialSlot + 1n)).rejects.toThrow("InvalidNetworkConfig");
    expect(runtime.diagnostics().currentSlot).toBe(config.initialSlot);
    expect((await runtime.applyIntent(same, config.initialSlot)).changed).toBe(false);
    for (const targets of [new Uint16Array(129), Uint16Array.of(config.resources.maxPeers + 1)]) {
      intent.demand.groupTargets = targets;
      await expect(runtime.applyIntent(intent, config.initialSlot)).rejects.toThrow(
        targets.length > 128 ? "InvalidNetworkBytes" : "InvalidNetworkInteger"
      );
    }
    const detached = new Uint16Array(128);
    structuredClone(detached, {transfer: [detached.buffer]});
    intent.demand.groupTargets = detached;
    await expect(runtime.applyIntent(intent, config.initialSlot)).rejects.toThrow("InvalidNetworkBytes");
    const wrongType = {...same, demand: {...same.demand, groupTargets: new Uint8Array(128)}};
    // @ts-expect-error Exercise the native typed-array type guard.
    await expect(runtime.applyIntent(wrongType, config.initialSlot)).rejects.toThrow("InvalidNetworkBytes");
    expect((await runtime.applyIntent(same, config.initialSlot)).changed).toBe(false);
  } finally {
    await runtime.close();
  }
});

test("compact intent copies masks before later getters mutate their backing", async () => {
  const config = applicationConfig();
  const runtime = startRuntime(config);
  const intent = localIntent(config);
  const mask = Uint8Array.of(1);
  intent.subscriptions = [
    {
      digest: requestForks[0].digest,
      subnets: {
        get beacon_attestation() {
          structuredClone(mask, {transfer: [mask.buffer]});
          return new Uint8Array(0);
        },
        beacon_block: mask,
      },
    },
  ];
  try {
    await runtime.applyIntent(intent, config.initialSlot);
    expect(
      (await runtime.getGossipDiagnostics()).topics.some((topic) => topic.subscribed && topic.topic === topicName())
    ).toBe(true);
  } finally {
    await runtime.close();
  }
});

test("closing from a mask getter rejects the prepared command and retires its storage", async () => {
  const config = applicationConfig();
  const runtime = startRuntime(config);
  const intent = localIntent(config);
  intent.subscriptions = [
    {
      digest: requestForks[0].digest,
      subnets: {
        get beacon_block() {
          void runtime.close();
          return Uint8Array.of(1);
        },
      },
    },
  ];
  try {
    await expect(runtime.applyIntent(intent, config.initialSlot)).rejects.toThrow("NetworkClosed");
    await runtime.closed;
    expect(runtime.diagnostics().preparingPins).toBe(0);
  } finally {
    await runtime.close();
  }
});

test("bounded generated masks agree with the configured subnet limits", async () => {
  const config = applicationConfig();
  const runtime = startRuntime(config);
  const intent = localIntent(config);
  let seed = 0x12345678;
  const random = (): number => {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    return seed;
  };
  try {
    for (let i = 0; i < 128; i++) {
      const kind = i % 2 ? "sync_committee" : "beacon_attestation";
      const count = kind === "sync_committee" ? 4 : 64;
      const maxBytes = Math.ceil(count / 8);
      const mask = Uint8Array.from({length: random() % (maxBytes + 2)}, () => random() & 255);
      const invalidBit = Array.from(mask).some((byte, index) => {
        for (let bit = 0; bit < 8; bit++) if (byte & (1 << bit) && index * 8 + bit >= count) return true;
        return false;
      });
      intent.subscriptions = [{digest: requestForks[0].digest, subnets: {[kind]: mask}}];
      if (mask.length > maxBytes) {
        await expect(runtime.applyIntent(intent, config.initialSlot)).rejects.toThrow("InvalidNetworkBytes");
      } else if (invalidBit) {
        await expect(runtime.applyIntent(intent, config.initialSlot)).rejects.toThrow("InvalidTopic");
      } else {
        await runtime.applyIntent(intent, config.initialSlot);
        const names: string[] = [];
        for (let subnet = 0; subnet < count; subnet++)
          if (mask[subnet >> 3] & (1 << (subnet % 8))) names.push(topicName(`${kind}_${subnet}`));
        expect(
          (await runtime.getGossipDiagnostics()).topics
            .filter((row) => row.subscribed)
            .map((row) => row.topic)
            .sort()
        ).toEqual(names.sort());
      }
    }
    expect(runtime.diagnostics().preparingPins).toBe(0);
  } finally {
    await runtime.close();
  }
});

test("three-boundary overlap refuses capacity without partially changing subscriptions", async () => {
  const config = applicationConfig();
  const chain = configureChain({
    BLOB_SCHEDULE: [
      {EPOCH: 2001, MAX_BLOBS_PER_BLOCK: 33},
      {EPOCH: 2002, MAX_BLOBS_PER_BLOCK: 66},
    ],
  });
  const sets: NativeSubscriptionSet[] = chain.forkBoundariesAscendingEpochOrder
    .filter((boundary) => boundary.epoch >= 2000 && boundary.epoch < Infinity)
    .map((boundary) => ({
      digest: chain.forkBoundary2ForkDigest(boundary),
      subnets: {
        beacon_attestation: new Uint8Array(8).fill(255),
        data_column_sidecar: new Uint8Array(16).fill(255),
      },
    }));
  expect(sets).toHaveLength(3);
  const runtime = startRuntime(config);
  const intent = localIntent(config);
  intent.subscriptions = sets.slice(0, 2);
  try {
    await runtime.applyIntent(intent, config.initialSlot);
    const before = (await runtime.getGossipDiagnostics()).topics.map(({topic, subscribed}) => ({
      subscribed,
      topic,
    }));
    intent.subscriptions = sets;
    await expect(runtime.applyIntent(intent, config.initialSlot + 1n)).rejects.toThrow("TopicCapacity");
    expect(runtime.diagnostics().currentSlot).toBe(config.initialSlot);
    intent.subscriptions = sets.slice(0, 2);
    expect((await runtime.applyIntent(intent, config.initialSlot)).changed).toBe(false);
    expect((await runtime.getGossipDiagnostics()).topics.map(({topic, subscribed}) => ({subscribed, topic}))).toEqual(
      before
    );
    expect(runtime.diagnostics().preparingPins).toBe(0);
  } finally {
    await runtime.close();
  }
});

test("host intents preserve native advertisement and reject endpoint overrides", async () => {
  const config = discoveryConfig();
  const runtime = startRuntime(config);
  try {
    const before = (await runtime.getIdentity()).localEnr;
    config.discovery.advertisement.ip4 = Uint8Array.of(192, 0, 2, 1);
    config.discovery.fixed.ip4 = Uint8Array.of(192, 0, 2, 1);
    const intent = localIntent(config);
    await runtime.applyIntent(intent, config.initialSlot);
    expect((await runtime.getIdentity()).localEnr).toEqual(before);
    Reflect.set(intent.update, "endpoints", config.discovery.advertisement);
    await expect(runtime.applyIntent(intent, config.initialSlot)).rejects.toThrow("InvalidNetworkConfig");
    expect((await runtime.getIdentity()).localEnr).toEqual(before);
  } finally {
    await runtime.close();
  }
});
