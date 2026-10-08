import {privateKeyFromRaw} from "@libp2p/crypto/keys";
import {peerIdFromPublicKey} from "@libp2p/peer-id";
import {expect, test} from "vitest";
import type {NativeRememberedPeer} from "../src/network.js";
import {applicationConfig, startRuntime, testChain} from "./utils/network.js";

test.each(["resources", "identify", "serveLightClients", "logLevel"])("rejects missing %s", (field) => {
  const config = applicationConfig();
  Reflect.deleteProperty(config, field);
  expect(() => startRuntime(config, () => undefined)).toThrow();
});

test.each([
  ["peerCapacity", 512],
  ["targetPeers", 256],
  ["maxPeers", 256],
  ["minOutbound", 256],
  ["outboundReserve", 512],
  ["connectionCapacity", 256],
  ["handshakingCapacity", 256],
  ["dialingCapacity", 64],
  ["receiveBudgetBytes", Number.MAX_SAFE_INTEGER],
  ["nativeBudgetBytes", 1024 ** 3],
  ["bridgeBudgetBytes", 1024 ** 3],
] as const)("rejects %s above its resource maximum", (field, maximum) => {
  const config = applicationConfig();
  config.resources[field] = maximum + 1;
  expect(() => startRuntime(config, () => undefined)).toThrow("InvalidNetworkInteger");
});

test.each([
  0,
  -1,
  1.5,
  Number.NaN,
  Number.POSITIVE_INFINITY,
  Number.MAX_SAFE_INTEGER + 1,
  1024 ** 3 + 1,
])("rejects native byte ceiling %s", (value) => {
  const config = applicationConfig();
  config.resources.nativeBudgetBytes = value;
  expect(() => startRuntime(config, () => undefined)).toThrow();
});

test.each([
  (c: ReturnType<typeof applicationConfig>) => {
    Reflect.set(c.resources, "extra", 1);
  },
  (c: ReturnType<typeof applicationConfig>) => {
    Reflect.set(c, "serveLightClients", 1);
  },
  (c: ReturnType<typeof applicationConfig>) => {
    Reflect.set(c, "logLevel", "trace");
  },
  (c: ReturnType<typeof applicationConfig>) => {
    c.identify.agentVersion = "x".repeat(257);
  },
  (c: ReturnType<typeof applicationConfig>) => {
    c.identify.protocolVersion = "é".repeat(33);
  },
  (c: ReturnType<typeof applicationConfig>) => {
    c.resources.maxPeers = 257;
  },
  (c: ReturnType<typeof applicationConfig>) => {
    c.resources.targetPeers = 13;
  },
  (c: ReturnType<typeof applicationConfig>) => {
    c.resources.connectionCapacity = 1;
  },
  (c: ReturnType<typeof applicationConfig>) => {
    Reflect.set(c.local.metadata, "custodyGroupCount", null);
  },
])("rejects malformed complete application configuration %#", (mutate) => {
  const config = applicationConfig();
  mutate(config);
  expect(() => startRuntime(config, () => undefined)).toThrow();
});

test.each(["native", "bridge"])("rejects insufficient %s reservation before owner spawn", (kind) => {
  const config = applicationConfig();
  if (kind === "native") config.resources.nativeBudgetBytes = 1;
  else config.resources.bridgeBudgetBytes = 1;
  expect(() => startRuntime(config)).toThrow(
    kind === "native" ? "NetworkNativeBudgetExceeded" : "NetworkBridgeBudgetExceeded"
  );
});

test.each([512, 513])("retained peer capacity %s respects the native gossip ceiling", async (capacity) => {
  const config = applicationConfig();
  config.resources.peerCapacity = capacity;
  if (capacity === 513) {
    expect(() => startRuntime(config)).toThrow("InvalidNetworkInteger");
    return;
  }
  const runtime = startRuntime(config);
  try {
    expect(runtime.limits.peerCapacity).toBe(512);
  } finally {
    await runtime.close();
  }
});

/** Replay dials the remembered endpoint, a closed loopback port. */
function rememberedPeer(tag: number, ageS: number, last = tag): NativeRememberedPeer {
  const secret = new Uint8Array(32);
  secret[31] = tag;
  return {
    endpoint: {address: Uint8Array.of(127, 0, 0, last), family: 4, port: 9},
    peerId: peerIdFromPublicKey(privateKeyFromRaw(secret).publicKey).toString(),
    qualifiedAtUnixS: Math.floor(Date.now() / 1000) - ageS,
  };
}

test("remembered peers return in the snapshot without expired or duplicate peers, until close", async () => {
  const config = applicationConfig();
  const kept = rememberedPeer(40, 60);
  const newer = rememberedPeer(41, 600, 1);
  config.rememberedPeers = {
    genesisValidatorsRoot: testChain.genesisValidatorsRoot,
    peers: [kept, rememberedPeer(41, 3600, 2), newer, rememberedPeer(42, 24 * 3600 + 60)],
  };
  const runtime = startRuntime(config);
  try {
    const snapshot = await runtime.getRememberedPeers();
    expect(snapshot.genesisValidatorsRoot).toEqual(testChain.genesisValidatorsRoot);
    expect(snapshot.ownerSequence).toBeTypeOf("bigint");
    const peers = new Map(snapshot.peers.map((peer) => [peer.peerId, peer]));
    expect(peers.size).toBe(2);
    expect(peers.get(kept.peerId)).toEqual(kept);
    expect(peers.get(newer.peerId)).toEqual(newer);
    const metrics = runtime.getMetrics();
    for (const [outcome, count] of [
      ["loaded", 2],
      ["expired", 1],
      ["duplicate", 1],
      ["invalid", 0],
    ] as const) {
      expect(metrics).toContain(`lodestar_peer_remembered_seeds_total{outcome="${outcome}"} ${count}\n`);
    }
  } finally {
    await runtime.close();
  }
  // The host takes its final snapshot before close, which refuses it.
  expect(() => runtime.getRememberedPeers()).toThrow("NetworkClosed");
});

test.each([null, undefined])("remembered peers may be %s", async (value) => {
  const config = applicationConfig();
  config.rememberedPeers = value;
  const runtime = startRuntime(config);
  try {
    expect(await runtime.getRememberedPeers()).toMatchObject({peers: []});
  } finally {
    await runtime.close();
  }
});

test.each([
  [
    "another network",
    "InvalidRememberedPeersNetwork",
    () => ({genesisValidatorsRoot: new Uint8Array(32).fill(1), peers: []}),
  ],
  [
    "257 peers",
    "InvalidNetworkConfig",
    () => ({
      genesisValidatorsRoot: testChain.genesisValidatorsRoot,
      peers: Array.from({length: 257}, () => rememberedPeer(1, 60)),
    }),
  ],
  [
    "a malformed identity",
    "InvalidNetworkPeerId",
    () => ({genesisValidatorsRoot: testChain.genesisValidatorsRoot, peers: [{...rememberedPeer(1, 60), peerId: "x"}]}),
  ],
  [
    "a zero port",
    "InvalidNetworkConfig",
    () => ({
      genesisValidatorsRoot: testChain.genesisValidatorsRoot,
      peers: [
        {...rememberedPeer(1, 60), endpoint: {address: Uint8Array.of(127, 0, 0, 1), family: 4 as const, port: 0}},
      ],
    }),
  ],
  [
    "an unspecified address",
    "InvalidNetworkConfig",
    () => ({
      genesisValidatorsRoot: testChain.genesisValidatorsRoot,
      peers: [{...rememberedPeer(1, 60), endpoint: {address: new Uint8Array(4), family: 4 as const, port: 9}}],
    }),
  ],
  [
    "a negative time",
    "InvalidNetworkInteger",
    () => ({
      genesisValidatorsRoot: testChain.genesisValidatorsRoot,
      peers: [{...rememberedPeer(1, 60), qualifiedAtUnixS: -1}],
    }),
  ],
  [
    "an extra field",
    "InvalidNetworkConfig",
    () => ({genesisValidatorsRoot: testChain.genesisValidatorsRoot, peers: [{...rememberedPeer(1, 60), enr: null}]}),
  ],
] as const)("rejects remembered peers with %s", (_, code, peers) => {
  const config = applicationConfig();
  Reflect.set(config, "rememberedPeers", peers());
  expect(() => startRuntime(config)).toThrow(code);
});
