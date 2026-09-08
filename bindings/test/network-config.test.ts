import {expect, it} from "vitest";
import bindings from "../src/bindings.js";
import {type NativeRuntimeConfig, createNativeNetworkRuntime} from "../src/network.js";
import {discoveryConfig, networkConfig} from "./utils/network.js";

const cases: readonly [string, (config: NativeRuntimeConfig) => void, string][] = [
  [
    "unknown profile",
    (c) => {
      Object.assign(c, {profile: "unknown"});
    },
    "InvalidNetworkConfig",
  ],
  [
    "nonobject policy",
    (c) => {
      Object.assign(c, {gossipPolicy: null});
    },
    "InvalidNetworkConfig",
  ],
  [
    "array policy",
    (c) => {
      Object.assign(c, {gossipPolicy: []});
    },
    "InvalidNetworkConfig",
  ],
  [
    "nonboolean schedule",
    (c) => {
      Object.assign(c.forkSchedule, {fuluScheduled: 1});
    },
    "InvalidNetworkConfig",
  ],
  [
    "wrong byte array type",
    (c) => {
      Object.assign(c, {identitySecretKey: new Uint16Array(32)});
    },
    "InvalidNetworkBytes",
  ],
  [
    "short status root",
    (c) => {
      c.local.status.headRoot = new Uint8Array(31);
    },
    "InvalidNetworkBytes",
  ],
  [
    "short phase0 digest",
    (c) => {
      c.gossipPolicy.phase0Digest = new Uint8Array(3);
    },
    "InvalidNetworkBytes",
  ],
  [
    "IPv4 bytes for IPv6 endpoint",
    (c) => {
      c.bind.family = 6;
    },
    "InvalidNetworkBytes",
  ],
  [
    "unsupported endpoint family",
    (c) => {
      Object.assign(c.bind, {family: 5});
    },
    "InvalidNetworkConfig",
  ],
  [
    "unsafe numeric port",
    (c) => {
      c.bind.port = Number.MAX_SAFE_INTEGER + 1;
    },
    "InvalidNetworkInteger",
  ],
  [
    "Number instead of BigInt",
    (c) => {
      Object.assign(c, {initialSlot: 100});
    },
    "InvalidNetworkInteger",
  ],
  [
    "NaN gossip factor",
    (c) => {
      c.gossipPolicy.gossipFactor = Number.NaN;
    },
    "InvalidNetworkConfig",
  ],
  [
    "invalid score decay",
    (c) => {
      c.gossipPolicy.score.behaviourDecay = 1.1;
    },
    "InvalidNetworkConfig",
  ],
  [
    "zero heartbeat",
    (c) => {
      c.gossipPolicy.heartbeatIntervalMs = 0n;
    },
    "InvalidNetworkConfig",
  ],
  [
    "oversized duration",
    (c) => {
      c.gossipPolicy.txTimeoutMs = 86400001n;
    },
    "InvalidNetworkConfig",
  ],
  [
    "unsupported fork",
    (c) => {
      Object.assign(c.local.fork, {fork: "heze"});
    },
    "InvalidNetworkConfig",
  ],
  [
    "mismatched fork digest",
    (c) => {
      c.local.fork.digest[0] = 99;
    },
    "InvalidNetworkConfig",
  ],
  [
    "zero custody groups",
    (c) => {
      c.local.fork.custodyGroups = 0;
    },
    "InvalidNetworkConfig",
  ],
  [
    "custody count over local limit",
    (c) => {
      c.local.metadata.custodyGroupCount = 2n;
    },
    "InvalidNetworkConfig",
  ],
  [
    "missing Fulu availability",
    (c) => {
      c.local.fork.fork = "fulu";
      c.local.metadata.custodyGroupCount = 1n;
    },
    "InvalidNetworkConfig",
  ],
  [
    "oversized fork table",
    (c) => {
      c.requestForks = Array.from({length: 65}, () => c.requestForks[0]);
    },
    "InvalidNetworkConfig",
  ],
  [
    "nonarray fork table",
    (c) => {
      Object.assign(c, {requestForks: {}});
    },
    "InvalidNetworkConfig",
  ],
  [
    "oversized IP allowlist",
    (c) => {
      c.gossipPolicy.ipAllowlist = Array.from({length: 33}, () => new Uint8Array(16));
    },
    "InvalidNetworkConfig",
  ],
  [
    "short allowlist address",
    (c) => {
      c.gossipPolicy.ipAllowlist = [new Uint8Array(4)];
    },
    "InvalidNetworkBytes",
  ],
  [
    "too many bootstraps",
    (c) => {
      c.discovery = {...discoveryConfig().discovery, bootstrapEnrs: Array.from({length: 17}, () => Uint8Array.of(1))};
    },
    "InvalidNetworkConfig",
  ],
  [
    "oversized bootstrap",
    (c) => {
      c.discovery = {...discoveryConfig().discovery, bootstrapEnrs: [new Uint8Array(301)]};
    },
    "InvalidNetworkBytes",
  ],
  [
    "empty bootstrap",
    (c) => {
      c.discovery = {...discoveryConfig().discovery, bootstrapEnrs: [new Uint8Array(0)]};
    },
    "InvalidNetworkBytes",
  ],
];

it.each(cases)("rejects %s before acquiring native thread or socket ownership", (_name, mutate, code) => {
  const config = networkConfig();
  mutate(config);
  const before: unknown = typeof bindings.networkTestStats === "function" ? bindings.networkTestStats() : null;
  expect(() => createNativeNetworkRuntime(config, () => undefined)).toThrow(code);
  if (before) expect(bindings.networkTestStats()).toEqual(before);
});

it("rejects a noncanonical bootstrap encoding during ordinary owner startup", async () => {
  const config = discoveryConfig();
  if (!config.discovery) throw new Error("Missing discovery config");
  config.discovery.bootstrapEnrs = [Uint8Array.of(0xf8, 0x00)];
  const runtime = createNativeNetworkRuntime(config, () => undefined);
  await expect(runtime.ready).rejects.toThrow("InvalidRecord");
  expect(await runtime.close()).toEqual({reason: "failed"});
  expect(runtime.diagnostics().terminalErrorCode).toBe("InvalidRecord");
});

it("accepts explicit host wire policy and zero IDONTWANT threshold", async () => {
  const config = networkConfig();
  Object.assign(config.gossipPolicy, {idontwantMinDataSize: 0, iwantFollowupMs: 12000n});
  const runtime = createNativeNetworkRuntime(config, () => undefined);
  try {
    await runtime.ready;
  } finally {
    await runtime.close();
  }
});

it.each([
  ["missing interval", {iwantFollowupMs: undefined}, "InvalidNetworkInteger"],
  ["missing threshold", {idontwantMinDataSize: undefined}, "InvalidNetworkInteger"],
  ["unknown wire field", {iwantDeadline: 12000n}, "InvalidNetworkConfig"],
  ["numeric interval", {iwantFollowupMs: 12000}, "InvalidNetworkInteger"],
  ["zero interval", {iwantFollowupMs: 0n}, "InvalidNetworkConfig"],
  ["large interval", {iwantFollowupMs: 86400001n}, "InvalidNetworkConfig"],
  ["negative interval", {iwantFollowupMs: -1n}, "InvalidNetworkInteger"],
  ["bigint threshold", {idontwantMinDataSize: 128n}, "InvalidNetworkInteger"],
  ["fractional threshold", {idontwantMinDataSize: 1.5}, "InvalidNetworkInteger"],
  ["unsafe threshold", {idontwantMinDataSize: Number.MAX_SAFE_INTEGER + 1}, "InvalidNetworkInteger"],
  ["negative threshold", {idontwantMinDataSize: -1}, "InvalidNetworkInteger"],
  ["large threshold", {idontwantMinDataSize: 20 * 1024 * 1024}, "InvalidNetworkInteger"],
] as const)("rejects %s wire policy before startup", (_name, fields, code) => {
  const config = networkConfig();
  Object.assign(config.gossipPolicy, fields);
  for (const [key, value] of Object.entries(fields))
    if (value === undefined) Reflect.deleteProperty(config.gossipPolicy, key);
  const before: unknown = typeof bindings.networkTestStats === "function" ? bindings.networkTestStats() : null;
  expect(() => createNativeNetworkRuntime(config, () => undefined)).toThrow(code);
  if (before) expect(bindings.networkTestStats()).toEqual(before);
});
