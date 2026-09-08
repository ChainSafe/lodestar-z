import {expect, it} from "vitest";
import bindings from "../src/bindings.js";
import {type NativeRuntimeConfig, createNativeNetworkRuntime} from "../src/network.js";
import {discoveryConfig, networkConfig, topicBoundary} from "./utils/network.js";

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

it("accepts a complete configured topic namespace at ordinary startup", async () => {
  const config = networkConfig();
  Object.assign(config, {topicPolicy: [topicBoundary()]});
  const runtime = createNativeNetworkRuntime(config, () => undefined);
  try {
    await runtime.ready;
  } finally {
    await runtime.close();
  }
});

it("requires an explicit nullable topic namespace", () => {
  const config = networkConfig();
  Reflect.deleteProperty(config, "topicPolicy");
  expect(() => createNativeNetworkRuntime(config, () => undefined)).toThrow("InvalidNetworkConfig");
});

const namespaceCases: readonly [string, (boundary: ReturnType<typeof topicBoundary>) => unknown, string][] = [
  ["empty array", () => [], "InvalidNetworkConfig"],
  ["nonarray", () => ({}), "InvalidNetworkConfig"],
  ["sparse array", () => new Array(1), "InvalidNetworkConfig"],
  ["65 boundaries", (b) => Array.from({length: 65}, () => b), "InvalidNetworkConfig"],
  ["duplicate digest", (b) => [b, b], "InvalidNetworkConfig"],
  ["short digest", (b) => [{...b, digest: new Uint8Array(3)}], "InvalidNetworkBytes"],
  ["wide digest elements", (b) => [{...b, digest: new Uint16Array(4)}], "InvalidNetworkBytes"],
  ["missing boundary field", (b) => [{rules: b.rules}], "InvalidNetworkConfig"],
  ["unknown boundary field", (b) => [{...b, typo: 1}], "InvalidNetworkConfig"],
  [
    "missing kind",
    (b) => {
      Reflect.deleteProperty(b.rules, "voluntary_exit");
      return [b];
    },
    "InvalidNetworkConfig",
  ],
  [
    "unknown kind",
    (b) => [{...b, rules: {...b.rules, unknown: {count: 0, sszMax: 0, sszMin: 0}}}],
    "InvalidNetworkConfig",
  ],
  [
    "missing rule field",
    (b) => {
      Reflect.deleteProperty(b.rules.beacon_block, "sszMin");
      return [b];
    },
    "InvalidNetworkConfig",
  ],
  [
    "unknown rule field",
    (b) => {
      Object.assign(b.rules.beacon_block, {min: 0});
      return [b];
    },
    "InvalidNetworkConfig",
  ],
  [
    "disabled nonzero bound",
    (b) => {
      b.rules.voluntary_exit.sszMax = 1;
      return [b];
    },
    "InvalidNetworkConfig",
  ],
  [
    "empty boundary",
    (b) => {
      for (const rule of Object.values(b.rules)) Object.assign(rule, {count: 0, sszMax: 0, sszMin: 0});
      return [b];
    },
    "InvalidNetworkConfig",
  ],
  [
    "singleton count",
    (b) => {
      b.rules.beacon_block.count = 2;
      return [b];
    },
    "InvalidNetworkConfig",
  ],
  [
    "attestation count",
    (b) => {
      b.rules.beacon_attestation.count = 65;
      return [b];
    },
    "InvalidNetworkConfig",
  ],
  [
    "sync count",
    (b) => {
      b.rules.sync_committee.count = 5;
      return [b];
    },
    "InvalidNetworkConfig",
  ],
  [
    "blob count",
    (b) => {
      b.rules.blob_sidecar.count = 129;
      return [b];
    },
    "InvalidNetworkConfig",
  ],
  [
    "column count",
    (b) => {
      b.rules.data_column_sidecar.count = 129;
      return [b];
    },
    "InvalidNetworkConfig",
  ],
  [
    "reversed bounds",
    (b) => {
      b.rules.beacon_block.sszMin = 21;
      return [b];
    },
    "InvalidNetworkConfig",
  ],
  [
    "global maximum",
    (b) => {
      b.rules.beacon_block.sszMax = 10485761;
      return [b];
    },
    "InvalidNetworkInteger",
  ],
];

it.each(namespaceCases)("rejects topic namespace %s before startup", (_label, mutate, expected) => {
  const config = networkConfig();
  Object.assign(config, {topicPolicy: mutate(topicBoundary())});
  expect(() => createNativeNetworkRuntime(config, () => undefined)).toThrow(expected);
});

it.each(["count", "sszMin", "sszMax"] as const)("rejects noninteger topic rule %s values", (key) => {
  for (const value of [-1, 0.5, Number.MAX_SAFE_INTEGER + 1, Number.NaN, Infinity, 1n]) {
    const config = networkConfig();
    const boundary = topicBoundary();
    Object.assign(boundary.rules.beacon_block, {[key]: value});
    config.topicPolicy = [boundary];
    expect(() => createNativeNetworkRuntime(config, () => undefined)).toThrow("InvalidNetworkInteger");
  }
});

it("accepts 64 unique topic boundaries and copies byte views", async () => {
  const config = networkConfig();
  config.topicPolicy = Array.from({length: 64}, (_, i) => {
    const b = topicBoundary();
    b.digest = Uint8Array.of(255, i, 2, 3, 4, 255).subarray(1, 5);
    return b;
  });
  const runtime = createNativeNetworkRuntime(config, () => undefined);
  for (const b of config.topicPolicy) b.digest.fill(0);
  try {
    await runtime.ready;
  } finally {
    await runtime.close();
  }
});

it("rejects sparse topic arrays even when inherited entries supply values", async () => {
  const config = networkConfig();
  const sparse = [topicBoundary()];
  const inherited: Record<number, ReturnType<typeof topicBoundary>> = Object.create(Array.prototype);
  inherited[0] = sparse[0];
  Reflect.deleteProperty(sparse, "0");
  Object.setPrototypeOf(sparse, inherited);
  config.topicPolicy = sparse;
  let runtime: ReturnType<typeof createNativeNetworkRuntime> | undefined;
  try {
    expect(() => {
      runtime = createNativeNetworkRuntime(config, () => undefined);
    }).toThrow("InvalidNetworkConfig");
  } finally {
    if (runtime) {
      await runtime.ready;
      await runtime.close();
    }
  }
});

it("requires explicit minimum sampling groups before owner startup", async () => {
  const config = networkConfig();
  Reflect.deleteProperty(config.local.fork, "minimumSamplingGroups");
  let runtime: ReturnType<typeof createNativeNetworkRuntime> | undefined;
  try {
    expect(() => {
      runtime = createNativeNetworkRuntime(config, () => undefined);
    }).toThrow("InvalidNetworkInteger");
  } finally {
    if (runtime) {
      await runtime.ready;
      await runtime.close();
    }
  }
});

it("accepts host minimum sampling groups at ordinary startup", async () => {
  const config = networkConfig();
  Object.assign(config.local.fork, {custodyGroups: 128, minimumSamplingGroups: 8});
  const runtime = createNativeNetworkRuntime(config, () => undefined);
  try {
    await runtime.ready;
  } finally {
    await runtime.close();
  }
});

it.each([
  undefined,
  null,
  "8",
  8n,
  -1,
  0.5,
  Number.NaN,
  Number.POSITIVE_INFINITY,
  Number.MAX_SAFE_INTEGER + 1,
  129,
])("rejects malformed minimum sampling groups %s", (value) => {
  const config = networkConfig();
  Object.assign(config.local.fork, {minimumSamplingGroups: value});
  expect(() => createNativeNetworkRuntime(config, () => undefined)).toThrow("InvalidNetworkInteger");
});

it("rejects minimum sampling groups above the active group bound", () => {
  const config = networkConfig();
  Object.assign(config.local.fork, {minimumSamplingGroups: 2});
  expect(() => createNativeNetworkRuntime(config, () => undefined)).toThrow("InvalidNetworkConfig");
});

it("rejects unknown fork context fields", () => {
  const config = networkConfig();
  Object.assign(config.local.fork, {samplingGroups: 0});
  expect(() => createNativeNetworkRuntime(config, () => undefined)).toThrow("InvalidNetworkConfig");
});
