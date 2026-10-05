import {expect, it} from "vitest";
import bindings from "../src/index.js";
import type {NativeApplicationConfig} from "../src/network.js";
import {applicationConfig, configureChain, discoveryConfig, startRuntime, testChain} from "./utils/network.js";

const cases: readonly [string, (config: NativeApplicationConfig) => void, string][] = [
  [
    "missing BeaconConfig",
    (c) => {
      Reflect.deleteProperty(c, "beaconConfig");
    },
    "TypeMismatch",
  ],
  [
    "null BeaconConfig",
    (c) => {
      Object.assign(c, {beaconConfig: null});
    },
    "TypeMismatch",
  ],
  [
    "plain object instead of BeaconConfig",
    (c) => {
      Object.assign(c, {beaconConfig: {}});
    },
    "TypeMismatch",
  ],
  [
    "forged BeaconConfig instance",
    (c) => {
      Object.assign(c, {beaconConfig: Object.create(bindings.BeaconConfig.prototype)});
    },
    "TypeMismatch",
  ],
  [
    "target without peer headroom",
    (c) => {
      c.resources.targetPeers = c.resources.maxPeers;
    },
    "InvalidOptions",
  ],
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
    "IPv4 bytes for IPv6 endpoint",
    (c) => {
      Object.assign(c.bind, {family: 6});
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
    "mapped IPv6 listener",
    (c) => {
      c.bind = {address: Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1), family: 6, port: 0};
    },
    "InvalidNetworkConfig",
  ],
  [
    "mapped IPv6 dual listener",
    (c) => {
      c.bind = [
        {address: Uint8Array.of(127, 0, 0, 1), family: 4, port: 0},
        {address: Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1), family: 6, port: 0},
      ];
    },
    "InvalidNetworkConfig",
  ],
  [
    "mapped IPv6 discovery listener",
    (c) => {
      c.discovery = {
        ...discoveryConfig().discovery,
        bind: {address: Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1), family: 6, port: 0},
      };
    },
    "InvalidNetworkConfig",
  ],
  [
    "mapped IPv6 advertisement with IPv6 listeners",
    (c) => {
      const bind = {
        address: Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1),
        family: 6 as const,
        port: 0,
      };
      c.bind = bind;
      c.discovery = {
        ...discoveryConfig().discovery,
        bind,
        fixed: {
          ip6: Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1),
          quic6: 9001,
          udp6: 9000,
        },
      };
    },
    "InvalidNetworkConfig",
  ],
  [
    "unsafe numeric port",
    (c) => {
      Object.assign(c.bind, {port: Number.MAX_SAFE_INTEGER + 1});
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
    "custody count over local limit",
    (c) => {
      c.local.metadata.custodyGroupCount = 129n;
    },
    "InvalidCustodyCount",
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
      c.discovery = {...discoveryConfig().discovery, bootstrapEnrs: Array.from({length: 65}, () => Uint8Array.of(1))};
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
  const config = applicationConfig();
  mutate(config);
  expect(() => startRuntime(config, () => undefined)).toThrow(code);
});

it("rejects a noncanonical bootstrap encoding during ordinary owner startup", async () => {
  const config = discoveryConfig();
  if (!config.discovery) throw new Error("Missing discovery config");
  config.discovery.bootstrapEnrs = [Uint8Array.of(0xf8, 0x00)];
  expect(() => startRuntime(config, () => undefined)).toThrow("InvalidRecord");
});

it("accepts explicit host wire policy and zero IDONTWANT threshold", async () => {
  const config = applicationConfig();
  Object.assign(config.gossipPolicy, {idontwantMinDataSize: 0, iwantFollowupMs: 12000n});
  const runtime = startRuntime(config, () => undefined);
  try {
    await runtime.identity;
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
  const config = applicationConfig();
  Object.assign(config.gossipPolicy, fields);
  for (const [key, value] of Object.entries(fields))
    if (value === undefined) Reflect.deleteProperty(config.gossipPolicy, key);
  expect(() => startRuntime(config, () => undefined)).toThrow(code);
});

it.each([
  "requestForks",
  "forkSchedule",
  "topicPolicy",
  "requestPolicy",
  "capabilities",
])("rejects independent chain input %s", (field) => {
  const config = applicationConfig();
  Reflect.set(config, field, {});
  expect(() => startRuntime(config, () => undefined)).toThrow("InvalidNetworkConfig");
});

it.each([0, 129])("rejects chain custody group bound %s", (groups) => {
  const config = applicationConfig();
  configureChain(config, {NUMBER_OF_CUSTODY_GROUPS: groups});
  expect(() => startRuntime(config, () => undefined)).toThrow("InvalidNetworkChain");
});

it.each([
  0,
  1,
  1_000_000,
  Number.MAX_SAFE_INTEGER,
])("rejects unsupported fork at epoch %s before owner allocation", (epoch) => {
  const config = applicationConfig();
  configureChain(config, {ELECTRA_FORK_EPOCH: 0, FULU_FORK_EPOCH: 0, GLOAS_FORK_EPOCH: epoch});
  expect(() => startRuntime(config)).toThrow("UnsupportedNetworkFork");
});

it("derives the Fulu availability requirement from its BeaconConfig", () => {
  const config = applicationConfig();
  configureChain(config, {ELECTRA_FORK_EPOCH: 0, FULU_FORK_EPOCH: 0});
  expect(() => startRuntime(config, () => undefined)).toThrow("MissingAvailability");
});

it("selects its BeaconConfig independently of later configurations", async () => {
  const config = applicationConfig();
  const other = applicationConfig();
  configureChain(other, {ELECTRA_FORK_EPOCH: 0, FULU_FORK_EPOCH: 0});
  expect(() => startRuntime(other)).toThrow("MissingAvailability");
  const runtime = startRuntime(config);
  try {
    expect(runtime.state).toBe("running");
  } finally {
    await runtime.close();
  }
});

it("copies the genesis root from its BeaconConfig", async () => {
  const config = applicationConfig();
  const root = new Uint8Array(32).fill(42);
  config.beaconConfig = new bindings.BeaconConfig(testChain, root);
  const runtime = startRuntime(config);
  try {
    config.beaconConfig = applicationConfig().beaconConfig;
    root.fill(0);
    global.gc?.();
    expect((await runtime.getRememberedPeers()).genesisValidatorsRoot).toEqual(new Uint8Array(32).fill(42));
  } finally {
    await runtime.close();
  }
});

it.each([
  [false, null],
  [true, null],
  [true, 1n],
] as const)("validates startup custody with unscheduled Fulu=%s, custody=%s", async (unscheduled, custody) => {
  const config = applicationConfig();
  if (unscheduled) configureChain(config, {BLOB_SCHEDULE: [], FULU_FORK_EPOCH: Infinity});
  Reflect.set(config.local.metadata, "custodyGroupCount", custody);
  if (custody === null) {
    expect(() => startRuntime(config)).toThrow("MissingCustodyAdvertisement");
    return;
  }
  const runtime = startRuntime(config);
  try {
    expect(runtime.identity.metadata.custodyGroupCount).toBe(1n);
  } finally {
    await runtime.close();
  }
});
