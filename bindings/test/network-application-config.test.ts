import {setTimeout as delay} from "node:timers/promises";
import {expect, test} from "vitest";
import {applicationConfig, startRuntime} from "./utils/network.js";
import {networkBindings as bindings} from "./utils/network-bindings.js";

test.each(["resources", "identify", "serveLightClients"])("rejects missing %s", (field) => {
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
  ["dialingCapacity", 256],
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

test
  .skipIf(process.env.LODESTAR_Z_NETWORK_TEST_FAILURES !== "1")
  .each([
    "owner_alloc",
    "application_stores",
    "application_snapshot_0",
    "application_snapshot_1",
    "application_lane",
    "wake",
    "notify",
    "hook",
    "close_promise",
    "copy_error_ref",
    "requested_ref",
    "failed_ref",
    "promise_holder",
    "entropy",
    "key",
    "core",
    "wake_attach",
    "spawn",
  ])("application acquisition prefix %s releases every owner", async (stage) => {
  bindings.networkTestFail(stage);
  expect(() => startRuntime(applicationConfig(), () => undefined)).toThrow("InjectedNetworkFailure");
  for (let i = 0; i < 100; i++) {
    await delay(10);
    global.gc?.();
    if (bindings.networkTestStats().runtimes === 0) break;
  }
  expect(bindings.networkTestStats()).toEqual({notifications: 0, owners: 0, runtimes: 0});
});

test.each([512, 513])("retained peer capacity %s respects the native gossip ceiling", async (capacity) => {
  const config = applicationConfig();
  config.resources.peerCapacity = capacity;
  config.resources.nativeBudgetBytes = 128 * 1024 * 1024;
  if (capacity === 513) {
    expect(() => startRuntime(config)).toThrow("InvalidNetworkInteger");
    return;
  }
  const runtime = startRuntime(config);
  try {
    expect(runtime.diagnostics().resolvedCapacities).toMatchObject({gossipRetainedCapacity: 512, peerCapacity: 512});
  } finally {
    await runtime.close();
  }
});
