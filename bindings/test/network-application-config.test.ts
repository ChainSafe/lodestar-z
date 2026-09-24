import {expect, test} from "vitest";
import {applicationConfig, startRuntime} from "./utils/network.js";

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
    expect(runtime.diagnostics().resolvedCapacities).toMatchObject({gossipRetainedCapacity: 512, peerCapacity: 512});
  } finally {
    await runtime.close();
  }
});
