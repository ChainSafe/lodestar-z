import {setTimeout as delay} from "node:timers/promises";
import {expect, test} from "vitest";
import bindings from "../src/bindings.js";
import {createNativeNetworkApplicationRuntime} from "../src/network.js";
import {applicationConfig} from "./utils/network.js";

test.each(["resources", "requestPolicy", "identify", "capabilities", "topicPolicy"])("rejects missing %s", (field) => {
  const config = applicationConfig();
  Reflect.deleteProperty(config, field);
  expect(() => createNativeNetworkApplicationRuntime(config, () => undefined)).toThrow();
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
  expect(() => createNativeNetworkApplicationRuntime(config, () => undefined)).toThrow();
});

test.each([
  (c: ReturnType<typeof applicationConfig>) => {
    Reflect.set(c.resources, "extra", 1);
  },
  (c: ReturnType<typeof applicationConfig>) => {
    c.capabilities.receive = [...c.capabilities.receive, c.capabilities.receive[0]];
  },
  (c: ReturnType<typeof applicationConfig>) => {
    Reflect.set(c.capabilities, "request", ["/unsupported"]);
  },
  (c: ReturnType<typeof applicationConfig>) => {
    c.capabilities.request = Array(2);
  },
  (c: ReturnType<typeof applicationConfig>) => {
    c.identify.agentVersion = "x".repeat(257);
  },
  (c: ReturnType<typeof applicationConfig>) => {
    c.identify.protocolVersion = "é".repeat(33);
  },
  (c: ReturnType<typeof applicationConfig>) => {
    c.requestPolicy.blobSchedule = [
      {maxBlobs: 6, startSlot: 0n},
      {maxBlobs: 1, startSlot: 0n},
    ];
  },
  (c: ReturnType<typeof applicationConfig>) => {
    c.requestPolicy.blobSchedule = Array(65);
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
    c.local.metadata.custodyGroupCount = null;
  },
])("rejects malformed complete application configuration %#", (mutate) => {
  const config = applicationConfig();
  mutate(config);
  expect(() => createNativeNetworkApplicationRuntime(config, () => undefined)).toThrow();
});

test("rejects insufficient fixed reservations before owner spawn", () => {
  const config = applicationConfig();
  config.resources.nativeBudgetBytes = 1;
  expect(() => createNativeNetworkApplicationRuntime(config, () => undefined)).toThrow("NetworkNativeBudgetExceeded");
  config.resources.nativeBudgetBytes = 80 * 1024 * 1024;
  config.resources.bridgeBudgetBytes = 1;
  expect(() => createNativeNetworkApplicationRuntime(config, () => undefined)).toThrow("NetworkBridgeBudgetExceeded");
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
    "ready_promise",
    "close_promise",
    "copy_error_ref",
    "requested_ref",
    "cancelled_ref",
    "failed_ref",
    "promise_holder",
    "entropy",
    "key",
    "core",
    "wake_attach",
    "spawn",
  ])("application acquisition prefix %s releases every owner", async (stage) => {
  bindings.networkTestFail(stage);
  expect(() => createNativeNetworkApplicationRuntime(applicationConfig(), () => undefined)).toThrow(
    "InjectedNetworkFailure"
  );
  for (let i = 0; i < 100; i++) {
    await delay(10);
    global.gc?.();
    if (bindings.networkTestStats().runtimes === 0) break;
  }
  expect(bindings.networkTestStats()).toEqual({notifications: 0, owners: 0, runtimes: 0});
});
