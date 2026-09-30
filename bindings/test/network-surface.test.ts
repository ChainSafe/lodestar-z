// The package's network entry, resolved through its exports map as a consumer resolves it.
import type {NativeHost, NativeNetwork} from "@chainsafe/lodestar-z/network";
import * as network from "@chainsafe/lodestar-z/network";
import {expect, test} from "vitest";

// @ts-expect-error The low-level runtime's types are not part of the package.
type Exchange = import("@chainsafe/lodestar-z/network").NativeExchange;
// @ts-expect-error Nor is its initializer.
type Initialize = typeof import("@chainsafe/lodestar-z/network").initializeNativeNetworkRuntime;

/** A name the facade must not have, or never when it has it. */
type Absent<K extends string> = K extends keyof NativeNetwork ? never : K;

test("the package's network entry exports only createNativeNetwork, whose facade hides the runtime", () => {
  expect(Object.keys(network)).toEqual(["createNativeNetwork"]);
  // Only the facade factory is a value export.
  const exported: keyof typeof network = "createNativeNetwork";
  const only: [keyof typeof network] extends ["createNativeNetwork"] ? true : false = true;
  // The exchange, escalation, ownership controls and log polling stay private.
  const hidden: [Absent<"exchange">, Absent<"fail">, Absent<"holdVerdicts">, Absent<"drainLogs">] = [
    "exchange",
    "fail",
    "holdVerdicts",
    "drainLogs",
  ];
  const host: (keyof NativeHost)[] = ["capacity", "validate", "checkDependencies", "serve", "peers", "failed", "logs"];
  const unexported: [Exchange?, Initialize?] = [];
  expect([exported, only, hidden.length, host.length, unexported]).toEqual(["createNativeNetwork", true, 4, 7, []]);
});
