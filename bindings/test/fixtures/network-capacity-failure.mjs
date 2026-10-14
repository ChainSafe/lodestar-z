import assert from "node:assert/strict";
import {NativePump} from "../../src/network-pump.js";
import {NativeRuntime} from "../../src/network-runtime.js";
import {applicationConfig} from "../utils/network.js";

let capacityReads = 0;
const {promise: failed, resolve: fail} = Promise.withResolvers();
const error = new Error("capacity failed");
const pump = new NativePump({
  subscribeCapacity: () => () => {},
  capacity: () => { capacityReads++; throw error; },
  validate: async () => [],
  checkDependencies: () => [],
  serve: (request) => request.cancel(),
  peers: () => {},
  failed: fail,
  logs: () => {},
});
const runtime = new NativeRuntime(applicationConfig(), pump.request);
pump.attach(runtime);
await runtime.getIdentity();
assert.equal(await failed, error);
assert.equal(capacityReads, 1);
assert.deepEqual(await runtime.close(), {reason: "failed", error});
console.log("capacity failed; identity settled; closed");
