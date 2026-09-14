import assert from "node:assert/strict";
import {createNativeNetworkApplicationRuntime} from "../../src/network.js";
import {applicationConfig} from "../utils/network.ts";

const runtime = createNativeNetworkApplicationRuntime(applicationConfig(), () => undefined);
await runtime.ready;
await runtime.close();
let setterCalls = 0;
Object.defineProperty(Object.prototype, "level", {
  configurable: true,
  set(value) {
    setterCalls++;
    delete Object.prototype.level;
    runtime.drainLogs();
    Object.defineProperty(this, "level", {value, enumerable: true, writable: true, configurable: true});
  },
});
const batch = runtime.drainLogs();
delete Object.prototype.level;
assert.equal(setterCalls, 0);
assert(batch.records.length > 0);
assert(batch.records.every((record) => Object.hasOwn(record, "level")));
assert.equal(runtime.drainLogs().records.length, 0);
console.log("ok");
