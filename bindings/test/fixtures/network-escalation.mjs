// A real pump drains a real native runtime until the fatal site named by the first argument terminates the process
// through native `fail`: `generated_batch` sends a demand native refuses, as a pump generating an invalid one would,
// `failed_turns` has a host whose capacity read keeps throwing, and `completion_contract` has exchanges deliver a
// completion the completion owner never admitted. Printing "survived" is the regression.
import bindings from "../../src/bindings.js";
import {NativePump} from "../../src/network-pump.js";
import {NativeRuntime} from "../../src/network-runtime.js";
import {applicationConfig} from "../utils/network.js";

const site = process.argv[2];
if (site === "completion_contract") {
  const exchange = bindings.NativeNetworkRuntime.prototype.exchange;
  bindings.NativeNetworkRuntime.prototype.exchange = function (actions, demand) {
    const result = exchange.call(this, actions, demand);
    return {...result, completions: [{family: "publication", handle: {generation: 1n, index: 0}, value: null}]};
  };
}
const host = {
  capacity: () => {
    if (site === "failed_turns") throw Error("capacity failed");
    return {ordinary: true, serving: 32};
  },
  validate: (job) => Promise.resolve(job.messages.map(() => "ignore")),
  checkDependencies: (checks) => checks.map(() => false),
  serve: (request) => request.cancel(),
  peers: () => undefined,
  failed: () => undefined,
  logs: () => undefined,
  error: () => undefined,
};
const pump = new NativePump(host, {failure: null});
const native = new NativeRuntime(applicationConfig(), pump.request);
pump.attach({
  get closed() {
    return native.closed;
  },
  get state() {
    return native.state;
  },
  close: () => native.close(),
  drainLogs: (max) => native.drainLogs(max),
  exchange: (actions, demand) =>
    native.exchange(actions, site === "generated_batch" ? {...demand, settleCells: 0} : demand),
  fail: (raised, reason) => native.fail(raised, reason),
  turns: native.turns,
});
// A failed capacity read retries on an unreferenced timer, so this one keeps the process alive for the third.
setTimeout(() => console.log("survived"), 5000);
pump.request();
