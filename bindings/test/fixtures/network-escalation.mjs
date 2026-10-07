// A real pump drains a real native runtime until the fatal site the first argument names terminates the process
// through native `fail`: `generated_batch` sends a demand native refuses, as a pump generating an invalid one would,
// `uncoded_exchange` has an exchange that throws without a code, `completion_contract` has exchanges deliver a
// completion the completion owner never admitted, and `close_missing` has them lose a command's completion before
// native closes. Printing "survived" is the regression.
import bindings from "../../src/bindings.js";
import {NativePump} from "../../src/network-pump.js";
import {NativeRuntime} from "../../src/network-runtime.js";
import {applicationConfig} from "../utils/network.js";

const site = process.argv[2];
const exchange = bindings.NativeNetworkRuntime.prototype.exchange;
if (site === "completion_contract") {
  bindings.NativeNetworkRuntime.prototype.exchange = function (actions, demand) {
    const result = exchange.call(this, actions, demand);
    return {...result, completions: [{family: "publication", handle: {generation: 1n, index: 0}, value: null}]};
  };
} else if (site === "close_missing") {
  bindings.NativeNetworkRuntime.prototype.exchange = function (actions, demand) {
    const result = exchange.call(this, actions, demand);
    return {...result, completions: result.completions.filter(({family}) => family !== "command")};
  };
}
let capacityReads = 0;
let capacityErrors = 0;
let identitySettled = false;
let failed;
const failure = new Promise((resolve) => {failed = resolve;});
const host = {
  subscribeCapacity: () => () => {},
  capacity: () => {
    if (site === "capacity_failure") {
      capacityReads++;
      throw Error("capacity failed");
    }
    return {gossipValidation: "ready", incomingRequestSlots: 32};
  },
  validate: (job) => Promise.resolve(job.messages.map(() => "ignore")),
  checkDependencies: (checks) => checks.map(() => false),
  serve: (request) => request.cancel(),
  peers: () => undefined,
  failed: () => failed?.(),
  logs: () => undefined,
  error: () => {capacityErrors++;},
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
  exchange: (actions, demand) => {
    if (site === "uncoded_exchange") throw Error("exchange failed");
    return native.exchange(actions, site === "generated_batch" ? {...demand, servingStarts: 9} : demand);
  },
  fail: (raised, reason) => native.fail(raised, reason),
});
// Keep failed/recovering turns alive until the bounded scenario settles or its deadline expires.
const deadline = setTimeout(() => console.log("survived"), 5000);
pump.request();
if (site === "close_missing") {
  void native.getIdentity();
  void native.close();
}

if (site === "capacity_failure") {
  await native.getIdentity();
  identitySettled = true;
  await failure;
  if (capacityReads !== 1 || !identitySettled) throw Error("Unexpected capacity failure behavior");
  pump.stopDelivery();
  await native.close();
  clearTimeout(deadline);
  console.log("capacity failed; identity settled; closed");
}
