// A real pump drains a real native runtime whose exchanges all fail from the moment the host closes, with nothing
// else keeping the event loop alive. Close must settle, or the third failed exchange must escalate through native
// `fail`, which aborts the process; exiting with neither is the regression.
import {NativePump} from "../../src/network-pump.js";
import {NativeRuntime} from "../../src/network-runtime.js";
import {applicationConfig} from "../utils/network.js";

let closing = false;
const host = {
  capacity: () => ({ordinary: true, serving: 32}),
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
  // Without a string code, the pump requeues the batch and retries on its timer.
  exchange: (actions, demand) => {
    if (closing) throw Error("exchange failed");
    return native.exchange(actions, demand);
  },
  fail: (trigger, reason) => native.fail(trigger, reason),
});
// A command settles through the pump before the host closes.
await native.getIdentity();
closing = true;
pump.close();
const result = await native.close();
console.log("closed", JSON.stringify(result));
