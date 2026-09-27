import {once} from "node:events";
import {isMainThread, Worker} from "node:worker_threads";

// Only the worker loads the addon, so Node unloads it when the worker's environment ends, before the thread exits.
if (isMainThread) {
  const [code] = await once(new Worker(new URL(import.meta.url)), "exit");
  console.log(`worker-exited ${code}`);
} else {
  const {applicationConfig, startRuntime} = await import("../utils/network.js");
  await startRuntime(applicationConfig()).close();
}
