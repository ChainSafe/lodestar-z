import {once} from "node:events";
import {isMainThread, Worker} from "node:worker_threads";

// Only the workers load the addon, one after another, so each worker's environment is the addon's last one and
// ends before its thread exits.
if (isMainThread) {
  const codes = [];
  for (let i = 0; i < 3; i++) {
    console.error("phase worker", i);
    codes.push((await once(new Worker(new URL(import.meta.url)), "exit"))[0]);
  }
  console.error("phase exit");
  console.log(`workers-exited ${codes.join(",")}`);
} else {
  const {applicationConfig, startRuntime} = await import("../utils/network.js");
  await startRuntime(applicationConfig()).close();
}
