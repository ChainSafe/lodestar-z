import assert from "node:assert/strict";
import {createSocket} from "node:dgram";
import {setTimeout as delay} from "node:timers/promises";
import {runtimeReleased, startRuntime, applicationConfig} from "../utils/network.js";

const mode = process.argv[2];
if (mode === "exit") {
  const runtime = startRuntime(applicationConfig());
  assert.equal(runtime.state, "running");
  console.log("ready-exit");
} else if (mode === "gc") {
  let runtime = startRuntime(applicationConfig());
  const identity = runtime.identity;
  const weak = new WeakRef(runtime);
  runtime = null;
  for (let i = 0; i < 100; i++) {
    await delay(10);
    global.gc();
    if (!weak.deref()) break;
  }
  assert.equal(weak.deref(), undefined, "TSFN must not retain the wrapper");
  await delay(20);
  const socket = createSocket("udp4");
  await new Promise((resolve, reject) => {
    socket.once("error", reject);
    socket.bind(identity.localEndpoint.port, "127.0.0.1", resolve);
  });
  socket.close();
  await runtimeReleased();
  await startRuntime(applicationConfig()).close();
  console.log("gc-rebound");
} else if (mode === "promises") {
  let runtime = startRuntime(applicationConfig());
  const closing = runtime.close();
  runtime = null;
  await delay(1);
  global.gc();
  assert.equal((await closing).reason, "requested");
  console.log("promises-settled");
} else if (mode === "callback") {
  const {incomingPair, takeIncoming, BLOCKS} = await import("../utils/network-incoming.js");
  let calls = 0;
  const thrown = new Promise((resolve) =>
    process.on("uncaughtException", (error) => {
      assert.equal(error.message, "ordinary-work-notification-failure");
      resolve(error);
    })
  );
  const pair = await incomingPair(undefined, () => {
    calls++;
    throw new Error("ordinary-work-notification-failure");
  });
  try {
    const request = pair.left.request(pair.remote.peerId, BLOCKS, new Uint8Array(32));
    const response = request.next().catch(() => undefined);
    assert.equal((await thrown).message, "ordinary-work-notification-failure");
    const incoming = await takeIncoming(pair.right);
    await incoming.finish();
    await response;
    assert(calls > 0);
    console.log("callback-closed");
  } finally {
    await Promise.all([pair.left.close(), pair.right.close()]);
  }
} else throw new Error("Unknown lifecycle scenario");
