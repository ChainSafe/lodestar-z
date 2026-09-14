import assert from "node:assert/strict";
import {createSocket} from "node:dgram";
import {setTimeout as delay} from "node:timers/promises";
import {createNativeNetworkApplicationRuntime} from "../../src/network.js";
import bindings from "../../src/bindings.js";
import {applicationConfig} from "../utils/network.ts";

const mode = process.argv[2];
if (mode === "callback") {
  bindings.networkTestScenario("application_peer_lane");
  let calls = 0;
  const thrown = new Promise((resolve) => process.once("uncaughtException", resolve));
  const runtime = createNativeNetworkApplicationRuntime(applicationConfig(), () => {
    calls++;
    throw new Error("ordinary-readable-failure");
  });
  await runtime.ready;
  assert.equal((await thrown).message, "ordinary-readable-failure");
  assert.equal(runtime.diagnostics().peerLaneOccupied, 64);
  assert.equal(runtime.drainPeers(1).events.length, 1);
  const closing = runtime.close();
  assert.equal(runtime.close(), closing);
  assert.equal((await closing).reason, "requested");
  await delay(50);
  assert.equal(calls, 1);
  console.log("callback-closed");
} else if (mode === "exit") {
  const runtime = createNativeNetworkApplicationRuntime(applicationConfig(), () => undefined);
  await runtime.ready;
  console.log("ready-exit");
} else if (mode === "gc") {
  const survivor = createNativeNetworkApplicationRuntime(applicationConfig(), () => undefined);
  await survivor.ready;
  let abandoned = createNativeNetworkApplicationRuntime(applicationConfig(), () => undefined);
  const identity = await abandoned.ready;
  const weak = new WeakRef(abandoned);
  abandoned = null;
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
  assert.equal((await survivor.getIdentity()).peerId.length, 39);
  await survivor.close();
  console.log("gc-rebound");
}
else if (mode === "promises") {
  let weak;
  const ready = (() => {
    const runtime = createNativeNetworkApplicationRuntime(applicationConfig(), () => undefined);
    weak = new WeakRef(runtime);
    return runtime.ready.then(() => "ready", (error) => error.message);
  })();
  for (let i = 0; i < 100; i++) {
    await delay(1);
    global.gc();
    if (!weak.deref()) break;
  }
  assert.equal(weak.deref(), undefined);
  assert(["ready", "AbortError"].includes(await Promise.race([ready, delay(5000, undefined, {ref: false}).then(() => "timeout")])));
  let runtime = createNativeNetworkApplicationRuntime(applicationConfig(), () => undefined);
  await runtime.ready;
  const closing = runtime.close();
  runtime = null;
  await delay(1);
  global.gc();
  assert.equal((await closing).reason, "requested");
  console.log("promises-settled");
}
