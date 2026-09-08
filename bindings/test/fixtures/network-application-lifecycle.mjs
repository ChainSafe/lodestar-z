import assert from "node:assert/strict";
import {createSocket} from "node:dgram";
import {setTimeout as delay} from "node:timers/promises";
import {createNativeNetworkApplicationRuntime} from "../../src/network.js";
import bindings from "../../src/bindings.js";
import {applicationConfig, localIntent} from "../utils/network.ts";

const mode = process.argv[2];
const config = applicationConfig();
let runtime = createNativeNetworkApplicationRuntime(config, () => { throw Error("application-notifier"); });
const identity = await runtime.ready;
await runtime.applyIntent(localIntent(config), config.initialSlot);
if (mode === "exit") {
  console.log("application-ready-exit");
} else {
  let settlements = 0;
  if (mode === "copy-failure") bindings.networkTestFail("operation_copy");
  const pending = mode === "gc" ? runtime.connect(
    Uint8Array.from(Buffer.from("00250802122102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5", "hex")),
    [{family: 4, address: Uint8Array.of(127, 0, 0, 1), port: 9}], 60000n) : runtime.getIdentity();
  const command = pending.then(() => { settlements++; return "ok"; }, (error) => { settlements++; return error.code; });
  const weak = new WeakRef(runtime);
  runtime = null;
  for (let i = 0; i < 100; i++) {
    await delay(10);
    global.gc();
    if (!weak.deref()) break;
  }
  assert.equal(weak.deref(), undefined, "a retained command Promise must not retain its facade");
  const result = await command;
  assert(["ok", "NetworkClosed", "NetworkResultAllocationFailed"].includes(result));
  if (mode === "gc") assert.equal(result, "NetworkClosed");
  if (mode === "copy-failure") assert.equal(result, "NetworkResultAllocationFailed");
  assert.equal(settlements, 1);
  if (process.env.LODESTAR_Z_NETWORK_TEST_FAILURES === "1") {
    for (let i = 0; i < 100 && bindings.networkTestStats().runtimes !== 0; i++) { await delay(10); global.gc(); }
    assert.deepEqual(bindings.networkTestStats(), {runtimes: 0, notifications: 0, owners: 0});
  }
  const socket = createSocket("udp4");
  await new Promise((resolve, reject) => {
    socket.once("error", reject);
    socket.bind(identity.localEndpoint.port, "127.0.0.1", resolve);
  });
  socket.close();
  console.log("application-command-settled", result);
}
