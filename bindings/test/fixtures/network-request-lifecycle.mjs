import assert from "node:assert/strict";
import {setTimeout as delay} from "node:timers/promises";
import {createNativeNetworkApplicationRuntime} from "../../src/network.js";
import {applicationConfig, localIntent} from "../utils/network.ts";
import {Child} from "../../../test/interop/child.mjs";

const mode = process.argv[2];
if (mode === "exit") {
  const leftConfig = applicationConfig();
  leftConfig.resources.bridgeBudgetBytes = 128 * 1024 * 1024;
  const rightConfig = applicationConfig();
  rightConfig.identitySecretKey[31] = 63;
  const left = createNativeNetworkApplicationRuntime(leftConfig, () => undefined);
  const right = createNativeNetworkApplicationRuntime(rightConfig, () => undefined);
  const [, remote] = await Promise.all([left.ready, right.ready]);
  await Promise.all([left.applyIntent(localIntent(leftConfig), leftConfig.initialSlot), right.applyIntent(localIntent(rightConfig), rightConfig.initialSlot)]);
  await left.connect(remote.peerId, [remote.localEndpoint], 5000n);
  void left.request(remote.peerId, "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy", new Uint8Array(32)).next().catch(() => undefined);
  console.log("request-lifecycle", mode, "ok");
  process.exit(0);
}

if (["closed-facade-gc", "closed-facade-gc-early", "closed-terminal", "closed-terminal-fault"].includes(mode)) {
  const {default: bindings} = await import("../../src/bindings.js");
  const config = applicationConfig();
  config.resources.bridgeBudgetBytes = 128 * 1024 * 1024;
  let runtime = createNativeNetworkApplicationRuntime(config, () => undefined);
  const identity = await runtime.ready;
  await runtime.applyIntent(localIntent(config), config.initialSlot);
  const stream = runtime.request(identity.peerId, "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy", new Uint8Array(32));
  await runtime.close();
  for (let i = 0; mode !== "closed-facade-gc-early" && i < 100; i++) {
    await delay(5);
    if (bindings.networkTestStats && bindings.networkTestStats().notifications === 0) break;
  }
  if (bindings.networkTestStats && mode !== "closed-facade-gc-early") assert.equal(bindings.networkTestStats().notifications, 0);
  if (mode.startsWith("closed-terminal")) {
    if (mode === "closed-terminal-fault") bindings.networkTestFail("operation_copy");
    await assert.rejects(stream.next(), {code: mode === "closed-terminal-fault" ? "NetworkResultAllocationFailed" : "NetworkClosed"});
    assert.equal(runtime.diagnostics().requests.occupied, 0);
  }
  const weak = new WeakRef(runtime);
  runtime = null;
  global.gc();
  for (let i = 0; i < 100; i++) {
    await delay(10);
    global.gc();
    if (!weak.deref() && (!bindings.networkTestStats || bindings.networkTestStats().runtimes === 0)) break;
  }
  assert.equal(weak.deref(), undefined);
  if (bindings.networkTestStats) assert.equal(bindings.networkTestStats().runtimes, 0);
  if (mode.startsWith("closed-facade-gc")) await assert.rejects(stream.next(), {code: "NetworkClosed"});
  console.log("request-lifecycle", mode, "ok");
  process.exit(0);
}

const peer = new Child("lifecycle-stock", process.execPath, ["test/interop/request_responder.mjs", process.env.LODESTAR_Z_NETWORK_STOCK_HOST]);
let runtime;
try {
  const info = await peer.command("ready");
  await peer.command("scenario", {scenario: "hold"});
  const config = applicationConfig();
  config.resources.bridgeBudgetBytes = 128 * 1024 * 1024;
  runtime = createNativeNetworkApplicationRuntime(config, () => { throw Error("request-notifier"); });
  await runtime.ready;
  await runtime.applyIntent(localIntent(config), config.initialSlot);
  const id = Uint8Array.from(Buffer.from(info.peer, "hex"));
  await runtime.connect(id, [{family: 4, address: Uint8Array.of(127, 0, 0, 1), port: Number(info.address.split("/")[4])}], 5000n);
  let stream = runtime.request(id, "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy", new Uint8Array(32));
  if (mode === "iterator-gc") {
    const weak = new WeakRef(stream);
    stream = null;
    for (let i = 0; i < 100; i++) {
      await delay(10);
      global.gc();
      if (!weak.deref() && runtime.diagnostics().requests.occupied === 0) break;
    }
    assert.equal(weak.deref(), undefined);
    assert.equal(runtime.diagnostics().requests.occupied, 0);
    assert.equal(runtime.diagnostics().requests.reservedBytes, 0);
  } else {
    const pending = stream.next().then(() => "unexpected", (error) => error.code);
    const weak = new WeakRef(runtime);
    runtime = null;
    for (let i = 0; i < 100; i++) {
      await delay(10);
      global.gc();
      if (!weak.deref()) break;
    }
    assert.equal(weak.deref(), undefined);
    assert.equal(await pending, "NetworkClosed");
    assert.deepEqual(await stream.next(), {done: true, value: undefined});
  }
  console.log("request-lifecycle", mode, "ok");
} finally {
  if (runtime) await runtime.close();
  await peer.stop();
}
