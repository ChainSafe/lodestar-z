import {startPeer} from "../utils/network-peer.js";
import {startRuntime} from "../utils/network.js";
import assert from "node:assert/strict";
import {setTimeout as delay} from "node:timers/promises";

import {
  applicationConfig,
  localIntent,
  peerIdFromHex,
  Settlements,
  topicName,
  unreachableConnect,
} from "../utils/network.ts";
import {Child} from "../../../test/interop/child.mjs";

const mode = process.argv[2];
if (mode === "exit") {
  const leftConfig = applicationConfig();
  const rightConfig = applicationConfig();
  rightConfig.identitySecretKey[31] = 63;
  const left = startRuntime(leftConfig, () => undefined);
  const right = await startPeer(rightConfig);
  const [, remote] = await Promise.all([left.identity, right.identity]);
  await Promise.all([
    left.applyIntent(localIntent(leftConfig), leftConfig.initialSlot),
    right.applyIntent(localIntent(rightConfig), rightConfig.initialSlot),
  ]);
  await left.connect(remote.peerId, [remote.localEndpoint], 5000n);
  void left
    .request(remote.peerId, "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy", new Uint8Array(32))
    .next()
    .catch(() => undefined);
  console.log("request-lifecycle", mode, "ok");
  process.exit(0);
}

if (["closed-facade-gc", "closed-facade-gc-early", "closed-terminal"].includes(mode)) {
  const config = applicationConfig();
  let runtime = startRuntime(config, () => undefined);
  const identity = await runtime.identity;
  await runtime.applyIntent(localIntent(config), config.initialSlot);
  const stream = runtime.request(
    identity.peerId,
    "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy",
    new Uint8Array(32)
  );
  await runtime.close();
  if (mode !== "closed-facade-gc-early") await delay(500);
  if (mode === "closed-terminal") {
    await assert.rejects(stream.next(), {code: "NetworkClosed"});
    assert.equal(runtime.diagnostics().requests.occupied, 0);
  }
  const weak = new WeakRef(runtime);
  runtime = null;
  global.gc();
  for (let i = 0; i < 100; i++) {
    await delay(10);
    global.gc();
    if (!weak.deref()) break;
  }
  assert.equal(weak.deref(), undefined);
  if (mode.startsWith("closed-facade-gc")) await assert.rejects(stream.next(), {code: "NetworkClosed"});
  console.log("request-lifecycle", mode, "ok");
  process.exit(0);
}

/** A peer that holds requests without answering: the stock responder's hold scenario, else a native peer that never takes them. */
async function holdingPeer() {
  const host = process.env.LODESTAR_Z_NETWORK_STOCK_HOST;
  if (host) {
    const peer = new Child("lifecycle-stock", process.execPath, ["test/interop/request_responder.mjs", host]);
    const info = await peer.command("ready");
    await peer.command("scenario", {scenario: "hold"});
    const port = Number(info.address.split("/")[4]);
    return {id: peerIdFromHex(info.peer), endpoint: {family: 4, address: Uint8Array.of(127, 0, 0, 1), port}, peer};
  }
  const config = applicationConfig();
  config.identitySecretKey[31] = 63;
  const peer = await startPeer(config);
  await peer.applyIntent(localIntent(config), config.initialSlot);
  return {id: peer.identity.peerId, endpoint: peer.identity.localEndpoint, peer, native: peer};
}

const holding = await holdingPeer();
let runtime;
try {
  const config = applicationConfig();
  runtime = startRuntime(config, () => {
    throw Error("request-notifier");
  });
  await runtime.identity;
  await runtime.applyIntent(localIntent(config), config.initialSlot);
  const id = holding.id;
  await runtime.connect(id, [holding.endpoint], 5000n);
  let stream = runtime.request(id, "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy", new Uint8Array(32), {
    responseTimeoutMs: 60000,
  });
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
    // The retirement cancels the stream at the peer, which retires its queued request.
    for (let i = 0; i < 100 && holding.native && (await holding.native.diagnostics()).incoming.occupied > 0; i++)
      await delay(10);
    if (holding.native) assert.equal((await holding.native.diagnostics()).incoming.occupied, 0);
  } else {
    // Promises held while the facade is collected without close still reach their terminals, closed last.
    const closed = runtime.closed;
    const settlements = new Settlements();
    const unsettled = settlements.unsettledAtClose(closed);
    settlements.watch(() => stream.next());
    settlements.watch(() => runtime.connect(...unreachableConnect()));
    settlements.watch(() =>
      runtime.publishGossip(topicName(), new Uint8Array(4000), {allowZeroPeers: true, ignoreDuplicate: true})
    );
    const weak = new WeakRef(runtime);
    runtime = null;
    for (let i = 0; i < 100; i++) {
      await delay(10);
      global.gc();
      if (!weak.deref()) break;
    }
    assert.equal(weak.deref(), undefined);
    await settlements.settled();
    assert.deepEqual(await closed, {reason: "requested"});
    assert.deepEqual(await unsettled, []);
    assert.deepEqual(settlements.counts, [1, 1, 1]);
    assert.deepEqual(settlements.outcomes.slice(0, 2), ["NetworkClosed", "NetworkClosed"]);
    assert.deepEqual(await stream.next(), {done: true, value: undefined});
  }
  console.log("request-lifecycle", mode, "ok");
} finally {
  if (runtime) await runtime.close();
  await holding.peer.stop();
}
