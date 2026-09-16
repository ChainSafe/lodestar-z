import assert from "node:assert/strict";
import {createSocket} from "node:dgram";
import {once} from "node:events";
import {setTimeout as delay} from "node:timers/promises";
import {isMainThread, parentPort, Worker} from "node:worker_threads";
import {createNativeNetworkApplicationRuntime} from "../../src/network.js";
import {applicationConfig, localIntent} from "../utils/network.ts";

const topic = "/eth2/01020304/beacon_block/ssz_snappy";
const blocks = "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy";
async function until(read) {
  for (let i = 0; i < 1000; i++) {
    const value = await read();
    if (value) return value;
    await delay(5);
  }
  throw Error("Live worker resources did not settle");
}
const config = applicationConfig();
config.identitySecretKey[31] = isMainThread ? 61 : 62;
config.resources.bridgeBudgetBytes = 512 * 1024 * 1024;
const runtime = createNativeNetworkApplicationRuntime(config, () => undefined);
const identity = await runtime.ready;
const intent = localIntent(config);
intent.subscriptions = [{name: topic, params: config.gossipPolicy.score.defaultTopic}];
await runtime.applyIntent(intent, config.initialSlot);

if (!isMainThread) {
  parentPort.postMessage(identity);
  const [remote] = await once(parentPort, "message");
  const outgoing = runtime.request(remote.peerId, blocks, new Uint8Array(32));
  const pending = outgoing.next().catch(() => undefined);
  const incoming = await until(() => runtime.takeIncomingRequest());
  await until(() => runtime.diagnostics().gossip.queued > 0);
  const batch = runtime.drainGossip();
  assert.equal(batch.messages.length, 1);
  parentPort.postMessage({port: identity.localEndpoint.port, diagnostics: runtime.diagnostics()});
  parentPort.on("message", () => void [incoming, outgoing, pending, batch]);
} else {
  const worker = new Worker(new URL(import.meta.url));
  try {
    const [remote] = await once(worker, "message");
    await runtime.connect(remote.peerId, [remote.localEndpoint], 5000n);
    await runtime.addDirectPeer(remote.peerId, [remote.localEndpoint]);
    const ready = once(worker, "message");
    worker.postMessage(identity);
    const outgoing = runtime.request(remote.peerId, blocks, new Uint8Array(32));
    const pending = outgoing.next().catch(() => undefined);
    const incoming = await until(() => runtime.takeIncomingRequest());
    await until(async () => (await runtime.getGossipDiagnostics()).peers.some((peer) => peer.outboundReady));
    await until(async () => {
      try {
        await runtime.publishGossip(topic, new Uint8Array(10).fill(7), {allowZeroPeers: false});
        return true;
      } catch (error) {
        if (error.reason === "no_peers_subscribed_to_topic") return false;
        throw error;
      }
    });
    const [held] = await ready;
    assert.equal(held.diagnostics.requests.occupied, 1);
    assert.equal(held.diagnostics.incoming.occupied, 1);
    assert.equal(held.diagnostics.gossip.occupied, 1);
    await worker.terminate();
    assert.deepEqual((await runtime.getIdentity()).peerId, identity.peerId);
    const socket = createSocket("udp4");
    try {
      socket.bind(held.port, "127.0.0.1");
      await once(socket, "listening");
    } finally {
      socket.close();
    }
    assert.equal(incoming.peerId.length, 39);
    await runtime.close();
    await pending;
    console.log("live-worker-resources-released");
  } finally {
    await worker.terminate();
    await runtime.close();
  }
}
