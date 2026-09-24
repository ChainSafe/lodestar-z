import assert from "node:assert/strict";
import {createSocket} from "node:dgram";
import {once} from "node:events";
import {isMainThread, parentPort, Worker} from "node:worker_threads";
import {applicationConfig, localIntent, startRuntime, topicName} from "../utils/network.js";

if (isMainThread) {
  const worker = new Worker(new URL(import.meta.url));
  try {
    const [{port, occupied}] = await once(worker, "message");
    assert(occupied > 0);
    await worker.terminate();
    const socket = createSocket("udp4");
    try {
      socket.bind(port, "127.0.0.1");
      await once(socket, "listening");
    } finally {
      socket.close();
    }
    console.log("worker-settlement-released");
  } finally {
    await worker.terminate();
  }
} else {
  const config = applicationConfig();
  const runtime = startRuntime(config);
  await runtime.applyIntent(localIntent(config), config.initialSlot);
  const payload = new Uint8Array(4000);
  new DataView(payload.buffer).setBigUint64(100, config.initialSlot, true);
  const pending = [];
  for (let i = 0; i < 16; i++) {
    pending.push(runtime.publishGossip(topicName(), payload, {allowZeroPeers: true, ignoreDuplicate: true}));
    pending.push(runtime.getIdentity());
  }
  void Promise.allSettled(pending);
  const diagnostics = runtime.diagnostics();
  parentPort.postMessage({
    port: runtime.identity.localEndpoint.port,
    occupied: diagnostics.publications.occupied + diagnostics.operationOccupied,
  });
  setInterval(() => {}, 1000);
}
