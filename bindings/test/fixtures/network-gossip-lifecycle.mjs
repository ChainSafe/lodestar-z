import {startPeer} from "../utils/network-peer.js";
import {startRuntime} from "../utils/network.js";
import assert from "node:assert/strict";
import {setTimeout as delay} from "node:timers/promises";

import {applicationConfig, localIntent, topicName} from "../utils/network.ts";

let notifierErrors = 0;
process.on("uncaughtException", (error) => {
  assert.equal(error.message, "expected gossip notifier");
  notifierErrors++;
});
const config = applicationConfig();
let runtime = startRuntime(config, () => {
  throw Error("expected gossip notifier");
});
await runtime.identity;
await runtime.applyIntent(localIntent(config), config.initialSlot);
const remoteConfig = applicationConfig();
remoteConfig.identitySecretKey[31] = 63;
const remote = await startPeer(remoteConfig);
const remoteIdentity = await remote.identity;
await remote.applyIntent(localIntent(remoteConfig), remoteConfig.initialSlot);
await runtime.connect(remoteIdentity.peerId, [remoteIdentity.localEndpoint], 5000n);
for (let i = 0; i < 100 && notifierErrors === 0; i++) await delay(10);
assert(notifierErrors > 0);
const weak = new WeakRef(runtime);
const pending = [];
for (let i = 0; i < 32; i++) {
  pending.push(runtime.publishGossip(topicName(), new Uint8Array(4000).fill(i)));
}
const results = Promise.allSettled(pending);
runtime = null;
for (let i = 0; i < 100; i++) {
  await delay(10);
  global.gc();
  if (!weak.deref()) break;
}
const outcomes = await results;
assert(outcomes.length > 0);
// The beacon block plan retains eight publications; later ones are refused until close.
for (const outcome of outcomes)
  if (outcome.status === "rejected" && outcome.reason.code !== "NetworkClosed")
    assert.equal(outcome.reason.reason, "resource_exhausted");
assert.equal(weak.deref(), undefined);
await remote.stop();
console.log(JSON.stringify({accepted: outcomes.length, settled: outcomes.length, collected: true, notifierErrors}));
