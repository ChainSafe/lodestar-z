import assert from "node:assert/strict";
import {setTimeout as delay} from "node:timers/promises";
import {createNativeNetworkApplicationRuntime} from "../../src/network.js";
import {applicationConfig, localIntent} from "../utils/network.ts";

let notifierErrors = 0;
process.on("uncaughtException", (error) => { assert.equal(error.message, "expected gossip notifier"); notifierErrors++; });
const config = applicationConfig();
let runtime = createNativeNetworkApplicationRuntime(config, () => { throw Error("expected gossip notifier"); });
await runtime.ready;
await runtime.applyIntent(localIntent(config), config.initialSlot);
const remoteConfig = applicationConfig();
remoteConfig.identitySecretKey[31] = 63;
const remote = createNativeNetworkApplicationRuntime(remoteConfig, () => undefined);
const remoteIdentity = await remote.ready;
await remote.applyIntent(localIntent(remoteConfig), remoteConfig.initialSlot);
await runtime.connect(remoteIdentity.peerId, [remoteIdentity.localEndpoint], 5000n);
for (let i = 0; i < 100 && notifierErrors === 0; i++) await delay(10);
assert(notifierErrors > 0);
const weak = new WeakRef(runtime);
const pending = [];
for (let i = 0; i < 32; i++) {
  try { pending.push(runtime.publishGossip("/eth2/01020304/beacon_block/ssz_snappy", new Uint8Array(10).fill(i))); }
  catch (error) { assert.equal(error.code, "NetworkCommandFull"); }
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
for (const outcome of outcomes) if (outcome.status === "rejected") assert.equal(outcome.reason.code, "NetworkClosed");
assert.equal(weak.deref(), undefined);
await remote.close();
console.log(JSON.stringify({accepted: outcomes.length, settled: outcomes.length, collected: true, notifierErrors}));
