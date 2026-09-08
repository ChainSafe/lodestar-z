import assert from "node:assert/strict";
import {setTimeout as delay} from "node:timers/promises";
import {BLOCKS, incomingPair, takeIncoming} from "../utils/network-incoming.ts";

const mode = process.argv[2];
let warnings = 0;
let thrown = 0;
if (mode === "notifier") process.on("warning", (warning) => {
  assert.match(warning.message, /Uncaught N-API callback exception/);
  warnings++;
});
let pair = await incomingPair(undefined, undefined, mode === "notifier" ? () => { thrown++; throw Error("incoming-notifier"); } : () => undefined);
let left = pair.left;
let right = pair.right;
const remote = pair.remote;
const context = pair.rightConfig.requestForks[0];
pair = null;
try {
  const stream = left.request(remote.peerId, BLOCKS, new Uint8Array(32));
  const pending = stream.next().catch(() => undefined);
  let incoming = await takeIncoming(right);
  const closed = incoming.closed;
  if (mode === "exit") {
    void incoming.respond(new Uint8Array(10 * 1024 * 1024), context).catch(() => undefined);
    console.log("incoming-lifecycle", mode, "ok");
    process.exit(0);
  }
  if (mode === "facade-gc") {
    const weak = new WeakRef(right);
    right = null;
    for (let i = 0; i < 300; i++) {
      await delay(10);
      global.gc();
      if (!weak.deref()) break;
    }
    assert.equal(weak.deref(), undefined);
    assert.deepEqual(await closed, {reason: "closed", chunks: 0});
  } else if (mode === "object-gc") {
    const weak = new WeakRef(incoming);
    incoming = null;
    for (let i = 0; i < 300; i++) {
      await delay(10);
      global.gc();
      if (!weak.deref()) break;
    }
    assert.equal(weak.deref(), undefined);
    assert.deepEqual(await closed, {reason: "failed", failure: "cancelled", chunks: 0});
  } else if (mode === "held-ack") {
    const ack = incoming.respond(new Uint8Array(10 * 1024 * 1024), context).then(() => "sent", (error) => error.code);
    await right.close();
    assert(["sent", "NetworkClosed"].includes(await ack));
    assert.equal((await closed).reason, "closed");
  } else if (mode === "notifier") {
    await incoming.finish();
    assert.deepEqual(await closed, {reason: "served", chunks: 0});
    await delay(10);
    assert(thrown > 0);
    assert(warnings > 0);
  } else if (mode === "held-closed") {
    await right.close();
    assert.deepEqual(await closed, {reason: "closed", chunks: 0});
    assert.equal(incoming.cancel(), closed);
    assert.equal(right.diagnostics().incoming.responseBytes, 0);
    assert.equal(right.diagnostics().incoming.requestBytes, 0);
    assert.equal(right.diagnostics().incoming.reservedBytes, 0);
    assert.equal(right.diagnostics().liveNativeRequestedBytes, 0);
  } else throw Error("unknown lifecycle scenario");
  await pending;
  console.log("incoming-lifecycle", mode, "ok");
} finally {
  await Promise.allSettled([left?.close(), right?.close()]);
}
