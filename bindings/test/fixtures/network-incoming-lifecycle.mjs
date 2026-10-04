import {holdSettling, requestForks, runtimeReleased} from "../utils/network.ts";
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
let pair = await incomingPair(undefined, mode === "notifier" ? () => { thrown++; throw Error("incoming-notifier"); } : () => undefined);
let left = pair.left;
let right = pair.right;
const remote = pair.remote;
const context = requestForks[0];
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
    assert.equal(await closed, undefined);
  } else if (mode === "object-gc") {
    const weak = new WeakRef(incoming);
    incoming = null;
    for (let i = 0; i < 300; i++) {
      await delay(10);
      global.gc();
      if (!weak.deref()) break;
    }
    assert.equal(weak.deref(), undefined);
    assert.equal(await closed, undefined);
  } else if (mode === "ready-gc") {
    // A runtime collected while its host awaits a permission settles it, refused, after the stream's close.
    holdSettling(right, true);
    const permission = incoming.ready();
    const order = [];
    void permission.then(
      () => order.push("granted"),
      (error) => order.push(error.code)
    );
    void closed.then(() => order.push("closed"));
    const weak = new WeakRef(right);
    right = null;
    for (let i = 0; i < 300; i++) {
      await delay(10);
      global.gc();
      if (!weak.deref()) break;
    }
    assert.equal(weak.deref(), undefined);
    await assert.rejects(permission, {code: "NetworkIncomingClosed"});
    assert.equal(await closed, undefined);
    assert.deepEqual(order, ["closed", "NetworkIncomingClosed"]);
  } else if (mode === "late-retire") {
    // Host work that outlives the native runtime itself retires quietly once the runtime is gone.
    let retire = () => undefined;
    incoming.retainUntil(
      new Promise((resolve) => {
        retire = resolve;
      })
    );
    assert.deepEqual(await right.close(), {reason: "requested"});
    assert.equal(await closed, undefined);
    right = null;
    await runtimeReleased();
    retire();
    await delay(10);
  } else if (mode === "held-ack") {
    const ack = incoming.respond(new Uint8Array(10 * 1024 * 1024), context).then(() => "sent", (error) => error.code);
    await right.close();
    assert(["sent", "NetworkClosed"].includes(await ack));
    assert.equal(await closed, undefined);
  } else if (mode === "notifier") {
    await incoming.finish();
    assert.equal(await closed, undefined);
    await delay(10);
    assert(thrown > 0);
    assert(warnings > 0);
  } else if (mode === "held-closed") {
    await right.close();
    assert.equal(await closed, undefined);
    assert.equal(incoming.cancel(), closed);
  } else throw Error("unknown lifecycle scenario");
  // A collected server stops without closing its connection, so its request would otherwise run to its deadline.
  if (mode === "facade-gc" || mode === "ready-gc") await stream.return();
  await pending;
  console.log("incoming-lifecycle", mode, "ok");
} finally {
  await Promise.allSettled([left?.stop(), right?.close()]);
}
