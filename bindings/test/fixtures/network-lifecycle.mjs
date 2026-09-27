import assert from "node:assert/strict";
import {createSocket} from "node:dgram";
import {setTimeout as delay} from "node:timers/promises";
import {createNativeNetwork} from "../../src/network.js";
import {initializeNativeNetworkRuntime} from "../../src/network-runtime.js";
import {
  applicationConfig,
  localIntent,
  runtimeReleased,
  Settlements,
  settleOnly,
  startRuntime,
  subscriptions,
  topicName,
  unreachableConnect,
} from "../utils/network.js";

const mode = process.argv[2];
const noop = () => undefined;
if (mode === "exit") {
  const runtime = startRuntime(applicationConfig());
  assert.equal(runtime.state, "running");
  console.log("ready-exit");
} else if (mode === "gc") {
  let runtime = startRuntime(applicationConfig());
  const identity = runtime.identity;
  const weak = new WeakRef(runtime);
  runtime = null;
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
  await runtimeReleased();
  await startRuntime(applicationConfig()).close();
  console.log("gc-rebound");
} else if (mode === "promises") {
  const config = applicationConfig();
  let runtime = startRuntime(config);
  const settlements = new Settlements();
  const unsettled = settlements.unsettledAtClose(runtime.closed);
  await runtime.applyIntent(localIntent(config), config.initialSlot);
  settlements.watch(() => runtime.connect(...unreachableConnect()));
  settlements.watch(() => runtime.getIdentity());
  for (let i = 0; i < 4; i++)
    settlements.watch(() =>
      runtime.publishGossip(topicName(), new Uint8Array(4000).fill(i), {allowZeroPeers: true, ignoreDuplicate: true})
    );
  const closing = runtime.close();
  runtime = null;
  await delay(1);
  global.gc();
  assert.equal((await closing).reason, "requested");
  await settlements.settled();
  assert.deepEqual(await unsettled, []);
  assert.deepEqual(settlements.counts, [1, 1, 1, 1, 1, 1]);
  assert.equal(settlements.outcomes[0], "NetworkClosed");
  console.log("promises-settled");
} else if (mode === "facade-gc" || mode === "facade-gc-reaction" || mode === "facade-gc-derived") {
  // A dropped facade and its host are collected without close, while operation promises alone remain and settle when
  // native closes. A job's report retained elsewhere rejects then; one dropped with the host may hold a deferred
  // handler that captures the host, which holds the facade, and still roots none of them. Promises only derived from
  // a report may stay pending once the report is collected.
  const retained = mode === "facade-gc";
  const derivedOnly = mode === "facade-gc-derived";
  const {startPeer} = await import("../utils/network-peer.js");
  const config = applicationConfig();
  const remoteConfig = applicationConfig();
  // Not the unreachable peer's key.
  remoteConfig.identitySecretKey[31] = 3;
  const remote = await startPeer(remoteConfig);
  let deliver;
  const delivered = new Promise((resolve) => {
    deliver = resolve;
  });
  let host = {
    network: null,
    handled: 0,
    capacity: () => ({ordinary: true, serving: 32}),
    // The validation never finishes, so the job's report stays outstanding.
    validate(job) {
      if (retained) deliver({reported: job.reported});
      else if (derivedOnly) {
        // The handoff holds the derivatives and a weak reference, never the report itself.
        const outcome = (promise) => promise.then(
          () => "resolved",
          (error) => error.code
        );
        const derived = [outcome(job.reported), outcome(Promise.all([delay(0), job.reported]))];
        deliver({derived, reported: null, source: new WeakRef(job.reported)});
      } else {
        job.reported.then(() => this.handled++, noop);
        deliver({reported: null});
      }
      return new Promise(() => undefined);
    },
    checkDependencies: (checks) => checks.map(() => false),
    serve: (request) => request.cancel(),
    peers: () => undefined,
    failed: () => undefined,
    logs: () => undefined,
  };
  let network = createNativeNetwork(config, host);
  host.network = network;
  const intent = (value) => ({...localIntent(value), subscriptions: subscriptions(topicName())});
  await network.applyIntent(intent(config), config.initialSlot);
  await remote.applyIntent(intent(remoteConfig), remoteConfig.initialSlot);
  const [identity, remoteIdentity] = await Promise.all([network.getIdentity(), remote.identity]);
  await remote.connect(identity.peerId, [identity.localEndpoint], 5000n);
  await Promise.all([
    remote.addDirectPeer(identity.peerId, [identity.localEndpoint]),
    network.setDirectPeer(remoteIdentity.peerId, [remoteIdentity.localEndpoint]),
  ]);
  await delay(1250);
  const block = new Uint8Array(4000).fill(7);
  new DataView(block.buffer).setBigUint64(100, 100n, true);
  await remote.publishGossip(topicName(), block, {allowZeroPeers: false});
  let {reported, derived, source} = await delivered;
  const report = reported?.then(
    () => "resolved",
    (error) => error.code
  );
  reported = null;
  const closed = network.closed;
  const settlements = new Settlements();
  const unsettled = settlements.unsettledAtClose(closed);
  settlements.watch(() => network.connect(...unreachableConnect()));
  settlements.watch(() =>
    network.publish(topicName(), new Uint8Array(4000), {allowZeroPeers: true, ignoreDuplicate: true})
  );
  const weakNetwork = new WeakRef(network);
  const weakHost = new WeakRef(host);
  network = null;
  host = null;
  for (let i = 0; i < 100; i++) {
    await delay(10);
    global.gc();
    if (!weakNetwork.deref() && !weakHost.deref()) break;
  }
  assert.equal(weakNetwork.deref(), undefined, "Nothing but the host may retain the facade");
  assert.equal(weakHost.deref(), undefined, "Only the facade may retain the host");
  await settlements.settled();
  assert.deepEqual(await closed, {reason: "requested"});
  assert.deepEqual(await unsettled, []);
  assert.deepEqual(settlements.counts, [1, 1]);
  assert.equal(settlements.outcomes[0], "NetworkClosed");
  if (retained) assert.equal(await Promise.race([report, delay(5000, "pending")]), "NetworkClosed");
  if (derivedOnly) {
    const outcomes = await Promise.all(derived.map((promise) => Promise.race([promise, delay(1000, "pending")])));
    derived = null;
    // A report that outlived native close was rejected, and its derivatives with it. Once it was collected they may
    // stay pending, and either outcome is correct.
    if (source.deref() === undefined) assert(outcomes.every((outcome) => outcome === "pending" || outcome === "NetworkClosed"));
    else assert.deepEqual(outcomes, ["NetworkClosed", "NetworkClosed"]);
    console.log(`derived ${outcomes.join(",")}; source ${source.deref() === undefined ? "collected" : "retained"}`);
  }
  await remote.stop();
  await runtimeReleased();
  console.log("facade-collected");
} else if (mode === "orphan") {
  // A host that never exchanges drops its runtime with operations outstanding. The collected wrapper's completion
  // owner stops native and settles them on its own turns, after native's last notification and with no timer left,
  // through as many exchanges of 32 publication completions as it takes.
  const config = applicationConfig();
  config.profile = "beaconNode";
  config.resources.bridgeBudgetBytes = 512 * 1024 * 1024;
  config.resources.nativeBudgetBytes = 512 * 1024 * 1024;
  let runtime = initializeNativeNetworkRuntime(config, noop);
  const outcome = (promise) =>
    promise.then(
      () => "resolved",
      (error) => error.code
    );
  const outcomes = Promise.all([runtime.getIdentity(), runtime.connect(...unreachableConnect())].map(outcome));
  const published = Promise.all(
    Array.from({length: 100}, (_, i) =>
      outcome(
        runtime.publishGossip(topicName(), new Uint8Array(4000).fill(i), {allowZeroPeers: true, ignoreDuplicate: true})
      )
    )
  );
  const closed = runtime.closed;
  const weak = new WeakRef(runtime);
  runtime = null;
  for (let i = 0; i < 100; i++) {
    await delay(10);
    global.gc();
    if (!weak.deref()) break;
  }
  assert.equal(weak.deref(), undefined, "The completion owner must not retain the wrapper");
  assert.deepEqual(await closed, {reason: "requested"});
  const [identity, connect] = await outcomes;
  assert(identity === "resolved" || identity === "NetworkClosed");
  assert.equal(connect, "NetworkClosed");
  assert((await published).every((result) => result === "resolved" || result === "NetworkClosed"));
  console.log("orphan-drained");
} else if (mode === "publication-exit" || mode === "command-exit") {
  // A completed publication or command leaves a running, idle network, which the process exits under without a close.
  const network = createNativeNetwork(applicationConfig(), {
    capacity: () => ({ordinary: true, serving: 32}),
    validate: (job) => Promise.resolve(job.messages.map(() => "ignore")),
    checkDependencies: (checks) => checks.map(() => false),
    serve: (request) => request.cancel(),
    peers: noop,
    failed: noop,
    logs: noop,
  });
  globalThis.retained = network;
  if (mode === "command-exit") {
    assert.equal(typeof (await network.getIdentity()).peerId, "string");
    console.log("commanded-exit");
  } else {
    const published = await network.publish(topicName(), new Uint8Array(4000), {allowZeroPeers: true});
    assert.equal(published.duplicate, false);
    console.log("published-exit");
  }
} else if (mode === "await-close") {
  // Only the notifier ref, taken by close, keeps the loop alive until closed settles.
  const config = applicationConfig();
  const runtime = startRuntime(config);
  await runtime.applyIntent(localIntent(config), config.initialSlot);
  assert.deepEqual(await runtime.close(), {reason: "requested"});
  console.log("close-awaited");
} else if (mode === "callback") {
  const {incomingPair, takeIncoming, BLOCKS} = await import("../utils/network-incoming.js");
  let calls = 0;
  const thrown = new Promise((resolve) =>
    process.on("uncaughtException", (error) => {
      assert.equal(error.message, "ordinary-work-notification-failure");
      resolve(error);
    })
  );
  const pair = await incomingPair(undefined, () => {
    calls++;
    throw new Error("ordinary-work-notification-failure");
  });
  try {
    const request = pair.left.request(pair.remote.peerId, BLOCKS, new Uint8Array(32));
    const response = request.next().catch(() => undefined);
    assert.equal((await thrown).message, "ordinary-work-notification-failure");
    const incoming = await takeIncoming(pair.right);
    await incoming.finish();
    await response;
    assert(calls > 0);
    console.log("callback-closed");
  } finally {
    await Promise.all([pair.left.close(), pair.right.close()]);
  }
} else if (mode === "rearm") {
  // A notifier that throws before scheduling an exchange leaves nothing queued, so a later completion notifies again.
  process.on("uncaughtException", (error) => assert.equal(error.message, "notifier"));
  let notifications = 0;
  const config = applicationConfig();
  const runtime = initializeNativeNetworkRuntime(config, () => {
    notifications++;
    throw new Error("notifier");
  });
  const intent = runtime.applyIntent(localIntent(config), config.initialSlot);
  for (let i = 0; i < 200 && notifications === 0; i++) await delay(10);
  // Owner activity while it starts can notify again; an idle owner has none.
  await delay(100);
  const idle = notifications;
  assert(idle > 0);
  const identity = runtime.getIdentity();
  for (let i = 0; i < 200 && notifications === idle; i++) await delay(10);
  assert(notifications > idle);
  let closed = false;
  void runtime.close().then(() => {
    closed = true;
  });
  for (let i = 0; i < 400 && !closed; i++) {
    runtime.exchange([], settleOnly);
    await delay(5);
  }
  assert.equal((await intent).slot, config.initialSlot);
  assert.equal((await identity).peerId, runtime.identity.peerId);
  console.log("rearmed");
} else throw new Error("Unknown lifecycle scenario");
