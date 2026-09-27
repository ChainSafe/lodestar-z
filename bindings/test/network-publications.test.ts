import {setTimeout as delay} from "node:timers/promises";
import {expect, test, vi} from "vitest";
import {initializeNativeNetworkRuntime} from "../src/network-runtime.js";
import {applicationConfig, holdSettling, localIntent, settleOnly, startRuntime, topicName} from "./utils/network.js";
import {startPeer} from "./utils/network-peer.js";

const BLOCK = topicName();
const SYNC = topicName("sync_committee_0");
const REQUEST = "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy";

test("publication byte pressure rejects before copying and keeps ordinary and urgent admission", async () => {
  const config = applicationConfig();
  const probe = await startPeer(config);
  const diagnostics = await probe.diagnostics();
  const {incomingMinimumBytes, outgoingMinimumBytes, publicationMinimumBytes} = diagnostics.payloadBudget;
  await probe.stop();
  config.resources.bridgeBudgetBytes =
    config.resources.bridgeBudgetBytes -
    diagnostics.payloadBudget.limitBytes +
    incomingMinimumBytes +
    outgoingMinimumBytes +
    publicationMinimumBytes +
    7999;
  const runtime = startRuntime(config);
  try {
    await runtime.applyIntent(localIntent(config), config.initialSlot);
    const options = {allowZeroPeers: true, ignoreDuplicate: true};
    // Ordinary publications share only the 7999 bytes past every protected minimum.
    await expect(runtime.publishGossip(SYNC, new Uint8Array(8000).fill(3), options)).rejects.toMatchObject({
      code: "NetworkGossipPublishFailed",
      reason: "admission_full",
    });
    expect(runtime.diagnostics().publications).toMatchObject({byteRefusals: 1n, copies: 0n, occupied: 0});
    await expect(runtime.publishGossip(SYNC, new Uint8Array(144).fill(3), options)).resolves.toMatchObject({
      duplicate: false,
    });
    await expect(runtime.publishGossip(BLOCK, new Uint8Array(8000).fill(3), options)).resolves.toMatchObject({
      duplicate: false,
    });
    expect(runtime.diagnostics().publications).toMatchObject({copies: 2n, occupied: 0, reservedBytes: 0});
    expect(runtime.diagnostics().payloadBudget.usedBytes).toBe(0);
  } finally {
    await runtime.close();
  }
}, 15000);

test("request capacity refusal is typed while control and publication admission remain available", async () => {
  const config = applicationConfig();
  config.resources.bridgeBudgetBytes = 256 * 1024 * 1024;
  const runtime = startRuntime(config);
  try {
    await runtime.applyIntent(localIntent(config), config.initialSlot);
    const streams = Array.from({length: runtime.diagnostics().requests.capacity}, () =>
      runtime.request(runtime.identity.peerId, REQUEST, new Uint8Array(0))
    );
    expect(() => runtime.request(runtime.identity.peerId, REQUEST, new Uint8Array(0))).toThrow(
      expect.objectContaining({code: "NetworkRequestRejected", reason: "slots_exhausted"})
    );
    await Promise.all([
      runtime.getIdentity(),
      runtime.publishGossip(BLOCK, new Uint8Array(4000), {allowZeroPeers: true}),
      ...streams.map((stream) => expect(stream.next()).rejects.toMatchObject({reason: "disconnected"})),
    ]);
    expect(runtime.diagnostics().requests).toMatchObject({occupied: 0, requestFull: 1n, reservedBytes: 0});
  } finally {
    await runtime.close();
  }
});

test("publication pressure preserves urgent, control and request admission", async () => {
  const config = applicationConfig();
  const runtime = startRuntime(config);
  try {
    await runtime.applyIntent(localIntent(config), config.initialSlot);
    const {capacity, urgentReserved} = runtime.diagnostics().publications;
    const options = {allowZeroPeers: true, ignoreDuplicate: true};
    const publications = Array.from({length: capacity - urgentReserved}, () =>
      runtime.publishGossip(SYNC, new Uint8Array(144), options)
    );
    const refused = expect(runtime.publishGossip(SYNC, new Uint8Array(144), options)).rejects.toMatchObject({
      code: "NetworkGossipPublishFailed",
      reason: "admission_full",
    });
    publications.push(
      ...Array.from({length: urgentReserved}, () => runtime.publishGossip(BLOCK, new Uint8Array(4000), options))
    );
    const controls = Array.from({length: 32}, () => runtime.getIdentity());
    const request = runtime.request(runtime.identity.peerId, REQUEST, new Uint8Array(0));
    expect(runtime.diagnostics()).toMatchObject({
      operationOccupied: 32,
      publications: {occupied: capacity, refusals: 1n},
      requests: {occupied: 1},
    });
    await Promise.all([
      refused,
      ...publications,
      ...controls,
      expect(request.next()).rejects.toMatchObject({code: "NetworkRequestRejected", reason: "disconnected"}),
    ]);
    expect(runtime.diagnostics()).toMatchObject({
      operationOccupied: 0,
      publications: {latencyCount: BigInt(capacity), occupied: 0, payloadBytes: 0, reservedBytes: 0},
      requests: {occupied: 0},
    });
    await expect(runtime.publishGossip(SYNC, new Uint8Array(144), options)).resolves.toMatchObject({duplicate: true});
  } finally {
    await runtime.close();
  }
});

test("beacon profile admits 200 publications without occupying control cells", async () => {
  const config = applicationConfig();
  config.profile = "beaconNode";
  config.resources.bridgeBudgetBytes = 512 * 1024 * 1024;
  config.resources.nativeBudgetBytes = 512 * 1024 * 1024;
  const runtime = startRuntime(config);
  try {
    await runtime.applyIntent(localIntent(config), config.initialSlot);
    const pending = Array.from({length: 200}, () =>
      runtime.publishGossip(BLOCK, new Uint8Array(4000), {allowZeroPeers: true, ignoreDuplicate: true})
    );
    expect(runtime.diagnostics()).toMatchObject({
      operationOccupied: 0,
      publications: {capacity: 256, highWater: 200, occupied: 200},
    });
    await Promise.all([...pending, runtime.getPeers()]);
    expect(runtime.diagnostics().publications).toMatchObject({
      copies: 200n,
      latencyCount: 200n,
      occupied: 0,
      payloadBytes: 0,
      reservedBytes: 0,
    });
  } finally {
    await runtime.close();
  }
});

test("publication turns make progress on payloads larger than the turn byte budget", async () => {
  const config = applicationConfig();
  const runtime = startRuntime(config);
  try {
    await runtime.applyIntent(localIntent(config), config.initialSlot);
    await Promise.all(
      [3 * 1024 * 1024, 3 * 1024 * 1024, 4000].map((size) =>
        runtime.publishGossip(BLOCK, new Uint8Array(size), {allowZeroPeers: true, ignoreDuplicate: true})
      )
    );
    expect(runtime.diagnostics().publications).toMatchObject({latencyCount: 3n, occupied: 0, reservedBytes: 0});
  } finally {
    await runtime.close();
  }
});

test("close settles every publication and releases its payload and result cells", async () => {
  const config = applicationConfig();
  const runtime = startRuntime(config);
  await runtime.applyIntent(localIntent(config), config.initialSlot);
  const pending = Array.from({length: runtime.diagnostics().publications.capacity}, () =>
    runtime.publishGossip(BLOCK, new Uint8Array(4000), {allowZeroPeers: true, ignoreDuplicate: true})
  );
  const results = Promise.allSettled(pending);
  await runtime.close();
  for (const result of await results) {
    if (result.status === "rejected") expect(result.reason).toMatchObject({code: "NetworkClosed"});
    else expect(result.value).toMatchObject({queued: 0});
  }
  expect(runtime.diagnostics()).toMatchObject({
    copyingPins: 0,
    operationOccupied: 0,
    preparingPins: 0,
    publications: {occupied: 0, payloadBytes: 0, reservedBytes: 0},
  });
});

test("limited settlement reaches a terminal publication above refilled lower cells", async () => {
  const runtime = initializeNativeNetworkRuntime(applicationConfig(), () => undefined);
  const publish = (fill: number) =>
    runtime.publishGossip(BLOCK, new Uint8Array(4000).fill(fill), {allowZeroPeers: true, ignoreDuplicate: true});
  const executed = () => vi.waitFor(() => expect(runtime.diagnostics().publications.payloadBytes).toBe(0));
  let closed = false;
  void runtime.closed.then(() => {
    closed = true;
  });
  let high = false;
  const publications = [
    publish(1),
    publish(2).then(() => {
      high = true;
    }),
  ];
  try {
    // Each pass settles one cell; the lowest cell then refills and completes before the next pass.
    for (let pass = 0; pass < 2; pass++) {
      await executed();
      runtime.exchange([], {...settleOnly, settleCells: 1});
      publications.push(publish(3 + pass));
    }
    await executed();
    expect(high).toBe(true);
  } finally {
    runtime.close();
    for (let i = 0; i < 400 && !closed; i++) {
      await delay(5);
      for (let pass = 0; pass < 8 && runtime.exchange([], settleOnly).more; pass++);
    }
  }
  await Promise.all(publications);
  expect(await runtime.closed).toEqual({reason: "requested"});
});

test("a completion delivered in the job that admitted its publication settles the record installed there", async () => {
  const runtime = startRuntime(applicationConfig());
  try {
    const published = runtime.publishGossip(BLOCK, new Uint8Array(4000), {allowZeroPeers: true});
    // Without yielding, exchange until the owner has published it, so its completion is the earliest possible.
    let delivered = 0;
    for (let i = 0; i < 1_000_000 && delivered === 0; i++)
      delivered = runtime.exchange([], settleOnly).completions.length;
    expect(delivered).toBe(1);
    await expect(published).resolves.toMatchObject({duplicate: false});
  } finally {
    await runtime.close();
  }
});

test("close settles after every publication and command admitted before it, one completion per exchange", async () => {
  const runtime = startRuntime(applicationConfig());
  holdSettling(runtime, true);
  const order: string[] = [];
  const record = (promise: Promise<unknown>, label: string) =>
    promise.then(
      () => order.push(label),
      () => order.push(label)
    );
  const options = {allowZeroPeers: true, ignoreDuplicate: true};
  const operations = [
    ...Array.from({length: 4}, (_, i) =>
      record(runtime.publishGossip(BLOCK, new Uint8Array(4000).fill(i), options), "publication")
    ),
    record(runtime.getIdentity(), "command"),
    record(runtime.getPeers(), "command"),
  ];
  const closing = record(runtime.close(), "closed");
  const delivered: number[] = [];
  for (let i = 0; i < 400 && !order.includes("closed"); i++) {
    await delay(5);
    delivered.push(runtime.exchange([], {...settleOnly, settleCells: 1}).completions.length);
  }
  await Promise.all([...operations, closing]);
  expect(order.at(-1)).toBe("closed");
  expect(order.filter((label) => label === "publication")).toHaveLength(4);
  expect(delivered.every((count) => count <= 1)).toBe(true);
  expect(delivered.reduce((sum, count) => sum + count, 0)).toBe(4);
});
