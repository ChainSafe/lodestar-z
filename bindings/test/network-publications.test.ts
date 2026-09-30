import {setTimeout as delay} from "node:timers/promises";
import {expect, test, vi} from "vitest";
import {initializeNativeNetworkRuntime} from "../src/network-runtime.js";
import {applicationConfig, holdSettling, localIntent, settleOnly, startRuntime, topicName} from "./utils/network.js";

const BLOCK = topicName();
const SYNC = topicName("sync_committee_0");
const REQUEST = "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy";

test("request capacity refusal is typed while control and publication admission remain available", async () => {
  const config = applicationConfig();
  config.resources.bridgeBudgetBytes = 256 * 1024 * 1024;
  const runtime = startRuntime(config);
  try {
    await runtime.applyIntent(localIntent(config), config.initialSlot);
    const streams: ReturnType<typeof runtime.request>[] = [];
    expect(() => {
      for (let i = 0; i < 1024; i++) streams.push(runtime.request(runtime.identity.peerId, REQUEST, new Uint8Array(0)));
    }).toThrow(expect.objectContaining({code: "NetworkRequestRejected", reason: "slots_exhausted"}));
    await Promise.all([
      runtime.getIdentity(),
      runtime.publishGossip(BLOCK, new Uint8Array(4000), {allowZeroPeers: true}),
      ...streams.map((stream) => expect(stream.next()).rejects.toMatchObject({reason: "disconnected"})),
    ]);
  } finally {
    await runtime.close();
  }
});

test("publication pressure preserves urgent, control and request admission", async () => {
  const config = applicationConfig();
  const runtime = startRuntime(config);
  try {
    await runtime.applyIntent(localIntent(config), config.initialSlot);
    runtime.holdOperations(true);
    const options = {allowZeroPeers: true, ignoreDuplicate: true};
    const publications: Promise<unknown>[] = [];
    let refusal: unknown;
    for (let i = 0; i < 1024 && refusal === undefined; i++) {
      const publication = runtime.publishGossip(SYNC, new Uint8Array(144), options);
      publications.push(publication);
      void publication.catch((error) => {
        refusal = error;
      });
      await Promise.resolve();
    }
    expect(refusal).toMatchObject({code: "NetworkGossipPublishFailed", reason: "admission_full"});
    const urgent = runtime.publishGossip(BLOCK, new Uint8Array(4000), options);
    const control = runtime.getIdentity();
    const request = runtime.request(runtime.identity.peerId, REQUEST, new Uint8Array(0));
    runtime.holdOperations(false);
    const [results] = await Promise.all([
      Promise.allSettled(publications),
      urgent,
      control,
      expect(request.next()).rejects.toMatchObject({code: "NetworkRequestRejected", reason: "disconnected"}),
    ]);
    expect(results.some((result) => result.status === "fulfilled")).toBe(true);
    for (const result of results) {
      if (result.status === "rejected")
        expect(result.reason).toMatchObject({code: "NetworkGossipPublishFailed", reason: "admission_full"});
    }

    await expect(runtime.publishGossip(SYNC, new Uint8Array(144), options)).resolves.toMatchObject({duplicate: true});
  } finally {
    await runtime.close();
  }
});

test("beacon profile admits 200 publications while control remains available", async () => {
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

    await Promise.all([...pending, runtime.getPeers()]);
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
  } finally {
    await runtime.close();
  }
});

test("close settles every pending publication", async () => {
  const config = applicationConfig();
  const runtime = startRuntime(config);
  await runtime.applyIntent(localIntent(config), config.initialSlot);
  const pending = Array.from({length: 16}, () =>
    runtime.publishGossip(BLOCK, new Uint8Array(4000), {allowZeroPeers: true, ignoreDuplicate: true})
  );
  const results = Promise.allSettled(pending);
  await runtime.close();
  for (const result of await results) {
    if (result.status === "rejected") expect(result.reason).toMatchObject({code: "NetworkClosed"});
    else expect(result.value).toMatchObject({queued: 0});
  }
});

test("limited settlement reaches a terminal publication above refilled lower cells", async () => {
  const runtime = initializeNativeNetworkRuntime(applicationConfig(), () => undefined);
  const publish = (fill: number) =>
    runtime.publishGossip(BLOCK, new Uint8Array(4000).fill(fill), {allowZeroPeers: true, ignoreDuplicate: true}).then(
      () => "published",
      (error) => error.code
    );

  let closed = false;
  void runtime.closed.then(() => {
    closed = true;
  });
  const publications = [publish(1), publish(2)];
  const delivered: number[] = [];
  try {
    // Each pass settles one cell; the lowest cell refills before the next pass.
    for (let pass = 0; pass < 2; pass++) {
      await vi.waitFor(() => {
        for (const {handle} of runtime.exchange([], {...settleOnly, settleCells: 1}).completions)
          delivered.push(handle.index);
        expect(delivered).toHaveLength(pass + 1);
      });
      if (pass === 0) publications.push(publish(3));
    }
    // The second pass reached the higher cell although the lowest had refilled.
    expect(delivered).toEqual([0, 1]);
  } finally {
    runtime.close();
    for (let i = 0; i < 400 && !closed; i++) {
      await delay(5);
      for (let pass = 0; pass < 8 && runtime.exchange([], settleOnly).more; pass++);
    }
  }
  expect(await Promise.all(publications)).toEqual(Array(3).fill("published"));
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

test("close settles after every publication and command admitted before it, one completion per family per exchange", async () => {
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
  const delivered: string[][] = [];
  for (let i = 0; i < 400 && !order.includes("closed"); i++) {
    await delay(5);
    delivered.push(runtime.exchange([], {...settleOnly, settleCells: 1}).completions.map(({family}) => family));
  }
  await Promise.all([...operations, closing]);
  expect(order.at(-1)).toBe("closed");
  expect(order.filter((label) => label === "publication")).toHaveLength(4);
  expect(order.filter((label) => label === "command")).toHaveLength(2);
  expect(delivered.every((families) => new Set(families).size === families.length)).toBe(true);
  expect(delivered.flat().sort()).toEqual(["command", "command", ...Array(4).fill("publication")]);
});
