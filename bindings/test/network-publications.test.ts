import {setTimeout as delay} from "node:timers/promises";
import {expect, test, vi} from "vitest";
import {
  applicationConfig,
  exchange,
  holdSettling,
  localIntent,
  settleOnly,
  startRuntime,
  topicName,
} from "./utils/network.js";
import {initializeNativeNetworkRuntime} from "./utils/network-runtime.js";

const BLOCK = topicName();
const SYNC = topicName("sync_committee_0");
const REQUEST = "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy";

test("request capacity refusal is typed while control and publication admission remain available", async () => {
  const config = applicationConfig();
  config.resources.bridgeBudgetBytes = 256 * 1024 * 1024;
  const runtime = startRuntime(config);
  try {
    await runtime.applyIntent(localIntent(config));
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
    await runtime.applyIntent(localIntent(config));
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

test("network admits 200 publications while control remains available", async () => {
  const config = applicationConfig();
  config.resources.bridgeBudgetBytes = 512 * 1024 * 1024;
  config.resources.nativeBudgetBytes = 512 * 1024 * 1024;
  const runtime = startRuntime(config);
  try {
    await runtime.applyIntent(localIntent(config));
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
    await runtime.applyIntent(localIntent(config));
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
  await runtime.applyIntent(localIntent(config));
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

test("native-owned publication Promises settle without completion envelopes", async () => {
  const runtime = initializeNativeNetworkRuntime(applicationConfig(), () => undefined);
  const delivered: number[] = [];
  const publish = (fill: number) =>
    runtime.publishGossip(BLOCK, new Uint8Array(4000).fill(fill), {allowZeroPeers: true, ignoreDuplicate: true}).then(
      () => {
        delivered.push(fill);
        return "published";
      },
      (error) => error.code
    );

  let closed = false;
  void runtime.closed.then(() => {
    closed = true;
  });
  const publications = [publish(1), publish(2)];
  try {
    await vi.waitFor(() => {
      runtime.exchange();
      expect(delivered).toHaveLength(2);
    });
    expect(delivered).toEqual([1, 2]);
    publications.push(publish(3));
    await vi.waitFor(() => {
      runtime.exchange();
      expect(delivered).toHaveLength(3);
    });
    expect(delivered).toEqual([1, 2, 3]);
  } finally {
    runtime.close();
    for (let i = 0; i < 400 && !closed; i++) {
      await delay(5);
      for (let pass = 0; pass < 8 && exchange(runtime, settleOnly).needsAnotherExchange; pass++);
    }
  }
  expect(await Promise.all(publications)).toEqual(Array(3).fill("published"));
  expect(await runtime.closed).toEqual({reason: "requested"});
});

test("close settles after every publication and command without exposing their completions", async () => {
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
  for (let i = 0; i < 400 && !order.includes("closed"); i++) {
    await delay(5);
    runtime.exchange();
  }
  await Promise.all([...operations, closing]);
  expect(order.at(-1)).toBe("closed");
  expect(order.filter((label) => label === "publication")).toHaveLength(4);
  expect(order.filter((label) => label === "command")).toHaveLength(2);
});
