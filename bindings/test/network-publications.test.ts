import {expect, test} from "vitest";
import {applicationConfig, localIntent, startRuntime, topicName} from "./utils/network.js";
import {networkBindings} from "./utils/network-bindings.js";
import {startPeer} from "./utils/network-peer.js";

const BLOCK = topicName();
const SYNC = topicName("sync_committee_0");
const REQUEST = "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy";

test("publication byte pressure rejects before copying and permits retry after credit returns", async () => {
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
    const options = {allowZeroPeers: true, ignoreDuplicate: true};
    let refused: Promise<unknown> | undefined;
    let second: Promise<unknown> | undefined;
    const chunk = publicationMinimumBytes / 2;
    await runtime.publishGossip(BLOCK, new Uint8Array(chunk).fill(1), {
      ...options,
      get flood() {
        second = runtime.publishGossip(BLOCK, new Uint8Array(chunk).fill(2), {
          ...options,
          get flood() {
            refused = runtime
              .publishGossip(BLOCK, new Uint8Array(8000).fill(3), options)
              .catch((error: unknown) => error);
            return false;
          },
        });
        return false;
      },
    });
    await second;
    expect(await refused).toMatchObject({code: "NetworkGossipPublishFailed", reason: "admission_full"});
    expect(runtime.diagnostics().publications).toMatchObject({byteRefusals: 1n, copies: 2n, occupied: 0});
    await expect(runtime.publishGossip(BLOCK, new Uint8Array(8000).fill(3), options)).resolves.toMatchObject({
      duplicate: false,
    });
    expect(runtime.diagnostics().publications).toMatchObject({copies: 3n, occupied: 0, reservedBytes: 0});
    expect(runtime.diagnostics().payloadBudget.usedBytes).toBe(0);
  } finally {
    await runtime.close();
  }
});

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

test.skipIf(!networkBindings.networkTestFail)(
  "publication result copy failure retires only that publication",
  async () => {
    const config = applicationConfig();
    const runtime = startRuntime(config);
    try {
      await runtime.applyIntent(localIntent(config), config.initialSlot);
      networkBindings.networkTestFail("operation_copy");
      await expect(runtime.publishGossip(BLOCK, new Uint8Array(4000), {allowZeroPeers: true})).rejects.toMatchObject({
        code: "NetworkResultAllocationFailed",
      });
      expect(runtime.state).toBe("running");
      await expect(
        runtime.publishGossip(BLOCK, new Uint8Array(4000), {allowZeroPeers: true, ignoreDuplicate: true})
      ).resolves.toBeDefined();
      expect(runtime.diagnostics()).toMatchObject({
        copyingPins: 0,
        publications: {occupied: 0, payloadBytes: 0, reservedBytes: 0},
      });
    } finally {
      await runtime.close();
    }
  }
);

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
