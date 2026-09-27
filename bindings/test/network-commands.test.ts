import {expect, test} from "vitest";
import type {NativeNetworkApplicationRuntime} from "../src/network-runtime.js";
import {applicationConfig, localIntent, startRuntime, topicName, unreachableConnect} from "./utils/network.js";
import {startPeer} from "./utils/network-peer.js";

const PUBLISH = {allowZeroPeers: true, ignoreDuplicate: true};

test("every command kind completes with its typed result", async () => {
  const config = applicationConfig();
  const remoteConfig = applicationConfig();
  remoteConfig.identitySecretKey[31] = 2;
  const runtime = startRuntime(config);
  const remote = await startPeer(remoteConfig);
  try {
    const peer = await remote.identity;
    await remote.applyIntent(localIntent(remoteConfig), 100n);
    const sequence = expect.any(BigInt);
    expect(await runtime.applyIntent(localIntent(config), 100n)).toEqual({
      changed: expect.any(Boolean),
      ownerSequence: sequence,
      slot: 100n,
    });
    expect(await runtime.updateStatus(config.local.status)).toBeUndefined();
    expect(await runtime.getIdentity()).toMatchObject({...runtime.identity, ownerSequence: sequence});
    expect(await runtime.connect(peer.peerId, [peer.localEndpoint], 5000n)).toBeUndefined();
    expect(await runtime.getPeers()).toMatchObject({
      capacity: expect.any(Number),
      counts: {connected: 1},
      occupiedCount: 1,
      ownerSequence: sequence,
      peers: [expect.objectContaining({identity: peer.peerId})],
    });
    expect(await runtime.getGossipDiagnostics(0)).toMatchObject({
      observedMonoMs: sequence,
      ownerSequence: sequence,
      peers: expect.any(Array),
      topics: expect.any(Array),
    });
    expect(await runtime.reStatusPeers([peer.peerId])).toBeUndefined();
    expect(await runtime.addDirectPeer(peer.peerId, [peer.localEndpoint])).toBeUndefined();
    expect(await runtime.getDirectPeers()).toEqual({identities: [peer.peerId], ownerSequence: sequence});
    expect(await runtime.removeDirectPeer(peer.peerId)).toBe(true);
    expect(await runtime.getRememberedPeers()).toMatchObject({
      genesisValidatorsRoot: expect.any(Uint8Array),
      ownerSequence: sequence,
      peers: expect.any(Array),
    });
    expect(await runtime.disconnect(peer.peerId)).toBeUndefined();
  } finally {
    await Promise.all([runtime.close(), remote.close()]);
  }
}, 20000);

type Command = (runtime: NativeNetworkApplicationRuntime) => Promise<unknown>;

/** Each command kind with valid input, split so the snapshot kinds fit the two snapshot stores. */
function commands(): [string, [string, Command][]][] {
  const config = applicationConfig();
  const [peer, endpoints] = unreachableConnect();
  return [
    [
      "ten kinds",
      [
        ["applyIntent", (runtime) => runtime.applyIntent(localIntent(config), 100n)],
        ["updateStatus", (runtime) => runtime.updateStatus(config.local.status)],
        ["getIdentity", (runtime) => runtime.getIdentity()],
        ["getPeers", (runtime) => runtime.getPeers()],
        ["getGossipDiagnostics", (runtime) => runtime.getGossipDiagnostics(0)],
        ["connect", (runtime) => runtime.connect(peer, endpoints, 60000n)],
        ["disconnect", (runtime) => runtime.disconnect(peer)],
        ["reStatusPeers", (runtime) => runtime.reStatusPeers([peer])],
        ["addDirectPeer", (runtime) => runtime.addDirectPeer(peer, endpoints)],
        ["removeDirectPeer", (runtime) => runtime.removeDirectPeer(peer)],
      ],
    ],
    [
      "the other two snapshot kinds",
      [
        ["getDirectPeers", (runtime) => runtime.getDirectPeers()],
        ["getRememberedPeers", (runtime) => runtime.getRememberedPeers()],
      ],
    ],
  ];
}

test.each(commands())(
  "%s, queued behind slow publications at close, each reject with NetworkClosed",
  async (_, kinds) => {
    const config = applicationConfig();
    config.resources.bridgeBudgetBytes = 512 * 1024 * 1024;
    const runtime = startRuntime(config);
    // The owner runs work in admission order, so publications it takes milliseconds each to publish hold the commands
    // queued until the close in this same job cancels them.
    const publications = Array.from({length: 4}, (_, i) =>
      runtime.publishGossip(topicName(), new Uint8Array(8 * 1024 * 1024).fill(i + 1), PUBLISH).catch(() => undefined)
    );
    const outcomes = kinds.map(([kind, command]) =>
      command(runtime).then(
        () => `${kind} resolved`,
        (error) => `${kind} ${error.code}`
      )
    );
    const closed = runtime.close();
    expect(await Promise.all(outcomes)).toEqual(kinds.map(([kind]) => `${kind} NetworkClosed`));
    await Promise.all([closed, ...publications]);
  },
  20000
);

test("a full command table refuses admission without a record: a throw, and a rejection from applyIntent", async () => {
  const config = applicationConfig();
  const runtime = startRuntime(config);
  try {
    const admitted = Array.from({length: 32}, () => runtime.getIdentity());
    expect(() => runtime.getIdentity()).toThrow("NetworkCommandFull");
    await expect(runtime.applyIntent(localIntent(config), 100n)).rejects.toThrow("NetworkCommandFull");
    expect(runtime.diagnostics().operationOccupied).toBe(32);
    await Promise.all(admitted);
    expect((await runtime.getIdentity()).peerId).toBe(runtime.identity.peerId);
  } finally {
    // A refused command left no record, so the close result finds none missing.
    expect(await runtime.close()).toEqual({reason: "requested"});
  }
});

test("a delivered snapshot keeps its contents while its cell and store serve the next command", async () => {
  const runtime = startRuntime(applicationConfig());
  try {
    const [peer, endpoints] = unreachableConnect();
    await runtime.addDirectPeer(peer, endpoints);
    const first = await runtime.getDirectPeers();
    expect(await runtime.removeDirectPeer(peer)).toBe(true);
    const second = await runtime.getDirectPeers();
    expect(first.identities).toEqual([peer]);
    expect(second.identities).toEqual([]);
    expect(second.ownerSequence).toBeGreaterThan(first.ownerSequence);
  } finally {
    await runtime.close();
  }
});

test("commands and publications execute in their admission order across families", async () => {
  const runtime = startRuntime(applicationConfig());
  try {
    const first = runtime.getIdentity();
    const publications = [1, 2, 3].map((fill) =>
      runtime.publishGossip(topicName(), new Uint8Array(4000).fill(fill), PUBLISH)
    );
    const last = runtime.getIdentity();
    const [before, after] = await Promise.all([first, last]);
    await Promise.all(publications);
    // Each execution advances the owner's sequence, so the three publications ran between the two commands.
    expect(after.ownerSequence - before.ownerSequence).toBeGreaterThanOrEqual(4n);
  } finally {
    await runtime.close();
  }
});
