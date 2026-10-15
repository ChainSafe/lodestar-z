import {createHook} from "node:async_hooks";
import {expect, test, vi} from "vitest";
import {applicationConfig, localIntent, startRuntime, unreachableConnect} from "./utils/network.js";
import {type PeerRuntime, startPeer} from "./utils/network-peer.js";
import type {NetworkTestRuntime} from "./utils/network-runtime.js";

test("every command kind completes with its typed result", async () => {
  const config = applicationConfig();
  const remoteConfig = applicationConfig();
  remoteConfig.identitySecretKey[31] = 2;
  const runtime = startRuntime(config);
  let remote: PeerRuntime | undefined;
  try {
    remote = await startPeer(remoteConfig);
    const peer = await remote.identity;
    await remote.applyIntent(localIntent(remoteConfig));
    expect(await runtime.applyIntent(localIntent(config))).toBeUndefined();
    expect(await runtime.updateStatus(config.local.status)).toBeUndefined();
    expect(await runtime.getIdentity()).toMatchObject(runtime.identity);
    expect(await runtime.connect(peer.peerId, [peer.localEndpoint], 5000n)).toBeUndefined();
    await vi.waitFor(async () => expect((await runtime.getPeers()).counts.connected).toBe(1));
    expect(await runtime.getPeers()).toMatchObject({
      counts: {connected: 1},
      peers: [expect.objectContaining({identity: peer.peerId})],
    });
    expect(await runtime.getGossipDiagnostics(0)).toMatchObject({
      observedMonoMs: expect.any(BigInt),
      peers: expect.any(Array),
      topics: expect.any(Array),
    });
    expect(await runtime.reStatusPeers([peer.peerId])).toBeUndefined();
    expect(await runtime.addDirectPeer(peer.peerId, [peer.localEndpoint])).toBeUndefined();
    expect(await runtime.getDirectPeers()).toEqual([peer.peerId]);
    expect(await runtime.removeDirectPeer(peer.peerId)).toBe(true);
    expect(await runtime.disconnect(peer.peerId)).toBeUndefined();
  } finally {
    await Promise.all([runtime.close(), remote?.stop()]);
  }
}, 20000);

type Command = (runtime: NetworkTestRuntime) => Promise<unknown>;

/** Diagnostics share one result buffer, so exercise the two query kinds separately. */
function commands(): [string, [string, Command][]][] {
  const config = applicationConfig();
  const [peer, endpoints] = unreachableConnect();
  return [
    [
      "mutations and gossip diagnostics",
      [
        ["applyIntent", (runtime) => runtime.applyIntent(localIntent(config))],
        ["updateStatus", (runtime) => runtime.updateStatus(config.local.status)],
        ["getMetrics", (runtime) => runtime.getMetrics()],
        ["getGossipDiagnostics", (runtime) => runtime.getGossipDiagnostics(0)],
        ["connect", (runtime) => runtime.connect(peer, endpoints, 60000n)],
        ["disconnect", (runtime) => runtime.disconnect(peer)],
        ["reStatusPeers", (runtime) => runtime.reStatusPeers([peer])],
        ["addDirectPeer", (runtime) => runtime.addDirectPeer(peer, endpoints)],
        ["removeDirectPeer", (runtime) => runtime.removeDirectPeer(peer)],
      ],
    ],
    ["peer score diagnostics", [["getPeerScores", (runtime) => runtime.getPeerScores()]]],
  ];
}

test.each(commands())("%s, held unstarted at close, settle without executing", async (_, kinds) => {
  const runtime = startRuntime(applicationConfig());
  // Held, the owner starts none of them, so the close cancels each one queued.
  runtime.holdOperations(true);
  const outcomes = kinds.map(([kind, command]) =>
    command(runtime).then(
      () => `${kind} resolved`,
      (error) => `${kind} ${error.code}`
    )
  );
  const closed = runtime.close();
  expect(await Promise.all(outcomes)).toEqual(kinds.map(([kind]) => `${kind} NetworkClosed`));
  expect(await closed).toEqual({reason: "requested"});
});

test("ordinary command pressure preserves one local-state admission", async () => {
  const config = applicationConfig();
  const runtime = startRuntime(config);
  try {
    const admitted = Array.from({length: 31}, () => runtime.getMetrics());
    expect(() => runtime.getMetrics()).toThrow("NetworkCommandFull");
    const state = runtime.applyIntent(localIntent(config));
    const refused = expect(runtime.applyIntent(localIntent(config))).rejects.toThrow("NetworkCommandFull");

    await Promise.all([...admitted, state, refused]);
    expect((await runtime.getIdentity()).peerId).toBe(runtime.identity.peerId);
  } finally {
    // A refused command left no record, so the close result finds none missing.
    expect(await runtime.close()).toEqual({reason: "requested"});
  }
});

test("a direct peer list remains independent of later membership changes", async () => {
  const runtime = startRuntime(applicationConfig());
  try {
    const [peer, endpoints] = unreachableConnect();
    await runtime.addDirectPeer(peer, endpoints);
    const first = await runtime.getDirectPeers();
    expect(await runtime.removeDirectPeer(peer)).toBe(true);
    const second = await runtime.getDirectPeers();
    expect(first).toEqual([peer]);
    expect(second).toEqual([]);
  } finally {
    await runtime.close();
  }
});

test("close during native Promise creation refuses admission without leaving an operation", async () => {
  const runtime = startRuntime(applicationConfig());
  let closedDuringCreation = false;
  const hook = createHook({
    init(_id, type) {
      if (type !== "PROMISE" || closedDuringCreation) return;
      closedDuringCreation = true;
      runtime.close();
    },
  });
  try {
    hook.enable();
    expect(() => runtime.reStatusPeers([])).toThrow("NetworkClosed");
  } finally {
    hook.disable();
    expect(await runtime.close()).toEqual({reason: "requested"});
  }
  expect(closedDuringCreation).toBe(true);
});
