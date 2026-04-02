import {describe, expect, it, beforeEach, afterEach} from "vitest";

// The peerManager binding is registered on the native addon's exports object.
// Import the raw addon to access it.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let bindings: any;

const defaultConfig = {
  targetPeers: 10,
  maxPeers: 15,
  targetGroupPeers: 6,
  pingIntervalInboundMs: 15000,
  pingIntervalOutboundMs: 20000,
  statusIntervalMs: 300000,
  statusInboundGracePeriodMs: 15000,
  gossipsubNegativeScoreWeight: -0.5,
  gossipsubPositiveScoreWeight: 0.5,
  negativeGossipScoreIgnoreThreshold: -100,
  disablePeerScoring: false,
  initialForkName: "deneb",
  numberOfCustodyGroups: 128,
  custodyRequirement: 4,
  samplesPerSlot: 8,
  slotsPerEpoch: 32,
};

const localStatus = {
  forkDigest: new Uint8Array([1, 2, 3, 4]),
  finalizedRoot: new Uint8Array(32).fill(0xaa),
  finalizedEpoch: 100,
  headRoot: new Uint8Array(32).fill(0xbb),
  headSlot: 3200,
};

describe("peerManager", () => {
  beforeEach(async () => {
    bindings = await import("../src/index.js");
    bindings.peerManager.init(defaultConfig);
  });

  afterEach(() => {
    try {
      bindings.peerManager.close();
    } catch {
      // Already closed
    }
  });

  it("init and close without error", () => {
    // init called in beforeEach, close called in afterEach
    expect(bindings.peerManager).toBeDefined();
  });

  it("onConnectionOpen increases peer count", () => {
    const actions = bindings.peerManager.onConnectionOpen("peer1", "outbound");
    expect(Array.isArray(actions)).toBe(true);
    expect(bindings.peerManager.getConnectedPeerCount()).toBe(1);
  });

  it("onConnectionOpen outbound emits ping and status", () => {
    const actions = bindings.peerManager.onConnectionOpen("peer1", "outbound");
    const types = actions.map((a: {type: string}) => a.type);
    expect(types).toContain("send_ping");
    expect(types).toContain("send_status");
  });

  it("onConnectionOpen duplicate is no-op", () => {
    bindings.peerManager.onConnectionOpen("peer1", "outbound");
    const actions = bindings.peerManager.onConnectionOpen("peer1", "outbound");
    expect(actions).toHaveLength(0);
    expect(bindings.peerManager.getConnectedPeerCount()).toBe(1);
  });

  it("onConnectionClose emits disconnect event", () => {
    bindings.peerManager.onConnectionOpen("peer1", "outbound");
    const actions = bindings.peerManager.onConnectionClose("peer1");
    const types = actions.map((a: {type: string}) => a.type);
    expect(types).toContain("emit_peer_disconnected");
    expect(bindings.peerManager.getConnectedPeerCount()).toBe(0);
  });

  it("heartbeat returns action array", () => {
    bindings.peerManager.onConnectionOpen("peer1", "outbound");
    const actions = bindings.peerManager.heartbeat(100, localStatus);
    expect(Array.isArray(actions)).toBe(true);
  });

  it("getPeerScore returns number", () => {
    bindings.peerManager.onConnectionOpen("peer1", "outbound");
    const score = bindings.peerManager.getPeerScore("peer1");
    expect(typeof score).toBe("number");
  });

  it("reportPeer reflects in getPeerScore", () => {
    bindings.peerManager.onConnectionOpen("peer1", "outbound");
    const scoreBefore = bindings.peerManager.getPeerScore("peer1");
    bindings.peerManager.reportPeer("peer1", "MidToleranceError");
    const scoreAfter = bindings.peerManager.getPeerScore("peer1");
    expect(scoreAfter).toBeLessThan(scoreBefore);
  });

  it("getConnectedPeers returns string array", () => {
    bindings.peerManager.onConnectionOpen("peer1", "outbound");
    bindings.peerManager.onConnectionOpen("peer2", "inbound");
    const peers = bindings.peerManager.getConnectedPeers();
    expect(Array.isArray(peers)).toBe(true);
    expect(peers).toHaveLength(2);
    expect(peers).toContain("peer1");
    expect(peers).toContain("peer2");
  });
});
