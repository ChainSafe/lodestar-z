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
  gossipsubNegativeScoreWeight: 0.001,
  gossipsubPositiveScoreWeight: 0.001,
  negativeGossipScoreIgnoreThreshold: -1000,
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
    bindings = (await import("../src/index.js")).default;
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

  it("onConnectionOpen second connection updates direction without adding a peer", () => {
    bindings.peerManager.onConnectionOpen("peer1", "inbound");
    // Our outbound dial to an already-inbound peer: direction is overwritten and
    // the outbound connection triggers an immediate handshake.
    const actions = bindings.peerManager.onConnectionOpen("peer1", "outbound");
    const types = actions.map((a: {type: string}) => a.type);
    expect(types).toContain("send_ping");
    expect(types).toContain("send_status");
    expect(bindings.peerManager.getConnectedPeerCount()).toBe(1);

    // A later inbound connection overwrites direction without a handshake.
    const actions2 = bindings.peerManager.onConnectionOpen("peer1", "inbound");
    expect(actions2).toHaveLength(0);
  });

  it("onConnectionClose emits disconnect event", () => {
    bindings.peerManager.onConnectionOpen("peer1", "outbound");
    const actions = bindings.peerManager.onConnectionClose("peer1");
    const types = actions.map((a: {type: string}) => a.type);
    expect(types).toContain("emit_peer_disconnected");
    expect(bindings.peerManager.getConnectedPeerCount()).toBe(0);
  });

  it("onConnectionClose only tears down on the last connection", () => {
    bindings.peerManager.onConnectionOpen("peer1", "inbound");
    bindings.peerManager.onConnectionOpen("peer1", "outbound");

    // First close: another connection is still open → no disconnect event.
    const first = bindings.peerManager.onConnectionClose("peer1");
    expect(first.map((a: {type: string}) => a.type)).not.toContain("emit_peer_disconnected");
    expect(bindings.peerManager.getConnectedPeerCount()).toBe(1);

    // Second close: last connection → disconnect event, peer removed.
    const second = bindings.peerManager.onConnectionClose("peer1");
    expect(second.map((a: {type: string}) => a.type)).toContain("emit_peer_disconnected");
    expect(bindings.peerManager.getConnectedPeerCount()).toBe(0);
  });

  it("heartbeat returns action array", () => {
    bindings.peerManager.onConnectionOpen("peer1", "outbound");
    const actions = bindings.peerManager.heartbeat(100, localStatus);
    expect(Array.isArray(actions)).toBe(true);
  });

  it("scrapes peer manager heartbeat_duration and starved metrics", () => {
    bindings.metrics.init();
    bindings.peerManager.onConnectionOpen("peer1", "outbound");
    bindings.peerManager.heartbeat(100, localStatus);
    const scraped = bindings.metrics.scrapeMetrics();
    expect(scraped).toContain("lodestar_peer_manager_heartbeat_duration_seconds");
    expect(scraped).toContain("lodestar_peer_manager_starved_bool");
  });

  it("reStatusPeers forces a status request for a not-yet-due peer", () => {
    // A freshly-connected inbound peer is not yet due for a status request.
    bindings.peerManager.onConnectionOpen("peer1", "inbound");
    const before = bindings.peerManager.checkPingAndStatus();
    expect(before.map((a: {type: string}) => a.type)).not.toContain("send_status");

    const actions = bindings.peerManager.reStatusPeers(["peer1"]);
    expect(actions.map((a: {type: string}) => a.type)).toContain("send_status");
  });

  it("goodbyeAndDisconnectAllPeers emits goodbye + disconnect for every peer", () => {
    bindings.peerManager.onConnectionOpen("peer1", "outbound");
    bindings.peerManager.onConnectionOpen("peer2", "inbound");
    const types = bindings.peerManager.goodbyeAndDisconnectAllPeers().map((a: {type: string}) => a.type);
    expect(types.filter((t: string) => t === "send_goodbye")).toHaveLength(2);
    expect(types.filter((t: string) => t === "disconnect_peer")).toHaveLength(2);
  });

  it("reconcileConnectedPeers prunes leaked store entries", () => {
    bindings.peerManager.onConnectionOpen("peer1", "outbound");
    bindings.peerManager.onConnectionOpen("peer2", "outbound");
    bindings.peerManager.onConnectionOpen("peer3", "outbound");

    // Within threshold → nothing pruned.
    expect(bindings.peerManager.reconcileConnectedPeers(["peer1", "peer2", "peer3"])).toBe(0);
    expect(bindings.peerManager.getConnectedPeerCount()).toBe(3);

    // Only one really connected → the two leaked entries are pruned.
    expect(bindings.peerManager.reconcileConnectedPeers(["peer2"])).toBe(2);
    expect(bindings.peerManager.getConnectedPeers()).toEqual(["peer2"]);
  });

  it("heartbeat discovery includes custody group queries when sampling groups are set", () => {
    bindings.peerManager.setSamplingGroups([0, 1, 2]);
    const actions = bindings.peerManager.heartbeat(100, localStatus);
    const discovery = actions.find((a: {type: string}) => a.type === "request_discovery");
    expect(discovery).toBeDefined();
    expect(Array.isArray(discovery.custodyGroupQueries)).toBe(true);
    expect(discovery.custodyGroupQueries.length).toBeGreaterThan(0);
  });

  it("onMetadataReceived returns a status re-request when custody group count changes", () => {
    bindings.peerManager.onConnectionOpen("peer1", "outbound");
    const meta = (seqNumber: number, custodyGroupCount: number) => ({
      seqNumber,
      attnets: new Uint8Array(8),
      syncnets: new Uint8Array(1),
      custodyGroupCount,
      custodyGroups: [0, 1, 2, 3],
      samplingGroups: [0, 1, 2, 3, 4, 5, 6, 7],
    });

    // First metadata → status re-request.
    const first = bindings.peerManager.onMetadataReceived("peer1", meta(1, 4));
    expect(first.map((a: {type: string}) => a.type)).toContain("send_status");
    // Same custody group count → no re-request.
    expect(bindings.peerManager.onMetadataReceived("peer1", meta(2, 4))).toHaveLength(0);
    // Changed custody group count → status re-request.
    const changed = bindings.peerManager.onMetadataReceived("peer1", meta(3, 8));
    expect(changed.map((a: {type: string}) => a.type)).toContain("send_status");
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

  it("onConnectionOpen rejects an unknown direction", () => {
    expect(() => bindings.peerManager.onConnectionOpen("peer1", "sideways")).toThrow();
  });

  it("setForkName rejects an unknown fork name", () => {
    expect(() => bindings.peerManager.setForkName("notafork")).toThrow();
  });

  it("init rejects a negative gossip score weight", () => {
    bindings.peerManager.close();
    expect(() => bindings.peerManager.init({...defaultConfig, gossipsubNegativeScoreWeight: -0.5})).toThrow();
  });

  it("reportPeer rejects an unknown action", () => {
    bindings.peerManager.onConnectionOpen("peer1", "outbound");
    expect(() => bindings.peerManager.reportPeer("peer1", "NotARealAction")).toThrow();
  });

  it("onGoodbye tolerates negative pseudo-codes (INBOUND_DISCONNECT = -1)", () => {
    bindings.peerManager.onConnectionOpen("peer1", "outbound");
    const actions = bindings.peerManager.onGoodbye("peer1", -1);
    expect(Array.isArray(actions)).toBe(true);
    const types = actions.map((a: {type: string}) => a.type);
    expect(types).toContain("disconnect_peer");
  });

  it("onStatusReceived rejects a negative headSlot instead of crashing", () => {
    bindings.peerManager.onConnectionOpen("peer1", "outbound");
    const badStatus = {...localStatus, headSlot: -1};
    expect(() => bindings.peerManager.onStatusReceived("peer1", badStatus, localStatus, 100)).toThrow();
  });

  it("onMetadataReceived rejects a negative seqNumber instead of crashing", () => {
    bindings.peerManager.onConnectionOpen("peer1", "outbound");
    const badMetadata = {
      seqNumber: -1,
      attnets: new Uint8Array(8),
      syncnets: new Uint8Array(1),
      custodyGroupCount: 4,
    };
    expect(() => bindings.peerManager.onMetadataReceived("peer1", badMetadata)).toThrow();
  });

  it("onMetadataReceived for an untracked peer does not throw", () => {
    const metadata = {
      seqNumber: 1,
      attnets: new Uint8Array(8),
      syncnets: new Uint8Array(1),
      custodyGroupCount: 4,
      custodyGroups: [0, 1, 2, 3],
      samplingGroups: [0, 1, 2, 3, 4, 5, 6, 7],
    };
    expect(() => bindings.peerManager.onMetadataReceived("unknown-peer", metadata)).not.toThrow();
    expect(bindings.peerManager.getConnectedPeerCount()).toBe(0);
  });
});
