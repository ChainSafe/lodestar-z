const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("types.zig");

const PeerData = types.PeerData;
const Direction = types.Direction;
const Status = types.Status;
const Metadata = types.Metadata;
const Encoding = types.Encoding;
const Config = types.Config;
const ClientKind = types.ClientKind;
const getKnownClientFromAgentVersion = types.getKnownClientFromAgentVersion;

pub const PeerStore = struct {
    allocator: Allocator,
    peers: std.StringHashMap(PeerData),

    pub fn init(allocator: Allocator) PeerStore {
        return .{
            .allocator = allocator,
            .peers = std.StringHashMap(PeerData).init(allocator),
        };
    }

    pub fn deinit(self: *PeerStore) void {
        var iter = self.peers.iterator();
        while (iter.next()) |entry| {
            freePeerOwnedData(self.allocator, entry.value_ptr);
            self.allocator.free(entry.key_ptr.*);
        }
        self.peers.deinit();
    }

    // --- Lifecycle ---

    pub const AddPeerError = error{
        PeerAlreadyExists,
        OutOfMemory,
    };

    /// Adds a peer with direction-dependent initial timestamps.
    /// Outbound: last_received_msg = 0, last_status = 0.
    /// Inbound: last_received_msg = now_ms,
    ///   last_status = now_ms - status_interval + grace_period.
    pub fn addPeer(
        self: *PeerStore,
        peer_id: []const u8,
        direction: Direction,
        now_ms: i64,
        config: Config,
    ) AddPeerError!void {
        // Use getOrPut to avoid double lookup and unnecessary allocation.
        const entry = try self.peers.getOrPut(peer_id); // This will allocate if not exists
        if (entry.found_existing) return error.PeerAlreadyExists;

        const owned_key = entry.key_ptr.*; // getOrPut already assigned the key
        errdefer self.allocator.free(owned_key);

        const last_received: i64 = switch (direction) {
            .outbound => 0,
            .inbound => now_ms,
        };
        const last_status: i64 = switch (direction) {
            .outbound => 0,
            .inbound => now_ms - config.status_interval_ms +
                config.status_inbound_grace_period_ms,
        };

        try self.peers.put(owned_key, .{
            .peer_id = owned_key,
            .direction = direction,
            .status = null,
            .metadata = null,
            .relevant_status = .unknown,
            .connected_unix_ts_ms = now_ms,
            .last_received_msg_unix_ts_ms = last_received,
            .last_status_unix_ts_ms = last_status,
            .agent_version = null,
            .agent_client = null,
            .node_id = null,
            .encoding_preference = null,
        });
    }

    pub fn removePeer(self: *PeerStore, peer_id: []const u8) void {
        const kv = self.peers.fetchRemove(peer_id) orelse return;
        freePeerOwnedData(self.allocator, &kv.value);
        self.allocator.free(kv.key);
    }

    pub fn contains(self: *const PeerStore, peer_id: []const u8) bool {
        return self.peers.contains(peer_id);
    }

    // --- Accessors ---

    pub fn getPeerData(
        self: *const PeerStore,
        peer_id: []const u8,
    ) ?*PeerData {
        return self.peers.getPtr(peer_id);
    }

    pub fn getConnectedPeerCount(self: *const PeerStore) u32 {
        return @intCast(self.peers.count());
    }

    // --- Mutators ---

    pub fn updateStatus(
        self: *PeerStore,
        peer_id: []const u8,
        status: Status,
    ) void {
        const peer = self.peers.getPtr(peer_id) orelse return;
        peer.status = status;
    }

    pub fn updateMetadata(
        self: *PeerStore,
        peer_id: []const u8,
        metadata: Metadata,
    ) void {
        const peer = self.peers.getPtr(peer_id) orelse return;
        freeMetadataOwnedData(self.allocator, &peer.metadata);
        peer.metadata = metadata;
    }

    pub fn setAgentVersion(
        self: *PeerStore,
        peer_id: []const u8,
        version: []const u8,
    ) !void {
        const peer = self.peers.getPtr(peer_id) orelse return;
        if (peer.agent_version) |old| self.allocator.free(old);
        peer.agent_version = try self.allocator.dupe(u8, version);
        peer.agent_client = getKnownClientFromAgentVersion(version);
    }

    pub fn setEncodingPreference(
        self: *PeerStore,
        peer_id: []const u8,
        encoding: Encoding,
    ) void {
        const peer = self.peers.getPtr(peer_id) orelse return;
        peer.encoding_preference = encoding;
    }

    pub fn updateLastReceivedMsg(
        self: *PeerStore,
        peer_id: []const u8,
        now_ms: i64,
    ) void {
        const peer = self.peers.getPtr(peer_id) orelse return;
        peer.last_received_msg_unix_ts_ms = now_ms;
    }

    pub fn updateLastStatus(
        self: *PeerStore,
        peer_id: []const u8,
        now_ms: i64,
    ) void {
        const peer = self.peers.getPtr(peer_id) orelse return;
        peer.last_status_unix_ts_ms = now_ms;
    }

    // --- Iteration ---

    pub fn iterPeers(
        self: *const PeerStore,
    ) std.StringHashMap(PeerData).Iterator {
        return self.peers.iterator();
    }

    // --- Internal helpers ---

    fn freeMetadataOwnedData(
        allocator: Allocator,
        metadata: *?Metadata,
    ) void {
        const md = metadata.* orelse return;
        if (md.custody_groups) |groups| allocator.free(groups);
        if (md.sampling_groups) |groups| allocator.free(groups);
    }

    fn freePeerOwnedData(allocator: Allocator, peer: *const PeerData) void {
        if (peer.agent_version) |v| allocator.free(v);
        var md = peer.metadata;
        freeMetadataOwnedData(allocator, &md);
    }
};

// =============================================================================
// Tests
// =============================================================================

fn testConfig() Config {
    return .{
        .gossipsub_negative_score_weight = 0.0,
        .gossipsub_positive_score_weight = 0.0,
        .negative_gossip_score_ignore_threshold = 0.0,
        .initial_fork_name = .deneb,
    };
}

test "addPeer and getConnectedPeerCount" {
    var store = PeerStore.init(std.testing.allocator);
    defer store.deinit();

    try store.addPeer("peer-a", .inbound, 1000, testConfig());
    try store.addPeer("peer-b", .outbound, 2000, testConfig());

    try std.testing.expectEqual(@as(u32, 2), store.getConnectedPeerCount());
}

test "addPeer duplicate returns error" {
    var store = PeerStore.init(std.testing.allocator);
    defer store.deinit();

    try store.addPeer("peer-a", .inbound, 1000, testConfig());
    try std.testing.expectError(
        error.PeerAlreadyExists,
        store.addPeer("peer-a", .outbound, 2000, testConfig()),
    );
}

test "addPeer sets direction-dependent timestamps" {
    const config = testConfig();
    var store = PeerStore.init(std.testing.allocator);
    defer store.deinit();

    const now: i64 = 10_000;
    try store.addPeer("outbound-peer", .outbound, now, config);
    try store.addPeer("inbound-peer", .inbound, now, config);

    const out_peer = store.getPeerData("outbound-peer").?;
    try std.testing.expectEqual(@as(i64, 0), out_peer.last_received_msg_unix_ts_ms);
    try std.testing.expectEqual(@as(i64, 0), out_peer.last_status_unix_ts_ms);
    try std.testing.expectEqual(now, out_peer.connected_unix_ts_ms);

    const in_peer = store.getPeerData("inbound-peer").?;
    try std.testing.expectEqual(now, in_peer.last_received_msg_unix_ts_ms);
    try std.testing.expectEqual(
        now - config.status_interval_ms + config.status_inbound_grace_period_ms,
        in_peer.last_status_unix_ts_ms,
    );
    try std.testing.expectEqual(now, in_peer.connected_unix_ts_ms);
}

test "removePeer frees owned memory" {
    var store = PeerStore.init(std.testing.allocator);
    defer store.deinit();

    try store.addPeer("peer-a", .inbound, 1000, testConfig());
    try store.setAgentVersion("peer-a", "Lighthouse/v4.0.0");
    store.removePeer("peer-a");

    try std.testing.expectEqual(@as(u32, 0), store.getConnectedPeerCount());
}

test "removePeer nonexistent is no-op" {
    var store = PeerStore.init(std.testing.allocator);
    defer store.deinit();

    store.removePeer("does-not-exist");
}

test "setAgentVersion frees previous" {
    var store = PeerStore.init(std.testing.allocator);
    defer store.deinit();

    try store.addPeer("peer-a", .inbound, 1000, testConfig());
    try store.setAgentVersion("peer-a", "Lighthouse/v4.0.0");
    try store.setAgentVersion("peer-a", "Teku/v23.1.0");

    const peer = store.getPeerData("peer-a").?;
    try std.testing.expectEqualStrings("Teku/v23.1.0", peer.agent_version.?);
    try std.testing.expectEqual(ClientKind.teku, peer.agent_client.?);
}

test "updateStatus round-trip" {
    var store = PeerStore.init(std.testing.allocator);
    defer store.deinit();

    try store.addPeer("peer-a", .inbound, 1000, testConfig());

    const status = Status{
        .fork_digest = .{ 0x01, 0x02, 0x03, 0x04 },
        .finalized_root = [_]u8{0xAA} ** 32,
        .finalized_epoch = 100,
        .head_root = [_]u8{0xBB} ** 32,
        .head_slot = 3200,
        .earliest_available_slot = null,
    };
    store.updateStatus("peer-a", status);

    const peer = store.getPeerData("peer-a").?;
    try std.testing.expectEqual(@as(u64, 100), peer.status.?.finalized_epoch);
    try std.testing.expectEqual(@as(u64, 3200), peer.status.?.head_slot);
}

test "contains" {
    var store = PeerStore.init(std.testing.allocator);
    defer store.deinit();

    try std.testing.expect(!store.contains("peer-a"));
    try store.addPeer("peer-a", .inbound, 1000, testConfig());
    try std.testing.expect(store.contains("peer-a"));
}

test "iterPeers" {
    var store = PeerStore.init(std.testing.allocator);
    defer store.deinit();

    try store.addPeer("peer-a", .inbound, 1000, testConfig());
    try store.addPeer("peer-b", .outbound, 2000, testConfig());

    var count: u32 = 0;
    var iter = store.iterPeers();
    while (iter.next()) |_| {
        count += 1;
    }
    try std.testing.expectEqual(@as(u32, 2), count);
}
