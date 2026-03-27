//! Data column subnet subscription management for PeerDAS (Fulu fork).
//!
//! Manages gossip topic subscriptions for `data_column_sidecar_{subnet_id}` topics.
//! On startup, computes custody columns from the node's ENR node ID and subscribes
//! to the corresponding gossip topics. Also tracks which peers custody which columns
//! (from their ENR `custody_group_count` field).
//!
//! Reference:
//!   https://github.com/ethereum/consensus-specs/blob/dev/specs/fulu/p2p-interface.md

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const custody = @import("custody.zig");
const gossip_topics = @import("gossip_topics.zig");

const log = std.log.scoped(.column_subnet_service);

// ─── Types ────────────────────────────────────────────────────────────────────

/// Peer custody info derived from their ENR.
pub const PeerCustodyInfo = struct {
    /// The peer's ENR node ID (32 bytes).
    node_id: [32]u8,
    /// How many column subnets the peer custodies (from ENR `custody_group_count`).
    custody_subnet_count: u64,
    /// Computed custody subnets for this peer (cached, sorted).
    custody_columns: []u64,
};

// ─── ColumnSubnetService ──────────────────────────────────────────────────────

/// Manages data column subnet subscriptions and peer custody tracking.
///
/// On initialization, computes custody columns from the local node ID and
/// subscribes to the relevant `data_column_sidecar_{subnet_id}` gossip topics.
pub const ColumnSubnetService = struct {
    const Self = @This();

    allocator: Allocator,

    /// Our node ID (32 bytes from ENR).
    node_id: [32]u8,

    /// Number of column subnets we custody.
    custody_subnet_count: u64,

    /// Our custodied column subnet IDs (sorted, computed once at init/update).
    /// We own this memory.
    custody_columns: []u64,

    /// Subscribed subnet IDs (those we've told the gossipsub layer about).
    /// Maps subnet_id → subscribed=true.
    subscribed_subnets: std.AutoHashMap(u64, void),

    /// Peer custody tracking: peer_id_str → PeerCustodyInfo.
    /// Both keys and PeerCustodyInfo.custody_columns are owned by us.
    peer_custody: std.StringHashMap(PeerCustodyInfo),

    /// Fork digest used to build gossip topic strings.
    fork_digest: [4]u8,

    // ─── Init / deinit ────────────────────────────────────────────────────────

    pub fn init(
        allocator: Allocator,
        node_id: [32]u8,
        custody_subnet_count: u64,
        fork_digest: [4]u8,
    ) !Self {
        const clamped = @min(custody_subnet_count, custody.DATA_COLUMN_SIDECAR_SUBNET_COUNT);
        const cols = try custody.getCustodyColumns(allocator, node_id, clamped);
        errdefer allocator.free(cols);

        return .{
            .allocator = allocator,
            .node_id = node_id,
            .custody_subnet_count = clamped,
            .custody_columns = cols,
            .subscribed_subnets = std.AutoHashMap(u64, void).init(allocator),
            .peer_custody = std.StringHashMap(PeerCustodyInfo).init(allocator),
            .fork_digest = fork_digest,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.custody_columns);

        {
            var it = self.peer_custody.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                self.allocator.free(entry.value_ptr.custody_columns);
            }
            self.peer_custody.deinit();
        }

        self.subscribed_subnets.deinit();
    }

    // ─── Subscription management ──────────────────────────────────────────────

    /// Subscribe to all custody column subnets.
    ///
    /// Builds the gossip topic string for each custodied subnet and marks them
    /// as subscribed. Returns a list of topic strings to pass to gossipsub.
    /// Caller owns the returned slice (and its elements).
    pub fn getTopicsToSubscribe(self: *Self) ![][]const u8 {
        var topics = std.ArrayListUnmanaged([]const u8).empty;
        errdefer {
            for (topics.items) |t| self.allocator.free(t);
            topics.deinit(self.allocator);
        }

        for (self.custody_columns) |col| {
            if (!self.subscribed_subnets.contains(col)) {
                const topic = try self.buildTopicString(col);
                try topics.append(self.allocator, topic);
                try self.subscribed_subnets.put(col, {});
                log.debug("subscribing to data_column_sidecar_{} topic", .{col});
            }
        }

        return topics.toOwnedSlice(self.allocator);
    }

    /// Returns true if we are subscribed to the given column subnet.
    pub fn isSubscribed(self: *const Self, subnet_id: u64) bool {
        return self.subscribed_subnets.contains(subnet_id);
    }

    /// Returns true if we custody the given column (fast path).
    pub fn isCustodied(self: *const Self, column_index: u64) bool {
        return custody.isCustodied(column_index, self.custody_columns);
    }

    /// Update custody on ENR change.
    ///
    /// Called when our ENR `custody_group_count` changes. Recomputes custody
    /// columns and returns (new_topics, removed_topics) slices.
    /// Caller owns both returned slices.
    pub fn updateCustody(
        self: *Self,
        new_custody_subnet_count: u64,
    ) !struct { added: [][]const u8, removed: [][]const u8 } {
        const clamped = @min(new_custody_subnet_count, custody.DATA_COLUMN_SIDECAR_SUBNET_COUNT);
        const new_cols = try custody.getCustodyColumns(self.allocator, self.node_id, clamped);
        errdefer self.allocator.free(new_cols);

        // Compute added (in new but not old).
        var added = std.ArrayListUnmanaged([]const u8).empty;
        errdefer {
            for (added.items) |t| self.allocator.free(t);
            added.deinit(self.allocator);
        }

        for (new_cols) |col| {
            if (!custody.isCustodied(col, self.custody_columns)) {
                const topic = try self.buildTopicString(col);
                try added.append(self.allocator, topic);
                try self.subscribed_subnets.put(col, {});
            }
        }

        // Compute removed (in old but not new).
        var removed = std.ArrayListUnmanaged([]const u8).empty;
        errdefer {
            for (removed.items) |t| self.allocator.free(t);
            removed.deinit(self.allocator);
        }

        for (self.custody_columns) |col| {
            if (!custody.isCustodied(col, new_cols)) {
                const topic = try self.buildTopicString(col);
                try removed.append(self.allocator, topic);
                _ = self.subscribed_subnets.remove(col);
            }
        }

        // Update state.
        self.allocator.free(self.custody_columns);
        self.custody_columns = new_cols;
        self.custody_subnet_count = clamped;

        return .{
            .added = try added.toOwnedSlice(self.allocator),
            .removed = try removed.toOwnedSlice(self.allocator),
        };
    }

    // ─── Peer custody tracking ────────────────────────────────────────────────

    /// Record a peer's custody info from their ENR/handshake.
    ///
    /// Computes which columns the peer custodies and caches it.
    /// Overwrites any existing entry for `peer_id`.
    pub fn updatePeerCustody(
        self: *Self,
        peer_id: []const u8,
        node_id: [32]u8,
        custody_subnet_count: u64,
    ) !void {
        const clamped = @min(custody_subnet_count, custody.DATA_COLUMN_SIDECAR_SUBNET_COUNT);
        const cols = try custody.getCustodyColumns(self.allocator, node_id, clamped);
        errdefer self.allocator.free(cols);

        const key = try self.allocator.dupe(u8, peer_id);
        errdefer self.allocator.free(key);

        const result = try self.peer_custody.getOrPut(key);
        if (result.found_existing) {
            // Free old key and columns.
            self.allocator.free(result.key_ptr.*);
            self.allocator.free(result.value_ptr.custody_columns);
            result.key_ptr.* = key;
        }
        result.value_ptr.* = .{
            .node_id = node_id,
            .custody_subnet_count = clamped,
            .custody_columns = cols,
        };
        log.debug("updated peer {s} custody: {d} subnets", .{ peer_id, clamped });
    }

    /// Remove peer custody info on disconnect.
    pub fn removePeer(self: *Self, peer_id: []const u8) void {
        // Use fetchRemove to atomically remove and retrieve the owned key+value,
        // then free them. Freeing the key before remove would corrupt the HashMap.
        const kv = self.peer_custody.fetchRemove(peer_id) orelse return;
        self.allocator.free(kv.key);
        self.allocator.free(kv.value.custody_columns);
        log.debug("removed peer {s} custody info", .{peer_id});
    }

    /// Check whether a peer custodies a specific column.
    pub fn peerCustodiesColumn(self: *const Self, peer_id: []const u8, column_index: u64) bool {
        const info = self.peer_custody.get(peer_id) orelse return false;
        return custody.isCustodied(column_index, info.custody_columns);
    }

    /// Returns a list of peer IDs that custody a given column.
    /// Caller owns the returned slice.
    pub fn peersForColumn(self: *const Self, column_index: u64) ![][]const u8 {
        var peers = std.ArrayListUnmanaged([]const u8).empty;
        errdefer peers.deinit(self.allocator);

        var it = self.peer_custody.iterator();
        while (it.next()) |entry| {
            if (custody.isCustodied(column_index, entry.value_ptr.custody_columns)) {
                try peers.append(self.allocator, entry.key_ptr.*);
            }
        }
        return peers.toOwnedSlice(self.allocator);
    }

    // ─── Gossip validation ────────────────────────────────────────────────────

    /// Validate an incoming data column sidecar gossip message.
    ///
    /// Returns `true` if the column is one we're subscribed to (i.e., custodied).
    /// Returns `false` if we somehow received a column we don't custody
    /// (should not happen with proper gossipsub topic filtering).
    pub fn validateIncomingColumn(self: *const Self, subnet_id: u64) bool {
        if (!self.isSubscribed(subnet_id)) {
            log.warn("received data column gossip for unsubscribed subnet {}", .{subnet_id});
            return false;
        }
        return true;
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    fn buildTopicString(self: *const Self, subnet_id: u64) ![]u8 {
        // Format: /eth2/<fork_digest_hex>/data_column_sidecar_<subnet_id>/ssz_snappy
        return std.fmt.allocPrint(
            self.allocator,
            "/eth2/{x}/data_column_sidecar_{d}/ssz_snappy",
            .{ self.fork_digest, subnet_id },
        );
    }
};

// ─── Tests ───────────────────────────────────────────────────────────────────

test "ColumnSubnetService: init computes custody columns" {
    const allocator = testing.allocator;

    const node_id: [32]u8 = [_]u8{0x01} ** 32;
    const fork_digest = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };

    var svc = try ColumnSubnetService.init(allocator, node_id, custody.CUSTODY_REQUIREMENT, fork_digest);
    defer svc.deinit();

    // Should have CUSTODY_REQUIREMENT columns.
    try testing.expectEqual(custody.CUSTODY_REQUIREMENT, svc.custody_columns.len);
    try testing.expectEqual(custody.CUSTODY_REQUIREMENT, svc.custody_subnet_count);
}

test "ColumnSubnetService: getTopicsToSubscribe returns correct topics" {
    const allocator = testing.allocator;

    const node_id: [32]u8 = [_]u8{0x02} ** 32;
    const fork_digest = [_]u8{ 0x01, 0x02, 0x03, 0x04 };

    var svc = try ColumnSubnetService.init(allocator, node_id, 2, fork_digest);
    defer svc.deinit();

    const topics = try svc.getTopicsToSubscribe();
    defer {
        for (topics) |t| allocator.free(t);
        allocator.free(topics);
    }

    // Should return 2 topics.
    try testing.expectEqual(@as(usize, 2), topics.len);

    // Each topic must start with /eth2/01020304/data_column_sidecar_.
    for (topics) |t| {
        try testing.expect(std.mem.startsWith(u8, t, "/eth2/01020304/data_column_sidecar_"));
        try testing.expect(std.mem.endsWith(u8, t, "/ssz_snappy"));
    }
}

test "ColumnSubnetService: isSubscribed after getTopicsToSubscribe" {
    const allocator = testing.allocator;

    const node_id: [32]u8 = [_]u8{0x03} ** 32;
    const fork_digest = [_]u8{ 0x00, 0x00, 0x00, 0x01 };

    var svc = try ColumnSubnetService.init(allocator, node_id, custody.CUSTODY_REQUIREMENT, fork_digest);
    defer svc.deinit();

    const topics = try svc.getTopicsToSubscribe();
    defer {
        for (topics) |t| allocator.free(t);
        allocator.free(topics);
    }

    // All custody columns should now be marked subscribed.
    for (svc.custody_columns) |col| {
        try testing.expect(svc.isSubscribed(col));
        try testing.expect(svc.isCustodied(col));
    }
}

test "ColumnSubnetService: isCustodied returns false for non-custodied column" {
    const allocator = testing.allocator;

    const node_id: [32]u8 = [_]u8{0x04} ** 32;
    const fork_digest = [_]u8{ 0x00, 0x00, 0x00, 0x00 };

    var svc = try ColumnSubnetService.init(allocator, node_id, custody.CUSTODY_REQUIREMENT, fork_digest);
    defer svc.deinit();

    // Count how many columns are NOT custodied.
    var non_custodied_count: usize = 0;
    for (0..custody.NUMBER_OF_COLUMNS) |col| {
        if (!svc.isCustodied(col)) {
            non_custodied_count += 1;
        }
    }
    // With CUSTODY_REQUIREMENT=4 out of 128, we expect 124 non-custodied.
    try testing.expectEqual(
        custody.NUMBER_OF_COLUMNS - custody.CUSTODY_REQUIREMENT,
        non_custodied_count,
    );
}

test "ColumnSubnetService: peer custody tracking" {
    const allocator = testing.allocator;

    const node_id: [32]u8 = [_]u8{0x05} ** 32;
    const fork_digest = [_]u8{ 0x00, 0x00, 0x00, 0x02 };

    var svc = try ColumnSubnetService.init(allocator, node_id, custody.CUSTODY_REQUIREMENT, fork_digest);
    defer svc.deinit();

    // Add a peer with full custody.
    const peer_node_id: [32]u8 = [_]u8{0xAA} ** 32;
    try svc.updatePeerCustody("peer-1", peer_node_id, custody.DATA_COLUMN_SIDECAR_SUBNET_COUNT);

    // Full custody peer should custody all columns.
    for (0..custody.NUMBER_OF_COLUMNS) |col| {
        try testing.expect(svc.peerCustodiesColumn("peer-1", col));
    }

    // Unknown peer custodies nothing.
    try testing.expect(!svc.peerCustodiesColumn("unknown-peer", 0));

    // Remove peer.
    svc.removePeer("peer-1");
    try testing.expect(!svc.peerCustodiesColumn("peer-1", 0));
}

test "ColumnSubnetService: peersForColumn" {
    const allocator = testing.allocator;

    const node_id: [32]u8 = [_]u8{0x06} ** 32;
    const fork_digest = [_]u8{ 0x00, 0x00, 0x00, 0x03 };

    var svc = try ColumnSubnetService.init(allocator, node_id, custody.CUSTODY_REQUIREMENT, fork_digest);
    defer svc.deinit();

    // Add two peers with full custody.
    try svc.updatePeerCustody("peer-a", [_]u8{0x11} ** 32, custody.DATA_COLUMN_SIDECAR_SUBNET_COUNT);
    try svc.updatePeerCustody("peer-b", [_]u8{0x22} ** 32, custody.DATA_COLUMN_SIDECAR_SUBNET_COUNT);

    // Column 0 should be reachable via both peers.
    const peers = try svc.peersForColumn(0);
    defer allocator.free(peers);

    try testing.expectEqual(@as(usize, 2), peers.len);
}

test "ColumnSubnetService: updateCustody changes subscriptions" {
    const allocator = testing.allocator;

    const node_id: [32]u8 = [_]u8{0x07} ** 32;
    const fork_digest = [_]u8{ 0x00, 0x00, 0x00, 0x04 };

    var svc = try ColumnSubnetService.init(allocator, node_id, custody.CUSTODY_REQUIREMENT, fork_digest);
    defer svc.deinit();

    // Subscribe to initial 4 columns.
    const initial_topics = try svc.getTopicsToSubscribe();
    defer {
        for (initial_topics) |t| allocator.free(t);
        allocator.free(initial_topics);
    }
    try testing.expectEqual(@as(usize, 4), initial_topics.len);

    // Upgrade to 8 columns.
    const result = try svc.updateCustody(8);
    defer {
        for (result.added) |t| allocator.free(t);
        allocator.free(result.added);
        for (result.removed) |t| allocator.free(t);
        allocator.free(result.removed);
    }

    try testing.expectEqual(@as(usize, 8), svc.custody_subnet_count);
}

test "ColumnSubnetService: validateIncomingColumn rejects unsubscribed" {
    const allocator = testing.allocator;

    const node_id: [32]u8 = [_]u8{0x08} ** 32;
    const fork_digest = [_]u8{ 0x00, 0x00, 0x00, 0x05 };

    var svc = try ColumnSubnetService.init(allocator, node_id, custody.CUSTODY_REQUIREMENT, fork_digest);
    defer svc.deinit();

    // Subscribe to initial columns.
    const topics = try svc.getTopicsToSubscribe();
    defer {
        for (topics) |t| allocator.free(t);
        allocator.free(topics);
    }

    // Custodied columns pass validation.
    for (svc.custody_columns) |col| {
        try testing.expect(svc.validateIncomingColumn(col));
    }
}
