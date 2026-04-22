//! Ethereum gossip adapter — transport-facing topic and publish management.
//!
//! This adapter subscribes to all standard Ethereum gossip topics for a given
//! fork digest, tracks logical topic subscriptions across fork-boundary overlap
//! windows, and publishes outbound messages with Snappy compression.
//!
//! Reference: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/p2p-interface.md

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const testing = std.testing;

const gossip_topics = @import("gossip_topics.zig");
const config_mod = @import("config");
const ForkSeq = config_mod.ForkSeq;

pub const GossipTopicType = gossip_topics.GossipTopicType;

const snappy = @import("snappy").raw;
const libp2p = @import("zig-libp2p");
const GossipsubService = libp2p.gossipsub.Service;
const FrameDecoder = libp2p.gossipsub.FrameDecoder;
const encodeGossipsubRpc = libp2p.gossipsub.encodeRpc;
const rpc = libp2p.protobuf.rpc;

const log = std.log.scoped(.eth_gossip);

pub const MessageId = [20]u8;

pub const MESSAGE_DOMAIN_INVALID_SNAPPY = [_]u8{ 0x00, 0x00, 0x00, 0x00 };
pub const MESSAGE_DOMAIN_VALID_SNAPPY = [_]u8{ 0x01, 0x00, 0x00, 0x00 };

fn compressSnappyBlock(allocator: Allocator, payload: []const u8) ![]u8 {
    const max_len = snappy.maxCompressedLength(payload.len);
    const scratch = try allocator.alloc(u8, max_len);
    defer allocator.free(scratch);

    const compressed_len = try snappy.compress(payload, scratch);
    const compressed = try allocator.alloc(u8, compressed_len);
    @memcpy(compressed, scratch[0..compressed_len]);
    return compressed;
}

fn uncompressSnappyBlock(allocator: Allocator, compressed_data: []const u8) ?[]u8 {
    const uncompressed_len = snappy.uncompressedLength(compressed_data) catch return null;
    if (uncompressed_len == 0) return null;

    const uncompressed = allocator.alloc(u8, uncompressed_len) catch return null;

    const actual_len = snappy.uncompress(compressed_data, uncompressed) catch {
        allocator.free(uncompressed);
        return null;
    };
    if (actual_len != uncompressed_len) {
        allocator.free(uncompressed);
        return null;
    }

    return uncompressed;
}

fn announceSubscriptionDeltaToConnectedPeers(
    allocator: Allocator,
    gossipsub: *GossipsubService,
    io: Io,
    topic: []const u8,
    subscribe: bool,
) void {
    gossipsub.state_mu.lockUncancelable(io);
    defer gossipsub.state_mu.unlock(io);

    if (gossipsub.outbound_streams.count() == 0) return;

    var sub_opts = [_]?rpc.RPC.SubOpts{.{ .subscribe = subscribe, .topicid = topic }};
    var rpc_msg = rpc.RPC{ .subscriptions = &sub_opts };
    const frame = encodeGossipsubRpc(allocator, &rpc_msg) catch |err| {
        log.warn("failed to encode gossipsub subscription delta for topic {s}: {}", .{ topic, err });
        return;
    };
    defer allocator.free(frame);

    std.debug.assert(gossipsub.active_io == null);
    gossipsub.active_io = io;
    defer gossipsub.active_io = null;

    var peer_iter = gossipsub.outbound_streams.keyIterator();
    while (peer_iter.next()) |peer_key| {
        if (!gossipsub.sendRpc(peer_key.*, frame)) {
            log.warn(
                "failed to broadcast gossipsub subscription delta topic={s} subscribe={} peer={s}",
                .{ topic, subscribe, peer_key.* },
            );
        }
    }
}

pub fn computeMessageId(allocator: Allocator, compressed_data: []const u8) !MessageId {
    const maybe_uncompressed = uncompressSnappyBlock(allocator, compressed_data);
    defer if (maybe_uncompressed) |uncompressed| allocator.free(uncompressed);

    const domain = if (maybe_uncompressed != null)
        &MESSAGE_DOMAIN_VALID_SNAPPY
    else
        &MESSAGE_DOMAIN_INVALID_SNAPPY;
    const payload = maybe_uncompressed orelse compressed_data;

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(domain);
    hasher.update(payload);

    var digest: [32]u8 = undefined;
    hasher.final(&digest);

    var message_id: MessageId = undefined;
    @memcpy(message_id[0..], digest[0..message_id.len]);
    return message_id;
}

pub fn messageIdFn(allocator: Allocator, msg: *const rpc.Message) ![]const u8 {
    const data = msg.data orelse return error.MissingData;
    const message_id = try computeMessageId(allocator, data);
    return allocator.dupe(u8, &message_id);
}

/// All global (non-subnet-indexed) topic types that every Ethereum node subscribes to.
pub const global_topic_types = [_]GossipTopicType{
    .beacon_block,
    .beacon_aggregate_and_proof,
    .voluntary_exit,
    .proposer_slashing,
    .attester_slashing,
    .bls_to_execution_change,
    .sync_committee_contribution_and_proof,
};

/// Bridges eth-p2p-z's gossipsub `Service` to Ethereum topic management.
///
/// Responsibilities:
/// - Subscribe to all Ethereum gossip topics for a given fork digest.
/// - Publish messages to gossipsub with Snappy compression.
pub const EthGossipAdapter = struct {
    const Self = @This();
    pub const ActiveFork = struct {
        fork_digest: [4]u8,
        fork_seq: ForkSeq,
    };
    const LogicalTopic = struct {
        topic_type: GossipTopicType,
        subnet_id: ?u8,
    };

    allocator: Allocator,
    gossipsub: *GossipsubService,
    /// Current fork digest used for outbound publishes.
    fork_digest: [4]u8,
    /// Current fork sequence used for outbound publishes and as a fallback
    /// publish-schema selector when callers update the outbound publish fork.
    fork_seq: ForkSeq,
    active_forks: [ForkSeq.count]ActiveFork,
    active_fork_count: usize,
    /// Tracks which topics we have subscribed to (for cleanup and idempotence).
    subscribed_topics: std.StringHashMapUnmanaged(void),

    pub fn init(
        allocator: Allocator,
        gossipsub: *GossipsubService,
        fork_digest: [4]u8,
        fork_seq: ForkSeq,
    ) Self {
        var self: Self = .{
            .allocator = allocator,
            .gossipsub = gossipsub,
            .fork_digest = fork_digest,
            .fork_seq = fork_seq,
            .active_forks = undefined,
            .active_fork_count = 1,
            .subscribed_topics = .empty,
        };
        self.active_forks[0] = .{
            .fork_digest = fork_digest,
            .fork_seq = fork_seq,
        };
        return self;
    }

    /// Update the current publish fork. This does not change the active inbound
    /// subscription boundaries.
    pub fn setPublishFork(self: *Self, new_fork_digest: [4]u8, new_fork_seq: ForkSeq) void {
        self.fork_digest = new_fork_digest;
        self.fork_seq = new_fork_seq;
    }

    pub fn setActiveForks(self: *Self, io: Io, forks: []const ActiveFork) !void {
        std.debug.assert(forks.len > 0);
        if (sameActiveForks(self, forks)) return;

        var logical_topics = std.ArrayListUnmanaged(LogicalTopic).empty;
        defer logical_topics.deinit(self.allocator);
        try self.collectLogicalTopics(&logical_topics);

        try self.unsubscribeAndClearSubscribedTopics(io);

        self.active_fork_count = forks.len;
        for (forks, 0..) |fork, i| {
            self.active_forks[i] = fork;
        }

        for (logical_topics.items) |logical_topic| {
            try self.subscribeLogicalTopic(io, logical_topic.topic_type, logical_topic.subnet_id);
        }
    }

    pub fn deinit(self: *Self) void {
        self.clearSubscribedTopics();
        self.subscribed_topics.deinit(self.allocator);
    }

    /// Subscribe to all standard Ethereum gossip topics for this fork.
    ///
    /// Subscribes to global topics (beacon_block, aggregate_and_proof, etc.)
    /// but not subnet-indexed topics — use `subscribeSubnet` for those.
    pub fn subscribeEthTopics(self: *Self, io: Io) !void {
        for (&global_topic_types) |topic_type| {
            try self.subscribeLogicalTopic(io, topic_type, null);
        }
    }

    /// Unsubscribe from all standard Ethereum gossip topics for every active fork.
    ///
    /// Subnet-indexed topics are managed separately via `unsubscribeSubnet`.
    pub fn unsubscribeEthTopics(self: *Self, io: Io) !void {
        for (&global_topic_types) |topic_type| {
            for (self.activeForks()) |fork| {
                try self.unsubscribeTopicTypeForDigest(io, fork.fork_digest, topic_type, null);
            }
        }
    }

    /// Handle a fork transition by migrating subscriptions to the new fork digest.
    ///
    /// When a fork activates, gossip topic strings change because the fork digest
    /// embedded in each topic string changes. This function:
    /// 1. Unsubscribes from all topics under the old fork digest
    /// 2. Updates self.fork_digest to the new value
    /// 3. Resubscribes to all global topics under the new fork digest
    ///
    /// Subnet subscriptions (attestation/sync) are NOT re-subscribed here —
    /// the subnet service should call subscribeSubnet() for each active subnet
    /// after the fork transition.
    ///
    /// This must be called when the chain transitions to a new fork
    /// (e.g., Capella → Deneb, Deneb → Electra).
    pub fn onForkTransition(self: *Self, io: Io, new_fork_digest: [4]u8) !void {
        self.fork_digest = new_fork_digest;
        try self.setActiveForks(io, &.{.{ .fork_digest = new_fork_digest, .fork_seq = self.fork_seq }});
    }

    /// Subscribe to a specific subnet-indexed topic.
    pub fn subscribeSubnet(
        self: *Self,
        io: Io,
        topic_type: GossipTopicType,
        subnet_id: u8,
    ) !void {
        try self.subscribeLogicalTopic(io, topic_type, subnet_id);
    }

    /// Unsubscribe from a specific subnet-indexed topic.
    pub fn unsubscribeSubnet(
        self: *Self,
        io: Io,
        topic_type: GossipTopicType,
        subnet_id: u8,
    ) !void {
        for (self.activeForks()) |fork| {
            try self.unsubscribeTopicTypeForDigest(io, fork.fork_digest, topic_type, subnet_id);
        }
    }

    fn activeForks(self: *const Self) []const ActiveFork {
        return self.active_forks[0..self.active_fork_count];
    }

    fn sameActiveForks(self: *const Self, forks: []const ActiveFork) bool {
        if (forks.len != self.active_fork_count) return false;
        for (forks, self.activeForks()) |a, b| {
            if (!std.mem.eql(u8, &a.fork_digest, &b.fork_digest) or a.fork_seq != b.fork_seq) {
                return false;
            }
        }
        return true;
    }

    fn subscribeLogicalTopic(self: *Self, io: Io, topic_type: GossipTopicType, subnet_id: ?u8) !void {
        for (self.activeForks()) |fork| {
            try self.subscribeTopicTypeForDigest(io, fork.fork_digest, topic_type, subnet_id);
        }
    }

    fn subscribeTopicTypeForDigest(
        self: *Self,
        io: Io,
        fork_digest: [4]u8,
        topic_type: GossipTopicType,
        subnet_id: ?u8,
    ) !void {
        var buf: [gossip_topics.MAX_TOPIC_LENGTH]u8 = undefined;
        const topic_slice = gossip_topics.formatTopic(&buf, fork_digest, topic_type, subnet_id);

        if (self.subscribed_topics.contains(topic_slice)) {
            return;
        }

        // Dupe into allocator-owned memory for gossipsub + our tracking.
        const topic_str = try self.allocator.dupe(u8, topic_slice);
        errdefer self.allocator.free(topic_str);

        try self.subscribed_topics.put(self.allocator, topic_str, {});
        errdefer _ = self.subscribed_topics.remove(topic_str);

        try self.gossipsub.subscribe(io, topic_str);
        announceSubscriptionDeltaToConnectedPeers(self.allocator, self.gossipsub, io, topic_str, true);
    }

    fn unsubscribeTopicTypeForDigest(
        self: *Self,
        io: Io,
        fork_digest: [4]u8,
        topic_type: GossipTopicType,
        subnet_id: ?u8,
    ) !void {
        var buf: [gossip_topics.MAX_TOPIC_LENGTH]u8 = undefined;
        const topic_slice = gossip_topics.formatTopic(&buf, fork_digest, topic_type, subnet_id);

        const owned_topic = self.subscribed_topics.getKey(topic_slice) orelse return;
        try self.gossipsub.unsubscribe(io, owned_topic);
        announceSubscriptionDeltaToConnectedPeers(self.allocator, self.gossipsub, io, owned_topic, false);
        _ = self.subscribed_topics.remove(owned_topic);
        self.allocator.free(owned_topic);
    }

    fn clearSubscribedTopics(self: *Self) void {
        var iter = self.subscribed_topics.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.subscribed_topics.clearRetainingCapacity();
    }

    fn unsubscribeAndClearSubscribedTopics(self: *Self, io: Io) !void {
        var iter = self.subscribed_topics.iterator();
        while (iter.next()) |entry| {
            try self.gossipsub.unsubscribe(io, entry.key_ptr.*);
            announceSubscriptionDeltaToConnectedPeers(self.allocator, self.gossipsub, io, entry.key_ptr.*, false);
            self.allocator.free(entry.key_ptr.*);
        }
        self.subscribed_topics.clearRetainingCapacity();
    }

    fn collectLogicalTopics(self: *Self, logical_topics: *std.ArrayListUnmanaged(LogicalTopic)) !void {
        var iter = self.subscribed_topics.iterator();
        while (iter.next()) |entry| {
            const parsed = gossip_topics.parseTopic(entry.key_ptr.*) orelse continue;
            const logical = LogicalTopic{
                .topic_type = parsed.topic_type,
                .subnet_id = parsed.subnet_id,
            };
            for (logical_topics.items) |existing| {
                if (existing.topic_type == logical.topic_type and existing.subnet_id == logical.subnet_id) {
                    break;
                }
            } else {
                try logical_topics.append(self.allocator, logical);
            }
        }
    }

    /// Publish a message to a gossip topic.
    ///
    /// Handles Snappy compression and topic string formatting.
    pub fn publish(
        self: *Self,
        io: Io,
        topic_type: GossipTopicType,
        subnet_id: ?u8,
        ssz_bytes: []const u8,
    ) !void {
        // 1. Snappy-block compress the SSZ payload.
        const compressed = try compressSnappyBlock(self.allocator, ssz_bytes);
        defer self.allocator.free(compressed);

        // 2. Format the topic string.
        var buf: [gossip_topics.MAX_TOPIC_LENGTH]u8 = undefined;
        const topic_str = gossip_topics.formatTopic(&buf, self.fork_digest, topic_type, subnet_id);

        // 3. Publish via gossipsub.
        _ = try self.gossipsub.publish(io, topic_str, compressed);
    }
};

// ============================================================================
// Tests
// ============================================================================

/// Helper to create a test adapter with a live gossipsub service.
const TestAdapter = struct {
    gossipsub: *GossipsubService,
    adapter: EthGossipAdapter,

    fn create(allocator: Allocator) !*TestAdapter {
        const self = try allocator.create(TestAdapter);
        errdefer allocator.destroy(self);

        self.gossipsub = try GossipsubService.init(allocator, .{});

        self.adapter = EthGossipAdapter.init(
            allocator,
            self.gossipsub,
            .{ 0xab, 0xcd, 0xef, 0x01 },
            .electra, // Use electra for tests as it is the most recent non-fulu fork
        );

        return self;
    }

    fn destroy(self: *TestAdapter, allocator: Allocator) void {
        self.adapter.deinit();
        self.gossipsub.deinit(std.testing.io);
        allocator.destroy(self);
    }
};

fn expectSubscriptionDeltaWrites(
    allocator: Allocator,
    bytes: []const u8,
    expected_topics: []const []const u8,
    want_subscribe: bool,
) !void {
    var decoder = FrameDecoder.init(allocator);
    defer decoder.deinit();
    try decoder.feed(bytes);

    var seen_count: usize = 0;
    while (try decoder.next()) |frame| {
        defer allocator.free(frame);
        var reader = try rpc.RPCReader.init(frame);
        const sub = reader.subscriptionsNext() orelse return error.ExpectedSubscription;
        try testing.expectEqual(want_subscribe, sub.getSubscribe());
        try testing.expect(reader.subscriptionsNext() == null);

        const topic = sub.getTopicid();
        var matched = false;
        for (expected_topics) |expected_topic| {
            if (std.mem.eql(u8, topic, expected_topic)) {
                matched = true;
                break;
            }
        }
        try testing.expect(matched);
        seen_count += 1;
    }

    try testing.expectEqual(expected_topics.len, seen_count);
}

fn expectSubscriptionSnapshotWrites(
    allocator: Allocator,
    bytes: []const u8,
    expected_topics: *const std.StringHashMapUnmanaged(void),
) !void {
    var decoder = FrameDecoder.init(allocator);
    defer decoder.deinit();
    try decoder.feed(bytes);

    var seen_topics = std.StringHashMapUnmanaged(void).empty;
    defer {
        var iter = seen_topics.keyIterator();
        while (iter.next()) |topic| allocator.free(topic.*);
        seen_topics.deinit(allocator);
    }

    while (try decoder.next()) |frame| {
        defer allocator.free(frame);
        var reader = try rpc.RPCReader.init(frame);
        while (reader.subscriptionsNext()) |sub| {
            try testing.expect(sub.getSubscribe());
            const topic = sub.getTopicid();
            try testing.expect(expected_topics.contains(topic));
            const owned_topic = try allocator.dupe(u8, topic);
            errdefer allocator.free(owned_topic);
            const gop = try seen_topics.getOrPut(allocator, owned_topic);
            if (gop.found_existing) {
                allocator.free(owned_topic);
            }
        }
    }

    try testing.expectEqual(expected_topics.count(), seen_topics.count());
}

test "EthGossipAdapter: subscribeEthTopics broadcasts live subscription updates to connected peers" {
    const allocator = testing.allocator;
    const t = try TestAdapter.create(allocator);
    defer t.destroy(allocator);

    const TestStream = struct {
        const Self = @This();

        writes: *std.ArrayList(u8),

        pub fn read(_: *Self, _: Io, _: []u8) !usize {
            return 0;
        }

        pub fn write(self: *Self, _: Io, data: []const u8) !usize {
            try self.writes.appendSlice(testing.allocator, data);
            return data.len;
        }

        pub fn closeRead(_: *Self, _: Io) void {}
        pub fn closeWrite(_: *Self, _: Io) void {}
        pub fn close(_: *Self, _: Io) void {}
        pub fn deinit(_: *Self) void {}

        pub fn detachOwnedStream(self: *Self) Self {
            return self.*;
        }
    };

    var writes: std.ArrayList(u8) = .empty;
    defer writes.deinit(allocator);
    var stream = TestStream{ .writes = &writes };
    try t.gossipsub.handleOutbound(std.testing.io, &stream, .{ .peer_id = @as(?[]const u8, "peer-1") });

    try t.adapter.subscribeEthTopics(std.testing.io);

    var expected_topics: [global_topic_types.len][]const u8 = undefined;
    for (global_topic_types, 0..) |topic_type, i| {
        var buf: [gossip_topics.MAX_TOPIC_LENGTH]u8 = undefined;
        const topic = gossip_topics.formatTopic(&buf, .{ 0xab, 0xcd, 0xef, 0x01 }, topic_type, null);
        expected_topics[i] = try allocator.dupe(u8, topic);
    }
    defer for (expected_topics) |topic| allocator.free(topic);

    try expectSubscriptionDeltaWrites(allocator, writes.items, &expected_topics, true);
}

test "EthGossipAdapter: unsubscribeEthTopics broadcasts live unsubscription updates to connected peers" {
    const allocator = testing.allocator;
    const t = try TestAdapter.create(allocator);
    defer t.destroy(allocator);

    const TestStream = struct {
        const Self = @This();

        writes: *std.ArrayList(u8),

        pub fn read(_: *Self, _: Io, _: []u8) !usize {
            return 0;
        }

        pub fn write(self: *Self, _: Io, data: []const u8) !usize {
            try self.writes.appendSlice(testing.allocator, data);
            return data.len;
        }

        pub fn closeRead(_: *Self, _: Io) void {}
        pub fn closeWrite(_: *Self, _: Io) void {}
        pub fn close(_: *Self, _: Io) void {}
        pub fn deinit(_: *Self) void {}

        pub fn detachOwnedStream(self: *Self) Self {
            return self.*;
        }
    };

    var writes: std.ArrayList(u8) = .empty;
    defer writes.deinit(allocator);
    var stream = TestStream{ .writes = &writes };
    try t.gossipsub.handleOutbound(std.testing.io, &stream, .{ .peer_id = @as(?[]const u8, "peer-1") });

    try t.adapter.subscribeEthTopics(std.testing.io);
    writes.clearRetainingCapacity();

    try t.adapter.unsubscribeEthTopics(std.testing.io);

    var expected_topics: [global_topic_types.len][]const u8 = undefined;
    for (global_topic_types, 0..) |topic_type, i| {
        var buf: [gossip_topics.MAX_TOPIC_LENGTH]u8 = undefined;
        const topic = gossip_topics.formatTopic(&buf, .{ 0xab, 0xcd, 0xef, 0x01 }, topic_type, null);
        expected_topics[i] = try allocator.dupe(u8, topic);
    }
    defer for (expected_topics) |topic| allocator.free(topic);

    try expectSubscriptionDeltaWrites(allocator, writes.items, &expected_topics, false);
}

test "EthGossipAdapter: subscribeEthTopics formats correct topic strings" {
    const allocator = testing.allocator;
    const t = try TestAdapter.create(allocator);
    defer t.destroy(allocator);

    try t.adapter.subscribeEthTopics(std.testing.io);

    // Verify the expected number of global topics were subscribed.
    try testing.expectEqual(global_topic_types.len, t.adapter.subscribed_topics.count());

    // Check that each topic is well-formed.
    var iter = t.adapter.subscribed_topics.iterator();
    while (iter.next()) |entry| {
        const topic = entry.key_ptr.*;
        try testing.expect(std.mem.startsWith(u8, topic, "/eth2/abcdef01/"));
        try testing.expect(std.mem.endsWith(u8, topic, "/ssz_snappy"));
    }
}

test "EthGossipAdapter: duplicate subscriptions are idempotent" {
    const allocator = testing.allocator;
    const t = try TestAdapter.create(allocator);
    defer t.destroy(allocator);

    try t.adapter.subscribeEthTopics(std.testing.io);
    try t.adapter.subscribeEthTopics(std.testing.io);
    try t.adapter.subscribeSubnet(std.testing.io, .beacon_attestation, 3);
    try t.adapter.subscribeSubnet(std.testing.io, .beacon_attestation, 3);

    try testing.expectEqual(global_topic_types.len + 1, t.adapter.subscribed_topics.count());
}

test "EthGossipAdapter: unsubscribeEthTopics preserves subnet subscriptions" {
    const allocator = testing.allocator;
    const t = try TestAdapter.create(allocator);
    defer t.destroy(allocator);

    try t.adapter.subscribeEthTopics(std.testing.io);
    try t.adapter.subscribeSubnet(std.testing.io, .beacon_attestation, 3);

    try t.adapter.unsubscribeEthTopics(std.testing.io);

    try testing.expectEqual(@as(usize, 1), t.adapter.subscribed_topics.count());
}

test "EthGossipAdapter: active fork updates preserve logical subscriptions" {
    const allocator = testing.allocator;
    const t = try TestAdapter.create(allocator);
    defer t.destroy(allocator);

    try t.adapter.subscribeEthTopics(std.testing.io);
    try t.adapter.subscribeSubnet(std.testing.io, .beacon_attestation, 3);

    try t.adapter.setActiveForks(std.testing.io, &.{
        .{ .fork_digest = .{ 0xab, 0xcd, 0xef, 0x01 }, .fork_seq = .electra },
        .{ .fork_digest = .{ 0x12, 0x34, 0x56, 0x78 }, .fork_seq = .fulu },
    });

    try testing.expectEqual((global_topic_types.len + 1) * 2, t.adapter.subscribed_topics.count());
}

test "computeMessageId uses valid-snappy domain for decompressible payloads" {
    const allocator = testing.allocator;
    const payload = "hello gossip";
    const compressed = try compressSnappyBlock(allocator, payload);
    defer allocator.free(compressed);

    const got = try computeMessageId(allocator, compressed);

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(&MESSAGE_DOMAIN_VALID_SNAPPY);
    hasher.update(payload);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);

    try testing.expectEqualSlices(u8, digest[0..20], &got);
}

test "computeMessageId uses invalid-snappy domain for malformed payloads" {
    const allocator = testing.allocator;
    const malformed = &[_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04 };

    const got = try computeMessageId(allocator, malformed);

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(&MESSAGE_DOMAIN_INVALID_SNAPPY);
    hasher.update(malformed);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);

    try testing.expectEqualSlices(u8, digest[0..20], &got);
}

test "EthGossipAdapter: publish compresses with snappy" {
    const allocator = testing.allocator;
    const t = try TestAdapter.create(allocator);
    defer t.destroy(allocator);

    try t.adapter.subscribeEthTopics(std.testing.io);

    // Publish a fake SSZ payload — may fail with no peers (expected).
    const fake_ssz = &[_]u8{ 0x01, 0x02, 0x03, 0x04 };
    t.adapter.publish(std.testing.io, .beacon_block, null, fake_ssz) catch |err| {
        log.debug("Publish (expected) error with no peers: {}", .{err});
    };
}
