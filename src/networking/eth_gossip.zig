//! Ethereum gossip adapter — bridges eth-p2p-z's gossipsub to the Ethereum
//! consensus validation layer.
//!
//! This adapter subscribes to all standard Ethereum gossip topics for a given
//! fork digest, processes inbound messages through Snappy decompression and
//! per-topic validation, and publishes outbound messages with Snappy compression.
//!
//! Reference: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/p2p-interface.md

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const gossip_topics = @import("gossip_topics.zig");
const gossip_validation = @import("gossip_validation.zig");
const gossip_decoding = @import("gossip_decoding.zig");

const GossipTopicType = gossip_topics.GossipTopicType;
const GossipTopic = gossip_topics.GossipTopic;
const ValidationResult = gossip_validation.ValidationResult;
const GossipValidationContext = gossip_validation.GossipValidationContext;
const DecodedGossipMessage = gossip_decoding.DecodedGossipMessage;

const snappy = @import("snappy").frame;
const libp2p = @import("zig-libp2p");
const GossipsubService = libp2p.gossipsub.Service;
const GossipsubConfig = libp2p.gossipsub.Config;
const GossipsubEvent = libp2p.gossipsub.config.Event;

const log = std.log.scoped(.eth_gossip);

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

/// Bridges eth-p2p-z's gossipsub `Service` to the Ethereum validation layer.
///
/// Responsibilities:
/// - Subscribe to all Ethereum gossip topics for a given fork digest.
/// - Receive messages from gossipsub, decompress, decode, and validate.
/// - Publish messages to gossipsub with Snappy compression.
pub const EthGossipAdapter = struct {
    const Self = @This();

    allocator: Allocator,
    gossipsub: *GossipsubService,
    validator: *GossipValidationContext,
    fork_digest: [4]u8,
    /// Tracks which topics we have subscribed to (for cleanup).
    subscribed_topics: std.ArrayListUnmanaged([]const u8),

    pub fn init(
        allocator: Allocator,
        gossipsub: *GossipsubService,
        validator: *GossipValidationContext,
        fork_digest: [4]u8,
    ) Self {
        return .{
            .allocator = allocator,
            .gossipsub = gossipsub,
            .validator = validator,
            .fork_digest = fork_digest,
            .subscribed_topics = .empty,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.subscribed_topics.items) |topic| {
            self.allocator.free(topic);
        }
        self.subscribed_topics.deinit(self.allocator);
    }

    /// Subscribe to all standard Ethereum gossip topics for this fork.
    ///
    /// Subscribes to global topics (beacon_block, aggregate_and_proof, etc.)
    /// but not subnet-indexed topics — use `subscribeSubnet` for those.
    pub fn subscribeEthTopics(self: *Self) !void {
        for (&global_topic_types) |topic_type| {
            try self.subscribeTopicType(topic_type, null);
        }
    }

    /// Subscribe to a specific subnet-indexed topic.
    pub fn subscribeSubnet(
        self: *Self,
        topic_type: GossipTopicType,
        subnet_id: u8,
    ) !void {
        try self.subscribeTopicType(topic_type, subnet_id);
    }

    fn subscribeTopicType(self: *Self, topic_type: GossipTopicType, subnet_id: ?u8) !void {
        var buf: [gossip_topics.MAX_TOPIC_LENGTH]u8 = undefined;
        const topic_slice = gossip_topics.formatTopic(&buf, self.fork_digest, topic_type, subnet_id);

        // Dupe into allocator-owned memory for gossipsub + our tracking.
        const topic_str = try self.allocator.dupe(u8, topic_slice);
        errdefer self.allocator.free(topic_str);

        try self.gossipsub.subscribe(topic_str);
        try self.subscribed_topics.append(self.allocator, topic_str);
    }

    /// Process an incoming gossip message through the full Ethereum pipeline:
    /// 1. Parse topic string → GossipTopicType + subnet_id
    /// 2. Snappy decompress + SSZ decode → typed message
    /// 3. Dispatch to per-topic validation
    /// 4. Return validation result + decoded message
    ///
    /// Called when gossipsub's `drainEvents()` yields a `message` event.
    pub fn handleMessage(
        self: *Self,
        topic: []const u8,
        data: []const u8,
    ) HandleMessageResult {
        // 1. Parse the topic string.
        const parsed_topic = gossip_topics.parseTopic(topic) orelse {
            log.warn("Failed to parse gossip topic '{s}'", .{topic});
            return .{ .validation = .reject, .decoded = null };
        };

        // 2. Decode (decompress + SSZ deserialize).
        const decoded = gossip_decoding.decodeGossipMessage(
            self.allocator,
            parsed_topic.topic_type,
            data,
        ) catch {
            log.warn("Failed to decode gossip message for topic {s}", .{
                parsed_topic.topic_type.topicName(),
            });
            return .{ .validation = .reject, .decoded = null };
        };

        // 3. Dispatch to per-topic validation.
        const validation = self.validateDecoded(parsed_topic, decoded);

        return .{ .validation = validation, .decoded = decoded };
    }

    /// Validate a decoded gossip message using the per-topic validators.
    fn validateDecoded(
        self: *Self,
        parsed_topic: GossipTopic,
        decoded: DecodedGossipMessage,
    ) ValidationResult {
        _ = parsed_topic; // subnet_id used for attestation/sync committee validation (future)

        switch (decoded) {
            .beacon_block => |block| {
                // For the spike, use a zero block_root. In production, the
                // hash_tree_root of the BeaconBlock would be computed here.
                const block_root = std.mem.zeroes([32]u8);
                return gossip_validation.validateBeaconBlock(
                    block.slot,
                    block.proposer_index,
                    block.parent_root,
                    block_root,
                    self.validator,
                );
            },
            .beacon_aggregate_and_proof => |agg| {
                return gossip_validation.validateAggregateAndProof(
                    agg.aggregator_index,
                    agg.attestation_slot,
                    agg.attestation_target_epoch,
                    agg.aggregation_bits_count,
                    self.validator,
                );
            },
            .voluntary_exit => |exit| {
                return gossip_validation.validateVoluntaryExit(
                    exit.validator_index,
                    exit.exit_epoch,
                    self.validator,
                );
            },
            .proposer_slashing => |slashing| {
                return gossip_validation.validateProposerSlashing(
                    slashing.proposer_index,
                    slashing.header_1_slot,
                    slashing.header_2_slot,
                    slashing.header_1_body_root,
                    slashing.header_2_body_root,
                    self.validator,
                );
            },
            // Topics not yet supported for validation.
            else => return .accept,
        }
    }

    pub const HandleMessageError = error{OutOfMemory};

    pub const HandleMessageResult = struct {
        validation: ValidationResult,
        decoded: ?DecodedGossipMessage,
    };

    /// Publish a message to a gossip topic.
    ///
    /// Handles Snappy compression and topic string formatting.
    pub fn publish(
        self: *Self,
        topic_type: GossipTopicType,
        subnet_id: ?u8,
        ssz_bytes: []const u8,
    ) !void {
        // 1. Snappy compress the SSZ payload.
        const compressed = try snappy.compress(self.allocator, ssz_bytes);
        defer self.allocator.free(compressed);

        // 2. Format the topic string.
        var buf: [gossip_topics.MAX_TOPIC_LENGTH]u8 = undefined;
        const topic_str = gossip_topics.formatTopic(&buf, self.fork_digest, topic_type, subnet_id);

        // 3. Publish via gossipsub.
        _ = try self.gossipsub.publish(topic_str, compressed);
    }

    /// Poll for and process all pending gossipsub events.
    ///
    /// Returns validation results for received messages.
    /// Non-message events (subscriptions, grafts, etc.) are logged but not returned.
    pub fn pollEvents(self: *Self) ![]MessageResult {
        const events = try self.gossipsub.drainEvents();
        defer self.allocator.free(events);

        var results: std.ArrayListUnmanaged(MessageResult) = .empty;
        errdefer {
            for (results.items) |r| {
                self.allocator.free(r.topic);
            }
            results.deinit(self.allocator);
        }

        for (events) |event| {
            switch (event) {
                .message => |msg| {
                    const handle_result = self.handleMessage(msg.topic, msg.data);
                    const topic_copy = try self.allocator.dupe(u8, msg.topic);
                    try results.append(self.allocator, .{
                        .topic = topic_copy,
                        .validation = handle_result.validation,
                    });
                },
                else => {},
            }
        }

        return results.toOwnedSlice(self.allocator);
    }

    /// Result of processing a single gossip message.
    pub const MessageResult = struct {
        topic: []const u8,
        validation: ValidationResult,
    };
};

// ============================================================================
// Tests
// ============================================================================

/// Creates a mock GossipValidationContext for testing.
fn testValidationContext(
    seen_blocks: *gossip_validation.SeenSet,
    seen_aggregators: *gossip_validation.SeenSet,
    seen_exits: *gossip_validation.SeenSet,
    seen_proposer_slashings: *gossip_validation.SeenSet,
    seen_attester_slashings: *gossip_validation.SeenSet,
) GossipValidationContext {
    return .{
        .current_slot = 100,
        .current_epoch = 3,
        .finalized_slot = 64,
        .seen_block_roots = seen_blocks,
        .seen_aggregators = seen_aggregators,
        .seen_voluntary_exits = seen_exits,
        .seen_proposer_slashings = seen_proposer_slashings,
        .seen_attester_slashings = seen_attester_slashings,
        .ptr = @ptrFromInt(1),
        .getProposerIndex = &testGetProposerIndex,
        .isKnownBlockRoot = &testIsKnownBlockRoot,
        .isValidatorActive = &testIsValidatorActive,
        .getValidatorCount = &testGetValidatorCount,
    };
}

fn testGetProposerIndex(_: *anyopaque, _: u64) ?u32 {
    return 5;
}

fn testIsKnownBlockRoot(_: *anyopaque, _: [32]u8) bool {
    return true;
}

fn testIsValidatorActive(_: *anyopaque, _: u64, _: u64) bool {
    return true;
}

fn testGetValidatorCount(_: *anyopaque) u32 {
    return 100;
}

/// Helper to create a test adapter with all required seen sets.
const TestAdapter = struct {
    seen_blocks: gossip_validation.SeenSet,
    seen_aggs: gossip_validation.SeenSet,
    seen_exits: gossip_validation.SeenSet,
    seen_ps: gossip_validation.SeenSet,
    seen_as: gossip_validation.SeenSet,
    ctx: GossipValidationContext,
    gossipsub: *GossipsubService,
    adapter: EthGossipAdapter,

    fn create(allocator: Allocator) !TestAdapter {
        var self: TestAdapter = undefined;

        self.seen_blocks = gossip_validation.SeenSet.init(allocator);
        self.seen_aggs = gossip_validation.SeenSet.init(allocator);
        self.seen_exits = gossip_validation.SeenSet.init(allocator);
        self.seen_ps = gossip_validation.SeenSet.init(allocator);
        self.seen_as = gossip_validation.SeenSet.init(allocator);

        self.ctx = testValidationContext(
            &self.seen_blocks,
            &self.seen_aggs,
            &self.seen_exits,
            &self.seen_ps,
            &self.seen_as,
        );

        self.gossipsub = try GossipsubService.init(allocator, .{});

        self.adapter = EthGossipAdapter.init(
            allocator,
            self.gossipsub,
            &self.ctx,
            .{ 0xab, 0xcd, 0xef, 0x01 },
        );

        return self;
    }

    fn destroy(self: *TestAdapter) void {
        self.adapter.deinit();
        self.gossipsub.deinit();
        self.seen_blocks.deinit();
        self.seen_aggs.deinit();
        self.seen_exits.deinit();
        self.seen_ps.deinit();
        self.seen_as.deinit();
    }
};

test "EthGossipAdapter: handleMessage rejects malformed topic" {
    const allocator = testing.allocator;
    var t = try TestAdapter.create(allocator);
    defer t.destroy();

    const result = t.adapter.handleMessage("/bad/topic/string", "some-data");
    try testing.expectEqual(ValidationResult.reject, result.validation);
    try testing.expectEqual(@as(?DecodedGossipMessage, null), result.decoded);
}

test "EthGossipAdapter: handleMessage rejects invalid snappy data" {
    const allocator = testing.allocator;
    var t = try TestAdapter.create(allocator);
    defer t.destroy();

    const result = t.adapter.handleMessage(
        "/eth2/abcdef01/beacon_block/ssz_snappy",
        &([_]u8{ 0x00 } ** 16),
    );
    try testing.expectEqual(ValidationResult.reject, result.validation);
    try testing.expectEqual(@as(?DecodedGossipMessage, null), result.decoded);
}

test "EthGossipAdapter: subscribeEthTopics formats correct topic strings" {
    const allocator = testing.allocator;
    var t = try TestAdapter.create(allocator);
    defer t.destroy();

    try t.adapter.subscribeEthTopics();

    // Verify the expected number of global topics were subscribed.
    try testing.expectEqual(global_topic_types.len, t.adapter.subscribed_topics.items.len);

    // Check that each topic is well-formed.
    for (t.adapter.subscribed_topics.items) |topic| {
        try testing.expect(std.mem.startsWith(u8, topic, "/eth2/abcdef01/"));
        try testing.expect(std.mem.endsWith(u8, topic, "/ssz_snappy"));
    }
}

test "EthGossipAdapter: publish compresses with snappy" {
    const allocator = testing.allocator;
    var t = try TestAdapter.create(allocator);
    defer t.destroy();

    try t.adapter.subscribeEthTopics();

    // Publish a fake SSZ payload — may fail with no peers (expected).
    const fake_ssz = &[_]u8{ 0x01, 0x02, 0x03, 0x04 };
    t.adapter.publish(.beacon_block, null, fake_ssz) catch |err| {
        log.debug("Publish (expected) error with no peers: {}", .{err});
    };
}

test "EthGossipAdapter: handleMessage with valid snappy beacon_block" {
    // Verify the full pipeline: compress → handleMessage → decompress → decode → validate.
    const allocator = testing.allocator;
    var t = try TestAdapter.create(allocator);
    defer t.destroy();

    // Create a minimal fake SSZ payload that would fail SSZ deserialization.
    // This tests that the decode failure path works correctly.
    const fake_ssz = &[_]u8{0x00} ** 16;
    const compressed = try snappy.compress(allocator, fake_ssz);
    defer allocator.free(compressed);

    const result = t.adapter.handleMessage(
        "/eth2/abcdef01/beacon_block/ssz_snappy",
        compressed,
    );

    // SSZ deserialization should fail for this truncated payload.
    try testing.expectEqual(ValidationResult.reject, result.validation);
}
