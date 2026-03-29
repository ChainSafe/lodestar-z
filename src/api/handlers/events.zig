//! Beacon events API handlers.
//!
//! Implements the Server-Sent Events (SSE) endpoint:
//!   GET /eth/v1/events?topics=head,block,finalized_checkpoint,...
//!
//! SSE delivers a stream of newline-delimited `event: <type>\ndata: {...}\n\n`
//! payloads over an HTTP/1.1 chunked-transfer keep-alive connection.
//!
//! The actual streaming is handled in `http_server.zig` via `handleSseEvents`
//! which uses `respondStreaming` for long-lived connections. This module
//! provides the topic parsing, filtering, and event type definitions used by
//! both the streaming handler and any polling fallback.
//!
//! Reference: https://ethereum.github.io/beacon-APIs/#/Events

const std = @import("std");
const types = @import("../types.zig");
const context = @import("../context.zig");
const event_bus = @import("../event_bus.zig");
const ApiContext = context.ApiContext;
const EventBus = event_bus.EventBus;
const Event = event_bus.Event;

// ---------------------------------------------------------------------------
// Event types (spec-compatible, richer than the bus types)
// ---------------------------------------------------------------------------

/// Emitted each time the node advances its canonical head.
pub const HeadEvent = struct {
    slot: u64,
    block: [32]u8,
    state: [32]u8,
    epoch_transition: bool,
    previous_duty_dependent_root: [32]u8,
    current_duty_dependent_root: [32]u8,
    execution_optimistic: bool,
};

/// Emitted when a new block is received (before import).
pub const BlockEvent = struct {
    slot: u64,
    block: [32]u8,
    execution_optimistic: bool,
};

/// Emitted when the finalized checkpoint advances.
pub const FinalizedCheckpointEvent = struct {
    block: [32]u8,
    state: [32]u8,
    epoch: u64,
    execution_optimistic: bool,
};

/// Emitted when the canonical chain reorganizes.
pub const ChainReorgEvent = struct {
    slot: u64,
    depth: u64,
    old_head_block: [32]u8,
    new_head_block: [32]u8,
    old_head_state: [32]u8,
    new_head_state: [32]u8,
    epoch: u64,
    execution_optimistic: bool,
};

/// The set of topic names accepted by the events endpoint.
pub const EventTopic = enum {
    head,
    block,
    attestation,
    voluntary_exit,
    bls_to_execution_change,
    finalized_checkpoint,
    chain_reorg,
    contribution_and_proof,
    payload_attributes,
    blob_sidecar,

    pub fn fromString(s: []const u8) ?EventTopic {
        const map = std.StaticStringMap(EventTopic).initComptime(.{
            .{ "head", .head },
            .{ "block", .block },
            .{ "attestation", .attestation },
            .{ "voluntary_exit", .voluntary_exit },
            .{ "bls_to_execution_change", .bls_to_execution_change },
            .{ "finalized_checkpoint", .finalized_checkpoint },
            .{ "chain_reorg", .chain_reorg },
            .{ "contribution_and_proof", .contribution_and_proof },
            .{ "payload_attributes", .payload_attributes },
            .{ "blob_sidecar", .blob_sidecar },
        });
        return map.get(s);
    }

    /// Returns the EventType that this topic maps to in the EventBus,
    /// or null if this topic isn't backed by an EventBus type yet.
    pub fn toEventType(self: EventTopic) ?event_bus.EventType {
        return switch (self) {
            .head => .head,
            .block => .block,
            .finalized_checkpoint => .finalized_checkpoint,
            .chain_reorg => .chain_reorg,
            .attestation => .attestation,
            .voluntary_exit => .voluntary_exit,
            .contribution_and_proof => .contribution_and_proof,
            .payload_attributes => .payload_attributes,
            .blob_sidecar => .blob_sidecar,
            .bls_to_execution_change => null,
        };
    }
};

/// Parsed topic filter — a bitset over EventType for fast matching.
pub const TopicFilter = struct {
    /// One bit per EventType — true means "subscribed".
    want_head: bool = false,
    want_block: bool = false,
    want_finalized_checkpoint: bool = false,
    want_chain_reorg: bool = false,
    want_attestation: bool = false,
    want_voluntary_exit: bool = false,
    want_contribution_and_proof: bool = false,
    want_payload_attributes: bool = false,
    want_blob_sidecar: bool = false,

    /// Parse a comma-separated topics query string.
    /// Unknown topics are silently ignored (per spec).
    pub fn parse(query: []const u8) TopicFilter {
        var filter = TopicFilter{};
        var iter = std.mem.splitScalar(u8, query, ',');
        while (iter.next()) |raw_topic| {
            const topic = std.mem.trim(u8, raw_topic, " ");
            if (EventTopic.fromString(topic)) |et| {
                switch (et) {
                    .head => filter.want_head = true,
                    .block => filter.want_block = true,
                    .finalized_checkpoint => filter.want_finalized_checkpoint = true,
                    .chain_reorg => filter.want_chain_reorg = true,
                    .attestation => filter.want_attestation = true,
                    .voluntary_exit => filter.want_voluntary_exit = true,
                    .contribution_and_proof => filter.want_contribution_and_proof = true,
                    .payload_attributes => filter.want_payload_attributes = true,
                    .blob_sidecar => filter.want_blob_sidecar = true,
                    .bls_to_execution_change => {}, // not yet backed by EventBus
                }
            }
        }
        return filter;
    }

    /// Returns true if any topics are subscribed.
    pub fn hasAny(self: TopicFilter) bool {
        return self.want_head or self.want_block or self.want_finalized_checkpoint or
            self.want_chain_reorg or self.want_attestation or self.want_voluntary_exit or
            self.want_contribution_and_proof or self.want_payload_attributes or self.want_blob_sidecar;
    }

    /// Returns true if the given event matches the filter.
    pub fn matches(self: TopicFilter, ev: Event) bool {
        return switch (ev) {
            .head => self.want_head,
            .block => self.want_block,
            .finalized_checkpoint => self.want_finalized_checkpoint,
            .chain_reorg => self.want_chain_reorg,
            .attestation => self.want_attestation,
            .voluntary_exit => self.want_voluntary_exit,
            .contribution_and_proof => self.want_contribution_and_proof,
            .payload_attributes => self.want_payload_attributes,
            .blob_sidecar => self.want_blob_sidecar,
        };
    }
};

// ---------------------------------------------------------------------------
// Handler (fallback — SSE streaming is in http_server.zig)
// ---------------------------------------------------------------------------

/// GET /eth/v1/events
///
/// This handler is only reached if the SSE streaming path in http_server.zig
/// is somehow bypassed (e.g. via the test-only `handleRequest` method).
/// Returns 501 Not Implemented since SSE requires streaming.
pub fn getEvents(ctx: *ApiContext, query: []const u8) !void {
    _ = ctx;
    _ = query;
    return error.NotImplemented;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const test_helpers = @import("../test_helpers.zig");

test "getEvents returns NotImplemented (SSE handled in http_server)" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const result = getEvents(&tc.ctx, "topics=head");
    try std.testing.expectError(error.NotImplemented, result);
}

test "EventTopic.fromString known topics" {
    try std.testing.expectEqual(EventTopic.head, EventTopic.fromString("head").?);
    try std.testing.expectEqual(EventTopic.block, EventTopic.fromString("block").?);
    try std.testing.expectEqual(EventTopic.finalized_checkpoint, EventTopic.fromString("finalized_checkpoint").?);
    try std.testing.expectEqual(EventTopic.chain_reorg, EventTopic.fromString("chain_reorg").?);
    try std.testing.expectEqual(EventTopic.attestation, EventTopic.fromString("attestation").?);
    try std.testing.expectEqual(EventTopic.voluntary_exit, EventTopic.fromString("voluntary_exit").?);
    try std.testing.expectEqual(EventTopic.contribution_and_proof, EventTopic.fromString("contribution_and_proof").?);
    try std.testing.expectEqual(EventTopic.payload_attributes, EventTopic.fromString("payload_attributes").?);
    try std.testing.expectEqual(EventTopic.blob_sidecar, EventTopic.fromString("blob_sidecar").?);
}

test "EventTopic.fromString unknown topic returns null" {
    try std.testing.expect(EventTopic.fromString("not_a_topic") == null);
}

test "TopicFilter.parse single topic" {
    const f = TopicFilter.parse("head");
    try std.testing.expect(f.want_head);
    try std.testing.expect(!f.want_block);
    try std.testing.expect(!f.want_finalized_checkpoint);
}

test "TopicFilter.parse multiple topics" {
    const f = TopicFilter.parse("head,block,finalized_checkpoint");
    try std.testing.expect(f.want_head);
    try std.testing.expect(f.want_block);
    try std.testing.expect(f.want_finalized_checkpoint);
    try std.testing.expect(!f.want_chain_reorg);
}

test "TopicFilter.parse with spaces" {
    const f = TopicFilter.parse("head , block");
    try std.testing.expect(f.want_head);
    try std.testing.expect(f.want_block);
}

test "TopicFilter.parse unknown topics ignored" {
    const f = TopicFilter.parse("head,not_real,block");
    try std.testing.expect(f.want_head);
    try std.testing.expect(f.want_block);
    try std.testing.expect(f.hasAny());
}

test "TopicFilter.matches filters correctly" {
    const f = TopicFilter.parse("head,finalized_checkpoint");

    // head event should match
    try std.testing.expect(f.matches(.{ .head = .{
        .slot = 1,
        .block_root = [_]u8{0} ** 32,
        .state_root = [_]u8{0} ** 32,
        .epoch_transition = false,
    } }));

    // block event should NOT match (not subscribed)
    try std.testing.expect(!f.matches(.{ .block = .{
        .slot = 1,
        .block_root = [_]u8{0} ** 32,
    } }));

    // finalized_checkpoint should match
    try std.testing.expect(f.matches(.{ .finalized_checkpoint = .{
        .epoch = 1,
        .root = [_]u8{0} ** 32,
        .state_root = [_]u8{0} ** 32,
    } }));
}

test "TopicFilter empty query has nothing" {
    const f = TopicFilter.parse("");
    try std.testing.expect(!f.hasAny());
}

test "TopicFilter.parse new event types" {
    const f = TopicFilter.parse("attestation,voluntary_exit,contribution_and_proof,payload_attributes,blob_sidecar");
    try std.testing.expect(f.want_attestation);
    try std.testing.expect(f.want_voluntary_exit);
    try std.testing.expect(f.want_contribution_and_proof);
    try std.testing.expect(f.want_payload_attributes);
    try std.testing.expect(f.want_blob_sidecar);
    try std.testing.expect(!f.want_head);
    try std.testing.expect(f.hasAny());
}

test "TopicFilter.matches new event types" {
    const f = TopicFilter.parse("attestation,blob_sidecar");

    // attestation event should match
    try std.testing.expect(f.matches(.{ .attestation = .{
        .aggregation_bits = [_]u8{0x01} ++ [_]u8{0} ** 7,
        .slot = 1,
        .committee_index = 0,
        .beacon_block_root = [_]u8{0} ** 32,
        .source_epoch = 0,
        .source_root = [_]u8{0} ** 32,
        .target_epoch = 0,
        .target_root = [_]u8{0} ** 32,
        .signature = [_]u8{0} ** 96,
    } }));

    // blob_sidecar event should match
    try std.testing.expect(f.matches(.{ .blob_sidecar = .{
        .block_root = [_]u8{0} ** 32,
        .index = 0,
        .slot = 1,
        .kzg_commitment = [_]u8{0} ** 48,
        .versioned_hash = [_]u8{0} ** 32,
    } }));

    // voluntary_exit should NOT match (not subscribed)
    try std.testing.expect(!f.matches(.{ .voluntary_exit = .{
        .epoch = 1,
        .validator_index = 0,
        .signature = [_]u8{0} ** 96,
    } }));
}

test "EventTopic.toEventType maps new topics" {
    try std.testing.expectEqual(event_bus.EventType.attestation, EventTopic.attestation.toEventType().?);
    try std.testing.expectEqual(event_bus.EventType.voluntary_exit, EventTopic.voluntary_exit.toEventType().?);
    try std.testing.expectEqual(event_bus.EventType.contribution_and_proof, EventTopic.contribution_and_proof.toEventType().?);
    try std.testing.expectEqual(event_bus.EventType.payload_attributes, EventTopic.payload_attributes.toEventType().?);
    try std.testing.expectEqual(event_bus.EventType.blob_sidecar, EventTopic.blob_sidecar.toEventType().?);
    // bls_to_execution_change has no EventBus backing yet
    try std.testing.expect(EventTopic.bls_to_execution_change.toEventType() == null);
}
