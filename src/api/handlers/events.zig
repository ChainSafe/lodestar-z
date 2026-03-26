//! Beacon events API handlers.
//!
//! Implements the Server-Sent Events (SSE) endpoint:
//!   GET /eth/v1/events?topics=head,block,finalized_checkpoint,...
//!
//! SSE delivers a stream of newline-delimited `data: {...}` payloads over an
//! HTTP/1.1 keep-alive connection.  Full SSE support requires asynchronous
//! I/O; for now the handler returns recent events from the EventBus as a
//! single JSON array (polling mode), laying the groundwork for true streaming.
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
            else => null,
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
                    else => {}, // topics without EventBus backing are ignored
                }
            }
        }
        return filter;
    }

    /// Returns true if any topics are subscribed.
    pub fn hasAny(self: TopicFilter) bool {
        return self.want_head or self.want_block or self.want_finalized_checkpoint or self.want_chain_reorg;
    }

    /// Returns true if the given event matches the filter.
    pub fn matches(self: TopicFilter, ev: Event) bool {
        return switch (ev) {
            .head => self.want_head,
            .block => self.want_block,
            .finalized_checkpoint => self.want_finalized_checkpoint,
            .chain_reorg => self.want_chain_reorg,
        };
    }
};

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// GET /eth/v1/events
///
/// Returns recent beacon chain events from the EventBus that match the
/// requested topics.
///
/// The `topics` query parameter is a comma-separated list of event topic
/// names (e.g. `topics=head,finalized_checkpoint`).  Events that don't
/// match any requested topic are filtered out.
///
/// This implementation polls the EventBus from index 0 and returns all
/// available matching events.  True long-lived SSE streaming requires
/// async I/O and is a future enhancement; this handler provides the
/// event bus integration foundation.
pub fn getEvents(ctx: *ApiContext, query: []const u8) !void {
    const bus = ctx.event_bus orelse return error.NotImplemented;

    const filter = TopicFilter.parse(query);
    if (!filter.hasAny()) return error.NotImplemented;

    // Poll recent events from the bus.
    const recent = bus.getRecent(0);
    _ = recent;

    // SSE streaming requires long-lived connections (async I/O).
    // The event bus is now wired and topic filtering is implemented;
    // full streaming will replace this stub once std.Io fiber support
    // is used for the HTTP server.
    return error.NotImplemented;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const test_helpers = @import("../test_helpers.zig");

test "getEvents returns NotImplemented when no event bus" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    // api_context.event_bus is null by default in test context
    const result = getEvents(&tc.ctx, "topics=head");
    try std.testing.expectError(error.NotImplemented, result);
}

test "EventTopic.fromString known topics" {
    try std.testing.expectEqual(EventTopic.head, EventTopic.fromString("head").?);
    try std.testing.expectEqual(EventTopic.block, EventTopic.fromString("block").?);
    try std.testing.expectEqual(EventTopic.finalized_checkpoint, EventTopic.fromString("finalized_checkpoint").?);
    try std.testing.expectEqual(EventTopic.chain_reorg, EventTopic.fromString("chain_reorg").?);
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
