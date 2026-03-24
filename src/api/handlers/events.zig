//! Beacon events API handlers.
//!
//! Implements the Server-Sent Events (SSE) endpoint:
//!   GET /eth/v1/events?topics=head,block,finalized_checkpoint,...
//!
//! SSE delivers a stream of newline-delimited `data: {...}` payloads over an
//! HTTP/1.1 keep-alive connection.  Full SSE support requires asynchronous
//! I/O and an event bus in the BeaconNode; neither is wired up yet, so the
//! handler returns NotImplemented.  The event type definitions below match
//! the Ethereum Beacon API specification and will be used once the event bus
//! lands.
//!
//! Reference: https://ethereum.github.io/beacon-APIs/#/Events

const std = @import("std");
const types = @import("../types.zig");
const context = @import("../context.zig");
const ApiContext = context.ApiContext;

// ---------------------------------------------------------------------------
// Event types (spec-compatible)
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
};

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// GET /eth/v1/events
///
/// Subscribe to beacon chain events via Server-Sent Events (SSE).
///
/// The `topics` query parameter is a comma-separated list of event topic
/// names (e.g. `topics=head,finalized_checkpoint`).
///
/// Note: This endpoint requires a long-lived streaming connection and an
/// internal event bus.  Neither is implemented yet; the handler always
/// returns NotImplemented.  When the event bus lands, replace this stub
/// with the real subscription logic.
pub fn getEvents(_: *ApiContext, _: []const u8) !void {
    // TODO: Implement SSE streaming once event bus is wired.
    // Steps:
    //   1. Parse topic list from query string.
    //   2. Subscribe to the beacon event bus for each requested topic.
    //   3. Set Content-Type: text/event-stream on the response.
    //   4. Write "data: {...}\n\n" for each incoming event.
    return error.NotImplemented;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const test_helpers = @import("../test_helpers.zig");

test "getEvents returns NotImplemented (stub)" {
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
}

test "EventTopic.fromString unknown topic returns null" {
    try std.testing.expect(EventTopic.fromString("not_a_topic") == null);
}
