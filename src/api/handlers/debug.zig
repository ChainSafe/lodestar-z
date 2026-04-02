//! Debug API handlers.
//!
//! Pure functions implementing the `/eth/v2/debug/*` Beacon API endpoints.
//! These endpoints expose raw chain internals — primarily for debugging
//! and testing. Production clients should prefer the standard endpoints.
//!
//! Reference: https://ethereum.github.io/beacon-APIs/#/Debug

const std = @import("std");
const types = @import("../types.zig");
const context = @import("../context.zig");
const ApiContext = context.ApiContext;
const CachedBeaconState = context.CachedBeaconState;
const preset = @import("preset").preset;
const handler_result = @import("../handler_result.zig");
const HandlerResult = handler_result.HandlerResult;
const ResponseMeta = handler_result.ResponseMeta;

/// A beacon chain head for the debug API response: (slot, root) of a chain tip
/// visible to fork-choice. This is the API response shape, not to be confused
/// with chain.HeadInfo which includes additional chain state.
pub const DebugChainHead = struct {
    slot: u64,
    root: [32]u8,
};

/// GET /eth/v2/debug/beacon/states/{state_id}
///
/// Returns raw SSZ bytes for the beacon state at the given state identifier.
///
/// Supports the following state_ids:
/// - `head` — returns SSZ of the current head state via the chain-backed state query
/// - `finalized` — returns the finalized checkpoint state
/// - `genesis` — returns the genesis state (slot 0)
/// - slot number — returns the canonical/archived state at that slot
/// - hex root — looks up state by state_root
pub fn getState(ctx: *ApiContext, state_id: types.StateId) !HandlerResult([]const u8) {
    const head = ctx.currentHeadTracker();
    switch (state_id) {
        .head => {
            const state_root = head.head_state_root;
            if (try ctx.stateBytesByRoot(state_root)) |data| {
                return .{
                    .data = data,
                    .meta = .{
                        .execution_optimistic = ctx.blockExecutionOptimistic(head.head_root),
                        .finalized = false,
                    },
                };
            }
            return error.StateNotAvailable;
        },
        .finalized => {
            const finalized_root = (try ctx.stateRootByBlockRoot(head.finalized_root)) orelse
                return error.StateNotAvailable;
            const data = (try ctx.stateBytesByRoot(finalized_root)) orelse return error.StateNotAvailable;
            return .{ .data = data, .meta = .{ .execution_optimistic = false, .finalized = true } };
        },
        .genesis => {
            const data = (try ctx.stateBytesBySlot(0)) orelse return error.StateNotAvailable;
            return .{ .data = data, .meta = .{ .execution_optimistic = false, .finalized = true } };
        },
        .justified => {
            const justified_root = (try ctx.stateRootByBlockRoot(head.justified_root)) orelse
                return error.StateNotAvailable;
            const data = (try ctx.stateBytesByRoot(justified_root)) orelse return error.StateNotAvailable;
            return .{
                .data = data,
                .meta = .{
                    .execution_optimistic = ctx.blockExecutionOptimistic(head.justified_root),
                    .finalized = false,
                },
            };
        },
        .slot => |slot| {
            const data = (try ctx.stateBytesBySlot(slot)) orelse return error.StateNotAvailable;
            const is_finalized = slot <= head.finalized_slot;
            return .{
                .data = data,
                .meta = .{
                    .execution_optimistic = try ctx.stateExecutionOptimisticBySlot(slot),
                    .finalized = is_finalized,
                },
            };
        },
        .root => |root| {
            const data = (try ctx.stateBytesByRoot(root)) orelse return error.StateNotAvailable;
            return .{
                .data = data,
                .meta = .{
                    .execution_optimistic = ctx.stateExecutionOptimisticByRoot(root),
                    .finalized = false,
                },
            };
        },
    }
}

/// GET /eth/v2/debug/beacon/heads
///
/// Returns the list of fork-choice chain heads.
///
/// Note: A full implementation would query the fork-choice store for all
/// known tips. Currently the head tracker exposes only the canonical head,
/// so we return that single entry.
pub fn getHeads(ctx: *ApiContext) !HandlerResult([]const DebugChainHead) {
    const head = ctx.currentHeadTracker();
    // Allocate a single-element slice on ctx.allocator so the caller can
    // free it uniformly.
    const heads = try ctx.allocator.alloc(DebugChainHead, 1);
    heads[0] = .{
        .slot = head.head_slot,
        .root = head.head_root,
    };
    return .{ .data = heads };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const test_helpers = @import("../test_helpers.zig");

test "getState head returns StateNotAvailable when not archived" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const result = getState(&tc.ctx, .head);
    try std.testing.expectError(error.StateNotAvailable, result);
}

test "getState head returns serialized bytes from live state query" {
    const allocator = std.testing.allocator;
    var tc = test_helpers.makeTestContext(allocator);
    defer test_helpers.destroyTestContext(allocator, &tc);

    const state_transition = @import("state_transition");
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 4);
    defer test_state.deinit();

    tc.chain_fixture.head_state = test_state.cached_state;
    tc.chain_fixture.state_by_root = test_state.cached_state;

    const result = try getState(&tc.ctx, .head);
    defer allocator.free(result.data);

    const expected = try test_state.cached_state.state.serialize(allocator);
    defer allocator.free(expected);

    try std.testing.expectEqualSlices(u8, expected, result.data);
}

test "getState finalized returns StateNotAvailable when not in DB" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const result = getState(&tc.ctx, .finalized);
    try std.testing.expectError(error.StateNotAvailable, result);
}

test "getState genesis returns StateNotAvailable when not in DB" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const result = getState(&tc.ctx, .genesis);
    try std.testing.expectError(error.StateNotAvailable, result);
}

test "getState slot returns StateNotAvailable for unknown slot" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const result = getState(&tc.ctx, .{ .slot = 42 });
    try std.testing.expectError(error.StateNotAvailable, result);
}

test "getState slot returns data from DB archive" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    // Store a fake state archive at slot 42.
    const fake_state = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    try tc.db.putStateArchive(42, [_]u8{0x11} ** 32, &fake_state);

    const result = try getState(&tc.ctx, .{ .slot = 42 });
    defer tc.ctx.allocator.free(result.data);
    try std.testing.expectEqualSlices(u8, &fake_state, result.data);
}

test "getState root returns data from DB archive" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const fake_state = [_]u8{ 0xCA, 0xFE };
    const state_root = [_]u8{0x22} ** 32;
    try tc.db.putStateArchive(100, state_root, &fake_state);

    const result = try getState(&tc.ctx, .{ .root = state_root });
    defer tc.ctx.allocator.free(result.data);
    try std.testing.expectEqualSlices(u8, &fake_state, result.data);
}

test "getHeads returns single head entry" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const result = try getHeads(&tc.ctx);
    defer tc.ctx.allocator.free(result.data);

    try std.testing.expectEqual(@as(usize, 1), result.data.len);
    try std.testing.expectEqual(tc.head_tracker.head_slot, result.data[0].slot);
    try std.testing.expectEqual(tc.head_tracker.head_root, result.data[0].root);
}

// ---------------------------------------------------------------------------
// Fork choice debug endpoint
// ---------------------------------------------------------------------------

/// GET /eth/v1/debug/fork_choice
///
/// Returns the full fork choice tree for debugging.
/// Stub until the fork-choice store is wired into the API context.
pub fn getForkChoice(ctx: *ApiContext) !HandlerResult(types.ForkChoiceDump) {
    const head = ctx.currentHeadTracker();
    // TODO: query fork-choice store via a callback.
    // For now return a single-node tree representing the current head.
    const nodes = try ctx.allocator.alloc(types.ForkChoiceNode, 1);
    nodes[0] = .{
        .slot = head.head_slot,
        .block_root = head.head_root,
        .parent_root = null,
        .justified_epoch = head.justified_slot / preset.SLOTS_PER_EPOCH,
        .finalized_epoch = head.finalized_slot / preset.SLOTS_PER_EPOCH,
        .weight = 0,
        .validity = "valid",
        .execution_block_hash = [_]u8{0} ** 32,
    };

    const justified_epoch = head.justified_slot / preset.SLOTS_PER_EPOCH;
    const finalized_epoch = head.finalized_slot / preset.SLOTS_PER_EPOCH;

    return .{
        .data = .{
            .justified_checkpoint = .{
                .epoch = justified_epoch,
                .root = head.justified_root,
            },
            .finalized_checkpoint = .{
                .epoch = finalized_epoch,
                .root = head.finalized_root,
            },
            .fork_choice_nodes = nodes,
        },
        .meta = .{},
    };
}
