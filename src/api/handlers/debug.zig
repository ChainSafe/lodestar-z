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

/// A beacon chain head: the pair (slot, root) of a chain tip visible to
/// fork-choice.
pub const HeadInfo = struct {
    slot: u64,
    root: [32]u8,
};

/// GET /eth/v2/debug/beacon/states/{state_id}
///
/// Returns raw SSZ bytes for the beacon state at the given state identifier.
///
/// Supports the following state_ids:
/// - `head` — returns SSZ of the current head state from the HeadStateCallback
/// - `finalized` — looks up the finalized state from the DB archive
/// - `genesis` — returns the genesis state (slot 0) from the DB archive
/// - slot number — returns the archived state at that slot
/// - hex root — looks up state by state_root in the DB archive
pub fn getState(ctx: *ApiContext, state_id: types.StateId) !HandlerResult([]const u8) {
    switch (state_id) {
        .head => {
            // Try to get the head state's raw SSZ via the DB.
            // The head state root is known from the head tracker.
            const state_root = ctx.head_tracker.head_state_root;
            if (try ctx.db.getStateArchiveByRoot(state_root)) |data| {
                return .{ .data = data, .meta = .{ .execution_optimistic = false, .finalized = false } };
            }
            // Head state might not be archived yet — not available.
            return error.StateNotAvailable;
        },
        .finalized => {
            // Look up the finalized slot's state from the archive.
            const finalized_slot = ctx.head_tracker.finalized_slot;
            const data = (try ctx.db.getStateArchive(finalized_slot)) orelse return error.StateNotAvailable;
            return .{ .data = data, .meta = .{ .execution_optimistic = false, .finalized = true } };
        },
        .genesis => {
            // Genesis state is at slot 0.
            const data = (try ctx.db.getStateArchive(0)) orelse return error.StateNotAvailable;
            return .{ .data = data, .meta = .{ .execution_optimistic = false, .finalized = true } };
        },
        .justified => {
            // Look up the justified slot's state from the archive.
            const justified_slot = ctx.head_tracker.justified_slot;
            const data = (try ctx.db.getStateArchive(justified_slot)) orelse return error.StateNotAvailable;
            return .{ .data = data, .meta = .{ .execution_optimistic = false, .finalized = false } };
        },
        .slot => |slot| {
            // Direct slot lookup in the archive.
            const data = (try ctx.db.getStateArchive(slot)) orelse return error.StateNotAvailable;
            const is_finalized = slot <= ctx.head_tracker.finalized_slot;
            return .{ .data = data, .meta = .{ .execution_optimistic = false, .finalized = is_finalized } };
        },
        .root => |root| {
            // Look up by state root.
            const data = (try ctx.db.getStateArchiveByRoot(root)) orelse return error.StateNotAvailable;
            return .{ .data = data, .meta = .{ .execution_optimistic = false, .finalized = false } };
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
pub fn getHeads(ctx: *ApiContext) !HandlerResult([]const HeadInfo) {
    // Allocate a single-element slice on ctx.allocator so the caller can
    // free it uniformly.
    const heads = try ctx.allocator.alloc(HeadInfo, 1);
    heads[0] = .{
        .slot = ctx.head_tracker.head_slot,
        .root = ctx.head_tracker.head_root,
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
    const fake_state = [_]u8{0xDE, 0xAD, 0xBE, 0xEF};
    try tc.db.putStateArchive(42, [_]u8{0x11} ** 32, &fake_state);

    const result = try getState(&tc.ctx, .{ .slot = 42 });
    defer tc.ctx.allocator.free(result.data);
    try std.testing.expectEqualSlices(u8, &fake_state, result.data);
}

test "getState root returns data from DB archive" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const fake_state = [_]u8{0xCA, 0xFE};
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
    try std.testing.expectEqual(tc.ctx.head_tracker.head_slot, result.data[0].slot);
    try std.testing.expectEqual(tc.ctx.head_tracker.head_root, result.data[0].root);
}
