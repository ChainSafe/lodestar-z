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
/// Note: Full implementation requires state regeneration (StateRegen) to
/// be wired into the ApiContext.  Until then we return StateNotAvailable
/// for all identifiers other than a synthetic head stub.
pub fn getState(ctx: *ApiContext, state_id: types.StateId) ![]const u8 {
    _ = ctx;
    _ = state_id;
    // TODO: Implement once state regen is wired into ApiContext.
    // Steps:
    //   1. Resolve state_id to a (slot, root) pair using head_tracker / db.
    //   2. Call ctx.regen.getStateAtSlot(slot) to obtain the BeaconState.
    //   3. SSZ-serialize the state and return the bytes.
    // state regen is not yet wired to the API context.
    return error.StateNotAvailable;
}

/// GET /eth/v2/debug/beacon/heads
///
/// Returns the list of fork-choice chain heads.
///
/// Note: A full implementation would query the fork-choice store for all
/// known tips. Currently the head tracker exposes only the canonical head,
/// so we return that single entry.
pub fn getHeads(ctx: *ApiContext) ![]const HeadInfo {
    // Allocate a single-element slice on ctx.allocator so the caller can
    // free it uniformly.
    const heads = try ctx.allocator.alloc(HeadInfo, 1);
    heads[0] = .{
        .slot = ctx.head_tracker.head_slot,
        .root = ctx.head_tracker.head_root,
    };
    return heads;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const test_helpers = @import("../test_helpers.zig");

test "getState returns StateNotAvailable (stub)" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);
    const result = getState(&tc.ctx, .head);
    try std.testing.expectError(error.StateNotAvailable, result);
}

test "getHeads returns single head entry" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const heads = try getHeads(&tc.ctx);
    defer tc.ctx.allocator.free(heads);

    try std.testing.expectEqual(@as(usize, 1), heads.len);
    try std.testing.expectEqual(tc.ctx.head_tracker.head_slot, heads[0].slot);
    try std.testing.expectEqual(tc.ctx.head_tracker.head_root, heads[0].root);
}
