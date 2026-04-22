const std = @import("std");
const zapi = @import("zapi");
const js = zapi.js;
const napi = zapi.napi;
const builtin = @import("builtin");
const fork_types = @import("fork_types");
const st = @import("state_transition");
const CachedBeaconState = st.CachedBeaconState;
const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;

var gpa: std.heap.DebugAllocator(.{}) = .init;
const allocator = if (builtin.mode == .Debug)
    gpa.allocator()
else
    std.heap.c_allocator;

fn parseOptions(options: ?js.Value) !st.TransitionOpt {
    var transit_options: st.TransitionOpt = .{};
    if (options) |value| {
        const raw = value.toValue();
        if (try raw.typeof() == .object) {
            if (try raw.hasNamedProperty("verifyStateRoot")) {
                transit_options.verify_state_root = try (try raw.getNamedProperty("verifyStateRoot")).getValueBool();
            }
            if (try raw.hasNamedProperty("verifyProposer")) {
                transit_options.verify_proposer = try (try raw.getNamedProperty("verifyProposer")).getValueBool();
            }
            if (try raw.hasNamedProperty("verifySignatures")) {
                transit_options.verify_signatures = try (try raw.getNamedProperty("verifySignatures")).getValueBool();
            }
            if (try raw.hasNamedProperty("transferCache")) {
                transit_options.transfer_cache = try (try raw.getNamedProperty("transferCache")).getValueBool();
            }
        }
    }
    return transit_options;
}

/// Perform a state transition given a signed beacon block.
///
/// Arguments:
/// - arg 0: BeaconStateView instance (the pre-state)
/// - arg 1: signed block bytes (Uint8Array)
/// - arg 2: options object (optional) with:
///   - verifyStateRoot: bool (default true)
///   - verifyProposer: bool (default true)
///   - verifySignatures: bool (default false)
///   - transferCache: bool (default true)
/// Returns: BeaconStateView (the post-state)
pub fn stateTransition(
    pre_state_value: js.Value,
    signed_block_bytes: js.Uint8Array,
    options: ?js.Value,
) !js.Value {
    const env = js.env();
    const pre_state = pre_state_value.toValue();
    const cached_state = try env.unwrap(CachedBeaconState, pre_state);
    const signed_block_bytes_slice = try signed_block_bytes.toSlice();

    const current_epoch = st.computeEpochAtSlot(try cached_state.state.slot());
    const fork = cached_state.config.forkSeqAtEpoch(current_epoch);
    const signed_block = try AnySignedBeaconBlock.deserialize(
        allocator,
        .full,
        fork,
        signed_block_bytes_slice,
    );
    defer signed_block.deinit(allocator);

    const post_state = try st.stateTransition(
        allocator,
        cached_state,
        signed_block,
        try parseOptions(options),
    );
    errdefer {
        post_state.deinit();
        allocator.destroy(post_state);
    }

    const ctor = try pre_state.getNamedProperty("constructor");
    const new_state_value = try env.newInstance(ctor, .{});
    const dummy_state = try env.unwrap(CachedBeaconState, new_state_value);
    dummy_state.* = post_state.*;
    allocator.destroy(post_state);

    return .{ .val = new_state_value };
}
