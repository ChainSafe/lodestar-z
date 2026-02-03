const std = @import("std");
const napi = @import("zapi:napi");
const builtin = @import("builtin");
const fork_types = @import("fork_types");
const state_transition = @import("state_transition");
const CachedBeaconState = state_transition.CachedBeaconState;
const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;

pub var gpa: std.heap.DebugAllocator(.{}) = .init;
const allocator = if (builtin.mode == .Debug)
    gpa.allocator()
else
    std.heap.c_allocator;

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
///
/// Returns: BeaconStateView (the post-state)
pub fn stateTransition(
    env: napi.Env,
    cb: napi.CallbackInfo(4),
) !napi.Value {
    const pre_state_value = cb.arg(0);
    const cached_state = try env.unwrap(CachedBeaconState, pre_state_value);

    const bytes_info = try cb.arg(1).getTypedarrayInfo();
    const current_epoch = state_transition.computeEpochAtSlot(try cached_state.state.slot());
    const fork = @import("config").mainnet.config.forkSeqAtEpoch(current_epoch);
    const signed_block = try AnySignedBeaconBlock.deserialize(
        allocator,
        .full,
        fork,
        bytes_info.data,
    );
    defer signed_block.deinit(allocator);

    var opts: state_transition.TransitionOpt = .{};
    if (cb.getArg(2)) |options_arg| {
        if (try options_arg.typeof() == .object) {
            if (try options_arg.hasNamedProperty("verifyStateRoot")) {
                opts.verify_state_root = try (try options_arg.getNamedProperty("verifyStateRoot")).getValueBool();
            }
            if (try options_arg.hasNamedProperty("verifyProposer")) {
                opts.verify_proposer = try (try options_arg.getNamedProperty("verifyProposer")).getValueBool();
            }
            if (try options_arg.hasNamedProperty("verifySignatures")) {
                opts.verify_signatures = try (try options_arg.getNamedProperty("verifySignatures")).getValueBool();
            }
            if (try options_arg.hasNamedProperty("transferCache")) {
                opts.transfer_cache = try (try options_arg.getNamedProperty("transferCache")).getValueBool();
            }
        }
    }

    const post_state = try state_transition.stateTransition(
        allocator,
        cached_state,
        signed_block,
        opts,
    );
    errdefer {
        post_state.deinit();
        allocator.destroy(post_state);
    }

    const ctor = try pre_state_value.getNamedProperty("constructor");
    const new_state_value = try env.newInstance(ctor, .{});
    const dummy_state = try env.unwrap(CachedBeaconState, new_state_value);

    dummy_state.* = post_state.*;
    allocator.destroy(post_state);

    return new_state_value;
}

pub fn register(env: napi.Env, exports: napi.Value) !void {
    const state_transition_obj = try env.createObject();
    try state_transition_obj.setNamedProperty("stateTransition", try env.createFunction(
        "stateTransition",
        4,
        stateTransition,
        null,
    ));
    try exports.setNamedProperty("state_transition", state_transition_obj);
}
