const std = @import("std");

const types = @import("consensus_types");
const preset = @import("preset").preset;

const Slot = types.primitive.Slot.Type;

const BeaconConfig = @import("config").BeaconConfig;
const BeaconState = @import("types/beacon_state.zig").BeaconState;
const EpochCache = @import("./cache/epoch_cache.zig").EpochCache;
pub const SignedBeaconBlock = @import("types/beacon_block.zig").SignedBeaconBlock;
const verifyProposerSignature = @import("./signature_sets/proposer.zig").verifyProposerSignature;
pub const processBlock = @import("./block/process_block.zig").processBlock;
const EpochTransitionCacheOpts = @import("cache/epoch_transition_cache.zig").EpochTransitionCacheOpts;
const EpochTransitionCache = @import("cache/epoch_transition_cache.zig").EpochTransitionCache;
const processEpoch = @import("epoch/process_epoch.zig").processEpoch;
const computeEpochAtSlot = @import("utils/epoch.zig").computeEpochAtSlot;
const processSlot = @import("slot/process_slot.zig").processSlot;
const deinitReusedEpochTransitionCache = @import("cache/epoch_transition_cache.zig").deinitReusedEpochTransitionCache;
const upgradeStateToAltair = @import("slot/upgrade_state_to_altair.zig").upgradeStateToAltair;
const upgradeStateToBellatrix = @import("slot/upgrade_state_to_bellatrix.zig").upgradeStateToBellatrix;
const upgradeStateToCapella = @import("slot/upgrade_state_to_capella.zig").upgradeStateToCapella;
const upgradeStateToDeneb = @import("slot/upgrade_state_to_deneb.zig").upgradeStateToDeneb;
const upgradeStateToElectra = @import("slot/upgrade_state_to_electra.zig").upgradeStateToElectra;
const upgradeStateToFulu = @import("slot/upgrade_state_to_fulu.zig").upgradeStateToFulu;

const SignedBlock = @import("types/block.zig").SignedBlock;

pub const ExecutionPayloadStatus = enum(u8) {
    pre_merge,
    invalid,
    valid,
};

pub const BlockExternalData = struct {
    execution_payload_status: ExecutionPayloadStatus,
    data_availability_status: enum(u8) {
        pre_data,
        out_of_range,
        available,
    },
};

pub fn processSlots(
    allocator: std.mem.Allocator,
    config: *const BeaconConfig,
    epoch_cache: *EpochCache,
    state: *BeaconState,
    slot: Slot,
    _: EpochTransitionCacheOpts,
) !void {
    if (try state.slot() > slot) return error.outdatedSlot;

    while (try state.slot() < slot) {
        try processSlot(state);

        const next_slot = try state.slot() + 1;
        if (next_slot % preset.SLOTS_PER_EPOCH == 0) {
            // TODO(bing): metrics
            // const epochTransitionTimer = metrics?.epochTransitionTime.startTimer();

            // TODO(bing): metrics: time beforeProcessEpoch
            var epoch_transition_cache = try EpochTransitionCache.init(
                allocator,
                config,
                epoch_cache,
                state,
            );
            defer {
                epoch_transition_cache.deinit();
                allocator.destroy(epoch_transition_cache);
            }
            switch (state.forkSeq()) {
                inline else => |f| {
                    try processEpoch(
                        f,
                        allocator,
                        config,
                        epoch_cache,
                        &@field(state, f),
                        epoch_transition_cache,
                    );
                },
            }
            // TODO(bing): registerValidatorStatuses

            try state.setSlot(next_slot);

            try epoch_cache.afterProcessEpoch(state, epoch_transition_cache);
            // state.commit

            const state_epoch = computeEpochAtSlot(next_slot);

            if (state_epoch == config.chain.ALTAIR_FORK_EPOCH) {
                state.* = .{ .altair = try upgradeStateToAltair(
                    allocator,
                    config,
                    epoch_cache,
                    @ptrCast(&state.phase0),
                ) };
            }
            if (state_epoch == config.chain.BELLATRIX_FORK_EPOCH) {
                state.* = .{ .bellatrix = try upgradeStateToBellatrix(
                    config,
                    epoch_cache,
                    state,
                ) };
            }
            if (state_epoch == config.chain.CAPELLA_FORK_EPOCH) {
                state.* = .{ .capella = try upgradeStateToCapella(
                    allocator,
                    state,
                ) };
            }
            if (state_epoch == config.chain.DENEB_FORK_EPOCH) {
                state.* = .{ .deneb = try upgradeStateToDeneb(allocator, state) };
            }
            if (state_epoch == config.chain.ELECTRA_FORK_EPOCH) {
                state.* = .{ .electra = try upgradeStateToElectra(allocator, state) };
            }
            if (state_epoch == config.chain.FULU_FORK_EPOCH) {
                state.* = .{ .fulu = try upgradeStateToFulu(allocator, state) };
            }

            try epoch_cache.finalProcessEpoch(state);
        } else {
            try state.setSlot(next_slot);
        }

        //epochTransitionTimer
    }
}

pub const TransitionOpt = struct {
    verify_state_root: bool = true,
    verify_proposer: bool = true,
    verify_signatures: bool = false,
    do_not_transfer_cache: bool = false,
};

pub fn stateTransition(
    allocator: std.mem.Allocator,
    config: *const BeaconConfig,
    epoch_cache: *EpochCache,
    state: *BeaconState,
    signed_block: SignedBlock,
    opts: TransitionOpt,
) !*BeaconState {
    const block = signed_block.message();
    const block_slot = switch (block) {
        .regular => |b| b.slot(),
        .blinded => |b| b.slot(),
    };

    const post_state = try state.clone(allocator, .{ .transfer_cache = !opts.do_not_transfer_cache });

    errdefer {
        post_state.deinit();
        allocator.destroy(post_state);
    }

    //TODO(bing): metrics
    //if (metrics) {
    //  onStateCloneMetrics(postState, metrics, StateCloneSource.stateTransition);
    //}

    try processSlots(allocator, post_state, block_slot, .{});

    // Verify proposer signature only
    if (opts.verify_proposer and !try verifyProposerSignature(post_state, signed_block)) {
        return error.InvalidBlockSignature;
    }

    //  // Note: time only on success
    //  const processBlockTimer = metrics?.processBlockTime.startTimer();
    //
    try processBlock(
        allocator,
        post_state,
        block,
        BlockExternalData{
            .execution_payload_status = .valid,
            .data_availability_status = .available,
        },
        .{ .verify_signature = opts.verify_signatures },
    );
    //
    // TODO(bing): commit
    //  const processBlockCommitTimer = metrics?.processBlockCommitTime.startTimer();
    //  postState.commit();
    //  processBlockCommitTimer?.();

    //  // Note: time only on success. Include processBlock and commit
    //  processBlockTimer?.();
    // TODO(bing): metrics
    //  if (metrics) {
    //    onPostStateMetrics(postState, metrics);
    //  }

    // Verify state root
    if (opts.verify_state_root) {
        //    const hashTreeRootTimer = metrics?.stateHashTreeRootTime.startTimer({
        //      source: StateHashTreeRootSource.stateTransition,
        //    });
        const post_state_root = try post_state.state.hashTreeRoot();
        //    hashTreeRootTimer?.();

        const block_state_root = switch (block) {
            .regular => |b| b.stateRoot(),
            .blinded => |b| b.stateRoot(),
        };
        if (!std.mem.eql(u8, post_state_root, &block_state_root)) {
            return error.InvalidStateRoot;
        }
    } else {
        // Even if we don't verify the state_root, commit the tree changes
        try post_state.state.commit();
    }

    return post_state;
}

pub fn deinitStateTransition() void {
    deinitReusedEpochTransitionCache();
}
