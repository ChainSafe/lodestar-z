const std = @import("std");

const types = @import("consensus_types");
const preset = @import("preset").preset;

const Slot = types.primitive.Slot.Type;

const BeaconConfig = @import("config").BeaconConfig;
const AnyBeaconState = @import("fork_types").AnyBeaconState;
const AnySignedBeaconBlock = @import("fork_types").AnySignedBeaconBlock;
const EpochCache = @import("./cache/epoch_cache.zig").EpochCache;
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
    state: *AnyBeaconState,
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
            defer epoch_transition_cache.deinit();

            switch (state.forkSeq()) {
                inline else => |f| {
                    try processEpoch(
                        f,
                        allocator,
                        config,
                        epoch_cache,
                        state.castToFork(f),
                        &epoch_transition_cache,
                    );
                },
            }
            // TODO(bing): registerValidatorStatuses

            try state.setSlot(next_slot);

            try epoch_cache.afterProcessEpoch(state, &epoch_transition_cache);
            // state.commit

            const state_epoch = computeEpochAtSlot(next_slot);

            if (state_epoch == config.chain.ALTAIR_FORK_EPOCH) {
                state.* = .{ .altair = (try upgradeStateToAltair(
                    allocator,
                    config,
                    epoch_cache,
                    try state.tryCastToFork(.phase0),
                )).inner };
            }
            if (state_epoch == config.chain.BELLATRIX_FORK_EPOCH) {
                state.* = .{ .bellatrix = (try upgradeStateToBellatrix(
                    config,
                    epoch_cache,
                    try state.tryCastToFork(.altair),
                )).inner };
            }
            if (state_epoch == config.chain.CAPELLA_FORK_EPOCH) {
                state.* = .{ .capella = (try upgradeStateToCapella(
                    allocator,
                    config,
                    epoch_cache,
                    try state.tryCastToFork(.bellatrix),
                )).inner };
            }
            if (state_epoch == config.chain.DENEB_FORK_EPOCH) {
                state.* = .{ .deneb = (try upgradeStateToDeneb(
                    allocator,
                    config,
                    epoch_cache,
                    try state.tryCastToFork(.capella),
                )).inner };
            }
            if (state_epoch == config.chain.ELECTRA_FORK_EPOCH) {
                state.* = .{ .electra = (try upgradeStateToElectra(
                    allocator,
                    config,
                    epoch_cache,
                    try state.tryCastToFork(.deneb),
                )).inner };
            }
            if (state_epoch == config.chain.FULU_FORK_EPOCH) {
                state.* = .{ .fulu = (try upgradeStateToFulu(
                    allocator,
                    config,
                    epoch_cache,
                    try state.tryCastToFork(.electra),
                )).inner };
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

pub const StateTransitionResult = struct {
    state: AnyBeaconState,
    epoch_cache: *EpochCache,

    pub fn deinit(self: *StateTransitionResult) void {
        self.state.deinit();
        self.epoch_cache.deinit();
    }
};

pub fn stateTransition(
    allocator: std.mem.Allocator,
    config: *const BeaconConfig,
    epoch_cache: *EpochCache,
    state: *AnyBeaconState,
    signed_block: AnySignedBeaconBlock,
    opts: TransitionOpt,
) !*StateTransitionResult {
    const block = signed_block.beaconBlock();
    const block_slot = block.slot();

    var post_state = try state.clone(
        .{ .transfer_cache = !opts.do_not_transfer_cache },
    );
    const post_epoch_cache = try epoch_cache.clone(allocator);

    errdefer post_state.deinit();
    errdefer post_epoch_cache.deinit();

    //TODO(bing): metrics
    //if (metrics) {
    //  onStateCloneMetrics(postState, metrics, StateCloneSource.stateTransition);
    //}

    try processSlots(
        allocator,
        config,
        post_epoch_cache,
        &post_state,
        block_slot,
        .{},
    );

    // Verify proposer signature only
    if (opts.verify_proposer and !try verifyProposerSignature(
        allocator,
        config,
        post_epoch_cache,
        signed_block,
    )) {
        return error.InvalidBlockSignature;
    }

    //  // Note: time only on success
    //  const processBlockTimer = metrics?.processBlockTime.startTimer();
    //
    if (block.forkSeq() != post_state.forkSeq()) {
        return error.InvalidBlockForkForState;
    }
    switch (post_state.forkSeq()) {
        inline else => |f| {
            switch (block.blockType()) {
                inline else => |bt| {
                    if (comptime bt == .blinded and f.lt(.bellatrix)) {
                        return error.InvalidBlockTypeForFork;
                    }
                    try processBlock(
                        f,
                        allocator,
                        config,
                        post_epoch_cache,
                        post_state.castToFork(f),
                        bt,
                        block.castToFork(bt, f),
                        BlockExternalData{
                            .execution_payload_status = .valid,
                            .data_availability_status = .available,
                        },
                        .{ .verify_signature = opts.verify_signatures },
                    );
                },
            }
        },
    }

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
        const post_state_root = try post_state.hashTreeRoot();
        //    hashTreeRootTimer?.();

        const block_state_root = block.stateRoot();
        if (!std.mem.eql(u8, post_state_root, block_state_root)) {
            return error.InvalidStateRoot;
        }
    } else {
        // Even if we don't verify the state_root, commit the tree changes
        try post_state.commit();
    }

    const result = try allocator.create(StateTransitionResult);
    result.* = .{
        .state = post_state,
        .epoch_cache = post_epoch_cache,
    };
    return result;
}

pub fn deinitStateTransition() void {
    deinitReusedEpochTransitionCache();
}

const TestCase = struct {
    transition_opt: TransitionOpt,
    expect_error: bool,
};

const TestCachedBeaconState = @import("test_utils/root.zig").TestCachedBeaconState;
const generateElectraBlock = @import("test_utils/generate_block.zig").generateElectraBlock;
const testing = std.testing;
const Node = @import("persistent_merkle_tree").Node;

test "state transition - electra block" {
    const test_cases = [_]TestCase{
        .{ .transition_opt = .{ .verify_signatures = true }, .expect_error = true },
        .{ .transition_opt = .{ .verify_signatures = false, .verify_proposer = true }, .expect_error = true },
        .{ .transition_opt = .{ .verify_signatures = false, .verify_proposer = false, .verify_state_root = true }, .expect_error = true },
        // this runs through epoch transition + process block without verifications
        .{ .transition_opt = .{ .verify_signatures = false, .verify_proposer = false, .verify_state_root = false }, .expect_error = false },
    };

    inline for (test_cases) |tc| {
        const allocator = std.testing.allocator;

        var test_state = try TestCachedBeaconState.init(allocator, 256);
        defer test_state.deinit();

        var electra_block = types.electra.SignedBeaconBlock.default_value;
        try generateElectraBlock(allocator, test_state.cached_state, &electra_block);
        defer types.electra.SignedBeaconBlock.deinit(allocator, &electra_block);

        const signed_beacon_block = AnySignedBeaconBlock{ .full_electra = &electra_block };

        // this returns the error so no need to handle returned post_state
        // TODO: if blst can publish BlstError.BadEncoding, can just use testing.expectError
        // testing.expectError(blst.c.BLST_BAD_ENCODING, stateTransition(allocator, test_state.cached_state, signed_block, .{ .verify_signatures = true }));
        const res = stateTransition(
            allocator,
            test_state.cached_state.config,
            test_state.cached_state.getEpochCache(),
            test_state.cached_state.state,
            signed_beacon_block,
            tc.transition_opt,
        );
        if (tc.expect_error) {
            if (res) |_| {
                try testing.expect(false);
            } else |_| {}
        } else {
            if (res) |post_state| {
                defer {
                    post_state.deinit();
                    allocator.destroy(post_state);
                }
            } else |_| {
                try testing.expect(false);
            }
        }
    }

    defer deinitStateTransition();
}
