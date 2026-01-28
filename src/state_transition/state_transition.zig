const std = @import("std");
const Allocator = std.mem.Allocator;
const ForkSeq = @import("config").ForkSeq;
const metrics = @import("metrics.zig");
const observeEpochTransitionStep = metrics.observeEpochTransitionStep;
const observeEpochTransition = metrics.observeEpochTransition;
const readSeconds = metrics.readSeconds;
const Timer = std.time.Timer;

const types = @import("consensus_types");
const preset = @import("preset").preset;

const Slot = types.primitive.Slot.Type;
const CachedBeaconState = @import("cache/state_cache.zig").CachedBeaconState;
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
    cached_state: *CachedBeaconState,
    slot: Slot,
    _: EpochTransitionCacheOpts,
) !void {
    const config = cached_state.config;
    const epoch_cache = cached_state.getEpochCache();
    const state = cached_state.state;

    if (try state.slot() > slot) return error.outdatedSlot;

    while (try state.slot() < slot) {
        try processSlot(cached_state.state);

        const next_slot = try state.slot() + 1;
        if (next_slot % preset.SLOTS_PER_EPOCH == 0) {
            var epoch_transition_timer = try Timer.start();

            var timer = try Timer.start();
            var epoch_transition_cache = try EpochTransitionCache.init(
                allocator,
                config,
                epoch_cache,
                state,
            );
            defer epoch_transition_cache.deinit();
            try observeEpochTransitionStep(.{ .step = .before_process_epoch }, timer.read());

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

            timer = try Timer.start();
            try epoch_cache.afterProcessEpoch(state, &epoch_transition_cache);
            try observeEpochTransitionStep(.{ .step = .after_process_epoch }, timer.read());
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
            metrics.state_transition.epoch_transition.observe(readSeconds(&epoch_transition_timer));
        } else {
            try state.setSlot(next_slot);
        }
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
    cached_state: *CachedBeaconState,
    signed_block: AnySignedBeaconBlock,
    opts: TransitionOpt,
) !*CachedBeaconState {
    const block = signed_block.beaconBlock();
    const block_slot = block.slot();

    var post_cached_state = try cached_state.clone(
        allocator,
        .{ .transfer_cache = !opts.do_not_transfer_cache },
    );
    errdefer {
        post_cached_state.deinit();
        allocator.destroy(post_cached_state);
    }

    try metrics.state_transition.onStateClone(post_cached_state, .state_transition);

    try processSlots(
        allocator,
        post_cached_state,
        block_slot,
        .{},
    );

    const config = post_cached_state.config;
    const post_epoch_cache = post_cached_state.getEpochCache();
    const post_state = post_cached_state.state;

    // Verify proposer signature only
    if (opts.verify_proposer and !try verifyProposerSignature(
        allocator,
        config,
        post_epoch_cache,
        signed_block,
    )) {
        return error.InvalidBlockSignature;
    }

    if (block.forkSeq() != post_state.forkSeq()) {
        return error.InvalidBlockForkForState;
    }
    // Note: time only on success
    var timer = try Timer.start();
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
    metrics.state_transition.process_block.observe(readSeconds(&timer));

    //
    // TODO(bing): commit
    //  const processBlockCommitTimer = metrics?.processBlockCommitTime.startTimer();
    //  postState.commit();
    //  processBlockCommitTimer?.();

    try metrics.state_transition.onPostState(post_cached_state);

    // Verify state root
    if (opts.verify_state_root) {
        timer = try Timer.start();
        const post_state_root = try post_state.hashTreeRoot();
        try metrics.state_transition.state_hash_tree_root.observe(.{ .source = .block_transition }, readSeconds(&timer));

        const block_state_root = block.stateRoot();
        if (!std.mem.eql(u8, post_state_root, block_state_root)) {
            return error.InvalidStateRoot;
        }
    } else {
        // Even if we don't verify the state_root, commit the tree changes
        try post_state.commit();
    }

    return post_cached_state;
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
        const pool_size = 256 * 5;
        var pool = try Node.Pool.init(allocator, pool_size);
        defer pool.deinit();

        var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
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
            test_state.cached_state,
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
