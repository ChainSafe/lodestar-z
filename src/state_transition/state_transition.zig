const std = @import("std");
const Allocator = std.mem.Allocator;
const ForkSeq = @import("config").ForkSeq;

const ssz = @import("consensus_types");
const preset = @import("preset").preset;
const Root = ssz.primitive.Root.Type;
const ZERO_HASH = @import("constants").ZERO_HASH;

const ExecutionPayload = @import("types/execution_payload.zig").ExecutionPayload;

const Slot = ssz.primitive.Slot.Type;

const CachedBeaconStateAllForks = @import("cache/state_cache.zig").CachedBeaconStateAllForks;
pub const SignedBeaconBlock = @import("types/beacon_block.zig").SignedBeaconBlock;
const verifyProposerSignature = @import("./signature_sets/proposer.zig").verifyProposerSignature;
const processBlock = @import("./block/process_block.zig").processBlock;
const BeaconBlock = @import("types/beacon_block.zig").BeaconBlock;
const SignedVoluntaryExit = ssz.phase0.SignedVoluntaryExit.Type;
const Attestation = @import("types/attestation.zig").Attestation;
const Attestations = @import("types/attestation.zig").Attestations;
const AttesterSlashings = @import("types/attester_slashing.zig").AttesterSlashings;
const ProposerSlashing = ssz.phase0.ProposerSlashing.Type;
const BlindedBeaconBlock = @import("types/beacon_block.zig").BlindedBeaconBlock;
const BlindedBeaconBlockBody = @import("types/beacon_block.zig").BlindedBeaconBlockBody;
const BeaconBlockBody = @import("types/beacon_block.zig").BeaconBlockBody;
const SignedBlindedBeaconBlock = @import("types/beacon_block.zig").SignedBlindedBeaconBlock;
const EpochTransitionCacheOpts = @import("cache/epoch_transition_cache.zig").EpochTransitionCacheOpts;
const EpochTransitionCache = @import("cache/epoch_transition_cache.zig").EpochTransitionCache;
const ReusedEpochTransitionCache = @import("cache/epoch_transition_cache.zig").ReusedEpochTransitionCache;
const processEpoch = @import("epoch/process_epoch.zig").processEpoch;
const computeEpochAtSlot = @import("utils/epoch.zig").computeEpochAtSlot;
const processSlot = @import("slot/process_slot.zig").processSlot;
const deinitReusedEpochTransitionCache = @import("cache/epoch_transition_cache.zig").deinitReusedEpochTransitionCache;
const upgradeStateToAltair = @import("slot/upgrade_state_to_altair.zig").upgradeStateToAltair;
const upgradeStateToBellatrix = @import("slot/upgrade_state_to_bellatrix.zig").upgradeStateToBellatrix;
const upgradeStateToCapella = @import("slot/upgrade_state_to_capella.zig").upgradeStateToCapella;

const SignedBlock = @import("types/signed_block.zig").SignedBlock;

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

pub fn processSlotsWithTransientCache(
    allocator: std.mem.Allocator,
    post_state: *CachedBeaconStateAllForks,
    slot: Slot,
    _: EpochTransitionCacheOpts,
) !void {
    var state = post_state.state;
    if (state.slot() > slot) return error.outdatedSlot;

    while (state.slot() < slot) {
        try processSlot(allocator, post_state);

        if ((state.slot() + 1) % preset.SLOTS_PER_EPOCH == 0) {
            // TODO(bing): metrics
            // const epochTransitionTimer = metrics?.epochTransitionTime.startTimer();

            // TODO(bing): metrics: time beforeProcessEpoch
            var epoch_transition_cache = try EpochTransitionCache.init(allocator, post_state);
            defer {
                epoch_transition_cache.deinit();
                allocator.destroy(epoch_transition_cache);
            }
            try processEpoch(allocator, post_state, epoch_transition_cache);
            // TODO(bing): registerValidatorStatuses

            state.slotPtr().* += 1;

            try post_state.epoch_cache_ref.get().afterProcessEpoch(post_state, epoch_transition_cache);
            // post_state.commit

            const state_epoch = computeEpochAtSlot(state.slot());

            const config = post_state.config;
            if (state_epoch == config.chain.ALTAIR_FORK_EPOCH) {
                try upgradeStateToAltair(allocator, post_state);
            }
            if (state_epoch == config.chain.BELLATRIX_FORK_EPOCH) {
                try upgradeStateToBellatrix(allocator, post_state);
            }
            if (state_epoch == config.chain.CAPELLA_FORK_EPOCH) {
                try upgradeStateToCapella(allocator, post_state);
            }
        } else {
            state.slotPtr().* += 1;
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
    state: *CachedBeaconStateAllForks,
    signed_block: SignedBlock,
    opts: TransitionOpt,
) !*CachedBeaconStateAllForks {
    const block = signed_block.message();
    const block_slot = switch (block) {
        .regular => |b| b.slot(),
        .blinded => |b| b.slot(),
    };

    const post_state = try state.clone(allocator);

    errdefer {
        post_state.deinit();
        allocator.destroy(post_state);
    }

    //TODO(bing): metrics
    //if (metrics) {
    //  onStateCloneMetrics(postState, metrics, StateCloneSource.stateTransition);
    //}

    try processSlotsWithTransientCache(allocator, post_state, block_slot, .{});

    // Verify proposer signature only
    if (opts.verify_proposer and !try verifyProposerSignature(post_state, &signed_block)) {
        return error.InvalidBlockSignature;
    }

    //  // Note: time only on success
    //  const processBlockTimer = metrics?.processBlockTime.startTimer();
    //
    try processBlock(
        allocator,
        post_state,
        &signed_block,
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
        var post_state_root: [32]u8 = undefined;
        //    const hashTreeRootTimer = metrics?.stateHashTreeRootTime.startTimer({
        //      source: StateHashTreeRootSource.stateTransition,
        //    });
        try post_state.state.hashTreeRoot(allocator, &post_state_root);
        //    hashTreeRootTimer?.();

        const block_state_root = switch (block) {
            .regular => |b| b.stateRoot(),
            .blinded => |b| b.stateRoot(),
        };
        if (!std.mem.eql(u8, &post_state_root, &block_state_root)) {
            return error.InvalidStateRoot;
        }
    }

    return post_state;
}

pub fn deinitStateTransition() void {
    deinitReusedEpochTransitionCache();
}
