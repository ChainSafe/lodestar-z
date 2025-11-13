const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("consensus_types");
const preset = @import("preset").preset;
const Root = types.primitive.Root.Type;
const ZERO_HASH = @import("constants").ZERO_HASH;

const ExecutionPayload = @import("types/execution_payload.zig").ExecutionPayload;

const Slot = types.primitive.Slot.Type;

const CachedBeaconStateAllForks = @import("cache/state_cache.zig").CachedBeaconStateAllForks;
pub const SignedBeaconBlock = @import("types/beacon_block.zig").SignedBeaconBlock;
const verifyProposerSignature = @import("./signature_sets/proposer.zig").verifyProposerSignature;
const processBlock = @import("./block/process_block.zig").processBlock;
const BeaconBlock = @import("types/beacon_block.zig").BeaconBlock;
const SignedVoluntaryExit = types.phase0.SignedVoluntaryExit.Type;
const Attestation = @import("types/attestation.zig").Attestation;
const Attestations = @import("types/attestation.zig").Attestations;
const AttesterSlashings = @import("types/attester_slashing.zig").AttesterSlashings;
const ProposerSlashing = types.phase0.ProposerSlashing.Type;
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

pub fn processSlotsWithTransientCache(
    allocator: std.mem.Allocator,
    post_state: *CachedBeaconStateAllForks,
    slot: Slot,
    _: EpochTransitionCacheOpts,
) !void {
    var cached_state = post_state.state;
    if (cached_state.slot() > slot) return error.outdatedSlot;

    while (cached_state.slot() < slot) {
        try processSlot(allocator, post_state);

        if ((cached_state.slot() + 1) % preset.SLOTS_PER_EPOCH == 0) {
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

            cached_state.slotPtr().* += 1;

            try post_state.epoch_cache_ref.get().afterProcessEpoch(post_state, epoch_transition_cache);
            // post_state.commit
            var root: Root = undefined;
            try cached_state.hashTreeRoot(allocator, &root);
        } else {
            cached_state.slotPtr().* += 1;
        }

        //epochTransitionTimer
        const state_epoch = computeEpochAtSlot(cached_state.slot());

        inline for (post_state.config.forks_descending_epoch_order) |f| {
            if (post_state.state.forkSeq().lt(f.fork_seq) and state_epoch == f.epoch) {
                _ = try post_state.state.upgradeUnsafe(allocator);
                break; // no need to check all forks once one hits
            }
        }
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
