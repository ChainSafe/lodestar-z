const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const ForkSeq = @import("config").ForkSeq;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const types = @import("consensus_types");
const preset = @import("preset").preset;

pub fn processParticipationFlagUpdates(allocator: std.mem.Allocator, cached_state: *CachedBeaconStateAllForks) !void {
    const state = cached_state.state;
    // rotate EpochParticipation
    try state.rotateEpochParticipations(allocator);

    // We need to replace the node of currentEpochParticipation with a node that represents an empty list of some length.
    // SSZ represents a list as = new BranchNode(chunksNode, lengthNode).
    // Since the chunks represent all zero'ed data we can re-use the pre-computed zeroNode at chunkDepth to skip any
    // data transformation and create the required tree almost for free.

    // TODO(ct) implement this using TreeView
    //   const currentEpochParticipationNode = types.altair.EpochParticipation.tree_setChunksNode(
    //   state.currentEpochParticipation.node,
    //   zeroNode(types.altair.EpochParticipation.chunkDepth),
    //   state.currentEpochParticipation.length
    // );

    // state.currentEpochParticipation = types.altair.EpochParticipation.getViewDU(currentEpochParticipationNode);
}
