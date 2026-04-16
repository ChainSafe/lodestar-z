const std = @import("std");
const Allocator = std.mem.Allocator;

const preset = @import("preset").preset;
const fork_choice_mod = @import("fork_choice");
const ForkChoice = fork_choice_mod.ForkChoiceStruct;

pub const Root = [32]u8;
pub const SlotToRootMap = std.array_hash_map.Auto(u64, Root);
pub const BlockToParentMap = std.array_hash_map.Auto(Root, Root);
pub const BlockToStateMap = std.array_hash_map.Auto(Root, Root);

pub const FinalizationPlan = struct {
    allocator: Allocator,
    finalized_epoch: u64,
    finalized_root: Root,
    finalized_slot: u64,
    prune_slot: u64,
    finalized_slot_roots: SlotToRootMap,
    finalized_parent_roots: BlockToParentMap,

    pub fn init(
        allocator: Allocator,
        finalized_epoch: u64,
        finalized_root: Root,
    ) FinalizationPlan {
        return .{
            .allocator = allocator,
            .finalized_epoch = finalized_epoch,
            .finalized_root = finalized_root,
            .finalized_slot = finalized_epoch * preset.SLOTS_PER_EPOCH,
            .prune_slot = if (finalized_epoch > 2)
                (finalized_epoch - 2) * preset.SLOTS_PER_EPOCH
            else
                0,
            .finalized_slot_roots = .empty,
            .finalized_parent_roots = .empty,
        };
    }

    pub fn initForArchive(
        allocator: Allocator,
        fork_choice: *const ForkChoice,
        from_slot: u64,
        finalized_epoch: u64,
        finalized_root: Root,
    ) !FinalizationPlan {
        var plan = FinalizationPlan.init(allocator, finalized_epoch, finalized_root);
        errdefer plan.deinit();

        try plan.collectCanonicalRange(fork_choice, from_slot);
        return plan;
    }

    pub fn deinit(self: *FinalizationPlan) void {
        self.finalized_parent_roots.deinit(self.allocator);
        self.finalized_slot_roots.deinit(self.allocator);
    }

    pub fn collectBlockStateRemovals(
        self: *const FinalizationPlan,
        fork_choice: *const ForkChoice,
        block_to_state: *const BlockToStateMap,
    ) !std.array_list.Managed(Root) {
        var roots_to_remove = std.array_list.Managed(Root).init(self.allocator);
        errdefer roots_to_remove.deinit();

        var b2s_it = block_to_state.iterator();
        while (b2s_it.next()) |entry| {
            const root = entry.key_ptr.*;
            if (std.mem.eql(u8, &root, &self.finalized_root)) continue;
            if (!fork_choice.hasBlock(root)) {
                try roots_to_remove.append(root);
            }
        }

        return roots_to_remove;
    }

    fn collectCanonicalRange(
        self: *FinalizationPlan,
        fork_choice: *const ForkChoice,
        from_slot: u64,
    ) !void {
        const finalized_block = try fork_choice.getFinalizedBlock();
        if (!std.mem.eql(u8, &finalized_block.block_root, &self.finalized_root)) {
            return error.FinalizedRootMismatch;
        }

        if (from_slot > self.finalized_slot) return;

        var slot = from_slot;
        while (slot <= self.finalized_slot) : (slot += 1) {
            const ancestor = try fork_choice.getAncestor(self.finalized_root, slot);
            if (ancestor.slot != slot) continue;
            try self.recordCanonicalNode(ancestor);
        }
    }
    fn recordCanonicalNode(self: *FinalizationPlan, node: fork_choice_mod.ProtoNode) !void {
        try self.finalized_slot_roots.put(self.allocator, node.slot, node.block_root);
        try self.finalized_parent_roots.put(self.allocator, node.block_root, node.parent_root);
    }
};
