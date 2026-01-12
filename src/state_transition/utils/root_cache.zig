const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const BeaconState = @import("../types/beacon_state.zig").BeaconState;
const getBlockRootFn = @import("../utils/block_root.zig").getBlockRoot;
const getBlockRootAtSlotFn = @import("../utils/block_root.zig").getBlockRootAtSlot;
const types = @import("consensus_types");
const Checkpoint = types.phase0.Checkpoint.Type;
const Epoch = types.primitive.Epoch.Type;
const Slot = types.primitive.Slot.Type;
const Root = types.primitive.Root.Type;

pub const RootCache = struct {
    allocator: Allocator,
    current_justified_checkpoint: Checkpoint,
    previous_justified_checkpoint: Checkpoint,
    state: *BeaconState,
    block_root_epoch_cache: std.AutoHashMap(Epoch, *const Root),
    block_root_slot_cache: std.AutoHashMap(Slot, *const Root),

    pub fn init(allocator: Allocator, cached_state: *CachedBeaconState) !*RootCache {
        const instance = try allocator.create(RootCache);
        errdefer allocator.destroy(instance);
        const state = cached_state.state;

        var current_justified_checkpoint_view = try state.currentJustifiedCheckpoint();
        var previous_justified_checkpoint_view = try state.previousJustifiedCheckpoint();
        var current_justified_checkpoint: Checkpoint = undefined;
        var previous_justified_checkpoint: Checkpoint = undefined;
        try current_justified_checkpoint_view.toValue(allocator, &current_justified_checkpoint);
        try previous_justified_checkpoint_view.toValue(allocator, &previous_justified_checkpoint);
        instance.* = RootCache{
            .allocator = allocator,
            .current_justified_checkpoint = current_justified_checkpoint,
            .previous_justified_checkpoint = previous_justified_checkpoint,
            .state = state,
            .block_root_epoch_cache = std.AutoHashMap(Epoch, *const Root).init(allocator),
            .block_root_slot_cache = std.AutoHashMap(Slot, *const Root).init(allocator),
        };

        return instance;
    }

    pub fn getBlockRoot(self: *RootCache, epoch: Epoch) !*const Root {
        if (self.block_root_epoch_cache.get(epoch)) |root| {
            return root;
        } else {
            const root = try getBlockRootFn(self.state, epoch);
            try self.block_root_epoch_cache.put(epoch, root);
            return root;
        }
    }

    pub fn getBlockRootAtSlot(self: *RootCache, slot: Slot) !*const Root {
        if (self.block_root_slot_cache.get(slot)) |root| {
            return root;
        } else {
            const root = try getBlockRootAtSlotFn(self.state, slot);
            try self.block_root_slot_cache.put(slot, root);
            return root;
        }
    }

    pub fn deinit(self: *RootCache) void {
        self.block_root_epoch_cache.deinit();
        self.block_root_slot_cache.deinit();
        self.allocator.destroy(self);
    }
};

// TODO: unit tests
