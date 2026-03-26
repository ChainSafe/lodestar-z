const std = @import("std");
const Allocator = std.mem.Allocator;
const getBlockRootFn = @import("../utils/block_root.zig").getBlockRoot;
const getBlockRootAtSlotFn = @import("../utils/block_root.zig").getBlockRootAtSlot;
const types = @import("consensus_types");
const ForkSeq = @import("config").ForkSeq;
const BeaconState = @import("fork_types").BeaconState;
const Checkpoint = types.phase0.Checkpoint.Type;
const Epoch = types.primitive.Epoch.Type;
const Slot = types.primitive.Slot.Type;
const Root = types.primitive.Root.Type;

pub fn RootCache(comptime fork: ForkSeq) type {
    return struct {
        allocator: Allocator,
        current_justified_checkpoint: Checkpoint,
        previous_justified_checkpoint: Checkpoint,
        state: *BeaconState(fork),
        block_root_epoch_cache: std.AutoHashMap(Epoch, *const Root),
        block_root_slot_cache: std.AutoHashMap(Slot, *const Root),

        const Self = @This();

        pub fn init(allocator: Allocator, state: *BeaconState(fork)) !*Self {
            const instance = try allocator.create(Self);
            errdefer allocator.destroy(instance);

            var current_justified_checkpoint: Checkpoint = undefined;
            var previous_justified_checkpoint: Checkpoint = undefined;
            try state.currentJustifiedCheckpoint(&current_justified_checkpoint);
            try state.previousJustifiedCheckpoint(&previous_justified_checkpoint);
            instance.* = Self{
                .allocator = allocator,
                .current_justified_checkpoint = current_justified_checkpoint,
                .previous_justified_checkpoint = previous_justified_checkpoint,
                .state = state,
                .block_root_epoch_cache = std.AutoHashMap(Epoch, *const Root).init(allocator),
                .block_root_slot_cache = std.AutoHashMap(Slot, *const Root).init(allocator),
            };

            return instance;
        }

        pub fn getBlockRoot(self: *Self, epoch: Epoch) !*const Root {
            if (self.block_root_epoch_cache.get(epoch)) |root| {
                return root;
            } else {
                const root = try getBlockRootFn(fork, self.state, epoch);
                try self.block_root_epoch_cache.put(epoch, root);
                return root;
            }
        }

        pub fn getBlockRootAtSlot(self: *Self, slot: Slot) !*const Root {
            if (self.block_root_slot_cache.get(slot)) |root| {
                return root;
            } else {
                const root = try getBlockRootAtSlotFn(fork, self.state, slot);
                try self.block_root_slot_cache.put(slot, root);
                return root;
            }
        }

        pub fn deinit(self: *Self) void {
            self.block_root_epoch_cache.deinit();
            self.block_root_slot_cache.deinit();
            self.allocator.destroy(self);
        }
    };
}


const testing = std.testing;
const Node = @import("persistent_merkle_tree").Node;
const AnyBeaconState = @import("fork_types").AnyBeaconState;
const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;

test "RootCache - init captures checkpoints from state" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 512);
    defer pool.deinit();

    var env = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer env.deinit();

    const fork_state = try env.cached_state.state.tryCastToFork(.electra);
    const root_cache = try RootCache(.electra).init(allocator, fork_state);
    defer root_cache.deinit();

    // Verify checkpoints were captured from state
    var expected_current: types.phase0.Checkpoint.Type = undefined;
    var expected_previous: types.phase0.Checkpoint.Type = undefined;
    try env.cached_state.state.currentJustifiedCheckpoint(&expected_current);
    try env.cached_state.state.previousJustifiedCheckpoint(&expected_previous);

    try testing.expectEqual(expected_current.epoch, root_cache.current_justified_checkpoint.epoch);
    try testing.expectEqual(expected_current.root, root_cache.current_justified_checkpoint.root);
    try testing.expectEqual(expected_previous.epoch, root_cache.previous_justified_checkpoint.epoch);
    try testing.expectEqual(expected_previous.root, root_cache.previous_justified_checkpoint.root);
}

test "RootCache - getBlockRootAtSlot returns and caches root" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 512);
    defer pool.deinit();

    var env = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer env.deinit();

    const fork_state = try env.cached_state.state.tryCastToFork(.electra);
    const state_slot = try env.cached_state.state.slot();
    const root_cache = try RootCache(.electra).init(allocator, fork_state);
    defer root_cache.deinit();

    // Query a valid slot (must be < state_slot and within SLOTS_PER_HISTORICAL_ROOT)
    const query_slot = state_slot - 2;
    const root1 = try root_cache.getBlockRootAtSlot(query_slot);
    const root2 = try root_cache.getBlockRootAtSlot(query_slot);

    // Same pointer — second call returns cached value
    try testing.expectEqual(root1, root2);
}

test "RootCache - getBlockRoot returns root for epoch" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 512);
    defer pool.deinit();

    var env = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer env.deinit();

    const fork_state = try env.cached_state.state.tryCastToFork(.electra);
    const state_slot = try env.cached_state.state.slot();
    const current_epoch = @divFloor(state_slot, @as(Slot, @import("preset").preset.SLOTS_PER_EPOCH));

    // Query a previous epoch whose start slot is within range
    const query_epoch = if (current_epoch > 1) current_epoch - 1 else 0;
    const root_cache = try RootCache(.electra).init(allocator, fork_state);
    defer root_cache.deinit();

    const root1 = try root_cache.getBlockRoot(query_epoch);
    const root2 = try root_cache.getBlockRoot(query_epoch);

    // Same pointer — cached
    try testing.expectEqual(root1, root2);

    // Root should not be all zeros (block_roots are initialized to 0x0101...01 in test state)
    const zero_root: [32]u8 = [_]u8{0} ** 32;
    try testing.expect(!std.mem.eql(u8, root1, &zero_root));
}

test "RootCache - different slots return independently cached entries" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 512);
    defer pool.deinit();

    var env = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer env.deinit();

    const fork_state = try env.cached_state.state.tryCastToFork(.electra);
    const state_slot = try env.cached_state.state.slot();
    const root_cache = try RootCache(.electra).init(allocator, fork_state);
    defer root_cache.deinit();

    const slot_a = state_slot - 2;
    const slot_b = state_slot - 3;

    const root_a = try root_cache.getBlockRootAtSlot(slot_a);
    const root_b = try root_cache.getBlockRootAtSlot(slot_b);

    // Verify both are cached — subsequent calls return same pointers
    try testing.expectEqual(root_a, try root_cache.getBlockRootAtSlot(slot_a));
    try testing.expectEqual(root_b, try root_cache.getBlockRootAtSlot(slot_b));
}
