const std = @import("std");
const Allocator = std.mem.Allocator;

const CachedBeaconState = @import("state_transition").CachedBeaconState;

pub fn destroyCachedBeaconState(allocator: Allocator, state: *CachedBeaconState) void {
    state.deinit();
    allocator.destroy(state);
}

/// Deferrable owner-thread disposal for published beacon states.
///
/// This is the future hook for PMT mutator leasing: while a mutator lease is
/// active, cache eviction/pruning can queue state teardown here instead of
/// touching shared PMT refcounts immediately.
pub const StateDisposer = struct {
    allocator: Allocator,
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    pending: std.ArrayListUnmanaged(*CachedBeaconState) = .empty,
    deferral_depth: usize = 0,

    pub fn init(allocator: Allocator, io: std.Io) StateDisposer {
        return .{
            .allocator = allocator,
            .io = io,
        };
    }

    pub fn deinit(self: *StateDisposer) void {
        self.flush();
        self.pending.deinit(self.allocator);
    }

    pub fn beginDeferral(self: *StateDisposer) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.deferral_depth += 1;
    }

    pub fn endDeferral(self: *StateDisposer) !void {
        var pending = std.ArrayListUnmanaged(*CachedBeaconState).empty;

        self.mutex.lockUncancelable(self.io);
        if (self.deferral_depth == 0) {
            self.mutex.unlock(self.io);
            return error.DeferralUnderflow;
        }
        self.deferral_depth -= 1;
        if (self.deferral_depth == 0) {
            pending = self.pending;
            self.pending = .empty;
        }
        self.mutex.unlock(self.io);

        flushPending(self.allocator, &pending);
    }

    pub fn isDeferring(self: *const StateDisposer) bool {
        const mutable_self: *StateDisposer = @constCast(self);
        mutable_self.mutex.lockUncancelable(mutable_self.io);
        defer mutable_self.mutex.unlock(mutable_self.io);
        return mutable_self.deferral_depth != 0;
    }

    pub fn pendingCount(self: *const StateDisposer) usize {
        const mutable_self: *StateDisposer = @constCast(self);
        mutable_self.mutex.lockUncancelable(mutable_self.io);
        defer mutable_self.mutex.unlock(mutable_self.io);
        return mutable_self.pending.items.len;
    }

    pub fn dispose(self: *StateDisposer, state: *CachedBeaconState) !void {
        var destroy_now = false;
        self.mutex.lockUncancelable(self.io);
        if (self.deferral_depth == 0) {
            destroy_now = true;
        } else {
            self.pending.append(self.allocator, state) catch |err| {
                self.mutex.unlock(self.io);
                return err;
            };
        }
        self.mutex.unlock(self.io);

        if (destroy_now) {
            destroyCachedBeaconState(self.allocator, state);
        }
    }

    pub fn flush(self: *StateDisposer) void {
        var pending = std.ArrayListUnmanaged(*CachedBeaconState).empty;

        self.mutex.lockUncancelable(self.io);
        pending = self.pending;
        self.pending = .empty;
        self.mutex.unlock(self.io);

        flushPending(self.allocator, &pending);
    }

    fn flushPending(allocator: Allocator, pending: *std.ArrayListUnmanaged(*CachedBeaconState)) void {
        defer pending.deinit(allocator);
        for (pending.items) |state| {
            destroyCachedBeaconState(allocator, state);
        }
    }
};

test "StateDisposer: defers and flushes state teardown" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;

    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    const baseline_nodes_in_use = pool.getNodesInUse();

    const cloned = try test_state.cached_state.clone(allocator, .{});
    try cloned.state.setSlot((try cloned.state.slot()) + 1);
    try cloned.state.commit();
    _ = try cloned.state.hashTreeRoot();

    const nodes_after_mutation = pool.getNodesInUse();
    try std.testing.expect(nodes_after_mutation > baseline_nodes_in_use);

    var disposer = StateDisposer.init(allocator, std.testing.io);
    defer disposer.deinit();

    disposer.beginDeferral();
    try disposer.dispose(cloned);
    try std.testing.expectEqual(@as(usize, 1), disposer.pendingCount());
    try std.testing.expectEqual(nodes_after_mutation, pool.getNodesInUse());

    try disposer.endDeferral();
    try std.testing.expectEqual(@as(usize, 0), disposer.pendingCount());
    try std.testing.expectEqual(baseline_nodes_in_use, pool.getNodesInUse());
}
