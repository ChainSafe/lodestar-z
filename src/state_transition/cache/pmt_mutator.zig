const std = @import("std");

const StateDisposer = @import("state_disposer.zig").StateDisposer;

/// High-level synchronization around shared PMT mutation.
///
/// This intentionally lives above the PMT primitives: one coarse lease per
/// state-mutating operation keeps teardown deferred while the mutation is
/// active, without adding lock/atomic overhead to every pool op.
pub const PmtMutator = struct {
    io: std.Io,
    state_disposer: *StateDisposer,
    mutex: std.Io.Mutex = .init,

    pub fn init(io: std.Io, state_disposer: *StateDisposer) PmtMutator {
        return .{
            .io = io,
            .state_disposer = state_disposer,
        };
    }

    pub fn acquire(self: *PmtMutator) Lease {
        self.mutex.lockUncancelable(self.io);
        self.state_disposer.beginDeferral();
        return .{ .mutator = self };
    }

    pub fn acquireOptional(pmt_mutator: ?*PmtMutator) Lease {
        if (pmt_mutator) |mutator| {
            return mutator.acquire();
        }
        return .{ .mutator = null };
    }

    pub const Lease = struct {
        mutator: ?*PmtMutator,
        released: bool = false,

        pub fn release(self: *Lease) void {
            if (self.released) return;
            self.released = true;
            if (self.mutator) |mutator| {
                mutator.state_disposer.endDeferral() catch @panic("PMT mutator deferral underflow");
                mutator.mutex.unlock(mutator.io);
            }
        }
    };
};

test "PmtMutator: optional lease is a no-op" {
    var lease = PmtMutator.acquireOptional(null);
    lease.release();
    lease.release();
}

test "PmtMutator: lease defers and flushes teardown" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;

    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256 * 5);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    const cloned = try test_state.cached_state.clone(allocator, .{});
    try cloned.state.setSlot((try cloned.state.slot()) + 1);
    try cloned.state.commit();
    _ = try cloned.state.hashTreeRoot();

    var disposer = StateDisposer.init(allocator, std.testing.io);
    defer disposer.deinit();

    var mutator = PmtMutator.init(std.testing.io, &disposer);
    var lease = mutator.acquire();
    defer lease.release();

    try disposer.dispose(cloned);
    try std.testing.expectEqual(@as(usize, 1), disposer.pendingCount());
    try std.testing.expect(disposer.isDeferring());
}
