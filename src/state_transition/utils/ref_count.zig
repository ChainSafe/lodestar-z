const std = @import("std");
const Allocator = std.mem.Allocator;

/// A reference counted wrapper for a type `T`.
/// `T` is stored inline; wrap the value, not a pointer to it. `T` must not be
/// `*const Something`, which deinit() cannot call through.
pub fn RefCount(comptime T: type) type {
    return struct {
        allocator: Allocator,
        _ref_count: std.atomic.Value(u32),
        instance: T,

        pub fn init(allocator: Allocator, instance: T) !*@This() {
            const ptr = try allocator.create(@This());
            initIn(ptr, allocator, instance);
            return ptr;
        }

        /// Fills a cell the caller allocated. Infallible, so a caller that builds `instance`
        /// itself can allocate the cell first and transfer ownership as its last step. `init`
        /// allocates after `instance` exists, so a failure there would strand it.
        pub fn initIn(cell: *@This(), allocator: Allocator, instance: T) void {
            cell.* = .{
                .allocator = allocator,
                ._ref_count = std.atomic.Value(u32).init(1),
                .instance = instance,
            };
        }

        /// Private deinit invoked internally only by
        /// the last remaining reference counted instance of T.
        ///
        /// Consumer should call unref() instead.
        ///
        /// Dispatches to either `T.deinit(self)` or `T.deinit(self, allocator)`
        /// depending on the wrapped type's signature. This is needed because
        /// 0.16 unmanaged ArrayList uses the 2-arg form while many project
        /// types still expose the 1-arg form.
        fn deinit(self: *@This()) void {
            const BaseT = switch (@typeInfo(T)) {
                .pointer => |p| p.child,
                else => T,
            };
            const deinit_params = @typeInfo(@TypeOf(BaseT.deinit)).@"fn".params;
            if (comptime deinit_params.len > 1) {
                self.instance.deinit(self.allocator);
            } else {
                self.instance.deinit();
            }
            self.allocator.destroy(self);
        }

        /// Borrows the shared instance. Consumers must not deinit it, and must not modify it
        /// unless no other holder can observe the change; clone instead when a shared value
        /// has to diverge.
        pub fn get(self: *@This()) *T {
            return &self.instance;
        }

        pub fn ref(self: *@This()) *@This() {
            _ = self._ref_count.fetchAdd(1, .monotonic);
            return self;
        }

        pub fn unref(self: *@This()) void {
            if (self._ref_count.fetchSub(1, .release) == 1) {
                _ = self._ref_count.load(.acquire);
                self.deinit();
            }
        }
    };
}

test {
    _ = @import("ref_count_test.zig");
}
