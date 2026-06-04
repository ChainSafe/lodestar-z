const std = @import("std");
const Allocator = std.mem.Allocator;

/// A reference counted wrapper for a type `T`.
/// T should be `*Something`, not `*const Something` due to deinit()
pub fn RefCount(comptime T: type) type {
    return struct {
        allocator: Allocator,
        _ref_count: std.atomic.Value(u32),
        instance: T,

        pub fn init(allocator: Allocator, instance: T) !*@This() {
            const ptr = try allocator.create(@This());
            ptr.* = .{
                .allocator = allocator,
                ._ref_count = std.atomic.Value(u32).init(1),
                .instance = instance,
            };
            return ptr;
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

        pub fn get(self: *@This()) T {
            return self.instance;
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

test "RefCount - *std.ArrayList(u32)" {
    const allocator = std.testing.allocator;
    const WrappedArrayList = RefCount(*std.ArrayList(u32));

    var array_list: std.ArrayList(u32) = .empty;
    try array_list.append(allocator, 1);
    try array_list.append(allocator, 2);

    // ref_count = 1
    var wrapped_array_list = try WrappedArrayList.init(allocator, &array_list);
    // ref_count = 2
    _ = wrapped_array_list.ref();

    // ref_count = 1
    wrapped_array_list.unref();
    // ref_count = 0 ===> deinit
    wrapped_array_list.unref();

    // the test does not leak any memory because array_list.deinit() is automatically called
}

test "RefCount - std.ArrayList(u32)" {
    const allocator = std.testing.allocator;
    const WrappedArrayList = RefCount(std.ArrayList(u32));

    // ref_count = 1
    var wrapped_array_list = try WrappedArrayList.init(allocator, .empty);
    // ref_count = 2
    _ = wrapped_array_list.ref();

    // ref_count = 1
    wrapped_array_list.unref();
    // ref_count = 0 ===> deinit
    wrapped_array_list.unref();

    // the test does not leak any memory because array_list.deinit() is automatically called
}
