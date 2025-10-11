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

        /// private deinit, consumer should call unref() instead
        fn deinit(self: *@This()) void {
            self.instance.deinit();
            self.allocator.destroy(self);
        }

        /// caution: this returns a copy of the instance, make sure this does not have copy overhead
        /// or use pointer type instead
        pub fn get(self: *@This()) T {
            return self.instance;
        }

        pub fn ref(self: *@This()) *@This() {
            _ = self._ref_count.fetchAdd(1, .acquire);
            return self;
        }

        pub fn unref(self: *@This()) void {
            const old_rc = self._ref_count.fetchSub(1, .release);
            if (old_rc == 1) {
                self.deinit();
            }
        }
    };
}

test "RefCount - *std.ArrayList(u32)" {
    const allocator = std.testing.allocator;
    const WrappedArrayList = RefCount(*std.ArrayList(u32));

    var array_list = std.ArrayList(u32).init(allocator);
    try array_list.append(1);
    try array_list.append(2);

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
    var wrapped_array_list = try WrappedArrayList.init(allocator, std.ArrayList(u32).init(allocator));
    // ref_count = 2
    _ = wrapped_array_list.ref();

    // ref_count = 1
    wrapped_array_list.unref();
    // ref_count = 0 ===> deinit
    wrapped_array_list.unref();

    // the test does not leak any memory because array_list.deinit() is automatically called
}
