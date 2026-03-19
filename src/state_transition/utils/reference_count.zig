const std = @import("std");
const Allocator = std.mem.Allocator;

/// A reference counted wrapper for a type `T`.
/// T should be `*Something`, not `*const Something` due to deinit()
pub fn ReferenceCount(comptime T: type) type {
    return struct {
        // TODO: switch to std.atomic
        allocator: Allocator,
        _ref_count: usize,
        instance: T,

        pub fn init(allocator: Allocator, instance: T) !*@This() {
            const ptr = try allocator.create(@This());
            errdefer allocator.destroy(ptr);
            ptr.* = .{
                .allocator = allocator,
                ._ref_count = 1,
                .instance = instance,
            };
            return ptr;
        }

        pub fn deinit(self: *@This()) void {
            self.instance.deinit();
            self.allocator.destroy(self);
        }

        pub fn clone(allocator: Allocator, instance: T) !*@This() {
            const cloned = try instance.clone(allocator);
            return @This().init(cloned);
        }

        pub fn get(self: *@This()) T {
            return self.instance;
        }

        pub fn acquire(self: *@This()) *@This() {
            self._ref_count += 1;
            return self;
        }

        pub fn release(self: *@This()) void {
            self._ref_count -= 1;
            if (self._ref_count == 0) {
                self.deinit();
            }
        }
    };
}

test "ReferenceCount - *std.array_list.AlignedManaged(u32, null)" {
    const allocator = std.testing.allocator;
    const WrappedArrayList = ReferenceCount(*std.array_list.AlignedManaged(u32, null));

    var array_list = std.array_list.AlignedManaged(u32, null).init(allocator);
    try array_list.append(1);
    try array_list.append(2);

    // ref_count = 1
    var wrapped_array_list = try WrappedArrayList.init(allocator, &array_list);
    // ref_count = 2
    _ = wrapped_array_list.acquire();

    // ref_count = 1
    wrapped_array_list.release();
    // ref_count = 0 ===> deinit
    wrapped_array_list.release();

    // the test does not leak any memory because array_list.deinit() is automatically called
}

test "ReferenceCount - std.array_list.AlignedManaged(u32, null)" {
    const allocator = std.testing.allocator;
    const WrappedArrayList = ReferenceCount(std.array_list.AlignedManaged(u32, null));

    // ref_count = 1
    var wrapped_array_list = try WrappedArrayList.init(allocator, std.array_list.AlignedManaged(u32, null).init(allocator));
    // ref_count = 2
    _ = wrapped_array_list.acquire();

    // ref_count = 1
    wrapped_array_list.release();
    // ref_count = 0 ===> deinit
    wrapped_array_list.release();

    // the test does not leak any memory because array_list.deinit() is automatically called
}
