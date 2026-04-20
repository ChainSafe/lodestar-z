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

test "ReferenceCount - *std.ArrayList(u32)" {
    const allocator = std.testing.allocator;
    const WrappedArrayList = ReferenceCount(*std.ArrayList(u32));

    var array_list: std.ArrayList(u32) = .empty;
    try array_list.append(allocator, 1);
    try array_list.append(allocator, 2);

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

test "ReferenceCount - std.ArrayList(u32)" {
    const allocator = std.testing.allocator;
    const WrappedArrayList = ReferenceCount(std.ArrayList(u32));

    // ref_count = 1
    var wrapped_array_list = try WrappedArrayList.init(allocator, .empty);
    // ref_count = 2
    _ = wrapped_array_list.acquire();

    // ref_count = 1
    wrapped_array_list.release();
    // ref_count = 0 ===> deinit
    wrapped_array_list.release();

    // the test does not leak any memory because array_list.deinit() is automatically called
}
