//! Tests for `ref_count.zig`.

const std = @import("std");
const RefCount = @import("ref_count.zig").RefCount;

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
