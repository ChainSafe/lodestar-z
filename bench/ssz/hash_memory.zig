const std = @import("std");
const ssz = @import("ssz");

/// Reports heap workspace separately from timing; input values and stack scratch are excluded.
pub fn report(
    comptime ST: type,
    io: std.Io,
    allocator: std.mem.Allocator,
    label: []const u8,
    value: *const ST.Type,
) !void {
    var managed = std.testing.FailingAllocator.init(allocator, .{});
    var scratch = try ssz.Hasher(ST).init(managed.allocator());
    defer scratch.deinit(managed.allocator());
    var cold_root: [32]u8 = undefined;
    try ssz.Hasher(ST).hash(&scratch, value, &cold_root);
    const cold_allocations = managed.allocations;
    const cold_resizes = managed.resize_index;
    const cold_bytes = managed.allocated_bytes;
    const cold_retained = managed.allocated_bytes - managed.freed_bytes;

    var warm_root: [32]u8 = undefined;
    try ssz.Hasher(ST).hash(&scratch, value, &warm_root);
    if (!std.mem.eql(u8, &cold_root, &warm_root)) return error.HashRootMismatch;

    var oneshot = std.testing.FailingAllocator.init(allocator, .{});
    var value_root: [32]u8 = undefined;
    if (comptime ssz.isFixedType(ST)) {
        try ST.hashTreeRoot(value, &value_root);
    } else {
        try ST.hashTreeRoot(oneshot.allocator(), value, &value_root);
    }
    if (!std.mem.eql(u8, &cold_root, &value_root)) return error.HashRootMismatch;

    var buffer: [1024]u8 = undefined;
    var output = std.Io.File.stdout().writerStreaming(io, &buffer);
    const writer = &output.interface;
    try writer.print("hash workspace: {s} (heap only; excludes input values)\n", .{label});
    try writer.writeAll("mode,allocations,resizes,allocated_bytes,retained_bytes\n");
    try writer.print("managed cold,{d},{d},{d},{d}\n", .{
        cold_allocations, cold_resizes, cold_bytes, cold_retained,
    });
    try writer.print("managed warm,{d},{d},{d},{d}\n", .{
        managed.allocations - cold_allocations,
        managed.resize_index - cold_resizes,
        managed.allocated_bytes - cold_bytes,
        managed.allocated_bytes - managed.freed_bytes,
    });
    try writer.print("value,{d},{d},{d},{d}\n", .{
        oneshot.allocations,     oneshot.resize_index,
        oneshot.allocated_bytes, oneshot.allocated_bytes - oneshot.freed_bytes,
    });
    try writer.flush();
}
