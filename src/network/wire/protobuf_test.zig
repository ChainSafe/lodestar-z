const std = @import("std");
const pb = @import("protobuf.zig");
test "protobuf checked scalar varints accept noncanonical and maximum values" {
    var reader = pb.Reader.init(&.{ 0x80, 0 });
    try std.testing.expectEqual(@as(u64, 0), try reader.varint());
    reader = pb.Reader.init(&.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1 });
    try std.testing.expectEqual(std.math.maxInt(u64), try reader.varint());
    reader = pb.Reader.init(&.{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 2 });
    try std.testing.expectError(error.Overflow, reader.varint());
    var bytes: [10]u8 = undefined;
    var writer = pb.Writer.init(&bytes);
    writer.varint(std.math.maxInt(u64));
    try std.testing.expectEqual(@as(usize, 10), writer.len);
}
