const std = @import("std");

pub const PeerIdFmt = struct {
    peer_id: ?[]const u8,

    pub fn format(self: PeerIdFmt, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        const peer_id = self.peer_id orelse {
            try writer.writeAll("(none)");
            return;
        };
        if (peer_id.len == 0) {
            try writer.writeAll("(empty)");
            return;
        }

        try writer.writeAll("0x");
        const prefix_len = @min(peer_id.len, 8);
        for (peer_id[0..prefix_len]) |byte| {
            try writer.print("{x:0>2}", .{byte});
        }
        if (peer_id.len > prefix_len) {
            try writer.writeAll("..");
        }
        try writer.print("({d}b)", .{peer_id.len});
    }
};

pub fn fmtPeerId(peer_id: ?[]const u8) PeerIdFmt {
    return .{ .peer_id = peer_id };
}

test "fmtPeerId renders prefix and size" {
    var buf: [64]u8 = undefined;
    const out = try std.fmt.bufPrint(&buf, "{f}", .{
        fmtPeerId(&.{ 0x00, 0x25, 0x08, 0x02, 0x12, 0x21, 0x03, 0xaa, 0xbb }),
    });
    try std.testing.expectEqualStrings("0x00250802122103aa..(9b)", out);
}
