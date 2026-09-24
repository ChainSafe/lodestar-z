const std = @import("std");
const assert = std.debug.assert;

/// The datagram send budget of one transport turn.
pub const Turn = struct {
    send_max: u32,
    sent: u32 = 0,

    pub fn init(send_max: u32) Turn {
        assert(send_max > 0);
        return .{ .send_max = send_max };
    }

    pub fn canSend(self: *const Turn) bool {
        return self.sent < self.send_max;
    }

    pub fn recordSend(self: *Turn) void {
        assert(self.canSend());
        self.sent += 1;
    }
};

test "schedule turn stops at its send budget" {
    var turn = Turn.init(2);
    turn.recordSend();
    try std.testing.expect(turn.canSend());
    turn.recordSend();
    try std.testing.expect(!turn.canSend());
    try std.testing.expectEqual(@as(u32, 2), turn.sent);
}
