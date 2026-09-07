const std = @import("std");
const builtin = @import("builtin");

pub const Wake = struct {
    read_fd: i32,
    write_fd: i32,

    pub fn init() !Wake {
        if (builtin.os.tag != .linux and builtin.os.tag != .macos) return error.UnsupportedWait;
        var fds: [2]i32 = undefined;
        if (std.c.pipe(&fds) != 0) return error.NetworkWakeFailed;
        errdefer {
            _ = std.c.close(fds[0]);
            _ = std.c.close(fds[1]);
        }
        for (fds) |fd| {
            if (std.c.fcntl(fd, std.c.F.SETFD, @as(c_int, std.c.FD_CLOEXEC)) < 0) return error.NetworkWakeFailed;
            const flags = std.c.fcntl(fd, std.c.F.GETFL);
            if (flags < 0) return error.NetworkWakeFailed;
            const nonblock: c_int = @bitCast(std.c.O{ .NONBLOCK = true });
            if (std.c.fcntl(fd, std.c.F.SETFL, flags | nonblock) < 0) return error.NetworkWakeFailed;
        }
        return .{ .read_fd = fds[0], .write_fd = fds[1] };
    }

    pub fn deinit(self: *Wake) void {
        _ = std.c.close(self.write_fd);
        _ = std.c.close(self.read_fd);
        self.* = .{ .read_fd = -1, .write_fd = -1 };
    }

    pub fn signal(self: *const Wake) !void {
        const byte = [_]u8{1};
        const result = std.c.write(self.write_fd, &byte, byte.len);
        if (result == 1) return;
        if (result < 0 and std.c.errno(result) == .AGAIN) return;
        return error.NetworkWakeFailed;
    }

    pub fn drain(self: *const Wake) !void {
        var buffer: [4096]u8 = undefined;
        const result = std.c.read(self.read_fd, &buffer, buffer.len);
        if (result > 0) return;
        if (result < 0 and std.c.errno(result) == .AGAIN) return;
        return error.NetworkWakeFailed;
    }
};

test "wake survives saturation and reports permanently invalid descriptors" {
    var wake = try Wake.init();
    defer wake.deinit();
    for (0..100_000) |_| try wake.signal();
    try wake.drain();
    try wake.signal();
    var invalid = wake;
    invalid.write_fd = -1;
    try std.testing.expectError(error.NetworkWakeFailed, invalid.signal());
    invalid.read_fd = -1;
    try std.testing.expectError(error.NetworkWakeFailed, invalid.drain());
}
