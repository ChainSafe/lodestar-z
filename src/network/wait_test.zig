const std = @import("std");
const wait = @import("wait.zig");
const net = std.Io.net;

fn socket() !net.Socket {
    return (net.IpAddress{ .ip4 = .loopback(0) }).bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
}

test "native wait retains independent and simultaneous datagrams with actual zero wait" {
    if (!wait.supported) return error.SkipZigTest;
    const first = try socket();
    defer first.close(std.testing.io);
    const second = try socket();
    defer second.close(std.testing.io);
    const host = try socket();
    defer host.close(std.testing.io);
    const sources: wait.Sources = .{ .quic = first.handle, .discovery = second.handle, .host = host.handle };
    const empty = wait.poll(std.testing.io, sources, 0);
    try std.testing.expect(empty.failure == null);
    try std.testing.expectEqual(@as(u32, 0), empty.timeout_ms);
    try std.testing.expect(!empty.quic and !empty.discovery and !empty.host);
    const sockets = [_]net.Socket{ first, second, host };
    for (sockets, 0..) |target, index| {
        try host.send(std.testing.io, &target.address, "retained");
        const ready = wait.poll(std.testing.io, sources, 100);
        try std.testing.expect(ready.failure == null);
        try std.testing.expectEqual(index == 0, ready.quic);
        try std.testing.expectEqual(index == 1, ready.discovery);
        try std.testing.expectEqual(index == 2, ready.host);
        var buffer: [8]u8 = undefined;
        const message = try target.receiveTimeout(std.testing.io, &buffer, .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(0) } });
        try std.testing.expectEqualStrings("retained", message.data);
    }
    for (sockets) |target| try host.send(std.testing.io, &target.address, "queued");
    const all = wait.poll(std.testing.io, sources, 0);
    try std.testing.expect(all.failure == null and all.quic and all.discovery and all.host);
    for (sockets) |target| {
        var buffer: [8]u8 = undefined;
        const message = try target.receiveTimeout(std.testing.io, &buffer, .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(0) } });
        try std.testing.expectEqualStrings("queued", message.data);
    }
}

test "native wait delayed wake preserves payload on each source" {
    if (!wait.supported) return error.SkipZigTest;
    const first = try socket();
    defer first.close(std.testing.io);
    const second = try socket();
    defer second.close(std.testing.io);
    const host = try socket();
    defer host.close(std.testing.io);
    for ([_]net.Socket{ first, second, host }, 0..) |target, index| {
        const sender = try std.Thread.spawn(.{}, delayedSend, .{ host, target.address });
        defer sender.join();
        const result = wait.poll(std.testing.io, .{ .quic = first.handle, .discovery = second.handle, .host = host.handle }, 1000);
        try std.testing.expect(result.failure == null);
        try std.testing.expectEqual(index == 0, result.quic);
        try std.testing.expectEqual(index == 1, result.discovery);
        try std.testing.expectEqual(index == 2, result.host);
        var buffer: [8]u8 = undefined;
        const message = try target.receiveTimeout(std.testing.io, &buffer, .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(0) } });
        try std.testing.expectEqualStrings("delayed", message.data);
    }
}

fn delayedSend(sender: net.Socket, address: net.IpAddress) void {
    std.testing.io.sleep(.fromMilliseconds(10), .awake) catch unreachable;
    sender.send(std.testing.io, &address, "delayed") catch unreachable;
}

test "native wait cancellation checkpoints preserve readiness after completion" {
    if (!wait.supported) return error.SkipZigTest;
    const target = try socket();
    defer target.close(std.testing.io);
    try target.send(std.testing.io, &target.address, "queued");
    var vtable = std.testing.io.vtable.*;
    vtable.checkCancel = Cancellation.check;
    var cancellation: Cancellation = .{ .cancel_at = 1 };
    const io: std.Io = .{ .userdata = &cancellation, .vtable = &vtable };
    const before = wait.poll(io, .{ .quic = target.handle }, 100);
    try std.testing.expectEqual(error.Canceled, before.failure.?);
    try std.testing.expect(!before.quic);
    try std.testing.expectEqual(@as(u32, 0), before.timeout_ms);
    cancellation = .{ .cancel_at = 2 };
    const after = wait.poll(io, .{ .quic = target.handle }, 100);
    try std.testing.expectEqual(error.Canceled, after.failure.?);
    try std.testing.expect(after.quic);
    var buffer: [8]u8 = undefined;
    const message = try target.receiveTimeout(std.testing.io, &buffer, .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(0) } });
    try std.testing.expectEqualStrings("queued", message.data);
}

const Cancellation = struct {
    checks: u8 = 0,
    cancel_at: u8,
    fn check(context: ?*anyopaque) std.Io.Cancelable!void {
        const self: *Cancellation = @ptrCast(@alignCast(context.?));
        self.checks += 1;
        if (self.checks == self.cancel_at) return error.Canceled;
    }
};

test "native wait signal interruption returns without retrying" {
    if (!wait.supported) return error.SkipZigTest;
    const target = try socket();
    defer target.close(std.testing.io);
    var old: std.posix.Sigaction = undefined;
    const action: std.posix.Sigaction = .{
        .handler = .{ .handler = signalHandler },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(.USR1, &action, &old);
    defer std.posix.sigaction(.USR1, &old, null);
    const sender = try std.Thread.spawn(.{}, sendSignal, .{std.c.pthread_self()});
    defer sender.join();
    const result = wait.poll(std.testing.io, .{ .quic = target.handle }, 1000);
    try std.testing.expect(result.failure == null);
    try std.testing.expect(result.interrupted);
    try std.testing.expect(!result.quic);
    try std.testing.expectEqual(@as(u32, 100), result.timeout_ms);
}

fn signalHandler(_: std.posix.SIG) callconv(.c) void {}
fn sendSignal(thread: std.c.pthread_t) void {
    std.testing.io.sleep(.fromMilliseconds(10), .awake) catch unreachable;
    std.debug.assert(std.c.pthread_kill(thread, .USR1) == 0);
}
