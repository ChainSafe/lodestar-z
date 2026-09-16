const std = @import("std");
const udp = @import("root.zig");
const net = std.Io.net;

const loopbacks: udp.Bindings = .{ .dual = .{ .ip4 = .loopback(0), .ip6 = .loopback(0) } };

fn timeout(milliseconds: i64) std.Io.Timeout {
    return .{ .duration = .{ .raw = .fromMilliseconds(milliseconds), .clock = .awake } };
}

test "UDP rejects mapped IPv6 listeners before any provider acquisition" {
    const Provider = struct {
        fn bind(_: ?*anyopaque, _: *const net.IpAddress, _: net.IpAddress.BindOptions) net.IpAddress.BindError!net.Socket {
            return error.NetworkDown;
        }
    };
    var vtable = std.testing.io.vtable.*;
    vtable.netBindIp = Provider.bind;
    const io: std.Io = .{ .userdata = null, .vtable = &vtable };
    const mapped: net.Ip6Address = .{ .bytes = .{0} ** 10 ++ .{ 0xff, 0xff, 127, 0, 0, 1 }, .port = 0 };
    try std.testing.expectError(error.AddressFamilyUnsupported, udp.Sockets.bind(io, .{ .ip6 = mapped }));
    try std.testing.expectError(error.AddressFamilyUnsupported, udp.Sockets.bind(io, .{ .dual = .{ .ip4 = .loopback(0), .ip6 = mapped } }));
    const received = udp.Address.fromNetwork(.{ .ip6 = mapped });
    try std.testing.expectEqualDeep(udp.Address{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 0 } }, received);
    try std.testing.expect(!(udp.Address{ .ip6 = .{ .octets = mapped.bytes, .port = 9000 } }).isUsable());
}

test "UDP delegates both families to the supplied bind provider" {
    const Provider = struct {
        fn bind(_: ?*anyopaque, _: *const net.IpAddress, options: net.IpAddress.BindOptions) net.IpAddress.BindError!net.Socket {
            std.debug.assert(!options.ip6_only);
            std.debug.assert(options.mode == .dgram and options.protocol == .udp);
            return error.NetworkDown;
        }
    };
    var vtable = std.testing.io.vtable.*;
    vtable.netBindIp = Provider.bind;
    const io: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    try std.testing.expectError(error.NetworkDown, udp.Sockets.bind(io, .{ .ip4 = .loopback(0) }));
    try std.testing.expectError(error.NetworkDown, udp.Sockets.bind(io, .{ .ip6 = .loopback(0) }));
}

test "UDP rolls back the first bind through its provider when the second fails" {
    const Provider = struct {
        binds: u8 = 0,
        closes: u8 = 0,

        fn bind(context: ?*anyopaque, address: *const net.IpAddress, _: net.IpAddress.BindOptions) net.IpAddress.BindError!net.Socket {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.binds += 1;
            return switch (address.*) {
                .ip4 => .{ .handle = 73, .address = address.* },
                .ip6 => error.AddressInUse,
            };
        }

        fn close(context: ?*anyopaque, handles: []const net.Socket.Handle) void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            std.debug.assert(handles.len == 1 and handles[0] == 73);
            self.closes += 1;
        }
    };
    var provider: Provider = .{};
    var vtable = std.testing.io.vtable.*;
    vtable.netBindIp = Provider.bind;
    vtable.netClose = Provider.close;
    const io: std.Io = .{ .userdata = &provider, .vtable = &vtable };
    try std.testing.expectError(error.AddressInUse, udp.Sockets.bind(io, loopbacks));
    try std.testing.expectEqual(@as(u8, 2), provider.binds);
    try std.testing.expectEqual(@as(u8, 1), provider.closes);
}

test "UDP retains packets arriving between readiness probes and blocking receives" {
    var sockets = try udp.Sockets.bind(std.testing.io, loopbacks);
    defer sockets.close(std.testing.io);
    const Arrival = struct {
        var targets: [2]?net.Socket = undefined;
        var fired: std.atomic.Value(bool) = .init(false);

        fn wait(userdata: ?*anyopaque, batch: *std.Io.Batch, deadline: std.Io.Timeout) std.Io.Batch.AwaitConcurrentError!void {
            const operation = batch.storage[batch.submitted.head.toIndex()].submission.operation.net_receive;
            if (operation.flags.peek and !fired.swap(true, .acq_rel)) {
                // The first arrival can finish the other waiter and cancel this injector.
                const protection = std.testing.io.swapCancelProtection(.blocked);
                defer _ = std.testing.io.swapCancelProtection(protection);
                for (targets) |target| target.?.send(std.testing.io, &target.?.address, "arrival") catch unreachable;
            }
            return std.testing.io.vtable.batchAwaitConcurrent(userdata, batch, deadline);
        }
    };
    Arrival.targets = sockets.values;
    Arrival.fired.store(false, .release);
    var vtable = std.testing.io.vtable.*;
    vtable.batchAwaitConcurrent = Arrival.wait;
    const io: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    var buffer: [16]u8 = undefined;
    var families: [2]bool = @splat(false);
    for (0..2) |_| {
        const packet = try sockets.receiveTimeout(io, &buffer, timeout(1_000));
        try std.testing.expectEqualStrings("arrival", packet.data);
        const family: usize = if (packet.from == .ip4) 0 else 1;
        try std.testing.expect(!families[family]);
        families[family] = true;
    }
    try std.testing.expect(Arrival.fired.load(.acquire));
    try std.testing.expect(families[0] and families[1]);
    try std.testing.expectEqual(null, try sockets.receiveReady(io, &buffer));
}

test "UDP partial wait startup failure cancels the first task and leaves sockets usable" {
    var sockets = try udp.Sockets.bind(std.testing.io, loopbacks);
    defer sockets.close(std.testing.io);
    const Provider = struct {
        threadlocal var starts: u8 = 0;

        fn start(userdata: ?*anyopaque, group: *std.Io.Group, context: []const u8, alignment: std.mem.Alignment, run: *const fn (*const anyopaque) void) std.Io.ConcurrentError!void {
            starts += 1;
            if (starts == 2) return error.ConcurrencyUnavailable;
            return std.testing.io.vtable.groupConcurrent(userdata, group, context, alignment, run);
        }
    };
    Provider.starts = 0;
    var vtable = std.testing.io.vtable.*;
    vtable.groupConcurrent = Provider.start;
    const io: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    var buffer: [16]u8 = undefined;
    try std.testing.expectError(error.ConcurrencyUnavailable, sockets.receiveTimeout(io, &buffer, .none));
    try std.testing.expectEqual(@as(u8, 2), Provider.starts);
    for (sockets.values) |target| try target.?.send(std.testing.io, &target.?.address, "retained");
    for (0..2) |_| {
        const packet = (try sockets.receiveReady(std.testing.io, &buffer)).?;
        try std.testing.expectEqualStrings("retained", packet.data);
    }
}

test "UDP dual-stack timeout joins waits and ready reads need no concurrency" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .concurrent_limit = .nothing });
    defer threaded.deinit();
    const io = threaded.io();
    var sockets = try udp.Sockets.bind(io, loopbacks);
    defer sockets.close(io);
    var buffer: [16]u8 = undefined;
    try std.testing.expectEqual(null, try sockets.receiveReady(io, &buffer));
    try std.testing.expectError(error.Timeout, sockets.receiveTimeout(io, &buffer, timeout(0)));
    for (sockets.values) |target| try target.?.send(io, &target.?.address, "ready");
    for (0..2) |_| {
        const packet = try sockets.receiveTimeout(io, &buffer, timeout(0));
        try std.testing.expectEqualStrings("ready", packet.data);
    }
    var concurrent_sockets = try udp.Sockets.bind(std.testing.io, loopbacks);
    defer concurrent_sockets.close(std.testing.io);
    try std.testing.expectError(error.Timeout, concurrent_sockets.receiveTimeout(std.testing.io, &buffer, timeout(10)));
    try std.testing.expectEqual(null, try concurrent_sockets.receiveReady(std.testing.io, &buffer));
}
