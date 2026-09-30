const std = @import("std");
const udp = @import("root.zig");
const net = std.Io.net;

const loopbacks: udp.Bindings = .{ .dual = .{ .ip4 = .loopback(0), .ip6 = .loopback(0) } };

fn timeout(milliseconds: i64) std.Io.Timeout {
    return .{ .duration = .{ .raw = .fromMilliseconds(milliseconds), .clock = .awake } };
}

/// A ready read that tries every family.
fn readAny(sockets: *udp.Sockets, io: std.Io, buffer: []u8) udp.ReceiveError!?net.IncomingMessage {
    var ready: [2]bool = @splat(true);
    return sockets.receiveReady(io, buffer, &ready);
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
        fn bind(_: ?*anyopaque, address: *const net.IpAddress, options: net.IpAddress.BindOptions) net.IpAddress.BindError!net.Socket {
            std.debug.assert(options.ip6_only == (address.* == .ip6));
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

test "UDP wildcard listeners share a port and keep datagrams in their address family" {
    var sockets = try udp.Sockets.bind(std.testing.io, .{ .ip6 = .unspecified(0) });
    defer sockets.close(std.testing.io);
    const port = sockets.values[1].?.address.getPort();
    sockets.values[0] = try (net.IpAddress{ .ip4 = .unspecified(port) }).bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    var senders = try udp.Sockets.bind(std.testing.io, loopbacks);
    defer senders.close(std.testing.io);
    for ([_]net.IpAddress{ .{ .ip4 = .loopback(port) }, .{ .ip6 = .loopback(port) } }, 0..) |destination, family| {
        try senders.values[family].?.send(std.testing.io, &destination, "same port");
        var buffer: [16]u8 = undefined;
        const packet = try sockets.values[family].?.receiveTimeout(std.testing.io, &buffer, timeout(1000));
        try std.testing.expectEqual(@as(usize, family), if (packet.from == .ip4) @as(usize, 0) else 1);
        try std.testing.expectEqualStrings("same port", packet.data);
    }
    sockets.close(std.testing.io);
    sockets = .{};
    sockets = try udp.Sockets.bind(std.testing.io, .{ .dual = .{ .ip4 = .unspecified(port), .ip6 = .unspecified(port) } });
    try std.testing.expectEqual(port, sockets.values[0].?.address.getPort());
    try std.testing.expectEqual(port, sockets.values[1].?.address.getPort());
    try std.testing.expectError(error.AddressInUse, udp.Sockets.bind(std.testing.io, .{ .ip6 = .unspecified(port) }));
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
    try std.testing.expectEqual(null, try readAny(&sockets, io, &buffer));
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
        const packet = (try readAny(&sockets, std.testing.io, &buffer)).?;
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
    try std.testing.expectEqual(null, try readAny(&sockets, io, &buffer));
    try std.testing.expectError(error.Timeout, sockets.receiveTimeout(io, &buffer, timeout(0)));
    for (sockets.values) |target| try target.?.send(io, &target.?.address, "ready");
    for (0..2) |_| {
        const packet = try sockets.receiveTimeout(io, &buffer, timeout(0));
        try std.testing.expectEqualStrings("ready", packet.data);
    }
    var concurrent_sockets = try udp.Sockets.bind(std.testing.io, loopbacks);
    defer concurrent_sockets.close(std.testing.io);
    try std.testing.expectError(error.Timeout, concurrent_sockets.receiveTimeout(std.testing.io, &buffer, timeout(10)));
    try std.testing.expectEqual(null, try readAny(&concurrent_sockets, std.testing.io, &buffer));
}

fn kernelSize(handle: net.Socket.Handle, option: u32) !u32 {
    const p = std.posix;
    var value: c_int = 0;
    var len: p.socklen_t = @sizeOf(c_int);
    try std.testing.expectEqual(p.E.SUCCESS, p.errno(p.system.getsockopt(handle, p.SOL.SOCKET, option, std.mem.asBytes(&value), &len)));
    return @intCast(value);
}

test "UDP records the kernel's socket buffer sizes and receive drops after a request" {
    const os = @import("builtin").os.tag;
    if (os != .linux and os != .macos) return error.SkipZigTest;
    var plain = try udp.Sockets.bind(std.testing.io, loopbacks);
    defer plain.close(std.testing.io);
    var sockets = try udp.Sockets.bind(std.testing.io, loopbacks);
    defer sockets.close(std.testing.io);
    const largest: udp.Buffers = .{ .receive = udp.Buffers.bytes_max, .send = udp.Buffers.bytes_max };
    const short = sockets.requestBuffers(std.testing.io, largest);
    const full: u64 = if (os == .linux) 2 * @as(u64, udp.Buffers.bytes_max) else udp.Buffers.bytes_max;
    for (plain.values, sockets.buffers, short) |socket, reported, below| {
        try std.testing.expect(reported.?.receive.? >= try kernelSize(socket.?.handle, std.posix.SO.RCVBUF));
        try std.testing.expect(reported.?.send.? >= try kernelSize(socket.?.handle, std.posix.SO.SNDBUF));
        try std.testing.expectEqual(reported.?.receive.? < full or reported.?.send.? < full, below);
    }
    try std.testing.expectEqual([2]?udp.Buffers.Reported{ null, null }, plain.buffers);
    // A supported observation must work equally before and after requesting buffers.
    try std.testing.expectEqual(sockets.drops(), plain.drops());
    const smallest: udp.Buffers = .{ .receive = udp.Buffers.bytes_min, .send = udp.Buffers.bytes_min };
    try std.testing.expectEqual([2]bool{ false, false }, sockets.requestBuffers(std.testing.io, smallest));
    if (os != .linux) return;
    // Kernels without SO_MEMINFO report no drop count, and production exports none.
    const initial = sockets.drops();
    if (initial[0] == null) return;
    try std.testing.expectEqual([2]?u64{ 0, 0 }, initial);
    const sent = 256;
    var payload: [1200]u8 = @splat(0);
    for (0..sent) |_| try plain.values[0].?.send(std.testing.io, &sockets.values[0].?.address, &payload);
    var received: usize = 0;
    for (0..1000) |_| {
        while (try readAny(&sockets, std.testing.io, &payload)) |_| received += 1;
        if (received + sockets.drops()[0].? == sent) break;
        try std.Io.sleep(std.testing.io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expect(received > 0 and received < sent);
    try std.testing.expectEqual(sent, received + sockets.drops()[0].?);
    try std.testing.expectEqual(@as(?u64, 0), sockets.drops()[1]);
}

test "UDP records a failed size readback as unknown and not below the request" {
    const os = @import("builtin").os.tag;
    if (os != .linux and os != .macos) return error.SkipZigTest;
    // getsockopt fails on a descriptor that is not open.
    var sockets: udp.Sockets = .{ .native = .{ true, false }, .values = .{ .{ .handle = -1, .address = .{ .ip4 = .loopback(0) } }, null } };
    const largest: udp.Buffers = .{ .receive = udp.Buffers.bytes_max, .send = udp.Buffers.bytes_max };
    try std.testing.expectEqual([2]bool{ false, false }, sockets.requestBuffers(std.testing.io, largest));
    try std.testing.expectEqual([2]?udp.Buffers.Reported{ .{ .receive = null, .send = null }, null }, sockets.buffers);
    try std.testing.expectEqual([2]?u64{ null, null }, sockets.drops());
}

test "UDP distinguishes refused sends from nonblocking send pressure" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var sockets: [4]udp.Sockets = undefined;
    for (&sockets, 0..) |*socket, index| {
        errdefer for (sockets[0..index]) |*bound| bound.close(std.testing.io);
        socket.* = try udp.Sockets.bind(std.testing.io, .{ .ip4 = .loopback(0) });
    }
    defer for (&sockets) |*socket| socket.close(std.testing.io);
    var outcome: Refusal = .{};
    const thread = try std.Thread.spawn(.{}, Refusal.run, .{ &outcome, &sockets });
    thread.join();
    // Kernels without seccomp filters cannot produce the errnos.
    if (!outcome.installed) return error.SkipZigTest;
    try std.testing.expectError(error.DestinationRefused, outcome.results[0]);
    try std.testing.expectError(error.AccessDenied, outcome.results[1]);
    try std.testing.expectError(error.WouldBlock, outcome.results[2]);
    try std.testing.expectError(error.SystemResources, outcome.results[3]);
    try std.testing.expectEqual(udp.SendOutcome{ .sent = 0, .failure = error.DestinationRefused }, outcome.batches[0]);
    try std.testing.expectEqual(udp.SendOutcome{ .sent = 0, .failure = error.AccessDenied }, outcome.batches[1]);
    try std.testing.expectEqual(udp.SendOutcome{ .sent = 0, .failure = error.WouldBlock }, outcome.batches[2]);
    try std.testing.expectEqual(udp.SendOutcome{ .sent = 0, .failure = error.SystemResources }, outcome.batches[3]);
    var buffer: [16]u8 = undefined;
    try std.testing.expectEqual(null, try readAny(&sockets[0], std.testing.io, &buffer));
}

/// Filters one thread's sends: EPERM from the first socket, as an egress firewall drop reports
/// it, EACCES from the second, EAGAIN from the third when the send asks not to wait, as a full
/// send buffer reports it, and ENOBUFS from the fourth. Each socket sends once alone and once as
/// a batch. The filter ends with the thread.
const Refusal = struct {
    installed: bool = false,
    results: [4]udp.SendError!void = @splat({}),
    batches: [4]udp.SendOutcome = undefined,

    const Instruction = udp.testing.SendFilter.Instruction;
    const Program = udp.testing.SendFilter.Program;

    fn run(self: *Refusal, sockets: *const [4]udp.Sockets) void {
        const errnos = [_]std.os.linux.E{ .PERM, .ACCES, .AGAIN, .NOBUFS };
        var rules: [4]udp.testing.SendFilter.Rule = undefined;
        for (&rules, sockets, errnos, 0..) |*rule, socket, errno, index| {
            rule.* = .{ .socket = socket.primary().handle, .errno = errno, .nonblocking_only = index == 2 };
        }
        if (!udp.testing.SendFilter.install(&rules)) return;
        self.installed = true;
        const destination = sockets[0].primary().address;
        for (sockets, &self.results, &self.batches) |*socket, *result, *batch| {
            result.* = socket.sendTo(std.testing.io, udp.Address.fromNetwork(destination), "filtered", 16);
            const message: udp.Outgoing = .{ .to = udp.Address.fromNetwork(destination), .bytes = "filtered" };
            batch.* = sendMany(socket, std.testing.io, (&message)[0..1]);
        }
    }
};

test "UDP batches report the exact prefix before a failing datagram and resume after it" {
    var sockets = try udp.Sockets.bind(std.testing.io, .{ .ip4 = .loopback(0) });
    defer sockets.close(std.testing.io);
    const self_address = sockets.primary().address;
    // Linux refuses a broadcast without SO_BROADCAST with EACCES.
    const broadcast: net.IpAddress = .{ .ip4 = .{ .bytes = @splat(255), .port = self_address.ip4.port } };
    const messages = [_]udp.Outgoing{
        .{ .to = udp.Address.fromNetwork(self_address), .bytes = "first" },
        .{ .to = udp.Address.fromNetwork(broadcast), .bytes = "refused" },
        .{ .to = udp.Address.fromNetwork(self_address), .bytes = "third" },
    };
    try std.testing.expectEqual(udp.SendOutcome{ .sent = 0, .failure = error.AccessDenied }, sendMany(&sockets, std.testing.io, messages[1..]));
    try std.testing.expectEqual(udp.SendOutcome{ .sent = 1, .failure = error.AccessDenied }, sendMany(&sockets, std.testing.io, &messages));
    try std.testing.expectEqual(@as(usize, 5), messages[0].bytes.len);
    try std.testing.expectEqual(udp.SendOutcome{ .sent = 1, .failure = null }, sendMany(&sockets, std.testing.io, messages[2..]));
    var buffer: [16]u8 = undefined;
    for ([_][]const u8{ "first", "third" }) |expected| {
        try std.testing.expectEqualStrings(expected, (try readAny(&sockets, std.testing.io, &buffer)).?.data);
    }
    try std.testing.expectEqual(null, try readAny(&sockets, std.testing.io, &buffer));
}

test "UDP native batches check cancellation before sending" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const Canceled = struct {
        fn check(_: ?*anyopaque) std.Io.Cancelable!void {
            return error.Canceled;
        }
    };
    var sockets = try udp.Sockets.bind(std.testing.io, .{ .ip4 = .loopback(0) });
    defer sockets.close(std.testing.io);
    var vtable = std.testing.io.vtable.*;
    vtable.checkCancel = Canceled.check;
    const io: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    const destination = sockets.primary().address;
    const message: udp.Outgoing = .{ .to = udp.Address.fromNetwork(destination), .bytes = "canceled" };
    try std.testing.expectEqual(udp.SendOutcome{ .sent = 0, .failure = error.Canceled }, sendMany(&sockets, io, (&message)[0..1]));
    var buffer: [16]u8 = undefined;
    try std.testing.expectEqual(null, try readAny(&sockets, std.testing.io, &buffer));
}

test "UDP native pressure returns without polling writable for EAGAIN ENOBUFS and ENOMEM" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var sockets = try udp.Sockets.bind(std.testing.io, .{ .ip4 = .loopback(0) });
    defer sockets.close(std.testing.io);
    for ([_]std.os.linux.E{ .AGAIN, .NOBUFS, .NOMEM }) |errno| {
        var pressure: Pressure = .{ .errno = errno };
        const thread = try std.Thread.spawn(.{}, Pressure.run, .{ &pressure, &sockets });
        thread.join();
        if (!pressure.installed) return error.SkipZigTest;
        try std.testing.expectEqual(@as(usize, 0), Pressure.waits);
        const expected: udp.SendError = if (errno == .AGAIN) error.WouldBlock else error.SystemResources;
        try std.testing.expectError(expected, pressure.single);
        try std.testing.expectEqual(udp.SendOutcome{ .sent = 0, .failure = expected }, pressure.batch);
    }
    var buffer: [16]u8 = undefined;
    try std.testing.expectEqual(null, try readAny(&sockets, std.testing.io, &buffer));
}

const Pressure = struct {
    errno: std.os.linux.E,
    installed: bool = false,
    single: udp.SendError!void = {},
    batch: udp.SendOutcome = undefined,
    var waits: usize = 0;

    fn run(self: *Pressure, sockets: *const udp.Sockets) void {
        if (!udp.testing.SendFilter.install(&.{.{ .socket = sockets.primary().handle, .errno = self.errno, .nonblocking_only = true }})) return;
        self.installed = true;
        waits = 0;
        var vtable = std.testing.io.vtable.*;
        vtable.batchAwaitConcurrent = wait;
        const io: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
        const destination = sockets.primary().address;
        self.single = sockets.sendTo(io, udp.Address.fromNetwork(destination), "dropped", 16);
        const message: udp.Outgoing = .{ .to = udp.Address.fromNetwork(destination), .bytes = "dropped" };
        self.batch = sendMany(sockets, io, (&message)[0..1]);
    }

    fn wait(_: ?*anyopaque, _: *std.Io.Batch, _: std.Io.Timeout) std.Io.Batch.AwaitConcurrentError!void {
        waits += 1;
        return error.Canceled;
    }
};

test "UDP leaves sends to a provider that replaces them" {
    var sockets = try udp.Sockets.bind(std.testing.io, .{ .ip4 = .loopback(0) });
    defer sockets.close(std.testing.io);
    var faults: udp.testing.FaultIo = .{ .send = .{} };
    faults.init(std.testing.io);
    defer faults.deinit();
    const destination = udp.Address.fromNetwork(sockets.primary().address);
    try std.testing.expectError(error.AddressFamilyUnsupported, sockets.sendTo(faults.io(), destination, "provider", 16));
    try std.testing.expectEqual(@as(usize, 1), faults.send_calls);
    const message: udp.Outgoing = .{ .to = udp.Address.fromNetwork(sockets.primary().address), .bytes = "provider" };
    try std.testing.expectEqual(udp.SendOutcome{ .sent = 0, .failure = error.AddressFamilyUnsupported }, sendMany(&sockets, faults.io(), (&message)[0..1]));
    try std.testing.expectEqual(@as(usize, 2), faults.send_calls);
}

test "UDP ready reads alternate marked families across turns and clear each one found empty" {
    var sockets = try udp.Sockets.bind(std.testing.io, loopbacks);
    defer sockets.close(std.testing.io);
    const ip4 = sockets.values[0].?;
    const ip6 = sockets.values[1].?;
    for ([_][]const u8{ "4a", "4b", "4c" }) |payload| try ip4.send(std.testing.io, &ip4.address, payload);
    for ([_][]const u8{ "6a", "6b" }) |payload| try ip6.send(std.testing.io, &ip6.address, payload);
    var buffer: [16]u8 = undefined;
    // A turn whose quota ends after three reads leaves the next turn to start at the other family.
    for ([_][]const []const u8{ &.{ "4a", "6a", "4b" }, &.{ "6b", "4c" } }) |turn| {
        var ready: [2]bool = @splat(true);
        for (turn) |expected| {
            const message = (try sockets.receiveReady(std.testing.io, &buffer, &ready)).?;
            try std.testing.expectEqualStrings(expected, message.data);
            try std.testing.expectEqual([2]bool{ true, true }, ready);
        }
        if (turn.len == 2) {
            try std.testing.expectEqual(null, try sockets.receiveReady(std.testing.io, &buffer, &ready));
            try std.testing.expectEqual([2]bool{ false, false }, ready);
        }
    }
    try ip6.send(std.testing.io, &ip6.address, "6c");
    var ready: [2]bool = .{ true, false };
    try std.testing.expectEqual(null, try sockets.receiveReady(std.testing.io, &buffer, &ready));
    try std.testing.expectEqual([2]bool{ false, false }, ready);
    ready = .{ false, true };
    try std.testing.expectEqualStrings("6c", (try sockets.receiveReady(std.testing.io, &buffer, &ready)).?.data);
    var single = try udp.Sockets.bind(std.testing.io, .{ .ip6 = .loopback(0) });
    defer single.close(std.testing.io);
    ready = @splat(true);
    try std.testing.expectEqual(null, try single.receiveReady(std.testing.io, &buffer, &ready));
    try std.testing.expectEqual([2]bool{ true, false }, ready);
}

test "UDP ready reads leave a provider that replaces timed receives on its own receive" {
    var sockets = try udp.Sockets.bind(std.testing.io, loopbacks);
    defer sockets.close(std.testing.io);
    for (sockets.values) |target| try target.?.send(std.testing.io, &target.?.address, "provider");
    var faults: udp.testing.FaultIo = .{};
    faults.init(std.testing.io);
    defer faults.deinit();
    var buffer: [16]u8 = undefined;
    var ready: [2]bool = .{ true, false };
    try std.testing.expectEqualStrings("provider", (try sockets.receiveReady(faults.io(), &buffer, &ready)).?.data);
    try std.testing.expectEqual(null, try sockets.receiveReady(faults.io(), &buffer, &ready));
    try std.testing.expectEqual([2]bool{ false, false }, ready);
    // One provider receive per read, the empty one included, and none for the unmarked family.
    try std.testing.expectEqual(@as(usize, 2), faults.receive_calls);
    faults.receive = .{ .at = 3 };
    ready = .{ false, true };
    try std.testing.expectError(error.Canceled, sockets.receiveReady(faults.io(), &buffer, &ready));
    try std.testing.expectEqual([2]bool{ false, true }, ready);
    faults.receive = null;
    try std.testing.expectEqualStrings("provider", (try sockets.receiveReady(faults.io(), &buffer, &ready)).?.data);
}

test "UDP native ready reads cost one receive each, never poll and never read an unmarked family" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var sockets = try udp.Sockets.bind(std.testing.io, loopbacks);
    defer sockets.close(std.testing.io);
    var single = try udp.Sockets.bind(std.testing.io, .{ .ip4 = .loopback(0) });
    defer single.close(std.testing.io);
    const ip4 = sockets.values[0].?;
    for ([_][]const u8{ "first", "second", "third" }) |payload| try ip4.send(std.testing.io, &ip4.address, payload);
    try sockets.values[1].?.send(std.testing.io, &sockets.values[1].?.address, "unmarked");
    var outcome: NoPoll = .{};
    const thread = try std.Thread.spawn(.{}, NoPoll.run, .{ &outcome, &sockets, &single });
    thread.join();
    // Kernels without seccomp filters cannot refuse the calls.
    if (!outcome.installed) return error.SkipZigTest;
    // The filter refuses every poll, which Threaded reports as ConcurrencyUnavailable, and every
    // read of the IPv6 socket.
    try std.testing.expectError(error.ConcurrencyUnavailable, outcome.polled);
    try std.testing.expectError(error.NetworkDown, outcome.unmarked);
    try outcome.drained;
    try std.testing.expectEqual(@as(usize, 3), outcome.received);
    try std.testing.expectEqual(@as(usize, 4), outcome.reads);
    try std.testing.expectEqual([2]bool{ false, false }, outcome.ready);
    try std.testing.expectError(error.Timeout, outcome.timed);
}

/// Filters one thread through seccomp: every poll and ppoll fails with EPERM, and every recvmsg
/// on the IPv6 socket with ENETDOWN. Counts native reads through the cancellation check each one
/// makes. The filter ends with the thread.
const NoPoll = struct {
    installed: bool = false,
    drained: udp.ReceiveError!void = {},
    received: usize = 0,
    reads: usize = 0,
    ready: [2]bool = @splat(true),
    timed: udp.ReceiveError!void = {},
    polled: udp.ReceiveError!void = {},
    unmarked: udp.ReceiveError!void = {},

    const Instruction = Refusal.Instruction;
    const Program = Refusal.Program;

    threadlocal var checks: usize = 0;

    fn check(userdata: ?*anyopaque) std.Io.Cancelable!void {
        checks += 1;
        return std.testing.io.vtable.checkCancel(userdata);
    }

    fn run(self: *NoPoll, sockets: *udp.Sockets, single: *udp.Sockets) void {
        const linux = std.os.linux;
        const bpf = linux.BPF;
        const little = comptime @import("builtin").cpu.arch.endian() == .little;
        const descriptor: u32 = @offsetOf(linux.SECCOMP.data, "arg0") + if (little) 0 else 4;
        const poll: u32 = if (@hasField(linux.SYS, "poll")) @intFromEnum(linux.SYS.poll) else @intFromEnum(linux.SYS.ppoll);
        const filter = [_]Instruction{
            .{ .code = bpf.LD | bpf.W | bpf.ABS, .jt = 0, .jf = 0, .k = @offsetOf(linux.SECCOMP.data, "nr") },
            .{ .code = bpf.JMP | bpf.JEQ | bpf.K, .jt = 0, .jf = 3, .k = @intFromEnum(linux.SYS.recvmsg) },
            .{ .code = bpf.LD | bpf.W | bpf.ABS, .jt = 0, .jf = 0, .k = descriptor },
            .{ .code = bpf.JMP | bpf.JEQ | bpf.K, .jt = 0, .jf = 4, .k = @intCast(sockets.values[1].?.handle) },
            .{ .code = bpf.RET | bpf.K, .jt = 0, .jf = 0, .k = linux.SECCOMP.RET.ERRNO | @as(u32, @intFromEnum(linux.E.NETDOWN)) },
            .{ .code = bpf.JMP | bpf.JEQ | bpf.K, .jt = 1, .jf = 0, .k = poll },
            .{ .code = bpf.JMP | bpf.JEQ | bpf.K, .jt = 0, .jf = 1, .k = @intFromEnum(linux.SYS.ppoll) },
            .{ .code = bpf.RET | bpf.K, .jt = 0, .jf = 0, .k = linux.SECCOMP.RET.ERRNO | @as(u32, @intFromEnum(linux.E.PERM)) },
            .{ .code = bpf.RET | bpf.K, .jt = 0, .jf = 0, .k = linux.SECCOMP.RET.ALLOW },
        };
        const program: Program = .{ .len = filter.len, .filter = &filter };
        if (linux.errno(linux.prctl(@intFromEnum(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0)) != .SUCCESS) return;
        if (linux.errno(linux.seccomp(linux.SECCOMP.SET_MODE_FILTER, 0, &program)) != .SUCCESS) return;
        self.installed = true;
        var vtable = std.testing.io.vtable.*;
        vtable.checkCancel = check;
        const io: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
        var buffer: [16]u8 = undefined;
        self.ready = .{ true, false };
        checks = 0;
        for (0..8) |_| {
            _ = (sockets.receiveReady(io, &buffer, &self.ready) catch |err| {
                self.drained = err;
                break;
            }) orelse break;
            self.received += 1;
        }
        self.reads = checks;
        if (single.receiveTimeout(io, &buffer, timeout(0))) |_| {} else |err| self.timed = err;
        const zero: std.Io.Timeout = .{ .duration = .{ .raw = .zero, .clock = .awake } };
        if (single.primary().receiveTimeout(std.testing.io, &buffer, zero)) |_| {} else |err| self.polled = err;
        var ip6_only: [2]bool = .{ false, true };
        if (sockets.receiveReady(io, &buffer, &ip6_only)) |_| {} else |err| self.unmarked = err;
    }
};

test "UDP native batch preserves its successful prefix when the next call reports pressure" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var sockets = try udp.Sockets.bind(std.testing.io, .{ .ip4 = .loopback(0) });
    defer sockets.close(std.testing.io);
    const Partial = struct {
        installed: bool = false,
        outcome: udp.SendOutcome = undefined,
        fn run(self: *@This(), sender: *const udp.Sockets) void {
            const linux = std.os.linux;
            const bpf = linux.BPF;
            const word: u32 = if (comptime @import("builtin").cpu.arch.endian() == .little) 0 else 4;
            const I = udp.testing.SendFilter.Instruction;
            const filter = [_]I{
                .{ .code = bpf.LD | bpf.W | bpf.ABS, .jt = 0, .jf = 0, .k = @offsetOf(linux.SECCOMP.data, "nr") },
                .{ .code = bpf.JMP | bpf.JEQ | bpf.K, .jt = 0, .jf = 5, .k = @intFromEnum(linux.SYS.sendmmsg) },
                .{ .code = bpf.LD | bpf.W | bpf.ABS, .jt = 0, .jf = 0, .k = @offsetOf(linux.SECCOMP.data, "arg0") + word },
                .{ .code = bpf.JMP | bpf.JEQ | bpf.K, .jt = 0, .jf = 3, .k = @intCast(sender.primary().handle) },
                .{ .code = bpf.LD | bpf.W | bpf.ABS, .jt = 0, .jf = 0, .k = @offsetOf(linux.SECCOMP.data, "arg2") + word },
                .{ .code = bpf.JMP | bpf.JEQ | bpf.K, .jt = 0, .jf = 1, .k = 1 },
                .{ .code = bpf.RET | bpf.K, .jt = 0, .jf = 0, .k = linux.SECCOMP.RET.ERRNO | @as(u32, @intFromEnum(linux.E.AGAIN)) },
                .{ .code = bpf.RET | bpf.K, .jt = 0, .jf = 0, .k = linux.SECCOMP.RET.ALLOW },
            };
            const program: udp.testing.SendFilter.Program = .{ .len = filter.len, .filter = &filter };
            if (linux.errno(linux.prctl(@intFromEnum(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0)) != .SUCCESS) return;
            if (linux.errno(linux.seccomp(linux.SECCOMP.SET_MODE_FILTER, 0, &program)) != .SUCCESS) return;
            self.installed = true;
            const destination = sender.primary().address;
            const broadcast: net.IpAddress = .{ .ip4 = .{ .bytes = @splat(255), .port = destination.ip4.port } };
            // The first call sends one datagram before broadcast refusal. Its successful prefix
            // hides that errno; the next call sees the injected EAGAIN on its own unsent suffix.
            const messages = [_]udp.Outgoing{
                .{ .to = udp.Address.fromNetwork(destination), .bytes = "prefix" },
                .{ .to = udp.Address.fromNetwork(broadcast), .bytes = "suffix" },
            };
            self.outcome = sendMany(sender, std.testing.io, &messages);
        }
    };
    var partial: Partial = .{};
    const thread = try std.Thread.spawn(.{}, Partial.run, .{ &partial, &sockets });
    thread.join();
    if (!partial.installed) return error.SkipZigTest;
    try std.testing.expectEqual(udp.SendOutcome{ .sent = 1, .failure = error.WouldBlock }, partial.outcome);
    var buffer: [16]u8 = undefined;
    try std.testing.expectEqualStrings("prefix", (try readAny(&sockets, std.testing.io, &buffer)).?.data);
    try std.testing.expectEqual(null, try readAny(&sockets, std.testing.io, &buffer));
}

fn sendMany(sockets: *const udp.Sockets, io: std.Io, messages: []const udp.Outgoing) udp.SendOutcome {
    var scratch: udp.BatchScratch = undefined;
    return sockets.sendMany(io, messages, 1500, &scratch);
}
