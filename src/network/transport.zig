const std = @import("std");
const driver_mod = @import("driver.zig");
const engine_mod = @import("quic/engine.zig");
const keys = @import("wire/keys.zig");
const multiaddr = @import("wire/multiaddr.zig");
const peer_id = @import("wire/peer_id.zig");
const tls = @import("tls/context.zig");
const types = @import("types.zig");
const udp_mod = @import("udp.zig");

const assert = std.debug.assert;

pub const Options = struct {
    host: *const keys.KeyPair,
    bind: std.Io.net.IpAddress,
    limits: engine_mod.Limits = .{},
    keylog_path: ?[]const u8 = null,
};

pub const InitError = tls.Error || engine_mod.Error || std.Io.net.IpAddress.BindError ||
    std.Io.RandomSecureError || std.Io.File.OpenError || std.Io.File.StatError ||
    error{ClockOutOfRange};

pub const DialError = driver_mod.DialError || error{MissingPeerId};

pub const StepError = driver_mod.StepError || error{KeylogWriteFailed};

pub const Transport = struct {
    engine: engine_mod.Engine = undefined,
    udp: udp_mod.Udp = undefined,
    driver: driver_mod.Driver = .{},
    keylog: ?std.Io.File = null,
    keylog_offset: u64 = 0,

    pub fn init(
        target: *Transport,
        allocator: std.mem.Allocator,
        io: std.Io,
        options: Options,
    ) InitError!void {
        var serial: [8]u8 = undefined;
        try std.Io.randomSecure(io, &serial);
        var seed_bytes: [8]u8 = undefined;
        try std.Io.randomSecure(io, &seed_bytes);
        const now = try driver_mod.currentTime(io);
        target.keylog = null;
        target.keylog_offset = 0;
        if (options.keylog_path) |path| {
            const file = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = false });
            errdefer file.close(io);
            target.keylog_offset = (try file.stat(io)).size;
            target.keylog = file;
        }
        errdefer if (target.keylog) |file| file.close(io);
        var context = try tls.Context.init(options.host, now.unix_s, serial);
        errdefer context.deinit();
        target.udp = try udp_mod.Udp.bind(io, options.bind);
        errdefer target.udp.close(io);
        target.engine = try engine_mod.Engine.init(allocator, .{
            .tls = context,
            .limits = options.limits,
            .local = target.udp.localAddress(),
            .seed = std.mem.readInt(u64, &seed_bytes, .little),
        });
        target.driver = driver_mod.Driver.init();
        assert(target.engine.slots.len == options.limits.connections_max);
        assert(target.keylog != null or options.keylog_path == null);
    }

    pub fn deinit(self: *Transport, io: std.Io) void {
        self.engine.deinit();
        self.udp.close(io);
        if (self.keylog) |file| file.close(io);
        self.* = undefined;
    }

    pub fn peerId(self: *const Transport) peer_id.PeerId {
        assert(self.engine.slots.len > 0);
        return self.engine.tls.local_peer_id;
    }

    pub fn localAddress(self: *const Transport) types.Address {
        assert(self.engine.slots.len > 0);
        return self.udp.localAddress();
    }

    pub fn localMultiaddr(self: *const Transport) multiaddr.Multiaddr {
        assert(self.engine.slots.len > 0);
        return .{ .address = self.udp.localAddress(), .peer = self.engine.tls.local_peer_id };
    }

    pub fn nextTimeoutMs(self: *const Transport) ?u64 {
        assert(self.engine.slots.len > 0);
        return self.driver.nextTimeoutMs(@constCast(&self.engine));
    }

    pub fn dial(
        self: *Transport,
        io: std.Io,
        target: *const multiaddr.Multiaddr,
    ) DialError!engine_mod.Handle {
        const expected = target.peer orelse return error.MissingPeerId;
        return self.dialPeer(io, target.address, expected);
    }

    pub fn dialPeer(
        self: *Transport,
        io: std.Io,
        address: types.Address,
        expected: peer_id.PeerId,
    ) DialError!engine_mod.Handle {
        assert(self.engine.slots.len > 0);
        return self.driver.dial(io, &self.engine, &self.udp, address, expected);
    }

    pub fn step(
        self: *Transport,
        io: std.Io,
        events: []engine_mod.Event,
        activity: []engine_mod.Handle,
        options: driver_mod.StepOptions,
    ) StepError!driver_mod.StepResult {
        assert(self.engine.slots.len > 0);
        const result = try self.driver.step(io, &self.engine, &self.udp, events, activity, options);
        try self.drainKeylog(io);
        return result;
    }

    fn drainKeylog(self: *Transport, io: std.Io) error{KeylogWriteFailed}!void {
        const file = self.keylog orelse return;
        const view = self.engine.driverView();
        var lines: [tls.keylog_capacity]u8 = undefined;
        for (view.activeIndices()) |index| {
            const length = view.takeKeylog(index, &lines);
            if (length == 0) continue;
            file.writePositionalAll(io, lines[0..length], self.keylog_offset) catch {
                file.close(io);
                self.keylog = null;
                return error.KeylogWriteFailed;
            };
            self.keylog_offset += length;
        }
    }
};
