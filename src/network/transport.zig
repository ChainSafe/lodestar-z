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
};

pub const InitError = tls.Error || engine_mod.Error || std.Io.net.IpAddress.BindError ||
    std.Io.RandomSecureError || error{ClockOutOfRange};

pub const DialError = driver_mod.DialError || error{MissingPeerId};

pub const Transport = struct {
    tls: tls.Context = undefined,
    engine: engine_mod.Engine = undefined,
    udp: udp_mod.Udp = undefined,
    driver: driver_mod.Driver = undefined,

    pub fn init(
        target: *Transport,
        allocator: std.mem.Allocator,
        io: std.Io,
        options: Options,
    ) InitError!void {
        var serial: [8]u8 = undefined;
        try std.Io.randomSecure(io, &serial);
        const now = try driver_mod.currentTime(io);
        target.tls = try tls.Context.init(options.host, now.unix_s, serial);
        errdefer target.tls.deinit();
        target.udp = try udp_mod.Udp.bind(io, options.bind);
        errdefer target.udp.close(io);
        const local = target.udp.localAddress();
        target.engine = try engine_mod.Engine.init(allocator, &target.tls, options.limits, &local);
        errdefer target.engine.deinit();
        target.driver = driver_mod.Driver.init(&target.engine, &target.udp);
        assert(target.driver.engine == &target.engine);
        assert(target.driver.udp == &target.udp);
    }

    pub fn deinit(self: *Transport, io: std.Io) void {
        assert(self.driver.engine == &self.engine);
        self.engine.deinit();
        self.udp.close(io);
        self.tls.deinit();
        self.* = undefined;
    }

    pub fn peerId(self: *const Transport) peer_id.PeerId {
        assert(self.driver.engine == &self.engine);
        return self.tls.local_peer_id;
    }

    pub fn localAddress(self: *const Transport) types.Address {
        assert(self.driver.udp == &self.udp);
        return self.udp.localAddress();
    }

    pub fn localMultiaddr(self: *const Transport) multiaddr.Multiaddr {
        assert(self.driver.engine == &self.engine);
        return .{ .address = self.udp.localAddress(), .peer = self.tls.local_peer_id };
    }

    pub fn dial(
        self: *Transport,
        io: std.Io,
        target: *const multiaddr.Multiaddr,
    ) DialError!engine_mod.Handle {
        assert(self.driver.engine == &self.engine);
        const expected = target.peer orelse return error.MissingPeerId;
        return self.driver.dial(io, target.address, expected);
    }

    pub fn step(
        self: *Transport,
        io: std.Io,
        events: []engine_mod.Event,
        activity: []engine_mod.Handle,
        options: driver_mod.StepOptions,
    ) driver_mod.StepError!driver_mod.StepResult {
        assert(self.driver.engine == &self.engine);
        assert(self.driver.udp == &self.udp);
        return self.driver.step(io, events, activity, options);
    }
};
