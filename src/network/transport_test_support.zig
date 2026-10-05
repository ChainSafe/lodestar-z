const std = @import("std");
const Transport = @import("transport.zig").Transport;
const keys = @import("wire/keys.zig");
const Event = @import("quic/Engine.zig").Event;
const transport_driver = @import("transport_driver.zig");

pub const Node = struct {
    transport: Transport = .{},

    pub fn init(self: *Node, seed: u8) !void {
        const key = try keys.KeyPair.fromSecretKey(&([_]u8{0} ** 31 ++ [_]u8{seed}));
        try self.transport.init(std.testing.allocator, std.testing.io, .{
            .host = &key,
            .bind = .{ .ip4 = .loopback(0) },
        });
    }

    pub fn deinit(self: *Node) void {
        self.transport.deinit(std.testing.io);
    }
};

pub fn step(transport: *Transport, io: std.Io, events: []Event, options: transport_driver.Options) transport_driver.Error!Transport.Progress {
    const result = transport_driver.step(transport, io, events, options);
    if (result.failure) |err| return err;
    return result.progress;
}
