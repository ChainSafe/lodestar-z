const std = @import("std");
const transport_mod = @import("transport.zig");
const keys = @import("wire/keys.zig");
const Event = @import("quic/Engine.zig").Event;

pub const Node = struct {
    transport: transport_mod.Transport = .{},

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

pub fn step(transport: *transport_mod.Transport, io: std.Io, events: []Event, options: transport_mod.StepOptions) transport_mod.StepError!transport_mod.StepResult {
    const result = transport.step(io, events, options);
    if (result.failure) |err| return err;
    return result.progress;
}
