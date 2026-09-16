const std = @import("std");
const Transport = @import("Transport.zig");
const Lookup = @import("Lookup.zig");
const Maintenance = @import("Maintenance.zig");
const Engine = @import("Engine.zig");

pub const Result = struct { started: bool = false, failure: ?Transport.Error = null };

pub fn startLookup(transport: *Transport, io: std.Io, lookup: *Lookup, now_ms: u64) !Result {
    var entropy: Engine.StartEntropy = undefined;
    try io.randomSecure(std.mem.asBytes(&entropy));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&entropy));
    const started = try lookup.startNext(&transport.engine, &transport.output, try Transport.requestId(io), now_ms, &entropy) orelse return .{};
    transport.transmit(io, started.peer.address, transport.output[0..started.call.packet_length]) catch |err| {
        lookup.onFailure(&transport.engine, started.call.handle) catch unreachable;
        return .{ .started = true, .failure = err };
    };
    return .{ .started = true };
}

pub fn startMaintenance(transport: *Transport, io: std.Io, maintenance: *Maintenance, now_ms: u64) !Result {
    var entropy: Engine.StartEntropy = undefined;
    try io.randomSecure(std.mem.asBytes(&entropy));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&entropy));
    const started = try maintenance.startNext(&transport.engine, &transport.output, try Transport.requestId(io), now_ms, &entropy) orelse return .{};
    transport.transmit(io, started.peer.address, transport.output[0..started.call.packet_length]) catch |err| {
        std.debug.assert(maintenance.onFailure(&transport.engine, started.call.handle, now_ms, .local));
        return .{ .started = true, .failure = err };
    };
    return .{ .started = true };
}
