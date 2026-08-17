//! Small cross-cutting helpers shared by the discv5 protocol and service layers.

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const Address = net.IpAddress;
const NodeId = @import("enr.zig").NodeId;

/// Bind a UDP (datagram) socket to `address`, restricting IPv6 sockets to v6-only.
pub fn bindDatagramSocket(io: Io, address: Address) !net.Socket {
    return try net.IpAddress.bind(&address, io, .{
        .mode = .dgram,
        .ip6_only = switch (address) {
            .ip4 => false,
            .ip6 => true,
        },
    });
}

/// First 4 bytes of a node id as lowercase hex, for compact logging.
pub fn shortNodeId(node_id: *const NodeId) [8]u8 {
    return std.fmt.bytesToHex(node_id[0..4].*, .lower);
}

/// Current real-clock time in nanoseconds.
pub fn nowNs(io: Io) i64 {
    return @intCast(Io.Timestamp.now(io, .real).toNanoseconds());
}

/// Current real-clock Unix time in milliseconds (clamped at 0).
pub fn nowMs(io: Io) u64 {
    const ms = Io.Timestamp.now(io, .real).toMilliseconds();
    return if (ms < 0) 0 else @intCast(ms);
}
