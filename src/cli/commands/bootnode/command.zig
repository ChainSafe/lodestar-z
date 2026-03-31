const std = @import("std");

const Io = std.Io;
const Allocator = std.mem.Allocator;

const bootnode_runtime = @import("runtime.zig");

pub fn run(io: Io, allocator: Allocator, opts: anytype) !void {
    try bootnode_runtime.run(io, allocator, .{
        .listen_address = opts.listen_address,
        .port = opts.discoveryPort orelse opts.bn_port,
        .listen_address6 = opts.listen_address6,
        .port6 = opts.discoveryPort6 orelse opts.port6,
        .bootnodes = opts.bootnodes,
        .bootnodes_file = opts.bootnodes_file,
        .enr_ip = opts.enr_ip,
        .enr_ip6 = opts.enr_ip6,
        .enr_udp = opts.enr_udp,
        .enr_udp6 = opts.enr_udp6,
        .persist_network_identity = opts.persist_network_identity,
        .nat = opts.nat,
        .data_dir = opts.data_dir,
        .network = @tagName(opts.network),
    });
}
