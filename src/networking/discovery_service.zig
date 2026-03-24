//! Discovery service: bridges discv5 peer discovery with the P2P layer.

const std = @import("std");
const Allocator = std.mem.Allocator;

const discv5 = @import("discv5");
const Protocol = discv5.protocol.Protocol;
const Enr = discv5.enr.Enr;
const RoutingTable = discv5.kbucket.RoutingTable;
const NodeId = discv5.enr.NodeId;
const bootnodes = @import("bootnodes.zig");
const BootnodeInfo = bootnodes.BootnodeInfo;

/// Configuration for the discovery service.
pub const DiscoveryConfig = struct {
    listen_port: u16 = 9000,
    bootnode_enrs: []const BootnodeInfo = &bootnodes.mainnet,
    target_peers: u32 = 50,
    lookup_interval_ms: u64 = 30_000,
    local_node_id: NodeId = [_]u8{0} ** 32,
};

/// A peer discovered via discv5.
pub const DiscoveredPeer = struct {
    node_id: [32]u8,
    ip: [4]u8,
    port: u16,
    pubkey: [33]u8,
};

/// Discovery service wrapping a discv5 Protocol instance.
pub const DiscoveryService = struct {
    allocator: Allocator,
    config: DiscoveryConfig,
    protocol: Protocol,

    pub fn init(allocator: Allocator, config: DiscoveryConfig) !DiscoveryService {
        return .{
            .allocator = allocator,
            .config = config,
            .protocol = try Protocol.init(allocator, .{
                .local_node_id = config.local_node_id,
                .local_secret_key = [_]u8{0} ** 32,
                .listen_addr = .{ .ip = [4]u8{ 0, 0, 0, 0 }, .port = config.listen_port },
            }),
        };
    }

    pub fn deinit(self: *DiscoveryService) void {
        self.protocol.deinit();
    }

    /// Seed the routing table with configured bootnodes.
    pub fn seedBootnodes(self: *DiscoveryService) void {
        for (self.config.bootnode_enrs) |bn| {
            const enr_data = if (std.mem.startsWith(u8, bn.enr, "enr:-"))
                bn.enr[5..]
            else if (std.mem.startsWith(u8, bn.enr, "enr:"))
                bn.enr[4..]
            else
                bn.enr;

            const decoded_len = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(enr_data) catch continue;
            const buf = self.allocator.alloc(u8, decoded_len) catch continue;
            defer self.allocator.free(buf);
            std.base64.url_safe_no_pad.Decoder.decode(buf, enr_data) catch continue;

            var parsed = discv5.enr.decode(self.allocator, buf) catch continue;
            defer parsed.deinit();

            if (parsed.pubkey) |pk| {
                const node_id = discv5.enr.nodeIdFromCompressedPubkey(&pk);
                self.protocol.routing_table.insert(.{
                    .node_id = node_id,
                    .addr = [_]u8{0} ** 6,
                    .last_seen = 0,
                    .status = .connected,
                });
            }
        }
    }

    pub fn knownPeerCount(self: *const DiscoveryService) usize {
        return self.protocol.routing_table.totalNodes();
    }
};

test "DiscoveryService: init and deinit" {
    var svc = try DiscoveryService.init(std.testing.allocator, .{});
    defer svc.deinit();
}

test "DiscoveryService: seedBootnodes runs without crash" {
    var svc = try DiscoveryService.init(std.testing.allocator, .{});
    defer svc.deinit();
    svc.seedBootnodes();
}

test "DiscoveredPeer struct layout" {
    const peer = DiscoveredPeer{
        .node_id = [_]u8{0xAA} ** 32,
        .ip = .{ 1, 2, 3, 4 },
        .port = 9000,
        .pubkey = [_]u8{0xBB} ** 33,
    };
    try std.testing.expectEqual(@as(u16, 9000), peer.port);
}
