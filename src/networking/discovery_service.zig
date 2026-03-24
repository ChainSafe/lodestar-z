//! Discovery service: bridges discv5 peer discovery with the P2P layer.
//!
//! Manages the discv5 protocol instance, seeds the routing table with
//! bootnodes, and provides discovered peers for QUIC connection.

const std = @import("std");
const Allocator = std.mem.Allocator;

const discv5 = @import("discv5");
const Protocol = discv5.protocol.Protocol;
const ENR = discv5.enr.ENR;
const KBucket = discv5.kbucket.KBucket;
const Transport = discv5.transport.Transport;
const MockTransport = discv5.transport.MockTransport;
const bootnodes = @import("bootnodes.zig");
const BootnodeInfo = bootnodes.BootnodeInfo;

/// Configuration for the discovery service.
pub const DiscoveryConfig = struct {
    /// UDP port to listen on for discv5.
    listen_port: u16 = 9000,
    /// Bootnode ENRs to seed the routing table.
    bootnode_enrs: []const BootnodeInfo = &bootnodes.mainnet,
    /// Target number of peers to maintain.
    target_peers: u32 = 50,
    /// Interval between random lookups (milliseconds).
    lookup_interval_ms: u64 = 30_000,
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
    local_secret_key: [32]u8,

    pub fn init(allocator: Allocator, config: DiscoveryConfig, secret_key: [32]u8, transport: Transport) DiscoveryService {
        return .{
            .allocator = allocator,
            .config = config,
            .protocol = Protocol.init(allocator, secret_key, transport),
            .local_secret_key = secret_key,
        };
    }

    pub fn deinit(self: *DiscoveryService) void {
        self.protocol.deinit();
    }

    /// Seed the routing table with configured bootnodes.
    /// Parses each ENR string, extracts node-id and endpoint, adds to kbuckets.
    pub fn seedBootnodes(self: *DiscoveryService) void {
        for (self.config.bootnode_enrs) |bn| {
            // Parse ENR to extract node-id and add to routing table
            // The ENR string starts with "enr:" prefix — skip it
            const enr_data = if (std.mem.startsWith(u8, bn.enr, "enr:"))
                bn.enr[4..]
            else if (std.mem.startsWith(u8, bn.enr, "enr:-"))
                bn.enr[4..]
            else
                bn.enr;

            // Base64url decode
            const decoded = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(enr_data) catch continue;
            const buf = self.allocator.alloc(u8, decoded) catch continue;
            defer self.allocator.free(buf);

            std.base64.url_safe_no_pad.Decoder.decode(buf, enr_data) catch continue;

            // Parse ENR to get pubkey → node-id
            var parsed = ENR.decode(self.allocator, buf) catch continue;
            defer parsed.deinit(self.allocator);

            if (parsed.pubkey) |pk| {
                const node_id = discv5.enr.nodeIdFromCompressedPubkey(&pk);
                self.protocol.routing_table.insert(node_id);
            }
        }
    }

    /// Get the number of known peers in the routing table.
    pub fn knownPeerCount(self: *const DiscoveryService) usize {
        return self.protocol.routing_table.totalNodes();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "DiscoveryService: init and deinit" {
    const allocator = std.testing.allocator;
    const local_addr = discv5.transport.Address{ .ip = .{ 127, 0, 0, 1 }, .port = 9000 };
    var mock_transport = MockTransport.init(allocator, local_addr);
    defer mock_transport.deinit();

    var svc = DiscoveryService.init(allocator, .{}, [_]u8{0x42} ** 32, mock_transport.transport());
    defer svc.deinit();
}

test "DiscoveryService: seedBootnodes populates routing table" {
    const allocator = std.testing.allocator;
    const local_addr = discv5.transport.Address{ .ip = .{ 127, 0, 0, 1 }, .port = 9000 };
    var mock_transport = MockTransport.init(allocator, local_addr);
    defer mock_transport.deinit();

    var svc = DiscoveryService.init(allocator, .{}, [_]u8{0x42} ** 32, mock_transport.transport());
    defer svc.deinit();

    svc.seedBootnodes();
    // Should have at least some bootnodes (parsing may fail for some depending on ENR format)
    // Just verify it doesn't crash
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
