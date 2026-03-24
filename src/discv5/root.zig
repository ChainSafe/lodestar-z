//! Discovery v5 protocol implementation
//!
//! This module implements the Ethereum Node Discovery Protocol v5 (discv5)
//! as specified in https://github.com/ethereum/devp2p/tree/master/discv5

pub const enr = @import("enr.zig");
pub const rlp = @import("rlp.zig");
pub const packet = @import("packet.zig");
pub const session = @import("session.zig");
pub const messages = @import("messages.zig");
pub const kbucket = @import("kbucket.zig");
pub const protocol = @import("protocol.zig");
pub const transport = @import("transport.zig");
pub const hex = @import("hex.zig");
pub const secp256k1 = @import("secp256k1.zig");

// Re-export common types
pub const NodeId = enr.NodeId;
pub const Enr = enr.Enr;
pub const RoutingTable = kbucket.RoutingTable;
pub const Protocol = protocol.Protocol;
pub const Transport = transport.Transport;
pub const MockTransport = transport.MockTransport;

// Include wire test vectors
test {
    _ = @import("wire_test_vectors.zig");
    _ = @import("enr.zig");
    _ = @import("rlp.zig");
    _ = @import("packet.zig");
    _ = @import("session.zig");
    _ = @import("messages.zig");
    _ = @import("kbucket.zig");
    _ = @import("protocol.zig");
    _ = @import("transport.zig");
}
