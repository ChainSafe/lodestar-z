//! Discovery v5 protocol implementation
//!
//! This module implements the Ethereum Node Discovery Protocol v5 (discv5)
//! as specified in https://github.com/ethereum/devp2p/tree/master/discv5

const std = @import("std");
const net = std.Io.net;

pub const enr = @import("enr.zig");
pub const rlp = @import("rlp.zig");
pub const packet = @import("protocol/packet.zig");
pub const session = @import("protocol/session.zig");
pub const message = @import("protocol/message.zig");
pub const messages = message;
pub const kbucket = @import("kbucket.zig");
pub const protocol = @import("protocol.zig");
pub const service = @import("service.zig");
pub const runtime = @import("runtime.zig");
pub const rate_limit = @import("rate_limit.zig");
pub const metrics = @import("metrics.zig");
pub const lru = @import("lru.zig");
pub const hex = @import("hex");
pub const secp256k1 = @import("secp256k1.zig");

// Re-export common types
pub const NodeId = enr.NodeId;
pub const Enr = enr.Enr;
pub const RoutingTable = kbucket.RoutingTable;
pub const Protocol = protocol.Protocol;
pub const Service = service.Service;
pub const RuntimeService = runtime.RuntimeService;
pub const Event = service.Event;
pub const EventKind = service.EventKind;
pub const BindAddresses = service.BindAddresses;
pub const Address = net.IpAddress;
pub const UdpSocket = net.Socket;

// Include wire test vectors
test {
    _ = @import("wire_test_vectors.zig");
    _ = @import("enr.zig");
    _ = @import("rlp.zig");
    _ = @import("protocol/packet.zig");
    _ = @import("protocol/session.zig");
    _ = @import("protocol/message.zig");
    _ = @import("kbucket.zig");
    _ = @import("protocol.zig");
    _ = @import("protocol/handshake.zig");
    _ = @import("protocol/contact_book.zig");
    _ = @import("protocol/events.zig");
    _ = @import("protocol/request_tracker.zig");
    _ = @import("protocol/state.zig");
    _ = @import("service.zig");
    _ = @import("service/addr_votes.zig");
    _ = @import("service/events.zig");
    _ = @import("service/ingress_queue.zig");
    _ = @import("service/lookup.zig");
    _ = @import("runtime.zig");
    _ = @import("rate_limit.zig");
    _ = @import("metrics.zig");
    _ = @import("lru.zig");
    _ = @import("event_queue.zig");
}
