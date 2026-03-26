//! Networking module for the Ethereum consensus P2P protocol.
//!
//! Provides wire encoding/decoding for req/resp messages using SSZ-Snappy,
//! protocol definitions, message types, varint utilities, gossip topic parsing,
//! gossip message validation, and gossip message decoding.

const std = @import("std");
const testing = std.testing;

pub const varint = @import("varint.zig");
pub const protocol = @import("protocol.zig");
pub const messages = @import("messages.zig");
pub const req_resp_encoding = @import("req_resp_encoding.zig");
pub const req_resp_handler = @import("req_resp_handler.zig");
pub const gossip_topics = @import("gossip_topics.zig");
pub const gossip_validation = @import("gossip_validation.zig");
pub const gossip_decoding = @import("gossip_decoding.zig");
pub const eth_gossip = @import("eth_gossip.zig");
pub const eth_reqresp = @import("eth_reqresp.zig");

// Re-export key types for convenience.
pub const ResponseCode = protocol.ResponseCode;
pub const Method = protocol.Method;
pub const Encoding = protocol.Encoding;

pub const encodeRequest = req_resp_encoding.encodeRequest;
pub const parseProtocolId = protocol.parseProtocolId;
pub const formatProtocolId = protocol.formatProtocolId;
pub const decodeRequest = req_resp_encoding.decodeRequest;
pub const encodeResponseChunk = req_resp_encoding.encodeResponseChunk;
pub const decodeResponseChunk = req_resp_encoding.decodeResponseChunk;

// Req/resp handler re-exports.
pub const ReqRespContext = req_resp_handler.ReqRespContext;
pub const ResponseChunk = req_resp_handler.ResponseChunk;
pub const handleRequest = req_resp_handler.handleRequest;
pub const freeResponseChunks = req_resp_handler.freeResponseChunks;

// Gossip re-exports.
pub const GossipTopic = gossip_topics.GossipTopic;
pub const GossipTopicType = gossip_topics.GossipTopicType;
pub const parseTopic = gossip_topics.parseTopic;
pub const formatTopic = gossip_topics.formatTopic;

pub const ValidationResult = gossip_validation.ValidationResult;
pub const GossipValidationContext = gossip_validation.GossipValidationContext;
pub const SeenSet = gossip_validation.SeenSet;

pub const DecodeError = gossip_decoding.DecodeError;
pub const DecodedGossipMessage = gossip_decoding.DecodedGossipMessage;
pub const decodeGossipMessage = gossip_decoding.decodeGossipMessage;

// eth-p2p-z adapter re-exports.
pub const EthGossipAdapter = eth_gossip.EthGossipAdapter;
pub const EthReqRespAdapter = eth_reqresp.EthReqRespAdapter;

// eth-p2p-z integration layer.
pub const eth2_protocols = @import("eth2_protocols.zig");
pub const p2p_service = @import("p2p_service.zig");
pub const P2pService = p2p_service.P2pService;
pub const QuicStream = p2p_service.QuicStream;
pub const P2pConfig = p2p_service.P2pConfig;

// Discovery.
pub const bootnodes = @import("bootnodes.zig");
pub const discovery_service = @import("discovery_service.zig");
pub const DiscoveryService = discovery_service.DiscoveryService;
pub const DiscoveryConfig = discovery_service.DiscoveryConfig;
pub const DiscoveredPeer = discovery_service.DiscoveredPeer;

test {
    testing.refAllDecls(@This());
}

pub const peer_scoring = @import("peer_scoring.zig");
pub const PeerScorer = peer_scoring.PeerScorer;

pub const gossip_context = @import("gossip_context.zig");
pub const NodeGossipContext = gossip_context.NodeGossipContext;
pub const GossipCallbacks = gossip_context.GossipCallbacks;

pub const connection_manager = @import("connection_manager.zig");
pub const ConnectionManager = connection_manager.ConnectionManager;
pub const ConnectionManagerConfig = connection_manager.ConnectionManagerConfig;
pub const ConnectionState = connection_manager.ConnectionState;
pub const ConnectionDirection = connection_manager.ConnectionDirection;
