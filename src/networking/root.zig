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
pub const gossip_topics = @import("gossip_topics.zig");
pub const gossip_validation = @import("gossip_validation.zig");
pub const gossip_decoding = @import("gossip_decoding.zig");

// Re-export key types for convenience.
pub const ResponseCode = protocol.ResponseCode;
pub const Method = protocol.Method;
pub const Encoding = protocol.Encoding;

pub const encodeRequest = req_resp_encoding.encodeRequest;
pub const decodeRequest = req_resp_encoding.decodeRequest;
pub const encodeResponseChunk = req_resp_encoding.encodeResponseChunk;
pub const decodeResponseChunk = req_resp_encoding.decodeResponseChunk;

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

test {
    testing.refAllDecls(@This());
}
