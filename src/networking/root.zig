//! Networking module for the Ethereum consensus P2P protocol.
//!
//! Provides wire encoding/decoding for req/resp messages using SSZ-Snappy,
//! protocol definitions, message types, and varint utilities.

const std = @import("std");
const testing = std.testing;

pub const varint = @import("varint.zig");
pub const protocol = @import("protocol.zig");
pub const messages = @import("messages.zig");
pub const req_resp_encoding = @import("req_resp_encoding.zig");

// Re-export key types for convenience.
pub const ResponseCode = protocol.ResponseCode;
pub const Method = protocol.Method;
pub const Encoding = protocol.Encoding;

pub const encodeRequest = req_resp_encoding.encodeRequest;
pub const decodeRequest = req_resp_encoding.decodeRequest;
pub const encodeResponseChunk = req_resp_encoding.encodeResponseChunk;
pub const decodeResponseChunk = req_resp_encoding.decodeResponseChunk;

test {
    testing.refAllDecls(@This());
}
