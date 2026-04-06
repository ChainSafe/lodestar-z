//! Execution layer client interface.
//!
//! Provides the Engine API types, vtable-based client interface, JSON-RPC
//! encoding, and a mock engine for testing/DST. This module handles all
//! communication between the consensus layer and execution layer clients.

const std = @import("std");
const testing = std.testing;

pub const engine_api_types = @import("engine_api_types.zig");
pub const engine_api = @import("engine_api.zig");
pub const json_rpc = @import("json_rpc.zig");
pub const mock_engine = @import("mock_engine.zig");
pub const http_engine = @import("http_engine.zig");
pub const payload_id_cache = @import("payload_id_cache.zig");
pub const builder = @import("builder.zig");

// Re-export primary types for convenience.
pub const EngineApi = engine_api.EngineApi;
pub const HttpEngine = http_engine.HttpEngine;
pub const Transport = http_engine.Transport;
pub const Header = http_engine.Header;
pub const IoHttpTransport = http_engine.IoHttpTransport;
pub const PayloadIdCache = payload_id_cache.PayloadIdCache;
pub const EngineState = http_engine.EngineState;
pub const RetryConfig = http_engine.RetryConfig;
pub const ClientVersion = http_engine.ClientVersion;
pub const TransitionConfiguration = http_engine.TransitionConfiguration;
pub const BuilderApi = builder.BuilderApi;
pub const HttpBuilder = builder.HttpBuilder;
pub const BuilderStatus = builder.BuilderStatus;

pub const ExecutionPayloadStatus = engine_api_types.ExecutionPayloadStatus;
pub const PayloadStatusV1 = engine_api_types.PayloadStatusV1;
pub const ForkchoiceStateV1 = engine_api_types.ForkchoiceStateV1;
pub const PayloadAttributesV3 = engine_api_types.PayloadAttributesV3;
pub const ForkchoiceUpdatedResponse = engine_api_types.ForkchoiceUpdatedResponse;
pub const ExecutionPayloadV3 = engine_api_types.ExecutionPayloadV3;
pub const GetPayloadResponse = engine_api_types.GetPayloadResponse;

test {
    testing.refAllDecls(engine_api_types);
    testing.refAllDecls(engine_api);
    testing.refAllDecls(json_rpc);
    testing.refAllDecls(mock_engine);
    testing.refAllDecls(http_engine);
    testing.refAllDecls(payload_id_cache);
    testing.refAllDecls(builder);
}
