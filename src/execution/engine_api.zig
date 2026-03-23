//! Engine API client interface.
//!
//! Provides a vtable-based polymorphic interface for communicating with
//! execution layer clients via the Engine API. Concrete implementations
//! include the HTTP JSON-RPC client and the mock engine for testing.
//!
//! Uses the idiomatic Zig pattern: a thin wrapper holding an erased pointer
//! and a const vtable, allowing callers to program against the interface
//! without knowing the concrete backend.

const std = @import("std");
const testing = std.testing;

const types = @import("engine_api_types.zig");

pub const ExecutionPayloadV3 = types.ExecutionPayloadV3;
pub const PayloadStatusV1 = types.PayloadStatusV1;
pub const ForkchoiceStateV1 = types.ForkchoiceStateV1;
pub const PayloadAttributesV3 = types.PayloadAttributesV3;
pub const ForkchoiceUpdatedResponse = types.ForkchoiceUpdatedResponse;
pub const GetPayloadResponse = types.GetPayloadResponse;

/// Polymorphic Engine API interface.
///
/// Wraps a concrete implementation behind a vtable so callers can use
/// any engine backend (HTTP, mock, etc.) through a uniform API.
pub const EngineApi = struct {
    /// Erased pointer to the concrete implementation.
    ptr: *anyopaque,
    /// Pointer to the implementation's vtable.
    vtable: *const VTable,

    pub const VTable = struct {
        /// engine_newPayloadV3: validate an execution payload.
        newPayloadV3: *const fn (
            ptr: *anyopaque,
            payload: ExecutionPayloadV3,
            versioned_hashes: []const [32]u8,
            parent_beacon_root: [32]u8,
        ) anyerror!PayloadStatusV1,

        /// engine_forkchoiceUpdatedV3: update fork choice and optionally start building.
        forkchoiceUpdatedV3: *const fn (
            ptr: *anyopaque,
            state: ForkchoiceStateV1,
            attrs: ?PayloadAttributesV3,
        ) anyerror!ForkchoiceUpdatedResponse,

        /// engine_getPayloadV3: retrieve a built payload.
        getPayloadV3: *const fn (
            ptr: *anyopaque,
            payload_id: [8]u8,
        ) anyerror!GetPayloadResponse,
    };

    /// Submit a new execution payload for validation.
    pub fn newPayload(
        self: EngineApi,
        payload: ExecutionPayloadV3,
        versioned_hashes: []const [32]u8,
        parent_beacon_root: [32]u8,
    ) !PayloadStatusV1 {
        return self.vtable.newPayloadV3(self.ptr, payload, versioned_hashes, parent_beacon_root);
    }

    /// Notify the EL of the current fork choice and optionally begin payload building.
    pub fn forkchoiceUpdated(
        self: EngineApi,
        state: ForkchoiceStateV1,
        attrs: ?PayloadAttributesV3,
    ) !ForkchoiceUpdatedResponse {
        return self.vtable.forkchoiceUpdatedV3(self.ptr, state, attrs);
    }

    /// Retrieve a previously requested payload by its identifier.
    pub fn getPayload(
        self: EngineApi,
        payload_id: [8]u8,
    ) !GetPayloadResponse {
        return self.vtable.getPayloadV3(self.ptr, payload_id);
    }
};

// ── Tests ────────────────────────────────────────────────────────────────────

test "EngineApi vtable struct layout" {
    // Verify vtable has all required function pointers.
    const info = @typeInfo(EngineApi.VTable);
    try testing.expectEqual(@as(usize, 3), info.@"struct".fields.len);
}

test "EngineApi methods exist" {
    // Verify the public API surface by checking method existence.
    try testing.expect(@hasDecl(EngineApi, "newPayload"));
    try testing.expect(@hasDecl(EngineApi, "forkchoiceUpdated"));
    try testing.expect(@hasDecl(EngineApi, "getPayload"));
}
