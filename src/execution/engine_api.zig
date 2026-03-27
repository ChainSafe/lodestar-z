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

pub const ExecutionPayloadV1 = types.ExecutionPayloadV1;
pub const ExecutionPayloadV2 = types.ExecutionPayloadV2;
pub const ExecutionPayloadV3 = types.ExecutionPayloadV3;
pub const ExecutionPayloadV4 = types.ExecutionPayloadV4;
pub const PayloadStatusV1 = types.PayloadStatusV1;
pub const ForkchoiceStateV1 = types.ForkchoiceStateV1;
pub const PayloadAttributesV1 = types.PayloadAttributesV1;
pub const PayloadAttributesV2 = types.PayloadAttributesV2;
pub const PayloadAttributesV3 = types.PayloadAttributesV3;
pub const ForkchoiceUpdatedResponse = types.ForkchoiceUpdatedResponse;
pub const GetPayloadResponseV1 = types.GetPayloadResponseV1;
pub const GetPayloadResponseV2 = types.GetPayloadResponseV2;
pub const GetPayloadResponse = types.GetPayloadResponse;
pub const GetPayloadResponseV4 = types.GetPayloadResponseV4;

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
        // ── newPayload variants ───────────────────────────────────────────────
        /// engine_newPayloadV1 (Bellatrix): validate a V1 execution payload.
        newPayloadV1: *const fn (
            ptr: *anyopaque,
            payload: ExecutionPayloadV1,
        ) anyerror!PayloadStatusV1,

        /// engine_newPayloadV2 (Capella): validate a V2 execution payload.
        newPayloadV2: *const fn (
            ptr: *anyopaque,
            payload: ExecutionPayloadV2,
        ) anyerror!PayloadStatusV1,

        /// engine_newPayloadV3 (Deneb): validate an execution payload with blob fields.
        newPayloadV3: *const fn (
            ptr: *anyopaque,
            payload: ExecutionPayloadV3,
            versioned_hashes: []const [32]u8,
            parent_beacon_root: [32]u8,
        ) anyerror!PayloadStatusV1,

        /// engine_newPayloadV4 (Electra): validate a V4 execution payload.
        newPayloadV4: *const fn (
            ptr: *anyopaque,
            payload: ExecutionPayloadV4,
            versioned_hashes: []const [32]u8,
            parent_beacon_root: [32]u8,
        ) anyerror!PayloadStatusV1,

        // ── forkchoiceUpdated variants ────────────────────────────────────────
        /// engine_forkchoiceUpdatedV1 (Bellatrix).
        forkchoiceUpdatedV1: *const fn (
            ptr: *anyopaque,
            state: ForkchoiceStateV1,
            attrs: ?PayloadAttributesV1,
        ) anyerror!ForkchoiceUpdatedResponse,

        /// engine_forkchoiceUpdatedV2 (Capella).
        forkchoiceUpdatedV2: *const fn (
            ptr: *anyopaque,
            state: ForkchoiceStateV1,
            attrs: ?PayloadAttributesV2,
        ) anyerror!ForkchoiceUpdatedResponse,

        /// engine_forkchoiceUpdatedV3 (Deneb).
        forkchoiceUpdatedV3: *const fn (
            ptr: *anyopaque,
            state: ForkchoiceStateV1,
            attrs: ?PayloadAttributesV3,
        ) anyerror!ForkchoiceUpdatedResponse,

        // ── getPayload variants ───────────────────────────────────────────────
        /// engine_getPayloadV1 (Bellatrix).
        getPayloadV1: *const fn (
            ptr: *anyopaque,
            payload_id: [8]u8,
        ) anyerror!GetPayloadResponseV1,

        /// engine_getPayloadV2 (Capella).
        getPayloadV2: *const fn (
            ptr: *anyopaque,
            payload_id: [8]u8,
        ) anyerror!GetPayloadResponseV2,

        /// engine_getPayloadV3 (Deneb): retrieve a built payload.
        getPayloadV3: *const fn (
            ptr: *anyopaque,
            payload_id: [8]u8,
        ) anyerror!GetPayloadResponse,

        /// engine_getPayloadV4 (Electra).
        getPayloadV4: *const fn (
            ptr: *anyopaque,
            payload_id: [8]u8,
        ) anyerror!GetPayloadResponseV4,
    };

    // ── newPayload wrappers ───────────────────────────────────────────────────

    /// Submit a Bellatrix execution payload for validation.
    pub fn newPayloadV1(
        self: EngineApi,
        payload: ExecutionPayloadV1,
    ) !PayloadStatusV1 {
        return self.vtable.newPayloadV1(self.ptr, payload);
    }

    /// Submit a Capella execution payload for validation.
    pub fn newPayloadV2(
        self: EngineApi,
        payload: ExecutionPayloadV2,
    ) !PayloadStatusV1 {
        return self.vtable.newPayloadV2(self.ptr, payload);
    }

    /// Submit a new execution payload for validation (Deneb, V3).
    pub fn newPayload(
        self: EngineApi,
        payload: ExecutionPayloadV3,
        versioned_hashes: []const [32]u8,
        parent_beacon_root: [32]u8,
    ) !PayloadStatusV1 {
        return self.vtable.newPayloadV3(self.ptr, payload, versioned_hashes, parent_beacon_root);
    }

    /// Submit an Electra execution payload for validation (V4).
    pub fn newPayloadV4(
        self: EngineApi,
        payload: ExecutionPayloadV4,
        versioned_hashes: []const [32]u8,
        parent_beacon_root: [32]u8,
    ) !PayloadStatusV1 {
        return self.vtable.newPayloadV4(self.ptr, payload, versioned_hashes, parent_beacon_root);
    }

    // ── forkchoiceUpdated wrappers ────────────────────────────────────────────

    /// Notify the EL of the current fork choice (V1, Bellatrix).
    pub fn forkchoiceUpdatedV1(
        self: EngineApi,
        state: ForkchoiceStateV1,
        attrs: ?PayloadAttributesV1,
    ) !ForkchoiceUpdatedResponse {
        return self.vtable.forkchoiceUpdatedV1(self.ptr, state, attrs);
    }

    /// Notify the EL of the current fork choice (V2, Capella).
    pub fn forkchoiceUpdatedV2(
        self: EngineApi,
        state: ForkchoiceStateV1,
        attrs: ?PayloadAttributesV2,
    ) !ForkchoiceUpdatedResponse {
        return self.vtable.forkchoiceUpdatedV2(self.ptr, state, attrs);
    }

    /// Notify the EL of the current fork choice and optionally begin payload building (V3, Deneb).
    pub fn forkchoiceUpdated(
        self: EngineApi,
        state: ForkchoiceStateV1,
        attrs: ?PayloadAttributesV3,
    ) !ForkchoiceUpdatedResponse {
        return self.vtable.forkchoiceUpdatedV3(self.ptr, state, attrs);
    }

    // ── getPayload wrappers ───────────────────────────────────────────────────

    /// Retrieve a Bellatrix payload by ID.
    pub fn getPayloadV1(
        self: EngineApi,
        payload_id: [8]u8,
    ) !GetPayloadResponseV1 {
        return self.vtable.getPayloadV1(self.ptr, payload_id);
    }

    /// Retrieve a Capella payload by ID.
    pub fn getPayloadV2(
        self: EngineApi,
        payload_id: [8]u8,
    ) !GetPayloadResponseV2 {
        return self.vtable.getPayloadV2(self.ptr, payload_id);
    }

    /// Retrieve a previously requested payload by its identifier (Deneb, V3).
    pub fn getPayload(
        self: EngineApi,
        payload_id: [8]u8,
    ) !GetPayloadResponse {
        return self.vtable.getPayloadV3(self.ptr, payload_id);
    }

    /// Retrieve an Electra payload by ID (V4).
    pub fn getPayloadV4(
        self: EngineApi,
        payload_id: [8]u8,
    ) !GetPayloadResponseV4 {
        return self.vtable.getPayloadV4(self.ptr, payload_id);
    }
};

// ── Tests ────────────────────────────────────────────────────────────────────

test "EngineApi vtable struct layout" {
    // Verify vtable has all required function pointers.
    const info = @typeInfo(EngineApi.VTable);
    try testing.expectEqual(@as(usize, 11), info.@"struct".fields.len);
}

test "EngineApi methods exist" {
    // Verify the public API surface by checking method existence.
    try testing.expect(@hasDecl(EngineApi, "newPayload"));
    try testing.expect(@hasDecl(EngineApi, "newPayloadV1"));
    try testing.expect(@hasDecl(EngineApi, "newPayloadV2"));
    try testing.expect(@hasDecl(EngineApi, "newPayloadV4"));
    try testing.expect(@hasDecl(EngineApi, "forkchoiceUpdated"));
    try testing.expect(@hasDecl(EngineApi, "forkchoiceUpdatedV1"));
    try testing.expect(@hasDecl(EngineApi, "forkchoiceUpdatedV2"));
    try testing.expect(@hasDecl(EngineApi, "getPayload"));
    try testing.expect(@hasDecl(EngineApi, "getPayloadV1"));
    try testing.expect(@hasDecl(EngineApi, "getPayloadV2"));
    try testing.expect(@hasDecl(EngineApi, "getPayloadV4"));
}
