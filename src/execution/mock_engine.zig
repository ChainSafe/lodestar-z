//! Mock execution engine for testing and deterministic simulation testing (DST).
//!
//! Implements the EngineApi vtable with configurable responses, allowing
//! beacon chain tests to exercise the CL↔EL interface without a real
//! execution client.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;

const engine_api = @import("engine_api.zig");
const types = @import("engine_api_types.zig");

const EngineApi = engine_api.EngineApi;
const ExecutionPayloadV3 = types.ExecutionPayloadV3;
const ExecutionPayloadStatus = types.ExecutionPayloadStatus;
const PayloadStatusV1 = types.PayloadStatusV1;
const ForkchoiceStateV1 = types.ForkchoiceStateV1;
const PayloadAttributesV3 = types.PayloadAttributesV3;
const ForkchoiceUpdatedResponse = types.ForkchoiceUpdatedResponse;
const GetPayloadResponse = types.GetPayloadResponse;
const BlobsBundle = types.BlobsBundle;

pub const MockEngine = struct {
    allocator: Allocator,

    /// Default status returned by newPayload. Override per-hash via `status_overrides`.
    default_status: ExecutionPayloadStatus = .valid,

    /// Per-block-hash status overrides for newPayload responses.
    status_overrides: std.AutoHashMap([32]u8, ExecutionPayloadStatus),

    /// Stored payloads keyed by block hash, populated by newPayload calls.
    payloads: std.AutoHashMap([32]u8, StoredPayload),

    /// Built payloads keyed by payload_id, populated by forkchoiceUpdated with attributes.
    built_payloads: std.AutoHashMap([8]u8, StoredPayload),

    /// Last forkchoice state received.
    last_forkchoice_state: ?ForkchoiceStateV1 = null,

    /// Monotonically increasing payload ID counter.
    next_payload_id: u64 = 0,

    /// Internal storage for a payload and its metadata.
    const StoredPayload = struct {
        payload: ExecutionPayloadV3,
        block_value: u256 = 0,
    };

    pub fn init(allocator: Allocator) MockEngine {
        return .{
            .allocator = allocator,
            .status_overrides = std.AutoHashMap([32]u8, ExecutionPayloadStatus).init(allocator),
            .payloads = std.AutoHashMap([32]u8, StoredPayload).init(allocator),
            .built_payloads = std.AutoHashMap([8]u8, StoredPayload).init(allocator),
        };
    }

    pub fn deinit(self: *MockEngine) void {
        self.status_overrides.deinit();
        self.payloads.deinit();
        self.built_payloads.deinit();
    }

    /// Return an EngineApi interface backed by this mock.
    pub fn engine(self: *MockEngine) EngineApi {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    /// Set a per-hash status override for newPayload responses.
    pub fn setPayloadStatus(self: *MockEngine, block_hash: [32]u8, status: ExecutionPayloadStatus) !void {
        try self.status_overrides.put(block_hash, status);
    }

    // ── vtable ───────────────────────────────────────────────────────────────

    const vtable = EngineApi.VTable{
        .newPayloadV3 = @ptrCast(&newPayloadV3),
        .forkchoiceUpdatedV3 = @ptrCast(&forkchoiceUpdatedV3),
        .getPayloadV3 = @ptrCast(&getPayloadV3),
    };

    fn newPayloadV3(
        self: *MockEngine,
        payload: ExecutionPayloadV3,
        _: []const [32]u8,
        _: [32]u8,
    ) anyerror!PayloadStatusV1 {
        // Store the payload.
        try self.payloads.put(payload.block_hash, .{ .payload = payload });

        // Check for per-hash override, otherwise use default.
        const status = self.status_overrides.get(payload.block_hash) orelse self.default_status;

        return PayloadStatusV1{
            .status = status,
            .latest_valid_hash = if (status == .valid) payload.block_hash else null,
        };
    }

    fn forkchoiceUpdatedV3(
        self: *MockEngine,
        state: ForkchoiceStateV1,
        attrs: ?PayloadAttributesV3,
    ) anyerror!ForkchoiceUpdatedResponse {
        self.last_forkchoice_state = state;

        // If payload attributes are provided, start "building" a payload.
        var payload_id: ?[8]u8 = null;
        if (attrs != null) {
            var id_bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &id_bytes, self.next_payload_id, .little);
            self.next_payload_id += 1;

            // Create a minimal built payload from the forkchoice head.
            const stored = self.payloads.get(state.head_block_hash);
            if (stored) |s| {
                try self.built_payloads.put(id_bytes, s);
            } else {
                // No existing payload — store a stub keyed by the head hash.
                const stub = ExecutionPayloadV3{
                    .parent_hash = state.head_block_hash,
                    .fee_recipient = std.mem.zeroes([20]u8),
                    .state_root = std.mem.zeroes([32]u8),
                    .receipts_root = std.mem.zeroes([32]u8),
                    .logs_bloom = std.mem.zeroes([256]u8),
                    .prev_randao = if (attrs) |a| a.prev_randao else std.mem.zeroes([32]u8),
                    .block_number = 0,
                    .gas_limit = 30_000_000,
                    .gas_used = 0,
                    .timestamp = if (attrs) |a| a.timestamp else 0,
                    .extra_data = &.{},
                    .base_fee_per_gas = 0,
                    .block_hash = std.mem.zeroes([32]u8),
                    .transactions = &.{},
                    .withdrawals = if (attrs) |a| a.withdrawals else &.{},
                    .blob_gas_used = 0,
                    .excess_blob_gas = 0,
                };
                try self.built_payloads.put(id_bytes, .{ .payload = stub });
            }
            payload_id = id_bytes;
        }

        // Determine status: valid if head is known, syncing otherwise.
        const status: ExecutionPayloadStatus = if (self.payloads.contains(state.head_block_hash))
            .valid
        else
            .syncing;

        return ForkchoiceUpdatedResponse{
            .payload_status = .{
                .status = status,
                .latest_valid_hash = if (status == .valid) state.head_block_hash else null,
            },
            .payload_id = payload_id,
        };
    }

    fn getPayloadV3(
        self: *MockEngine,
        payload_id: [8]u8,
    ) anyerror!GetPayloadResponse {
        const stored = self.built_payloads.get(payload_id) orelse
            return error.UnknownPayload;

        return GetPayloadResponse{
            .execution_payload = stored.payload,
            .block_value = stored.block_value,
            .blobs_bundle = .{
                .commitments = &.{},
                .proofs = &.{},
                .blobs = &.{},
            },
            .should_override_builder = false,
        };
    }
};

// ── Tests ────────────────────────────────────────────────────────────────────

test "MockEngine: newPayload returns valid by default" {
    var mock = MockEngine.init(testing.allocator);
    defer mock.deinit();

    const api = mock.engine();
    const payload = makeTestPayload([_]u8{0x01} ** 32);

    const result = try api.newPayload(payload, &.{}, std.mem.zeroes([32]u8));
    try testing.expectEqual(ExecutionPayloadStatus.valid, result.status);
    try testing.expect(result.latest_valid_hash != null);
    try testing.expectEqual([_]u8{0x01} ** 32, result.latest_valid_hash.?);
}

test "MockEngine: newPayload with status override" {
    var mock = MockEngine.init(testing.allocator);
    defer mock.deinit();

    const block_hash = [_]u8{0x02} ** 32;
    try mock.setPayloadStatus(block_hash, .invalid);

    const api = mock.engine();
    const payload = makeTestPayload(block_hash);

    const result = try api.newPayload(payload, &.{}, std.mem.zeroes([32]u8));
    try testing.expectEqual(ExecutionPayloadStatus.invalid, result.status);
    try testing.expect(result.latest_valid_hash == null);
}

test "MockEngine: forkchoiceUpdated without attributes" {
    var mock = MockEngine.init(testing.allocator);
    defer mock.deinit();

    // Submit a payload first so the head is known.
    const api = mock.engine();
    const block_hash = [_]u8{0x03} ** 32;
    _ = try api.newPayload(makeTestPayload(block_hash), &.{}, std.mem.zeroes([32]u8));

    const fcu = try api.forkchoiceUpdated(.{
        .head_block_hash = block_hash,
        .safe_block_hash = block_hash,
        .finalized_block_hash = block_hash,
    }, null);

    try testing.expectEqual(ExecutionPayloadStatus.valid, fcu.payload_status.status);
    try testing.expect(fcu.payload_id == null);
    try testing.expect(mock.last_forkchoice_state != null);
}

test "MockEngine: forkchoiceUpdated with attributes returns payload_id" {
    var mock = MockEngine.init(testing.allocator);
    defer mock.deinit();

    const api = mock.engine();
    const block_hash = [_]u8{0x04} ** 32;
    _ = try api.newPayload(makeTestPayload(block_hash), &.{}, std.mem.zeroes([32]u8));

    const fcu = try api.forkchoiceUpdated(.{
        .head_block_hash = block_hash,
        .safe_block_hash = block_hash,
        .finalized_block_hash = block_hash,
    }, .{
        .timestamp = 1_000_000,
        .prev_randao = [_]u8{0xbb} ** 32,
        .suggested_fee_recipient = [_]u8{0xcc} ** 20,
        .withdrawals = &.{},
        .parent_beacon_block_root = [_]u8{0xdd} ** 32,
    });

    try testing.expectEqual(ExecutionPayloadStatus.valid, fcu.payload_status.status);
    try testing.expect(fcu.payload_id != null);
}

test "MockEngine: getPayload returns built payload" {
    var mock = MockEngine.init(testing.allocator);
    defer mock.deinit();

    const api = mock.engine();
    const block_hash = [_]u8{0x05} ** 32;
    _ = try api.newPayload(makeTestPayload(block_hash), &.{}, std.mem.zeroes([32]u8));

    const fcu = try api.forkchoiceUpdated(.{
        .head_block_hash = block_hash,
        .safe_block_hash = block_hash,
        .finalized_block_hash = block_hash,
    }, .{
        .timestamp = 2_000_000,
        .prev_randao = [_]u8{0xee} ** 32,
        .suggested_fee_recipient = [_]u8{0xff} ** 20,
        .withdrawals = &.{},
        .parent_beacon_block_root = std.mem.zeroes([32]u8),
    });

    const payload_id = fcu.payload_id.?;
    const resp = try api.getPayload(payload_id);
    try testing.expectEqual(block_hash, resp.execution_payload.block_hash);
    try testing.expect(!resp.should_override_builder);
}

test "MockEngine: getPayload with unknown id returns error" {
    var mock = MockEngine.init(testing.allocator);
    defer mock.deinit();

    const api = mock.engine();
    const result = api.getPayload([_]u8{0xff} ** 8);
    try testing.expectError(error.UnknownPayload, result);
}

test "MockEngine: forkchoiceUpdated with unknown head returns syncing" {
    var mock = MockEngine.init(testing.allocator);
    defer mock.deinit();

    const api = mock.engine();
    const fcu = try api.forkchoiceUpdated(.{
        .head_block_hash = [_]u8{0xab} ** 32,
        .safe_block_hash = [_]u8{0xab} ** 32,
        .finalized_block_hash = [_]u8{0xab} ** 32,
    }, null);

    try testing.expectEqual(ExecutionPayloadStatus.syncing, fcu.payload_status.status);
    try testing.expect(fcu.payload_status.latest_valid_hash == null);
}

/// Create a minimal test payload with the given block hash.
fn makeTestPayload(block_hash: [32]u8) ExecutionPayloadV3 {
    return .{
        .parent_hash = std.mem.zeroes([32]u8),
        .fee_recipient = std.mem.zeroes([20]u8),
        .state_root = std.mem.zeroes([32]u8),
        .receipts_root = std.mem.zeroes([32]u8),
        .logs_bloom = std.mem.zeroes([256]u8),
        .prev_randao = std.mem.zeroes([32]u8),
        .block_number = 1,
        .gas_limit = 30_000_000,
        .gas_used = 21_000,
        .timestamp = 1_700_000_000,
        .extra_data = &.{},
        .base_fee_per_gas = 1_000_000_000,
        .block_hash = block_hash,
        .transactions = &.{},
        .withdrawals = &.{},
        .blob_gas_used = 0,
        .excess_blob_gas = 0,
    };
}
