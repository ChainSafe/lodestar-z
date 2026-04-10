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
const ExecutionPayloadV1 = types.ExecutionPayloadV1;
const ExecutionPayloadV2 = types.ExecutionPayloadV2;
const ExecutionPayloadV3 = types.ExecutionPayloadV3;
const ExecutionPayloadV4 = types.ExecutionPayloadV4;
const ExecutionPayloadStatus = types.ExecutionPayloadStatus;
const PayloadStatusV1 = types.PayloadStatusV1;
const ForkchoiceStateV1 = types.ForkchoiceStateV1;
const PayloadAttributesV1 = types.PayloadAttributesV1;
const PayloadAttributesV2 = types.PayloadAttributesV2;
const PayloadAttributesV3 = types.PayloadAttributesV3;
const ForkchoiceUpdatedResponse = types.ForkchoiceUpdatedResponse;
const GetPayloadResponseV1 = types.GetPayloadResponseV1;
const GetPayloadResponseV2 = types.GetPayloadResponseV2;
const GetPayloadResponse = types.GetPayloadResponse;
const GetPayloadResponseV4 = types.GetPayloadResponseV4;
const BlobsBundle = types.BlobsBundle;

pub const MockEngine = struct {
    allocator: Allocator,

    /// Default status returned by newPayload after parent availability checks.
    default_status: ExecutionPayloadStatus = .valid,

    /// Per-block-hash status overrides for newPayload and forkchoiceUpdated responses.
    status_overrides: std.AutoHashMap([32]u8, ExecutionPayloadStatus),

    /// Known valid blocks keyed by block hash, populated by successful newPayload calls.
    payloads: std.AutoHashMap([32]u8, StoredPayloadV3),

    /// Built payloads keyed by payload_id, populated by forkchoiceUpdated with attributes.
    built_payloads: std.AutoHashMap([8]u8, StoredPayloadV3),

    /// Last forkchoice state received.
    last_forkchoice_state: ?ForkchoiceStateV1 = null,

    /// Monotonically increasing payload ID counter.
    next_payload_id: u64 = 0,

    /// Internal storage for a V3 payload and its metadata.
    const StoredPayloadV3 = struct {
        payload: ExecutionPayloadV3,
        block_value: u256 = 0,
    };

    const BuildAttrs = struct {
        timestamp: u64,
        prev_randao: [32]u8,
        suggested_fee_recipient: [20]u8,
    };

    pub const SeedPayload = struct {
        parent_hash: [32]u8,
        block_hash: [32]u8,
        block_number: u64,
        timestamp: u64,
    };

    pub fn init(allocator: Allocator) MockEngine {
        return .{
            .allocator = allocator,
            .status_overrides = std.AutoHashMap([32]u8, ExecutionPayloadStatus).init(allocator),
            .payloads = std.AutoHashMap([32]u8, StoredPayloadV3).init(allocator),
            .built_payloads = std.AutoHashMap([8]u8, StoredPayloadV3).init(allocator),
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

    /// Seed the mock with a known payload, e.g. a trusted checkpoint execution head.
    pub fn seedPayload(self: *MockEngine, seed: SeedPayload) !void {
        const gop = try self.payloads.getOrPut(seed.block_hash);
        if (gop.found_existing) return;
        gop.value_ptr.* = .{ .payload = .{
            .parent_hash = seed.parent_hash,
            .fee_recipient = std.mem.zeroes([20]u8),
            .state_root = std.mem.zeroes([32]u8),
            .receipts_root = std.mem.zeroes([32]u8),
            .logs_bloom = std.mem.zeroes([256]u8),
            .prev_randao = std.mem.zeroes([32]u8),
            .block_number = seed.block_number,
            .gas_limit = 30_000_000,
            .gas_used = 0,
            .timestamp = seed.timestamp,
            .extra_data = &.{},
            .base_fee_per_gas = 0,
            .block_hash = seed.block_hash,
            .transactions = &.{},
            .withdrawals = &.{},
            .blob_gas_used = 0,
            .excess_blob_gas = 0,
        } };
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn makePayloadId(self: *MockEngine) [8]u8 {
        var id_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &id_bytes, self.next_payload_id, .little);
        self.next_payload_id += 1;
        return id_bytes;
    }

    fn statusForHash(self: *const MockEngine, block_hash: [32]u8) ExecutionPayloadStatus {
        return self.status_overrides.get(block_hash) orelse self.default_status;
    }

    fn newPayloadStatusResponse(
        self: *const MockEngine,
        block_hash: [32]u8,
        status_override: ?ExecutionPayloadStatus,
    ) PayloadStatusV1 {
        const status = status_override orelse self.statusForHash(block_hash);
        return PayloadStatusV1{
            .status = status,
            .latest_valid_hash = if (status == .valid) block_hash else null,
        };
    }

    fn forkchoiceStatusResponse(status: ExecutionPayloadStatus) PayloadStatusV1 {
        return PayloadStatusV1{
            .status = status,
            .latest_valid_hash = null,
        };
    }

    fn knownPayload(self: *const MockEngine, block_hash: [32]u8) ?StoredPayloadV3 {
        if (std.mem.eql(u8, block_hash[0..], &[_]u8{0} ** 32)) {
            return .{ .payload = .{
                .parent_hash = std.mem.zeroes([32]u8),
                .fee_recipient = std.mem.zeroes([20]u8),
                .state_root = std.mem.zeroes([32]u8),
                .receipts_root = std.mem.zeroes([32]u8),
                .logs_bloom = std.mem.zeroes([256]u8),
                .prev_randao = std.mem.zeroes([32]u8),
                .block_number = 0,
                .gas_limit = 30_000_000,
                .gas_used = 0,
                .timestamp = 0,
                .extra_data = &.{},
                .base_fee_per_gas = 0,
                .block_hash = std.mem.zeroes([32]u8),
                .transactions = &.{},
                .withdrawals = &.{},
                .blob_gas_used = 0,
                .excess_blob_gas = 0,
            } };
        }

        return self.payloads.get(block_hash);
    }

    fn sanitizePayloadV3(payload: ExecutionPayloadV3) StoredPayloadV3 {
        return .{ .payload = .{
            .parent_hash = payload.parent_hash,
            .fee_recipient = payload.fee_recipient,
            .state_root = payload.state_root,
            .receipts_root = payload.receipts_root,
            .logs_bloom = payload.logs_bloom,
            .prev_randao = payload.prev_randao,
            .block_number = payload.block_number,
            .gas_limit = payload.gas_limit,
            .gas_used = payload.gas_used,
            .timestamp = payload.timestamp,
            .extra_data = &.{},
            .base_fee_per_gas = payload.base_fee_per_gas,
            .block_hash = payload.block_hash,
            .transactions = &.{},
            .withdrawals = &.{},
            .blob_gas_used = payload.blob_gas_used,
            .excess_blob_gas = payload.excess_blob_gas,
        } };
    }

    fn handleNewPayload(self: *MockEngine, payload: ExecutionPayloadV3) !PayloadStatusV1 {
        if (self.status_overrides.get(payload.block_hash)) |status| {
            return self.newPayloadStatusResponse(payload.block_hash, status);
        }

        if (self.knownPayload(payload.parent_hash) == null) {
            return self.newPayloadStatusResponse(payload.block_hash, .syncing);
        }

        const status = self.default_status;
        if (status == .valid) {
            try self.payloads.put(payload.block_hash, sanitizePayloadV3(payload));
        }

        return self.newPayloadStatusResponse(payload.block_hash, status);
    }

    /// Build a minimal child payload on top of the current FCU head.
    fn buildStubV3(
        self: *MockEngine,
        state: ForkchoiceStateV1,
        payload_id: [8]u8,
        attrs_timestamp: u64,
        attrs_prev_randao: [32]u8,
        attrs_fee_recipient: [20]u8,
    ) StoredPayloadV3 {
        const head = self.knownPayload(state.head_block_hash).?;
        var block_hash = state.head_block_hash;
        for (payload_id, 0..) |byte, i| {
            block_hash[i] ^= byte;
        }
        block_hash[31] ^= 0x01;

        return .{ .payload = .{
            .parent_hash = state.head_block_hash,
            .fee_recipient = attrs_fee_recipient,
            .state_root = std.mem.zeroes([32]u8),
            .receipts_root = std.mem.zeroes([32]u8),
            .logs_bloom = std.mem.zeroes([256]u8),
            .prev_randao = attrs_prev_randao,
            .block_number = head.payload.block_number + 1,
            .gas_limit = 30_000_000,
            .gas_used = 15_000_000,
            .timestamp = attrs_timestamp,
            .extra_data = &.{},
            .base_fee_per_gas = 0,
            .block_hash = block_hash,
            .transactions = &.{},
            .withdrawals = &.{},
            .blob_gas_used = 0,
            .excess_blob_gas = 0,
        } };
    }

    fn handleForkchoiceUpdated(
        self: *MockEngine,
        state: ForkchoiceStateV1,
        attrs: ?BuildAttrs,
    ) !ForkchoiceUpdatedResponse {
        self.last_forkchoice_state = state;

        if (self.status_overrides.get(state.head_block_hash)) |status| {
            return .{
                .payload_status = forkchoiceStatusResponse(status),
                .payload_id = null,
            };
        }

        const head = self.knownPayload(state.head_block_hash) orelse {
            return .{
                .payload_status = forkchoiceStatusResponse(.syncing),
                .payload_id = null,
            };
        };

        var payload_id: ?[8]u8 = null;
        if (attrs) |a| {
            if (head.payload.timestamp > a.timestamp) {
                return error.InvalidPayloadAttributes;
            }

            const id = self.makePayloadId();
            const stub = self.buildStubV3(
                state,
                id,
                a.timestamp,
                a.prev_randao,
                a.suggested_fee_recipient,
            );
            try self.built_payloads.put(id, stub);
            payload_id = id;
        }

        return .{
            .payload_status = forkchoiceStatusResponse(.valid),
            .payload_id = payload_id,
        };
    }

    // ── vtable ────────────────────────────────────────────────────────────────

    const vtable = EngineApi.VTable{
        .newPayloadV1 = &newPayloadV1Impl,
        .newPayloadV2 = &newPayloadV2Impl,
        .newPayloadV3 = &newPayloadV3Impl,
        .newPayloadV4 = &newPayloadV4Impl,
        .forkchoiceUpdatedV1 = &forkchoiceUpdatedV1Impl,
        .forkchoiceUpdatedV2 = &forkchoiceUpdatedV2Impl,
        .forkchoiceUpdatedV3 = &forkchoiceUpdatedV3Impl,
        .getPayloadV1 = &getPayloadV1Impl,
        .getPayloadV2 = &getPayloadV2Impl,
        .getPayloadV3 = &getPayloadV3Impl,
        .getPayloadV4 = &getPayloadV4Impl,
        .freeGetPayloadResponse = &freeGetPayloadResponseImpl,
    };

    fn freeGetPayloadResponseImpl(_: *anyopaque, _: GetPayloadResponse) void {}

    // ── newPayload implementations ────────────────────────────────────────────

    fn newPayloadV1Impl(
        ptr: *anyopaque,
        payload: ExecutionPayloadV1,
    ) anyerror!PayloadStatusV1 {
        const self: *MockEngine = @ptrCast(@alignCast(ptr));
        // Promote to V3 for storage (fill missing fields with zero).
        const v3 = ExecutionPayloadV3{
            .parent_hash = payload.parent_hash,
            .fee_recipient = payload.fee_recipient,
            .state_root = payload.state_root,
            .receipts_root = payload.receipts_root,
            .logs_bloom = payload.logs_bloom,
            .prev_randao = payload.prev_randao,
            .block_number = payload.block_number,
            .gas_limit = payload.gas_limit,
            .gas_used = payload.gas_used,
            .timestamp = payload.timestamp,
            .extra_data = payload.extra_data,
            .base_fee_per_gas = payload.base_fee_per_gas,
            .block_hash = payload.block_hash,
            .transactions = payload.transactions,
            .withdrawals = &.{},
            .blob_gas_used = 0,
            .excess_blob_gas = 0,
        };
        return self.handleNewPayload(v3);
    }

    fn newPayloadV2Impl(
        ptr: *anyopaque,
        payload: ExecutionPayloadV2,
    ) anyerror!PayloadStatusV1 {
        const self: *MockEngine = @ptrCast(@alignCast(ptr));
        const v3 = ExecutionPayloadV3{
            .parent_hash = payload.parent_hash,
            .fee_recipient = payload.fee_recipient,
            .state_root = payload.state_root,
            .receipts_root = payload.receipts_root,
            .logs_bloom = payload.logs_bloom,
            .prev_randao = payload.prev_randao,
            .block_number = payload.block_number,
            .gas_limit = payload.gas_limit,
            .gas_used = payload.gas_used,
            .timestamp = payload.timestamp,
            .extra_data = payload.extra_data,
            .base_fee_per_gas = payload.base_fee_per_gas,
            .block_hash = payload.block_hash,
            .transactions = payload.transactions,
            .withdrawals = payload.withdrawals,
            .blob_gas_used = 0,
            .excess_blob_gas = 0,
        };
        return self.handleNewPayload(v3);
    }

    fn newPayloadV3Impl(
        ptr: *anyopaque,
        payload: ExecutionPayloadV3,
        _: []const [32]u8,
        _: [32]u8,
    ) anyerror!PayloadStatusV1 {
        const self: *MockEngine = @ptrCast(@alignCast(ptr));
        return self.handleNewPayload(payload);
    }

    fn newPayloadV4Impl(
        ptr: *anyopaque,
        payload: ExecutionPayloadV4,
        _: []const [32]u8,
        _: [32]u8,
    ) anyerror!PayloadStatusV1 {
        const self: *MockEngine = @ptrCast(@alignCast(ptr));
        // Demote to V3 for storage (V4-specific fields are dropped).
        const v3 = ExecutionPayloadV3{
            .parent_hash = payload.parent_hash,
            .fee_recipient = payload.fee_recipient,
            .state_root = payload.state_root,
            .receipts_root = payload.receipts_root,
            .logs_bloom = payload.logs_bloom,
            .prev_randao = payload.prev_randao,
            .block_number = payload.block_number,
            .gas_limit = payload.gas_limit,
            .gas_used = payload.gas_used,
            .timestamp = payload.timestamp,
            .extra_data = payload.extra_data,
            .base_fee_per_gas = payload.base_fee_per_gas,
            .block_hash = payload.block_hash,
            .transactions = payload.transactions,
            .withdrawals = payload.withdrawals,
            .blob_gas_used = payload.blob_gas_used,
            .excess_blob_gas = payload.excess_blob_gas,
        };
        return self.handleNewPayload(v3);
    }

    // ── forkchoiceUpdated implementations ─────────────────────────────────────

    fn forkchoiceUpdatedV1Impl(
        ptr: *anyopaque,
        state: ForkchoiceStateV1,
        attrs: ?PayloadAttributesV1,
    ) anyerror!ForkchoiceUpdatedResponse {
        const self: *MockEngine = @ptrCast(@alignCast(ptr));
        return self.handleForkchoiceUpdated(state, if (attrs) |a|
            .{
                .timestamp = a.timestamp,
                .prev_randao = a.prev_randao,
                .suggested_fee_recipient = a.suggested_fee_recipient,
            }
        else
            null);
    }

    fn forkchoiceUpdatedV2Impl(
        ptr: *anyopaque,
        state: ForkchoiceStateV1,
        attrs: ?PayloadAttributesV2,
    ) anyerror!ForkchoiceUpdatedResponse {
        const self: *MockEngine = @ptrCast(@alignCast(ptr));
        return self.handleForkchoiceUpdated(state, if (attrs) |a|
            .{
                .timestamp = a.timestamp,
                .prev_randao = a.prev_randao,
                .suggested_fee_recipient = a.suggested_fee_recipient,
            }
        else
            null);
    }

    fn forkchoiceUpdatedV3Impl(
        ptr: *anyopaque,
        state: ForkchoiceStateV1,
        attrs: ?PayloadAttributesV3,
    ) anyerror!ForkchoiceUpdatedResponse {
        const self: *MockEngine = @ptrCast(@alignCast(ptr));
        return self.handleForkchoiceUpdated(state, if (attrs) |a|
            .{
                .timestamp = a.timestamp,
                .prev_randao = a.prev_randao,
                .suggested_fee_recipient = a.suggested_fee_recipient,
            }
        else
            null);
    }

    // ── getPayload implementations ────────────────────────────────────────────

    fn getPayloadV1Impl(
        ptr: *anyopaque,
        payload_id: [8]u8,
    ) anyerror!GetPayloadResponseV1 {
        const self: *MockEngine = @ptrCast(@alignCast(ptr));
        const stored = self.built_payloads.get(payload_id) orelse
            return error.UnknownPayload;
        const p = stored.payload;
        return GetPayloadResponseV1{
            .execution_payload = .{
                .parent_hash = p.parent_hash,
                .fee_recipient = p.fee_recipient,
                .state_root = p.state_root,
                .receipts_root = p.receipts_root,
                .logs_bloom = p.logs_bloom,
                .prev_randao = p.prev_randao,
                .block_number = p.block_number,
                .gas_limit = p.gas_limit,
                .gas_used = p.gas_used,
                .timestamp = p.timestamp,
                .extra_data = p.extra_data,
                .base_fee_per_gas = p.base_fee_per_gas,
                .block_hash = p.block_hash,
                .transactions = p.transactions,
            },
            .block_value = stored.block_value,
        };
    }

    fn getPayloadV2Impl(
        ptr: *anyopaque,
        payload_id: [8]u8,
    ) anyerror!GetPayloadResponseV2 {
        const self: *MockEngine = @ptrCast(@alignCast(ptr));
        const stored = self.built_payloads.get(payload_id) orelse
            return error.UnknownPayload;
        const p = stored.payload;
        return GetPayloadResponseV2{
            .execution_payload = .{
                .parent_hash = p.parent_hash,
                .fee_recipient = p.fee_recipient,
                .state_root = p.state_root,
                .receipts_root = p.receipts_root,
                .logs_bloom = p.logs_bloom,
                .prev_randao = p.prev_randao,
                .block_number = p.block_number,
                .gas_limit = p.gas_limit,
                .gas_used = p.gas_used,
                .timestamp = p.timestamp,
                .extra_data = p.extra_data,
                .base_fee_per_gas = p.base_fee_per_gas,
                .block_hash = p.block_hash,
                .transactions = p.transactions,
                .withdrawals = p.withdrawals,
            },
            .block_value = stored.block_value,
        };
    }

    fn getPayloadV3Impl(
        ptr: *anyopaque,
        payload_id: [8]u8,
    ) anyerror!GetPayloadResponse {
        const self: *MockEngine = @ptrCast(@alignCast(ptr));
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

    fn getPayloadV4Impl(
        ptr: *anyopaque,
        payload_id: [8]u8,
    ) anyerror!GetPayloadResponseV4 {
        const self: *MockEngine = @ptrCast(@alignCast(ptr));
        const stored = self.built_payloads.get(payload_id) orelse
            return error.UnknownPayload;
        const p = stored.payload;
        return GetPayloadResponseV4{
            .execution_payload = .{
                .parent_hash = p.parent_hash,
                .fee_recipient = p.fee_recipient,
                .state_root = p.state_root,
                .receipts_root = p.receipts_root,
                .logs_bloom = p.logs_bloom,
                .prev_randao = p.prev_randao,
                .block_number = p.block_number,
                .gas_limit = p.gas_limit,
                .gas_used = p.gas_used,
                .timestamp = p.timestamp,
                .extra_data = p.extra_data,
                .base_fee_per_gas = p.base_fee_per_gas,
                .block_hash = p.block_hash,
                .transactions = p.transactions,
                .withdrawals = p.withdrawals,
                .blob_gas_used = p.blob_gas_used,
                .excess_blob_gas = p.excess_blob_gas,
                .deposit_requests = &.{},
                .withdrawal_requests = &.{},
                .consolidation_requests = &.{},
            },
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

test "MockEngine: newPayload V3 returns valid by default" {
    var mock = MockEngine.init(testing.allocator);
    defer mock.deinit();

    const api = mock.engine();
    const payload = makeTestPayloadV3([_]u8{0x01} ** 32);

    const result = try api.newPayload(payload, &.{}, std.mem.zeroes([32]u8));
    try testing.expectEqual(ExecutionPayloadStatus.valid, result.status);
    try testing.expect(result.latest_valid_hash != null);
    try testing.expectEqual([_]u8{0x01} ** 32, result.latest_valid_hash.?);
}

test "MockEngine: newPayload with unknown parent returns syncing" {
    var mock = MockEngine.init(testing.allocator);
    defer mock.deinit();

    const api = mock.engine();
    var payload = makeTestPayloadV3([_]u8{0x06} ** 32);
    payload.parent_hash = [_]u8{0xaa} ** 32;

    const result = try api.newPayload(payload, &.{}, std.mem.zeroes([32]u8));
    try testing.expectEqual(ExecutionPayloadStatus.syncing, result.status);
    try testing.expect(result.latest_valid_hash == null);
}

test "MockEngine: seeded payload lets child newPayload validate" {
    var mock = MockEngine.init(testing.allocator);
    defer mock.deinit();

    try mock.seedPayload(.{
        .parent_hash = std.mem.zeroes([32]u8),
        .block_hash = [_]u8{0xaa} ** 32,
        .block_number = 10,
        .timestamp = 100,
    });

    const api = mock.engine();
    var payload = makeTestPayloadV3([_]u8{0xbb} ** 32);
    payload.parent_hash = [_]u8{0xaa} ** 32;
    payload.block_number = 11;
    payload.timestamp = 101;

    const result = try api.newPayload(payload, &.{}, std.mem.zeroes([32]u8));
    try testing.expectEqual(ExecutionPayloadStatus.valid, result.status);
    try testing.expectEqual([_]u8{0xbb} ** 32, result.latest_valid_hash.?);
}

test "MockEngine: newPayload V1 returns valid" {
    var mock = MockEngine.init(testing.allocator);
    defer mock.deinit();

    const api = mock.engine();
    const payload = makeTestPayloadV1([_]u8{0x10} ** 32);
    const result = try api.newPayloadV1(payload);
    try testing.expectEqual(ExecutionPayloadStatus.valid, result.status);
}

test "MockEngine: newPayload V2 returns valid" {
    var mock = MockEngine.init(testing.allocator);
    defer mock.deinit();

    const api = mock.engine();
    const payload = makeTestPayloadV2([_]u8{0x20} ** 32);
    const result = try api.newPayloadV2(payload);
    try testing.expectEqual(ExecutionPayloadStatus.valid, result.status);
}

test "MockEngine: newPayload V4 returns valid" {
    var mock = MockEngine.init(testing.allocator);
    defer mock.deinit();

    const api = mock.engine();
    const payload = makeTestPayloadV4([_]u8{0x40} ** 32);
    const result = try api.newPayloadV4(payload, &.{}, std.mem.zeroes([32]u8));
    try testing.expectEqual(ExecutionPayloadStatus.valid, result.status);
}

test "MockEngine: newPayload with status override" {
    var mock = MockEngine.init(testing.allocator);
    defer mock.deinit();

    const block_hash = [_]u8{0x02} ** 32;
    try mock.setPayloadStatus(block_hash, .invalid);

    const api = mock.engine();
    const payload = makeTestPayloadV3(block_hash);

    const result = try api.newPayload(payload, &.{}, std.mem.zeroes([32]u8));
    try testing.expectEqual(ExecutionPayloadStatus.invalid, result.status);
    try testing.expect(result.latest_valid_hash == null);
}

test "MockEngine: forkchoiceUpdatedV1 without attributes" {
    var mock = MockEngine.init(testing.allocator);
    defer mock.deinit();

    const api = mock.engine();
    const block_hash = [_]u8{0x30} ** 32;
    _ = try api.newPayloadV1(makeTestPayloadV1(block_hash));

    const fcu = try api.forkchoiceUpdatedV1(.{
        .head_block_hash = block_hash,
        .safe_block_hash = block_hash,
        .finalized_block_hash = block_hash,
    }, null);
    try testing.expectEqual(ExecutionPayloadStatus.valid, fcu.payload_status.status);
    try testing.expect(fcu.payload_status.latest_valid_hash == null);
    try testing.expect(fcu.payload_id == null);
}

test "MockEngine: forkchoiceUpdatedV1 with attributes returns payload_id" {
    var mock = MockEngine.init(testing.allocator);
    defer mock.deinit();

    const api = mock.engine();
    const block_hash = [_]u8{0x31} ** 32;
    _ = try api.newPayloadV1(makeTestPayloadV1(block_hash));

    const fcu = try api.forkchoiceUpdatedV1(.{
        .head_block_hash = block_hash,
        .safe_block_hash = block_hash,
        .finalized_block_hash = block_hash,
    }, .{
        .timestamp = 1_700_000_001,
        .prev_randao = [_]u8{0xbb} ** 32,
        .suggested_fee_recipient = [_]u8{0xcc} ** 20,
    });
    try testing.expect(fcu.payload_id != null);
    try testing.expect(fcu.payload_status.latest_valid_hash == null);
}

test "MockEngine: forkchoiceUpdatedV2 with attributes returns payload_id" {
    var mock = MockEngine.init(testing.allocator);
    defer mock.deinit();

    const api = mock.engine();
    const block_hash = [_]u8{0x32} ** 32;
    _ = try api.newPayloadV2(makeTestPayloadV2(block_hash));

    const fcu = try api.forkchoiceUpdatedV2(.{
        .head_block_hash = block_hash,
        .safe_block_hash = block_hash,
        .finalized_block_hash = block_hash,
    }, .{
        .timestamp = 1_700_000_001,
        .prev_randao = [_]u8{0xdd} ** 32,
        .suggested_fee_recipient = [_]u8{0xee} ** 20,
        .withdrawals = &.{},
    });
    try testing.expect(fcu.payload_id != null);
}

test "MockEngine: forkchoiceUpdated V3 without attributes" {
    var mock = MockEngine.init(testing.allocator);
    defer mock.deinit();

    const api = mock.engine();
    const block_hash = [_]u8{0x03} ** 32;
    _ = try api.newPayload(makeTestPayloadV3(block_hash), &.{}, std.mem.zeroes([32]u8));

    const fcu = try api.forkchoiceUpdated(.{
        .head_block_hash = block_hash,
        .safe_block_hash = block_hash,
        .finalized_block_hash = block_hash,
    }, null);

    try testing.expectEqual(ExecutionPayloadStatus.valid, fcu.payload_status.status);
    try testing.expect(fcu.payload_id == null);
    try testing.expect(mock.last_forkchoice_state != null);
}

test "MockEngine: forkchoiceUpdated V3 with attributes returns payload_id" {
    var mock = MockEngine.init(testing.allocator);
    defer mock.deinit();

    const api = mock.engine();
    const block_hash = [_]u8{0x04} ** 32;
    _ = try api.newPayload(makeTestPayloadV3(block_hash), &.{}, std.mem.zeroes([32]u8));

    const fcu = try api.forkchoiceUpdated(.{
        .head_block_hash = block_hash,
        .safe_block_hash = block_hash,
        .finalized_block_hash = block_hash,
    }, .{
        .timestamp = 1_700_000_001,
        .prev_randao = [_]u8{0xbb} ** 32,
        .suggested_fee_recipient = [_]u8{0xcc} ** 20,
        .withdrawals = &.{},
        .parent_beacon_block_root = [_]u8{0xdd} ** 32,
    });

    try testing.expectEqual(ExecutionPayloadStatus.valid, fcu.payload_status.status);
    try testing.expect(fcu.payload_status.latest_valid_hash == null);
    try testing.expect(fcu.payload_id != null);
}

test "MockEngine: getPayload V3 returns built payload" {
    var mock = MockEngine.init(testing.allocator);
    defer mock.deinit();

    const api = mock.engine();
    const block_hash = [_]u8{0x05} ** 32;
    _ = try api.newPayload(makeTestPayloadV3(block_hash), &.{}, std.mem.zeroes([32]u8));

    const fcu = try api.forkchoiceUpdated(.{
        .head_block_hash = block_hash,
        .safe_block_hash = block_hash,
        .finalized_block_hash = block_hash,
    }, .{
        .timestamp = 1_700_000_001,
        .prev_randao = [_]u8{0xee} ** 32,
        .suggested_fee_recipient = [_]u8{0xff} ** 20,
        .withdrawals = &.{},
        .parent_beacon_block_root = std.mem.zeroes([32]u8),
    });

    const payload_id = fcu.payload_id.?;
    const resp = try api.getPayload(payload_id);
    try testing.expectEqual(block_hash, resp.execution_payload.parent_hash);
    try testing.expect(!std.mem.eql(u8, resp.execution_payload.block_hash[0..], block_hash[0..]));
    try testing.expectEqual(@as(u64, 2), resp.execution_payload.block_number);
    try testing.expectEqual(@as(u64, 1_700_000_001), resp.execution_payload.timestamp);
    try testing.expectEqual([_]u8{0xff} ** 20, resp.execution_payload.fee_recipient);
    try testing.expectEqual([_]u8{0xee} ** 32, resp.execution_payload.prev_randao);
    try testing.expect(!resp.should_override_builder);
}

test "MockEngine: getPayloadV1 returns built payload" {
    var mock = MockEngine.init(testing.allocator);
    defer mock.deinit();

    const api = mock.engine();
    const block_hash = [_]u8{0x61} ** 32;
    _ = try api.newPayloadV1(makeTestPayloadV1(block_hash));

    const fcu = try api.forkchoiceUpdatedV1(.{
        .head_block_hash = block_hash,
        .safe_block_hash = block_hash,
        .finalized_block_hash = block_hash,
    }, .{
        .timestamp = 1_700_000_001,
        .prev_randao = std.mem.zeroes([32]u8),
        .suggested_fee_recipient = std.mem.zeroes([20]u8),
    });

    const pid = fcu.payload_id.?;
    const resp = try api.getPayloadV1(pid);
    try testing.expectEqual(block_hash, resp.execution_payload.parent_hash);
    try testing.expect(!std.mem.eql(u8, resp.execution_payload.block_hash[0..], block_hash[0..]));
}

test "MockEngine: getPayloadV4 returns built payload" {
    var mock = MockEngine.init(testing.allocator);
    defer mock.deinit();

    const api = mock.engine();
    const block_hash = [_]u8{0x64} ** 32;
    _ = try api.newPayloadV4(makeTestPayloadV4(block_hash), &.{}, std.mem.zeroes([32]u8));

    const fcu = try api.forkchoiceUpdated(.{
        .head_block_hash = block_hash,
        .safe_block_hash = block_hash,
        .finalized_block_hash = block_hash,
    }, .{
        .timestamp = 1_700_000_001,
        .prev_randao = std.mem.zeroes([32]u8),
        .suggested_fee_recipient = std.mem.zeroes([20]u8),
        .withdrawals = &.{},
        .parent_beacon_block_root = std.mem.zeroes([32]u8),
    });

    const pid = fcu.payload_id.?;
    const resp = try api.getPayloadV4(pid);
    try testing.expectEqual(block_hash, resp.execution_payload.parent_hash);
    try testing.expect(!std.mem.eql(u8, resp.execution_payload.block_hash[0..], block_hash[0..]));
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

test "MockEngine: forkchoiceUpdated with unknown head and attributes does not start build" {
    var mock = MockEngine.init(testing.allocator);
    defer mock.deinit();

    const api = mock.engine();
    const fcu = try api.forkchoiceUpdated(.{
        .head_block_hash = [_]u8{0xac} ** 32,
        .safe_block_hash = [_]u8{0xac} ** 32,
        .finalized_block_hash = [_]u8{0xac} ** 32,
    }, .{
        .timestamp = 1_700_000_001,
        .prev_randao = [_]u8{0x01} ** 32,
        .suggested_fee_recipient = [_]u8{0x02} ** 20,
        .withdrawals = &.{},
        .parent_beacon_block_root = std.mem.zeroes([32]u8),
    });

    try testing.expectEqual(ExecutionPayloadStatus.syncing, fcu.payload_status.status);
    try testing.expect(fcu.payload_id == null);
}

test "MockEngine: forkchoiceUpdated with status override does not start build" {
    var mock = MockEngine.init(testing.allocator);
    defer mock.deinit();

    const api = mock.engine();
    const block_hash = [_]u8{0xad} ** 32;
    try mock.setPayloadStatus(block_hash, .invalid);

    const fcu = try api.forkchoiceUpdated(.{
        .head_block_hash = block_hash,
        .safe_block_hash = block_hash,
        .finalized_block_hash = block_hash,
    }, .{
        .timestamp = 1_700_000_001,
        .prev_randao = [_]u8{0x03} ** 32,
        .suggested_fee_recipient = [_]u8{0x04} ** 20,
        .withdrawals = &.{},
        .parent_beacon_block_root = std.mem.zeroes([32]u8),
    });

    try testing.expectEqual(ExecutionPayloadStatus.invalid, fcu.payload_status.status);
    try testing.expect(fcu.payload_id == null);
}

test "MockEngine: forkchoiceUpdated rejects stale payload attributes" {
    var mock = MockEngine.init(testing.allocator);
    defer mock.deinit();

    const api = mock.engine();
    const block_hash = [_]u8{0xae} ** 32;
    _ = try api.newPayload(makeTestPayloadV3(block_hash), &.{}, std.mem.zeroes([32]u8));

    const result = api.forkchoiceUpdated(.{
        .head_block_hash = block_hash,
        .safe_block_hash = block_hash,
        .finalized_block_hash = block_hash,
    }, .{
        .timestamp = 1_699_999_999,
        .prev_randao = [_]u8{0x05} ** 32,
        .suggested_fee_recipient = [_]u8{0x06} ** 20,
        .withdrawals = &.{},
        .parent_beacon_block_root = std.mem.zeroes([32]u8),
    });

    try testing.expectError(error.InvalidPayloadAttributes, result);
}

// ── Test helpers ──────────────────────────────────────────────────────────────

fn makeTestPayloadV1(block_hash: [32]u8) ExecutionPayloadV1 {
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
    };
}

fn makeTestPayloadV2(block_hash: [32]u8) ExecutionPayloadV2 {
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
    };
}

fn makeTestPayloadV3(block_hash: [32]u8) ExecutionPayloadV3 {
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

fn makeTestPayloadV4(block_hash: [32]u8) ExecutionPayloadV4 {
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
        .deposit_requests = &.{},
        .withdrawal_requests = &.{},
        .consolidation_requests = &.{},
    };
}
