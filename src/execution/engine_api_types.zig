//! Engine API types for JSON-RPC communication with execution layer clients.
//!
//! These are plain Zig types (not SSZ containers) representing the Engine API
//! request/response structures used in JSON-RPC calls to EL clients like
//! Geth, Nethermind, Besu, and Erigon.
//!
//! Reference: https://github.com/ethereum/execution-apis/tree/main/src/engine

const std = @import("std");
const testing = std.testing;

/// Withdrawal represents a validator withdrawal from the beacon chain
/// to the execution layer.
pub const Withdrawal = struct {
    index: u64,
    validator_index: u64,
    address: [20]u8,
    amount: u64,
};

/// Status returned by the execution engine after validating a payload.
pub const ExecutionPayloadStatus = enum {
    valid,
    invalid,
    syncing,
    accepted,
    invalid_block_hash,
};

/// Response from engine_newPayloadV* and part of engine_forkchoiceUpdatedV*.
pub const PayloadStatusV1 = struct {
    status: ExecutionPayloadStatus,
    /// The hash of the most recent valid block in the branch defined by the payload
    /// and its ancestors. null when status is syncing or accepted.
    latest_valid_hash: ?[32]u8 = null,
    /// Validation error message. null when status is valid.
    validation_error: ?[]const u8 = null,
};

/// The current head, safe, and finalized block hashes of the beacon chain,
/// sent to the EL via engine_forkchoiceUpdatedV*.
pub const ForkchoiceStateV1 = struct {
    head_block_hash: [32]u8,
    safe_block_hash: [32]u8,
    finalized_block_hash: [32]u8,
};

/// Payload attributes sent with forkchoiceUpdated to trigger block building.
/// V3 includes parent_beacon_block_root (post-Deneb).
pub const PayloadAttributesV3 = struct {
    timestamp: u64,
    prev_randao: [32]u8,
    suggested_fee_recipient: [20]u8,
    withdrawals: []const Withdrawal,
    parent_beacon_block_root: [32]u8,
};

/// Response from engine_forkchoiceUpdatedV*.
pub const ForkchoiceUpdatedResponse = struct {
    payload_status: PayloadStatusV1,
    /// Identifier of the payload build process; null when no build was requested.
    payload_id: ?[8]u8 = null,
};

/// Execution payload as returned by the EL (V3: post-Deneb with blob gas fields).
pub const ExecutionPayloadV3 = struct {
    parent_hash: [32]u8,
    fee_recipient: [20]u8,
    state_root: [32]u8,
    receipts_root: [32]u8,
    logs_bloom: [256]u8,
    prev_randao: [32]u8,
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: []const u8,
    base_fee_per_gas: u256,
    block_hash: [32]u8,
    transactions: []const []const u8,
    withdrawals: []const Withdrawal,
    blob_gas_used: u64,
    excess_blob_gas: u64,
};

/// Response from engine_getPayloadV3.
pub const GetPayloadResponse = struct {
    execution_payload: ExecutionPayloadV3,
    block_value: u256,
    blobs_bundle: BlobsBundle,
    should_override_builder: bool,
};

/// Bundle of blobs, commitments, and proofs returned with the payload.
pub const BlobsBundle = struct {
    commitments: []const [48]u8,
    proofs: []const [48]u8,
    blobs: []const [131072]u8,
};

// ── Tests ────────────────────────────────────────────────────────────────────

test "ExecutionPayloadStatus enum values" {
    // Verify all status variants exist and can be compared.
    const statuses = [_]ExecutionPayloadStatus{
        .valid,
        .invalid,
        .syncing,
        .accepted,
        .invalid_block_hash,
    };
    try testing.expectEqual(@as(usize, 5), statuses.len);
    try testing.expect(statuses[0] != statuses[1]);
}

test "PayloadStatusV1 defaults" {
    const status = PayloadStatusV1{
        .status = .valid,
    };
    try testing.expectEqual(ExecutionPayloadStatus.valid, status.status);
    try testing.expect(status.latest_valid_hash == null);
    try testing.expect(status.validation_error == null);
}

test "ForkchoiceStateV1 zero init" {
    const state = ForkchoiceStateV1{
        .head_block_hash = std.mem.zeroes([32]u8),
        .safe_block_hash = std.mem.zeroes([32]u8),
        .finalized_block_hash = std.mem.zeroes([32]u8),
    };
    try testing.expectEqual(std.mem.zeroes([32]u8), state.head_block_hash);
}

test "ForkchoiceUpdatedResponse with payload_id" {
    const resp = ForkchoiceUpdatedResponse{
        .payload_status = .{
            .status = .valid,
            .latest_valid_hash = [_]u8{0xaa} ** 32,
        },
        .payload_id = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
    };
    try testing.expectEqual(ExecutionPayloadStatus.valid, resp.payload_status.status);
    try testing.expect(resp.payload_id != null);
    try testing.expectEqual(@as(u8, 0x01), resp.payload_id.?[0]);
}

test "Withdrawal struct layout" {
    const w = Withdrawal{
        .index = 42,
        .validator_index = 100,
        .address = [_]u8{0xff} ** 20,
        .amount = 32_000_000_000,
    };
    try testing.expectEqual(@as(u64, 42), w.index);
    try testing.expectEqual(@as(u64, 32_000_000_000), w.amount);
}
