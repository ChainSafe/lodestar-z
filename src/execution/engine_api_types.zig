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

/// DepositRequest (Electra EIP-6110): deposit from execution layer.
pub const DepositRequest = struct {
    pubkey: [48]u8,
    withdrawal_credentials: [32]u8,
    amount: u64,
    signature: [96]u8,
    index: u64,
};

/// WithdrawalRequest (Electra EIP-7002): validator withdrawal triggered on EL.
pub const WithdrawalRequest = struct {
    source_address: [20]u8,
    validator_pubkey: [48]u8,
    amount: u64,
};

/// ConsolidationRequest (Electra EIP-7251): validator consolidation on EL.
pub const ConsolidationRequest = struct {
    source_address: [20]u8,
    source_pubkey: [48]u8,
    target_pubkey: [48]u8,
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
    /// Heap-allocated by the JSON decoder — must be freed via `deinit()`.
    validation_error: ?[]const u8 = null,

    /// Free the heap-allocated `validation_error` string (if any).
    /// Must be called when the caller is done with the payload status.
    pub fn deinit(self: *const PayloadStatusV1, allocator: std.mem.Allocator) void {
        if (self.validation_error) |ve| {
            allocator.free(ve);
        }
    }
};

/// The current head, safe, and finalized block hashes of the beacon chain,
/// sent to the EL via engine_forkchoiceUpdatedV*.
pub const ForkchoiceStateV1 = struct {
    head_block_hash: [32]u8,
    safe_block_hash: [32]u8,
    finalized_block_hash: [32]u8,
};

// ── PayloadAttributes ─────────────────────────────────────────────────────────

/// V1 payload attributes (Bellatrix): no withdrawals, no parent_beacon_block_root.
pub const PayloadAttributesV1 = struct {
    timestamp: u64,
    prev_randao: [32]u8,
    suggested_fee_recipient: [20]u8,
};

/// V2 payload attributes (Capella): adds withdrawals.
pub const PayloadAttributesV2 = struct {
    timestamp: u64,
    prev_randao: [32]u8,
    suggested_fee_recipient: [20]u8,
    withdrawals: []const Withdrawal,
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

    /// Free heap-allocated fields (validation_error in payload_status).
    pub fn deinit(self: *const ForkchoiceUpdatedResponse, allocator: std.mem.Allocator) void {
        self.payload_status.deinit(allocator);
    }
};

// ── Execution Payloads ────────────────────────────────────────────────────────

/// Execution payload V1 (Bellatrix): no withdrawals, no blob fields.
pub const ExecutionPayloadV1 = struct {
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
};

/// Execution payload V2 (Capella): adds withdrawals.
pub const ExecutionPayloadV2 = struct {
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

/// Execution payload V4 (Electra): adds deposit_requests, withdrawal_requests,
/// consolidation_requests.
pub const ExecutionPayloadV4 = struct {
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
    deposit_requests: []const DepositRequest,
    withdrawal_requests: []const WithdrawalRequest,
    consolidation_requests: []const ConsolidationRequest,
};

// ── Payload responses ─────────────────────────────────────────────────────────

/// Response from engine_getPayloadV1 (Bellatrix).
pub const GetPayloadResponseV1 = struct {
    execution_payload: ExecutionPayloadV1,
    block_value: u256,
};

/// Response from engine_getPayloadV2 (Capella).
pub const GetPayloadResponseV2 = struct {
    execution_payload: ExecutionPayloadV2,
    block_value: u256,
};

/// Response from engine_getPayloadV3/V4 (Deneb/Electra).
///
/// The `execution_payload` field always contains an `ExecutionPayloadV3`
/// (blob fields zero for pre-Deneb forks). For Electra+, the Electra-specific
/// execution requests are stored in the optional fields below rather than
/// discarded via V3 promotion.
pub const GetPayloadResponse = struct {
    execution_payload: ExecutionPayloadV3,
    block_value: u256,
    blobs_bundle: BlobsBundle,
    should_override_builder: bool,
    // Fix 2: Electra execution requests preserved from V4 response.
    deposit_requests: []const DepositRequest = &.{},
    withdrawal_requests: []const WithdrawalRequest = &.{},
    consolidation_requests: []const ConsolidationRequest = &.{},
};

/// Response from engine_getPayloadV4 (Electra).
pub const GetPayloadResponseV4 = struct {
    execution_payload: ExecutionPayloadV4,
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

test "ExecutionPayloadV1 struct" {
    const p = ExecutionPayloadV1{
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
        .block_hash = [_]u8{0x01} ** 32,
        .transactions = &.{},
    };
    try testing.expectEqual(@as(u64, 1), p.block_number);
    try testing.expect(!@hasField(ExecutionPayloadV1, "withdrawals"));
    try testing.expect(!@hasField(ExecutionPayloadV1, "blob_gas_used"));
}

test "ExecutionPayloadV2 has withdrawals but no blob fields" {
    try testing.expect(@hasField(ExecutionPayloadV2, "withdrawals"));
    try testing.expect(!@hasField(ExecutionPayloadV2, "blob_gas_used"));
    try testing.expect(!@hasField(ExecutionPayloadV2, "excess_blob_gas"));
}

test "ExecutionPayloadV3 has withdrawals and blob fields" {
    try testing.expect(@hasField(ExecutionPayloadV3, "withdrawals"));
    try testing.expect(@hasField(ExecutionPayloadV3, "blob_gas_used"));
    try testing.expect(@hasField(ExecutionPayloadV3, "excess_blob_gas"));
}

test "ExecutionPayloadV4 has Electra request fields" {
    try testing.expect(@hasField(ExecutionPayloadV4, "deposit_requests"));
    try testing.expect(@hasField(ExecutionPayloadV4, "withdrawal_requests"));
    try testing.expect(@hasField(ExecutionPayloadV4, "consolidation_requests"));
}

test "PayloadAttributesV1 no withdrawals" {
    try testing.expect(!@hasField(PayloadAttributesV1, "withdrawals"));
    try testing.expect(!@hasField(PayloadAttributesV1, "parent_beacon_block_root"));
}

test "PayloadAttributesV2 has withdrawals but no parent_beacon_block_root" {
    try testing.expect(@hasField(PayloadAttributesV2, "withdrawals"));
    try testing.expect(!@hasField(PayloadAttributesV2, "parent_beacon_block_root"));
}

test "PayloadAttributesV3 has withdrawals and parent_beacon_block_root" {
    try testing.expect(@hasField(PayloadAttributesV3, "withdrawals"));
    try testing.expect(@hasField(PayloadAttributesV3, "parent_beacon_block_root"));
}

test "DepositRequest struct" {
    const dr = DepositRequest{
        .pubkey = [_]u8{0x01} ** 48,
        .withdrawal_credentials = [_]u8{0x02} ** 32,
        .amount = 32_000_000_000,
        .signature = [_]u8{0x03} ** 96,
        .index = 0,
    };
    try testing.expectEqual(@as(u64, 32_000_000_000), dr.amount);
}

test "WithdrawalRequest struct" {
    const wr = WithdrawalRequest{
        .source_address = [_]u8{0xaa} ** 20,
        .validator_pubkey = [_]u8{0xbb} ** 48,
        .amount = 1_000_000_000,
    };
    try testing.expectEqual(@as(u64, 1_000_000_000), wr.amount);
}

test "ConsolidationRequest struct" {
    const cr = ConsolidationRequest{
        .source_address = [_]u8{0x01} ** 20,
        .source_pubkey = [_]u8{0x02} ** 48,
        .target_pubkey = [_]u8{0x03} ** 48,
    };
    try testing.expectEqual([_]u8{0x01} ** 20, cr.source_address);
}
