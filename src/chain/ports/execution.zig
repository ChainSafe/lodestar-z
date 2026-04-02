//! Chain-owned execution payload submission port.
//!
//! This models the semantic CL -> EL boundary for `engine_newPayload` calls.
//! The chain constructs an explicit request from consensus data, outer
//! runtimes submit it to the execution layer, and the chain consumes the
//! structured result to drive optimistic / invalidation semantics.

const std = @import("std");

const constants = @import("constants");
const execution_mod = @import("execution");
const fork_types = @import("fork_types");

const AnyExecutionPayload = fork_types.AnyExecutionPayload;
const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;
const AnyBeaconBlockBody = fork_types.AnyBeaconBlockBody;

const DepositRequest = execution_mod.engine_api_types.DepositRequest;
const WithdrawalRequest = execution_mod.engine_api_types.WithdrawalRequest;
const ConsolidationRequest = execution_mod.engine_api_types.ConsolidationRequest;
const Withdrawal = execution_mod.engine_api_types.Withdrawal;
const ExecutionPayloadV1 = execution_mod.engine_api_types.ExecutionPayloadV1;
const ExecutionPayloadV2 = execution_mod.engine_api_types.ExecutionPayloadV2;
const ExecutionPayloadV3 = execution_mod.engine_api_types.ExecutionPayloadV3;
const ExecutionPayloadV4 = execution_mod.engine_api_types.ExecutionPayloadV4;

const Allocator = std.mem.Allocator;
const Root = [32]u8;

pub const BellatrixRequest = struct {
    payload: ExecutionPayloadV1,
    extra_data: []const u8,
    transactions: []const []const u8,

    pub fn deinit(self: *BellatrixRequest, allocator: Allocator) void {
        freeTransactions(allocator, self.transactions);
        allocator.free(self.extra_data);
        self.* = undefined;
    }
};

pub const CapellaRequest = struct {
    payload: ExecutionPayloadV2,
    extra_data: []const u8,
    transactions: []const []const u8,
    withdrawals: []const Withdrawal,

    pub fn deinit(self: *CapellaRequest, allocator: Allocator) void {
        allocator.free(self.withdrawals);
        freeTransactions(allocator, self.transactions);
        allocator.free(self.extra_data);
        self.* = undefined;
    }
};

pub const DenebRequest = struct {
    payload: ExecutionPayloadV3,
    extra_data: []const u8,
    transactions: []const []const u8,
    withdrawals: []const Withdrawal,
    versioned_hashes: []const Root,
    parent_beacon_block_root: Root,

    pub fn deinit(self: *DenebRequest, allocator: Allocator) void {
        allocator.free(self.versioned_hashes);
        allocator.free(self.withdrawals);
        freeTransactions(allocator, self.transactions);
        allocator.free(self.extra_data);
        self.* = undefined;
    }
};

pub const ElectraRequest = struct {
    payload: ExecutionPayloadV4,
    extra_data: []const u8,
    transactions: []const []const u8,
    withdrawals: []const Withdrawal,
    deposit_requests: []const DepositRequest,
    withdrawal_requests: []const WithdrawalRequest,
    consolidation_requests: []const ConsolidationRequest,
    versioned_hashes: []const Root,
    parent_beacon_block_root: Root,

    pub fn deinit(self: *ElectraRequest, allocator: Allocator) void {
        allocator.free(self.versioned_hashes);
        allocator.free(self.consolidation_requests);
        allocator.free(self.withdrawal_requests);
        allocator.free(self.deposit_requests);
        allocator.free(self.withdrawals);
        freeTransactions(allocator, self.transactions);
        allocator.free(self.extra_data);
        self.* = undefined;
    }
};

pub const NewPayloadRequest = union(enum) {
    bellatrix: BellatrixRequest,
    capella: CapellaRequest,
    deneb: DenebRequest,
    electra: ElectraRequest,

    pub fn deinit(self: *NewPayloadRequest, allocator: Allocator) void {
        switch (self.*) {
            .bellatrix => |*req| req.deinit(allocator),
            .capella => |*req| req.deinit(allocator),
            .deneb => |*req| req.deinit(allocator),
            .electra => |*req| req.deinit(allocator),
        }
    }

    pub fn blockHash(self: NewPayloadRequest) Root {
        return switch (self) {
            .bellatrix => |req| req.payload.block_hash,
            .capella => |req| req.payload.block_hash,
            .deneb => |req| req.payload.block_hash,
            .electra => |req| req.payload.block_hash,
        };
    }
};

pub const NewPayloadResult = union(enum) {
    valid: struct {
        latest_valid_hash: Root,
    },
    invalid: struct {
        latest_valid_hash: ?Root,
    },
    syncing: void,
    accepted: void,
    invalid_block_hash: struct {
        latest_valid_hash: ?Root,
    },
    unavailable: void,
};

pub const ExecutionPort = struct {
    ptr: *anyopaque,
    submitNewPayloadFn: *const fn (
        ptr: *anyopaque,
        request: NewPayloadRequest,
    ) NewPayloadResult,

    pub fn submitNewPayload(self: ExecutionPort, request: NewPayloadRequest) NewPayloadResult {
        return self.submitNewPayloadFn(self.ptr, request);
    }
};

// Compatibility alias while callers are migrated.
pub const ExecutionVerifier = ExecutionPort;

pub fn makeNewPayloadRequest(
    allocator: Allocator,
    block: AnySignedBeaconBlock,
) !?NewPayloadRequest {
    const beacon_block = block.beaconBlock();
    const body = beacon_block.beaconBlockBody();
    const execution_payload = body.executionPayload() catch return null;

    return switch (block.forkSeq()) {
        .phase0, .altair, .gloas => null,
        .bellatrix => .{ .bellatrix = try prepareBellatrixRequest(allocator, execution_payload) },
        .capella => .{ .capella = try prepareCapellaRequest(allocator, execution_payload) },
        .deneb => .{ .deneb = try prepareDenebRequest(allocator, execution_payload, body, beacon_block.parentRoot().*) },
        .electra, .fulu => .{ .electra = try prepareElectraRequest(allocator, execution_payload, body, beacon_block.parentRoot().*) },
    };
}

fn prepareBellatrixRequest(
    allocator: Allocator,
    payload: AnyExecutionPayload,
) !BellatrixRequest {
    const extra_data = try allocator.dupe(u8, payload.extraData().items);
    errdefer allocator.free(extra_data);
    const transactions = try convertTransactions(allocator, payload);
    errdefer freeTransactions(allocator, transactions);

    return .{
        .payload = .{
            .parent_hash = payload.parentHash().*,
            .fee_recipient = payload.feeRecipient().*,
            .state_root = payload.stateRoot().*,
            .receipts_root = payload.receiptsRoot().*,
            .logs_bloom = payload.logsBloom().*,
            .prev_randao = payload.prevRandao().*,
            .block_number = payload.blockNumber(),
            .gas_limit = payload.gasLimit(),
            .gas_used = payload.gasUsed(),
            .timestamp = payload.timestamp(),
            .extra_data = extra_data,
            .base_fee_per_gas = payload.baseFeePerGas(),
            .block_hash = payload.blockHash().*,
            .transactions = transactions,
        },
        .extra_data = extra_data,
        .transactions = transactions,
    };
}

fn prepareCapellaRequest(
    allocator: Allocator,
    payload: AnyExecutionPayload,
) !CapellaRequest {
    const extra_data = try allocator.dupe(u8, payload.extraData().items);
    errdefer allocator.free(extra_data);
    const transactions = try convertTransactions(allocator, payload);
    errdefer freeTransactions(allocator, transactions);
    const withdrawals = try convertWithdrawals(allocator, payload);
    errdefer allocator.free(withdrawals);

    return .{
        .payload = .{
            .parent_hash = payload.parentHash().*,
            .fee_recipient = payload.feeRecipient().*,
            .state_root = payload.stateRoot().*,
            .receipts_root = payload.receiptsRoot().*,
            .logs_bloom = payload.logsBloom().*,
            .prev_randao = payload.prevRandao().*,
            .block_number = payload.blockNumber(),
            .gas_limit = payload.gasLimit(),
            .gas_used = payload.gasUsed(),
            .timestamp = payload.timestamp(),
            .extra_data = extra_data,
            .base_fee_per_gas = payload.baseFeePerGas(),
            .block_hash = payload.blockHash().*,
            .transactions = transactions,
            .withdrawals = withdrawals,
        },
        .extra_data = extra_data,
        .transactions = transactions,
        .withdrawals = withdrawals,
    };
}

fn prepareDenebRequest(
    allocator: Allocator,
    payload: AnyExecutionPayload,
    body: AnyBeaconBlockBody,
    parent_beacon_block_root: Root,
) !DenebRequest {
    const extra_data = try allocator.dupe(u8, payload.extraData().items);
    errdefer allocator.free(extra_data);
    const transactions = try convertTransactions(allocator, payload);
    errdefer freeTransactions(allocator, transactions);
    const withdrawals = try convertWithdrawals(allocator, payload);
    errdefer allocator.free(withdrawals);
    const versioned_hashes = try convertVersionedHashes(allocator, body);
    errdefer allocator.free(versioned_hashes);

    return .{
        .payload = .{
            .parent_hash = payload.parentHash().*,
            .fee_recipient = payload.feeRecipient().*,
            .state_root = payload.stateRoot().*,
            .receipts_root = payload.receiptsRoot().*,
            .logs_bloom = payload.logsBloom().*,
            .prev_randao = payload.prevRandao().*,
            .block_number = payload.blockNumber(),
            .gas_limit = payload.gasLimit(),
            .gas_used = payload.gasUsed(),
            .timestamp = payload.timestamp(),
            .extra_data = extra_data,
            .base_fee_per_gas = payload.baseFeePerGas(),
            .block_hash = payload.blockHash().*,
            .transactions = transactions,
            .withdrawals = withdrawals,
            .blob_gas_used = try payload.blobGasUsed(),
            .excess_blob_gas = try payload.excessBlobGas(),
        },
        .extra_data = extra_data,
        .transactions = transactions,
        .withdrawals = withdrawals,
        .versioned_hashes = versioned_hashes,
        .parent_beacon_block_root = parent_beacon_block_root,
    };
}

fn prepareElectraRequest(
    allocator: Allocator,
    payload: AnyExecutionPayload,
    body: AnyBeaconBlockBody,
    parent_beacon_block_root: Root,
) !ElectraRequest {
    const extra_data = try allocator.dupe(u8, payload.extraData().items);
    errdefer allocator.free(extra_data);
    const transactions = try convertTransactions(allocator, payload);
    errdefer freeTransactions(allocator, transactions);
    const withdrawals = try convertWithdrawals(allocator, payload);
    errdefer allocator.free(withdrawals);
    const versioned_hashes = try convertVersionedHashes(allocator, body);
    errdefer allocator.free(versioned_hashes);
    const deposit_requests = try convertDepositRequests(allocator, body);
    errdefer allocator.free(deposit_requests);
    const withdrawal_requests = try convertWithdrawalRequests(allocator, body);
    errdefer allocator.free(withdrawal_requests);
    const consolidation_requests = try convertConsolidationRequests(allocator, body);
    errdefer allocator.free(consolidation_requests);

    return .{
        .payload = .{
            .parent_hash = payload.parentHash().*,
            .fee_recipient = payload.feeRecipient().*,
            .state_root = payload.stateRoot().*,
            .receipts_root = payload.receiptsRoot().*,
            .logs_bloom = payload.logsBloom().*,
            .prev_randao = payload.prevRandao().*,
            .block_number = payload.blockNumber(),
            .gas_limit = payload.gasLimit(),
            .gas_used = payload.gasUsed(),
            .timestamp = payload.timestamp(),
            .extra_data = extra_data,
            .base_fee_per_gas = payload.baseFeePerGas(),
            .block_hash = payload.blockHash().*,
            .transactions = transactions,
            .withdrawals = withdrawals,
            .blob_gas_used = try payload.blobGasUsed(),
            .excess_blob_gas = try payload.excessBlobGas(),
            .deposit_requests = deposit_requests,
            .withdrawal_requests = withdrawal_requests,
            .consolidation_requests = consolidation_requests,
        },
        .extra_data = extra_data,
        .transactions = transactions,
        .withdrawals = withdrawals,
        .deposit_requests = deposit_requests,
        .withdrawal_requests = withdrawal_requests,
        .consolidation_requests = consolidation_requests,
        .versioned_hashes = versioned_hashes,
        .parent_beacon_block_root = parent_beacon_block_root,
    };
}

fn convertTransactions(
    allocator: Allocator,
    payload: AnyExecutionPayload,
) ![]const []const u8 {
    const txs = payload.transactions().items;
    const out = try allocator.alloc([]const u8, txs.len);
    errdefer allocator.free(out);

    var i: usize = 0;
    errdefer {
        for (out[0..i]) |tx| allocator.free(tx);
    }

    for (txs, 0..) |tx, idx| {
        out[idx] = try allocator.dupe(u8, tx.items);
        i = idx + 1;
    }
    return out;
}

fn freeTransactions(allocator: Allocator, transactions: []const []const u8) void {
    for (transactions) |tx| allocator.free(tx);
    allocator.free(transactions);
}

fn convertWithdrawals(
    allocator: Allocator,
    payload: AnyExecutionPayload,
) ![]const Withdrawal {
    const withdrawals_in = (payload.withdrawals() catch return try allocator.alloc(Withdrawal, 0)).items;
    const out = try allocator.alloc(Withdrawal, withdrawals_in.len);
    errdefer allocator.free(out);

    for (withdrawals_in, 0..) |withdrawal, i| {
        out[i] = .{
            .index = withdrawal.index,
            .validator_index = withdrawal.validator_index,
            .address = withdrawal.address,
            .amount = withdrawal.amount,
        };
    }

    return out;
}

fn convertVersionedHashes(
    allocator: Allocator,
    body: AnyBeaconBlockBody,
) ![]const Root {
    const commitments = (try body.blobKzgCommitments()).items;
    const out = try allocator.alloc(Root, commitments.len);
    errdefer allocator.free(out);

    for (commitments, 0..) |commitment, i| {
        out[i] = kzgCommitmentToVersionedHash(commitment);
    }
    return out;
}

fn convertDepositRequests(
    allocator: Allocator,
    body: AnyBeaconBlockBody,
) ![]const DepositRequest {
    const requests = body.depositRequests() catch return try allocator.alloc(DepositRequest, 0);
    const out = try allocator.alloc(DepositRequest, requests.len);
    errdefer allocator.free(out);

    for (requests, 0..) |request, i| {
        out[i] = .{
            .pubkey = request.pubkey,
            .withdrawal_credentials = request.withdrawal_credentials,
            .amount = request.amount,
            .signature = request.signature,
            .index = request.index,
        };
    }
    return out;
}

fn convertWithdrawalRequests(
    allocator: Allocator,
    body: AnyBeaconBlockBody,
) ![]const WithdrawalRequest {
    const requests = body.withdrawalRequests() catch return try allocator.alloc(WithdrawalRequest, 0);
    const out = try allocator.alloc(WithdrawalRequest, requests.len);
    errdefer allocator.free(out);

    for (requests, 0..) |request, i| {
        out[i] = .{
            .source_address = request.source_address,
            .validator_pubkey = request.validator_pubkey,
            .amount = request.amount,
        };
    }
    return out;
}

fn convertConsolidationRequests(
    allocator: Allocator,
    body: AnyBeaconBlockBody,
) ![]const ConsolidationRequest {
    const requests = body.consolidationRequests() catch return try allocator.alloc(ConsolidationRequest, 0);
    const out = try allocator.alloc(ConsolidationRequest, requests.len);
    errdefer allocator.free(out);

    for (requests, 0..) |request, i| {
        out[i] = .{
            .source_address = request.source_address,
            .source_pubkey = request.source_pubkey,
            .target_pubkey = request.target_pubkey,
        };
    }
    return out;
}

fn kzgCommitmentToVersionedHash(commitment: [48]u8) Root {
    var hash: Root = undefined;
    std.crypto.hash.sha2.Sha256.hash(&commitment, &hash, .{});
    hash[0] = constants.VERSIONED_HASH_VERSION_KZG;
    return hash;
}
