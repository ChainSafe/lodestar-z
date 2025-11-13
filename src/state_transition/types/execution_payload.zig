const std = @import("std");
const types = @import("consensus_types");
const Allocator = std.mem.Allocator;
const Root = types.primitive.Root.Type;
const ExecutionAddress = types.primitive.ExecutionAddress;

pub const ExecutionPayload = union(enum) {
    bellatrix: *const types.bellatrix.ExecutionPayload.Type,
    capella: *const types.capella.ExecutionPayload.Type,
    deneb: *const types.deneb.ExecutionPayload.Type,
    electra: *const types.electra.ExecutionPayload.Type,

    pub fn isCapellaPayload(self: *const ExecutionPayload) bool {
        return switch (self.*) {
            .bellatrix => false,
            else => true,
        };
    }

    // consumer don't have to deinit

    pub fn toPayloadHeader(self: *const ExecutionPayload, allocator: Allocator) !ExecutionPayloadHeader {
        return switch (self.*) {
            .bellatrix => |payload| {
                var header = try toExecutionPayloadHeader(
                    allocator,
                    types.bellatrix.ExecutionPayloadHeader.Type,
                    payload,
                );
                errdefer header.extra_data.deinit(allocator);
                try types.bellatrix.Transactions.hashTreeRoot(allocator, &payload.transactions, &header.transactions_root);
                return .{
                    .bellatrix = &header,
                };
            },
            .capella => |payload| {
                var header = try toExecutionPayloadHeader(
                    allocator,
                    types.capella.ExecutionPayloadHeader.Type,
                    payload,
                );
                errdefer header.extra_data.deinit(allocator);
                try types.bellatrix.Transactions.hashTreeRoot(allocator, &payload.transactions, &header.transactions_root);
                try types.capella.Withdrawals.hashTreeRoot(allocator, &payload.withdrawals, &header.withdrawals_root);
                return .{
                    .capella = &header,
                };
            },
            .deneb => |payload| {
                var header = try toExecutionPayloadHeader(
                    allocator,
                    types.deneb.ExecutionPayloadHeader.Type,
                    payload,
                );
                errdefer header.extra_data.deinit(allocator);
                try types.bellatrix.Transactions.hashTreeRoot(allocator, &payload.transactions, &header.transactions_root);
                try types.capella.Withdrawals.hashTreeRoot(allocator, &payload.withdrawals, &header.withdrawals_root);
                header.blob_gas_used = payload.blob_gas_used;
                header.excess_blob_gas = payload.excess_blob_gas;
                return .{
                    .deneb = &header,
                };
            },
            .electra => |payload| {
                // TODO: dedup to deneb?
                var header = try toExecutionPayloadHeader(
                    allocator,
                    types.electra.ExecutionPayloadHeader.Type,
                    payload,
                );
                errdefer header.extra_data.deinit(allocator);
                try types.bellatrix.Transactions.hashTreeRoot(allocator, &payload.transactions, &header.transactions_root);
                try types.capella.Withdrawals.hashTreeRoot(allocator, &payload.withdrawals, &header.withdrawals_root);
                header.blob_gas_used = payload.blob_gas_used;
                header.excess_blob_gas = payload.excess_blob_gas;
                return .{
                    .electra = &header,
                };
            },
        };
    }

    pub fn getParentHash(self: *const ExecutionPayload) Root {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra => |payload| payload.parent_hash,
        };
    }

    pub fn getFeeRecipient(self: *const ExecutionPayload) ExecutionAddress {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra => |payload| payload.fee_recipient,
        };
    }

    pub fn stateRoot(self: *const ExecutionPayload) Root {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra => |payload| payload.state_root,
        };
    }

    pub fn getReceiptsRoot(self: *const ExecutionPayload) Root {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra => |payload| payload.receipts_root,
        };
    }

    pub fn getLogsBloom(self: *const ExecutionPayload) types.bellatrix.LogsBoom.Type {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra => |payload| payload.logs_bloom,
        };
    }

    pub fn getPrevRandao(self: *const ExecutionPayload) Root {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra => |payload| payload.prev_randao,
        };
    }

    pub fn getBlockNumber(self: *const ExecutionPayload) u64 {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra => |payload| payload.block_number,
        };
    }

    pub fn getGasLimit(self: *const ExecutionPayload) u64 {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra => |payload| payload.gas_limit,
        };
    }

    pub fn getGasUsed(self: *const ExecutionPayload) u64 {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra => |payload| payload.gas_used,
        };
    }

    pub fn getTimestamp(self: *const ExecutionPayload) u64 {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra => |payload| payload.timestamp,
        };
    }

    pub fn getExtraData(self: *const ExecutionPayload) types.bellatrix.ExtraData.Type {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra => |payload| payload.extra_data,
        };
    }

    pub fn getBaseFeePerGas(self: *const ExecutionPayload) u256 {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra => |payload| payload.base_fee_per_gas,
        };
    }

    pub fn getBlockHash(self: *const ExecutionPayload) Root {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra => |payload| payload.block_hash,
        };
    }

    pub fn getTransactions(self: *const ExecutionPayload) types.bellatrix.Transactions.Type {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra => |payload| payload.transactions,
        };
    }

    pub fn getWithdrawals(self: *const ExecutionPayload) types.capella.Withdrawals.Type {
        return switch (self.*) {
            .bellatrix => @panic("Withdrawals are not available in bellatrix"),
            inline .capella, .deneb, .electra => |payload| payload.withdrawals,
        };
    }

    pub fn getBlobGasUsed(self: *const ExecutionPayload) u64 {
        return switch (self.*) {
            inline .bellatrix, .capella => @panic("Blob gas used is not available in bellatrix or capella"),
            inline .deneb, .electra => |payload| payload.blob_gas_used,
        };
    }

    pub fn getExcessBlobGas(self: *const ExecutionPayload) u64 {
        return switch (self.*) {
            inline .bellatrix, .capella => @panic("Excess blob gas is not available in bellatrix or capella"),
            inline .deneb, .electra => |payload| payload.excess_blob_gas,
        };
    }
};

pub const ExecutionPayloadHeader = union(enum) {
    bellatrix: *const types.bellatrix.ExecutionPayloadHeader.Type,
    capella: *const types.capella.ExecutionPayloadHeader.Type,
    deneb: *const types.deneb.ExecutionPayloadHeader.Type,
    electra: *const types.electra.ExecutionPayloadHeader.Type,

    pub fn isCapellaPayloadHeader(self: *const ExecutionPayloadHeader) bool {
        return switch (self.*) {
            .bellatrix => false,
            else => true,
        };
    }

    pub fn getParentHash(self: *const ExecutionPayloadHeader) Root {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra => |payload_header| payload_header.parent_hash,
        };
    }

    pub fn getFeeRecipient(self: *const ExecutionPayloadHeader) ExecutionAddress {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra => |payload_header| payload_header.fee_recipient,
        };
    }

    pub fn stateRoot(self: *const ExecutionPayloadHeader) Root {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra => |payload_header| payload_header.state_root,
        };
    }

    pub fn getReceiptsRoot(self: *const ExecutionPayloadHeader) Root {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra => |payload_header| payload_header.receipts_root,
        };
    }

    pub fn getLogsBloom(self: *const ExecutionPayloadHeader) types.bellatrix.LogsBoom.Type {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra => |payload_header| payload_header.logs_bloom,
        };
    }

    pub fn getPrevRandao(self: *const ExecutionPayloadHeader) Root {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra => |payload_header| payload_header.prev_randao,
        };
    }

    pub fn getBlockNumber(self: *const ExecutionPayloadHeader) u64 {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra => |payload_header| payload_header.block_number,
        };
    }

    pub fn getGasLimit(self: *const ExecutionPayloadHeader) u64 {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra => |payload_header| payload_header.gas_limit,
        };
    }

    pub fn getGasUsed(self: *const ExecutionPayloadHeader) u64 {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra => |payload_header| payload_header.gas_used,
        };
    }

    pub fn getTimestamp(self: *const ExecutionPayloadHeader) u64 {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra => |payload_header| payload_header.timestamp,
        };
    }

    pub fn getExtraData(self: *const ExecutionPayloadHeader) types.bellatrix.ExtraData.Type {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra => |payload_header| payload_header.extra_data,
        };
    }

    pub fn getBaseFeePerGas(self: *const ExecutionPayloadHeader) u256 {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra => |payload_header| payload_header.base_fee_per_gas,
        };
    }

    pub fn getBlockHash(self: *const ExecutionPayloadHeader) Root {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra => |payload_header| payload_header.block_hash,
        };
    }

    pub fn getTransactionsRoot(self: *const ExecutionPayloadHeader) Root {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra => |payload_header| payload_header.transactions_root,
        };
    }

    pub fn getWithdrawalsRoot(self: *const ExecutionPayloadHeader) Root {
        return switch (self.*) {
            .bellatrix => @panic("Withdrawals are not available in bellatrix"),
            inline .capella, .deneb, .electra => |payload_header| payload_header.withdrawals_root,
        };
    }

    pub fn getBlobGasUsed(self: *const ExecutionPayloadHeader) u64 {
        return switch (self.*) {
            inline .bellatrix, .capella => @panic("Blob gas used is not available in bellatrix or capella"),
            inline .deneb, .electra => |payload_header| payload_header.blob_gas_used,
        };
    }

    pub fn getExcessBlobGas(self: *const ExecutionPayloadHeader) u64 {
        return switch (self.*) {
            inline .bellatrix, .capella => @panic("Excess blob gas is not available in bellatrix or capella"),
            inline .deneb, .electra => |payload_header| payload_header.excess_blob_gas,
        };
    }
};

/// Converts some basic fields of ExecutionPayload to ExecutionPayloadHeader.
pub fn toExecutionPayloadHeader(
    allocator: Allocator,
    comptime execution_payload_header_type: type,
    payload: anytype,
) !execution_payload_header_type {
    var result: execution_payload_header_type = undefined;

    result.parent_hash = payload.parent_hash;
    result.fee_recipient = payload.fee_recipient;
    result.state_root = payload.state_root;
    result.receipts_root = payload.receipts_root;
    result.logs_bloom = payload.logs_bloom;
    result.prev_randao = payload.prev_randao;
    result.block_number = payload.block_number;
    result.gas_limit = payload.gas_limit;
    result.gas_used = payload.gas_used;
    result.timestamp = payload.timestamp;
    result.extra_data = try payload.extra_data.clone(allocator);
    result.base_fee_per_gas = payload.base_fee_per_gas;
    result.block_hash = payload.block_hash;
    // remaining fields are left unset

    return result;
}

test "electra - sanity" {
    const payload = types.electra.ExecutionPayload.Type{
        .parent_hash = types.primitive.Root.default_value,
        .fee_recipient = types.primitive.Bytes20.default_value,
        .state_root = types.primitive.Root.default_value,
        .receipts_root = types.primitive.Root.default_value,
        .logs_bloom = types.bellatrix.LogsBloom.default_value,
        .prev_randao = types.primitive.Root.default_value,
        .block_number = 12345,
        .gas_limit = 0,
        .gas_used = 0,
        .timestamp = 0,
        .extra_data = types.bellatrix.ExtraData.default_value,
        .base_fee_per_gas = 0,
        .block_hash = types.primitive.Root.default_value,
        .transactions = types.bellatrix.Transactions.Type{},
        .withdrawals = types.capella.Withdrawals.Type{},
        .blob_gas_used = 0,
        .excess_blob_gas = 0,
    };
    const electra_payload: ExecutionPayload = .{ .electra = &payload };
    const header: ExecutionPayloadHeader =
        try electra_payload.toPayloadHeader(std.testing.allocator);
    _ = header.getGasUsed();
    try std.testing.expect(header.electra.block_number == payload.block_number);
}
