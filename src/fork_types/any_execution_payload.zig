const std = @import("std");
const ct = @import("consensus_types");
const ForkSeq = @import("config").ForkSeq;
const Allocator = std.mem.Allocator;
const Root = ct.primitive.Root.Type;
const ExecutionAddress = ct.primitive.ExecutionAddress;

pub const AnyExecutionPayload = union(enum) {
    bellatrix: ct.bellatrix.ExecutionPayload.Type,
    capella: ct.capella.ExecutionPayload.Type,
    deneb: ct.deneb.ExecutionPayload.Type,

    /// Converts ExecutionPayload to ExecutionPayloadHeader.
    pub fn createPayloadHeader(self: *const AnyExecutionPayload, allocator: Allocator, out: *AnyExecutionPayloadHeader) !void {
        switch (self.*) {
            .bellatrix => |payload| {
                out.* = .{ .bellatrix = undefined };
                try toExecutionPayloadHeader(
                    allocator,
                    ct.bellatrix.ExecutionPayloadHeader.Type,
                    &payload,
                    &out.bellatrix,
                );
                errdefer out.deinit(allocator);
                try ct.bellatrix.Transactions.hashTreeRoot(
                    allocator,
                    &payload.transactions,
                    &out.bellatrix.transactions_root,
                );
            },
            .capella => |payload| {
                out.* = .{ .capella = undefined };
                try toExecutionPayloadHeader(
                    allocator,
                    ct.capella.ExecutionPayloadHeader.Type,
                    &payload,
                    &out.capella,
                );
                errdefer out.deinit(allocator);
                try ct.bellatrix.Transactions.hashTreeRoot(
                    allocator,
                    &payload.transactions,
                    &out.capella.transactions_root,
                );
                try ct.capella.Withdrawals.hashTreeRoot(
                    allocator,
                    &payload.withdrawals,
                    &out.capella.withdrawals_root,
                );
            },
            .deneb => |payload| {
                out.* = .{ .deneb = undefined };
                try toExecutionPayloadHeader(
                    allocator,
                    ct.deneb.ExecutionPayloadHeader.Type,
                    &payload,
                    &out.deneb,
                );
                errdefer out.deinit(allocator);
                try ct.bellatrix.Transactions.hashTreeRoot(
                    allocator,
                    &payload.transactions,
                    &out.deneb.transactions_root,
                );
                try ct.capella.Withdrawals.hashTreeRoot(
                    allocator,
                    &payload.withdrawals,
                    &out.deneb.withdrawals_root,
                );
                out.deneb.blob_gas_used = payload.blob_gas_used;
                out.deneb.excess_blob_gas = payload.excess_blob_gas;
            },
        }
    }

    pub fn getParentHash(self: *const AnyExecutionPayload) *const Root {
        return switch (self.*) {
            inline else => |*payload| &payload.parent_hash,
        };
    }

    pub fn getFeeRecipient(self: *const AnyExecutionPayload) *const ExecutionAddress {
        return switch (self.*) {
            inline else => |*payload| &payload.fee_recipient,
        };
    }

    pub fn stateRoot(self: *const AnyExecutionPayload) *const Root {
        return switch (self.*) {
            inline else => |*payload| &payload.state_root,
        };
    }

    pub fn getReceiptsRoot(self: *const AnyExecutionPayload) *const Root {
        return switch (self.*) {
            inline else => |*payload| &payload.receipts_root,
        };
    }

    pub fn getLogsBloom(self: *const AnyExecutionPayload) *const ct.bellatrix.LogsBloom.Type {
        return switch (self.*) {
            inline else => |*payload| &payload.logs_bloom,
        };
    }

    pub fn getPrevRandao(self: *const AnyExecutionPayload) *const Root {
        return switch (self.*) {
            inline else => |*payload| &payload.prev_randao,
        };
    }

    pub fn getBlockNumber(self: *const AnyExecutionPayload) u64 {
        return switch (self.*) {
            inline else => |payload| payload.block_number,
        };
    }

    pub fn getGasLimit(self: *const AnyExecutionPayload) u64 {
        return switch (self.*) {
            inline else => |payload| payload.gas_limit,
        };
    }

    pub fn getGasUsed(self: *const AnyExecutionPayload) u64 {
        return switch (self.*) {
            inline else => |payload| payload.gas_used,
        };
    }

    pub fn getTimestamp(self: *const AnyExecutionPayload) u64 {
        return switch (self.*) {
            inline else => |payload| payload.timestamp,
        };
    }

    pub fn getExtraData(self: *const AnyExecutionPayload) *const ct.bellatrix.ExtraData.Type {
        return switch (self.*) {
            inline else => |payload| payload.extra_data,
        };
    }

    pub fn getBaseFeePerGas(self: *const AnyExecutionPayload) u256 {
        return switch (self.*) {
            inline else => |payload| payload.base_fee_per_gas,
        };
    }

    pub fn getBlockHash(self: *const AnyExecutionPayload) *const Root {
        return switch (self.*) {
            inline else => |*payload| &payload.block_hash,
        };
    }

    pub fn getTransactions(self: *const AnyExecutionPayload) *const ct.bellatrix.Transactions.Type {
        return switch (self.*) {
            inline else => |*payload| &payload.transactions,
        };
    }

    pub fn getWithdrawals(self: *const AnyExecutionPayload) !*const ct.capella.Withdrawals.Type {
        return switch (self.*) {
            .bellatrix => return error.InvalidFork,
            inline else => |*payload| &payload.withdrawals,
        };
    }

    pub fn getBlobGasUsed(self: *const AnyExecutionPayload) !u64 {
        return switch (self.*) {
            inline .bellatrix, .capella => error.InvalidFork,
            inline else => |payload| payload.blob_gas_used,
        };
    }

    pub fn getExcessBlobGas(self: *const AnyExecutionPayload) !u64 {
        return switch (self.*) {
            inline .bellatrix, .capella => error.InvalidFork,
            inline else => |payload| payload.excess_blob_gas,
        };
    }
};

pub const AnyExecutionPayloadHeader = union(enum) {
    bellatrix: ct.bellatrix.ExecutionPayloadHeader.Type,
    capella: ct.capella.ExecutionPayloadHeader.Type,
    deneb: ct.deneb.ExecutionPayloadHeader.Type,

    pub fn init(fork_seq: ForkSeq) !AnyExecutionPayloadHeader {
        return switch (fork_seq) {
            .bellatrix => .{ .bellatrix = ct.bellatrix.ExecutionPayloadHeader.default_value },
            .capella => .{ .capella = ct.capella.ExecutionPayloadHeader.default_value },
            .deneb, .electra, .fulu => .{ .deneb = ct.deneb.ExecutionPayloadHeader.default_value },
            else => error.UnexpectedForkSeq,
        };
    }

    pub fn deinit(self: *AnyExecutionPayloadHeader, allocator: Allocator) void {
        switch (self.*) {
            .bellatrix => |*header| ct.bellatrix.ExecutionPayloadHeader.deinit(allocator, header),
            .capella => |*header| ct.capella.ExecutionPayloadHeader.deinit(allocator, header),
            .deneb => |*header| ct.deneb.ExecutionPayloadHeader.deinit(allocator, header),
        }
    }

    pub fn clone(self: *const AnyExecutionPayloadHeader, allocator: Allocator, out: *AnyExecutionPayloadHeader) !void {
        switch (self.*) {
            .bellatrix => |header| {
                try ct.bellatrix.ExecutionPayloadHeader.clone(allocator, &header, &out.bellatrix);
            },
            .capella => |header| {
                try ct.capella.ExecutionPayloadHeader.clone(allocator, &header, &out.capella);
            },
            .deneb => |header| {
                try ct.deneb.ExecutionPayloadHeader.clone(allocator, &header, &out.deneb);
            },
        }
    }

    pub fn getParentHash(self: *const AnyExecutionPayloadHeader) Root {
        return switch (self.*) {
            inline else => |payload_header| payload_header.parent_hash,
        };
    }

    pub fn getFeeRecipient(self: *const AnyExecutionPayloadHeader) ExecutionAddress {
        return switch (self.*) {
            inline else => |payload_header| payload_header.fee_recipient,
        };
    }

    pub fn stateRoot(self: *const AnyExecutionPayloadHeader) Root {
        return switch (self.*) {
            inline else => |payload_header| payload_header.state_root,
        };
    }

    pub fn getReceiptsRoot(self: *const AnyExecutionPayloadHeader) Root {
        return switch (self.*) {
            inline else => |payload_header| payload_header.receipts_root,
        };
    }

    pub fn getLogsBloom(self: *const AnyExecutionPayloadHeader) ct.bellatrix.LogsBoom.Type {
        return switch (self.*) {
            inline else => |payload_header| payload_header.logs_bloom,
        };
    }

    pub fn getPrevRandao(self: *const AnyExecutionPayloadHeader) Root {
        return switch (self.*) {
            inline else => |payload_header| payload_header.prev_randao,
        };
    }

    pub fn getBlockNumber(self: *const AnyExecutionPayloadHeader) u64 {
        return switch (self.*) {
            inline else => |payload_header| payload_header.block_number,
        };
    }

    pub fn getGasLimit(self: *const AnyExecutionPayloadHeader) u64 {
        return switch (self.*) {
            inline else => |payload_header| payload_header.gas_limit,
        };
    }

    pub fn getGasUsed(self: *const AnyExecutionPayloadHeader) u64 {
        return switch (self.*) {
            inline else => |payload_header| payload_header.gas_used,
        };
    }

    pub fn getTimestamp(self: *const AnyExecutionPayloadHeader) u64 {
        return switch (self.*) {
            inline else => |payload_header| payload_header.timestamp,
        };
    }

    pub fn getExtraData(self: *const AnyExecutionPayloadHeader) ct.bellatrix.ExtraData.Type {
        return switch (self.*) {
            inline else => |payload_header| payload_header.extra_data,
        };
    }

    pub fn getBaseFeePerGas(self: *const AnyExecutionPayloadHeader) u256 {
        return switch (self.*) {
            inline else => |payload_header| payload_header.base_fee_per_gas,
        };
    }

    pub fn getBlockHash(self: *const AnyExecutionPayloadHeader) Root {
        return switch (self.*) {
            inline else => |payload_header| payload_header.block_hash,
        };
    }

    pub fn getTransactionsRoot(self: *const AnyExecutionPayloadHeader) Root {
        return switch (self.*) {
            inline else => |payload_header| payload_header.transactions_root,
        };
    }

    pub fn getWithdrawalsRoot(self: *const AnyExecutionPayloadHeader) Root {
        return switch (self.*) {
            .bellatrix => @panic("Withdrawals are not available in bellatrix"),
            inline else => |payload_header| payload_header.withdrawals_root,
        };
    }

    pub fn getBlobGasUsed(self: *const AnyExecutionPayloadHeader) u64 {
        return switch (self.*) {
            inline .bellatrix, .capella => @panic("Blob gas used is not available in bellatrix or capella"),
            inline else => |payload_header| payload_header.blob_gas_used,
        };
    }

    pub fn getExcessBlobGas(self: *const AnyExecutionPayloadHeader) u64 {
        return switch (self.*) {
            inline .bellatrix, .capella => @panic("Excess blob gas is not available in bellatrix or capella"),
            inline else => |payload_header| payload_header.excess_blob_gas,
        };
    }
};

/// Converts some basic fields of ExecutionPayload to ExecutionPayloadHeader.
/// Can also be used to upgrade between different ExecutionPayloadHeader versions.
/// Writes the fields directly into the provided result pointer.
pub fn toExecutionPayloadHeader(
    allocator: Allocator,
    comptime execution_payload_header_type: type,
    payload: anytype,
    result: *execution_payload_header_type,
) !void {
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
    if (@hasField(@TypeOf(payload.*), "transactions_root")) {
        result.transactions_root = payload.transactions_root;
    }
    if (@hasField(@TypeOf(payload.*), "withdrawals_root")) {
        result.withdrawals_root = payload.withdrawals_root;
    }
    // remaining fields are left unset
}

test "electra - sanity" {
    const payload = ct.electra.ExecutionPayload.Type{
        .parent_hash = ct.primitive.Root.default_value,
        .fee_recipient = ct.primitive.Bytes20.default_value,
        .state_root = ct.primitive.Root.default_value,
        .receipts_root = ct.primitive.Root.default_value,
        .logs_bloom = ct.bellatrix.LogsBloom.default_value,
        .prev_randao = ct.primitive.Root.default_value,
        .block_number = 12345,
        .gas_limit = 0,
        .gas_used = 0,
        .timestamp = 0,
        .extra_data = ct.bellatrix.ExtraData.default_value,
        .base_fee_per_gas = 0,
        .block_hash = ct.primitive.Root.default_value,
        .transactions = ct.bellatrix.Transactions.Type{},
        .withdrawals = ct.capella.Withdrawals.Type{},
        .blob_gas_used = 0,
        .excess_blob_gas = 0,
    };
    const electra_payload: AnyExecutionPayload = .{ .deneb = payload };
    const header_out = ct.electra.ExecutionPayloadHeader.default_value;
    var header: AnyExecutionPayloadHeader = .{ .deneb = header_out };
    try electra_payload.createPayloadHeader(std.testing.allocator, &header);
    defer header.deinit(std.testing.allocator);
    _ = header.getGasUsed();
    try std.testing.expect(header.deneb.block_number == payload.block_number);
}
