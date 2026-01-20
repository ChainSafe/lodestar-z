const std = @import("std");
const ct = @import("consensus_types");
const ForkSeq = @import("config").ForkSeq;
const Allocator = std.mem.Allocator;
const Root = ct.primitive.Root.Type;
const ExecutionAddress = ct.primitive.ExecutionAddress;

// TODO Either make this a union(ForkSeq) or else remove the duplicate union branches
pub const ExecutionPayload = union(enum) {
    bellatrix: ct.bellatrix.ExecutionPayload.Type,
    capella: ct.capella.ExecutionPayload.Type,
    deneb: ct.deneb.ExecutionPayload.Type,
    electra: ct.electra.ExecutionPayload.Type,
    fulu: ct.fulu.ExecutionPayload.Type,

    /// Converts ExecutionPayload to an owned ExecutionPayloadHeader.
    pub fn toPayloadHeader(self: *const ExecutionPayload, allocator: Allocator) !ExecutionPayloadHeader {
        var header: ExecutionPayloadHeader = undefined;
        try self.createPayloadHeader(allocator, &header);
        return header;
    }

    /// Converts ExecutionPayload to ExecutionPayloadHeader.
    pub fn createPayloadHeader(self: *const ExecutionPayload, allocator: Allocator, out: *ExecutionPayloadHeader) !void {
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
            .electra => |payload| {
                out.* = .{ .electra = undefined };
                // Electra reuses Deneb execution payload types.
                try toExecutionPayloadHeader(
                    allocator,
                    ct.electra.ExecutionPayloadHeader.Type,
                    &payload,
                    &out.electra,
                );
                errdefer out.deinit(allocator);
                try ct.bellatrix.Transactions.hashTreeRoot(
                    allocator,
                    &payload.transactions,
                    &out.electra.transactions_root,
                );
                try ct.capella.Withdrawals.hashTreeRoot(
                    allocator,
                    &payload.withdrawals,
                    &out.electra.withdrawals_root,
                );
                out.electra.blob_gas_used = payload.blob_gas_used;
                out.electra.excess_blob_gas = payload.excess_blob_gas;
            },
            .fulu => |payload| {
                out.* = .{ .fulu = undefined };
                // Fulu reuses Electra (which reuses Deneb) execution payload types.
                try toExecutionPayloadHeader(
                    allocator,
                    ct.fulu.ExecutionPayloadHeader.Type,
                    &payload,
                    &out.fulu,
                );
                errdefer out.deinit(allocator);
                try ct.bellatrix.Transactions.hashTreeRoot(
                    allocator,
                    &payload.transactions,
                    &out.fulu.transactions_root,
                );
                try ct.capella.Withdrawals.hashTreeRoot(
                    allocator,
                    &payload.withdrawals,
                    &out.fulu.withdrawals_root,
                );
                out.fulu.blob_gas_used = payload.blob_gas_used;
                out.fulu.excess_blob_gas = payload.excess_blob_gas;
            },
        }
    }

    pub fn getParentHash(self: *const ExecutionPayload) Root {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra, .fulu => |payload| payload.parent_hash,
        };
    }

    pub fn getFeeRecipient(self: *const ExecutionPayload) ExecutionAddress {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra, .fulu => |payload| payload.fee_recipient,
        };
    }

    pub fn stateRoot(self: *const ExecutionPayload) Root {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra, .fulu => |payload| payload.state_root,
        };
    }

    pub fn getReceiptsRoot(self: *const ExecutionPayload) Root {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra, .fulu => |payload| payload.receipts_root,
        };
    }

    pub fn getLogsBloom(self: *const ExecutionPayload) ct.bellatrix.LogsBoom.Type {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra, .fulu => |payload| payload.logs_bloom,
        };
    }

    pub fn getPrevRandao(self: *const ExecutionPayload) Root {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra, .fulu => |payload| payload.prev_randao,
        };
    }

    pub fn getBlockNumber(self: *const ExecutionPayload) u64 {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra, .fulu => |payload| payload.block_number,
        };
    }

    pub fn getGasLimit(self: *const ExecutionPayload) u64 {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra, .fulu => |payload| payload.gas_limit,
        };
    }

    pub fn getGasUsed(self: *const ExecutionPayload) u64 {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra, .fulu => |payload| payload.gas_used,
        };
    }

    pub fn getTimestamp(self: *const ExecutionPayload) u64 {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra, .fulu => |payload| payload.timestamp,
        };
    }

    pub fn getExtraData(self: *const ExecutionPayload) ct.bellatrix.ExtraData.Type {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra, .fulu => |payload| payload.extra_data,
        };
    }

    pub fn getBaseFeePerGas(self: *const ExecutionPayload) u256 {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra, .fulu => |payload| payload.base_fee_per_gas,
        };
    }

    pub fn getBlockHash(self: *const ExecutionPayload) Root {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra, .fulu => |payload| payload.block_hash,
        };
    }

    pub fn getTransactions(self: *const ExecutionPayload) ct.bellatrix.Transactions.Type {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra, .fulu => |payload| payload.transactions,
        };
    }

    pub fn getWithdrawals(self: *const ExecutionPayload) ct.capella.Withdrawals.Type {
        return switch (self.*) {
            .bellatrix => @panic("Withdrawals are not available in bellatrix"),
            inline .capella, .deneb, .electra, .fulu => |payload| payload.withdrawals,
        };
    }

    pub fn getBlobGasUsed(self: *const ExecutionPayload) u64 {
        return switch (self.*) {
            inline .bellatrix, .capella => @panic("Blob gas used is not available in bellatrix or capella"),
            inline .deneb, .electra, .fulu => |payload| payload.blob_gas_used,
        };
    }

    pub fn getExcessBlobGas(self: *const ExecutionPayload) u64 {
        return switch (self.*) {
            inline .bellatrix, .capella => @panic("Excess blob gas is not available in bellatrix or capella"),
            inline .deneb, .electra, .fulu => |payload| payload.excess_blob_gas,
        };
    }
};

// TODO Either make this a union(ForkSeq) or else remove the duplicate union branches
pub const ExecutionPayloadHeader = union(enum) {
    bellatrix: ct.bellatrix.ExecutionPayloadHeader.Type,
    capella: ct.capella.ExecutionPayloadHeader.Type,
    deneb: ct.deneb.ExecutionPayloadHeader.Type,
    electra: ct.electra.ExecutionPayloadHeader.Type,
    fulu: ct.fulu.ExecutionPayloadHeader.Type,

    pub fn init(fork_seq: ForkSeq) !ExecutionPayloadHeader {
        return switch (fork_seq) {
            .bellatrix => .{ .bellatrix = ct.bellatrix.ExecutionPayloadHeader.default_value },
            .capella => .{ .capella = ct.capella.ExecutionPayloadHeader.default_value },
            .deneb => .{ .deneb = ct.deneb.ExecutionPayloadHeader.default_value },
            .electra => .{ .electra = ct.electra.ExecutionPayloadHeader.default_value },
            .fulu => .{ .fulu = ct.fulu.ExecutionPayloadHeader.default_value },
            else => error.UnexpectedForkSeq,
        };
    }

    pub fn getParentHash(self: *const ExecutionPayloadHeader) Root {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra, .fulu => |payload_header| payload_header.parent_hash,
        };
    }

    pub fn getFeeRecipient(self: *const ExecutionPayloadHeader) ExecutionAddress {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra, .fulu => |payload_header| payload_header.fee_recipient,
        };
    }

    pub fn stateRoot(self: *const ExecutionPayloadHeader) Root {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra, .fulu => |payload_header| payload_header.state_root,
        };
    }

    pub fn getReceiptsRoot(self: *const ExecutionPayloadHeader) Root {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra, .fulu => |payload_header| payload_header.receipts_root,
        };
    }

    pub fn getLogsBloom(self: *const ExecutionPayloadHeader) ct.bellatrix.LogsBoom.Type {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra, .fulu => |payload_header| payload_header.logs_bloom,
        };
    }

    pub fn getPrevRandao(self: *const ExecutionPayloadHeader) Root {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra, .fulu => |payload_header| payload_header.prev_randao,
        };
    }

    pub fn getBlockNumber(self: *const ExecutionPayloadHeader) u64 {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra, .fulu => |payload_header| payload_header.block_number,
        };
    }

    pub fn getGasLimit(self: *const ExecutionPayloadHeader) u64 {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra, .fulu => |payload_header| payload_header.gas_limit,
        };
    }

    pub fn getGasUsed(self: *const ExecutionPayloadHeader) u64 {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra, .fulu => |payload_header| payload_header.gas_used,
        };
    }

    pub fn getTimestamp(self: *const ExecutionPayloadHeader) u64 {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra, .fulu => |payload_header| payload_header.timestamp,
        };
    }

    pub fn getExtraData(self: *const ExecutionPayloadHeader) ct.bellatrix.ExtraData.Type {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra, .fulu => |payload_header| payload_header.extra_data,
        };
    }

    pub fn getBaseFeePerGas(self: *const ExecutionPayloadHeader) u256 {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra, .fulu => |payload_header| payload_header.base_fee_per_gas,
        };
    }

    pub fn getBlockHash(self: *const ExecutionPayloadHeader) Root {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra, .fulu => |payload_header| payload_header.block_hash,
        };
    }

    pub fn getTransactionsRoot(self: *const ExecutionPayloadHeader) Root {
        return switch (self.*) {
            inline .bellatrix, .capella, .deneb, .electra, .fulu => |payload_header| payload_header.transactions_root,
        };
    }

    pub fn getWithdrawalsRoot(self: *const ExecutionPayloadHeader) Root {
        return switch (self.*) {
            .bellatrix => @panic("Withdrawals are not available in bellatrix"),
            inline .capella, .deneb, .electra, .fulu => |payload_header| payload_header.withdrawals_root,
        };
    }

    pub fn getBlobGasUsed(self: *const ExecutionPayloadHeader) u64 {
        return switch (self.*) {
            inline .bellatrix, .capella => @panic("Blob gas used is not available in bellatrix or capella"),
            inline .deneb, .electra, .fulu => |payload_header| payload_header.blob_gas_used,
        };
    }

    pub fn getExcessBlobGas(self: *const ExecutionPayloadHeader) u64 {
        return switch (self.*) {
            inline .bellatrix, .capella => @panic("Excess blob gas is not available in bellatrix or capella"),
            inline .deneb, .electra, .fulu => |payload_header| payload_header.excess_blob_gas,
        };
    }

    pub fn clone(self: *const ExecutionPayloadHeader, allocator: Allocator, out: *ExecutionPayloadHeader) !void {
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
            .electra => |header| {
                try ct.electra.ExecutionPayloadHeader.clone(allocator, &header, &out.electra);
            },
            .fulu => |header| {
                try ct.fulu.ExecutionPayloadHeader.clone(allocator, &header, &out.fulu);
            },
        }
    }

    pub fn deinit(self: *ExecutionPayloadHeader, allocator: Allocator) void {
        switch (self.*) {
            .bellatrix => |*header| ct.bellatrix.ExecutionPayloadHeader.deinit(allocator, header),
            .capella => |*header| ct.capella.ExecutionPayloadHeader.deinit(allocator, header),
            .deneb => |*header| ct.deneb.ExecutionPayloadHeader.deinit(allocator, header),
            .electra => |*header| ct.electra.ExecutionPayloadHeader.deinit(allocator, header),
            .fulu => |*header| ct.fulu.ExecutionPayloadHeader.deinit(allocator, header),
        }
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
    const electra_payload: ExecutionPayload = .{ .electra = payload };
    const header_out = ct.electra.ExecutionPayloadHeader.default_value;
    var header: ExecutionPayloadHeader = .{ .electra = header_out };
    try electra_payload.createPayloadHeader(std.testing.allocator, &header);
    defer header.deinit(std.testing.allocator);
    _ = header.getGasUsed();
    try std.testing.expect(header.electra.block_number == payload.block_number);

    var owned_header = try electra_payload.toPayloadHeader(std.testing.allocator);
    defer owned_header.deinit(std.testing.allocator);
    try std.testing.expect(owned_header.electra.block_number == payload.block_number);
}
