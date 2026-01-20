const std = @import("std");
const Allocator = std.mem.Allocator;
const preset = @import("preset").preset;
const ForkSeq = @import("config").ForkSeq;
const Node = @import("persistent_merkle_tree").Node;
const isBasicType = @import("ssz").isBasicType;

const ForkTypes = @import("./fork_types.zig").ForkTypes;

pub fn ForkExecutionPayload(comptime f: ForkSeq) type {
    return struct {
        const Self = @This();

        inner: ForkTypes(f).ExecutionPayload.Type,

        pub const fork_seq = f;

        pub inline fn parentHash(self: *const Self) *const [32]u8 {
            return &self.inner.parent_hash;
        }

        pub inline fn blockHash(self: *const Self) *const [32]u8 {
            return &self.inner.block_hash;
        }

        pub inline fn prevRandao(self: *const Self) *const [32]u8 {
            return &self.inner.prev_randao;
        }

        pub inline fn timestamp(self: *const Self) u64 {
            return self.inner.timestamp;
        }

        /// Creates an ExecutionPayloadHeader from this ExecutionPayload
        /// Caller is responsible for properly deallocating the execution payload header
        pub fn createExecutionPayloadHeader(self: *const Self, allocator: Allocator, out: *ForkTypes(f).ExecutionPayloadHeader) !void {
            out.parent_hash = self.inner.parent_hash;
            out.fee_recipient = self.inner.fee_recipient;
            out.state_root = self.inner.state_root;
            out.receipts_root = self.inner.receipts_root;
            out.logs_bloom = self.inner.logs_bloom;
            out.prev_randao = self.inner.prev_randao;
            out.block_number = self.inner.block_number;
            out.gas_limit = self.inner.gas_limit;
            out.gas_used = self.inner.gas_used;
            out.timestamp = self.inner.timestamp;
            out.extra_data = try self.inner.extra_data.clone(allocator);
            errdefer allocator.free(out.extra_data);
            out.base_fee_per_gas = self.inner.base_fee_per_gas;
            out.block_hash = self.inner.block_hash;
            try ForkTypes(f).Transactions.hashTreeRoot(allocator, &self.inner.transactions, &out.transactions_root);
            if (comptime f.gte(.capella)) {
                try ForkTypes(f).Withdrawals.hashTreeRoot(allocator, &self.inner.withdrawals, &out.withdrawals_root);
            }
        }
    };
}

pub fn ForkExecutionPayloadHeader(comptime f: ForkSeq) type {
    return struct {
        const Self = @This();

        inner: ForkTypes(f).ExecutionPayloadHeader.Type,

        pub const fork_seq = f;

        pub inline fn parentHash(self: *const Self) *const [32]u8 {
            return &self.inner.parent_hash;
        }

        pub inline fn blockHash(self: *const Self) *const [32]u8 {
            return &self.inner.block_hash;
        }

        pub inline fn prevRandao(self: *const Self) *const [32]u8 {
            return &self.inner.prev_randao;
        }

        pub inline fn timestamp(self: *const Self) u64 {
            return self.inner.timestamp;
        }
    };
}
