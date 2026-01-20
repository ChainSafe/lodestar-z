const std = @import("std");
const preset = @import("preset").preset;
const ForkSeq = @import("config").ForkSeq;
const isBasicType = @import("ssz").isBasicType;

const ForkTypes = @import("./fork_types.zig").ForkTypes;

pub const BlockType = enum {
    full,
    blinded,
};

pub fn ForkBeaconBlock(comptime f: ForkSeq, comptime bt: BlockType) type {
    return struct {
        const Self = @This();

        inner: switch (bt) {
            .full => ForkTypes(f).BeaconBlock,
            .blinded => ForkTypes(f).BlindedBeaconBlock,
        },

        pub const fork_seq = f;
        pub const block_type = bt;

        pub inline fn slot(self: *const Self) ForkTypes(f).Slot {
            return self.inner.slot;
        }

        pub inline fn proposerIndex(self: *const Self) u64 {
            return self.inner.proposer_index;
        }

        pub inline fn parentRoot(self: *const Self) ForkTypes(f).Root {
            return self.inner.parent_root;
        }

        pub inline fn body(self: *const Self) *const ForkBeaconBlockBody(f) {
            return @ptrCast(&self.inner.body);
        }
    };
}

pub fn ForkBeaconBlockBody(comptime f: ForkSeq, comptime bt: BlockType) type {
    return struct {
        const Self = @This();

        inner: switch (bt) {
            .full => ForkTypes(f).BeaconBlockBody,
            .blinded => ForkTypes(f).BlindedBeaconBlockBody,
        },

        pub const fork_seq = f;
        pub const block_type = bt;

        pub inline fn executionPayload(self: *const Self) *const ForkTypes(f).ExecutionPayload {
            if (bt != .full) {
                @compileError("executionPayload is only available for full blocks");
            }

            return &self.inner.execution_payload;
        }

        pub inline fn executionPayloadHeader(self: *const Self) *const ForkTypes(f).ExecutionPayloadHeader {
            if (bt != .blinded) {
                @compileError("executionPayloadHeader is only available for blinded blocks");
            }

            return &self.inner.execution_payload_header;
        }
    };
}
