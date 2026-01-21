const ForkSeq = @import("config").ForkSeq;

const ForkTypes = @import("./fork_types.zig").ForkTypes;
const ForkExecutionPayload = @import("./fork_execution_payload.zig").ForkExecutionPayload;
const ForkExecutionPayloadHeader = @import("./fork_execution_payload.zig").ForkExecutionPayloadHeader;

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

        pub inline fn eth1Data(self: *const Self) *const ForkTypes(f).Eth1Data {
            return &self.inner.eth1_data;
        }

        pub inline fn executionPayload(self: *const Self) *const ForkExecutionPayload(f) {
            if (bt != .full) {
                @compileError("executionPayload is only available for full blocks");
            }

            return @ptrCast(&self.inner.execution_payload);
        }

        pub inline fn executionPayloadHeader(self: *const Self) *const ForkExecutionPayloadHeader(f) {
            if (bt != .blinded) {
                @compileError("executionPayloadHeader is only available for blinded blocks");
            }

            return @ptrCast(&self.inner.execution_payload_header);
        }
    };
}
