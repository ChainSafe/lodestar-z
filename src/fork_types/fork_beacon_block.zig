const std = @import("std");
const ForkSeq = @import("config").ForkSeq;

const BlockType = @import("./block_type.zig").BlockType;
const ForkTypes = @import("./fork_types.zig").ForkTypes;
const ForkExecutionPayload = @import("./fork_execution_payload.zig").ForkExecutionPayload;
const ForkExecutionPayloadHeader = @import("./fork_execution_payload.zig").ForkExecutionPayloadHeader;

pub fn ForkSignedBeaconBlock(comptime bt: BlockType, comptime f: ForkSeq) type {
    return struct {
        const Self = @This();

        inner: switch (bt) {
            .full => ForkTypes(f).SignedBeaconBlock.Type,
            .blinded => ForkTypes(f).SignedBlindedBeaconBlock.Type,
        },

        pub const block_type = bt;
        pub const fork_seq = f;

        pub inline fn message(self: *const Self) *const ForkBeaconBlock(bt, f) {
            return @ptrCast(&self.inner.body);
        }
    };
}

pub fn ForkBeaconBlock(comptime bt: BlockType, comptime f: ForkSeq) type {
    return struct {
        const Self = @This();

        inner: switch (bt) {
            .full => ForkTypes(f).BeaconBlock.Type,
            .blinded => switch (f) {
                .phase0, .altair => @compileError("Blinded blocks are not defined for phase0 and altair forks"),
                else => ForkTypes(f).BlindedBeaconBlock.Type,
            },
        },

        pub const block_type = bt;
        pub const fork_seq = f;

        pub inline fn slot(self: *const Self) u64 {
            return self.inner.slot;
        }

        pub inline fn proposerIndex(self: *const Self) u64 {
            return self.inner.proposer_index;
        }

        pub inline fn parentRoot(self: *const Self) *const [32]u8 {
            return &self.inner.parent_root;
        }

        pub inline fn body(self: *const Self) *const ForkBeaconBlockBody(bt, f) {
            return @ptrCast(&self.inner.body);
        }
    };
}

pub fn ForkBeaconBlockBody(comptime bt: BlockType, comptime f: ForkSeq) type {
    return struct {
        const Self = @This();

        inner: switch (bt) {
            .full => ForkTypes(f).BeaconBlockBody.Type,
            .blinded => ForkTypes(f).BlindedBeaconBlockBody.Type,
        },

        pub const block_type = bt;
        pub const fork_seq = f;

        pub inline fn hashTreeRoot(self: *const Self, allocator: std.mem.Allocator, out: *[32]u8) !void {
            if (bt == .full) {
                return ForkTypes(f).BeaconBlockBody.hashTreeRoot(allocator, &self.inner, out);
            }
            return ForkTypes(f).BlindedBeaconBlockBody.hashTreeRoot(allocator, &self.inner, out);
        }

        pub inline fn eth1Data(self: *const Self) *const ForkTypes(f).Eth1Data.Type {
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

        pub inline fn randaoReveal(self: *const Self) *const [96]u8 {
            return &self.inner.randao_reveal;
        }

        pub inline fn syncAggregate(self: *const Self) *const ForkTypes(f).SyncAggregate.Type {
            if (f.lt(.altair)) {
                @compileError("syncAggregate is only available for altair and later forks");
            }
            return &self.inner.sync_aggregate;
        }

        pub inline fn blobKzgCommitments(self: *const Self) []const [48]u8 {
            if (f.lt(.deneb)) {
                @compileError("blobKzgCommitments is only available for deneb and later forks");
            }
            return self.inner.blob_kzg_commitments.items;
        }
    };
}

test "sanity" {
    std.testing.refAllDecls(ForkSignedBeaconBlock(.full, .capella));
    std.testing.refAllDecls(ForkBeaconBlock(.full, .capella));
    std.testing.refAllDecls(ForkBeaconBlockBody(.full, .capella));
}
