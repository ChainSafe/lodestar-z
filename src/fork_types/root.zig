pub const ForkTypes = @import("./fork_types.zig").ForkTypes;
pub const BlockType = @import("./block_type.zig").BlockType;

pub const BeaconState = @import("./beacon_state.zig").BeaconState;
pub const SignedBeaconBlock = @import("./beacon_block.zig").SignedBeaconBlock;
pub const BeaconBlock = @import("./beacon_block.zig").BeaconBlock;
pub const BeaconBlockBody = @import("./beacon_block.zig").BeaconBlockBody;
pub const ExecutionPayload = @import("./execution_payload.zig").ExecutionPayload;
pub const ExecutionPayloadHeader = @import("./execution_payload.zig").ExecutionPayloadHeader;

pub const AnyBeaconState = @import("./any_beacon_state.zig").AnyBeaconState;
pub const AnySignedBeaconBlock = @import("./any_beacon_block.zig").AnySignedBeaconBlock;
pub const AnyBeaconBlock = @import("./any_beacon_block.zig").AnyBeaconBlock;
pub const AnyBeaconBlockBody = @import("./any_beacon_block.zig").AnyBeaconBlockBody;
pub const AnyExecutionPayload = @import("./any_execution_payload.zig").AnyExecutionPayload;
pub const AnyExecutionPayloadHeader = @import("./any_execution_payload.zig").AnyExecutionPayloadHeader;

test {
    @import("std").testing.refAllDecls(@This());
}
