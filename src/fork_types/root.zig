pub const ForkTypes = @import("./fork_types.zig").ForkTypes;
pub const BlockType = @import("./block_type.zig").BlockType;

pub const ForkBeaconState = @import("./fork_beacon_state.zig").ForkBeaconState;
pub const ForkSignedBeaconBlock = @import("./fork_beacon_block.zig").ForkSignedBeaconBlock;
pub const ForkBeaconBlock = @import("./fork_beacon_block.zig").ForkBeaconBlock;
pub const ForkBeaconBlockBody = @import("./fork_beacon_block.zig").ForkBeaconBlockBody;
pub const ForkExecutionPayload = @import("./fork_execution_payload.zig").ForkExecutionPayload;
pub const ForkExecutionPayloadHeader = @import("./fork_execution_payload.zig").ForkExecutionPayloadHeader;

pub const AnyBeaconState = @import("./any_beacon_state.zig").AnyBeaconState;
pub const AnySignedBeaconBlock = @import("./any_beacon_block.zig").AnySignedBeaconBlock;
pub const AnyBeaconBlock = @import("./any_beacon_block.zig").AnyBeaconBlock;
pub const AnyBeaconBlockBody = @import("./any_beacon_block.zig").AnyBeaconBlockBody;
pub const AnyExecutionPayload = @import("./any_execution_payload.zig").AnyExecutionPayload;
pub const AnyExecutionPayloadHeader = @import("./any_execution_payload.zig").AnyExecutionPayloadHeader;

test {
    @import("std").testing.refAllDecls(@This());
}
