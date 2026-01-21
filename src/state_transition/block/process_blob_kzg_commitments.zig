const BlockExternalData = @import("../state_transition.zig").BlockExternalData;

pub fn processBlobKzgCommitments(external_data: BlockExternalData) !void {
    switch (external_data.execution_payload_status) {
        .pre_merge => return error.ExecutionPayloadStatusPreMerge,
        .invalid => return error.InvalidExecutionPayload,
        // ok
        else => {},
    }
}
