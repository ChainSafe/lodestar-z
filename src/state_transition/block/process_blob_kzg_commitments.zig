const std = @import("std");
const BlockExternalData = @import("../state_transition.zig").BlockExternalData;

pub fn processBlobKzgCommitments(external_data: BlockExternalData) !void {
    switch (external_data.execution_payload_status) {
        .pre_merge => return error.ExecutionPayloadStatusPreMerge,
        .invalid => return error.InvalidExecutionPayload,
        .valid => {},
    }
}

test "process blob kzg commitments - sanity" {
    try processBlobKzgCommitments(.{
        .execution_payload_status = .valid,
        .data_availability_status = .available,
    });
}

test "process blob kzg commitments - rejects unverified payload statuses" {
    try std.testing.expectError(error.InvalidExecutionPayload, processBlobKzgCommitments(.{ .execution_payload_status = .invalid }));
    try std.testing.expectError(error.ExecutionPayloadStatusPreMerge, processBlobKzgCommitments(.{ .execution_payload_status = .pre_merge }));
}
