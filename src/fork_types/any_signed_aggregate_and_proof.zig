const std = @import("std");
const ct = @import("consensus_types");
const config = @import("config");
const AnyAttestation = @import("./any_attestation.zig").AnyAttestation;

const ForkSeq = config.ForkSeq;

pub const AnySignedAggregateAndProof = union(enum) {
    phase0: ct.phase0.SignedAggregateAndProof.Type,
    electra: ct.electra.SignedAggregateAndProof.Type,

    pub fn deserialize(
        allocator: std.mem.Allocator,
        fork_seq: ForkSeq,
        bytes: []const u8,
    ) !AnySignedAggregateAndProof {
        if (fork_seq.gte(.electra)) {
            var signed_agg: ct.electra.SignedAggregateAndProof.Type = undefined;
            try ct.electra.SignedAggregateAndProof.deserializeFromBytes(allocator, bytes, &signed_agg);
            return .{ .electra = signed_agg };
        }

        var signed_agg: ct.phase0.SignedAggregateAndProof.Type = undefined;
        try ct.phase0.SignedAggregateAndProof.deserializeFromBytes(allocator, bytes, &signed_agg);
        return .{ .phase0 = signed_agg };
    }

    pub fn deinit(self: *AnySignedAggregateAndProof, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .phase0 => |*signed_agg| signed_agg.message.aggregate.aggregation_bits.data.deinit(allocator),
            .electra => |*signed_agg| signed_agg.message.aggregate.aggregation_bits.data.deinit(allocator),
        }
    }

    pub fn attestation(self: *const AnySignedAggregateAndProof) AnyAttestation {
        return switch (self.*) {
            .phase0 => |signed_agg| .{ .phase0 = signed_agg.message.aggregate },
            .electra => |signed_agg| .{ .electra = signed_agg.message.aggregate },
        };
    }

    pub fn aggregatorIndex(self: *const AnySignedAggregateAndProof) u64 {
        return switch (self.*) {
            .phase0 => |signed_agg| signed_agg.message.aggregator_index,
            .electra => |signed_agg| signed_agg.message.aggregator_index,
        };
    }
};
