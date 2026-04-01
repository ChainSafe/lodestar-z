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
            var signed_agg: ct.electra.SignedAggregateAndProof.Type = ct.electra.SignedAggregateAndProof.default_value;
            try ct.electra.SignedAggregateAndProof.deserializeFromBytes(allocator, bytes, &signed_agg);
            return .{ .electra = signed_agg };
        }

        var signed_agg: ct.phase0.SignedAggregateAndProof.Type = ct.phase0.SignedAggregateAndProof.default_value;
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

    pub fn selectionProof(self: *const AnySignedAggregateAndProof) [96]u8 {
        return switch (self.*) {
            .phase0 => |signed_agg| signed_agg.message.selection_proof,
            .electra => |signed_agg| signed_agg.message.selection_proof,
        };
    }

    pub fn signature(self: *const AnySignedAggregateAndProof) [96]u8 {
        return switch (self.*) {
            .phase0 => |signed_agg| signed_agg.signature,
            .electra => |signed_agg| signed_agg.signature,
        };
    }

    pub fn slot(self: *const AnySignedAggregateAndProof) u64 {
        return self.attestation().slot();
    }

    pub fn targetEpoch(self: *const AnySignedAggregateAndProof) u64 {
        return self.attestation().data().target.epoch;
    }

    pub fn dataIndex(self: *const AnySignedAggregateAndProof) u64 {
        return self.attestation().data().index;
    }

    pub fn committeeCount(self: *const AnySignedAggregateAndProof) u32 {
        return self.attestation().committeeCount();
    }

    pub fn participantCount(self: *const AnySignedAggregateAndProof) u32 {
        return self.attestation().participantCount();
    }
};
