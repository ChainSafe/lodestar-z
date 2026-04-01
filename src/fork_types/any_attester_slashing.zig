const std = @import("std");
const ct = @import("consensus_types");
const p = @import("consensus_types").primitive;
const ForkSeq = @import("config").ForkSeq;

/// A single attester slashing from any fork.
/// Wraps either phase0 or electra concrete AttesterSlashing types.
pub const AnyAttesterSlashing = union(enum) {
    phase0: ct.phase0.AttesterSlashing.Type,
    electra: ct.electra.AttesterSlashing.Type,

    pub fn deserialize(
        allocator: std.mem.Allocator,
        fork_seq: ForkSeq,
        bytes: []const u8,
    ) !AnyAttesterSlashing {
        if (fork_seq.gte(.electra)) {
            var slashing = ct.electra.AttesterSlashing.default_value;
            try ct.electra.AttesterSlashing.deserializeFromBytes(allocator, bytes, &slashing);
            return .{ .electra = slashing };
        }

        var slashing = ct.phase0.AttesterSlashing.default_value;
        try ct.phase0.AttesterSlashing.deserializeFromBytes(allocator, bytes, &slashing);
        return .{ .phase0 = slashing };
    }

    pub fn clone(self: *const AnyAttesterSlashing, allocator: std.mem.Allocator, out: *AnyAttesterSlashing) !void {
        switch (self.*) {
            .phase0 => |*slashing| {
                out.* = .{ .phase0 = ct.phase0.AttesterSlashing.default_value };
                try ct.phase0.AttesterSlashing.clone(allocator, slashing, &out.phase0);
            },
            .electra => |*slashing| {
                out.* = .{ .electra = ct.electra.AttesterSlashing.default_value };
                try ct.electra.AttesterSlashing.clone(allocator, slashing, &out.electra);
            },
        }
    }

    pub fn deinit(self: *AnyAttesterSlashing, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .phase0 => |*slashing| ct.phase0.AttesterSlashing.deinit(allocator, slashing),
            .electra => |*slashing| ct.electra.AttesterSlashing.deinit(allocator, slashing),
        }
    }

    pub fn hashTreeRoot(self: *const AnyAttesterSlashing, allocator: std.mem.Allocator, out: *[32]u8) !void {
        switch (self.*) {
            .phase0 => |*slashing| try ct.phase0.AttesterSlashing.hashTreeRoot(allocator, slashing, out),
            .electra => |*slashing| try ct.electra.AttesterSlashing.hashTreeRoot(allocator, slashing, out),
        }
    }

    /// Returns the attesting indices from the first attestation.
    pub fn attestingIndices1(self: *const AnyAttesterSlashing) []const p.ValidatorIndex.Type {
        return switch (self.*) {
            .phase0 => |s| s.attestation_1.attesting_indices.items,
            .electra => |s| s.attestation_1.attesting_indices.items,
        };
    }

    /// Returns the attesting indices from the second attestation.
    pub fn attestingIndices2(self: *const AnyAttesterSlashing) []const p.ValidatorIndex.Type {
        return switch (self.*) {
            .phase0 => |s| s.attestation_2.attesting_indices.items,
            .electra => |s| s.attestation_2.attesting_indices.items,
        };
    }

    pub fn isSlashable(self: *const AnyAttesterSlashing) bool {
        return switch (self.*) {
            .phase0 => |s| isSlashableAttestationData(&s.attestation_1.data, &s.attestation_2.data),
            .electra => |s| isSlashableAttestationData(&s.attestation_1.data, &s.attestation_2.data),
        };
    }

    pub fn slashableKey(self: *const AnyAttesterSlashing) [32]u8 {
        return attesterSlashingKey(self.attestingIndices1(), self.attestingIndices2());
    }
};

pub const AnyAttesterSlashings = union(enum) {
    phase0: ct.phase0.AttesterSlashings.Type,
    electra: ct.electra.AttesterSlashings.Type,

    pub fn length(self: *const AnyAttesterSlashings) usize {
        return switch (self.*) {
            inline else => |attester_slashings| attester_slashings.items.len,
        };
    }

    pub fn items(self: *const AnyAttesterSlashings) AnyAttesterSlashingItems {
        return switch (self.*) {
            .phase0 => |attester_slashings| .{ .phase0 = attester_slashings.items },
            .electra => |attester_slashings| .{ .electra = attester_slashings.items },
        };
    }
};

pub const AnyAttesterSlashingItems = union(enum) {
    phase0: []ct.phase0.AttesterSlashing.Type,
    electra: []ct.electra.AttesterSlashing.Type,
};

fn isSlashableAttestationData(
    attestation_1: *const ct.phase0.AttestationData.Type,
    attestation_2: *const ct.phase0.AttestationData.Type,
) bool {
    const is_double_vote = !ct.phase0.AttestationData.equals(attestation_1, attestation_2) and
        attestation_1.target.epoch == attestation_2.target.epoch;
    const is_surround_vote = attestation_1.source.epoch < attestation_2.source.epoch and
        attestation_2.target.epoch < attestation_1.target.epoch;
    return is_double_vote or is_surround_vote;
}

fn attesterSlashingKey(
    indices_a: []const p.ValidatorIndex.Type,
    indices_b: []const p.ValidatorIndex.Type,
) [32]u8 {
    var hasher = std.hash.Wyhash.init(0x04);
    var i: usize = 0;
    var j: usize = 0;
    while (i < indices_a.len and j < indices_b.len) {
        if (indices_a[i] == indices_b[j]) {
            var buf: [8]u8 = undefined;
            std.mem.writeInt(u64, &buf, indices_a[i], .little);
            hasher.update(&buf);
            i += 1;
            j += 1;
        } else if (indices_a[i] < indices_b[j]) {
            i += 1;
        } else {
            j += 1;
        }
    }

    var out = std.mem.zeroes([32]u8);
    const digest = hasher.final();
    std.mem.writeInt(u64, out[0..8], digest, .little);
    return out;
}
