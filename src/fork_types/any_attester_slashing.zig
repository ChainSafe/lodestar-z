const ct = @import("consensus_types");
const p = @import("consensus_types").primitive;

/// A single attester slashing from any fork.
/// Wraps either phase0 or electra concrete AttesterSlashing types.
pub const AnyAttesterSlashing = union(enum) {
    phase0: ct.phase0.AttesterSlashing.Type,
    electra: ct.electra.AttesterSlashing.Type,

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
