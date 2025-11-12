const types = @import("consensus_types");

pub const AttesterSlashings = union(enum) {
    // no need pointer because this is ArrayList already
    phase0: types.phase0.AttesterSlashings.Type,
    electra: types.electra.AttesterSlashings.Type,

    pub fn length(self: *const AttesterSlashings) usize {
        return switch (self.*) {
            inline .phase0, .electra => |attester_slashings| attester_slashings.items.len,
        };
    }

    pub fn items(self: *const AttesterSlashings) AttesterSlashingItems {
        return switch (self.*) {
            .phase0 => |attester_slashings| .{ .phase0 = attester_slashings.items },
            .electra => |attester_slashings| .{ .electra = attester_slashings.items },
        };
    }
};

pub const AttesterSlashingItems = union(enum) {
    phase0: []types.phase0.AttesterSlashing.Type,
    electra: []types.electra.AttesterSlashing.Type,
};
