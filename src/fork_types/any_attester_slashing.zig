const ct = @import("consensus_types");

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
