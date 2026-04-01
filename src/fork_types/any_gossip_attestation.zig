const std = @import("std");
const ct = @import("consensus_types");
const config = @import("config");

const ForkSeq = config.ForkSeq;

pub const AnyGossipAttestation = union(enum) {
    phase0: ct.phase0.Attestation.Type,
    electra_single: ct.electra.SingleAttestation.Type,

    pub fn deserialize(
        allocator: std.mem.Allocator,
        fork_seq: ForkSeq,
        bytes: []const u8,
    ) !AnyGossipAttestation {
        if (fork_seq.gte(.electra)) {
            var att: ct.electra.SingleAttestation.Type = undefined;
            try ct.electra.SingleAttestation.deserializeFromBytes(bytes, &att);
            return .{ .electra_single = att };
        }

        var att: ct.phase0.Attestation.Type = ct.phase0.Attestation.default_value;
        try ct.phase0.Attestation.deserializeFromBytes(allocator, bytes, &att);
        return .{ .phase0 = att };
    }

    pub fn deinit(self: *AnyGossipAttestation, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .phase0 => |*att| att.aggregation_bits.data.deinit(allocator),
            .electra_single => {},
        }
    }

    pub fn data(self: *const AnyGossipAttestation) ct.phase0.AttestationData.Type {
        return switch (self.*) {
            .phase0 => |att| att.data,
            .electra_single => |att| att.data,
        };
    }

    pub fn slot(self: *const AnyGossipAttestation) u64 {
        return self.data().slot;
    }

    pub fn committeeIndex(self: *const AnyGossipAttestation) u64 {
        return switch (self.*) {
            .phase0 => |att| att.data.index,
            .electra_single => |att| att.committee_index,
        };
    }

    pub fn beaconBlockRoot(self: *const AnyGossipAttestation) [32]u8 {
        return self.data().beacon_block_root;
    }

    pub fn targetEpoch(self: *const AnyGossipAttestation) u64 {
        return self.data().target.epoch;
    }

    pub fn targetRoot(self: *const AnyGossipAttestation) [32]u8 {
        return self.data().target.root;
    }

    pub fn sourceEpoch(self: *const AnyGossipAttestation) u64 {
        return self.data().source.epoch;
    }

    pub fn sourceRoot(self: *const AnyGossipAttestation) [32]u8 {
        return self.data().source.root;
    }

    pub fn signature(self: *const AnyGossipAttestation) [96]u8 {
        return switch (self.*) {
            .phase0 => |att| att.signature,
            .electra_single => |att| att.signature,
        };
    }

    pub fn participantCount(self: *const AnyGossipAttestation) u32 {
        return switch (self.*) {
            .phase0 => |att| countSetBits(att.aggregation_bits.data.items, att.aggregation_bits.bit_len),
            .electra_single => 1,
        };
    }
};

fn countSetBits(bytes: []const u8, bit_len: usize) u32 {
    var count: u32 = 0;
    const full_bytes = bit_len / 8;
    const remainder = bit_len % 8;

    for (bytes[0..@min(full_bytes, bytes.len)]) |byte| {
        count += @popCount(byte);
    }

    if (remainder > 0 and bytes.len > full_bytes) {
        const mask: u8 = (@as(u8, 1) << @intCast(remainder)) - 1;
        count += @popCount(bytes[full_bytes] & mask);
    }

    return count;
}
