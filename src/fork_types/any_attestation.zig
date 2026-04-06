const std = @import("std");
const ct = @import("consensus_types");
const preset = @import("preset").preset;
const ssz = @import("ssz");

pub const AnyAttestations = union(enum) {
    phase0: ct.phase0.Attestations.Type,
    electra: ct.electra.Attestations.Type,

    pub fn length(self: *const AnyAttestations) usize {
        return switch (self.*) {
            inline else => |attestations| attestations.items.len,
        };
    }

    pub fn items(self: *const AnyAttestations) AnyAttestationItems {
        return switch (self.*) {
            .phase0 => |attestations| .{ .phase0 = attestations.items },
            .electra => |attestations| .{ .electra = attestations.items },
        };
    }
};

pub const AnyAttestationItems = union(enum) {
    phase0: []ct.phase0.Attestation.Type,
    electra: []ct.electra.Attestation.Type,
};

// ---------------------------------------------------------------------------
// AnyAttestation — a single attestation from any fork
// ---------------------------------------------------------------------------

/// A single attestation from any fork.
/// Wraps either phase0 (pre-Electra) or electra concrete Attestation types.
///
/// Electra changes (EIP-7549):
///   - `data.index` is always 0
///   - Committee membership encoded in `committee_bits` bitvector
///   - `aggregation_bits` spans ALL committees in the slot
pub const AnyAttestation = union(enum) {
    phase0: ct.phase0.Attestation.Type,
    electra: ct.electra.Attestation.Type,

    pub fn clone(self: *const AnyAttestation, allocator: std.mem.Allocator, out: *AnyAttestation) !void {
        switch (self.*) {
            .phase0 => |*att| {
                out.* = .{ .phase0 = ct.phase0.Attestation.default_value };
                try ct.phase0.Attestation.clone(allocator, att, &out.phase0);
            },
            .electra => |*att| {
                out.* = .{ .electra = ct.electra.Attestation.default_value };
                try ct.electra.Attestation.clone(allocator, att, &out.electra);
            },
        }
    }

    pub fn deinit(self: *AnyAttestation, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .phase0 => |*att| ct.phase0.Attestation.deinit(allocator, att),
            .electra => |*att| ct.electra.Attestation.deinit(allocator, att),
        }
    }

    /// Returns the attestation data (same struct for both forks).
    pub fn data(self: *const AnyAttestation) ct.phase0.AttestationData.Type {
        return switch (self.*) {
            inline else => |att| att.data,
        };
    }

    /// Returns the slot from the attestation data.
    pub fn slot(self: *const AnyAttestation) u64 {
        return self.data().slot;
    }

    /// Returns the committee index.
    /// Pre-Electra: from data.index.
    /// Electra: from committee_bits (first set bit), or 0 if none set.
    pub fn committeeIndex(self: *const AnyAttestation) u64 {
        return switch (self.*) {
            .phase0 => |att| att.data.index,
            .electra => |att| blk: {
                // Find the first set bit in committee_bits.
                for (0..preset.MAX_COMMITTEES_PER_SLOT) |i| {
                    if (att.committee_bits.get(i) catch false) break :blk @as(u64, i);
                }
                break :blk 0;
            },
        };
    }

    /// Returns the number of set committees.
    /// Pre-Electra: always 1 (single committee per attestation).
    /// Electra: count of set bits in committee_bits.
    pub fn committeeCount(self: *const AnyAttestation) u32 {
        return switch (self.*) {
            .phase0 => 1,
            .electra => |att| blk: {
                var count: u32 = 0;
                for (0..preset.MAX_COMMITTEES_PER_SLOT) |i| {
                    if (att.committee_bits.get(i) catch false) count += 1;
                }
                break :blk count;
            },
        };
    }

    pub fn containsCommitteeIndex(self: *const AnyAttestation, committee_index: u64) bool {
        return switch (self.*) {
            .phase0 => |att| att.data.index == committee_index,
            .electra => |att| att.committee_bits.get(@intCast(committee_index)) catch false,
        };
    }

    /// Returns the aggregation bits as raw bytes (for bitwise operations).
    pub fn aggregationBitsBytes(self: *const AnyAttestation) []const u8 {
        return switch (self.*) {
            inline else => |att| att.aggregation_bits.data.items,
        };
    }

    /// Returns the aggregation bits length (number of logical bits).
    pub fn aggregationBitLen(self: *const AnyAttestation) usize {
        return switch (self.*) {
            inline else => |att| att.aggregation_bits.bit_len,
        };
    }

    /// Returns the number of participating validators represented by the
    /// aggregation bitfield.
    pub fn participantCount(self: *const AnyAttestation) u32 {
        const bytes = self.aggregationBitsBytes();
        const bit_len = self.aggregationBitLen();
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

    /// Returns the signature.
    pub fn signature(self: *const AnyAttestation) [96]u8 {
        return switch (self.*) {
            inline else => |att| att.signature,
        };
    }

    /// Check if this is an Electra-format attestation.
    pub fn isElectra(self: *const AnyAttestation) bool {
        return self.* == .electra;
    }
};
