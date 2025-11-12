const std = @import("std");
const ct = @import("consensus_types");

const AttestationData = ct.primitive.AttestationData.Type;
const BLSSignature = ct.primitive.BLSSignature.Type;
const ValidatorIndex = ct.primitive.ValidatorIndex.Type;

pub const Attestations = union(enum) {
    phase0: *const ct.phase0.Attestations.Type,
    electra: *const ct.electra.Attestations.Type,

    pub fn length(self: *const Attestations) usize {
        return switch (self.*) {
            inline .phase0, .electra => |attestations| attestations.items.len,
        };
    }

    pub fn items(self: *const Attestations) AttestationItems {
        return switch (self.*) {
            .phase0 => |attestations| .{ .phase0 = attestations.items },
            .electra => |attestations| .{ .electra = attestations.items },
        };
    }
};

pub const AttestationItems = union(enum) {
    phase0: []ct.phase0.Attestation.Type,
    electra: []ct.electra.Attestation.Type,
};

pub const IndexedAttestation = union(enum) {
    phase0: *const ct.phase0.IndexedAttestation.Type,
    electra: *const ct.electra.IndexedAttestation.Type,

    pub fn getAttestationData(self: *const IndexedAttestation) AttestationData {
        return switch (self.*) {
            .phase0 => |indexed_attestation| indexed_attestation.attestation.data,
            .electra => |indexed_attestation| indexed_attestation.attestation.data,
        };
    }

    pub fn signature(self: *const IndexedAttestation) BLSSignature {
        return switch (self.*) {
            .phase0 => |indexed_attestation| indexed_attestation.attestation.signature,
            .electra => |indexed_attestation| indexed_attestation.attestation.signature,
        };
    }

    pub fn getAttestingIndices(self: *const IndexedAttestation) std.ArrayListUnmanaged(ValidatorIndex) {
        return switch (self.*) {
            .phase0 => |indexed_attestation| indexed_attestation.attesting_indices,
            .electra => |indexed_attestation| indexed_attestation.attesting_indices,
        };
    }
};
