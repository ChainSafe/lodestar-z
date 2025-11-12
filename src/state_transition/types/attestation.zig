const std = @import("std");
const types = @import("consensus_types");

const AttestationData = types.primitive.AttestationData.Type;
const BLSSignature = types.primitive.BLSSignature.Type;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;

pub const Attestations = union(enum) {
    phase0: *const types.phase0.Attestations.Type,
    electra: *const types.electra.Attestations.Type,

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
    phase0: []types.phase0.Attestation.Type,
    electra: []types.electra.Attestation.Type,
};

pub const IndexedAttestation = union(enum) {
    phase0: *const types.phase0.IndexedAttestation.Type,
    electra: *const types.electra.IndexedAttestation.Type,

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
