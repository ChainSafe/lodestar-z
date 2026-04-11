pub const ForkTypes = @import("./fork_types.zig").ForkTypes;
pub const BlockType = @import("./block_type.zig").BlockType;

pub const BeaconState = @import("./beacon_state.zig").BeaconState;
pub const SignedBeaconBlock = @import("./beacon_block.zig").SignedBeaconBlock;
pub const BeaconBlock = @import("./beacon_block.zig").BeaconBlock;
pub const BeaconBlockBody = @import("./beacon_block.zig").BeaconBlockBody;
pub const ExecutionPayload = @import("./execution_payload.zig").ExecutionPayload;
pub const ExecutionPayloadHeader = @import("./execution_payload.zig").ExecutionPayloadHeader;

pub const any_beacon_state = @import("./any_beacon_state.zig");
pub const AnyBeaconState = any_beacon_state.AnyBeaconState;
pub const readSlotFromAnyBeaconStateBytes = any_beacon_state.readSlotFromAnyBeaconStateBytes;
pub const readGenesisValidatorsRootFromAnyBeaconStateBytes = any_beacon_state.readGenesisValidatorsRootFromAnyBeaconStateBytes;
pub const AnySignedBeaconBlock = @import("./any_beacon_block.zig").AnySignedBeaconBlock;
pub const AnyBeaconBlock = @import("./any_beacon_block.zig").AnyBeaconBlock;
pub const AnyBeaconBlockBody = @import("./any_beacon_block.zig").AnyBeaconBlockBody;
pub const AnyExecutionPayload = @import("./any_execution_payload.zig").AnyExecutionPayload;
pub const AnyExecutionPayloadHeader = @import("./any_execution_payload.zig").AnyExecutionPayloadHeader;
pub const AnySignedAggregateAndProof = @import("./any_signed_aggregate_and_proof.zig").AnySignedAggregateAndProof;
pub const AnyAttesterSlashing = @import("./any_attester_slashing.zig").AnyAttesterSlashing;
pub const AnyAttesterSlashings = @import("./any_attester_slashing.zig").AnyAttesterSlashings;
pub const AnyAttesterSlashingItems = @import("./any_attester_slashing.zig").AnyAttesterSlashingItems;
pub const AnyAttestation = @import("./any_attestation.zig").AnyAttestation;
pub const AnyAttestations = @import("./any_attestation.zig").AnyAttestations;
pub const AnyAttestationItems = @import("./any_attestation.zig").AnyAttestationItems;
pub const AnyGossipAttestation = @import("./any_gossip_attestation.zig").AnyGossipAttestation;
pub const AnyIndexedAttestation = @import("./any_indexed_attestation.zig").AnyIndexedAttestation;

const testing = @import("std").testing;
test {
    testing.refAllDecls(BeaconState(.fulu));
    testing.refAllDecls(SignedBeaconBlock(.full, .fulu));
    testing.refAllDecls(BeaconBlock(.full, .fulu));
    testing.refAllDecls(BeaconBlockBody(.full, .fulu));
    testing.refAllDecls(ExecutionPayload(.fulu));
    testing.refAllDecls(ExecutionPayloadHeader(.fulu));

    testing.refAllDecls(AnyBeaconState);
    testing.refAllDecls(AnySignedBeaconBlock);
    testing.refAllDecls(AnyBeaconBlock);
    testing.refAllDecls(AnyBeaconBlockBody);
    testing.refAllDecls(AnyExecutionPayload);
    testing.refAllDecls(AnyExecutionPayloadHeader);
    testing.refAllDecls(AnyGossipAttestation);
    testing.refAllDecls(AnyIndexedAttestation);
    testing.refAllDecls(AnyAttesterSlashing);
}
