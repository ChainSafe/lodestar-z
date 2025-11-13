const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const ForkSeq = @import("config").ForkSeq;
const types = @import("consensus_types");
const ProposerSlashing = types.phase0.ProposerSlashing.Type;
const isSlashableValidator = @import("../utils/validator.zig").isSlashableValidator;
const getProposerSlashingSignatureSets = @import("../signature_sets/proposer_slashings.zig").getProposerSlashingSignatureSets;
const verifySignature = @import("../utils/signature_sets.zig").verifySingleSignatureSet;
const slashValidator = @import("./slash_validator.zig").slashValidator;

pub fn processProposerSlashing(
    cached_state: *const CachedBeaconStateAllForks,
    proposer_slashing: *const ProposerSlashing,
    verify_signatures: bool,
) !void {
    try assertValidProposerSlashing(cached_state, proposer_slashing, verify_signatures);
    const proposer_index = proposer_slashing.signed_header_1.message.proposer_index;
    try slashValidator(cached_state, proposer_index, null);
}

pub fn assertValidProposerSlashing(
    cached_state: *const CachedBeaconStateAllForks,
    proposer_slashing: *const ProposerSlashing,
    verify_signature: bool,
) !void {
    const state = cached_state.state;
    const epoch_cache = cached_state.getEpochCache();
    const header_1 = proposer_slashing.signed_header_1.message;
    const header_2 = proposer_slashing.signed_header_2.message;

    // verify header slots match
    if (header_1.slot != header_2.slot) {
        return error.InvalidProposerSlashingSlotMismatch;
    }

    // verify header proposer indices match
    if (header_1.proposer_index != header_2.proposer_index) {
        return error.InvalidProposerSlashingProposerIndexMismatch;
    }

    if (header_1.proposer_index >= state.validators().items.len) {
        return error.InvalidProposerSlashingProposerIndexOutOfRange;
    }

    // verify headers are different
    if (types.phase0.BeaconBlockHeader.equals(&header_1, &header_2)) {
        return error.InvalidProposerSlashingHeadersEqual;
    }

    // verify the proposer is slashable
    const proposer = state.validators().items[header_1.proposer_index];
    if (!isSlashableValidator(&proposer, epoch_cache.epoch)) {
        return error.InvalidProposerSlashingProposerNotSlashable;
    }

    // verify signatures
    if (verify_signature) {
        const signature_sets = try getProposerSlashingSignatureSets(cached_state, proposer_slashing);
        if (!try verifySignature(&signature_sets[0]) or !try verifySignature(&signature_sets[1])) {
            return error.InvalidProposerSlashingSignature;
        }
    }
}
