const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const types = @import("consensus_types");
const ProposerSlashing = types.phase0.ProposerSlashing.Type;
const isSlashableValidator = @import("../utils/validator.zig").isSlashableValidator;
const getProposerSlashingSignatureSets = @import("../signature_sets/proposer_slashings.zig").getProposerSlashingSignatureSets;
const verifySignature = @import("../utils/signature_sets.zig").verifySingleSignatureSet;
const slashValidator = @import("./slash_validator.zig").slashValidator;

pub fn processProposerSlashing(
    cached_state: *CachedBeaconState,
    proposer_slashing: *const ProposerSlashing,
    verify_signatures: bool,
) !void {
    try assertValidProposerSlashing(cached_state, proposer_slashing, verify_signatures);
    const proposer_index = proposer_slashing.signed_header_1.message.proposer_index;
    try slashValidator(cached_state, proposer_index, null);
}

pub fn assertValidProposerSlashing(
    cached_state: *CachedBeaconState,
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

    var validators_view = try state.validators();
    const validators_len = try validators_view.length();
    if (header_1.proposer_index >= validators_len) {
        return error.InvalidProposerSlashingProposerIndexOutOfRange;
    }

    // verify headers are different
    if (types.phase0.BeaconBlockHeader.equals(&header_1, &header_2)) {
        return error.InvalidProposerSlashingHeadersEqual;
    }

    // verify the proposer is slashable
    var proposer_view = try validators_view.get(header_1.proposer_index);
    var proposer: types.phase0.Validator.Type = undefined;
    try proposer_view.toValue(cached_state.allocator, &proposer);
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
