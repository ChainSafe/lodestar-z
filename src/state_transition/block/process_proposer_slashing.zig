const std = @import("std");
const BeaconConfig = @import("config").BeaconConfig;
const ForkSeq = @import("config").ForkSeq;
const ForkTypes = @import("fork_types").ForkTypes;
const ForkBeaconState = @import("fork_types").ForkBeaconState;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const types = @import("consensus_types");
const isSlashableValidator = @import("../utils/validator.zig").isSlashableValidator;
const getProposerSlashingSignatureSets = @import("../signature_sets/proposer_slashings.zig").getProposerSlashingSignatureSets;
const verifySignature = @import("../utils/signature_sets.zig").verifySingleSignatureSet;
const slashValidator = @import("./slash_validator.zig").slashValidator;

pub fn processProposerSlashing(
    comptime fork: ForkSeq,
    config: *const BeaconConfig,
    epoch_cache: *EpochCache,
    state: *ForkBeaconState(fork),
    proposer_slashing: *const ForkTypes(fork).ProposerSlashing.Type,
    verify_signatures: bool,
) !void {
    try assertValidProposerSlashing(fork, config, epoch_cache, state, proposer_slashing, verify_signatures);
    const proposer_index = proposer_slashing.signed_header_1.message.proposer_index;
    try slashValidator(fork, config, epoch_cache, state, proposer_index, null);
}

pub fn assertValidProposerSlashing(
    comptime fork: ForkSeq,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: *ForkBeaconState(fork),
    proposer_slashing: *const ForkTypes(fork).ProposerSlashing.Type,
    verify_signature: bool,
) !void {
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
    try proposer_view.toValue(undefined, &proposer);
    if (!isSlashableValidator(&proposer, epoch_cache.epoch)) {
        return error.InvalidProposerSlashingProposerNotSlashable;
    }

    // verify signatures
    if (verify_signature) {
        const signature_sets = try getProposerSlashingSignatureSets(
            config,
            epoch_cache,
            proposer_slashing,
        );
        if (!try verifySignature(&signature_sets[0]) or !try verifySignature(&signature_sets[1])) {
            return error.InvalidProposerSlashingSignature;
        }
    }
}
