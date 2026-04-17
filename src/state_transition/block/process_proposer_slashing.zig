const std = @import("std");
const BeaconConfig = @import("config").BeaconConfig;
const ForkSeq = @import("config").ForkSeq;
const ForkTypes = @import("fork_types").ForkTypes;
const BeaconState = @import("fork_types").BeaconState;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const SlashingsCache = @import("../cache/slashings_cache.zig").SlashingsCache;
const buildSlashingsCacheIfNeeded = @import("../cache/slashings_cache.zig").buildFromStateIfNeeded;
const types = @import("consensus_types");
const isSlashableValidator = @import("../utils/validator.zig").isSlashableValidator;
const getProposerSlashingSignatureSets = @import("../signature_sets/proposer_slashings.zig").getProposerSlashingSignatureSets;
const verifySignature = @import("../utils/signature_sets.zig").verifySingleSignatureSet;
const slashValidator = @import("./slash_validator.zig").slashValidator;
const computeEpochAtSlot = @import("../utils/epoch.zig").computeEpochAtSlot;
const computePreviousEpoch = @import("../utils/epoch.zig").computePreviousEpoch;
const preset = @import("preset").preset;

pub fn processProposerSlashing(
    comptime fork: ForkSeq,
    allocator: std.mem.Allocator,
    config: *const BeaconConfig,
    epoch_cache: *EpochCache,
    state: *BeaconState(fork),
    slashings_cache: *SlashingsCache,
    proposer_slashing: *const ForkTypes(fork).ProposerSlashing.Type,
    verify_signatures: bool,
) !void {
    try buildSlashingsCacheIfNeeded(allocator, state, slashings_cache);
    try assertValidProposerSlashing(fork, config, epoch_cache, state, proposer_slashing, verify_signatures);

    if (fork.gte(.gloas)) {
        const slot = proposer_slashing.signed_header_1.message.slot;
        const proposal_epoch = computeEpochAtSlot(slot);
        const current_epoch = epoch_cache.epoch;
        const previous_epoch = computePreviousEpoch(current_epoch);

        const payment_index: ?u64 = if (proposal_epoch == current_epoch)
            preset.SLOTS_PER_EPOCH + (slot % preset.SLOTS_PER_EPOCH)
        else if (proposal_epoch == previous_epoch)
            slot % preset.SLOTS_PER_EPOCH
        else
            null;

        if (payment_index) |idx| {
            var builder_pending_payments = try state.inner.get("builder_pending_payments");
            const default_payment = types.gloas.BuilderPendingPayment.default_value;
            try builder_pending_payments.setValue(idx, &default_payment);
        }
    }

    const proposer_index = proposer_slashing.signed_header_1.message.proposer_index;
    try slashValidator(fork, config, epoch_cache, state, slashings_cache, proposer_index, null);
}

pub fn assertValidProposerSlashing(
    comptime fork: ForkSeq,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: *BeaconState(fork),
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
