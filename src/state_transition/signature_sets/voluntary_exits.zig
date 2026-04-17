const std = @import("std");
const Allocator = std.mem.Allocator;
const BeaconConfig = @import("config").BeaconConfig;
const ForkSeq = @import("config").ForkSeq;
const ForkTypes = @import("fork_types").ForkTypes;
const BeaconState = @import("fork_types").BeaconState;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const SingleSignatureSet = @import("../utils/signature_sets.zig").SingleSignatureSet;
const types = @import("consensus_types");
const SignedVoluntaryExit = types.phase0.SignedVoluntaryExit.Type;
const computeStartSlotAtEpoch = @import("../utils/epoch.zig").computeStartSlotAtEpoch;
const computeSigningRoot = @import("../utils/signing_root.zig").computeSigningRoot;
const verifySingleSignatureSet = @import("../utils/signature_sets.zig").verifySingleSignatureSet;
const isBuilderIndex = @import("../utils/gloas.zig").isBuilderIndex;
const convertValidatorIndexToBuilderIndex = @import("../utils/gloas.zig").convertValidatorIndexToBuilderIndex;
const bls = @import("bls");

pub fn verifyVoluntaryExitSignature(
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: anytype,
    signed_voluntary_exit: *const SignedVoluntaryExit,
) !bool {
    const signature_set = try getVoluntaryExitSignatureSet(
        allocator,
        config,
        epoch_cache,
        state,
        signed_voluntary_exit,
    );
    return try verifySingleSignatureSet(&signature_set);
}

pub fn getVoluntaryExitSignatureSet(
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: anytype,
    signed_voluntary_exit: *const SignedVoluntaryExit,
) !SingleSignatureSet {
    if (isBuilderVoluntaryExit(signed_voluntary_exit)) {
        const gloas_state: *BeaconState(.gloas) = @ptrCast(state);
        return getBuilderVoluntaryExitSignatureSet(allocator, config, epoch_cache, gloas_state, signed_voluntary_exit);
    }
    return getValidatorVoluntaryExitSignatureSet(config, epoch_cache, signed_voluntary_exit);
}

pub fn getValidatorVoluntaryExitSignatureSet(
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    signed_voluntary_exit: *const SignedVoluntaryExit,
) !SingleSignatureSet {
    const message_slot = computeStartSlotAtEpoch(signed_voluntary_exit.message.epoch);
    const domain = try config.getDomainForVoluntaryExit(epoch_cache.epoch, message_slot);
    var signing_root: [32]u8 = undefined;
    try computeSigningRoot(types.phase0.VoluntaryExit, &signed_voluntary_exit.message, domain, &signing_root);

    return .{
        .pubkey = epoch_cache.index_to_pubkey.items[signed_voluntary_exit.message.validator_index],
        .signing_root = signing_root,
        .signature = signed_voluntary_exit.signature,
    };
}

pub fn getBuilderVoluntaryExitSignatureSet(
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: *BeaconState(.gloas),
    signed_voluntary_exit: *const SignedVoluntaryExit,
) !SingleSignatureSet {
    const message_slot = computeStartSlotAtEpoch(signed_voluntary_exit.message.epoch);
    const domain = try config.getDomainForVoluntaryExit(epoch_cache.epoch, message_slot);
    var signing_root: [32]u8 = undefined;
    try computeSigningRoot(types.phase0.VoluntaryExit, &signed_voluntary_exit.message, domain, &signing_root);

    const builder_index = convertValidatorIndexToBuilderIndex(signed_voluntary_exit.message.validator_index);
    var builders = try state.inner.get("builders");
    var builder: types.gloas.Builder.Type = undefined;
    try builders.getValue(allocator, builder_index, &builder);
    const pubkey = bls.PublicKey.uncompress(&builder.pubkey) catch return error.InvalidBuilderPubkey;

    return .{
        .pubkey = pubkey,
        .signing_root = signing_root,
        .signature = signed_voluntary_exit.signature,
    };
}

pub fn isBuilderVoluntaryExit(signed_voluntary_exit: *const SignedVoluntaryExit) bool {
    return isBuilderIndex(signed_voluntary_exit.message.validator_index);
}

pub fn voluntaryExitsSignatureSets(
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: anytype,
    voluntary_exits: []types.phase0.SignedVoluntaryExit.Type,
    out: std.ArrayList(SingleSignatureSet),
) !void {
    for (voluntary_exits) |*signed_voluntary_exit| {
        const signature_set = try getVoluntaryExitSignatureSet(
            allocator,
            config,
            epoch_cache,
            state,
            signed_voluntary_exit,
        );
        try out.append(signature_set);
    }
}
