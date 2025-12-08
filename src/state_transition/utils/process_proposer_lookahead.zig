const std = @import("std");
const Allocator = std.mem.Allocator;
const ssz = @import("consensus_types");
const preset = @import("preset").preset;
const c = @import("constants");
const BeaconStateAllForks = @import("../types/beacon_state.zig").BeaconStateAllForks;
const Epoch = ssz.primitive.Epoch.Type;
const Slot = ssz.primitive.Slot.Type;
const ValidatorIndex = ssz.primitive.ValidatorIndex.Type;
const EffectiveBalanceIncrements = @import("../cache/effective_balance_increments.zig").EffectiveBalanceIncrements;
const computeStartSlotAtEpoch = @import("./epoch.zig").computeStartSlotAtEpoch;
const computeEpochAtSlot = @import("./epoch.zig").computeEpochAtSlot;
const getSeed = @import("./seed.zig").getSeed;
const ComputeIndexUtils = @import("./committee_indices.zig").ComputeIndexUtils(ValidatorIndex);
const computeProposerIndex = ComputeIndexUtils.computeProposerIndex;
const digest = @import("./sha256.zig").digest;
const ByteCount = @import("./committee_indices.zig").ByteCount;
const getActiveValidatorIndices = @import("./validator.zig").getActiveValidatorIndices;

/// Computes proposer indices for a given epoch.
/// Returns an array of SLOTS_PER_EPOCH proposer indices.
pub fn computeProposerIndices(
    allocator: Allocator,
    epoch: Epoch,
    seed: *const [32]u8,
    active_indices: []const ValidatorIndex,
    effective_balance_increments: *const EffectiveBalanceIncrements,
    out: []ValidatorIndex,
) !void {
    std.debug.assert(effective_balance_increments.items.len > 0);
    std.debug.assert(out.len == preset.SLOTS_PER_EPOCH);

    const start_slot = computeStartSlotAtEpoch(epoch);
    const rand_byte_count = ByteCount.Two; // Fulu uses 2-byte randomness like Electra
    const max_effective_balance = preset.MAX_EFFECTIVE_BALANCE_ELECTRA;

    for (0..preset.SLOTS_PER_EPOCH) |i| {
        const slot = start_slot + i;
        var slot_buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &slot_buf, slot, .little);

        // Hash seed + slot to get the proposer seed for this slot
        var buffer: [40]u8 = [_]u8{0} ** 40;
        @memcpy(buffer[0..32], seed[0..]);
        @memcpy(buffer[32..40], slot_buf[0..]);
        var slot_seed: [32]u8 = undefined;
        digest(buffer[0..], &slot_seed);

        out[i] = try computeProposerIndex(
            allocator,
            &slot_seed,
            active_indices,
            effective_balance_increments.items,
            rand_byte_count,
            max_effective_balance,
            preset.EFFECTIVE_BALANCE_INCREMENT,
            preset.SHUFFLE_ROUND_COUNT,
        );
    }
}

/// Gets beacon proposer indices for a given epoch.
/// Allocates and returns an array of SLOTS_PER_EPOCH proposer indices.
/// The caller owns the returned slice and must free it.
pub fn getBeaconProposerIndices(
    allocator: Allocator,
    state: *const BeaconStateAllForks,
    epoch: Epoch,
    effective_balance_increments: *const EffectiveBalanceIncrements,
) ![]ValidatorIndex {
    std.debug.assert(effective_balance_increments.items.len > 0);
    var active_indices_list = try getActiveValidatorIndices(allocator, state, epoch);
    defer active_indices_list.deinit();

    var seed: [32]u8 = undefined;
    try getSeed(state, epoch, c.DOMAIN_BEACON_PROPOSER, &seed);

    const proposer_indices = try allocator.alloc(ValidatorIndex, preset.SLOTS_PER_EPOCH);
    try computeProposerIndices(
        allocator,
        epoch,
        &seed,
        active_indices_list.items,
        effective_balance_increments,
        proposer_indices,
    );

    return proposer_indices;
}

/// Initializes `proposer_lookahead` during the Electra -> Fulu upgrade.
/// Fills the `proposer_lookahead` field with `(MIN_SEED_LOOKAHEAD + 1)` epochs worth of proposer indices.
pub fn initializeProposerLookahead(
    allocator: Allocator,
    state: *const BeaconStateAllForks,
    effective_balance_increments: *const EffectiveBalanceIncrements,
    out: []ValidatorIndex,
) !void {
    std.debug.assert(effective_balance_increments.items.len > 0);
    const lookahead_epochs = preset.MIN_SEED_LOOKAHEAD + 1;
    const expected_len = lookahead_epochs * preset.SLOTS_PER_EPOCH;
    std.debug.assert(out.len == expected_len);

    const current_epoch = computeEpochAtSlot(state.slot());

    // Fill proposer_lookahead with current epoch through current_epoch + MIN_SEED_LOOKAHEAD
    for (0..lookahead_epochs) |i| {
        const epoch = current_epoch + i;
        const epoch_proposers = try getBeaconProposerIndices(
            allocator,
            state,
            epoch,
            effective_balance_increments,
        );
        defer allocator.free(epoch_proposers);

        const offset = i * preset.SLOTS_PER_EPOCH;
        std.mem.copyForwards(ValidatorIndex, out[offset .. offset + preset.SLOTS_PER_EPOCH], epoch_proposers);
    }
}

/// Updates `proposer_lookahead` during epoch processing.
/// Shifts out the oldest epoch and appends the new epoch at the end.
pub fn processProposerLookahead(
    allocator: Allocator,
    state: *BeaconStateAllForks,
    effective_balance_increments: *const EffectiveBalanceIncrements,
) !void {
    std.debug.assert(effective_balance_increments.items.len > 0);
    // Only process for Fulu fork
    if (!state.isFulu()) return;

    const fulu_state = switch (state.*) {
        .fulu => |s| s,
        else => return error.NotFuluState,
    };

    const lookahead_epochs = preset.MIN_SEED_LOOKAHEAD + 1;
    const last_epoch_start = (lookahead_epochs - 1) * preset.SLOTS_PER_EPOCH;

    // Shift out proposers in the first epoch
    std.mem.copyForwards(
        ValidatorIndex,
        fulu_state.proposer_lookahead[0..last_epoch_start],
        fulu_state.proposer_lookahead[preset.SLOTS_PER_EPOCH..],
    );

    // Fill in the last epoch with new proposer indices
    const current_epoch = computeEpochAtSlot(state.slot());
    const last_epoch = current_epoch + preset.MIN_SEED_LOOKAHEAD + 1;

    const last_epoch_proposers = try getBeaconProposerIndices(
        allocator,
        state,
        last_epoch,
        effective_balance_increments,
    );
    defer allocator.free(last_epoch_proposers);

    std.mem.copyForwards(
        ValidatorIndex,
        fulu_state.proposer_lookahead[last_epoch_start..],
        last_epoch_proposers,
    );
}
