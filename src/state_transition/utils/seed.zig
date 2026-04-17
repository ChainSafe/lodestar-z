const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("consensus_types");
const preset = @import("preset").preset;
const ForkSeq = @import("config").ForkSeq;
const BeaconState = @import("fork_types").BeaconState;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Epoch = types.primitive.Epoch.Type;
const DomainType = types.primitive.DomainType.Type;
const c = @import("constants");
const EPOCHS_PER_HISTORICAL_VECTOR = preset.EPOCHS_PER_HISTORICAL_VECTOR;
const MIN_SEED_LOOKAHEAD = preset.MIN_SEED_LOOKAHEAD;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const EffectiveBalanceIncrements = @import("../cache/effective_balance_increments.zig").EffectiveBalanceIncrements;
const computeStartSlotAtEpoch = @import("./epoch.zig").computeStartSlotAtEpoch;
const ComputeIndexUtils = @import("./committee_indices.zig");
const computeProposerIndex = ComputeIndexUtils.computeProposerIndex;
const computeSyncCommitteeIndices = ComputeIndexUtils.computeSyncCommitteeIndices;
const computeEpochAtSlot = @import("./epoch.zig").computeEpochAtSlot;
const ByteCount = @import("./committee_indices.zig").ByteCount;

pub fn computeProposers(
    comptime fork_seq: ForkSeq,
    allocator: Allocator,
    epoch_seed: [32]u8,
    epoch: Epoch,
    active_indices: []const ValidatorIndex,
    effective_balance_increments: EffectiveBalanceIncrements,
    out: []ValidatorIndex,
) !void {
    const start_slot = computeStartSlotAtEpoch(epoch);
    for (start_slot..start_slot + preset.SLOTS_PER_EPOCH, 0..) |slot, i| {
        // epoch_seed is 32 bytes, slot is 8 bytes
        var buffer: [40]u8 = [_]u8{0} ** (32 + 8);
        @memcpy(buffer[0..32], epoch_seed[0..]);
        std.mem.writeInt(u64, buffer[32..][0..8], slot, .little);

        var seed: [32]u8 = undefined;
        Sha256.hash(buffer[0..], &seed, .{});

        const rand_byte_count: ByteCount = if (comptime fork_seq.gte(.electra)) ByteCount.Two else ByteCount.One;
        const max_effective_balance: u64 = if (comptime fork_seq.gte(.electra)) preset.MAX_EFFECTIVE_BALANCE_ELECTRA else preset.MAX_EFFECTIVE_BALANCE;
        out[i] = try computeProposerIndex(
            allocator,
            &seed,
            active_indices,
            effective_balance_increments.items,
            rand_byte_count,
            max_effective_balance,
            preset.EFFECTIVE_BALANCE_INCREMENT,
            preset.SHUFFLE_ROUND_COUNT,
        );
    }
}

test "computeProposers - sanity" {
    const allocator = std.testing.allocator;
    const epoch_seed: [32]u8 = [_]u8{0} ** 32;
    var active_indices: [5]ValidatorIndex = .{ 0, 1, 2, 3, 4 };
    var effective_balance_increments = EffectiveBalanceIncrements.init(allocator);
    defer effective_balance_increments.deinit();
    for (0..active_indices.len) |_| {
        try effective_balance_increments.append(32);
    }
    var out: [preset.SLOTS_PER_EPOCH]ValidatorIndex = undefined;

    try computeProposers(ForkSeq.phase0, allocator, epoch_seed, 0, active_indices[0..], effective_balance_increments, &out);
    try computeProposers(ForkSeq.electra, allocator, epoch_seed, 0, active_indices[0..], effective_balance_increments, &out);
}

pub fn getNextSyncCommitteeIndices(comptime fork: ForkSeq, allocator: Allocator, state: *BeaconState(fork), active_indices: []const ValidatorIndex, effective_balance_increments: EffectiveBalanceIncrements, out: []ValidatorIndex) !void {
    const rand_byte_count: ByteCount = if (comptime fork.gte(.electra)) ByteCount.Two else ByteCount.One;
    const max_effective_balance: u64 = if (comptime fork.gte(.electra)) preset.MAX_EFFECTIVE_BALANCE_ELECTRA else preset.MAX_EFFECTIVE_BALANCE;
    const epoch = computeEpochAtSlot(try state.slot()) + 1;
    var seed: [32]u8 = undefined;
    try getSeed(fork, state, epoch, c.DOMAIN_SYNC_COMMITTEE, &seed);
    try computeSyncCommitteeIndices(allocator, &seed, active_indices, effective_balance_increments.items, rand_byte_count, max_effective_balance, preset.EFFECTIVE_BALANCE_INCREMENT, preset.SHUFFLE_ROUND_COUNT, out);
}

/// Select PTC_SIZE validators from the given indices using balance-weighted acceptance sampling.
pub fn computePayloadTimelinessCommitteeIndices(
    effective_balance_increments: []const u16,
    indices: []const ValidatorIndex,
    seed: *const [32]u8,
) ![preset.PTC_SIZE]ValidatorIndex {
    if (indices.len == 0) return error.EmptyIndices;

    const MAX_RANDOM_VALUE: u64 = 0xFFFF;
    const max_effective_balance_increment: u64 = preset.MAX_EFFECTIVE_BALANCE_ELECTRA / preset.EFFECTIVE_BALANCE_INCREMENT;

    var result: [preset.PTC_SIZE]ValidatorIndex = undefined;
    var result_len: usize = 0;

    // Pre-allocate hash input buffer: seed (32 bytes) + block index (8 bytes)
    var hash_input: [40]u8 = undefined;
    @memcpy(hash_input[0..32], seed);

    var i: u64 = 0;
    var random_bytes: [32]u8 = undefined;
    var last_block: u64 = std.math.maxInt(u64);

    while (result_len < preset.PTC_SIZE) {
        const candidate_index = indices[@intCast(i % indices.len)];

        // Only recompute hash every 16 iterations
        const block = i / 16;
        if (block != last_block) {
            std.mem.writeInt(u64, hash_input[32..][0..8], block, .little);
            Sha256.hash(&hash_input, &random_bytes, .{});
            last_block = block;
        }

        const offset: usize = @intCast((i % 16) * 2);
        const random_value: u64 = std.mem.readInt(u16, random_bytes[offset..][0..2], .little);

        const candidate_effective_balance_increment: u64 = effective_balance_increments[@intCast(candidate_index)];
        if (candidate_effective_balance_increment * MAX_RANDOM_VALUE >= max_effective_balance_increment * random_value) {
            result[result_len] = candidate_index;
            result_len += 1;
        }
        i += 1;
    }

    return result;
}

/// Compute the Payload Timeliness Committee for a single slot by concatenating all
/// beacon committees for that slot and selecting PTC_SIZE members via balance-weighted sampling.
pub fn computePayloadTimelinessCommitteeForSlot(
    allocator: Allocator,
    slot_seed: *const [32]u8,
    slot_committees: []const []const ValidatorIndex,
    effective_balance_increments: []const u16,
) ![preset.PTC_SIZE]ValidatorIndex {
    var total_len: usize = 0;
    for (slot_committees) |committee| {
        total_len += committee.len;
    }

    const all_indices = try allocator.alloc(ValidatorIndex, total_len);
    defer allocator.free(all_indices);

    var offset: usize = 0;
    for (slot_committees) |committee| {
        @memcpy(all_indices[offset .. offset + committee.len], committee);
        offset += committee.len;
    }

    return computePayloadTimelinessCommitteeIndices(effective_balance_increments, all_indices, slot_seed);
}

/// Compute the Payload Timeliness Committee for every slot in an epoch.
pub fn computePayloadTimelinessCommitteesForEpoch(
    comptime fork: ForkSeq,
    allocator: Allocator,
    state: *BeaconState(fork),
    epoch: Epoch,
    epoch_cache: *const @import("../cache/epoch_cache.zig").EpochCache,
) ![preset.SLOTS_PER_EPOCH][preset.PTC_SIZE]ValidatorIndex {
    var epoch_seed: [32]u8 = undefined;
    try getSeed(fork, state, epoch, c.DOMAIN_PTC_ATTESTER, &epoch_seed);

    const start_slot = computeStartSlotAtEpoch(epoch);

    var slot_seed_input: [40]u8 = undefined;
    @memcpy(slot_seed_input[0..32], &epoch_seed);

    var result: [preset.SLOTS_PER_EPOCH][preset.PTC_SIZE]ValidatorIndex = undefined;

    for (0..preset.SLOTS_PER_EPOCH) |i| {
        const slot = start_slot + i;
        std.mem.writeInt(u64, slot_seed_input[32..][0..8], slot, .little);

        var slot_seed: [32]u8 = undefined;
        Sha256.hash(&slot_seed_input, &slot_seed, .{});

        const committees_per_slot = try epoch_cache.getCommitteeCountPerSlot(epoch);
        const slot_committees = try allocator.alloc([]const ValidatorIndex, committees_per_slot);
        defer allocator.free(slot_committees);

        for (0..committees_per_slot) |ci| {
            slot_committees[ci] = try epoch_cache.getBeaconCommittee(slot, ci);
        }

        result[i] = try computePayloadTimelinessCommitteeForSlot(allocator, &slot_seed, slot_committees, epoch_cache.effective_balance_increments.get().items);
    }

    return result;
}

pub fn getRandaoMix(comptime fork: ForkSeq, state: *BeaconState(fork), epoch: Epoch) !*const [32]u8 {
    var randao_mixes = try state.randaoMixes();
    return try randao_mixes.getFieldRoot(epoch % EPOCHS_PER_HISTORICAL_VECTOR);
}

pub fn getSeed(comptime fork: ForkSeq, state: *BeaconState(fork), epoch: Epoch, domain_type: DomainType, out: *[32]u8) !void {
    const mix = try getRandaoMix(fork, state, epoch + EPOCHS_PER_HISTORICAL_VECTOR - MIN_SEED_LOOKAHEAD - 1);
    var epoch_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &epoch_buf, epoch, .little);
    var buffer = [_]u8{0} ** (types.primitive.DomainType.length + 8 + types.primitive.Bytes32.length);
    std.mem.copyForwards(u8, buffer[0..domain_type.len], domain_type[0..]);
    std.mem.copyForwards(u8, buffer[domain_type.len..(domain_type.len + 8)], epoch_buf[0..]);
    std.mem.copyForwards(u8, buffer[(domain_type.len + 8)..], mix[0..]);
    Sha256.hash(buffer[0..], out, .{});
}
