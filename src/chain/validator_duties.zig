//! Validator duty computation.
//!
//! Provides functions to determine what each validator should do at a given
//! slot: propose blocks, attest in committees, or participate in sync
//! committees.  All lookups are backed by the `EpochCache` which holds
//! pre-computed shufflings and proposer indices.

const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("consensus_types");
const preset = @import("preset").preset;
const state_transition = @import("state_transition");

const Slot = types.primitive.Slot.Type;
const Epoch = types.primitive.Epoch.Type;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const CommitteeIndex = types.primitive.CommitteeIndex.Type;

const EpochCache = state_transition.EpochCache;

const computeEpochAtSlot = state_transition.computeEpochAtSlot;

// ---------------------------------------------------------------------------
// Duty types
// ---------------------------------------------------------------------------

/// A validator's attestation committee assignment for a single slot.
pub const AttestationDuty = struct {
    /// Slot in which the validator must attest.
    slot: Slot,
    /// Committee index within the slot.
    committee_index: CommitteeIndex,
    /// Number of validators in the committee.
    committee_length: u32,
    /// Validator's position within the committee (0-based).
    validator_committee_index: u32,
};

/// A validator's sync committee assignment.
pub const SyncDuty = struct {
    /// Index into the current sync committee.
    sync_committee_index: u32,
};

// ---------------------------------------------------------------------------
// Duty lookups
// ---------------------------------------------------------------------------

pub const ValidatorDuties = struct {
    /// Return the proposer for `slot`.
    ///
    /// Delegates to `EpochCache.getBeaconProposer`, which indexes into the
    /// pre-computed per-epoch proposer array.
    pub fn getProposer(epoch_cache: *const EpochCache, slot: Slot) !ValidatorIndex {
        return epoch_cache.getBeaconProposer(slot);
    }

    /// Compute the attestation duty for `validator_index` in `epoch`.
    ///
    /// Scans every slot and committee in the epoch's shuffling to find the
    /// validator.  Returns `null` if the validator is not active in the
    /// epoch.
    pub fn getAttestationDuty(
        epoch_cache: *const EpochCache,
        validator_index: ValidatorIndex,
        epoch: Epoch,
    ) !?AttestationDuty {
        const committees_per_slot = epoch_cache.getCommitteeCountPerSlot(epoch) catch return null;
        const epoch_start_slot = epoch * preset.SLOTS_PER_EPOCH;

        var slot: Slot = epoch_start_slot;
        while (slot < epoch_start_slot + preset.SLOTS_PER_EPOCH) : (slot += 1) {
            var ci: CommitteeIndex = 0;
            while (ci < committees_per_slot) : (ci += 1) {
                const committee = epoch_cache.getBeaconCommittee(slot, ci) catch continue;
                for (committee, 0..) |member, pos| {
                    if (member == validator_index) {
                        return AttestationDuty{
                            .slot = slot,
                            .committee_index = ci,
                            .committee_length = @intCast(committee.len),
                            .validator_committee_index = @intCast(pos),
                        };
                    }
                }
            }
        }
        return null;
    }

    /// Find sync committee positions for `validator_index` in the current
    /// sync committee.
    ///
    /// Returns a list of `SyncDuty` entries (one per position the validator
    /// holds in the committee).  Most validators hold at most one position,
    /// but duplicates are possible.  Caller owns the returned slice.
    pub fn getSyncCommitteeDuties(
        allocator: Allocator,
        epoch_cache: *const EpochCache,
        validator_index: ValidatorIndex,
        slot: Slot,
    ) ![]SyncDuty {
        const sync_cache = epoch_cache.getIndexedSyncCommittee(slot) catch return &[_]SyncDuty{};
        const indices = sync_cache.getValidatorIndices();

        var duties = std.ArrayListUnmanaged(SyncDuty).empty;
        errdefer duties.deinit(allocator);

        for (indices, 0..) |idx, i| {
            if (idx == validator_index) {
                try duties.append(allocator, .{
                    .sync_committee_index = @intCast(i),
                });
            }
        }
        return duties.items;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
// Full integration tests require a CachedBeaconState + EpochCache which is
// expensive to construct.  The simulation tests in src/testing/ exercise
// these paths end-to-end.  Here we provide basic compile-time smoke checks.

test "AttestationDuty struct layout" {
    const duty = AttestationDuty{
        .slot = 64,
        .committee_index = 3,
        .committee_length = 128,
        .validator_committee_index = 42,
    };
    try std.testing.expectEqual(@as(Slot, 64), duty.slot);
    try std.testing.expectEqual(@as(u32, 42), duty.validator_committee_index);
}

test "SyncDuty struct layout" {
    const duty = SyncDuty{ .sync_committee_index = 7 };
    try std.testing.expectEqual(@as(u32, 7), duty.sync_committee_index);
}
