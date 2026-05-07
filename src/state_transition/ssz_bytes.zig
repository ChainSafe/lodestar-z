const std = @import("std");

const types = @import("consensus_types");
const ForkSeq = @import("config").ForkSeq;
const BeaconConfig = @import("config").BeaconConfig;

const Slot = types.primitive.Slot.Type;

///
/// 8 + 32 = 40
///
/// ```
/// class BeaconState(Container):
///   genesis_time: uint64 [fixed - 8 bytes]
///   genesis_validators_root: Root [fixed - 32 bytes]
///   slot: Slot [fixed - 8 bytes]
///   ...
/// ```
const SLOT_BYTES_POSITION_IN_STATE: usize = 40;

/// Slot is `uint64`.
const SLOT_BYTE_COUNT: usize = 8;

/// SSZ-serialized size of a phase0 Validator. Stable across forks.
pub const VALIDATOR_BYTES_SIZE: usize = types.phase0.Validator.fixed_size;

pub fn getStateSlotFromBytes(bytes: []const u8) !Slot {
    if (bytes.len < SLOT_BYTES_POSITION_IN_STATE + SLOT_BYTE_COUNT) return error.InvalidSize;
    return @intCast(std.mem.readInt(u64, bytes[SLOT_BYTES_POSITION_IN_STATE .. SLOT_BYTES_POSITION_IN_STATE + SLOT_BYTE_COUNT], .little));
}

pub fn getForkFromStateBytes(config: *const BeaconConfig, bytes: []const u8) !ForkSeq {
    const slot = try getStateSlotFromBytes(bytes);
    return config.forkSeq(slot);
}
