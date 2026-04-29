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

/// 48 + 32 + 8 + 1 + 8 + 8 + 8 + 8 = 121
///
/// ```
/// class Validator(Container):
///   pubkey: BLSPubkey [fixed - 48 bytes]
///   withdrawal_credentials: Bytes32 [fixed - 32 bytes]
///   effective_balance: Gwei [fixed - 8 bytes]
///   slashed: boolean [fixed - 1 byte]
///   # Status epochs
///   activation_eligibility_epoch: Epoch [fixed - 8 bytes]
///   activation_epoch: Epoch [fixed - 8 bytes]
///   exit_epoch: Epoch [fixed - 8 bytes]
///   withdrawable_epoch: Epoch [fixed - 8 bytes]
/// ```
pub const VALIDATOR_BYTES_SIZE: usize = 121;

pub fn getStateSlotFromBytes(bytes: []const u8) !Slot {
    if (bytes.len < SLOT_BYTES_POSITION_IN_STATE + SLOT_BYTE_COUNT) return error.InvalidSize;
    return @intCast(std.mem.readInt(u64, bytes[SLOT_BYTES_POSITION_IN_STATE .. SLOT_BYTES_POSITION_IN_STATE + SLOT_BYTE_COUNT], .little));
}

pub fn getForkFromStateBytes(config: *const BeaconConfig, bytes: []const u8) !ForkSeq {
    const slot = try getStateSlotFromBytes(bytes);
    return config.forkSeq(slot);
}
