//! Shared utilities for state transition benchmarks

const std = @import("std");
const types = @import("consensus_types");
const config = @import("config");
const state_transition = @import("state_transition");

const ForkSeq = config.ForkSeq;
const BeaconStateAllForks = state_transition.BeaconStateAllForks;
const Slot = types.primitive.Slot.Type;

/// Read slot from raw BeaconState SSZ bytes (offset 40)
pub fn slotFromStateBytes(state_bytes: []const u8) Slot {
    std.debug.assert(state_bytes.len >= 48);
    return std.mem.readInt(u64, state_bytes[40..48], .little);
}

/// Read slot from raw SignedBeaconBlock SSZ bytes (offset 100)
pub fn slotFromBlockBytes(block_bytes: []const u8) Slot {
    std.debug.assert(block_bytes.len >= 108);
    return std.mem.readInt(u64, block_bytes[100..108], .little);
}

/// Load and deserialize BeaconState from SSZ bytes for a specific fork
pub fn loadState(comptime fork: ForkSeq, allocator: std.mem.Allocator, state_bytes: []const u8) !*BeaconStateAllForks {
    const BeaconState = @field(types, @tagName(fork)).BeaconState;
    const state_data = try allocator.create(BeaconState.Type);
    errdefer allocator.destroy(state_data);
    state_data.* = BeaconState.default_value;
    try BeaconState.deserializeFromBytes(allocator, state_bytes, state_data);

    const beacon_state = try allocator.create(BeaconStateAllForks);
    beacon_state.* = @unionInit(BeaconStateAllForks, @tagName(fork), state_data);
    return beacon_state;
}

/// Load and deserialize SignedBeaconBlock from SSZ bytes for a specific fork
pub fn loadBlock(comptime fork: ForkSeq, allocator: std.mem.Allocator, block_bytes: []const u8) !state_transition.SignedBeaconBlock {
    const SignedBeaconBlock = @field(types, @tagName(fork)).SignedBeaconBlock;
    const block_data = try allocator.create(SignedBeaconBlock.Type);
    errdefer allocator.destroy(block_data);
    block_data.* = SignedBeaconBlock.default_value;
    try SignedBeaconBlock.deserializeFromBytes(allocator, block_bytes, block_data);
    return @unionInit(state_transition.SignedBeaconBlock, @tagName(fork), block_data);
}
