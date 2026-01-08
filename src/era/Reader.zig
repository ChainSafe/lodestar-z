///! Reader is responsible for reading and validating ERA files.
///! See https://github.com/eth-clients/e2store-format-specs/blob/main/formats/era.md
const std = @import("std");
const c = @import("config");
const preset = @import("preset").preset;
const state_transition = @import("state_transition");
const snappy = @import("snappy").frame;
const e2s = @import("e2s.zig");
const era = @import("era.zig");

config: c.BeaconConfig,
/// The file being read
file: std.fs.File,
/// The era number retrieved from the file name
era_number: u64,
/// The short historical root retrieved from the file name
short_historical_root: [8]u8,
/// An array of state and block indices, one per group
group_indices: []era.GroupIndex,

const Reader = @This();

pub fn open(allocator: std.mem.Allocator, config: c.BeaconConfig, path: []const u8) !Reader {
    const file = try std.fs.cwd().openFile(path, .{});
    const era_file_name = try era.EraFileName.parse(path);
    const group_indices = try era.readAllGroupIndices(allocator, file);
    return .{
        .config = config,
        .file = file,
        .era_number = era_file_name.era_number,
        .short_historical_root = era_file_name.short_historical_root,
        .group_indices = group_indices,
    };
}

pub fn close(self: *Reader, allocator: std.mem.Allocator) void {
    self.file.close();
    for (self.group_indices) |group_index| {
        allocator.free(group_index.state_index.offsets);
        if (group_index.blocks_index) |bi| {
            allocator.free(bi.offsets);
        }
    }
    allocator.free(self.group_indices);
}

pub fn readCompressedState(self: Reader, allocator: std.mem.Allocator, era_number: ?u64) ![]const u8 {
    const state_era_number = era_number orelse self.era_number;
    const group_index = try std.math.sub(u64, state_era_number, self.era_number);
    if (group_index >= self.group_indices.len) {
        return error.InvalidEraNumber;
    }
    const index = self.group_indices[group_index];
    const offset: u64 = @intCast(try std.math.add(i64, @intCast(index.state_index.record_start), index.state_index.offsets[0]));
    const entry = try e2s.readEntry(allocator, self.file, offset);
    errdefer allocator.free(entry.data);
    if (entry.entry_type != .CompressedBeaconState) {
        return error.InvalidE2SHeader;
    }
    return entry.data;
}

pub fn readSerializedState(self: Reader, allocator: std.mem.Allocator, era_number: ?u64) ![]const u8 {
    const compressed = try self.readCompressedState(allocator, era_number);
    defer allocator.free(compressed);

    return try snappy.uncompress(allocator, compressed) orelse error.InvalidE2SHeader;
}

pub fn readState(self: Reader, allocator: std.mem.Allocator, era_number: ?u64) !state_transition.BeaconStateAllForks {
    const serialized = try self.readSerializedState(allocator, era_number);
    defer allocator.free(serialized);

    const state_slot = era.readSlotFromBeaconStateBytes(serialized);
    const state_fork = self.config.forkSeq(state_slot);

    return try state_transition.BeaconStateAllForks.deserialize(allocator, state_fork, serialized);
}

pub fn readCompressedBlock(self: Reader, allocator: std.mem.Allocator, slot: u64) !?[]const u8 {
    const slot_era = era.computeEraNumberFromBlockSlot(slot);
    const group_index = try std.math.sub(u64, slot_era, self.era_number);
    if (group_index >= self.group_indices.len) {
        return error.InvalidEraNumber;
    }
    const index = self.group_indices[group_index];
    const blocks_index = index.blocks_index orelse return error.NoBlockIndex;

    // Calculate offset within the index
    const slot_offset = try std.math.sub(u64, slot, blocks_index.start_slot);
    const offset: u64 = @intCast(try std.math.add(i64, @intCast(blocks_index.record_start), blocks_index.offsets[slot_offset]));
    if (offset == 0) {
        return null; // Empty slot
    }
    const entry = try e2s.readEntry(allocator, self.file, offset);
    errdefer allocator.free(entry.data);
    if (entry.entry_type != .CompressedSignedBeaconBlock) {
        return error.InvalidE2SHeader;
    }
    return entry.data;
}

pub fn readSerializedBlock(self: Reader, allocator: std.mem.Allocator, slot: u64) !?[]const u8 {
    const compressed = try self.readCompressedBlock(allocator, slot) orelse return null;
    defer allocator.free(compressed);

    return try snappy.uncompress(allocator, compressed) orelse error.InvalidE2SHeader;
}

pub fn readBlock(self: Reader, allocator: std.mem.Allocator, slot: u64) !?state_transition.SignedBeaconBlock {
    const serialized = try self.readSerializedBlock(allocator, slot) orelse return null;
    defer allocator.free(serialized);

    const fork_seq = self.config.forkSeq(slot);

    return try state_transition.SignedBeaconBlock.deserialize(allocator, fork_seq, serialized);
}

/// Validate the era file.
/// - e2s format correctness
/// - era range correctness
/// - network correctness for state and blocks
/// - TODO block root and signature matches
pub fn validate(self: Reader, allocator: std.mem.Allocator) !void {
    for (self.group_indices, 0..) |index, group_index| {
        const era_number = self.era_number + group_index;

        // validate version entry
        const start: i64 = if (index.blocks_index) |bi|
            @as(i64, @intCast(bi.record_start)) + bi.offsets[0] - e2s.header_size
        else
            @as(i64, @intCast(index.state_index.record_start)) + index.state_index.offsets[0] - e2s.header_size;
        if (start < 0) {
            return error.InvalidGroupStartIndex;
        }
        try e2s.readVersion(self.file, @intCast(start));

        // Genesis era cannot have a block index
        if (era_number == 0 and index.blocks_index != null) {
            return error.GenesisEraHasBlockIndex;
        }

        // validate state
        // the state is loadable and consistent with the given config
        var state = try self.readState(allocator, era_number);
        defer state.deinit(allocator);

        if (!std.mem.eql(u8, &self.config.genesis_validator_root, &state.genesisValidatorsRoot())) {
            return error.GenesisValidatorRootMismatch;
        }

        // validate blocks
        if (era_number > 0) {
            if (index.blocks_index == null) {
                return error.MissingBlockIndex;
            }

            const start_slot = index.blocks_index.?.start_slot;
            const end_slot = start_slot + index.blocks_index.?.offsets.len;

            if (start_slot % preset.SLOTS_PER_HISTORICAL_ROOT != 0) {
                return error.InvalidBlockIndex;
            }

            if (end_slot != start_slot + preset.SLOTS_PER_HISTORICAL_ROOT) {
                return error.InvalidBlockIndex;
            }

            const blockRoots = state.blockRoots();
            for (start_slot..end_slot) |slot| {
                const block = try self.readBlock(allocator, slot) orelse {
                    if (slot == start_slot) {
                        // first slot in the era can't be easily validated
                        continue;
                    }
                    if (std.mem.eql(
                        u8,
                        &blockRoots[(slot - 1) % preset.SLOTS_PER_HISTORICAL_ROOT],
                        &blockRoots[slot % preset.SLOTS_PER_HISTORICAL_ROOT],
                    )) {
                        continue;
                    }
                    return error.MissingBlock;
                };
                defer block.deinit(allocator);

                var block_root: [32]u8 = undefined;
                try block.beaconBlock().hashTreeRoot(allocator, &block_root);

                if (!std.mem.eql(
                    u8,
                    &blockRoots[slot % preset.SLOTS_PER_HISTORICAL_ROOT],
                    &block_root,
                )) {
                    return error.BlockRootMismatch;
                }
            }
        }
    }
}
