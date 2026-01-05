const std = @import("std");
const config = @import("config");
const preset = @import("preset").preset;
const state_transition = @import("state_transition");
const ct = @import("consensus_types");
const e2s = @import("e2s.zig");

/// Parsed components of an .era file name.
/// Format: <config-name>-<era-number>-<short-historical-root>.era
pub const EraFileName = struct {
    config_name: []const u8,
    era_number: u64,
    short_historical_root: [8]u8,

    pub fn parse(path: []const u8) (error{InvalidEraFileName} || std.fmt.ParseIntError)!EraFileName {
        if (!std.mem.endsWith(u8, path, ".era")) {
            return error.InvalidEraFileName;
        }
        var it = std.mem.splitScalar(u8, std.fs.path.stem(path), '-');
        const config_name = it.next() orelse return error.InvalidEraFileName;
        const era_number = try std.fmt.parseUnsigned(u64, it.next() orelse return error.InvalidEraFileName, 10);
        var short_historical_root: [8]u8 = undefined;
        const maybe_short_historical_root = it.next() orelse return error.InvalidEraFileName;
        if (maybe_short_historical_root.len != 8) {
            return error.InvalidEraFileName;
        }
        @memcpy(&short_historical_root, maybe_short_historical_root);
        return .{
            .config_name = config_name,
            .era_number = era_number,
            .short_historical_root = short_historical_root,
        };
    }
};

pub const GroupIndex = struct {
    state_index: e2s.SlotIndex,
    blocks_index: ?e2s.SlotIndex,

    pub fn deinit(self: GroupIndex, allocator: std.mem.Allocator) void {
        self.state_index.deinit(allocator);
        if (self.blocks_index) |bi| {
            bi.deinit(allocator);
        }
    }
};

/// Read state and block SlotIndex entries from an era file and validate alignment.
///
/// Ownership of the returned GroupIndex is transferred to the caller.
pub fn readGroupIndex(allocator: std.mem.Allocator, file: std.fs.File, end: u64) !GroupIndex {
    const state_index = try e2s.readSlotIndex(allocator, file, end);
    errdefer state_index.deinit(allocator);

    if (state_index.offsets.len != 1) {
        return error.InvalidE2SHeader;
    }

    // Read block index if not genesis era (era 0)
    var blocks_index: ?e2s.SlotIndex = null;
    if (state_index.start_slot != 0) {
        blocks_index = try e2s.readSlotIndex(allocator, file, state_index.record_start);
        errdefer blocks_index.?.deinit(allocator);

        if (blocks_index.?.offsets.len != preset.SLOTS_PER_HISTORICAL_ROOT) {
            return error.InvalidE2SHeader;
        }

        // Validate block and state indices are properly aligned
        const expected_block_start = try std.math.sub(u64, state_index.start_slot, preset.SLOTS_PER_HISTORICAL_ROOT);
        if (blocks_index.?.start_slot != expected_block_start) {
            return error.InvalidE2SHeader;
        }
    }

    return .{
        .state_index = state_index,
        .blocks_index = blocks_index,
    };
}

/// Read all indices from an era file
///
/// Ownership of the returned GroupIndex slice is transferred to the caller
pub fn readAllGroupIndices(allocator: std.mem.Allocator, file: std.fs.File) ![]GroupIndex {
    var end: i64 = @intCast(try file.getEndPos());

    var group_indices = try std.ArrayList(GroupIndex).initCapacity(
        allocator,
        // Most era files have a single group, though the spec allows for multiple
        1,
    );
    errdefer {
        for (group_indices.items) |gi| {
            gi.deinit(allocator);
        }
        group_indices.deinit();
    }

    while (end > e2s.header_size) {
        const index = try readGroupIndex(allocator, file, @intCast(end));
        errdefer index.deinit(allocator);

        try group_indices.append(index);
        end = if (index.blocks_index) |bi|
            @as(i64, @intCast(bi.record_start)) + bi.offsets[0] - e2s.header_size
        else
            @as(i64, @intCast(index.state_index.record_start)) + index.state_index.offsets[0] - e2s.header_size;
    }

    return group_indices.toOwnedSlice();
}

pub fn readSlotFromBeaconStateBytes(bytes: []const u8) u64 {
    // slot is at offset 40: 8 (genesisTime) + 32 (genesisValidatorsRoot)
    std.debug.assert(bytes.len >= 48);
    return std.mem.readInt(u64, bytes[40..][0..8], .little);
}

pub fn isValidEraBlockSlot(slot: u64, era_number: u64) bool {
    return computeEraNumberFromBlockSlot(slot) == era_number;
}

pub fn isValidEraStateSlot(slot: u64, era_number: u64) bool {
    return slot % preset.SLOTS_PER_HISTORICAL_ROOT == 0 and slot / preset.SLOTS_PER_HISTORICAL_ROOT == era_number;
}

pub fn computeEraNumberFromBlockSlot(slot: u64) u64 {
    return slot / preset.SLOTS_PER_HISTORICAL_ROOT + 1;
}

pub fn computeStartBlockSlotFromEraNumber(era_number: u64) !u64 {
    return (try std.math.sub(u64, era_number, 1)) * preset.SLOTS_PER_HISTORICAL_ROOT;
}

pub fn getShortHistoricalRoot(state: state_transition.BeaconStateAllForks) ![8]u8 {
    var short_historical_root: [8]u8 = undefined;
    const historical_root = if (state.slot() == 0)
        state.genesisValidatorsRoot()
    else if (state.forkSeq().gte(.capella)) blk: {
        var root: [32]u8 = undefined;
        try ct.capella.HistoricalSummary.hashTreeRoot(&state.historicalSummaries().getLast(), &root);
        break :blk root;
    } else state.historicalRoots().getLast();

    _ = try std.fmt.bufPrint(&short_historical_root, "{x}", .{std.fmt.fmtSliceHexLower(historical_root[0..4])});
    return short_historical_root;
}
