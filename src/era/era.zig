const std = @import("std");
const preset = @import("preset").preset;
const fork_types = @import("fork_types");
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
pub fn readGroupIndex(allocator: std.mem.Allocator, file: std.Io.File, io: std.Io, end: u64) !GroupIndex {
    const state_index = try e2s.readSlotIndex(allocator, file, io, end);
    errdefer state_index.deinit(allocator);

    if (state_index.offsets.len != 1) {
        return error.InvalidE2SHeader;
    }

    // Read block index if not genesis era (era 0)
    var blocks_index: ?e2s.SlotIndex = null;
    if (state_index.start_slot != 0) {
        blocks_index = try e2s.readSlotIndex(allocator, file, io, state_index.record_start);
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
pub fn readAllGroupIndices(allocator: std.mem.Allocator, io: std.Io, file: std.Io.File) ![]GroupIndex {
    var end: i64 = @intCast(try file.length(io));

    var group_indices = try std.array_list.AlignedManaged(GroupIndex, null).initCapacity(
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
        const index = try readGroupIndex(allocator, file, io, @intCast(end));
        errdefer index.deinit(allocator);

        try group_indices.append(index);
        end = if (index.blocks_index) |bi|
            @as(i64, @intCast(bi.record_start)) + bi.offsets[0] - e2s.header_size
        else
            @as(i64, @intCast(index.state_index.record_start)) + index.state_index.offsets[0] - e2s.header_size;
    }

    return group_indices.toOwnedSlice();
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

pub fn getShortHistoricalRoot(state: fork_types.AnyBeaconState) ![8]u8 {
    const allocator = std.heap.page_allocator;
    var short_historical_root: [8]u8 = undefined;
    var s = state;
    var historical_root: [32]u8 = undefined;
    if (try s.slot() == 0) {
        historical_root = (try s.genesisValidatorsRoot()).*;
    } else if (s.forkSeq().gte(.capella)) {
        var summaries = try s.historicalSummaries();
        const len = try summaries.length();
        if (len == 0) return error.EmptyHistoricalSummaries;
        var last = try summaries.get(len - 1);
        historical_root = (try last.hashTreeRoot()).*;
    } else {
        var roots = try s.historicalRoots();
        const len = try roots.length();
        if (len == 0) return error.EmptyHistoricalRoots;
        var last = try roots.get(len - 1);
        try last.toValue(allocator, &historical_root);
    }

    _ = try std.fmt.bufPrint(&short_historical_root, "{x}", .{historical_root[0..4]});
    return short_historical_root;
}

// ── Unit tests ──────────────────────────────────────────────────────────

test "EraFileName.parse - valid filename" {
    const result = try EraFileName.parse("mainnet-00001-a1b2c3d4.era");
    try std.testing.expectEqualStrings("mainnet", result.config_name);
    try std.testing.expectEqual(@as(u64, 1), result.era_number);
    try std.testing.expectEqualStrings("a1b2c3d4", &result.short_historical_root);
}

test "EraFileName.parse - large era number" {
    const result = try EraFileName.parse("mainnet-99999-deadbeef.era");
    try std.testing.expectEqual(@as(u64, 99999), result.era_number);
    try std.testing.expectEqualStrings("deadbeef", &result.short_historical_root);
}

test "EraFileName.parse - different config names" {
    const result = try EraFileName.parse("goerli-00042-12345678.era");
    try std.testing.expectEqualStrings("goerli", result.config_name);
    try std.testing.expectEqual(@as(u64, 42), result.era_number);
}

test "EraFileName.parse - invalid: no .era extension" {
    try std.testing.expectError(error.InvalidEraFileName, EraFileName.parse("mainnet-00001-a1b2c3d4.bin"));
}

test "EraFileName.parse - invalid: wrong root length" {
    try std.testing.expectError(error.InvalidEraFileName, EraFileName.parse("mainnet-00001-abc.era"));
}

test "EraFileName.parse - with directory path" {
    const result = try EraFileName.parse("/data/era/mainnet-00100-aabbccdd.era");
    try std.testing.expectEqualStrings("mainnet", result.config_name);
    try std.testing.expectEqual(@as(u64, 100), result.era_number);
}

test "computeEraNumberFromBlockSlot" {
    // Slot 0 → era 1 (genesis blocks are in era 1)
    try std.testing.expectEqual(@as(u64, 1), computeEraNumberFromBlockSlot(0));
    // Slot 8191 → era 1 (last slot of first era, with SLOTS_PER_HISTORICAL_ROOT=8192)
    try std.testing.expectEqual(@as(u64, 1), computeEraNumberFromBlockSlot(preset.SLOTS_PER_HISTORICAL_ROOT - 1));
    // Slot 8192 → era 2
    try std.testing.expectEqual(@as(u64, 2), computeEraNumberFromBlockSlot(preset.SLOTS_PER_HISTORICAL_ROOT));
}

test "computeStartBlockSlotFromEraNumber" {
    // Era 1 starts at slot 0
    try std.testing.expectEqual(@as(u64, 0), try computeStartBlockSlotFromEraNumber(1));
    // Era 2 starts at SLOTS_PER_HISTORICAL_ROOT
    try std.testing.expectEqual(@as(u64, preset.SLOTS_PER_HISTORICAL_ROOT), try computeStartBlockSlotFromEraNumber(2));
}

test "computeStartBlockSlotFromEraNumber - era 0 underflows" {
    try std.testing.expectError(error.Overflow, computeStartBlockSlotFromEraNumber(0));
}

test "isValidEraBlockSlot" {
    // Slot 0 is valid for era 1
    try std.testing.expect(isValidEraBlockSlot(0, 1));
    // Slot 0 is NOT valid for era 2
    try std.testing.expect(!isValidEraBlockSlot(0, 2));
    // Slot SLOTS_PER_HISTORICAL_ROOT is valid for era 2
    try std.testing.expect(isValidEraBlockSlot(preset.SLOTS_PER_HISTORICAL_ROOT, 2));
}

test "isValidEraStateSlot" {
    // Slot 0 is valid state slot for era 0
    try std.testing.expect(isValidEraStateSlot(0, 0));
    // Slot SLOTS_PER_HISTORICAL_ROOT is valid state slot for era 1
    try std.testing.expect(isValidEraStateSlot(preset.SLOTS_PER_HISTORICAL_ROOT, 1));
    // Non-aligned slot is not valid
    try std.testing.expect(!isValidEraStateSlot(1, 0));
    try std.testing.expect(!isValidEraStateSlot(100, 0));
}

test "era number and block slot roundtrip" {
    // For any era number > 0, the start block slot should map back to that era
    for (1..10) |era_num| {
        const start_slot = try computeStartBlockSlotFromEraNumber(era_num);
        try std.testing.expectEqual(era_num, computeEraNumberFromBlockSlot(start_slot));
    }
}
