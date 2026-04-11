const std = @import("std");
const Allocator = std.mem.Allocator;
const bls = @import("bls");
const BeaconConfig = @import("config").BeaconConfig;
const types = @import("consensus_types");
const Validator = types.phase0.Validator.Type;
const EpochCacheImmutableData = @import("./epoch_cache.zig").EpochCacheImmutableData;
const pubkey_cache = @import("./pubkey_cache.zig");
const PubkeyIndexMap = pubkey_cache.PubkeyIndexMap;
const Index2PubkeyCache = pubkey_cache.Index2PubkeyCache;
const syncPubkeysParallel = pubkey_cache.syncPubkeysParallel;

const pkix_magic = "PKIX";
const pkix_version: u8 = 1;
const pkix_header_len = 52;
const pubkey_index_max_load_percentage: u32 = 80;

/// Application-owned append-only validator pubkey caches.
///
/// The cache is shared by all published states in the process. Validator
/// registries only grow, so historical states can safely borrow any prefix of
/// this cache without requiring a per-state copy.
pub const SharedValidatorPubkeys = struct {
    allocator: Allocator,
    pubkey_to_index: PubkeyIndexMap,
    index_to_pubkey: Index2PubkeyCache,

    pub fn init(allocator: Allocator) SharedValidatorPubkeys {
        return .{
            .allocator = allocator,
            .pubkey_to_index = PubkeyIndexMap.init(allocator),
            .index_to_pubkey = Index2PubkeyCache.init(allocator),
        };
    }

    pub fn deinit(self: *SharedValidatorPubkeys) void {
        self.pubkey_to_index.deinit();
        self.index_to_pubkey.deinit();
    }

    pub fn syncFromValidators(self: *SharedValidatorPubkeys, validators: []const Validator) !void {
        try syncPubkeysParallel(self.allocator, validators, &self.pubkey_to_index, &self.index_to_pubkey);
    }

    pub fn tryLoadOpaqueCache(
        self: *SharedValidatorPubkeys,
        io: std.Io,
        path: []const u8,
        expected_genesis_validators_root: [32]u8,
    ) !bool {
        const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch |err| switch (err) {
            error.FileNotFound => return false,
            else => return err,
        };
        defer file.close(io);

        var header: [pkix_header_len]u8 = undefined;
        const bytes_read = try file.readPositionalAll(io, header[0..], 0);
        if (bytes_read != header.len) {
            std.log.debug("Rejecting validator pubkey cache '{s}': short header read ({d}/{d})", .{ path, bytes_read, header.len });
            return false;
        }

        if (!std.mem.eql(u8, header[0..4], pkix_magic)) {
            std.log.debug("Rejecting validator pubkey cache '{s}': bad magic", .{path});
            return false;
        }
        if (header[4] != pkix_version) {
            std.log.debug("Rejecting validator pubkey cache '{s}': version mismatch (got {d}, want {d})", .{ path, header[4], pkix_version });
            return false;
        }
        if (!std.mem.eql(u8, header[8..40], expected_genesis_validators_root[0..])) {
            std.log.debug("Rejecting validator pubkey cache '{s}': genesis validators root mismatch", .{path});
            return false;
        }

        const len = std.mem.readInt(u32, header[40..44], .little);
        const pubkey_to_index_capacity = std.mem.readInt(u32, header[44..48], .little);
        const index_to_pubkey_capacity = std.mem.readInt(u32, header[48..52], .little);
        if (len > pubkey_to_index_capacity) {
            std.log.debug("Rejecting validator pubkey cache '{s}': len {d} exceeds pubkey_to_index capacity {d}", .{ path, len, pubkey_to_index_capacity });
            return false;
        }
        if (len > index_to_pubkey_capacity) {
            std.log.debug("Rejecting validator pubkey cache '{s}': len {d} exceeds index_to_pubkey capacity {d}", .{ path, len, index_to_pubkey_capacity });
            return false;
        }

        var loaded_pubkey_to_index = PubkeyIndexMap.init(self.allocator);
        var loaded_index_to_pubkey: Index2PubkeyCache = undefined;
        var loaded_index_to_pubkey_initialized = false;
        var keep_loaded_caches = false;
        defer if (!keep_loaded_caches) {
            loaded_pubkey_to_index.deinit();
            if (loaded_index_to_pubkey_initialized) loaded_index_to_pubkey.deinit();
        };
        if (pubkey_to_index_capacity > 0) {
            try ensurePubkeyIndexRawCapacity(&loaded_pubkey_to_index, pubkey_to_index_capacity);
        }

        loaded_index_to_pubkey = try Index2PubkeyCache.initCapacity(self.allocator, @intCast(index_to_pubkey_capacity));
        loaded_index_to_pubkey_initialized = true;
        loaded_index_to_pubkey.items.len = @intCast(len);

        const pubkey_to_index_size = pubkeyIndexWrittenSizeForCapacity(pubkey_to_index_capacity);
        const index_to_pubkey_size = @sizeOf(bls.PublicKey) * @as(usize, len);
        const expected_file_size =
            @as(u64, pkix_header_len) +
            @as(u64, pubkey_to_index_size) +
            @as(u64, index_to_pubkey_size);
        const actual_file_size = (try file.stat(io)).size;
        if (actual_file_size != expected_file_size) {
            std.log.debug("Rejecting validator pubkey cache '{s}': file size mismatch (got {d}, want {d})", .{ path, actual_file_size, expected_file_size });
            return false;
        }

        var offset: u64 = pkix_header_len;
        if (pubkey_to_index_size > 0) {
            const ptr: [*]u8 = @ptrCast(loaded_pubkey_to_index.unmanaged.metadata.?);
            const bytes = ptr[0..pubkey_to_index_size];
            if (try file.readPositionalAll(io, bytes, offset) != bytes.len) {
                std.log.debug("Rejecting validator pubkey cache '{s}': short pubkey_to_index read", .{path});
                return false;
            }
            offset += bytes.len;
        }
        loaded_pubkey_to_index.unmanaged.size = len;
        loaded_pubkey_to_index.unmanaged.available = pubkeyIndexMaxLoad(pubkey_to_index_capacity) - len;

        if (index_to_pubkey_size > 0) {
            const bytes = std.mem.sliceAsBytes(loaded_index_to_pubkey.items);
            if (try file.readPositionalAll(io, bytes, offset) != bytes.len) {
                std.log.debug("Rejecting validator pubkey cache '{s}': short index_to_pubkey read", .{path});
                return false;
            }
        }

        self.pubkey_to_index.deinit();
        self.index_to_pubkey.deinit();
        self.pubkey_to_index = loaded_pubkey_to_index;
        self.index_to_pubkey = loaded_index_to_pubkey;
        keep_loaded_caches = true;
        return true;
    }

    pub fn saveOpaqueCache(
        self: *const SharedValidatorPubkeys,
        io: std.Io,
        path: []const u8,
        genesis_validators_root: [32]u8,
    ) !void {
        if (self.pubkey_to_index.count() != self.index_to_pubkey.items.len) {
            return error.InconsistentCache;
        }

        const file = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
        defer file.close(io);

        var header = [_]u8{0} ** pkix_header_len;
        @memcpy(header[0..4], pkix_magic);
        header[4] = pkix_version;
        @memcpy(header[8..40], genesis_validators_root[0..]);
        std.mem.writeInt(u32, header[40..44], @intCast(self.index_to_pubkey.items.len), .little);
        std.mem.writeInt(u32, header[44..48], @intCast(self.pubkey_to_index.capacity()), .little);
        std.mem.writeInt(u32, header[48..52], @intCast(self.index_to_pubkey.capacity), .little);
        try file.writePositionalAll(io, header[0..], 0);

        const pubkey_to_index_size = pubkeyIndexWrittenSizeForCapacity(self.pubkey_to_index.capacity());
        var offset: u64 = pkix_header_len;
        if (pubkey_to_index_size > 0) {
            const ptr: [*]const u8 = @ptrCast(self.pubkey_to_index.unmanaged.metadata.?);
            try file.writePositionalAll(io, ptr[0..pubkey_to_index_size], offset);
            offset += pubkey_to_index_size;
        }

        try file.writePositionalAll(io, std.mem.sliceAsBytes(self.index_to_pubkey.items), offset);
    }

    pub fn immutableData(
        self: *SharedValidatorPubkeys,
        config: *const BeaconConfig,
    ) EpochCacheImmutableData {
        return .{
            .config = config,
            .pubkey_to_index = &self.pubkey_to_index,
            .index_to_pubkey = &self.index_to_pubkey,
        };
    }

    pub fn ownsStateCaches(
        self: *const SharedValidatorPubkeys,
        pubkey_to_index: *PubkeyIndexMap,
        index_to_pubkey: *Index2PubkeyCache,
    ) bool {
        return pubkey_to_index == &self.pubkey_to_index and index_to_pubkey == &self.index_to_pubkey;
    }
};

fn pubkeyIndexWrittenSizeForCapacity(capacity: usize) usize {
    if (capacity == 0) return 0;

    const K = [48]u8;
    const V = u64;
    const Header = struct {
        values: [*]V,
        keys: [*]K,
        capacity: u32,
    };
    const Metadata = packed struct {
        const FingerPrint = u7;
        fingerprint: FingerPrint,
        used: u1,
    };
    const header_align = @alignOf(Header);
    const key_align = @alignOf(K);
    const val_align = @alignOf(V);
    const max_align = comptime @max(header_align, key_align, val_align);

    const meta_size = @sizeOf(Header) + capacity * @sizeOf(Metadata);

    const keys_start = std.mem.alignForward(usize, meta_size, key_align);
    const keys_end = keys_start + capacity * @sizeOf(K);

    const vals_start = std.mem.alignForward(usize, keys_end, val_align);
    const vals_end = vals_start + capacity * @sizeOf(V);

    const total_size = std.mem.alignForward(usize, vals_end, max_align);
    return total_size - @sizeOf(Header);
}

fn pubkeyIndexMaxLoad(raw_capacity: u32) u32 {
    return @intCast((@as(u64, raw_capacity) * pubkey_index_max_load_percentage) / 100);
}

fn minCountForRawCapacity(raw_capacity: u32) u32 {
    if (raw_capacity == 0) return 0;
    const prev_capacity = raw_capacity / 2;
    if (prev_capacity == 0) return 1;
    return pubkeyIndexMaxLoad(prev_capacity) + 1;
}

fn ensurePubkeyIndexRawCapacity(pubkey_to_index: *PubkeyIndexMap, raw_capacity: u32) !void {
    if (raw_capacity == 0) return;
    try pubkey_to_index.ensureTotalCapacity(@intCast(minCountForRawCapacity(raw_capacity)));
    if (pubkey_to_index.capacity() != raw_capacity) return error.UnexpectedPubkeyIndexCapacity;
}

const testing = std.testing;
const interop = @import("../test_utils/interop_pubkeys.zig");

test "opaque pubkey cache round-trips" {
    const allocator = testing.allocator;
    const count = 4;
    const io = std.testing.io;
    const genesis_validators_root = [_]u8{0x42} ** 32;

    var pubkeys: [count]types.primitive.BLSPubkey.Type = undefined;
    try interop.interopPubkeysCached(count, &pubkeys);

    var validators: [count]Validator = undefined;
    for (0..count) |i| {
        validators[i] = std.mem.zeroes(Validator);
        validators[i].pubkey = pubkeys[i];
    }

    var original = SharedValidatorPubkeys.init(allocator);
    defer original.deinit();
    try original.syncFromValidators(&validators);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const cache_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/pkix", .{tmp.sub_path});
    defer allocator.free(cache_path);

    try original.saveOpaqueCache(io, cache_path, genesis_validators_root);

    var restored = SharedValidatorPubkeys.init(allocator);
    defer restored.deinit();
    try testing.expect(try restored.tryLoadOpaqueCache(io, cache_path, genesis_validators_root));
    try testing.expectEqual(original.pubkey_to_index.count(), restored.pubkey_to_index.count());
    try testing.expectEqual(original.index_to_pubkey.items.len, restored.index_to_pubkey.items.len);

    for (0..count) |i| {
        const original_compressed = original.index_to_pubkey.items[i].compress();
        const restored_compressed = restored.index_to_pubkey.items[i].compress();
        try testing.expectEqualSlices(
            u8,
            original_compressed[0..],
            restored_compressed[0..],
        );
        try testing.expectEqual(original.pubkey_to_index.get(pubkeys[i]), restored.pubkey_to_index.get(pubkeys[i]));
    }
}

test "opaque pubkey cache rejects mismatched genesis validators root" {
    const allocator = testing.allocator;
    const count = 2;
    const io = std.testing.io;
    const genesis_validators_root = [_]u8{0x11} ** 32;
    const wrong_root = [_]u8{0x22} ** 32;

    var pubkeys: [count]types.primitive.BLSPubkey.Type = undefined;
    try interop.interopPubkeysCached(count, &pubkeys);

    var validators: [count]Validator = undefined;
    for (0..count) |i| {
        validators[i] = std.mem.zeroes(Validator);
        validators[i].pubkey = pubkeys[i];
    }

    var original = SharedValidatorPubkeys.init(allocator);
    defer original.deinit();
    try original.syncFromValidators(&validators);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const cache_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/pkix", .{tmp.sub_path});
    defer allocator.free(cache_path);

    try original.saveOpaqueCache(io, cache_path, genesis_validators_root);

    var restored = SharedValidatorPubkeys.init(allocator);
    defer restored.deinit();
    try testing.expect(!(try restored.tryLoadOpaqueCache(io, cache_path, wrong_root)));
    try testing.expectEqual(@as(u32, 0), restored.pubkey_to_index.count());
    try testing.expectEqual(@as(usize, 0), restored.index_to_pubkey.items.len);
}

test "opaque pubkey cache rejects truncated file" {
    const allocator = testing.allocator;
    const io = std.testing.io;
    const genesis_validators_root = [_]u8{0x33} ** 32;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const cache_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/pkix", .{tmp.sub_path});
    defer allocator.free(cache_path);

    const file = try std.Io.Dir.cwd().createFile(io, cache_path, .{ .truncate = true });
    defer file.close(io);
    try file.writePositionalAll(io, "PKIX", 0);

    var restored = SharedValidatorPubkeys.init(allocator);
    defer restored.deinit();
    try testing.expect(!(try restored.tryLoadOpaqueCache(io, cache_path, genesis_validators_root)));
}
