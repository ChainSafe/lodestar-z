//! In-memory deterministic storage with fault injection.
//!
//! Simulates block, state, and blob storage for consensus testing.
//! Supports configurable read corruption and write failure rates.
//! All randomness comes from a seeded PRNG.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Root = [32]u8;

pub const BlobKey = struct {
    root: Root,
    index: u64,
};

pub const Config = struct {
    /// Probability of read corruption (0.0 - 1.0).
    read_corruption_rate: f64 = 0.0,
    /// Probability of write failure.
    write_failure_rate: f64 = 0.0,
};

pub const StorageError = error{
    WriteFailure,
    ReadCorruption,
    OutOfMemory,
};

pub const SimStorage = struct {
    allocator: Allocator,
    prng: *std.Random.DefaultPrng,
    config: Config,

    /// Block storage: root -> data.
    blocks: std.AutoHashMap(Root, []const u8),
    /// State storage: root -> data.
    states: std.AutoHashMap(Root, []const u8),
    /// Blob storage: (root, index) -> data.
    blobs: std.AutoHashMap(BlobKey, []const u8),

    /// Stats for test assertions.
    stats: Stats = .{},

    pub const Stats = struct {
        blocks_written: u64 = 0,
        blocks_read: u64 = 0,
        states_written: u64 = 0,
        states_read: u64 = 0,
        blobs_written: u64 = 0,
        blobs_read: u64 = 0,
        write_failures: u64 = 0,
        read_corruptions: u64 = 0,
    };

    pub fn init(allocator: Allocator, prng: *std.Random.DefaultPrng, config: Config) SimStorage {
        return .{
            .allocator = allocator,
            .prng = prng,
            .config = config,
            .blocks = std.AutoHashMap(Root, []const u8).init(allocator),
            .states = std.AutoHashMap(Root, []const u8).init(allocator),
            .blobs = std.AutoHashMap(BlobKey, []const u8).init(allocator),
        };
    }

    pub fn deinit(self: *SimStorage) void {
        self.freeMap(Root, &self.blocks);
        self.freeMap(Root, &self.states);
        self.freeMap(BlobKey, &self.blobs);
    }

    fn freeMap(self: *SimStorage, comptime K: type, map: *std.AutoHashMap(K, []const u8)) void {
        var it = map.valueIterator();
        while (it.next()) |val| {
            self.allocator.free(val.*);
        }
        map.deinit();
    }

    // ── Block operations ─────────────────────────────────────────────

    pub fn putBlock(self: *SimStorage, root: Root, data: []const u8) StorageError!void {
        return self.put(Root, &self.blocks, root, data, &self.stats.blocks_written);
    }

    pub fn getBlock(self: *SimStorage, root: Root) StorageError!?[]const u8 {
        return self.get(Root, &self.blocks, root, &self.stats.blocks_read);
    }

    pub fn hasBlock(self: *const SimStorage, root: Root) bool {
        return self.blocks.contains(root);
    }

    pub fn deleteBlock(self: *SimStorage, root: Root) void {
        if (self.blocks.fetchRemove(root)) |entry| {
            self.allocator.free(entry.value);
        }
    }

    // ── State operations ─────────────────────────────────────────────

    pub fn putState(self: *SimStorage, root: Root, data: []const u8) StorageError!void {
        return self.put(Root, &self.states, root, data, &self.stats.states_written);
    }

    pub fn getState(self: *SimStorage, root: Root) StorageError!?[]const u8 {
        return self.get(Root, &self.states, root, &self.stats.states_read);
    }

    pub fn hasState(self: *const SimStorage, root: Root) bool {
        return self.states.contains(root);
    }

    // ── Blob operations ──────────────────────────────────────────────

    pub fn putBlob(self: *SimStorage, root: Root, index: u64, data: []const u8) StorageError!void {
        return self.put(BlobKey, &self.blobs, .{ .root = root, .index = index }, data, &self.stats.blobs_written);
    }

    pub fn getBlob(self: *SimStorage, root: Root, index: u64) StorageError!?[]const u8 {
        return self.get(BlobKey, &self.blobs, .{ .root = root, .index = index }, &self.stats.blobs_read);
    }

    pub fn hasBlob(self: *const SimStorage, root: Root, index: u64) bool {
        return self.blobs.contains(.{ .root = root, .index = index });
    }

    // ── Generic operations ───────────────────────────────────────────

    fn put(
        self: *SimStorage,
        comptime K: type,
        map: *std.AutoHashMap(K, []const u8),
        key: K,
        data: []const u8,
        counter: *u64,
    ) StorageError!void {
        // Check for write failure.
        if (self.config.write_failure_rate > 0.0) {
            if (self.randomFloat() < self.config.write_failure_rate) {
                self.stats.write_failures += 1;
                return error.WriteFailure;
            }
        }

        // Free existing data if overwriting.
        if (map.get(key)) |existing| {
            self.allocator.free(existing);
        }

        const data_copy = self.allocator.dupe(u8, data) catch return error.OutOfMemory;
        map.put(key, data_copy) catch {
            self.allocator.free(data_copy);
            return error.OutOfMemory;
        };
        counter.* += 1;
    }

    fn get(
        self: *SimStorage,
        comptime K: type,
        map: *std.AutoHashMap(K, []const u8),
        key: K,
        counter: *u64,
    ) StorageError!?[]const u8 {
        counter.* += 1;

        const data = map.get(key) orelse return null;

        // Check for read corruption.
        if (self.config.read_corruption_rate > 0.0) {
            if (self.randomFloat() < self.config.read_corruption_rate) {
                self.stats.read_corruptions += 1;
                return error.ReadCorruption;
            }
        }

        return data;
    }

    fn randomFloat(self: *SimStorage) f64 {
        const val = self.prng.random().int(u32);
        return @as(f64, @floatFromInt(val)) / @as(f64, @floatFromInt(std.math.maxInt(u32)));
    }

    /// Number of stored blocks.
    pub fn blockCount(self: *const SimStorage) u32 {
        return self.blocks.count();
    }

    /// Number of stored states.
    pub fn stateCount(self: *const SimStorage) u32 {
        return self.states.count();
    }

    /// Number of stored blobs.
    pub fn blobCount(self: *const SimStorage) u32 {
        return self.blobs.count();
    }
};

// ── Tests ────────────────────────────────────────────────────────────

test "SimStorage: basic block CRUD" {
    var prng = std.Random.DefaultPrng.init(42);
    var storage = SimStorage.init(std.testing.allocator, &prng, .{});
    defer storage.deinit();

    const root = [_]u8{0xAA} ** 32;
    const data = "test block data";

    // Not found initially.
    const missing = try storage.getBlock(root);
    try std.testing.expectEqual(@as(?[]const u8, null), missing);
    try std.testing.expect(!storage.hasBlock(root));

    // Store and retrieve.
    try storage.putBlock(root, data);
    try std.testing.expect(storage.hasBlock(root));

    const retrieved = try storage.getBlock(root);
    try std.testing.expect(retrieved != null);
    try std.testing.expectEqualStrings(data, retrieved.?);
    try std.testing.expectEqual(@as(u64, 1), storage.stats.blocks_written);
    try std.testing.expectEqual(@as(u64, 2), storage.stats.blocks_read); // 1 miss + 1 hit
}

test "SimStorage: basic state CRUD" {
    var prng = std.Random.DefaultPrng.init(42);
    var storage = SimStorage.init(std.testing.allocator, &prng, .{});
    defer storage.deinit();

    const root = [_]u8{0xBB} ** 32;
    const data = "test state data";

    try storage.putState(root, data);
    const retrieved = try storage.getState(root);
    try std.testing.expect(retrieved != null);
    try std.testing.expectEqualStrings(data, retrieved.?);
}

test "SimStorage: blob operations" {
    var prng = std.Random.DefaultPrng.init(42);
    var storage = SimStorage.init(std.testing.allocator, &prng, .{});
    defer storage.deinit();

    const root = [_]u8{0xCC} ** 32;

    try storage.putBlob(root, 0, "blob0");
    try storage.putBlob(root, 1, "blob1");

    const b0 = try storage.getBlob(root, 0);
    try std.testing.expectEqualStrings("blob0", b0.?);

    const b1 = try storage.getBlob(root, 1);
    try std.testing.expectEqualStrings("blob1", b1.?);

    // Non-existent index.
    const b2 = try storage.getBlob(root, 2);
    try std.testing.expectEqual(@as(?[]const u8, null), b2);
}

test "SimStorage: write failure" {
    var prng = std.Random.DefaultPrng.init(42);
    var storage = SimStorage.init(std.testing.allocator, &prng, .{
        .write_failure_rate = 1.0, // 100% failure.
    });
    defer storage.deinit();

    const root = [_]u8{0xDD} ** 32;
    const result = storage.putBlock(root, "fail");
    try std.testing.expectError(error.WriteFailure, result);
    try std.testing.expectEqual(@as(u64, 1), storage.stats.write_failures);
}

test "SimStorage: read corruption" {
    var prng = std.Random.DefaultPrng.init(42);
    var storage = SimStorage.init(std.testing.allocator, &prng, .{
        .read_corruption_rate = 1.0, // 100% corruption.
    });
    defer storage.deinit();

    const root = [_]u8{0xEE} ** 32;

    // Write succeeds (no write failure configured).
    try storage.putBlock(root, "good data");

    // Read returns corruption error.
    const result = storage.getBlock(root);
    try std.testing.expectError(error.ReadCorruption, result);
    try std.testing.expectEqual(@as(u64, 1), storage.stats.read_corruptions);
}

test "SimStorage: overwrite existing data" {
    var prng = std.Random.DefaultPrng.init(42);
    var storage = SimStorage.init(std.testing.allocator, &prng, .{});
    defer storage.deinit();

    const root = [_]u8{0xFF} ** 32;

    try storage.putBlock(root, "version1");
    try storage.putBlock(root, "version2");

    const retrieved = try storage.getBlock(root);
    try std.testing.expectEqualStrings("version2", retrieved.?);
    try std.testing.expectEqual(@as(u32, 1), storage.blockCount()); // No duplicates.
}

test "SimStorage: deleteBlock removes data" {
    var prng = std.Random.DefaultPrng.init(42);
    var storage = SimStorage.init(std.testing.allocator, &prng, .{});
    defer storage.deinit();

    const root = [_]u8{0xDD} ** 32;

    // Store, verify, delete, verify gone.
    try storage.putBlock(root, "ephemeral");
    try std.testing.expect(storage.hasBlock(root));
    try std.testing.expectEqual(@as(u32, 1), storage.blockCount());

    storage.deleteBlock(root);
    try std.testing.expect(!storage.hasBlock(root));
    try std.testing.expectEqual(@as(u32, 0), storage.blockCount());

    // Deleting non-existent key is a no-op.
    storage.deleteBlock(root);
    try std.testing.expectEqual(@as(u32, 0), storage.blockCount());
}

test "SimStorage: counts" {
    var prng = std.Random.DefaultPrng.init(42);
    var storage = SimStorage.init(std.testing.allocator, &prng, .{});
    defer storage.deinit();

    try std.testing.expectEqual(@as(u32, 0), storage.blockCount());
    try std.testing.expectEqual(@as(u32, 0), storage.stateCount());
    try std.testing.expectEqual(@as(u32, 0), storage.blobCount());

    try storage.putBlock([_]u8{1} ** 32, "b1");
    try storage.putBlock([_]u8{2} ** 32, "b2");
    try storage.putState([_]u8{3} ** 32, "s1");
    try storage.putBlob([_]u8{4} ** 32, 0, "bl1");

    try std.testing.expectEqual(@as(u32, 2), storage.blockCount());
    try std.testing.expectEqual(@as(u32, 1), storage.stateCount());
    try std.testing.expectEqual(@as(u32, 1), storage.blobCount());
}
