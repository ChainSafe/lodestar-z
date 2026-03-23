//! CPStateDatastore: interface and implementations for persisting checkpoint states.
//!
//! Provides:
//! - `CPStateDatastore` — vtable-based interface for checkpoint state persistence
//! - `FileCPStateDatastore` — file-system backed implementation
//! - `MemoryCPStateDatastore` — in-memory implementation for testing
const std = @import("std");
const Allocator = std.mem.Allocator;

/// Key identifying a checkpoint: epoch + block root.
pub const CheckpointKey = struct {
    epoch: u64,
    root: [32]u8,

    pub fn eql(a: CheckpointKey, b: CheckpointKey) bool {
        return a.epoch == b.epoch and std.mem.eql(u8, &a.root, &b.root);
    }

    /// Format as "{epoch:016x}_{root_hex}" for use as a filename / map key.
    /// Caller owns the returned slice.
    pub fn toKeyString(self: CheckpointKey, allocator: Allocator) ![]u8 {
        // 16 hex chars for epoch + 1 underscore + 64 hex chars for root = 81 bytes
        const buf = try allocator.alloc(u8, 81);
        _ = std.fmt.bufPrint(buf[0..81], "{x:0>16}_{x}", .{ self.epoch, self.root }) catch unreachable;
        return buf;
    }
};

/// Read the slot from SSZ-encoded beacon state bytes.
/// In all forks, the BeaconState SSZ layout starts with:
///   genesis_time: u64 (offset 0, 8 bytes)
///   genesis_validators_root: Bytes32 (offset 8, 32 bytes)
///   slot: u64 (offset 40, 8 bytes)
pub fn readSlotFromBytes(state_bytes: []const u8) u64 {
    if (state_bytes.len < 48) return 0;
    return std.mem.readInt(u64, state_bytes[40..48], .little);
}

/// Vtable-based interface for checkpoint state persistence.
pub const CPStateDatastore = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        write: *const fn (ptr: *anyopaque, checkpoint: CheckpointKey, state_bytes: []const u8) anyerror![]const u8,
        read: *const fn (ptr: *anyopaque, key: []const u8) anyerror!?[]const u8,
        remove: *const fn (ptr: *anyopaque, key: []const u8) anyerror!void,
        readKeys: *const fn (ptr: *anyopaque) anyerror![]const []const u8,
    };

    /// Write state bytes for a checkpoint. Returns a datastore key for later retrieval.
    pub fn write(self: CPStateDatastore, cp: CheckpointKey, bytes: []const u8) ![]const u8 {
        return self.vtable.write(self.ptr, cp, bytes);
    }

    /// Read state bytes by datastore key. Returns null if not found.
    pub fn read(self: CPStateDatastore, key: []const u8) !?[]const u8 {
        return self.vtable.read(self.ptr, key);
    }

    /// Remove a persisted state by datastore key.
    pub fn remove(self: CPStateDatastore, key: []const u8) !void {
        return self.vtable.remove(self.ptr, key);
    }

    /// List all persisted datastore keys.
    pub fn readKeys(self: CPStateDatastore) ![]const []const u8 {
        return self.vtable.readKeys(self.ptr);
    }
};

// ---------------------------------------------------------------------------
// In-memory implementation (for testing)
// ---------------------------------------------------------------------------

pub const MemoryCPStateDatastore = struct {
    allocator: Allocator,
    /// key string -> state bytes (both owned by this struct)
    data: std.StringHashMap([]const u8),

    pub fn init(allocator: Allocator) MemoryCPStateDatastore {
        return .{
            .allocator = allocator,
            .data = std.StringHashMap([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *MemoryCPStateDatastore) void {
        var it = self.data.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.value_ptr.*);
            self.allocator.free(entry.key_ptr.*);
        }
        self.data.deinit();
    }

    pub fn datastore(self: *MemoryCPStateDatastore) CPStateDatastore {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &mem_vtable,
        };
    }

    const mem_vtable = CPStateDatastore.VTable{
        .write = memWrite,
        .read = memRead,
        .remove = memRemove,
        .readKeys = memReadKeys,
    };

    fn memWrite(ptr: *anyopaque, checkpoint: CheckpointKey, state_bytes: []const u8) anyerror![]const u8 {
        const self: *MemoryCPStateDatastore = @ptrCast(@alignCast(ptr));
        const key = try checkpoint.toKeyString(self.allocator);
        errdefer self.allocator.free(key);

        // If key already exists, free old value
        if (self.data.fetchRemove(key)) |old| {
            self.allocator.free(old.value);
            self.allocator.free(old.key);
        }

        const bytes_copy = try self.allocator.dupe(u8, state_bytes);
        errdefer self.allocator.free(bytes_copy);

        try self.data.put(key, bytes_copy);

        // Return a caller-owned copy — internal key belongs to the hashmap
        return try self.allocator.dupe(u8, key);
    }

    fn memRead(ptr: *anyopaque, key: []const u8) anyerror!?[]const u8 {
        const self: *MemoryCPStateDatastore = @ptrCast(@alignCast(ptr));
        const data = self.data.get(key) orelse return null;
        // Return owned copy — caller must free with the same allocator
        return try self.allocator.dupe(u8, data);
    }

    fn memRemove(ptr: *anyopaque, key: []const u8) anyerror!void {
        const self: *MemoryCPStateDatastore = @ptrCast(@alignCast(ptr));
        if (self.data.fetchRemove(key)) |old| {
            self.allocator.free(old.value);
            self.allocator.free(old.key);
        }
    }

    fn memReadKeys(ptr: *anyopaque) anyerror![]const []const u8 {
        const self: *MemoryCPStateDatastore = @ptrCast(@alignCast(ptr));
        const keys = try self.allocator.alloc([]const u8, self.data.count());
        var i: usize = 0;
        var it = self.data.keyIterator();
        while (it.next()) |k| {
            keys[i] = k.*;
            i += 1;
        }
        return keys;
    }

    pub fn count(self: *const MemoryCPStateDatastore) usize {
        return self.data.count();
    }
};

// ---------------------------------------------------------------------------
// File-based implementation
// ---------------------------------------------------------------------------

pub const FileCPStateDatastore = struct {
    allocator: Allocator,
    dir_path: []const u8,
    io: std.Io,

    pub fn init(allocator: Allocator, io: std.Io, dir_path: []const u8) !FileCPStateDatastore {
        // Ensure directory exists
        std.Io.Dir.cwd().makePath(io, dir_path) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        return .{
            .allocator = allocator,
            .dir_path = dir_path,
            .io = io,
        };
    }

    pub fn deinit(self: *FileCPStateDatastore) void {
        _ = self;
    }

    pub fn datastore(self: *FileCPStateDatastore) CPStateDatastore {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &file_vtable,
        };
    }

    const file_vtable = CPStateDatastore.VTable{
        .write = fileWrite,
        .read = fileRead,
        .remove = fileRemove,
        .readKeys = fileReadKeys,
    };

    fn fileWrite(ptr: *anyopaque, checkpoint: CheckpointKey, state_bytes: []const u8) anyerror![]const u8 {
        const self: *FileCPStateDatastore = @ptrCast(@alignCast(ptr));
        const key = try checkpoint.toKeyString(self.allocator);
        errdefer self.allocator.free(key);

        const path = try std.fs.path.join(self.allocator, &[_][]const u8{ self.dir_path, key });
        defer self.allocator.free(path);

        const file = try std.Io.Dir.cwd().createFile(self.io, path, .{ .truncate = true });
        defer file.close(self.io);
        try file.writeAll(self.io, state_bytes);

        return key;
    }

    fn fileRead(ptr: *anyopaque, key: []const u8) anyerror!?[]const u8 {
        const self: *FileCPStateDatastore = @ptrCast(@alignCast(ptr));
        const path = try std.fs.path.join(self.allocator, &[_][]const u8{ self.dir_path, key });
        defer self.allocator.free(path);

        const file = std.Io.Dir.cwd().openFile(self.io, path, .{}) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
        defer file.close(self.io);
        return try file.readToEndAlloc(self.io, self.allocator, 512 * 1024 * 1024); // 512MB max
    }

    fn fileRemove(ptr: *anyopaque, key: []const u8) anyerror!void {
        const self: *FileCPStateDatastore = @ptrCast(@alignCast(ptr));
        const path = try std.fs.path.join(self.allocator, &[_][]const u8{ self.dir_path, key });
        defer self.allocator.free(path);

        std.Io.Dir.cwd().deleteFile(self.io, path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
    }

    fn fileReadKeys(ptr: *anyopaque) anyerror![]const []const u8 {
        const self: *FileCPStateDatastore = @ptrCast(@alignCast(ptr));
        var dir = std.Io.Dir.cwd().openDir(self.io, self.dir_path, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound => return try self.allocator.alloc([]const u8, 0),
            else => return err,
        };
        defer dir.close(self.io);

        var keys: std.ArrayListUnmanaged([]const u8) = .empty;
        errdefer {
            for (keys.items) |k| self.allocator.free(k);
            keys.deinit(self.allocator);
        }

        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (entry.kind == .file and entry.name.len == 81) {
                try keys.append(self.allocator, try self.allocator.dupe(u8, entry.name));
            }
        }

        return try keys.toOwnedSlice(self.allocator);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "MemoryCPStateDatastore: write, read, remove" {
    const allocator = std.testing.allocator;
    var store = MemoryCPStateDatastore.init(allocator);
    defer store.deinit();

    var ds = store.datastore();

    const cp = CheckpointKey{ .epoch = 42, .root = [_]u8{0xab} ** 32 };
    const state_bytes: []const u8 = "hello state";

    // Write
    const key = try ds.write(cp, state_bytes);
    defer allocator.free(key);

    // Read (returns owned copy)
    const read_bytes = try ds.read(key);
    defer if (read_bytes) |b| allocator.free(b);
    try std.testing.expect(read_bytes != null);
    try std.testing.expectEqualSlices(u8, state_bytes, read_bytes.?);

    // ReadKeys
    const keys = try ds.readKeys();
    defer allocator.free(keys);
    try std.testing.expectEqual(@as(usize, 1), keys.len);

    // Remove
    try ds.remove(key);
    const after_remove = try ds.read(key);
    try std.testing.expect(after_remove == null);
}

test "MemoryCPStateDatastore: overwrite existing key" {
    const allocator = std.testing.allocator;
    var store = MemoryCPStateDatastore.init(allocator);
    defer store.deinit();

    var ds = store.datastore();

    const cp = CheckpointKey{ .epoch = 1, .root = [_]u8{0x01} ** 32 };

    const key1 = try ds.write(cp, "first");
    defer allocator.free(key1);

    const key2 = try ds.write(cp, "second");
    defer allocator.free(key2);

    const read_bytes = try ds.read(key2);
    defer if (read_bytes) |b| allocator.free(b);
    try std.testing.expect(read_bytes != null);
    try std.testing.expectEqualSlices(u8, "second", read_bytes.?);
}

test "CheckpointKey.toKeyString" {
    const allocator = std.testing.allocator;
    const cp = CheckpointKey{ .epoch = 0x1234, .root = [_]u8{0xab} ** 32 };
    const key = try cp.toKeyString(allocator);
    defer allocator.free(key);

    try std.testing.expectEqual(@as(usize, 81), key.len);
    // epoch part
    try std.testing.expectEqualSlices(u8, "0000000000001234", key[0..16]);
    // separator
    try std.testing.expectEqual(@as(u8, '_'), key[16]);
    // root hex (64 chars of "ab" repeated)
    try std.testing.expectEqualSlices(u8, "abababababababababababababababababababababababababababababababab", key[17..81]);
}



test "readSlotFromBytes" {
    // Construct minimal state bytes: genesis_time(8) + genesis_validators_root(32) + slot(8) = 48 bytes
    var buf: [64]u8 = undefined;
    @memset(&buf, 0);

    // Set slot (offset 40) to 12345 in little-endian
    const slot: u64 = 12345;
    @memcpy(buf[40..48], std.mem.asBytes(&slot));

    try std.testing.expectEqual(@as(u64, 12345), readSlotFromBytes(&buf));

    // Too short buffer returns 0
    try std.testing.expectEqual(@as(u64, 0), readSlotFromBytes(buf[0..16]));
}
