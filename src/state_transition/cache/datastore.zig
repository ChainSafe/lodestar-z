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
    pub fn toKeyString(self: CheckpointKey, allocator: Allocator) ![]u8 {
        // 16 hex chars for epoch + 1 underscore + 64 hex chars for root = 81 bytes
        const buf = try allocator.alloc(u8, 81);
        _ = std.fmt.bufPrint(buf[0..16], "{x:0>16}", .{self.epoch}) catch unreachable;
        buf[16] = '_';
        _ = std.fmt.bufPrint(buf[17..81], "{s}", .{std.fmt.fmtSliceHexLower(&self.root)}) catch unreachable;
        return buf;
    }
};

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
        return key;
    }

    fn memRead(ptr: *anyopaque, key: []const u8) anyerror!?[]const u8 {
        const self: *MemoryCPStateDatastore = @ptrCast(@alignCast(ptr));
        return self.data.get(key);
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
        var keys = try self.allocator.alloc([]const u8, self.data.count());
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

    pub fn init(allocator: Allocator, dir_path: []const u8) !FileCPStateDatastore {
        // Ensure directory exists
        std.fs.cwd().makePath(dir_path) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        return .{
            .allocator = allocator,
            .dir_path = dir_path,
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

        const file = try std.fs.cwd().createFile(path, .{ .truncate = true });
        defer file.close();
        try file.writeAll(state_bytes);

        return key;
    }

    fn fileRead(ptr: *anyopaque, key: []const u8) anyerror!?[]const u8 {
        const self: *FileCPStateDatastore = @ptrCast(@alignCast(ptr));
        const path = try std.fs.path.join(self.allocator, &[_][]const u8{ self.dir_path, key });
        defer self.allocator.free(path);

        const file = std.fs.cwd().openFile(path, .{}) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
        defer file.close();
        return try file.readToEndAlloc(self.allocator, 512 * 1024 * 1024); // 512MB max
    }

    fn fileRemove(ptr: *anyopaque, key: []const u8) anyerror!void {
        const self: *FileCPStateDatastore = @ptrCast(@alignCast(ptr));
        const path = try std.fs.path.join(self.allocator, &[_][]const u8{ self.dir_path, key });
        defer self.allocator.free(path);

        std.fs.cwd().deleteFile(path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
    }

    fn fileReadKeys(ptr: *anyopaque) anyerror![]const []const u8 {
        const self: *FileCPStateDatastore = @ptrCast(@alignCast(ptr));
        var dir = std.fs.cwd().openDir(self.dir_path, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound => return try self.allocator.alloc([]const u8, 0),
            else => return err,
        };
        defer dir.close();

        var keys = std.ArrayList([]const u8).init(self.allocator);
        errdefer {
            for (keys.items) |k| self.allocator.free(k);
            keys.deinit();
        }

        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (entry.kind == .file and entry.name.len == 81) {
                try keys.append(try self.allocator.dupe(u8, entry.name));
            }
        }

        return try keys.toOwnedSlice();
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

    // Read
    const read_bytes = try ds.read(key);
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
    try std.testing.expectEqualSlices(u8, "abababababababababababababababababababababababababababababababababab", key[17..81]);
}
