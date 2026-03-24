//! LmdbKVStore: persistent KVStore implementation backed by LMDB.
//!
//! Maps the KVStore vtable interface onto LMDB transactions:
//! - get: read-only transaction, dupe mmap data into owned slice
//! - put/delete: single write transaction per call
//! - writeBatch: single write transaction for all ops (atomic)
//! - keysWithPrefix/entriesWithPrefix: cursor scan with prefix filter
//!
//! Thread-safety: Read operations are fully concurrent (LMDB MVCC).
//! Write operations are serialized by LMDB's single-writer lock.

const std = @import("std");
const Allocator = std.mem.Allocator;
const lmdb = @import("lmdb.zig");
const LmdbEnv = lmdb.LmdbEnv;
const LmdbTxn = lmdb.LmdbTxn;
const LmdbError = lmdb.LmdbError;
const kv_store = @import("kv_store.zig");
const KVStore = kv_store.KVStore;
const BatchOp = kv_store.BatchOp;

pub const LmdbKVStore = struct {
    allocator: Allocator,
    env: LmdbEnv,
    closed: bool,

    /// Open an LMDB-backed KVStore at the given directory path.
    ///
    /// The directory must exist. A `data.mdb` and `lock.mdb` file will be
    /// created inside it.
    pub fn open(allocator: Allocator, path: [*:0]const u8, opts: OpenOptions) LmdbError!LmdbKVStore {
        return .{
            .allocator = allocator,
            .env = try LmdbEnv.open(path, .{
                .map_size = opts.map_size,
                .max_readers = opts.max_readers,
            }),
            .closed = false,
        };
    }

    pub const OpenOptions = struct {
        map_size: usize = 256 * 1024 * 1024 * 1024, // 256 GB
        max_readers: u32 = 126,
    };

    /// Return the KVStore vtable interface.
    pub fn kvStore(self: *LmdbKVStore) KVStore {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    /// Close the underlying LMDB environment.
    pub fn deinit(self: *LmdbKVStore) void {
        if (!self.closed) {
            self.env.close();
            self.closed = true;
        }
    }

    // ---- VTable ----

    const vtable = KVStore.VTable{
        .get = vtableGet,
        .put = vtablePut,
        .delete = vtableDelete,
        .writeBatch = vtableWriteBatch,
        .keysWithPrefix = vtableKeysWithPrefix,
        .entriesWithPrefix = vtableEntriesWithPrefix,
        .close = vtableClose,
    };

    fn vtableGet(ptr: *anyopaque, key: []const u8) anyerror!?[]const u8 {
        const self: *LmdbKVStore = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StoreClosed;

        var txn = try self.env.beginTxn(.{ .read_only = true });
        defer txn.abort();

        const value = try txn.get(key) orelse return null;
        // Dupe from mmap into owned allocation (mmap data is only valid within txn)
        return try self.allocator.dupe(u8, value);
    }

    fn vtablePut(ptr: *anyopaque, key: []const u8, value: []const u8) anyerror!void {
        const self: *LmdbKVStore = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StoreClosed;

        var txn = try self.env.beginTxn(.{});
        errdefer txn.abort();
        try txn.put(key, value);
        try txn.commit();
    }

    fn vtableDelete(ptr: *anyopaque, key: []const u8) anyerror!void {
        const self: *LmdbKVStore = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StoreClosed;

        var txn = try self.env.beginTxn(.{});
        errdefer txn.abort();
        _ = try txn.del(key);
        try txn.commit();
    }

    fn vtableWriteBatch(ptr: *anyopaque, ops: []const BatchOp) anyerror!void {
        const self: *LmdbKVStore = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StoreClosed;

        // Single write transaction for all ops — atomic commit.
        var txn = try self.env.beginTxn(.{});
        errdefer txn.abort();

        for (ops) |op| {
            switch (op) {
                .put => |p| try txn.put(p.key, p.value),
                .delete => |d| _ = try txn.del(d.key),
            }
        }

        try txn.commit();
    }

    fn vtableKeysWithPrefix(ptr: *anyopaque, prefix: []const u8) anyerror![]const []const u8 {
        const self: *LmdbKVStore = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StoreClosed;

        var txn = try self.env.beginTxn(.{ .read_only = true });
        defer txn.abort();

        var cursor = try txn.openCursor();
        defer cursor.close();

        var result: std.ArrayListUnmanaged([]const u8) = .empty;
        errdefer {
            for (result.items) |k| self.allocator.free(k);
            result.deinit(self.allocator);
        }

        var entry = try cursor.seekRange(prefix);
        while (entry) |e| {
            if (e.key.len < prefix.len or
                !std.mem.eql(u8, e.key[0..prefix.len], prefix)) break;
            try result.append(self.allocator, try self.allocator.dupe(u8, e.key));
            entry = try cursor.next();
        }

        return try result.toOwnedSlice(self.allocator);
    }

    fn vtableEntriesWithPrefix(ptr: *anyopaque, prefix: []const u8) anyerror!KVStore.EntryList {
        const self: *LmdbKVStore = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StoreClosed;

        var txn = try self.env.beginTxn(.{ .read_only = true });
        defer txn.abort();

        var cursor = try txn.openCursor();
        defer cursor.close();

        var keys: std.ArrayListUnmanaged([]const u8) = .empty;
        var values: std.ArrayListUnmanaged([]const u8) = .empty;
        errdefer {
            for (keys.items) |k| self.allocator.free(k);
            keys.deinit(self.allocator);
            for (values.items) |v| self.allocator.free(v);
            values.deinit(self.allocator);
        }

        var entry = try cursor.seekRange(prefix);
        while (entry) |e| {
            if (e.key.len < prefix.len or
                !std.mem.eql(u8, e.key[0..prefix.len], prefix)) break;
            try keys.append(self.allocator, try self.allocator.dupe(u8, e.key));
            try values.append(self.allocator, try self.allocator.dupe(u8, e.value));
            entry = try cursor.next();
        }

        return .{
            .keys = try keys.toOwnedSlice(self.allocator),
            .values = try values.toOwnedSlice(self.allocator),
        };
    }

    fn vtableClose(ptr: *anyopaque) void {
        const self: *LmdbKVStore = @ptrCast(@alignCast(ptr));
        self.deinit();
    }
};
