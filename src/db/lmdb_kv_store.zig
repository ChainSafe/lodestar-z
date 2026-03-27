//! LmdbKVStore: persistent KVStore implementation backed by LMDB with named databases.
//!
//! Each DatabaseId maps to a separate LMDB named database (DBI), opened at init.
//! All DBIs share a single memory-mapped environment — zero extra overhead per DBI.
//!
//! Thread-safety: Read operations are fully concurrent (LMDB MVCC).
//! Write operations are serialized by LMDB's single-writer lock.

const std = @import("std");
const Allocator = std.mem.Allocator;
const lmdb = @import("lmdb.zig");
const LmdbEnv = lmdb.LmdbEnv;
const LmdbError = lmdb.LmdbError;
const kv_store = @import("kv_store.zig");
const KVStore = kv_store.KVStore;
const BatchOp = kv_store.BatchOp;
const buckets = @import("buckets.zig");
const DatabaseId = buckets.DatabaseId;

pub const LmdbKVStore = struct {
    allocator: Allocator,
    env: LmdbEnv,
    /// DBI handles indexed by DatabaseId enum value.
    dbis: [DatabaseId.count]lmdb.Dbi,
    closed: bool,

    /// Open an LMDB-backed KVStore with named databases at the given directory path.
    pub fn open(allocator: Allocator, path: [*:0]const u8, opts: OpenOptions) LmdbError!LmdbKVStore {
        const env = try LmdbEnv.open(path, .{
            .map_size = opts.map_size,
            .max_readers = opts.max_readers,
            .max_dbs = DatabaseId.count,
        });
        errdefer env.close();

        // Open all named databases in a single write transaction.
        var dbis: [DatabaseId.count]lmdb.Dbi = undefined;
        {
            var txn = try env.beginTxn(.{});
            errdefer txn.abort();

            for (DatabaseId.all, 0..) |db_id, i| {
                dbis[i] = try txn.openDbi(db_id.name());
            }

            try txn.commit();
        }

        return .{
            .allocator = allocator,
            .env = env,
            .dbis = dbis,
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

    fn getDbi(self: *LmdbKVStore, db_id: DatabaseId) lmdb.Dbi {
        return self.dbis[@intFromEnum(db_id)];
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
        .allKeys = vtableAllKeys,
        .allEntries = vtableAllEntries,
        .close = vtableClose,
    };

    fn vtableGet(ptr: *anyopaque, db_id: DatabaseId, key: []const u8) anyerror!?[]const u8 {
        const self: *LmdbKVStore = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StoreClosed;

        var txn = try self.env.beginTxn(.{ .read_only = true });
        defer txn.abort();

        const value = try txn.getFromDbi(self.getDbi(db_id), key) orelse return null;
        return try self.allocator.dupe(u8, value);
    }

    fn vtablePut(ptr: *anyopaque, db_id: DatabaseId, key: []const u8, value: []const u8) anyerror!void {
        const self: *LmdbKVStore = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StoreClosed;

        var txn = try self.env.beginTxn(.{});
        errdefer txn.abort();
        try txn.putToDbi(self.getDbi(db_id), key, value);
        try txn.commit();
    }

    fn vtableDelete(ptr: *anyopaque, db_id: DatabaseId, key: []const u8) anyerror!void {
        const self: *LmdbKVStore = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StoreClosed;

        var txn = try self.env.beginTxn(.{});
        errdefer txn.abort();
        _ = try txn.delFromDbi(self.getDbi(db_id), key);
        try txn.commit();
    }

    fn vtableWriteBatch(ptr: *anyopaque, ops: []const BatchOp) anyerror!void {
        const self: *LmdbKVStore = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StoreClosed;

        var txn = try self.env.beginTxn(.{});
        errdefer txn.abort();

        for (ops) |op| {
            switch (op) {
                .put => |p| try txn.putToDbi(self.getDbi(p.db), p.key, p.value),
                .delete => |d| _ = try txn.delFromDbi(self.getDbi(d.db), d.key),
            }
        }

        try txn.commit();
    }

    fn vtableAllKeys(ptr: *anyopaque, db_id: DatabaseId) anyerror![]const []const u8 {
        const self: *LmdbKVStore = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StoreClosed;

        var txn = try self.env.beginTxn(.{ .read_only = true });
        defer txn.abort();

        var cursor = try txn.openCursorDbi(self.getDbi(db_id));
        defer cursor.close();

        var result: std.ArrayListUnmanaged([]const u8) = .empty;
        errdefer {
            for (result.items) |k| self.allocator.free(k);
            result.deinit(self.allocator);
        }

        var entry = try cursor.first();
        while (entry) |e| {
            try result.append(self.allocator, try self.allocator.dupe(u8, e.key));
            entry = try cursor.next();
        }

        return try result.toOwnedSlice(self.allocator);
    }

    fn vtableAllEntries(ptr: *anyopaque, db_id: DatabaseId) anyerror!KVStore.EntryList {
        const self: *LmdbKVStore = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StoreClosed;

        var txn = try self.env.beginTxn(.{ .read_only = true });
        defer txn.abort();

        var cursor = try txn.openCursorDbi(self.getDbi(db_id));
        defer cursor.close();

        var keys: std.ArrayListUnmanaged([]const u8) = .empty;
        var values: std.ArrayListUnmanaged([]const u8) = .empty;
        errdefer {
            for (keys.items) |k| self.allocator.free(k);
            keys.deinit(self.allocator);
            for (values.items) |v| self.allocator.free(v);
            values.deinit(self.allocator);
        }

        var entry = try cursor.first();
        while (entry) |e| {
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
