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
const db_metrics = @import("metrics.zig");
const DatabaseMetrics = db_metrics.MetricsSnapshot;
const DatabaseOperation = db_metrics.Operation;
pub const LmdbKVStore = struct {
    allocator: Allocator,
    io: std.Io,
    env: LmdbEnv,
    /// DBI handles indexed by DatabaseId enum value.
    dbis: [DatabaseId.count]lmdb.Dbi,
    op_counts: [db_metrics.metric_operations.len]std.atomic.Value(u64),
    op_time_ns: [db_metrics.metric_operations.len]std.atomic.Value(u64),
    closed: bool,

    /// Open an LMDB-backed KVStore with named databases at the given directory path.
    pub fn open(allocator: Allocator, io: std.Io, path: [*:0]const u8, opts: OpenOptions) LmdbError!LmdbKVStore {
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
            .io = io,
            .env = env,
            .dbis = dbis,
            .op_counts = zeroAtomicCounters(),
            .op_time_ns = zeroAtomicCounters(),
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

    fn getDbi(self: *const LmdbKVStore, db_id: DatabaseId) lmdb.Dbi {
        return self.dbis[@intFromEnum(db_id)];
    }

    /// Close the underlying LMDB environment.
    pub fn deinit(self: *LmdbKVStore) void {
        if (!self.closed) {
            self.env.close();
            self.closed = true;
        }
    }

    pub fn metricsSnapshot(self: *const LmdbKVStore) !DatabaseMetrics {
        if (self.closed) return error.StoreClosed;

        var txn = try self.env.beginTxn(.{ .read_only = true });
        defer txn.abort();

        const env_info = try self.env.info();
        const env_stat = try self.env.stat();

        var snapshot: DatabaseMetrics = .{
            .lmdb_map_size_bytes = @intCast(env_info.me_mapsize),
            .lmdb_page_size_bytes = @intCast(env_stat.ms_psize),
            .lmdb_last_page_number = @intCast(env_info.me_last_pgno),
            .lmdb_last_txnid = @intCast(env_info.me_last_txnid),
            .lmdb_readers_used = @intCast(env_info.me_numreaders),
            .lmdb_readers_max = @intCast(env_info.me_maxreaders),
        };
        snapshot.lmdb_data_size_bytes = snapshot.lmdb_page_size_bytes * (snapshot.lmdb_last_page_number + 1);

        for (DatabaseId.all, 0..) |db_id, i| {
            const stat = try txn.statDbi(self.getDbi(db_id));
            const entries: u64 = @intCast(stat.ms_entries);
            snapshot.entry_counts[i] = entries;
            snapshot.total_entries += entries;
        }

        inline for (db_metrics.metric_operations, 0..) |operation, i| {
            snapshot.operation_counts[i] = self.op_counts[@intFromEnum(operation)].load(.monotonic);
            snapshot.operation_time_ns[i] = self.op_time_ns[@intFromEnum(operation)].load(.monotonic);
        }
        return snapshot;
    }

    // ---- VTable ----

    const vtable = KVStore.VTable{
        .get = vtableGet,
        .put = vtablePut,
        .delete = vtableDelete,
        .writeBatch = vtableWriteBatch,
        .allKeys = vtableAllKeys,
        .allEntries = vtableAllEntries,
        .firstKey = vtableFirstKey,
        .lastKey = vtableLastKey,
        .close = vtableClose,
    };

    fn vtableGet(ptr: *anyopaque, db_id: DatabaseId, key: []const u8) anyerror!?[]const u8 {
        const self: *LmdbKVStore = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StoreClosed;
        const started_ns = self.nowNs();
        defer self.recordOperation(.get, started_ns);

        var txn = try self.env.beginTxn(.{ .read_only = true });
        defer txn.abort();

        const value = try txn.getFromDbi(self.getDbi(db_id), key) orelse return null;
        return try self.allocator.dupe(u8, value);
    }

    fn vtablePut(ptr: *anyopaque, db_id: DatabaseId, key: []const u8, value: []const u8) anyerror!void {
        const self: *LmdbKVStore = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StoreClosed;
        const started_ns = self.nowNs();
        defer self.recordOperation(.put, started_ns);

        var txn = try self.env.beginTxn(.{});
        txn.putToDbi(self.getDbi(db_id), key, value) catch |err| {
            txn.abort();
            return err;
        };
        try txn.commit();
    }

    fn vtableDelete(ptr: *anyopaque, db_id: DatabaseId, key: []const u8) anyerror!void {
        const self: *LmdbKVStore = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StoreClosed;
        const started_ns = self.nowNs();
        defer self.recordOperation(.delete, started_ns);

        var txn = try self.env.beginTxn(.{});
        _ = txn.delFromDbi(self.getDbi(db_id), key) catch |err| {
            txn.abort();
            return err;
        };
        try txn.commit();
    }

    fn vtableWriteBatch(ptr: *anyopaque, ops: []const BatchOp) anyerror!void {
        const self: *LmdbKVStore = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StoreClosed;
        const started_ns = self.nowNs();
        defer self.recordOperation(.write_batch, started_ns);

        var txn = try self.env.beginTxn(.{});

        for (ops) |op| {
            switch (op) {
                .put => |p| txn.putToDbi(self.getDbi(p.db), p.key, p.value) catch |err| {
                    txn.abort();
                    return err;
                },
                .delete => |d| {
                    _ = txn.delFromDbi(self.getDbi(d.db), d.key) catch |err| {
                        txn.abort();
                        return err;
                    };
                },
            }
        }

        try txn.commit();
    }

    fn vtableAllKeys(ptr: *anyopaque, db_id: DatabaseId) anyerror![]const []const u8 {
        const self: *LmdbKVStore = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StoreClosed;
        const started_ns = self.nowNs();
        defer self.recordOperation(.all_keys, started_ns);

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
        const started_ns = self.nowNs();
        defer self.recordOperation(.all_entries, started_ns);

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

    fn vtableFirstKey(ptr: *anyopaque, db_id: DatabaseId) anyerror!?[]const u8 {
        const self: *LmdbKVStore = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StoreClosed;
        const started_ns = self.nowNs();
        defer self.recordOperation(.first_key, started_ns);

        var txn = try self.env.beginTxn(.{ .read_only = true });
        defer txn.abort();

        var cursor = try txn.openCursorDbi(self.getDbi(db_id));
        defer cursor.close();

        const entry = try cursor.first() orelse return null;
        return try self.allocator.dupe(u8, entry.key);
    }

    fn vtableLastKey(ptr: *anyopaque, db_id: DatabaseId) anyerror!?[]const u8 {
        const self: *LmdbKVStore = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StoreClosed;
        const started_ns = self.nowNs();
        defer self.recordOperation(.last_key, started_ns);

        var txn = try self.env.beginTxn(.{ .read_only = true });
        defer txn.abort();

        var cursor = try txn.openCursorDbi(self.getDbi(db_id));
        defer cursor.close();

        const entry = try cursor.last() orelse return null;
        return try self.allocator.dupe(u8, entry.key);
    }

    fn zeroAtomicCounters() [db_metrics.metric_operations.len]std.atomic.Value(u64) {
        var counters: [db_metrics.metric_operations.len]std.atomic.Value(u64) = undefined;
        for (&counters) |*counter| {
            counter.* = std.atomic.Value(u64).init(0);
        }
        return counters;
    }

    fn nowNs(self: *const LmdbKVStore) i128 {
        return std.Io.Timestamp.now(self.io, .awake).toNanoseconds();
    }

    fn recordOperation(
        self: *LmdbKVStore,
        operation: DatabaseOperation,
        started_ns: i128,
    ) void {
        const idx = @intFromEnum(operation);
        const ended_ns = self.nowNs();
        const elapsed_ns: u64 = if (ended_ns > started_ns)
            @intCast(ended_ns - started_ns)
        else
            0;
        _ = self.op_counts[idx].fetchAdd(1, .monotonic);
        _ = self.op_time_ns[idx].fetchAdd(elapsed_ns, .monotonic);
    }

    fn vtableClose(ptr: *anyopaque) void {
        const self: *LmdbKVStore = @ptrCast(@alignCast(ptr));
        self.deinit();
    }
};
