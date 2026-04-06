//! LMDB: Zig wrapper over the Lightning Memory-Mapped Database C API.
//!
//! Provides a safe, idiomatic Zig interface to LMDB's core operations:
//! environment management, transactions, cursor-based iteration,
//! and named database (DBI) support.
//!
//! LMDB characteristics:
//! - Memory-mapped reads (zero-copy from mmap, no allocator needed)
//! - Single-writer / multi-reader (MVCC)
//! - Crash-safe (copy-on-write B+tree)
//! - Tiny footprint (~10K lines C)
//! - Up to 128 named databases per environment
//!
//! All data pointers returned from read transactions point directly into
//! the memory map and are valid only for the lifetime of the transaction.

const std = @import("std");

pub const c = @cImport({
    @cInclude("lmdb.h");
});

/// Opaque DBI handle — wraps MDB_dbi.
pub const Dbi = c.MDB_dbi;

/// LMDB-specific errors mapped from MDB return codes.
pub const LmdbError = error{
    KeyExists,
    NotFound,
    PageNotFound,
    Corrupted,
    Panic,
    VersionMismatch,
    Invalid,
    MapFull,
    DbsFull,
    ReadersFull,
    TlsFull,
    TxnFull,
    CursorFull,
    PageFull,
    MapResized,
    Incompatible,
    BadReaderSlot,
    BadTxn,
    BadValSize,
    BadDbi,
    Unexpected,
};

/// Convert an LMDB C return code to a Zig error.
fn checkRc(rc: c_int) LmdbError!void {
    if (rc == 0) return;
    return switch (rc) {
        c.MDB_KEYEXIST => error.KeyExists,
        c.MDB_NOTFOUND => error.NotFound,
        c.MDB_PAGE_NOTFOUND => error.PageNotFound,
        c.MDB_CORRUPTED => error.Corrupted,
        c.MDB_PANIC => error.Panic,
        c.MDB_VERSION_MISMATCH => error.VersionMismatch,
        c.MDB_INVALID => error.Invalid,
        c.MDB_MAP_FULL => error.MapFull,
        c.MDB_DBS_FULL => error.DbsFull,
        c.MDB_READERS_FULL => error.ReadersFull,
        c.MDB_TLS_FULL => error.TlsFull,
        c.MDB_TXN_FULL => error.TxnFull,
        c.MDB_CURSOR_FULL => error.CursorFull,
        c.MDB_PAGE_FULL => error.PageFull,
        c.MDB_MAP_RESIZED => error.MapResized,
        c.MDB_INCOMPATIBLE => error.Incompatible,
        c.MDB_BAD_RSLOT => error.BadReaderSlot,
        c.MDB_BAD_TXN => error.BadTxn,
        c.MDB_BAD_VALSIZE => error.BadValSize,
        c.MDB_BAD_DBI => error.BadDbi,
        else => error.Unexpected,
    };
}

/// Helper to create an MDB_val from a Zig slice.
fn toVal(data: []const u8) c.MDB_val {
    return .{
        .mv_size = data.len,
        .mv_data = @ptrCast(@constCast(data.ptr)),
    };
}

/// Helper to convert an MDB_val to a Zig slice.
fn fromVal(val: c.MDB_val) []const u8 {
    if (val.mv_data == null or val.mv_size == 0) return &.{};
    const ptr: [*]const u8 = @ptrCast(val.mv_data.?);
    return ptr[0..val.mv_size];
}

// ---------------------------------------------------------------------------
// LmdbEnv
// ---------------------------------------------------------------------------

/// LMDB environment — wraps a single database directory.
///
/// An environment may contain multiple named databases (sub-DBs).
/// Set max_dbs > 0 to enable named database support.
pub const LmdbEnv = struct {
    env: *c.MDB_env,

    pub const OpenOptions = struct {
        /// Maximum database size. Sparse file — costs nothing until written.
        map_size: usize = 256 * 1024 * 1024 * 1024, // 256 GB
        /// Use MDB_NOSUBDIR — path is a filename, not a directory.
        no_subdir: bool = false,
        /// Open in read-only mode (MDB_RDONLY).
        read_only: bool = false,
        /// Maximum number of named databases. 0 = single unnamed DB only.
        max_dbs: u32 = 0,
        /// Maximum concurrent reader slots.
        max_readers: u32 = 126,
        /// File permissions (Unix mode).
        mode: c_uint = 0o664,
    };

    /// Create and open an LMDB environment.
    pub fn open(path: [*:0]const u8, opts: OpenOptions) LmdbError!LmdbEnv {
        var env: ?*c.MDB_env = null;
        try checkRc(c.mdb_env_create(&env));
        errdefer c.mdb_env_close(env.?);

        try checkRc(c.mdb_env_set_mapsize(env.?, opts.map_size));
        if (opts.max_dbs > 0) {
            try checkRc(c.mdb_env_set_maxdbs(env.?, opts.max_dbs));
        }
        try checkRc(c.mdb_env_set_maxreaders(env.?, opts.max_readers));

        var flags: c_uint = c.MDB_NOTLS;
        if (opts.no_subdir) flags |= c.MDB_NOSUBDIR;
        if (opts.read_only) flags |= c.MDB_RDONLY;

        try checkRc(c.mdb_env_open(env.?, path, flags, opts.mode));

        return .{ .env = env.? };
    }

    /// Close the environment and release resources.
    pub fn close(self: LmdbEnv) void {
        c.mdb_env_close(self.env);
    }

    /// Begin a new transaction.
    pub fn beginTxn(self: LmdbEnv, opts: TxnOptions) LmdbError!LmdbTxn {
        var txn: ?*c.MDB_txn = null;
        var flags: c_uint = 0;
        if (opts.read_only) flags |= c.MDB_RDONLY;

        try checkRc(c.mdb_txn_begin(self.env, null, flags, &txn));

        return .{ .txn = txn.? };
    }

    /// Force a sync of the memory map to disk.
    pub fn sync(self: LmdbEnv, force: bool) LmdbError!void {
        try checkRc(c.mdb_env_sync(self.env, @intFromBool(force)));
    }

    /// Get environment-wide statistics.
    pub fn stat(self: LmdbEnv) LmdbError!c.MDB_stat {
        var s: c.MDB_stat = undefined;
        try checkRc(c.mdb_env_stat(self.env, &s));
        return s;
    }

    /// Get environment information such as map size and reader usage.
    pub fn info(self: LmdbEnv) LmdbError!c.MDB_envinfo {
        var i: c.MDB_envinfo = undefined;
        try checkRc(c.mdb_env_info(self.env, &i));
        return i;
    }

    /// Get statistics for a named database.
    pub fn statDbi(self: LmdbEnv, dbi: Dbi) LmdbError!c.MDB_stat {
        var txn: ?*c.MDB_txn = null;
        try checkRc(c.mdb_txn_begin(self.env, null, c.MDB_RDONLY, &txn));
        defer c.mdb_txn_abort(txn.?);
        var s: c.MDB_stat = undefined;
        try checkRc(c.mdb_stat(txn.?, dbi, &s));
        return s;
    }

    pub const TxnOptions = struct {
        read_only: bool = false,
    };
};

// ---------------------------------------------------------------------------
// LmdbTxn
// ---------------------------------------------------------------------------

/// LMDB transaction — provides DBI opening and data operations.
///
/// Read transactions may be used concurrently. Write transactions are
/// serialized by LMDB (single writer lock).
pub const LmdbTxn = struct {
    txn: *c.MDB_txn,

    /// Open (or create) a named database. Must be called from a write transaction
    /// the first time a database is used. Returns a DBI handle.
    pub fn openDbi(self: LmdbTxn, db_name: [*:0]const u8) LmdbError!Dbi {
        var dbi: Dbi = undefined;
        try checkRc(c.mdb_dbi_open(self.txn, db_name, c.MDB_CREATE, &dbi));
        return dbi;
    }

    /// Get a value from a named database. Zero-copy from mmap.
    pub fn getFromDbi(self: LmdbTxn, dbi: Dbi, key: []const u8) LmdbError!?[]const u8 {
        var k = toVal(key);
        var v: c.MDB_val = undefined;
        const rc = c.mdb_get(self.txn, dbi, &k, &v);
        if (rc == c.MDB_NOTFOUND) return null;
        try checkRc(rc);
        return fromVal(v);
    }

    /// Store a key-value pair in a named database.
    pub fn putToDbi(self: LmdbTxn, dbi: Dbi, key: []const u8, value: []const u8) LmdbError!void {
        var k = toVal(key);
        var v = toVal(value);
        try checkRc(c.mdb_put(self.txn, dbi, &k, &v, 0));
    }

    /// Delete a key from a named database. Returns false if not found.
    pub fn delFromDbi(self: LmdbTxn, dbi: Dbi, key: []const u8) LmdbError!bool {
        var k = toVal(key);
        const rc = c.mdb_del(self.txn, dbi, &k, null);
        if (rc == c.MDB_NOTFOUND) return false;
        try checkRc(rc);
        return true;
    }

    /// Open a cursor on a named database.
    pub fn openCursorDbi(self: LmdbTxn, dbi: Dbi) LmdbError!LmdbCursor {
        var cursor: ?*c.MDB_cursor = null;
        try checkRc(c.mdb_cursor_open(self.txn, dbi, &cursor));
        return .{ .cursor = cursor.? };
    }

    /// Get statistics for a named database within this transaction.
    pub fn statDbi(self: LmdbTxn, dbi: Dbi) LmdbError!c.MDB_stat {
        var s: c.MDB_stat = undefined;
        try checkRc(c.mdb_stat(self.txn, dbi, &s));
        return s;
    }

    /// Commit the transaction.
    pub fn commit(self: LmdbTxn) LmdbError!void {
        try checkRc(c.mdb_txn_commit(self.txn));
    }

    /// Abort the transaction.
    pub fn abort(self: LmdbTxn) void {
        c.mdb_txn_abort(self.txn);
    }
};

// ---------------------------------------------------------------------------
// LmdbCursor
// ---------------------------------------------------------------------------

/// LMDB cursor for sequential/range iteration over key-value pairs.
pub const LmdbCursor = struct {
    cursor: *c.MDB_cursor,

    pub const Entry = struct {
        key: []const u8,
        value: []const u8,
    };

    /// Position at the first entry (MDB_FIRST).
    pub fn first(self: LmdbCursor) LmdbError!?Entry {
        var k: c.MDB_val = undefined;
        var v: c.MDB_val = undefined;
        const rc = c.mdb_cursor_get(self.cursor, &k, &v, c.MDB_FIRST);
        if (rc == c.MDB_NOTFOUND) return null;
        try checkRc(rc);
        return .{ .key = fromVal(k), .value = fromVal(v) };
    }

    /// Position at the first entry >= `key` (MDB_SET_RANGE).
    pub fn seekRange(self: LmdbCursor, key: []const u8) LmdbError!?Entry {
        var k = toVal(key);
        var v: c.MDB_val = undefined;
        const rc = c.mdb_cursor_get(self.cursor, &k, &v, c.MDB_SET_RANGE);
        if (rc == c.MDB_NOTFOUND) return null;
        try checkRc(rc);
        return .{ .key = fromVal(k), .value = fromVal(v) };
    }

    /// Advance to the next entry (MDB_NEXT).
    pub fn next(self: LmdbCursor) LmdbError!?Entry {
        var k: c.MDB_val = undefined;
        var v: c.MDB_val = undefined;
        const rc = c.mdb_cursor_get(self.cursor, &k, &v, c.MDB_NEXT);
        if (rc == c.MDB_NOTFOUND) return null;
        try checkRc(rc);
        return .{ .key = fromVal(k), .value = fromVal(v) };
    }

    /// Position at the last entry (MDB_LAST). O(1) — LMDB stores keys sorted.
    pub fn last(self: LmdbCursor) LmdbError!?Entry {
        var k: c.MDB_val = undefined;
        var v: c.MDB_val = undefined;
        const rc = c.mdb_cursor_get(self.cursor, &k, &v, c.MDB_LAST);
        if (rc == c.MDB_NOTFOUND) return null;
        try checkRc(rc);
        return .{ .key = fromVal(k), .value = fromVal(v) };
    }

    /// Close the cursor.
    pub fn close(self: LmdbCursor) void {
        c.mdb_cursor_close(self.cursor);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn openTestEnv(opts: struct { max_dbs: u32 = 0 }) !struct { env: LmdbEnv, dir: [:0]u8 } {
    const tmp_dir = testing.tmpDir(.{});
    const path = try tmp_dir.dir.realPathFileAlloc(testing.io, ".", testing.allocator);
    const env = try LmdbEnv.open(path, .{
        .map_size = 1024 * 1024,
        .max_dbs = opts.max_dbs,
    });
    return .{ .env = env, .dir = path };
}

fn cleanupTestEnv(env: LmdbEnv, dir: [:0]u8) void {
    env.close();
    testing.allocator.free(dir);
}

test "LmdbEnv: open and close" {
    const result = try openTestEnv(.{});
    cleanupTestEnv(result.env, result.dir);
}

test "LmdbTxn: put and get with named database" {
    const result = try openTestEnv(.{ .max_dbs = 4 });
    defer cleanupTestEnv(result.env, result.dir);

    // Open named DB and write
    var dbi: Dbi = undefined;
    {
        var txn = try result.env.beginTxn(.{});
        dbi = try txn.openDbi("test_db");
        try txn.putToDbi(dbi, "hello", "world");
        try txn.commit();
    }

    // Read back
    {
        const txn = try result.env.beginTxn(.{ .read_only = true });
        defer txn.abort();
        const value = try txn.getFromDbi(dbi, "hello");
        try testing.expect(value != null);
        try testing.expectEqualStrings("world", value.?);
    }
}

test "LmdbTxn: named databases are isolated" {
    const result = try openTestEnv(.{ .max_dbs = 4 });
    defer cleanupTestEnv(result.env, result.dir);

    var dbi_a: Dbi = undefined;
    var dbi_b: Dbi = undefined;
    {
        var txn = try result.env.beginTxn(.{});
        dbi_a = try txn.openDbi("db_a");
        dbi_b = try txn.openDbi("db_b");
        try txn.putToDbi(dbi_a, "key", "value_a");
        try txn.putToDbi(dbi_b, "key", "value_b");
        try txn.commit();
    }

    {
        const txn = try result.env.beginTxn(.{ .read_only = true });
        defer txn.abort();

        const va = try txn.getFromDbi(dbi_a, "key");
        try testing.expectEqualStrings("value_a", va.?);

        const vb = try txn.getFromDbi(dbi_b, "key");
        try testing.expectEqualStrings("value_b", vb.?);
    }
}

test "LmdbTxn: get nonexistent returns null" {
    const result = try openTestEnv(.{ .max_dbs = 2 });
    defer cleanupTestEnv(result.env, result.dir);

    var dbi: Dbi = undefined;
    {
        var txn = try result.env.beginTxn(.{});
        dbi = try txn.openDbi("test");
        try txn.commit();
    }

    const txn = try result.env.beginTxn(.{ .read_only = true });
    defer txn.abort();
    const value = try txn.getFromDbi(dbi, "nonexistent");
    try testing.expect(value == null);
}

test "LmdbTxn: delete from named database" {
    const result = try openTestEnv(.{ .max_dbs = 2 });
    defer cleanupTestEnv(result.env, result.dir);

    var dbi: Dbi = undefined;
    {
        var txn = try result.env.beginTxn(.{});
        dbi = try txn.openDbi("test");
        try txn.putToDbi(dbi, "key1", "value1");
        try txn.commit();
    }

    {
        var txn = try result.env.beginTxn(.{});
        const deleted = try txn.delFromDbi(dbi, "key1");
        try testing.expect(deleted);
        try txn.commit();
    }

    {
        const txn = try result.env.beginTxn(.{ .read_only = true });
        defer txn.abort();
        try testing.expect(try txn.getFromDbi(dbi, "key1") == null);
    }
}

test "LmdbTxn: abort discards writes" {
    const result = try openTestEnv(.{ .max_dbs = 2 });
    defer cleanupTestEnv(result.env, result.dir);

    var dbi: Dbi = undefined;
    {
        var txn = try result.env.beginTxn(.{});
        dbi = try txn.openDbi("test");
        try txn.commit();
    }

    {
        var txn = try result.env.beginTxn(.{});
        try txn.putToDbi(dbi, "key", "value");
        txn.abort();
    }

    {
        const txn = try result.env.beginTxn(.{ .read_only = true });
        defer txn.abort();
        try testing.expect(try txn.getFromDbi(dbi, "key") == null);
    }
}

test "LmdbCursor: iterate named database" {
    const result = try openTestEnv(.{ .max_dbs = 2 });
    defer cleanupTestEnv(result.env, result.dir);

    var dbi: Dbi = undefined;
    {
        var txn = try result.env.beginTxn(.{});
        dbi = try txn.openDbi("test");
        try txn.putToDbi(dbi, "aaa", "v1");
        try txn.putToDbi(dbi, "bbb", "v2");
        try txn.putToDbi(dbi, "ccc", "v3");
        try txn.commit();
    }

    {
        const txn = try result.env.beginTxn(.{ .read_only = true });
        defer txn.abort();

        const cursor = try txn.openCursorDbi(dbi);
        defer cursor.close();

        var count: usize = 0;
        var entry = try cursor.first();
        while (entry) |_| {
            count += 1;
            entry = try cursor.next();
        }

        try testing.expectEqual(@as(usize, 3), count);
    }
}

test "LmdbEnv: statDbi returns entry count" {
    const result = try openTestEnv(.{ .max_dbs = 2 });
    defer cleanupTestEnv(result.env, result.dir);

    var dbi: Dbi = undefined;
    {
        var txn = try result.env.beginTxn(.{});
        dbi = try txn.openDbi("test");
        try txn.putToDbi(dbi, "a", "1");
        try txn.putToDbi(dbi, "b", "2");
        try txn.putToDbi(dbi, "c", "3");
        try txn.commit();
    }

    const s = try result.env.statDbi(dbi);
    try testing.expectEqual(@as(usize, 3), s.ms_entries);
}
