//! LMDB: Zig wrapper over the Lightning Memory-Mapped Database C API.
//!
//! Provides a safe, idiomatic Zig interface to LMDB's core operations:
//! environment management, transactions, and cursor-based iteration.
//!
//! LMDB characteristics:
//! - Memory-mapped reads (zero-copy from mmap, no allocator needed)
//! - Single-writer / multi-reader (MVCC)
//! - Crash-safe (copy-on-write B+tree)
//! - Tiny footprint (~10K lines C)
//!
//! All data pointers returned from read transactions point directly into
//! the memory map and are valid only for the lifetime of the transaction.

const std = @import("std");

pub const c = @cImport({
    @cInclude("lmdb.h");
});

/// LMDB-specific errors mapped from MDB return codes.
pub const LmdbError = error{
    /// Key/data pair already exists (MDB_KEYEXIST).
    KeyExists,
    /// Key/data pair not found (MDB_NOTFOUND).
    NotFound,
    /// Requested page not found — usually database corruption (MDB_PAGE_NOTFOUND).
    PageNotFound,
    /// Located page was wrong type (MDB_CORRUPTED).
    Corrupted,
    /// Update of meta page failed or environment had fatal error (MDB_PANIC).
    Panic,
    /// Environment version mismatch (MDB_VERSION_MISMATCH).
    VersionMismatch,
    /// File is not a valid LMDB file (MDB_INVALID).
    Invalid,
    /// Environment mapsize reached (MDB_MAP_FULL).
    MapFull,
    /// Environment maxdbs reached (MDB_DBS_FULL).
    DbsFull,
    /// Environment maxreaders reached (MDB_READERS_FULL).
    ReadersFull,
    /// Too many TLS keys in use — Windows only (MDB_TLS_FULL).
    TlsFull,
    /// Txn has too many dirty pages (MDB_TXN_FULL).
    TxnFull,
    /// Cursor stack too deep — internal error (MDB_CURSOR_FULL).
    CursorFull,
    /// Page has not enough space — internal error (MDB_PAGE_FULL).
    PageFull,
    /// Database contents grew beyond environment mapsize (MDB_MAP_RESIZED).
    MapResized,
    /// Operation and target DB incompatible or DB doesn't exist (MDB_INCOMPATIBLE).
    Incompatible,
    /// Invalid reuse of reader locktable slot (MDB_BAD_RSLOT).
    BadReaderSlot,
    /// Transaction must abort, has a child, or is invalid (MDB_BAD_TXN).
    BadTxn,
    /// Unsupported size of key/DB name/data or wrong DUPFIXED size (MDB_BAD_VALSIZE).
    BadValSize,
    /// The specified DBI was changed unexpectedly (MDB_BAD_DBI).
    BadDbi,
    /// Unexpected LMDB error code.
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
        .mv_data = @constCast(@ptrCast(data.ptr)),
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
/// An environment may contain multiple named databases (sub-DBs), but for
/// beacon chain use we default to a single unnamed DB (maxdbs = 0).
pub const LmdbEnv = struct {
    env: *c.MDB_env,

    pub const OpenOptions = struct {
        /// Maximum database size. LMDB uses a sparse file so this costs nothing
        /// until actually written. 256 GB is reasonable for beacon chain.
        map_size: usize = 256 * 1024 * 1024 * 1024, // 256 GB
        /// Use MDB_NOSUBDIR — path is a filename, not a directory.
        no_subdir: bool = false,
        /// Open in read-only mode (MDB_RDONLY).
        read_only: bool = false,
        /// Maximum number of named databases. 0 = single unnamed DB.
        max_dbs: u32 = 0,
        /// Maximum concurrent reader slots.
        max_readers: u32 = 126,
        /// File permissions for the database (Unix mode).
        mode: c_uint = 0o664,
    };

    /// Create and open an LMDB environment.
    ///
    /// `path` must be a null-terminated directory path. When `no_subdir` is set,
    /// `path` is treated as a filename.
    pub fn open(path: [*:0]const u8, opts: OpenOptions) LmdbError!LmdbEnv {
        var env: ?*c.MDB_env = null;
        try checkRc(c.mdb_env_create(&env));
        errdefer c.mdb_env_close(env.?);

        try checkRc(c.mdb_env_set_mapsize(env.?, opts.map_size));
        if (opts.max_dbs > 0) {
            try checkRc(c.mdb_env_set_maxdbs(env.?, opts.max_dbs));
        }
        try checkRc(c.mdb_env_set_maxreaders(env.?, opts.max_readers));

        var flags: c_uint = c.MDB_NOTLS; // Avoid TLS issues with Zig's thread pool
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
        errdefer c.mdb_txn_abort(txn.?);

        // Open the unnamed (default) database
        var dbi: c.MDB_dbi = undefined;
        try checkRc(c.mdb_dbi_open(txn.?, null, 0, &dbi));

        return .{
            .txn = txn.?,
            .dbi = dbi,
        };
    }

    /// Force a sync of the memory map to disk.
    pub fn sync(self: LmdbEnv, force: bool) LmdbError!void {
        try checkRc(c.mdb_env_sync(self.env, @intFromBool(force)));
    }

    /// Get environment statistics.
    pub fn stat(self: LmdbEnv) LmdbError!c.MDB_stat {
        var txn: ?*c.MDB_txn = null;
        try checkRc(c.mdb_txn_begin(self.env, null, c.MDB_RDONLY, &txn));
        defer c.mdb_txn_abort(txn.?);
        var dbi: c.MDB_dbi = undefined;
        try checkRc(c.mdb_dbi_open(txn.?, null, 0, &dbi));
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

/// LMDB transaction — provides get/put/del/cursor operations.
///
/// Read transactions may be used concurrently. Write transactions are
/// serialized by LMDB (single writer lock).
///
/// Data returned by `get` points into the memory map and is valid only
/// while this transaction is alive.
pub const LmdbTxn = struct {
    txn: *c.MDB_txn,
    dbi: c.MDB_dbi,

    /// Get the value for a key. Returns null if not found.
    ///
    /// The returned slice points into LMDB's memory map — zero copy.
    /// It is valid only for the lifetime of this transaction.
    pub fn get(self: LmdbTxn, key: []const u8) LmdbError!?[]const u8 {
        var k = toVal(key);
        var v: c.MDB_val = undefined;
        const rc = c.mdb_get(self.txn, self.dbi, &k, &v);
        if (rc == c.MDB_NOTFOUND) return null;
        try checkRc(rc);
        return fromVal(v);
    }

    /// Store a key-value pair. Overwrites existing values.
    pub fn put(self: LmdbTxn, key: []const u8, value: []const u8) LmdbError!void {
        var k = toVal(key);
        var v = toVal(value);
        try checkRc(c.mdb_put(self.txn, self.dbi, &k, &v, 0));
    }

    /// Delete a key. Returns false if the key was not found.
    pub fn del(self: LmdbTxn, key: []const u8) LmdbError!bool {
        var k = toVal(key);
        const rc = c.mdb_del(self.txn, self.dbi, &k, null);
        if (rc == c.MDB_NOTFOUND) return false;
        try checkRc(rc);
        return true;
    }

    /// Commit the transaction, making all writes durable.
    pub fn commit(self: LmdbTxn) LmdbError!void {
        try checkRc(c.mdb_txn_commit(self.txn));
    }

    /// Abort the transaction, discarding all writes.
    pub fn abort(self: LmdbTxn) void {
        c.mdb_txn_abort(self.txn);
    }

    /// Open a cursor for iteration.
    pub fn openCursor(self: LmdbTxn) LmdbError!LmdbCursor {
        var cursor: ?*c.MDB_cursor = null;
        try checkRc(c.mdb_cursor_open(self.txn, self.dbi, &cursor));
        return .{ .cursor = cursor.? };
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

    /// Close the cursor.
    pub fn close(self: LmdbCursor) void {
        c.mdb_cursor_close(self.cursor);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn openTestEnv() !struct { env: LmdbEnv, dir: [:0]u8 } {
    const tmp_dir = testing.tmpDir(.{});
    const path = try tmp_dir.dir.realPathFileAlloc(testing.io, ".", testing.allocator);
    const env = try LmdbEnv.open(path, .{ .map_size = 1024 * 1024 }); // 1 MB
    return .{ .env = env, .dir = path };
}

fn cleanupTestEnv(env: LmdbEnv, dir: [:0]u8) void {
    env.close();
    testing.allocator.free(dir);
}

test "LmdbEnv: open and close" {
    const result = try openTestEnv();
    cleanupTestEnv(result.env, result.dir);
}

test "LmdbTxn: put and get" {
    const result = try openTestEnv();
    defer cleanupTestEnv(result.env, result.dir);

    // Write
    {
        var txn = try result.env.beginTxn(.{});
        try txn.put("hello", "world");
        try txn.commit();
    }

    // Read
    {
        const txn = try result.env.beginTxn(.{ .read_only = true });
        defer txn.abort();
        const value = try txn.get("hello");
        try testing.expect(value != null);
        try testing.expectEqualStrings("world", value.?);
    }
}

test "LmdbTxn: get nonexistent returns null" {
    const result = try openTestEnv();
    defer cleanupTestEnv(result.env, result.dir);

    const txn = try result.env.beginTxn(.{ .read_only = true });
    defer txn.abort();
    const value = try txn.get("nonexistent");
    try testing.expect(value == null);
}

test "LmdbTxn: delete" {
    const result = try openTestEnv();
    defer cleanupTestEnv(result.env, result.dir);

    // Write
    {
        var txn = try result.env.beginTxn(.{});
        try txn.put("key1", "value1");
        try txn.commit();
    }

    // Delete
    {
        var txn = try result.env.beginTxn(.{});
        const deleted = try txn.del("key1");
        try testing.expect(deleted);
        try txn.commit();
    }

    // Verify deleted
    {
        const txn = try result.env.beginTxn(.{ .read_only = true });
        defer txn.abort();
        try testing.expect(try txn.get("key1") == null);
    }
}

test "LmdbTxn: delete nonexistent returns false" {
    const result = try openTestEnv();
    defer cleanupTestEnv(result.env, result.dir);

    var txn = try result.env.beginTxn(.{});
    const deleted = try txn.del("nonexistent");
    try testing.expect(!deleted);
    txn.abort();
}

test "LmdbTxn: overwrite value" {
    const result = try openTestEnv();
    defer cleanupTestEnv(result.env, result.dir);

    {
        var txn = try result.env.beginTxn(.{});
        try txn.put("key", "value1");
        try txn.commit();
    }
    {
        var txn = try result.env.beginTxn(.{});
        try txn.put("key", "value2");
        try txn.commit();
    }
    {
        const txn = try result.env.beginTxn(.{ .read_only = true });
        defer txn.abort();
        const v = try txn.get("key");
        try testing.expectEqualStrings("value2", v.?);
    }
}

test "LmdbTxn: abort discards writes" {
    const result = try openTestEnv();
    defer cleanupTestEnv(result.env, result.dir);

    {
        var txn = try result.env.beginTxn(.{});
        try txn.put("key", "value");
        txn.abort(); // discard
    }
    {
        const txn = try result.env.beginTxn(.{ .read_only = true });
        defer txn.abort();
        try testing.expect(try txn.get("key") == null);
    }
}

test "LmdbCursor: prefix scan" {
    const result = try openTestEnv();
    defer cleanupTestEnv(result.env, result.dir);

    // Insert prefixed keys
    {
        var txn = try result.env.beginTxn(.{});
        try txn.put("pfx:aaa", "v1");
        try txn.put("pfx:bbb", "v2");
        try txn.put("pfx:ccc", "v3");
        try txn.put("other:zzz", "v4");
        try txn.commit();
    }

    // Scan with prefix "pfx:"
    {
        const txn = try result.env.beginTxn(.{ .read_only = true });
        defer txn.abort();

        const cursor = try txn.openCursor();
        defer cursor.close();

        const prefix = "pfx:";
        var count: usize = 0;

        var entry = try cursor.seekRange(prefix);
        while (entry) |e| {
            if (e.key.len < prefix.len or
                !std.mem.eql(u8, e.key[0..prefix.len], prefix)) break;
            count += 1;
            entry = try cursor.next();
        }

        try testing.expectEqual(@as(usize, 3), count);
    }
}

test "LmdbEnv: stat returns entry count" {
    const result = try openTestEnv();
    defer cleanupTestEnv(result.env, result.dir);

    {
        var txn = try result.env.beginTxn(.{});
        try txn.put("a", "1");
        try txn.put("b", "2");
        try txn.put("c", "3");
        try txn.commit();
    }

    const s = try result.env.stat();
    try testing.expectEqual(@as(usize, 3), s.ms_entries);
}
