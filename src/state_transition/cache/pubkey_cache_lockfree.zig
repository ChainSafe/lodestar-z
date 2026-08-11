const std = @import("std");
const bls = @import("bls");
const types = @import("consensus_types");
const Validator = types.phase0.Validator.Type;
const locked = @import("pubkey_cache.zig");
const PubkeyHashContext = locked.PubkeyHashContext;
const uncompress_batch_size = locked.uncompress_batch_size;

const HashKey = [std.hash.SipHash64(1, 3).key_length]u8;

/// First chunk holds 2^12 entries; chunk k holds 2^(12+k). 19 chunks cover max_capacity.
const chunk_base_log2 = 12;
const max_chunks = 19;

/// Bound total entries well below u32 so index+1 slot encoding and 2x table sizing cannot overflow.
pub const max_capacity: u32 = 1 << 30;

const Entry = struct {
    compressed: [48]u8,
    affine: bls.PublicKey,
};

/// Open-addressing pubkey -> index table. Slots hold index+1; 0 is empty. Insert-only:
/// slots are published with release stores and never deleted, so readers probe without
/// a lock. Replaced wholesale (RCU-style pointer swap) when it must grow.
const IndexTable = struct {
    mask: u32,
    slots: []std.atomic.Value(u32),
};

/// Shared read-only sentinel so `table` is never null. Its single slot stays 0 forever:
/// inserts always grow (and swap in a real table) before storing a slot.
var empty_table_slots = [_]std.atomic.Value(u32){std.atomic.Value(u32).init(0)};
var empty_table = IndexTable{ .mask = 0, .slots = &empty_table_slots };

/// Append-only pubkey cache with lock-free reads.
///
/// Dense storage is a segmented array of fixed chunks that never move, so published
/// entries are immutable and stable. A read is: acquire-load `len`, bounds-check,
/// deref. The reverse lookup probes the current IndexTable via an acquire-load of the
/// table pointer. No read path takes a lock.
///
/// Writers (append/syncPubkeys/ensureTotalCapacity, from any thread) serialize on
/// `writer_lock`, which readers never touch. Publication order per entry: write dense
/// entry, release-store `len`, release-store the table slot. Readers that find a slot
/// therefore always see a fully written dense entry.
///
/// Replaced index tables are retired, not freed, until deinit: a reader may still be
/// probing them. Doubling growth bounds retired memory below one current table.
///
/// `clear` and `deinit` require external exclusion of all concurrent users.
pub const LockFreePubkeyCache = struct {
    allocator: std.mem.Allocator,
    hash_key: HashKey,
    /// Serializes writers only. Never taken by readers.
    writer_lock: std.Io.Mutex,
    len: std.atomic.Value(u32),
    chunks: [max_chunks]std.atomic.Value(?[*]Entry),
    table: std.atomic.Value(*IndexTable),
    retired: std.ArrayList(*IndexTable),

    pub fn init(allocator: std.mem.Allocator, io: std.Io) LockFreePubkeyCache {
        var hash_key: HashKey = undefined;
        io.random(&hash_key);
        return .{
            .allocator = allocator,
            .hash_key = hash_key,
            .writer_lock = std.Io.Mutex.init,
            .len = std.atomic.Value(u32).init(0),
            .chunks = @splat(std.atomic.Value(?[*]Entry).init(null)),
            .table = std.atomic.Value(*IndexTable).init(&empty_table),
            .retired = .empty,
        };
    }

    pub fn initCapacity(
        allocator: std.mem.Allocator,
        io: std.Io,
        initial_capacity: usize,
    ) !LockFreePubkeyCache {
        var self = init(allocator, io);
        errdefer self.deinit();
        try self.ensureTotalCapacity(io, initial_capacity);
        return self;
    }

    /// The owner must exclude concurrent users before destroying the cache.
    pub fn deinit(self: *LockFreePubkeyCache) void {
        for (&self.chunks, 0..) |*chunk, k| {
            if (chunk.load(.monotonic)) |ptr| {
                self.allocator.free(ptr[0..chunkSize(@intCast(k))]);
            }
        }
        self.destroyTableIfOwned(self.table.load(.monotonic));
        for (self.retired.items) |table| self.destroyTableIfOwned(table);
        self.retired.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn hashContext(self: *const LockFreePubkeyCache) PubkeyHashContext {
        return .{ .hash_key = self.hash_key };
    }

    pub fn count(self: *const LockFreePubkeyCache, io: std.Io) u32 {
        _ = io;
        return self.len.load(.acquire);
    }

    /// Dense capacity currently backed by allocated chunks.
    pub fn capacity(self: *const LockFreePubkeyCache, io: std.Io) usize {
        _ = io;
        var chunk_count: u5 = 0;
        for (&self.chunks) |*chunk| {
            if (chunk.load(.acquire) == null) break;
            chunk_count += 1;
        }
        return coveredCapacity(chunk_count);
    }

    /// Get the validator index for a compressed pubkey, if cached. Lock-free.
    pub fn get(self: *const LockFreePubkeyCache, io: std.Io, pubkey: [48]u8) ?u64 {
        _ = io;
        const table = self.table.load(.acquire);
        return self.tableLookup(table, pubkey);
    }

    /// Get the affine pubkey for a validator index. Lock-free. A value is returned
    /// for API parity with PubkeyCache; entries are immutable so a pointer would be
    /// equally safe.
    pub fn getPubkey(
        self: *const LockFreePubkeyCache,
        io: std.Io,
        index: u64,
    ) ?bls.PublicKey {
        _ = io;
        if (index >= self.len.load(.acquire)) return null;
        return self.entryAt(@intCast(index)).affine;
    }

    /// Copy affine pubkeys for a batch of validator indices. Lock-free.
    pub fn getPubkeys(
        self: *const LockFreePubkeyCache,
        io: std.Io,
        indices: []const u64,
        out: []bls.PublicKey,
    ) !void {
        _ = io;
        if (indices.len != out.len) return error.InvalidLength;
        const len = self.len.load(.acquire);
        for (indices) |index| {
            if (index >= len) return error.InvalidIndex;
        }
        for (indices, out) |index, *pubkey| {
            pubkey.* = self.entryAt(@intCast(index)).affine;
        }
    }

    /// Resolve a batch of compressed pubkeys to validator indices. Lock-free.
    pub fn getValidatorIndices(
        self: *const LockFreePubkeyCache,
        io: std.Io,
        pubkeys: []const [48]u8,
        out: []u64,
    ) !void {
        _ = io;
        if (pubkeys.len != out.len) return error.InvalidLength;
        const table = self.table.load(.acquire);
        for (pubkeys, out) |pubkey, *index| {
            index.* = self.tableLookup(table, pubkey) orelse return error.PubkeyNotFound;
        }
    }

    /// Aggregate the pubkeys at the requested validator indices. Lock-free.
    pub fn aggregate(
        self: *const LockFreePubkeyCache,
        io: std.Io,
        indices: []const u64,
    ) !bls.PublicKey {
        _ = io;
        if (indices.len == 0) return error.InvalidLength;
        const len = self.len.load(.acquire);
        for (indices) |index| {
            if (index >= len) return error.InvalidIndex;
        }
        var aggregate_pubkey = self.entryAt(@intCast(indices[0])).affine.toAggregate();
        for (indices[1..]) |index| {
            aggregate_pubkey.add(&self.entryAt(@intCast(index)).affine);
        }
        return aggregate_pubkey.toPublicKey();
    }

    /// Reserve dense chunks and index-table capacity for `new_capacity` entries so
    /// appends up to that count never allocate or swap tables.
    pub fn ensureTotalCapacity(
        self: *LockFreePubkeyCache,
        io: std.Io,
        new_capacity: usize,
    ) !void {
        try validateCapacity(new_capacity);
        try self.writer_lock.lock(io);
        defer self.writer_lock.unlock(io);

        try self.ensureChunkCapacityLocked(@intCast(new_capacity));
        const table = self.table.load(.acquire);
        const wanted = tableCapacityFor(@intCast(new_capacity));
        if (tableCap(table) < wanted) {
            try self.growTableLocked(wanted);
        }
    }

    /// Test/reset API. Requires external exclusion of all concurrent users: readers
    /// probing the old table during a clear may observe stale mappings.
    pub fn clear(self: *LockFreePubkeyCache, io: std.Io) !void {
        try self.writer_lock.lock(io);
        defer self.writer_lock.unlock(io);
        self.len.store(0, .release);
        const old = self.table.swap(&empty_table, .acq_rel);
        try self.retire(old);
    }

    /// Append a compressed pubkey at the next validator index. Supplying an
    /// already-cached index is an idempotent consistency check (a lock-free read).
    pub fn append(
        self: *LockFreePubkeyCache,
        io: std.Io,
        pubkey: [48]u8,
        index: u64,
    ) !void {
        // Fast path: replaying history (e.g. historical state regen) never blocks
        // and never touches the writer lock.
        if (try self.checkExisting(pubkey, index)) return;

        const affine = try bls.PublicKey.uncompress(&pubkey);

        try self.writer_lock.lock(io);
        defer self.writer_lock.unlock(io);

        // Another writer may have won the race for this index.
        if (try self.checkExisting(pubkey, index)) return;

        const current_len = self.len.load(.acquire);
        if (index > current_len) return error.InvalidIndexToAppend;
        try validateCapacity(current_len + 1);

        var table = self.table.load(.acquire);
        if (self.tableLookup(table, pubkey) != null) return error.DuplicatePubkey;

        try self.ensureChunkCapacityLocked(current_len + 1);
        if ((current_len + 1) * 2 > tableCap(table)) {
            try self.growTableLocked(tableCapacityFor(current_len + 1));
            table = self.table.load(.acquire);
        }

        const entry = self.entryAt(current_len);
        entry.compressed = pubkey;
        entry.affine = affine;
        self.len.store(current_len + 1, .release);
        self.tableInsert(table, pubkey, current_len);
    }

    /// Populate the cache from the missing suffix of a validator list. Existing
    /// entries are trusted as the application's unforkable singleton history.
    /// When behind, this is a single atomic load.
    pub fn syncPubkeys(
        self: *LockFreePubkeyCache,
        io: std.Io,
        validators: []const *const Validator,
    ) !void {
        try validateCapacity(validators.len);
        if (validators.len <= self.len.load(.acquire)) return;

        try self.writer_lock.lock(io);
        defer self.writer_lock.unlock(io);

        const old_len = self.len.load(.acquire);
        if (validators.len <= old_len) return;
        const total: u32 = @intCast(validators.len);

        const suffix = validators[old_len..];
        const prepared = try self.allocator.alloc(bls.PublicKey, suffix.len);
        defer self.allocator.free(prepared);

        const batch_count = (suffix.len - 1) / uncompress_batch_size + 1;
        const batch_errors = try self.allocator.alloc(?bls.BlstError, batch_count);
        defer self.allocator.free(batch_errors);
        @memset(batch_errors, null);

        var group: std.Io.Group = .init;
        errdefer group.cancel(io);
        // `async` bounds worker growth and runs excess batches on the caller.
        for (batch_errors, 0..) |*batch_error, batch_index| {
            const batch_start = batch_index * uncompress_batch_size;
            const batch_end = @min(batch_start + uncompress_batch_size, suffix.len);
            group.async(io, uncompressBatch, .{
                suffix[batch_start..batch_end],
                prepared[batch_start..batch_end],
                batch_error,
            });
        }
        try group.await(io);

        for (batch_errors) |batch_error| {
            if (batch_error) |err| return err;
        }

        // Write dense entries first. They stay invisible (len is not bumped), which
        // lets duplicate detection below read every key from one place.
        try self.ensureChunkCapacityLocked(total);
        for (suffix, prepared, 0..) |validator, affine, i| {
            const entry = self.entryAt(old_len + @as(u32, @intCast(i)));
            entry.compressed = validator.pubkey;
            entry.affine = affine;
        }

        // Build the replacement table off to the side, catching duplicates (against
        // old entries and within the batch) before anything is published.
        const new_table = try self.allocTable(tableCapacityFor(total));
        for (0..total) |i| {
            const index: u32 = @intCast(i);
            if (self.tableInsertCheck(new_table, self.entryAt(index).compressed, index)) |_| {
                self.destroyTableIfOwned(new_table);
                return error.DuplicatePubkey;
            }
        }

        // Publish: entries, then the table that references them.
        self.len.store(total, .release);
        const old_table = self.table.swap(new_table, .acq_rel);
        try self.retire(old_table);
    }

    // -- internals --

    /// Idempotent-append fast path: true if `index` already holds `pubkey`.
    fn checkExisting(self: *const LockFreePubkeyCache, pubkey: [48]u8, index: u64) !bool {
        if (index >= self.len.load(.acquire)) return false;
        if (!std.mem.eql(u8, &self.entryAt(@intCast(index)).compressed, &pubkey)) {
            return error.ConflictingPubkey;
        }
        return true;
    }

    fn entryAt(self: *const LockFreePubkeyCache, index: u32) *Entry {
        const pos = chunkPosition(index);
        const chunk = self.chunks[pos.chunk].load(.acquire) orelse unreachable;
        return &chunk[pos.offset];
    }

    fn tableLookup(
        self: *const LockFreePubkeyCache,
        table: *const IndexTable,
        pubkey: [48]u8,
    ) ?u64 {
        var slot = self.hashContext().hash(pubkey) & table.mask;
        var probes: usize = 0;
        while (probes <= table.mask) : (probes += 1) {
            const value = table.slots[slot].load(.acquire);
            if (value == 0) return null;
            const index = value - 1;
            if (std.mem.eql(u8, &self.entryAt(index).compressed, &pubkey)) return index;
            slot = (slot + 1) & table.mask;
        }
        return null;
    }

    /// Writer-only. Probes for `pubkey`; returns the existing index if present,
    /// otherwise claims an empty slot for `index` and returns null.
    fn tableInsertCheck(
        self: *const LockFreePubkeyCache,
        table: *IndexTable,
        pubkey: [48]u8,
        index: u32,
    ) ?u32 {
        std.debug.assert(table != &empty_table);
        var slot = self.hashContext().hash(pubkey) & table.mask;
        while (true) {
            const value = table.slots[slot].load(.acquire);
            if (value == 0) {
                table.slots[slot].store(index + 1, .release);
                return null;
            }
            const existing = value - 1;
            if (std.mem.eql(u8, &self.entryAt(existing).compressed, &pubkey)) return existing;
            slot = (slot + 1) & table.mask;
        }
    }

    fn tableInsert(
        self: *const LockFreePubkeyCache,
        table: *IndexTable,
        pubkey: [48]u8,
        index: u32,
    ) void {
        const existing = self.tableInsertCheck(table, pubkey, index);
        std.debug.assert(existing == null);
    }

    fn allocTable(self: *LockFreePubkeyCache, cap: u32) !*IndexTable {
        std.debug.assert(std.math.isPowerOfTwo(cap));
        const table = try self.allocator.create(IndexTable);
        errdefer self.allocator.destroy(table);
        const slots = try self.allocator.alloc(std.atomic.Value(u32), cap);
        @memset(slots, std.atomic.Value(u32).init(0));
        table.* = .{ .mask = cap - 1, .slots = slots };
        return table;
    }

    fn destroyTableIfOwned(self: *LockFreePubkeyCache, table: *IndexTable) void {
        if (table == &empty_table) return;
        self.allocator.free(table.slots);
        self.allocator.destroy(table);
    }

    fn retire(self: *LockFreePubkeyCache, table: *IndexTable) !void {
        if (table == &empty_table) return;
        try self.retired.append(self.allocator, table);
    }

    /// Writer-only. Builds a bigger table containing all published entries and swaps
    /// it in; readers keep probing the old table until they reload the pointer.
    fn growTableLocked(self: *LockFreePubkeyCache, cap: u32) !void {
        const new_table = try self.allocTable(cap);
        const len = self.len.load(.acquire);
        for (0..len) |i| {
            const index: u32 = @intCast(i);
            self.tableInsert(new_table, self.entryAt(index).compressed, index);
        }
        const old_table = self.table.swap(new_table, .acq_rel);
        try self.retire(old_table);
    }

    fn ensureChunkCapacityLocked(self: *LockFreePubkeyCache, new_capacity: u32) !void {
        var chunk_count: u5 = 0;
        for (&self.chunks) |*chunk| {
            if (chunk.load(.acquire) == null) break;
            chunk_count += 1;
        }
        while (coveredCapacity(chunk_count) < new_capacity) : (chunk_count += 1) {
            const entries = try self.allocator.alloc(Entry, chunkSize(chunk_count));
            self.chunks[chunk_count].store(entries.ptr, .release);
        }
    }
};

fn uncompressBatch(
    validators: []const *const Validator,
    prepared: []bls.PublicKey,
    batch_error: *?bls.BlstError,
) void {
    std.debug.assert(validators.len == prepared.len);
    std.debug.assert(validators.len <= uncompress_batch_size);

    for (validators, prepared) |validator, *affine| {
        affine.* = bls.PublicKey.uncompress(&validator.pubkey) catch |err| {
            batch_error.* = err;
            return;
        };
    }
}

const ChunkPosition = struct { chunk: u5, offset: u32 };

/// Chunk k spans [base*(2^k - 1), base*(2^(k+1) - 1)) with base = 2^chunk_base_log2.
fn chunkPosition(index: u32) ChunkPosition {
    const m = (index >> chunk_base_log2) + 1;
    const k: u5 = @intCast(31 - @clz(m));
    const chunk_start = ((@as(u32, 1) << k) - 1) << chunk_base_log2;
    return .{ .chunk = k, .offset = index - chunk_start };
}

fn chunkSize(k: u5) u32 {
    return @as(u32, 1) << (chunk_base_log2 + @as(u5, @intCast(k)));
}

fn coveredCapacity(chunk_count: u5) u32 {
    return ((@as(u32, 1) << chunk_count) - 1) << chunk_base_log2;
}

/// Smallest power of two giving load factor <= 0.5 for `count` entries.
fn tableCapacityFor(count: u32) u32 {
    const wanted = @max(4, @as(u64, count) * 2);
    return @intCast(std.math.ceilPowerOfTwoAssert(u64, wanted));
}

fn tableCap(table: *const IndexTable) u32 {
    if (table == &empty_table) return 0;
    return table.mask + 1;
}

fn validateCapacity(requested_capacity: usize) !void {
    if (requested_capacity > max_capacity) return error.CapacityOverflow;
}
