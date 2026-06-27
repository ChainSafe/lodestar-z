const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

const hex = @import("hex");

const DatastoreKey = @import("key.zig").DatastoreKey;
const DATASTORE_KEY_LEN = @import("key.zig").DATASTORE_KEY_LEN;
const Checkpoint = @import("key.zig").Checkpoint;
const datastoreKey = @import("key.zig").datastoreKey;
const datastoreKeyEpoch = @import("key.zig").datastoreKeyEpoch;

const types = @import("consensus_types");
const Epoch = types.primitive.Epoch.Type;

const state_transition = @import("state_transition");
const computeStartSlotAtEpoch = state_transition.computeStartSlotAtEpoch;
const getStateSlotFromBytes = state_transition.getStateSlotFromBytes;
const getLastProcessedSlotFromStateBytes = state_transition.getLastProcessedSlotFromStateBytes;
const testing = std.testing;

/// On-disk store for serialized checkpoint states. The backend is chosen at construction at RUNTIME
/// — so it is a vtable, not a comptime generic.
pub const CPStateDatastore = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Persist `state_bytes` for `key`, returning its `DatastoreKey`. Writing an existing key is
        /// a no-op (bytes are identical), preserving idempotence.
        write: *const fn (ctx: *anyopaque, io: std.Io, key: Checkpoint, state_bytes: []const u8) anyerror!DatastoreKey,
        /// Delete the state at `key`. Absent keys are ignored.
        remove: *const fn (ctx: *anyopaque, io: std.Io, dk: DatastoreKey) anyerror!void,
        /// Delete the states at `keys`, possibly fanned out concurrently. The first failure surfaces
        /// (after all run); absent keys are ignored.
        removeMany: *const fn (ctx: *anyopaque, io: std.Io, allocator: Allocator, keys: []const DatastoreKey) anyerror!void,
        /// Read the state bytes at `key` (allocated with `allocator`, caller frees), or null if absent.
        read: *const fn (ctx: *anyopaque, io: std.Io, allocator: Allocator, dk: DatastoreKey) anyerror!?[]u8,
        /// All persisted keys. Caller frees the returned slice with `allocator`.
        readKeys: *const fn (ctx: *anyopaque, io: std.Io, allocator: Allocator) anyerror![]DatastoreKey,
        /// Optional one-time backend setup (e.g. ensure the directory exists).
        init: ?*const fn (ctx: *anyopaque, io: std.Io) anyerror!void,
    };

    pub fn write(self: CPStateDatastore, io: std.Io, key: Checkpoint, state_bytes: []const u8) !DatastoreKey {
        return self.vtable.write(self.ptr, io, key, state_bytes);
    }

    pub fn remove(self: CPStateDatastore, io: std.Io, dk: DatastoreKey) !void {
        return self.vtable.remove(self.ptr, io, dk);
    }

    pub fn removeMany(self: CPStateDatastore, io: std.Io, allocator: Allocator, keys: []const DatastoreKey) !void {
        return self.vtable.removeMany(self.ptr, io, allocator, keys);
    }

    pub fn read(self: CPStateDatastore, io: std.Io, allocator: Allocator, dk: DatastoreKey) !?[]u8 {
        return self.vtable.read(self.ptr, io, allocator, dk);
    }

    pub fn readKeys(self: CPStateDatastore, io: std.Io, allocator: Allocator) ![]DatastoreKey {
        return self.vtable.readKeys(self.ptr, io, allocator);
    }

    pub fn initStore(self: CPStateDatastore, io: std.Io) !void {
        if (self.vtable.init) |init_fn| try init_fn(self.ptr, io);
    }

    /// Get the latest safe checkpoint state the node can use to boot from, or null:
    ///   - it should be the checkpoint state that's unique in its epoch,
    ///   - its last processed block slot should be at epoch boundary or last slot of previous epoch,
    ///   - state slot should be at epoch boundary,
    ///   - state slot should be equal to epoch * SLOTS_PER_EPOCH.
    ///
    /// Return the serialized data of Current Root Checkpoint State (CRCS) or Previous Root Checkpoint
    /// State (PRCS). Caller owns the returned bytes.
    pub fn readLatestSafe(self: CPStateDatastore, io: std.Io, allocator: Allocator) !?[]u8 {
        const keys = try self.readKeys(io, allocator);
        defer allocator.free(keys);

        if (keys.len == 0) return null;

        // Epoch-descending, so the first qualifying state encountered is the newest.
        std.mem.sort(DatastoreKey, keys, {}, struct {
            fn desc(_: void, a: DatastoreKey, b: DatastoreKey) bool {
                return datastoreKeyEpoch(a) > datastoreKeyEpoch(b);
            }
        }.desc);

        var i: usize = 0;
        while (i < keys.len) : (i += 1) {
            const epoch = datastoreKeyEpoch(keys[i]);
            // only consider epochs with a single checkpoint to avoid ambiguity from forks; sorted, so
            // an epoch's duplicates are adjacent.
            const prev_dup = i > 0 and datastoreKeyEpoch(keys[i - 1]) == epoch;
            const next_dup = i + 1 < keys.len and datastoreKeyEpoch(keys[i + 1]) == epoch;
            if (prev_dup or next_dup) continue;

            const bytes = (try self.read(io, allocator, keys[i])) orelse continue;
            if (isSafeCheckpointState(bytes, epoch)) return bytes;
            allocator.free(bytes);
        }
        return null;
    }
};

/// Whether `state_bytes` is a safe boot state for `epoch`: at epoch boundary and a CRCS or PRCS.
/// Short or foreign bytes fail the slot reads (treated as unsafe) rather than asserting.
fn isSafeCheckpointState(state_bytes: []const u8, epoch: Epoch) bool {
    const state_slot = getStateSlotFromBytes(state_bytes) catch return false;
    const last_processed = getLastProcessedSlotFromStateBytes(state_bytes) catch return false;
    // not CRCS or PRCS, skip. Guard the subtract so a malformed slot-0 state cannot underflow.
    const is_crcs = last_processed == state_slot;
    const is_prcs = state_slot > 0 and last_processed == state_slot - 1;
    if (!is_crcs and !is_prcs) return false;
    // at epoch boundary (subsumes the slot % SLOTS_PER_EPOCH == 0 check).
    return state_slot == computeStartSlotAtEpoch(epoch);
}

/// In-memory datastore for tests. Backed by an insertion-ordered map so `readKeys` yields a stable
/// order and a write of an existing key is a no-op (no reorder).
pub const InMemoryCPStateDatastore = struct {
    allocator: Allocator,
    states: std.AutoArrayHashMapUnmanaged(DatastoreKey, []u8),

    pub fn init(allocator: Allocator) InMemoryCPStateDatastore {
        return .{ .allocator = allocator, .states = .empty };
    }

    pub fn deinit(self: *InMemoryCPStateDatastore) void {
        for (self.states.values()) |bytes| {
            self.allocator.free(bytes);
        }
        self.states.deinit(self.allocator);
    }

    pub fn datastore(self: *InMemoryCPStateDatastore) CPStateDatastore {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = CPStateDatastore.VTable{
        .write = writeImpl,
        .remove = removeImpl,
        .removeMany = removeManyImpl,
        .read = readImpl,
        .readKeys = readKeysImpl,
        .init = null,
    };

    fn writeImpl(ctx: *anyopaque, io: std.Io, key: Checkpoint, state_bytes: []const u8) anyerror!DatastoreKey {
        _ = io;
        const self: *InMemoryCPStateDatastore = @ptrCast(@alignCast(ctx));
        const dk = datastoreKey(key);
        if (self.states.contains(dk)) return dk;

        const owned = try self.allocator.dupe(u8, state_bytes);
        errdefer self.allocator.free(owned);

        try self.states.put(self.allocator, dk, owned);
        return dk;
    }

    fn removeImpl(ctx: *anyopaque, io: std.Io, dk: DatastoreKey) anyerror!void {
        _ = io;
        const self: *InMemoryCPStateDatastore = @ptrCast(@alignCast(ctx));
        // `orderedRemove` keeps the surviving keys in insertion order.
        if (self.states.fetchOrderedRemove(dk)) |kv| {
            self.allocator.free(kv.value);
        }
    }

    fn removeManyImpl(ctx: *anyopaque, io: std.Io, allocator: Allocator, keys: []const DatastoreKey) anyerror!void {
        _ = io;
        _ = allocator;
        const self: *InMemoryCPStateDatastore = @ptrCast(@alignCast(ctx));
        for (keys) |dk| if (self.states.fetchOrderedRemove(dk)) |kv| self.allocator.free(kv.value);
    }

    fn readImpl(ctx: *anyopaque, io: std.Io, allocator: Allocator, dk: DatastoreKey) anyerror!?[]u8 {
        _ = io;
        const self: *InMemoryCPStateDatastore = @ptrCast(@alignCast(ctx));
        const bytes = self.states.get(dk) orelse return null;
        return try allocator.dupe(u8, bytes);
    }

    fn readKeysImpl(ctx: *anyopaque, io: std.Io, allocator: Allocator) anyerror![]DatastoreKey {
        _ = io;
        const self: *InMemoryCPStateDatastore = @ptrCast(@alignCast(ctx));
        return try allocator.dupe(DatastoreKey, self.states.keys());
    }
};

/// Implementation of CPStateDatastore using file system, this is beneficial for debugging. Each state
/// is one file under `<data_dir>/checkpoint_states/` named `hex(DatastoreKey)` (82 chars: "0x" + 80
/// hex).
pub const FileCPStateDatastore = struct {
    /// "0x" + 2 hex chars per `DatastoreKey` byte (82 for a 40-byte key).
    const FILE_NAME_LEN: usize = 2 + 2 * DATASTORE_KEY_LEN;
    const SUBDIR = "checkpoint_states";

    allocator: Allocator,
    /// `<data_dir>/checkpoint_states` (service deployment: `/beacon/...`, docker: `/data/...`).
    dir_path: []u8,
    /// Open handle to the checkpoint-states directory, created in `initStore`.
    dir: ?std.Io.Dir,

    pub fn init(allocator: Allocator, data_dir: []const u8) !FileCPStateDatastore {
        const dir_path = try std.fs.path.join(allocator, &.{ data_dir, SUBDIR });
        return .{ .allocator = allocator, .dir_path = dir_path, .dir = null };
    }

    pub fn deinit(self: *FileCPStateDatastore, io: std.Io) void {
        if (self.dir) |dir| dir.close(io);
        self.allocator.free(self.dir_path);
    }

    pub fn datastore(self: *FileCPStateDatastore) CPStateDatastore {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = CPStateDatastore.VTable{
        .write = writeImpl,
        .remove = removeImpl,
        .removeMany = removeManyImpl,
        .read = readImpl,
        .readKeys = readKeysImpl,
        .init = initImpl,
    };

    fn fileName(dk: DatastoreKey) [FILE_NAME_LEN]u8 {
        var name: [FILE_NAME_LEN]u8 = undefined;
        // `name` is sized exactly "0x" + 2 hex chars per `dk` byte, so the encode cannot run short.
        _ = hex.bytesToHex(&name, &dk) catch unreachable;
        return name;
    }

    fn initImpl(ctx: *anyopaque, io: std.Io) anyerror!void {
        const self: *FileCPStateDatastore = @ptrCast(@alignCast(ctx));
        self.dir = try std.Io.Dir.cwd().createDirPathOpen(io, self.dir_path, .{ .open_options = .{ .iterate = true } });
    }

    fn writeImpl(ctx: *anyopaque, io: std.Io, key: Checkpoint, state_bytes: []const u8) anyerror!DatastoreKey {
        const self: *FileCPStateDatastore = @ptrCast(@alignCast(ctx));
        const dir = self.dir orelse return error.DatastoreNotInitialized;
        const dk = datastoreKey(key);

        const name = fileName(dk);
        // Create only if absent — re-persisting an existing checkpoint is skipped (same bytes).
        dir.writeFile(io, .{ .sub_path = &name, .data = state_bytes, .flags = .{ .exclusive = true } }) catch |err| switch (err) {
            error.PathAlreadyExists => return dk,
            else => return err,
        };
        return dk;
    }

    /// Delete one state file. Per-key unit shared by `removeImpl` and the `removeMany` fan-out.
    fn removeOne(self: *FileCPStateDatastore, io: std.Io, dk: DatastoreKey) anyerror!void {
        const dir = self.dir orelse return error.DatastoreNotInitialized;

        const name = fileName(dk);
        dir.deleteFile(io, &name) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
    }

    fn removeImpl(ctx: *anyopaque, io: std.Io, dk: DatastoreKey) anyerror!void {
        const self: *FileCPStateDatastore = @ptrCast(@alignCast(ctx));
        return self.removeOne(io, dk);
    }

    fn removeManyImpl(ctx: *anyopaque, io: std.Io, allocator: Allocator, keys: []const DatastoreKey) anyerror!void {
        const self: *FileCPStateDatastore = @ptrCast(@alignCast(ctx));
        if (keys.len == 0) return;
        const futures = try allocator.alloc(std.Io.Future(anyerror!void), keys.len);
        defer allocator.free(futures);

        for (keys, 0..) |dk, i| futures[i] = io.async(removeOne, .{ self, io, dk });

        var first_err: ?anyerror = null;
        for (futures) |*f| f.await(io) catch |err| {
            if (first_err == null) first_err = err;
        };
        if (first_err) |err| return err;
    }

    fn readImpl(ctx: *anyopaque, io: std.Io, allocator: Allocator, dk: DatastoreKey) anyerror!?[]u8 {
        const self: *FileCPStateDatastore = @ptrCast(@alignCast(ctx));
        const dir = self.dir orelse return error.DatastoreNotInitialized;

        const name = fileName(dk);
        return dir.readFileAlloc(io, &name, allocator, .unlimited) catch |err| switch (err) {
            error.FileNotFound => null,
            else => err,
        };
    }

    fn readKeysImpl(ctx: *anyopaque, io: std.Io, allocator: Allocator) anyerror![]DatastoreKey {
        const self: *FileCPStateDatastore = @ptrCast(@alignCast(ctx));
        const dir = self.dir orelse return error.DatastoreNotInitialized;

        var keys: std.ArrayListUnmanaged(DatastoreKey) = .empty;
        errdefer keys.deinit(allocator);

        var it = dir.iterate();
        while (try it.next(io)) |entry| {
            if (entry.kind != .file) continue;
            if (entry.name.len != FILE_NAME_LEN) continue;
            if (!hex.hasOxPrefix(entry.name)) continue;

            var dk: DatastoreKey = undefined;
            // A foreign file matching only the length + "0x" prefix decodes to a non-hex char; skip it.
            // Length/space errors are pre-checked away, so any other error is unexpected and propagates.
            _ = hex.hexToBytes(&dk, entry.name) catch |e| switch (e) {
                error.InvalidCharacter => continue,
                else => return e,
            };
            try keys.append(allocator, dk);
        }

        return keys.toOwnedSlice(allocator);
    }
};

const FileStoreFixture = struct {
    tmp: testing.TmpDir,
    base: []u8,
    store: FileCPStateDatastore,

    fn init(allocator: Allocator) !FileStoreFixture {
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();

        const base = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
        errdefer allocator.free(base);

        const store = try FileCPStateDatastore.init(allocator, base);
        return .{ .tmp = tmp, .base = base, .store = store };
    }

    fn deinit(self: *FileStoreFixture, allocator: Allocator, io: std.Io) void {
        self.store.deinit(io);
        allocator.free(self.base);
        self.tmp.cleanup();
    }

    fn datastore(self: *FileStoreFixture) CPStateDatastore {
        return self.store.datastore();
    }
};

test "InMemoryCPStateDatastore write/read/remove and insertion-ordered keys" {
    const allocator = testing.allocator;
    const io = std.testing.io;
    var store = InMemoryCPStateDatastore.init(allocator);
    defer store.deinit();

    const ds = store.datastore();

    const key_a = Checkpoint{ .root = [_]u8{0xa1} ** 32, .epoch = 5 };
    const key_b = Checkpoint{ .root = [_]u8{0xb2} ** 32, .epoch = 7 };

    const dk_a = try ds.write(io, key_a, "alpha");
    const dk_b = try ds.write(io, key_b, "beta");

    // Re-writing the same key must NOT overwrite or reorder.
    _ = try ds.write(io, key_a, "OVERWRITE-ATTEMPT");

    const read_a = (try ds.read(io, allocator, dk_a)).?;
    defer allocator.free(read_a);

    try testing.expectEqualStrings("alpha", read_a);

    const keys = try ds.readKeys(io, allocator);
    defer allocator.free(keys);

    try testing.expectEqual(@as(usize, 2), keys.len);
    try testing.expectEqualSlices(u8, &dk_a, &keys[0]);
    try testing.expectEqualSlices(u8, &dk_b, &keys[1]);

    try ds.remove(io, dk_a);
    try testing.expect((try ds.read(io, allocator, dk_a)) == null);

    const keys_after = try ds.readKeys(io, allocator);
    defer allocator.free(keys_after);

    try testing.expectEqual(@as(usize, 1), keys_after.len);
    try testing.expectEqualSlices(u8, &dk_b, &keys_after[0]);
}

test "InMemoryCPStateDatastore removeMany removes all keys sequentially and is no-op when absent" {
    const allocator = testing.allocator;
    const io = std.testing.io;
    var store = InMemoryCPStateDatastore.init(allocator);
    defer store.deinit();

    const ds = store.datastore();

    var keys: [8]DatastoreKey = undefined;
    for (0..8) |i| keys[i] = try ds.write(io, .{ .root = [_]u8{@intCast(i + 1)} ** 32, .epoch = @intCast(i) }, "x");
    {
        const before = try ds.readKeys(io, allocator);
        defer allocator.free(before);

        try testing.expectEqual(@as(usize, 8), before.len);
    }

    try ds.removeMany(io, allocator, &keys);
    {
        const after = try ds.readKeys(io, allocator);
        defer allocator.free(after);

        try testing.expectEqual(@as(usize, 0), after.len);
    }

    // Re-removing the now-absent keys must be a clean no-op.
    try ds.removeMany(io, allocator, &keys);
    {
        const after = try ds.readKeys(io, allocator);
        defer allocator.free(after);

        try testing.expectEqual(@as(usize, 0), after.len);
    }
}

test "FileCPStateDatastore write/read/remove/readKeys round-trip" {
    const allocator = testing.allocator;
    const io = std.testing.io;

    var fx = try FileStoreFixture.init(allocator);
    defer fx.deinit(allocator, io);
    const ds = fx.datastore();
    try ds.initStore(io);

    const key_a = Checkpoint{ .root = [_]u8{0xc3} ** 32, .epoch = 9 };
    const dk_a = try ds.write(io, key_a, "gamma-bytes");

    // Create-exclusive: a second write of the same key is a no-op.
    _ = try ds.write(io, key_a, "ignored");

    const read_a = (try ds.read(io, allocator, dk_a)).?;
    defer allocator.free(read_a);
    try testing.expectEqualStrings("gamma-bytes", read_a);

    const keys = try ds.readKeys(io, allocator);
    defer allocator.free(keys);
    try testing.expectEqual(@as(usize, 1), keys.len);
    try testing.expectEqualSlices(u8, &dk_a, &keys[0]);

    try ds.remove(io, dk_a);
    try testing.expect((try ds.read(io, allocator, dk_a)) == null);
    // Removing an absent key is a no-op.
    try ds.remove(io, dk_a);
}

test "FileCPStateDatastore initStore opens an existing dir without clobbering" {
    const allocator = testing.allocator;
    const io = std.testing.io;

    var fx = try FileStoreFixture.init(allocator);
    defer fx.deinit(allocator, io);

    const key = Checkpoint{ .root = [_]u8{0xe5} ** 32, .epoch = 11 };
    var dk: DatastoreKey = undefined;

    // First store persists a state; the fixture's own store owns the dir.
    {
        const ds = fx.datastore();
        try ds.initStore(io);
        dk = try ds.write(io, key, "persisted-bytes");
    }

    // Re-open the SAME dir with a fresh store (the restart case).
    {
        var store = try FileCPStateDatastore.init(allocator, fx.base);
        defer store.deinit(io);
        const ds = store.datastore();
        // Dir already exists from the first store: must succeed, opening it.
        try ds.initStore(io);

        const keys = try ds.readKeys(io, allocator);
        defer allocator.free(keys);

        try testing.expectEqual(@as(usize, 1), keys.len);
        try testing.expectEqualSlices(u8, &dk, &keys[0]);

        const bytes = (try ds.read(io, allocator, dk)).?;
        defer allocator.free(bytes);

        try testing.expectEqualStrings("persisted-bytes", bytes);
    }
}

test "FileCPStateDatastore operations before initStore return DatastoreNotInitialized" {
    const allocator = testing.allocator;
    const io = std.testing.io;

    var fx = try FileStoreFixture.init(allocator);
    defer fx.deinit(allocator, io);

    const ds = fx.datastore();

    const cp = Checkpoint{ .root = [_]u8{0x01} ** 32, .epoch = 1 };
    const dk = datastoreKey(cp);

    try testing.expectError(error.DatastoreNotInitialized, ds.write(io, cp, "x"));
    try testing.expectError(error.DatastoreNotInitialized, ds.read(io, allocator, dk));
    try testing.expectError(error.DatastoreNotInitialized, ds.remove(io, dk));
    try testing.expectError(error.DatastoreNotInitialized, ds.readKeys(io, allocator));
}

test "FileCPStateDatastore removeMany fans out concurrently" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fs.path.join(testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer testing.allocator.free(base);

    // `.limited(4)` forces real concurrency for the fan-out regardless of host core count.
    var threaded: std.Io.Threaded = .init(testing.allocator, .{ .async_limit = .limited(4) });
    defer threaded.deinit();
    const io = threaded.io();

    var store = try FileCPStateDatastore.init(testing.allocator, base);
    defer store.deinit(io);
    const ds = store.datastore();
    try ds.initStore(io);

    var keys: [16]DatastoreKey = undefined;
    for (0..16) |i| keys[i] = try ds.write(io, .{ .root = [_]u8{@intCast(i + 1)} ** 32, .epoch = @intCast(i) }, "x");
    try ds.removeMany(io, testing.allocator, &keys);

    const after = try ds.readKeys(io, testing.allocator);
    defer testing.allocator.free(after);
    try testing.expectEqual(@as(usize, 0), after.len);
}

// Craft a minimal serialized-state buffer with just the two fields `readLatestSafe` reads:
// `state.slot` at offset 40 and `latest_block_header.slot` (last processed slot) at offset 64.
fn makeStateBytes(allocator: Allocator, state_slot: u64, last_processed_slot: u64) ![]u8 {
    const buf = try allocator.alloc(u8, 72);
    @memset(buf, 0);
    std.mem.writeInt(u64, buf[40..][0..8], state_slot, .little);
    std.mem.writeInt(u64, buf[64..][0..8], last_processed_slot, .little);
    return buf;
}

test "readLatestSafe returns null on an empty store" {
    const allocator = testing.allocator;
    const io = std.testing.io;
    var store = InMemoryCPStateDatastore.init(allocator);
    defer store.deinit();
    try testing.expect((try store.datastore().readLatestSafe(io, allocator)) == null);
}

test "readLatestSafe skips a fork epoch (two roots at one epoch is ambiguous)" {
    const allocator = testing.allocator;
    const io = std.testing.io;
    var store = InMemoryCPStateDatastore.init(allocator);
    defer store.deinit();
    const ds = store.datastore();

    // Two checkpoints at epoch 3 → can't tell which is canonical → readLatestSafe skips the epoch.
    const slot3 = computeStartSlotAtEpoch(3);
    for ([_]u8{ 0x31, 0x32 }) |tag| {
        const bytes = try makeStateBytes(allocator, slot3, slot3);
        defer allocator.free(bytes);

        _ = try ds.write(io, .{ .epoch = 3, .root = [_]u8{tag} ** 32 }, bytes);
    }

    try testing.expect((try ds.readLatestSafe(io, allocator)) == null);
}

test "readLatestSafe accepts a PRCS (last processed slot is boundary - 1)" {
    const allocator = testing.allocator;
    const io = std.testing.io;
    var store = InMemoryCPStateDatastore.init(allocator);
    defer store.deinit();
    const ds = store.datastore();

    // PRCS: the state's last-processed slot is one below its epoch boundary.
    const slot4 = computeStartSlotAtEpoch(4);
    const bytes = try makeStateBytes(allocator, slot4, slot4 - 1);
    defer allocator.free(bytes);

    _ = try ds.write(io, .{ .epoch = 4, .root = [_]u8{0x40} ** 32 }, bytes);

    const got = (try ds.readLatestSafe(io, allocator)).?;
    defer allocator.free(got);

    try testing.expectEqual(slot4, try getStateSlotFromBytes(got));
}

test "readLatestSafe returns the highest safe boundary, skipping a fork and an off-boundary state" {
    const allocator = testing.allocator;
    const io = std.testing.io;
    var store = InMemoryCPStateDatastore.init(allocator);
    defer store.deinit();
    const ds = store.datastore();

    const slot7 = computeStartSlotAtEpoch(7);
    const slot6 = computeStartSlotAtEpoch(6);
    const slot5 = computeStartSlotAtEpoch(5);

    // epoch 7: a fork (two roots) → skipped despite being newest.
    for ([_]u8{ 0x71, 0x72 }) |tag| {
        const bytes = try makeStateBytes(allocator, slot7, slot7);
        defer allocator.free(bytes);
        _ = try ds.write(io, .{ .epoch = 7, .root = [_]u8{tag} ** 32 }, bytes);
    }
    // epoch 6: single, but its state slot is 3 past the boundary (off-boundary) → skipped.
    const bytes6 = try makeStateBytes(allocator, slot6 + 3, slot6 + 3);
    defer allocator.free(bytes6);
    _ = try ds.write(io, .{ .epoch = 6, .root = [_]u8{0x60} ** 32 }, bytes6);
    // epoch 5: a clean boundary CRCS → the answer.
    const bytes5 = try makeStateBytes(allocator, slot5, slot5);
    defer allocator.free(bytes5);
    _ = try ds.write(io, .{ .epoch = 5, .root = [_]u8{0x50} ** 32 }, bytes5);

    const got = (try ds.readLatestSafe(io, allocator)).?;
    defer allocator.free(got);
    try testing.expectEqual(slot5, try getStateSlotFromBytes(got));
}
