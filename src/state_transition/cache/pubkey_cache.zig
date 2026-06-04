const std = @import("std");
const bls = @import("bls");
const types = @import("consensus_types");
const Validator = types.phase0.Validator.Type;

/// Map from pubkey to validator index
pub const PubkeyIndexMap = std.AutoHashMap([48]u8, u64);

/// Map from validator index to pubkey
pub const Index2PubkeyCache = std.ArrayList(bls.PublicKey);

/// Populate `pubkey_to_index` and `index_to_pubkey` caches from validators list.
///
/// Runs serially on the current thread. For parallel decompression over a
/// worker pool, see `syncPubkeysParallel`.
pub fn syncPubkeys(
    allocator: std.mem.Allocator,
    validators: []const Validator,
    pubkey_to_index: *PubkeyIndexMap,
    index_to_pubkey: *Index2PubkeyCache,
) !void {
    const old_len = index_to_pubkey.items.len;
    if (pubkey_to_index.count() != old_len) {
        return error.InconsistentCache;
    }

    const new_count = validators.len;
    if (new_count == old_len) {
        return;
    }

    try index_to_pubkey.resize(allocator, new_count);
    try pubkey_to_index.ensureTotalCapacity(@intCast(new_count));

    for (old_len..new_count) |i| {
        const pubkey = &validators[i].pubkey;
        pubkey_to_index.putAssumeCapacity(pubkey.*, @intCast(i));
        index_to_pubkey.items[i] = try bls.PublicKey.uncompress(pubkey);
    }
}

fn uncompressPubkeys(
    start_index: usize,
    end_index_exclusive: usize,
    validators: []const Validator,
    index_to_pubkey: *Index2PubkeyCache,
    uncompress_error: *std.atomic.Value(bool),
) void {
    std.debug.assert(start_index <= end_index_exclusive);
    std.debug.assert(end_index_exclusive <= validators.len);
    std.debug.assert(end_index_exclusive <= index_to_pubkey.items.len);

    for (start_index..end_index_exclusive) |i| {
        if (uncompress_error.load(.monotonic)) return;
        const pubkey = &validators[i].pubkey;
        index_to_pubkey.items[i] = bls.PublicKey.uncompress(pubkey) catch {
            uncompress_error.store(true, .release);
            return;
        };
    }
}

/// Populate `pubkey_to_index` and `index_to_pubkey` caches from validators list,
/// parallelizing BLS pubkey decompression across the `io` executor's worker pool
/// via `std.Io.Group.concurrent`. The `pubkey_to_index` HashMap is updated
/// single-threaded at the end (HashMap is not thread-safe).
pub fn syncPubkeysParallel(
    allocator: std.mem.Allocator,
    io: std.Io,
    validators: []const Validator,
    pubkey_to_index: *PubkeyIndexMap,
    index_to_pubkey: *Index2PubkeyCache,
) !void {
    const old_len = index_to_pubkey.items.len;
    if (pubkey_to_index.count() != old_len) {
        return error.InconsistentCache;
    }

    const new_count = validators.len;
    if (new_count == old_len) {
        return;
    }

    try index_to_pubkey.resize(allocator, new_count);
    errdefer index_to_pubkey.shrinkRetainingCapacity(old_len);

    try pubkey_to_index.ensureTotalCapacity(@intCast(new_count));

    var uncompress_error = std.atomic.Value(bool).init(false);

    var group: std.Io.Group = .init;
    errdefer group.cancel(io);

    const batch_size = 1000;
    var i = old_len;
    while (i < new_count) : (i += batch_size) {
        const end = @min(i + batch_size, new_count);
        try group.concurrent(io, uncompressPubkeys, .{
            i,
            end,
            validators,
            index_to_pubkey,
            &uncompress_error,
        });
    }

    try group.await(io);

    if (uncompress_error.load(.acquire)) {
        return error.InvalidPubkey;
    }

    // HashMap updates must run single-threaded.
    for (old_len..new_count) |j| {
        pubkey_to_index.putAssumeCapacity(validators[j].pubkey, @intCast(j));
    }
}

const testing = std.testing;
const interop = @import("../test_utils/interop_pubkeys.zig");

test "syncPubkeys populates both caches" {
    const allocator = testing.allocator;
    const count = 4;

    var pubkeys: [count]types.primitive.BLSPubkey.Type = undefined;
    try interop.interopPubkeysCached(count, &pubkeys);

    var validators: [count]Validator = undefined;
    for (0..count) |i| {
        validators[i] = std.mem.zeroes(Validator);
        validators[i].pubkey = pubkeys[i];
    }

    var pubkey_to_index = PubkeyIndexMap.init(allocator);
    defer pubkey_to_index.deinit();
    var index_to_pubkey: Index2PubkeyCache = .empty;
    defer index_to_pubkey.deinit(allocator);

    try syncPubkeys(allocator, &validators, &pubkey_to_index, &index_to_pubkey);

    try testing.expectEqual(@as(usize, count), index_to_pubkey.items.len);
    try testing.expectEqual(@as(u32, count), pubkey_to_index.count());

    // Verify each pubkey maps to the correct index
    for (0..count) |i| {
        const idx = pubkey_to_index.get(pubkeys[i]).?;
        try testing.expectEqual(@as(u64, i), idx);
    }
}

test "syncPubkeys incremental sync adds only new validators" {
    const allocator = testing.allocator;
    const initial_count = 2;
    const total_count = 4;

    var pubkeys: [total_count]types.primitive.BLSPubkey.Type = undefined;
    try interop.interopPubkeysCached(total_count, &pubkeys);

    var validators: [total_count]Validator = undefined;
    for (0..total_count) |i| {
        validators[i] = std.mem.zeroes(Validator);
        validators[i].pubkey = pubkeys[i];
    }

    var pubkey_to_index = PubkeyIndexMap.init(allocator);
    defer pubkey_to_index.deinit();
    var index_to_pubkey: Index2PubkeyCache = .empty;
    defer index_to_pubkey.deinit(allocator);

    // Initial sync with first 2 validators
    try syncPubkeys(allocator, validators[0..initial_count], &pubkey_to_index, &index_to_pubkey);
    try testing.expectEqual(@as(usize, initial_count), index_to_pubkey.items.len);

    // Incremental sync with all 4 validators
    try syncPubkeys(allocator, &validators, &pubkey_to_index, &index_to_pubkey);
    try testing.expectEqual(@as(usize, total_count), index_to_pubkey.items.len);
    try testing.expectEqual(@as(u32, total_count), pubkey_to_index.count());

    // Verify all pubkeys are correctly mapped
    for (0..total_count) |i| {
        const idx = pubkey_to_index.get(pubkeys[i]).?;
        try testing.expectEqual(@as(u64, i), idx);
    }
}

test "syncPubkeys no-op when already synced" {
    const allocator = testing.allocator;
    const count = 2;

    var pubkeys: [count]types.primitive.BLSPubkey.Type = undefined;
    try interop.interopPubkeysCached(count, &pubkeys);

    var validators: [count]Validator = undefined;
    for (0..count) |i| {
        validators[i] = std.mem.zeroes(Validator);
        validators[i].pubkey = pubkeys[i];
    }

    var pubkey_to_index = PubkeyIndexMap.init(allocator);
    defer pubkey_to_index.deinit();
    var index_to_pubkey: Index2PubkeyCache = .empty;
    defer index_to_pubkey.deinit(allocator);

    try syncPubkeys(allocator, &validators, &pubkey_to_index, &index_to_pubkey);
    // Second call should be no-op
    try syncPubkeys(allocator, &validators, &pubkey_to_index, &index_to_pubkey);
    try testing.expectEqual(@as(usize, count), index_to_pubkey.items.len);
}

test "syncPubkeys detects inconsistent cache" {
    const allocator = testing.allocator;

    var pubkey_to_index = PubkeyIndexMap.init(allocator);
    defer pubkey_to_index.deinit();
    var index_to_pubkey: Index2PubkeyCache = .empty;
    defer index_to_pubkey.deinit(allocator);

    // Manually desync: add to pubkey_to_index but not index_to_pubkey
    const dummy_key = [_]u8{0} ** 48;
    try pubkey_to_index.put(dummy_key, 0);

    var validators: [1]Validator = undefined;
    validators[0] = std.mem.zeroes(Validator);

    try testing.expectError(error.InconsistentCache, syncPubkeys(allocator, &validators, &pubkey_to_index, &index_to_pubkey));
}
