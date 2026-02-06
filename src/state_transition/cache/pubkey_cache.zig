const std = @import("std");
const blst = @import("blst");
const types = @import("consensus_types");
const Validator = types.phase0.Validator.Type;

/// Map from pubkey to validator index
pub const PubkeyIndexMap = std.AutoHashMap([48]u8, u64);

/// Map from validator index to pubkey
pub const Index2PubkeyCache = std.ArrayList(blst.PublicKey);

/// Populate `pubkey_to_index` and `index_to_pubkey` caches from validators list.
pub fn syncPubkeys(
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

    try index_to_pubkey.resize(new_count);
    try pubkey_to_index.ensureTotalCapacity(@intCast(new_count));

    for (old_len..new_count) |i| {
        const pubkey = &validators[i].pubkey;
        pubkey_to_index.putAssumeCapacity(pubkey.*, @intCast(i));
        index_to_pubkey.items[i] = try blst.PublicKey.uncompress(pubkey);
    }
}

fn putPubkeysAtIndices(start_index: usize, end_index_exclusive: usize, validators: []const Validator, pubkey_to_index: *PubkeyIndexMap, index_to_pubkey: *Index2PubkeyCache) void {
    for (start_index..end_index_exclusive) |i| {
        const pubkey = &validators[i].pubkey;
        pubkey_to_index.putAssumeCapacity(pubkey.*, @intCast(i));
        index_to_pubkey.items[i] = blst.PublicKey.uncompress(pubkey) catch unreachable;
    }
}

/// Populate `pubkey_to_index` and `index_to_pubkey` caches from validators list.
/// Spawns a temporary thread pool to parallelize the work.
pub fn syncPubkeysParallel(
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

    try index_to_pubkey.resize(new_count);
    try pubkey_to_index.ensureTotalCapacity(@intCast(new_count));

    var thread_pool: std.Thread.Pool = undefined;
    try thread_pool.init(.{ .allocator = allocator });
    defer thread_pool.deinit();

    var wg = std.Thread.WaitGroup{};

    var i = old_len;
    const batch_size = 1000;

    while (i < new_count) : (i += batch_size) {
        thread_pool.spawnWg(
            &wg,
            putPubkeysAtIndices,
            .{
                i,
                @min(i + batch_size, new_count),
                validators,
                pubkey_to_index,
                index_to_pubkey,
            },
        );
    }

    wg.wait();
}

// TODO: unit tests
