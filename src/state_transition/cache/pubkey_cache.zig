const std = @import("std");
const bls = @import("bls");
const types = @import("consensus_types");
const Validator = types.phase0.Validator.Type;

/// Map from pubkey to validator index
pub const PubkeyIndexMap = std.AutoHashMap([48]u8, u64);

/// Map from validator index to pubkey
pub const Index2PubkeyCache = std.array_list.AlignedManaged(bls.PublicKey, null);

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

/// Populate `pubkey_to_index` and `index_to_pubkey` caches from validators list.
/// Spawns a temporary thread pool to parallelize the work.
pub fn syncPubkeysParallel(
    allocator: std.mem.Allocator,
    validators: []const Validator,
    pubkey_to_index: *PubkeyIndexMap,
    index_to_pubkey: *Index2PubkeyCache,
) !void {
    _ = allocator; // TODO: re-use with parallel implementation
    const old_len = index_to_pubkey.items.len;
    if (pubkey_to_index.count() != old_len) {
        return error.InconsistentCache;
    }

    const new_count = validators.len;
    if (new_count == old_len) {
        return;
    }

    try index_to_pubkey.resize(new_count);
    errdefer index_to_pubkey.shrinkRetainingCapacity(old_len);

    try pubkey_to_index.ensureTotalCapacity(@intCast(new_count));

    // TODO: Re-parallelize with std.Io batch API when 0.16 patterns are settled.
    // For now, run serially.
    var uncompress_error = std.atomic.Value(bool).init(false);

    var i = old_len;
    const batch_size = 1000;

    while (i < new_count) : (i += batch_size) {
        uncompressPubkeys(
            i,
            @min(i + batch_size, new_count),
            validators,
            index_to_pubkey,
            &uncompress_error,
        );
    }

    if (uncompress_error.load(.acquire)) {
        return error.InvalidPubkey;
    }

    // Update the shared map in single thread
    for (old_len..new_count) |j| {
        pubkey_to_index.putAssumeCapacity(validators[j].pubkey, @intCast(j));
    }
}

// TODO: unit tests
