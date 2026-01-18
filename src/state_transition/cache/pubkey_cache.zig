const std = @import("std");
const Allocator = std.mem.Allocator;
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
    try index_to_pubkey.resize(new_count);
    try pubkey_to_index.ensureTotalCapacity(@intCast(new_count));

    for (old_len..new_count) |i| {
        const pubkey = &validators[i].pubkey;
        pubkey_to_index.putAssumeCapacity(pubkey.*, @intCast(i));
        index_to_pubkey.items[i] = try blst.PublicKey.uncompress(pubkey);
    }
}

// TODO: unit tests
