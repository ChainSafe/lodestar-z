//! A digest of everything a store holds, so two runs can be compared tick
//! by tick.

const std = @import("std");
const assert = std.debug.assert;
const limits = @import("../limits.zig");
const types = @import("../types.zig");
const Store = @import("../store.zig").Store;

const Sha256 = std.crypto.hash.sha2.Sha256;

fn feed(hasher: *Sha256, value: u32) void {
    var word: [4]u8 = undefined;
    std.mem.writeInt(u32, &word, value, .little);
    hasher.update(&word);
}

pub fn storeDigest(store: *const Store) types.Root {
    assert(store.tree.count >= 1);
    var hasher = Sha256.init(.{});
    feed(&hasher, store.t);
    feed(&hasher, store.tree.count);
    for (0..store.tree.count) |i| {
        const node = store.tree.node(@intCast(i));
        hasher.update(&node.block.root);
        feed(&hasher, node.parent);
        feed(&hasher, node.timestamp);
    }
    for (0..limits.max_slots) |s| {
        const pool = store.pool.slotConst(@intCast(s));
        feed(&hasher, pool.entries.count);
        for (pool.entries.constSlice()) |*entry| {
            feed(&hasher, entry.vote.val_index);
            feed(&hasher, entry.vote.slot);
            hasher.update(&entry.vote.head);
            feed(&hasher, entry.timestamp);
        }
    }
    feed(&hasher, store.live_confirmed);
    feed(&hasher, store.latest_confirmed);
    feed(&hasher, store.latest_stable);
    feed(&hasher, store.finalized);
    var out: types.Root = undefined;
    hasher.final(&out);
    assert(!std.mem.eql(u8, &out, &types.genesis_root));
    return out;
}

/// Folds one more digest into a running digest.
pub fn combine(acc: *types.Root, next: *const types.Root) void {
    var hasher = Sha256.init(.{});
    hasher.update(acc);
    hasher.update(next);
    hasher.final(acc);
    assert(!std.mem.eql(u8, acc, next));
}
