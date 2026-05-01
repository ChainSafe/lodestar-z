//! Chunked-leaf slab payload for Phase B of the chunked-leaf design.
//!
//! A `Storage` block holds K=1024 contiguous 32-byte chunks plus a per-chunk
//! dirty bitset and a length counter. Slab nodes in the Pool point at one of
//! these heap-allocated blocks. Slab merkleization is a fixed-shape K-leaf
//! perfect binary tree whose root we cache on the Node side.
const std = @import("std");
const Allocator = std.mem.Allocator;
const hashOne = @import("hashing").hashOne;

pub const K: u16 = 1024;
pub const k_log2: u8 = 10;

comptime {
    std.debug.assert(@as(usize, 1) << k_log2 == K);
}

pub const Storage = struct {
    chunks: [K][32]u8 align(64),
    len: u16,
    dirty: std.StaticBitSet(K),
};

/// Allocates a zero-initialized Storage block. Caller owns; pair with destroy().
pub fn allocZero(allocator: Allocator) Allocator.Error!*Storage {
    const s = try allocator.create(Storage);
    @memset(std.mem.asBytes(&s.chunks), 0);
    s.len = 0;
    s.dirty = std.StaticBitSet(K).initEmpty();
    return s;
}

pub fn destroy(allocator: Allocator, s: *Storage) void {
    allocator.destroy(s);
}

/// Compute the slab subtree root: K-leaf perfect binary tree, no padding.
///
/// Two-buffer pingpong: read K leaves into buf_a, hash pairs into buf_b
/// (now K/2 hashes). Subsequent halvings happen in-place on buf_b's first
/// `width` slots until width hits 1.
pub fn computeRoot(slab: *const Storage, out: *[32]u8) void {
    comptime std.debug.assert(@popCount(K) == 1);

    var buf_a: [K][32]u8 align(64) = slab.chunks;
    var buf_b: [K / 2][32]u8 align(64) = undefined;

    // First reduction: K leaves -> K/2 hashes.
    var i: usize = 0;
    while (i < K) : (i += 2) {
        hashOne(&buf_b[i / 2], &buf_a[i], &buf_a[i + 1]);
    }

    // Subsequent reductions in-place on buf_b.
    var width: usize = K / 2;
    while (width > 1) : (width /= 2) {
        var j: usize = 0;
        while (j < width) : (j += 2) {
            hashOne(&buf_b[j / 2], &buf_b[j], &buf_b[j + 1]);
        }
    }

    out.* = buf_b[0];
}
