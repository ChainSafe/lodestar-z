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
    /// Slab chunks, cache-line aligned. Chunks at indices `>= len` MUST be
    /// zero-bytes; this invariant is the caller's responsibility (allocZero
    /// establishes it; subsequent slab CoW writes preserve it).
    chunks: [K][32]u8 align(64),
    /// Number of valid chunks in this slab. The last slab in a list/vector
    /// may be partial (`len < K`); all earlier slabs satisfy `len == K`.
    len: u16,
    /// Per-chunk modification flag tracking writes since the last slab-root
    /// recompute. Cleared by the slab-root cache layer (Node-side) once the
    /// cached root in the owning slab Node is refreshed.
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
/// Single working buffer of K/2 hashes. The first reduction reads pairs
/// directly from `slab.chunks` (no 32 KB stack copy); subsequent halvings
/// happen in-place on `buf`'s first `width` slots until width hits 1.
pub fn computeRoot(slab: *const Storage, out: *[32]u8) void {
    comptime std.debug.assert(@popCount(K) == 1);

    var buf: [K / 2][32]u8 align(64) = undefined;

    // First reduction: read directly from slab.chunks, no 32 KB stack copy.
    var i: usize = 0;
    while (i < K) : (i += 2) {
        hashOne(&buf[i / 2], &slab.chunks[i], &slab.chunks[i + 1]);
    }

    // Subsequent reductions in-place.
    var width: usize = K / 2;
    while (width > 1) : (width /= 2) {
        var j: usize = 0;
        while (j < width) : (j += 2) {
            hashOne(&buf[j / 2], &buf[j], &buf[j + 1]);
        }
    }

    out.* = buf[0];
}
