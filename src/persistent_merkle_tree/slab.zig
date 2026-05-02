//! Chunked-leaf slab payload.
//!
//! `Storage` is the heap-allocated 32 KB chunk array shared by a slab Node.
//! Per-slab metadata (`len`, `dirty`, cached `root`) lives inline in the
//! Node.slab union variant, NOT in Storage — keeping the two in sync would
//! be error-prone and wasteful. Storage is therefore minimal and immutable
//! in shape (always `[K][32]u8`); per-chunk mutation is per-element write
//! into `chunks[i]`.
const std = @import("std");
const Allocator = std.mem.Allocator;
const hashOne = @import("hashing").hashOne;

pub const K: u16 = 1024;
pub const k_log2: u8 = 10;

comptime {
    std.debug.assert(@as(usize, 1) << k_log2 == K);
}

pub const Storage = struct {
    /// Slab chunks, cache-line aligned. The slab Node's inline `len` field
    /// (B2 onward) decides which chunks are valid; chunks at indices `>= len`
    /// MUST hold zero-bytes — `allocZero` establishes this invariant and
    /// subsequent CoW writes preserve it.
    chunks: [K][32]u8 align(64),
};

/// Allocates a zero-initialized Storage block. Caller owns; pair with destroy().
pub fn allocZero(allocator: Allocator) Allocator.Error!*Storage {
    const s = try allocator.create(Storage);
    @memset(std.mem.asBytes(&s.chunks), 0);
    return s;
}

pub fn destroy(allocator: Allocator, s: *Storage) void {
    allocator.destroy(s);
}

/// Compute the slab subtree root: K-leaf perfect binary tree, no padding.
///
/// Single-buffer layout: read first reduction directly from `slab.chunks`
/// (no 32 KB stack copy), then halve in-place on `buf` (K/2 chunks).
pub fn computeRoot(slab: *const Storage, out: *[32]u8) void {
    comptime std.debug.assert(@popCount(K) == 1);

    var buf: [K / 2][32]u8 align(64) = undefined;

    // First reduction: K leaves -> K/2 hashes, reading slab.chunks directly.
    var i: usize = 0;
    while (i < K) : (i += 2) {
        hashOne(&buf[i / 2], &slab.chunks[i], &slab.chunks[i + 1]);
    }

    // Subsequent reductions in-place on buf.
    var width: usize = K / 2;
    while (width > 1) : (width /= 2) {
        var j: usize = 0;
        while (j < width) : (j += 2) {
            hashOne(&buf[j / 2], &buf[j], &buf[j + 1]);
        }
    }

    out.* = buf[0];
}
