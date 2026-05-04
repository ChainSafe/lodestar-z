//! Chunked-leaf payload.
//!
//! Replaces K=1024 individual leaf Nodes with a single `Storage` heap blob
//! (chunk array + length) referenced by one `.chunked_leaf` Node. Storage
//! is self-contained, ref-counted via the Pool's Node ref count, and
//! copy-on-write on mutation.
const std = @import("std");
const Allocator = std.mem.Allocator;
const hashOne = @import("hashing").hashOne;

pub const K: u16 = 1024;
pub const k_log2: u8 = 10;

comptime {
    std.debug.assert(@as(usize, 1) << k_log2 == K);
}

pub const Storage = struct {
    /// Chunk bytes, 64-byte aligned for cache-line locality. Chunks at
    /// indices `>= len` MUST hold zero-bytes — `allocZero` establishes
    /// this invariant and subsequent CoW writes preserve it. `chunks` is
    /// at offset 0 within Storage.
    chunks: [K][32]u8 align(64),
    /// Number of valid chunks in this payload. The last chunked-leaf in a
    /// list/vector may be partial (`len < K`); all earlier ones satisfy
    /// `len == K`.
    len: u16,
};

/// Allocates a zero-initialized Storage block with `len = 0`. Caller owns;
/// pair with destroy().
pub fn allocZero(allocator: Allocator) Allocator.Error!*Storage {
    const s = try allocator.create(Storage);
    @memset(std.mem.asBytes(&s.chunks), 0);
    s.len = 0;
    return s;
}

pub fn destroy(allocator: Allocator, s: *Storage) void {
    allocator.destroy(s);
}

/// Compute the chunked_leaf subtree root: K-leaf perfect binary tree, no padding.
///
/// Single-buffer layout: read first reduction directly from `chunked_leaf.chunks`
/// (no 32 KB stack copy), then halve in-place on `buf` (K/2 chunks).
pub fn computeRoot(chunked_leaf: *const Storage, out: *[32]u8) void {
    comptime std.debug.assert(@popCount(K) == 1);

    var buf: [K / 2][32]u8 align(64) = undefined;

    // First reduction: K leaves -> K/2 hashes, reading chunked_leaf.chunks directly.
    var i: usize = 0;
    while (i < K) : (i += 2) {
        hashOne(&buf[i / 2], &chunked_leaf.chunks[i], &chunked_leaf.chunks[i + 1]);
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
