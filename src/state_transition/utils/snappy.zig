//! Snappy frame format implementation.
//!
//! Reference: https://github.com/google/snappy/blob/main/framing_format.txt

/// Chunk type tags from the Snappy framing format.
const ChunkType = enum(u8) {
    identifier = 0xff,
    compressed = 0x00,
    uncompressed = 0x01,
    padding = 0xfe,
    skippable = 0x80,
};

/// "sNaPpY" identifier payload.
const IDENTIFIER: [6]u8 = [_]u8{ 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59 };

/// Full identifier frame (type + length + payload).
const IDENTIFIER_FRAME: [10]u8 = [_]u8{ 0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59 };

/// Max allowed size for an uncompressed payload according to the spec.
const UNCOMPRESSED_CHUNK_SIZE_LIMIT = 65536;

const UncompressError = error{
    BadIdentifier,
    BadChecksum,
    IllegalChunkLength,
};

const EncodeError = std.mem.Allocator.Error || snappy.Error;

/// Frame `bytes` into Snappy chunks, choosing compressed payloads only
/// when they are smaller than their uncompressed counterparts.
fn encode(allocator: std.mem.Allocator, bytes: []const u8) EncodeError![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try out.appendSlice(&IDENTIFIER_FRAME);

    const max_compressed_len = snappy.maxCompressedLength(UNCOMPRESSED_CHUNK_SIZE_LIMIT);
    var compressed_buf = try allocator.alloc(u8, max_compressed_len);
    defer allocator.free(compressed_buf);

    var i: usize = 0;
    while (i < bytes.len) : (i += UNCOMPRESSED_CHUNK_SIZE_LIMIT) {
        const end = @min(i + UNCOMPRESSED_CHUNK_SIZE_LIMIT, bytes.len);
        const chunk = bytes[i..end];

        const compressed_len = try snappy.compress(chunk, compressed_buf);
        const compressed = compressed_buf[0..compressed_len];

        const use_compressed = compressed.len < chunk.len;
        const payload = if (use_compressed) compressed else chunk;
        const chunk_type: ChunkType = if (use_compressed) .compressed else .uncompressed;
        const frame_size = payload.len + 4;

        var header: [4]u8 = .{
            @intFromEnum(chunk_type),
            @truncate(frame_size & 0xff),
            @truncate((frame_size >> 8) & 0xff),
            @truncate((frame_size >> 16) & 0xff),
        };
        try out.appendSlice(&header);

        var checksum: [4]u8 = undefined;
        std.mem.writeInt(u32, &checksum, crc(chunk), .little);
        try out.appendSlice(&checksum);
        try out.appendSlice(payload);
    }

    return out.toOwnedSlice();
}

/// Parse framed Snappy data and return the uncompressed payload,
/// or `null` if the frame explicitly signalled an empty buffer.
pub fn uncompress(chunk: []const u8) UncompressError!?[]const u8 {
    std.debug.assert(chunk.len > 0);
    var slice = chunk;
    var buffer: ?[]const u8 = null;

    while (slice.len > 0) {
        if (slice.len < 4) break;
        const chunk_type: ChunkType = @enumFromInt(slice[0]);

        const frame_size: usize = slice[1] + (@as(usize, slice[2]) << 8) + (@as(usize, slice[3]) << 16);
        const frame = slice[4 .. 4 + frame_size];
        slice = slice[4 + frame_size ..];

        switch (chunk_type) {
            .identifier => {
                if (!std.mem.eql(u8, frame, &IDENTIFIER)) {
                    return UncompressError.BadIdentifier;
                }
            },
            .compressed => {
                const checksum = frame[0..4];
                const compressed = frame[4..];
                const uncompressed = try uncompress(compressed);

                if (uncompressed) |u| {
                    if (crc(u) != std.mem.bytesToValue(u32, checksum)) return UncompressError.BadChecksum;
                    buffer = u;
                }
                break;
            },
            .uncompressed => {
                const checksum = frame[0..4];
                const uncompressed = frame[4..];

                if (uncompressed.len > UNCOMPRESSED_CHUNK_SIZE_LIMIT) {
                    return UncompressError.IllegalChunkLength;
                }
                if (crc(uncompressed) != std.mem.bytesToValue(u32, checksum)) return UncompressError.BadChecksum;
                buffer = uncompressed;

                break;
            },
            .padding, .skippable => continue,
        }
    }

    if (buffer) |b| if (b.len == 0) return null;

    return buffer;
}

/// Masked CRC32C hash used by the Snappy framing format.
fn crc(b: []const u8) u32 {
    const c = std.hash.crc.Crc32Iscsi;
    const hash = c.hash(b);
    return @as(u32, hash >> 15 | hash << 17) +% 0xa282ead8;
}
test "snappy crc - sanity" {
    try std.testing.expect(crc("snappy") == 0x293d0c23);
}

test "round trip" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(blk: {
        var seed: u64 = undefined;
        try std.posix.getrandom(std.mem.asBytes(&seed));
        break :blk seed;
    });
    const rand = prng.random();
    for (0..1000) |_| {
        var buf: [69]u8 = undefined;
        rand.bytes(&buf);
        var tmp = buf;
        const encoded = try encode(allocator, tmp[0..]);
        defer allocator.free(encoded);
        const uncompressed = try uncompress(encoded);
        try std.testing.expect(std.mem.eql(
            u8,
            if (uncompressed) |u| u else "",
            &buf,
        ));
    }
}

const snappy = @import("snappy");
const std = @import("std");
