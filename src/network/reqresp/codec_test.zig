const std = @import("std");
const codec = @import("codec.zig");
const constants = @import("constants.zig");

const Decoder = codec.Decoder;

fn fromHex(comptime text: []const u8) [text.len / 2]u8 {
    var out: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;
    return out;
}

const phase0_metadata_prefix = fromHex("10");
const phase0_metadata_chunk = fromHex("ff060000734e61507059011400000b5ee91209000000000000000000000000000000");
const altair_metadata_prefix = fromHex("11");
const altair_metadata_chunk = fromHex("ff060000734e6150705901150000ff4669fc0800000000000000000000000000000000");
const ping_prefix = fromHex("08");
const ping_chunk = fromHex("ff060000734e61507059010c00000175de410100000000000000");

fn decodeAll(decoder: *Decoder, bytes: []const u8, piece: usize) ![]const u8 {
    var cursor: usize = 0;
    while (cursor < bytes.len) {
        const end = @min(bytes.len, cursor + piece);
        const progress = try decoder.feed(bytes[cursor..end]);
        cursor += progress.consumed;
        if (progress.done) break;
        try std.testing.expect(progress.consumed > 0);
    }
    try std.testing.expect(decoder.isDone());
    return decoder.payload();
}

test "codec decodes the Lodestar metadata and ping fixtures" {
    var sink: [64]u8 = undefined;
    var scratch: [codec.frame_scratch_max]u8 = undefined;

    var decoder = Decoder.initRequest(.{ .min = 16, .max = 16 }, &sink, &scratch);
    const phase0 = phase0_metadata_prefix ++ phase0_metadata_chunk;
    const metadata = try decodeAll(&decoder, &phase0, 3);
    try std.testing.expectEqual(@as(usize, 16), metadata.len);
    try std.testing.expectEqual(@as(u8, 9), metadata[0]);
    try std.testing.expect(std.mem.allEqual(u8, metadata[1..], 0));

    decoder = Decoder.initRequest(.{ .min = 17, .max = 17 }, &sink, &scratch);
    const altair = altair_metadata_prefix ++ altair_metadata_chunk;
    const altair_metadata = try decodeAll(&decoder, &altair, 1);
    try std.testing.expectEqual(@as(usize, 17), altair_metadata.len);
    try std.testing.expectEqual(@as(u8, 8), altair_metadata[0]);

    decoder = Decoder.initResponse(.{ .min = 8, .max = 8 }, false, &sink, &scratch);
    const ping = [_]u8{0} ++ ping_prefix ++ ping_chunk;
    const ping_payload = try decodeAll(&decoder, &ping, 5);
    try std.testing.expectEqual(@as(u64, 1), std.mem.readInt(u64, ping_payload[0..8], .little));
    try std.testing.expectEqual(@as(u8, 0), decoder.result());
    try std.testing.expect(decoder.context() == null);
}

test "codec encodes the Lodestar fixtures byte for byte" {
    var out: [128]u8 = undefined;
    var ping_value: [8]u8 = undefined;
    std.mem.writeInt(u64, &ping_value, 1, .little);
    const ping = try codec.encodeRequest(&ping_value, &out);
    try std.testing.expectEqualSlices(u8, &(ping_prefix ++ ping_chunk), ping);

    var metadata_value = [_]u8{0} ** 16;
    metadata_value[0] = 9;
    const metadata = try codec.encodeChunk(0, null, &metadata_value, &out);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ++ phase0_metadata_prefix ++ phase0_metadata_chunk), metadata);
}

test "codec round trips a large payload in one-byte and seven-byte pieces" {
    const allocator = std.testing.allocator;
    const payload = try allocator.alloc(u8, 100_000);
    defer allocator.free(payload);
    var prng = std.Random.DefaultPrng.init(7);
    prng.random().bytes(payload);
    const encoded = try allocator.alloc(u8, codec.encodedLengthMax(payload.len));
    defer allocator.free(encoded);
    const context = [4]u8{ 0xde, 0xad, 0xbe, 0xef };
    const bytes = try codec.encodeChunk(0, context, payload, encoded);
    try std.testing.expect(bytes.len > payload.len);

    const sink = try allocator.alloc(u8, payload.len);
    defer allocator.free(sink);
    const scratch = try allocator.alloc(u8, codec.frame_scratch_max);
    defer allocator.free(scratch);
    for ([_]usize{ 1, 7, 65_536 }) |piece| {
        var decoder = Decoder.initResponse(.{ .min = 1, .max = payload.len }, true, sink, scratch);
        const decoded = try decodeAll(&decoder, bytes, piece);
        try std.testing.expectEqualSlices(u8, payload, decoded);
        try std.testing.expectEqual(context, decoder.context().?);
    }
}

test "codec compresses repetitive payloads into compressed frames" {
    const allocator = std.testing.allocator;
    const payload = try allocator.alloc(u8, 70_000);
    defer allocator.free(payload);
    @memset(payload, 0);
    const encoded = try allocator.alloc(u8, codec.encodedLengthMax(payload.len));
    defer allocator.free(encoded);
    const bytes = try codec.encodeRequest(payload, encoded);
    try std.testing.expect(bytes.len < payload.len / 10);
    try std.testing.expectEqual(@as(u8, 0x00), bytes[3 + codec.identifier.len]);

    const sink = try allocator.alloc(u8, payload.len);
    defer allocator.free(sink);
    var scratch: [codec.frame_scratch_max]u8 = undefined;
    var decoder = Decoder.initRequest(.{ .min = 0, .max = payload.len }, sink, &scratch);
    const decoded = try decodeAll(&decoder, bytes, 1_000);
    try std.testing.expectEqualSlices(u8, payload, decoded);
}

test "codec streams a chunk through the writer identically to the one-shot encoder" {
    const allocator = std.testing.allocator;
    const payload = try allocator.alloc(u8, 200_000);
    defer allocator.free(payload);
    for (payload, 0..) |*byte, index| byte.* = @truncate(index *% 13);
    const whole = try allocator.alloc(u8, codec.encodedLengthMax(payload.len));
    defer allocator.free(whole);
    const expected = try codec.encodeChunk(0, [4]u8{ 1, 2, 3, 4 }, payload, whole);

    var writer = codec.ChunkWriter.initChunk(0, [4]u8{ 1, 2, 3, 4 }, payload);
    var piece_buffer: [codec.frame_header_length + codec.frame_body_max]u8 = undefined;
    const streamed = try allocator.alloc(u8, expected.len);
    defer allocator.free(streamed);
    var cursor: usize = 0;
    var pieces: usize = 0;
    while (!writer.done()) : (pieces += 1) {
        const piece = try writer.next(&piece_buffer);
        @memcpy(streamed[cursor..][0..piece.len], piece);
        cursor += piece.len;
    }
    try std.testing.expectEqual(@as(usize, 5), pieces);
    try std.testing.expectEqualSlices(u8, expected, streamed[0..cursor]);
}

test "codec decodes error chunks and rejects reserved results" {
    var sink: [codec.error_message_max]u8 = undefined;
    var scratch: [codec.frame_scratch_max]u8 = undefined;
    var out: [128]u8 = undefined;
    const chunk = try codec.encodeChunk(1, null, "bad", &out);
    var decoder = Decoder.initResponse(.{ .min = 8, .max = 8 }, true, &sink, &scratch);
    const message = try decodeAll(&decoder, chunk, 4);
    try std.testing.expectEqualStrings("bad", message);
    try std.testing.expectEqual(@as(u8, 1), decoder.result());
    try std.testing.expect(decoder.isError());
    try std.testing.expect(decoder.context() == null);

    const custom = try codec.encodeChunk(200, null, "", &out);
    decoder = Decoder.initResponse(.{ .min = 8, .max = 8 }, true, &sink, &scratch);
    try std.testing.expectEqual(@as(usize, 0), (try decodeAll(&decoder, custom, 64)).len);
    try std.testing.expectEqual(@as(u8, 200), decoder.result());

    decoder = Decoder.initResponse(.{ .min = 8, .max = 8 }, false, &sink, &scratch);
    try std.testing.expectError(error.ReservedResult, decoder.feed(&[_]u8{5}));
}

test "codec rejects every malformed input it must" {
    var sink: [256]u8 = undefined;
    var scratch: [codec.frame_scratch_max]u8 = undefined;
    const bounds = codec.Bounds{ .min = 8, .max = 64 };

    var decoder = Decoder.initRequest(bounds, &sink, &scratch);
    const long_varint = [_]u8{0x80} ** 10 ++ [_]u8{0x01};
    try std.testing.expectError(error.VarintTooLong, decoder.feed(&long_varint));

    decoder = Decoder.initRequest(bounds, &sink, &scratch);
    try std.testing.expectError(error.LengthOutOfBounds, decoder.feed(&[_]u8{7}));
    decoder = Decoder.initRequest(bounds, &sink, &scratch);
    try std.testing.expectError(error.LengthOutOfBounds, decoder.feed(&[_]u8{65}));

    decoder = Decoder.initRequest(bounds, &sink, &scratch);
    try std.testing.expectError(error.BadIdentifier, decoder.feed(&[_]u8{ 8, 0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x58 }));

    decoder = Decoder.initRequest(bounds, &sink, &scratch);
    const reserved_frame = [_]u8{8} ++ codec.identifier ++ [_]u8{ 0x02, 0x04, 0x00, 0x00 };
    try std.testing.expectError(error.BadFrameType, decoder.feed(&reserved_frame));

    decoder = Decoder.initRequest(bounds, &sink, &scratch);
    const huge_frame = [_]u8{8} ++ codec.identifier ++ [_]u8{ 0x01, 0xff, 0xff, 0xff };
    try std.testing.expectError(error.FrameTooLarge, decoder.feed(&huge_frame));

    decoder = Decoder.initRequest(bounds, &sink, &scratch);
    const long_frame = [_]u8{8} ++ codec.identifier ++ [_]u8{ 0x01, 40, 0x00, 0x00 } ++ [_]u8{0} ** 40;
    try std.testing.expectError(error.TooManyCompressedBytes, decoder.feed(&long_frame));

    var bad_crc = ping_prefix ++ ping_chunk;
    bad_crc[1 + codec.identifier.len + 4] ^= 0x01;
    decoder = Decoder.initRequest(bounds, &sink, &scratch);
    try std.testing.expectError(error.BadChecksum, decoder.feed(&bad_crc));

    const second_frame = ping_chunk[codec.identifier.len..].*;
    const two_frames = ping_prefix ++ ping_chunk ++ second_frame;
    decoder = Decoder.initRequest(bounds, &sink, &scratch);
    const progress = try decoder.feed(&two_frames);
    try std.testing.expect(progress.done);
    try std.testing.expectEqual(@as(usize, 1 + ping_chunk.len), progress.consumed);

    var too_many = [_]u8{8} ++ codec.identifier ++ [_]u8{ 0x01, 0x0d, 0x00, 0x00 } ++ [_]u8{0} ** 13;
    std.mem.writeInt(u32, too_many[1 + codec.identifier.len + 4 ..][0..4], codec.maskedChecksum(too_many[1 + codec.identifier.len + 8 ..]), .little);
    decoder = Decoder.initRequest(bounds, &sink, &scratch);
    try std.testing.expectError(error.TooManyBytes, decoder.feed(&too_many));

    decoder = Decoder.initRequest(.{ .min = 0, .max = 8 }, &sink, &scratch);
    const empty = try decoder.feed(&[_]u8{0});
    try std.testing.expect(empty.done);
    try std.testing.expectEqual(@as(usize, 0), decoder.payload().len);
}

test "codec frame size constants and header bound hold" {
    try std.testing.expectEqual(@as(usize, 4 + 32 + 65_536 + 65_536 / 6), codec.frame_body_max);
    try std.testing.expectEqual(@as(usize, 25 + 40 + 100 + 16), codec.encodedLengthMax(100));
    try std.testing.expectEqual(@as(usize, 2), codec.frameCount(65_537));
    try std.testing.expectEqual(@as(usize, 1), codec.frameCount(0));
    var out: [16]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, codec.encodeRequest(&[_]u8{1} ** 8, &out));
}
