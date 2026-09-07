const std = @import("std");
const codec = @import("network").reqresp.codec;

const input_max = 128 * 1024;
const payload_max = 64 * 1024;

pub export fn zig_fuzz_init() callconv(.c) void {}

pub export fn zig_fuzz_test(buf: [*]const u8, len: usize) callconv(.c) void {
    if (len == 0 or len > input_max) return;
    var sink: [payload_max]u8 = undefined;
    var scratch: [codec.frame_scratch_max]u8 = undefined;
    var decoder = codec.Decoder.initResponseWithContext(.{ .min = 0, .max = payload_max }, &sink, &scratch);
    var offset: usize = 0;
    for (0..4096) |_| {
        if (offset == len or decoder.isDone()) break;
        const take = @min(@as(usize, buf[offset] % 127 + 1), len - offset);
        const result = decoder.feed(buf[offset..][0..take]) catch return;
        if (result.consumed == 0) return;
        offset += result.consumed;
        if (decoder.awaitingContext()) {
            const digest = decoder.context().?;
            const min: usize = std.mem.readInt(u16, digest[0..2], .little);
            const max: usize = std.mem.readInt(u16, digest[2..4], .little);
            decoder.setContextBounds(.{ .min = min, .max = max }) catch return;
        }
    }
    if (!decoder.isDone()) return;
    const value = decoder.payload();
    std.debug.assert(value.len <= payload_max);
}
