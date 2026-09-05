const std = @import("std");
const codec = @import("network").reqresp.codec;

const input_max = 128 * 1024;
const payload_max = 64 * 1024;

pub export fn zig_fuzz_init() callconv(.c) void {}

pub export fn zig_fuzz_test(buf: [*]const u8, len: usize) callconv(.c) void {
    if (len == 0 or len > input_max) return;
    var sink: [payload_max]u8 = undefined;
    var scratch: [codec.frame_scratch_max]u8 = undefined;
    var decoder = codec.Decoder.initResponse(.{ .min = 0, .max = payload_max }, true, &sink, &scratch);
    var offset: usize = 0;
    for (0..4096) |_| {
        if (offset == len or decoder.isDone()) break;
        const take = @min(@as(usize, buf[offset] % 127 + 1), len - offset);
        const result = decoder.feed(buf[offset..][0..take]) catch return;
        if (result.consumed == 0) return;
        offset += result.consumed;
    }
    if (!decoder.isDone()) return;
    const value = decoder.payload();
    std.debug.assert(value.len <= payload_max);
}
