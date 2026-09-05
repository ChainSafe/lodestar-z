const std = @import("std");
const gossip = @import("network").gossipsub;

const input_max = 128 * 1024;
const body_max = 64 * 1024;

pub export fn zig_fuzz_init() callconv(.c) void {}

pub export fn zig_fuzz_test(buf: [*]const u8, len: usize) callconv(.c) void {
    if (len == 0 or len > input_max) return;
    var frame = gossip.frame.Reader{};
    var body: [body_max]u8 = undefined;
    var offset: usize = 0;
    for (0..4096) |_| {
        if (offset == len) break;
        const take = @min(@as(usize, buf[offset] % 127 + 1), len - offset);
        const result = frame.feed(buf[offset..][0..take], &body) catch return;
        if (result.consumed == 0 and frame.declaredLen() != null) {
            frame.discard();
            continue;
        }
        if (result.consumed == 0) return;
        offset += result.consumed;
        const rpc = result.frame orelse continue;
        var reader = gossip.protobuf.RpcReader.init(rpc);
        for (0..4096) |_| {
            const item = reader.next() catch break;
            if (item == null) break;
        }
    }
}
