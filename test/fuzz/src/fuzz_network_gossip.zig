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
    var steps_left: usize = 4096;
    var fields_left: usize = input_max;
    var decode_left: usize = input_max;
    var decoded: [body_max]u8 = undefined;
    for (0..4096) |_| {
        if (offset == len or steps_left == 0) break;
        steps_left -= 1;
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
            if (steps_left == 0) return;
            steps_left -= 1;
            const step = reader.step(&fields_left) catch break;
            const item = switch (step) {
                .item => |item| item,
                .skipped => continue,
                .end, .deferred => break,
            };
            if (item != .message) continue;
            const message = item.message;
            const header = gossip.admission.inspect(&message);
            if (header != .payload or header.payload > decoded.len) continue;
            const cost = message.data.len + header.payload;
            if (cost > decode_left) return;
            decode_left -= cost;
            const admitted = gossip.admission.decode(&message, decoded[0..header.payload], .{});
            if (admitted == .valid) std.debug.assert(admitted.valid.bytes.len == header.payload);
            std.mem.doNotOptimizeAway(admitted);
        }
    }
}
