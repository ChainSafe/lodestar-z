const std = @import("std");
const network = @import("network");
const quic = network.quic;
const Engine = quic.engine.Engine;
var context: network.tls.context.Context = undefined;
var engine: Engine = undefined;

pub export fn zig_fuzz_init() callconv(.c) void {
    const key = network.KeyPair.fromSecretKey(&([_]u8{0} ** 31 ++ .{1})) catch unreachable;
    context = network.tls.context.Context.init(&key, 1_800_000_000, @splat(1)) catch @panic("TLS initialization failed");
    engine = Engine.init(std.heap.c_allocator, .{
        .tls = context,
        .limits = .{ .connections_max = 4, .handshaking_max = 2, .handshaking_per_source_max = 1, .dialing_max = 1 },
        .local = .{ .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 9000 } }, null },
        .seed = @splat(1),
    }) catch @panic("QUIC initialization failed");
}

pub export fn zig_fuzz_test(bytes: [*]const u8, len: usize) callconv(.c) void {
    if (len == 0 or len > network.constants.datagram_size_max) return;
    var datagram: [network.constants.datagram_size_max]u8 = undefined;
    var output: [datagram.len]u8 = undefined;
    var events: [32]quic.engine.Event = undefined;
    var now: network.Now = .{ .mono_ms = 0, .unix_s = 1_800_000_000 };
    var entropy: quic.engine.EntropyPool = .{};
    for (0..4) |i| {
        @memcpy(datagram[0..len], bytes[0..len]);
        const source: network.Address = .{ .ip4 = .{ .octets = .{ 192, 0, 2, @intCast(1 + i / 2) }, .port = @intCast(9000 + i) } };
        entropy.fill(@splat(@intCast(i + 1)));
        _ = engine.receive(datagram[0..len], &source, now, &entropy, &output);
        now.mono_ms += 1;
        engine.tick(now);
        _ = engine.pollEvents(&events);
        engine.releaseReported();
        std.debug.assert(engine.registry.active_len <= 4);
        std.debug.assert(engine.registry.handshaking <= 2);
        std.debug.assert(engine.registry.routes.count <= 2 * engine.registry.active_len);
    }
    for (engine.activeIndices()) |index| engine.failSend(index);
    _ = engine.pollEvents(&events);
    engine.releaseReported();
    std.debug.assert(engine.registry.active_len == 0 and engine.registry.handshaking == 0);
    std.debug.assert(engine.registry.routes.count == 0);
}
