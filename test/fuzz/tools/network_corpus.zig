const std = @import("std");
const network = @import("network");
const discv5 = @import("discv5");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const cwd = std.Io.Dir.cwd();
    for ([_][]const u8{ "discv5_wire", "network_tls", "network_quic_receive" }) |target| {
        var path: [128]u8 = undefined;
        try cwd.createDirPath(io, try std.fmt.bufPrint(&path, "corpus/{s}-initial", .{target}));
    }
    const key = try network.KeyPair.fromSecretKey(&([_]u8{0} ** 31 ++ .{1}));
    var certificate = try network.tls.cert.Certificate.create(&key, 1_800_000_000, @splat(1));
    defer certificate.deinit();
    var buffer: [network.constants.datagram_size_max + 1]u8 = undefined;
    const der = try certificate.der(&buffer);
    _ = try network.tls.verify.verifyDer(der, 1_800_000_000);
    try write(io, "network_tls", "valid.der", der);
    try write(io, "network_tls", "truncated.der", der[0 .. der.len - 1]);
    const c = network.quic.binding.c;
    std.debug.assert(c.X509_get_ext_count(certificate.x509) == 1);
    c.X509_EXTENSION_free(c.X509_delete_ext(certificate.x509, 0));
    if (c.X509_sign(certificate.x509, certificate.key, c.EVP_sha256()) <= 0) return error.SignFailed;
    try write(io, "network_tls", "missing-extension.der", try certificate.der(&buffer));

    var context = try network.tls.context.Context.init(&key, 1_800_000_000, @splat(1));
    const local: network.Address = .{ .ip4 = .{ .octets = .{ 192, 0, 2, 1 }, .port = 9000 } };
    const remote: network.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 9000 } };
    var engine = network.Engine.init(std.heap.page_allocator, .{
        .tls = context,
        .limits = .{ .connections_max = 4, .handshaking_max = 2, .dialing_max = 1 },
        .local = .{ local, null },
        .seed = &@as([32]u8, @splat(1)),
    }) catch |err| {
        context.deinit();
        return err;
    };
    defer engine.deinit();
    const now: network.Now = .{ .mono_ms = 0, .unix_s = 1_800_000_000 };
    const handle = try engine.dial(&remote, context.local_peer_id, now);
    const sent = engine.sendOne(handle.index, now, &buffer) orelse return error.MissingInitial;
    try write(io, "network_quic_receive", "initial", sent.bytes);

    var server_context = try network.tls.context.Context.init(&key, now.unix_s, @splat(1));
    var server = network.Engine.init(std.heap.page_allocator, .{
        .tls = server_context,
        .limits = .{ .connections_max = 4, .handshaking_max = 2, .handshaking_per_source_max = 1, .dialing_max = 1 },
        .local = .{ remote, null },
        .seed = &@as([32]u8, @splat(1)),
    }) catch |err| {
        server_context.deinit();
        return err;
    };
    defer server.deinit();
    var response: [network.constants.datagram_size_max]u8 = undefined;
    const retried = server.receive(sent.bytes, &local, now, &response);
    if (retried != .retry) return error.MissingRetry;
    _ = engine.receive(retried.retry, &remote, now, &buffer);
    const validated = engine.sendOne(handle.index, now, &buffer) orelse return error.MissingInitial;
    try write(io, "network_quic_receive", "validated-initial", validated.bytes);

    @memcpy(buffer[1..5], &[_]u8{ 0xfa, 0xce, 0xb0, 0x0c });
    try write(io, "network_quic_receive", "unknown-version", validated.bytes);
    try write(io, "network_quic_receive", "short-header", &([_]u8{0x40} ++ [_]u8{0} ** 40));

    const message = discv5.wire.message;
    const ping: message.Message = .{ .ping = .{ .request_id = try message.RequestId.init(&.{1}), .enr_sequence = 1 } };
    buffer[0] = 0;
    const encoded = try ping.encode(buffer[1..]);
    try write(io, "discv5_wire", "ping", buffer[0 .. 1 + encoded.len]);
    try write(io, "discv5_wire", "truncated-rlp", buffer[0..encoded.len]);
    const packet = discv5.wire.packet;
    buffer[0] = 1;
    const who = try packet.encodeWhoareyou(buffer[1..], .{
        .masking_iv = &@as([16]u8, @splat(1)),
        .recipient_id = &@as([32]u8, @splat(0x42)),
        .request_nonce = &@as([12]u8, @splat(2)),
        .id_nonce = &@as([16]u8, @splat(3)),
        .enr_sequence = 1,
    }, null);
    var scratch: packet.DecodeScratch = .{};
    _ = try packet.decode(who, &@as([32]u8, @splat(0x42)), &scratch);
    try write(io, "discv5_wire", "whoareyou", buffer[0 .. 1 + who.len]);
    const discovery_key = try discv5.identity.crypto.keyPairFromSecret(&([_]u8{0} ** 31 ++ .{1}));
    const record = try discv5.identity.enr.Record.create(&discovery_key, 1, local);
    buffer[0] = 2;
    @memcpy(buffer[1..][0..record.length], record.slice());
    try write(io, "discv5_wire", "signed-enr", buffer[0 .. 1 + record.length]);
    buffer[3] ^= 1;
    try write(io, "discv5_wire", "invalid-enr", buffer[0 .. 1 + record.length]);
}

fn write(io: std.Io, target: []const u8, name: []const u8, bytes: []const u8) !void {
    var path: [256]u8 = undefined;
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = try std.fmt.bufPrint(&path, "corpus/{s}-initial/{s}", .{ target, name }),
        .data = bytes,
    });
}
