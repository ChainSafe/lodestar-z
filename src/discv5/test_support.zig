const std = @import("std");
const crypto = @import("identity/crypto.zig");
const enr = @import("identity/enr.zig");
const types = @import("types.zig");
const rlp = @import("wire/rlp.zig");

pub fn buildRecord(
    key_pair: *const crypto.KeyPair,
    sequence: u64,
    endpoint: types.Address,
) !enr.Record {
    const ip4 = switch (endpoint) {
        .ip4 => |value| value,
        .ip6 => return error.UnsupportedTestAddress,
    };
    const public_key = crypto.compressedPublicKey(key_pair);
    var content_buffer: [300]u8 = undefined;
    var content_writer = rlp.Writer.init(&content_buffer);
    const content = try content_writer.beginList();
    try content_writer.writeUint(sequence);
    try content_writer.writeBytes("id");
    try content_writer.writeBytes("v4");
    try content_writer.writeBytes("ip");
    try content_writer.writeBytes(&ip4.octets);
    try content_writer.writeBytes("secp256k1");
    try content_writer.writeBytes(&public_key);
    try content_writer.writeBytes("udp");
    try content_writer.writeUint(ip4.port);
    content_writer.finishList(content);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(content_writer.bytes(), &digest, .{});
    const signature = try crypto.sign(&digest, key_pair);

    var full_buffer: [300]u8 = undefined;
    var full_writer = rlp.Writer.init(&full_buffer);
    const full = try full_writer.beginList();
    try full_writer.writeBytes(&signature);
    var content_reader = rlp.Reader.init(content_writer.bytes());
    var fields = try content_reader.readList();
    for (0..16) |_| {
        if (fields.atEnd()) break;
        try full_writer.writeRawItem(try fields.readRawItem());
    }
    if (!fields.atEnd()) return error.TooManyTestRecordFields;
    full_writer.finishList(full);
    return enr.Record.init(full_writer.bytes());
}
