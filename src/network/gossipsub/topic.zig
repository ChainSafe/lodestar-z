const std = @import("std");
const constants = @import("constants.zig");

const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const prefix = "/eth2/";
pub const suffix = "/ssz_snappy";
pub const digest_hex_len: usize = 8;
/// The longest name a Fulu node speaks is `data_column_sidecar_<0..127>`.
pub const name_max_len: usize = 24;
pub const topic_max_len: usize = prefix.len + digest_hex_len + 1 + name_max_len + suffix.len;

pub const ForkDigest = [4]u8;

pub const Parsed = struct {
    digest: ForkDigest,
    name: []const u8,
};

/// Writes `/eth2/<fork-digest-hex>/<name>/ssz_snappy` into `out` and returns it.
pub fn build(digest: ForkDigest, name: []const u8, out: []u8) []const u8 {
    assert(name.len <= name_max_len);
    const hex = std.fmt.bytesToHex(digest, .lower);
    var len: usize = 0;
    len = append(out, len, prefix);
    len = append(out, len, &hex);
    len = append(out, len, "/");
    len = append(out, len, name);
    len = append(out, len, suffix);
    return out[0..len];
}

fn append(out: []u8, at: usize, part: []const u8) usize {
    assert(at + part.len <= out.len);
    @memcpy(out[at..][0..part.len], part);
    return at + part.len;
}

/// Splits a topic string into its fork digest and name, or null when it does not
/// match `/eth2/<8 hex>/<name>/ssz_snappy`.
pub fn parse(topic: []const u8) ?Parsed {
    if (topic.len < prefix.len + digest_hex_len + 1 + suffix.len) return null;
    if (!std.mem.startsWith(u8, topic, prefix)) return null;
    if (!std.mem.endsWith(u8, topic, suffix)) return null;
    const after_prefix = topic[prefix.len..];
    if (after_prefix.len < digest_hex_len + 1) return null;
    if (after_prefix[digest_hex_len] != '/') return null;
    var digest: ForkDigest = undefined;
    _ = std.fmt.hexToBytes(&digest, after_prefix[0..digest_hex_len]) catch return null;
    const name = topic[prefix.len + digest_hex_len + 1 .. topic.len - suffix.len];
    if (name.len == 0 or name.len > name_max_len) return null;
    return .{ .digest = digest, .name = name };
}

pub const MessageId = [constants.message_id_length]u8;

fn digestWithDomain(domain: [4]u8, payload: []const u8) MessageId {
    var hash: [Sha256.digest_length]u8 = undefined;
    var state = Sha256.init(.{});
    state.update(&domain);
    state.update(payload);
    state.final(&hash);
    return hash[0..constants.message_id_length].*;
}

/// Message id over the snappy-decompressed payload (the valid-snappy case).
pub fn validMessageId(decompressed: []const u8) MessageId {
    return digestWithDomain(constants.MESSAGE_DOMAIN_VALID_SNAPPY, decompressed);
}

/// Message id over the raw message data when it does not snappy-decompress.
pub fn invalidMessageId(raw: []const u8) MessageId {
    return digestWithDomain(constants.MESSAGE_DOMAIN_INVALID_SNAPPY, raw);
}

fn expect(comptime hex: []const u8) MessageId {
    return (std.fmt.hexToBytes(
        @constCast(&([_]u8{0} ** constants.message_id_length)),
        hex,
    ) catch unreachable)[0..constants.message_id_length].*;
}

test "topic builds and round trips through parse" {
    var buf: [topic_max_len]u8 = undefined;
    const digest = ForkDigest{ 0x6a, 0x95, 0xa1, 0xa9 };
    const topic = build(digest, "beacon_block", &buf);
    try std.testing.expectEqualStrings("/eth2/6a95a1a9/beacon_block/ssz_snappy", topic);
    const parsed = parse(topic).?;
    try std.testing.expectEqual(digest, parsed.digest);
    try std.testing.expectEqualStrings("beacon_block", parsed.name);

    var sub: [topic_max_len]u8 = undefined;
    const columns = build(digest, "data_column_sidecar_127", &sub);
    try std.testing.expectEqualStrings("data_column_sidecar_127", parse(columns).?.name);
}

test "topic parse rejects malformed strings" {
    try std.testing.expect(parse("/eth2/6a95a1a9/beacon_block/ssz") == null);
    try std.testing.expect(parse("/eth1/6a95a1a9/beacon_block/ssz_snappy") == null);
    try std.testing.expect(parse("/eth2/zzzzzzzz/beacon_block/ssz_snappy") == null);
    try std.testing.expect(parse("/eth2/6a95a1/beacon_block/ssz_snappy") == null);
    try std.testing.expect(parse("/eth2/6a95a1a9//ssz_snappy") == null);
    try std.testing.expect(parse("") == null);
}

test "message id uses the domain and truncates to twenty bytes" {
    const valid = validMessageId("hello");
    const invalid = invalidMessageId("hello");
    try std.testing.expectEqual(expect("79d62a59d0e47597aeb73cb85ba034c3f67f90e8"), valid);
    try std.testing.expectEqual(expect("44c0a0d0ddc9808a27834e778f82623f9c897072"), invalid);
    const empty = validMessageId("");
    try std.testing.expectEqual(expect("67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b"), empty);
    try std.testing.expect(!std.mem.eql(u8, &valid, &invalid));
}
