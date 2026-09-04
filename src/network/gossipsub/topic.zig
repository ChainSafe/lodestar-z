const std = @import("std");
const constants = @import("constants.zig");

const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const prefix = "/eth2/";
pub const suffix = "/ssz_snappy";
pub const digest_hex_len: usize = 8;
/// The longest supported gossip name is `sync_committee_contribution_and_proof`.
pub const name_max_len: usize = "sync_committee_contribution_and_proof".len;
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

pub const MessageIdPolicy = struct {
    /// Topics with this digest use Phase0 IDs; all other topics use Altair IDs.
    phase0_digest: ?ForkDigest = null,

    fn isPhase0(self: MessageIdPolicy, topic: []const u8) bool {
        const phase0_digest = self.phase0_digest orelse return false;
        const parsed = parse(topic) orelse return false;
        return std.mem.eql(u8, &phase0_digest, &parsed.digest);
    }
};

fn digestWithDomain(
    domain: [4]u8,
    topic: []const u8,
    payload: []const u8,
    policy: MessageIdPolicy,
) MessageId {
    var hash: [Sha256.digest_length]u8 = undefined;
    var state = Sha256.init(.{});
    state.update(&domain);
    if (!policy.isPhase0(topic)) {
        var topic_length: [8]u8 = undefined;
        std.mem.writeInt(u64, &topic_length, @intCast(topic.len), .little);
        state.update(&topic_length);
        state.update(topic);
    }
    state.update(payload);
    state.final(&hash);
    return hash[0..constants.message_id_length].*;
}

/// Message id over the snappy-decompressed payload (the valid-snappy case).
pub fn validMessageId(
    topic: []const u8,
    decompressed: []const u8,
    policy: MessageIdPolicy,
) MessageId {
    return digestWithDomain(constants.MESSAGE_DOMAIN_VALID_SNAPPY, topic, decompressed, policy);
}

/// Message id over the raw message data when it does not snappy-decompress.
pub fn invalidMessageId(topic: []const u8, raw: []const u8, policy: MessageIdPolicy) MessageId {
    return digestWithDomain(constants.MESSAGE_DOMAIN_INVALID_SNAPPY, topic, raw, policy);
}

fn expect(comptime hex: []const u8) MessageId {
    var out: MessageId = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
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

const vector_topic = "/eth2/01020304/beacon_block/ssz_snappy";
const vector_other_topic = "/eth2/01020304/beacon_aggregate_and_proof/ssz_snappy";
const phase0_policy = MessageIdPolicy{ .phase0_digest = .{ 1, 2, 3, 4 } };

// Independently derived with Python hashlib from consensus-specs v1.7.0-alpha.11
// specs/{phase0,altair}/p2p-interface.md, GossipSub message-id formulas.
test "message id preserves the configured Phase0 domain and twenty byte truncation" {
    const valid = validMessageId(vector_topic, "hello", phase0_policy);
    const invalid = invalidMessageId(vector_topic, "hello", phase0_policy);
    try std.testing.expectEqual(expect("79d62a59d0e47597aeb73cb85ba034c3f67f90e8"), valid);
    try std.testing.expectEqual(expect("44c0a0d0ddc9808a27834e778f82623f9c897072"), invalid);
    const empty = validMessageId(vector_topic, "", phase0_policy);
    try std.testing.expectEqual(expect("67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b"), empty);
    try std.testing.expect(!std.mem.eql(u8, &valid, &invalid));
    try std.testing.expectEqual(
        expect("a0960f8d63bfe4fce6c26ae9e33f8f2d2729239a"),
        invalidMessageId(vector_topic, &.{0xff}, phase0_policy),
    );
    try std.testing.expectEqual(valid, validMessageId(vector_other_topic, "hello", phase0_policy));
}

test "message id includes the Altair topic length and bytes" {
    try std.testing.expectEqual(
        expect("a9fe6ab574e2aac2f18a37d95a6250a6e0f5b583"),
        validMessageId(vector_topic, "hello", .{}),
    );
}

test "message id includes the topic for invalid Snappy" {
    try std.testing.expectEqual(
        expect("a28c11a9057a41e968c2c3eead4b4c9fdd39c0d0"),
        invalidMessageId(vector_topic, &.{0xff}, .{}),
    );
}

test "message id separates modern topics when Phase0 is configured" {
    const policy = MessageIdPolicy{ .phase0_digest = .{ 9, 8, 7, 6 } };
    try std.testing.expectEqual(
        expect("a9fe6ab574e2aac2f18a37d95a6250a6e0f5b583"),
        validMessageId(vector_topic, "hello", policy),
    );
    try std.testing.expectEqual(
        expect("da00350732db6a43c1f625bf287c9a136f6dfc75"),
        validMessageId(vector_other_topic, "hello", policy),
    );
    try std.testing.expectEqual(
        expect("6e01bb6dbc25bf015fe1884bae6973aff4614ddf"),
        invalidMessageId(vector_other_topic, &.{0xff}, policy),
    );
}

test "topic accepts the aggregate and proof protocol name" {
    try std.testing.expect(parse(vector_other_topic) != null);
    var out: [topic_max_len]u8 = undefined;
    try std.testing.expectEqualStrings(
        vector_other_topic,
        build(.{ 1, 2, 3, 4 }, "beacon_aggregate_and_proof", &out),
    );
}
