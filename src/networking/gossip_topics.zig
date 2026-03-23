//! Gossip topic parsing and formatting for the Ethereum consensus P2P protocol.
//!
//! Ethereum gossip topics follow the pattern:
//! `/eth2/<fork_digest_hex>/<topic_name>/ssz_snappy`
//!
//! Some topics are subnet-indexed:
//! `/eth2/<fork_digest_hex>/beacon_attestation_<subnet_id>/ssz_snappy`
//!
//! Reference: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/p2p-interface.md#topics-and-messages

const std = @import("std");
const testing = std.testing;
const constants = @import("constants");

/// The fixed encoding suffix for all gossip topics.
const ENCODING_SUFFIX = "ssz_snappy";

/// The fixed topic prefix.
const TOPIC_PREFIX = "/eth2/";

/// Maximum subnet index for attestation subnets.
pub const MAX_ATTESTATION_SUBNET_ID = constants.ATTESTATION_SUBNET_COUNT;

/// Maximum subnet index for sync committee subnets.
pub const MAX_SYNC_COMMITTEE_SUBNET_ID = constants.SYNC_COMMITTEE_SUBNET_COUNT;

/// Maximum subnet index for blob sidecars (currently 6 on mainnet).
/// This must match MAX_BLOBS_PER_BLOCK from the preset/config.
pub const MAX_BLOB_SIDECAR_SUBNET_ID = 6;

/// Gossip topic types as defined by the consensus spec.
pub const GossipTopicType = enum {
    beacon_block,
    beacon_aggregate_and_proof,
    beacon_attestation,
    voluntary_exit,
    proposer_slashing,
    attester_slashing,
    bls_to_execution_change,
    blob_sidecar,
    sync_committee_contribution_and_proof,
    sync_committee,

    /// Returns the canonical topic name string for non-subnet-indexed topics.
    /// For subnet-indexed topics, use `subnetTopicName` instead.
    pub fn topicName(self: GossipTopicType) []const u8 {
        return switch (self) {
            .beacon_block => "beacon_block",
            .beacon_aggregate_and_proof => "beacon_aggregate_and_proof",
            .beacon_attestation => "beacon_attestation",
            .voluntary_exit => "voluntary_exit",
            .proposer_slashing => "proposer_slashing",
            .attester_slashing => "attester_slashing",
            .bls_to_execution_change => "bls_to_execution_change",
            .blob_sidecar => "blob_sidecar",
            .sync_committee_contribution_and_proof => "sync_committee_contribution_and_proof",
            .sync_committee => "sync_committee",
        };
    }

    /// Whether this topic type uses a subnet index suffix.
    pub fn isSubnetIndexed(self: GossipTopicType) bool {
        return switch (self) {
            .beacon_attestation, .sync_committee, .blob_sidecar => true,
            else => false,
        };
    }
};

/// A fully parsed gossip topic with fork digest and optional subnet index.
pub const GossipTopic = struct {
    fork_digest: [4]u8,
    topic_type: GossipTopicType,
    /// Subnet index for subnet-indexed topics. Null for global topics.
    subnet_id: ?u8,

    pub fn eql(a: GossipTopic, b: GossipTopic) bool {
        return std.mem.eql(u8, &a.fork_digest, &b.fork_digest) and
            a.topic_type == b.topic_type and
            a.subnet_id == b.subnet_id;
    }
};

/// Error type for topic parsing failures.
pub const ParseError = error{
    /// Topic string is too short or missing required segments.
    MalformedTopic,
    /// Fork digest hex is invalid (not exactly 8 hex chars).
    InvalidForkDigest,
    /// The topic name is not recognized.
    UnknownTopicName,
    /// The encoding suffix is not `ssz_snappy`.
    UnsupportedEncoding,
    /// Subnet index is out of valid range.
    InvalidSubnetId,
};

/// Parse a gossip topic string into its components.
///
/// Expected format: `/eth2/<fork_digest_hex>/<topic_name>/ssz_snappy`
/// Where `<fork_digest_hex>` is 8 hex characters (4 bytes).
///
/// Returns null for unrecoverable parse failures (malformed structure).
/// Use `parseTopicStrict` for detailed error reporting.
pub fn parseTopic(topic_str: []const u8) ?GossipTopic {
    return parseTopicStrict(topic_str) catch null;
}

/// Parse a gossip topic string with detailed error reporting.
pub fn parseTopicStrict(topic_str: []const u8) ParseError!GossipTopic {
    // Must start with "/eth2/"
    if (topic_str.len < TOPIC_PREFIX.len) return error.MalformedTopic;
    if (!std.mem.eql(u8, topic_str[0..TOPIC_PREFIX.len], TOPIC_PREFIX)) return error.MalformedTopic;

    const after_prefix = topic_str[TOPIC_PREFIX.len..];

    // Find the fork digest (next segment between slashes).
    const first_slash = std.mem.indexOfScalar(u8, after_prefix, '/') orelse return error.MalformedTopic;
    const fork_digest_hex = after_prefix[0..first_slash];

    // Fork digest must be exactly 8 hex characters (4 bytes).
    if (fork_digest_hex.len != 8) return error.InvalidForkDigest;

    var fork_digest: [4]u8 = undefined;
    _ = std.fmt.hexToBytes(&fork_digest, fork_digest_hex) catch return error.InvalidForkDigest;

    // After fork_digest/, find the topic name segment.
    const after_fork = after_prefix[first_slash + 1 ..];
    const second_slash = std.mem.indexOfScalar(u8, after_fork, '/') orelse return error.MalformedTopic;
    const topic_name = after_fork[0..second_slash];

    // Encoding suffix must be ssz_snappy.
    const encoding = after_fork[second_slash + 1 ..];
    if (!std.mem.eql(u8, encoding, ENCODING_SUFFIX)) return error.UnsupportedEncoding;

    // Parse the topic name, checking for subnet-indexed topics.
    return parseTopicName(topic_name, fork_digest);
}

/// Parse the topic name segment, handling subnet-indexed variants.
fn parseTopicName(name: []const u8, fork_digest: [4]u8) ParseError!GossipTopic {
    // Try exact matches for non-subnet-indexed topics first.
    const exact_topics = [_]struct { name: []const u8, topic_type: GossipTopicType }{
        .{ .name = "beacon_block", .topic_type = .beacon_block },
        .{ .name = "beacon_aggregate_and_proof", .topic_type = .beacon_aggregate_and_proof },
        .{ .name = "voluntary_exit", .topic_type = .voluntary_exit },
        .{ .name = "proposer_slashing", .topic_type = .proposer_slashing },
        .{ .name = "attester_slashing", .topic_type = .attester_slashing },
        .{ .name = "bls_to_execution_change", .topic_type = .bls_to_execution_change },
        .{ .name = "sync_committee_contribution_and_proof", .topic_type = .sync_committee_contribution_and_proof },
    };

    for (exact_topics) |entry| {
        if (std.mem.eql(u8, name, entry.name)) {
            return .{
                .fork_digest = fork_digest,
                .topic_type = entry.topic_type,
                .subnet_id = null,
            };
        }
    }

    // Try subnet-indexed topics: `<base_name>_<subnet_id>`
    const subnet_topics = [_]struct { prefix: []const u8, topic_type: GossipTopicType, max_subnet: u8 }{
        .{ .prefix = "beacon_attestation_", .topic_type = .beacon_attestation, .max_subnet = MAX_ATTESTATION_SUBNET_ID },
        .{ .prefix = "sync_committee_", .topic_type = .sync_committee, .max_subnet = MAX_SYNC_COMMITTEE_SUBNET_ID },
        .{ .prefix = "blob_sidecar_", .topic_type = .blob_sidecar, .max_subnet = MAX_BLOB_SIDECAR_SUBNET_ID },
    };

    for (subnet_topics) |entry| {
        if (std.mem.startsWith(u8, name, entry.prefix)) {
            const subnet_str = name[entry.prefix.len..];
            const subnet_id = std.fmt.parseInt(u8, subnet_str, 10) catch return error.InvalidSubnetId;
            if (subnet_id >= entry.max_subnet) return error.InvalidSubnetId;
            return .{
                .fork_digest = fork_digest,
                .topic_type = entry.topic_type,
                .subnet_id = subnet_id,
            };
        }
    }

    return error.UnknownTopicName;
}

/// Format a gossip topic into its wire-format string.
///
/// For subnet-indexed topics, `subnet_id` must be provided.
/// Returns a slice from the provided buffer.
pub fn formatTopic(buf: []u8, fork_digest: [4]u8, topic_type: GossipTopicType, subnet_id: ?u8) []const u8 {
    if (topic_type.isSubnetIndexed()) {
        std.debug.assert(subnet_id != null);
        return std.fmt.bufPrint(buf, "{s}{x}/{s}_{d}/{s}", .{
            TOPIC_PREFIX,
            fork_digest[0..],
            topic_type.topicName(),
            subnet_id.?,
            ENCODING_SUFFIX,
        }) catch unreachable;
    } else {
        return std.fmt.bufPrint(buf, "{s}{x}/{s}/{s}", .{
            TOPIC_PREFIX,
            fork_digest[0..],
            topic_type.topicName(),
            ENCODING_SUFFIX,
        }) catch unreachable;
    }
}

/// Maximum buffer size needed for `formatTopic`.
/// `/eth2/` (6) + digest_hex (8) + `/` (1) + longest_topic (39) + `_` (1) + subnet (max 2 digits) + `/` (1) + `ssz_snappy` (10) = ~68
pub const MAX_TOPIC_LENGTH = 128;

// === Tests ===

test "parse well-formed beacon_block topic" {
    const topic_str = "/eth2/deadbeef/beacon_block/ssz_snappy";
    const parsed = parseTopic(topic_str) orelse return error.TestFailed;

    try testing.expectEqual(GossipTopicType.beacon_block, parsed.topic_type);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xde, 0xad, 0xbe, 0xef }, &parsed.fork_digest);
    try testing.expectEqual(@as(?u8, null), parsed.subnet_id);
}

test "parse beacon_attestation with subnet_id" {
    const topic_str = "/eth2/aabbccdd/beacon_attestation_42/ssz_snappy";
    const parsed = parseTopic(topic_str) orelse return error.TestFailed;

    try testing.expectEqual(GossipTopicType.beacon_attestation, parsed.topic_type);
    try testing.expectEqual(@as(?u8, 42), parsed.subnet_id);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xaa, 0xbb, 0xcc, 0xdd }, &parsed.fork_digest);
}

test "parse sync_committee with subnet_id" {
    const topic_str = "/eth2/11223344/sync_committee_3/ssz_snappy";
    const parsed = parseTopic(topic_str) orelse return error.TestFailed;

    try testing.expectEqual(GossipTopicType.sync_committee, parsed.topic_type);
    try testing.expectEqual(@as(?u8, 3), parsed.subnet_id);
}

test "parse blob_sidecar with subnet_id" {
    const topic_str = "/eth2/11223344/blob_sidecar_5/ssz_snappy";
    const parsed = parseTopic(topic_str) orelse return error.TestFailed;

    try testing.expectEqual(GossipTopicType.blob_sidecar, parsed.topic_type);
    try testing.expectEqual(@as(?u8, 5), parsed.subnet_id);
}

test "parse all non-subnet topic types" {
    const fork_hex = "deadbeef";
    const topics = [_]struct { name: []const u8, expected: GossipTopicType }{
        .{ .name = "beacon_block", .expected = .beacon_block },
        .{ .name = "beacon_aggregate_and_proof", .expected = .beacon_aggregate_and_proof },
        .{ .name = "voluntary_exit", .expected = .voluntary_exit },
        .{ .name = "proposer_slashing", .expected = .proposer_slashing },
        .{ .name = "attester_slashing", .expected = .attester_slashing },
        .{ .name = "bls_to_execution_change", .expected = .bls_to_execution_change },
        .{ .name = "sync_committee_contribution_and_proof", .expected = .sync_committee_contribution_and_proof },
    };

    for (topics) |t| {
        var buf: [MAX_TOPIC_LENGTH]u8 = undefined;
        const topic_str = std.fmt.bufPrint(&buf, "/eth2/{s}/{s}/ssz_snappy", .{ fork_hex, t.name }) catch unreachable;
        const parsed = parseTopic(topic_str) orelse {
            std.debug.print("Failed to parse topic: {s}\n", .{t.name});
            return error.TestFailed;
        };
        try testing.expectEqual(t.expected, parsed.topic_type);
    }
}

test "reject malformed topics" {
    // Missing prefix.
    try testing.expectEqual(@as(?GossipTopic, null), parseTopic("beacon_block/ssz_snappy"));
    // Wrong prefix.
    try testing.expectEqual(@as(?GossipTopic, null), parseTopic("/eth3/deadbeef/beacon_block/ssz_snappy"));
    // Too short fork digest.
    try testing.expectEqual(@as(?GossipTopic, null), parseTopic("/eth2/dead/beacon_block/ssz_snappy"));
    // Invalid hex in fork digest.
    try testing.expectEqual(@as(?GossipTopic, null), parseTopic("/eth2/zzzzzzzz/beacon_block/ssz_snappy"));
    // Unknown topic name.
    try testing.expectEqual(@as(?GossipTopic, null), parseTopic("/eth2/deadbeef/unknown_topic/ssz_snappy"));
    // Wrong encoding.
    try testing.expectEqual(@as(?GossipTopic, null), parseTopic("/eth2/deadbeef/beacon_block/ssz"));
    // Missing segments.
    try testing.expectEqual(@as(?GossipTopic, null), parseTopic("/eth2/deadbeef"));
    // Empty string.
    try testing.expectEqual(@as(?GossipTopic, null), parseTopic(""));
}

test "reject invalid subnet ids" {
    // Subnet ID out of range for attestation (>= 64).
    try testing.expectEqual(@as(?GossipTopic, null), parseTopic("/eth2/deadbeef/beacon_attestation_64/ssz_snappy"));
    // Subnet ID out of range for sync committee (>= 4).
    try testing.expectEqual(@as(?GossipTopic, null), parseTopic("/eth2/deadbeef/sync_committee_4/ssz_snappy"));
    // Non-numeric subnet ID.
    try testing.expectEqual(@as(?GossipTopic, null), parseTopic("/eth2/deadbeef/beacon_attestation_abc/ssz_snappy"));
}

test "formatTopic roundtrip for non-subnet topic" {
    const fork_digest = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    var buf: [MAX_TOPIC_LENGTH]u8 = undefined;
    const formatted = formatTopic(&buf, fork_digest, .beacon_block, null);

    try testing.expectEqualStrings("/eth2/deadbeef/beacon_block/ssz_snappy", formatted);

    // Parse the formatted string back.
    const parsed = parseTopic(formatted) orelse return error.TestFailed;
    try testing.expectEqual(GossipTopicType.beacon_block, parsed.topic_type);
    try testing.expectEqualSlices(u8, &fork_digest, &parsed.fork_digest);
    try testing.expectEqual(@as(?u8, null), parsed.subnet_id);
}

test "formatTopic roundtrip for subnet topic" {
    const fork_digest = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    var buf: [MAX_TOPIC_LENGTH]u8 = undefined;
    const formatted = formatTopic(&buf, fork_digest, .beacon_attestation, 42);

    try testing.expectEqualStrings("/eth2/aabbccdd/beacon_attestation_42/ssz_snappy", formatted);

    const parsed = parseTopic(formatted) orelse return error.TestFailed;
    try testing.expectEqual(GossipTopicType.beacon_attestation, parsed.topic_type);
    try testing.expectEqual(@as(?u8, 42), parsed.subnet_id);
}
