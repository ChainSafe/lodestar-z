const std = @import("std");
const consensus = @import("constants");
const preset = @import("preset");
const topic_mod = @import("topic.zig");

/// The gossip topic names a Fulu node speaks, per the consensus p2p-interface.
/// `build` in topic.zig turns a name plus a fork digest into the wire string
/// `/eth2/<digest>/<name>/ssz_snappy`; a host subscribes to the ones it needs.
pub const beacon_block = "beacon_block";
pub const beacon_aggregate_and_proof = "beacon_aggregate_and_proof";
pub const voluntary_exit = "voluntary_exit";
pub const proposer_slashing = "proposer_slashing";
pub const attester_slashing = "attester_slashing";
pub const bls_to_execution_change = "bls_to_execution_change";
pub const sync_committee_contribution_and_proof = "sync_committee_contribution_and_proof";
pub const light_client_finality_update = "light_client_finality_update";
pub const light_client_optimistic_update = "light_client_optimistic_update";

pub const attestation_subnet_count = consensus.ATTESTATION_SUBNET_COUNT;
pub const sync_committee_subnet_count = consensus.SYNC_COMMITTEE_SUBNET_COUNT;
pub const data_column_subnet_count = preset.NUMBER_OF_COLUMNS;

/// Writes `beacon_attestation_<subnet>` into `out` and returns it.
pub fn attestationSubnet(subnet: u64, out: []u8) []const u8 {
    return subnetName("beacon_attestation_", subnet, out);
}

pub fn syncCommitteeSubnet(subnet: u64, out: []u8) []const u8 {
    return subnetName("sync_committee_", subnet, out);
}

pub fn dataColumnSubnet(subnet: u64, out: []u8) []const u8 {
    return subnetName("data_column_sidecar_", subnet, out);
}

fn subnetName(comptime name_prefix: []const u8, subnet: u64, out: []u8) []const u8 {
    return std.fmt.bufPrint(out, "{s}{d}", .{ name_prefix, subnet }) catch unreachable;
}

test "topic names build valid topic strings and subnet names format" {
    const digest = topic_mod.ForkDigest{ 0x6a, 0x95, 0xa1, 0xa9 };
    var buf: [topic_mod.topic_max_len]u8 = undefined;
    const names = [_][]const u8{
        beacon_block,
        beacon_aggregate_and_proof,
        voluntary_exit,
        proposer_slashing,
        attester_slashing,
        bls_to_execution_change,
        sync_committee_contribution_and_proof,
        light_client_finality_update,
        light_client_optimistic_update,
    };
    for (names) |topic_name| {
        const built = topic_mod.build(digest, topic_name, &buf);
        try std.testing.expectEqualStrings(topic_name, topic_mod.parse(built).?.name);
    }

    var name: [topic_mod.name_max_len]u8 = undefined;
    try std.testing.expectEqualStrings("beacon_attestation_63", attestationSubnet(63, &name));
    try std.testing.expectEqualStrings("data_column_sidecar_127", dataColumnSubnet(127, &name));
    var topic_buf: [topic_mod.topic_max_len]u8 = undefined;
    const columns = topic_mod.build(digest, dataColumnSubnet(127, &name), &topic_buf);
    try std.testing.expectEqualStrings("data_column_sidecar_127", topic_mod.parse(columns).?.name);
}
