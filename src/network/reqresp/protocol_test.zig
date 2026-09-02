const std = @import("std");
const constants = @import("constants.zig");
const consensus = @import("constants");
const ct = @import("consensus_types");
const preset = @import("preset");
const protocol = @import("protocol.zig");

const Protocol = protocol.Protocol;

test "protocol ids follow the specification form and round trip" {
    try std.testing.expectEqualStrings("/eth2/beacon_chain/req/status/1/ssz_snappy", Protocol.status_v1.id());
    try std.testing.expectEqualStrings("/eth2/beacon_chain/req/status/2/ssz_snappy", Protocol.status_v2.id());
    try std.testing.expectEqualStrings("/eth2/beacon_chain/req/goodbye/1/ssz_snappy", Protocol.goodbye_v1.id());
    try std.testing.expectEqualStrings("/eth2/beacon_chain/req/ping/1/ssz_snappy", Protocol.ping_v1.id());
    try std.testing.expectEqualStrings("/eth2/beacon_chain/req/metadata/3/ssz_snappy", Protocol.metadata_v3.id());
    try std.testing.expectEqualStrings(
        "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy",
        Protocol.blocks_by_range_v2.id(),
    );
    try std.testing.expectEqualStrings(
        "/eth2/beacon_chain/req/data_column_sidecars_by_root/1/ssz_snappy",
        Protocol.data_column_sidecars_by_root_v1.id(),
    );
    inline for (@typeInfo(Protocol).@"enum".fields) |field| {
        const value: Protocol = @enumFromInt(field.value);
        try std.testing.expectEqual(value, Protocol.fromId(value.id()).?);
        try std.testing.expectEqualStrings(value.id(), protocol.ids[field.value]);
    }
    try std.testing.expect(Protocol.fromId("/eth2/beacon_chain/req/status/3/ssz_snappy") == null);
    try std.testing.expect(Protocol.fromId("/eth2/beacon_chain/req/status/1/ssz") == null);
    try std.testing.expect(Protocol.fromId("/eth2/beacon_chain/req/beacon_blocks_by_range/1/ssz_snappy") == null);
    try std.testing.expect(Protocol.fromId("") == null);
}

test "protocol info sizes follow the consensus types" {
    const status = Protocol.status_v1.info();
    try std.testing.expectEqual(@as(usize, 84), status.request_min);
    try std.testing.expectEqual(@as(usize, 84), status.response_max);
    try std.testing.expect(!status.context_bytes);
    try std.testing.expectEqual(@as(u32, 1), status.chunks_max);
    try std.testing.expectEqual(@as(usize, 92), Protocol.status_v2.info().request_max);
    try std.testing.expectEqual(@as(usize, 0), Protocol.metadata_v2.info().request_max);
    try std.testing.expectEqual(@as(usize, 17), Protocol.metadata_v2.info().response_max);
    try std.testing.expectEqual(@as(usize, 25), Protocol.metadata_v3.info().response_max);

    const blocks = Protocol.blocks_by_range_v2.info();
    try std.testing.expectEqual(@as(usize, 24), blocks.request_max);
    try std.testing.expectEqual(constants.MAX_PAYLOAD_SIZE, blocks.response_max);
    try std.testing.expectEqual(ct.phase0.SignedBeaconBlock.min_size, blocks.response_min);
    try std.testing.expect(blocks.context_bytes);
    try std.testing.expectEqual(@as(u32, consensus.MAX_REQUEST_BLOCKS_DENEB), blocks.chunks_max);
    try std.testing.expectEqual(@as(u32, 128), blocks.quota_tokens);
    try std.testing.expectEqual(@as(usize, 32 * consensus.MAX_REQUEST_BLOCKS_DENEB), Protocol.blocks_by_root_v2.info().request_max);
    try std.testing.expectEqual(ct.deneb.BlobSidecar.fixed_size, Protocol.blob_sidecars_by_root_v1.info().response_min);
    try std.testing.expectEqual(@as(u32, preset.MAX_REQUEST_DATA_COLUMN_SIDECARS), Protocol.data_column_sidecars_by_range_v1.info().chunks_max);
    try std.testing.expectEqual(protocol.requestMaxAll(), Protocol.blob_sidecars_by_root_v1.info().request_max);
    try std.testing.expectEqual(constants.MAX_PAYLOAD_SIZE, protocol.responseMaxAll());
}

test "protocol request weights follow counts and list lengths" {
    var by_range: [24]u8 = undefined;
    const request = ct.phase0.BeaconBlocksByRangeRequest.Type{ .start_slot = 100, .count = 5, .step = 1 };
    _ = ct.phase0.BeaconBlocksByRangeRequest.serializeIntoBytes(&request, &by_range);
    try std.testing.expectEqual(@as(u32, 5), Protocol.blocks_by_range_v2.requestWeight(&by_range));

    const huge = ct.phase0.BeaconBlocksByRangeRequest.Type{ .start_slot = 0, .count = 100_000, .step = 1 };
    _ = ct.phase0.BeaconBlocksByRangeRequest.serializeIntoBytes(&huge, &by_range);
    try std.testing.expectEqual(@as(u32, consensus.MAX_REQUEST_BLOCKS_DENEB), Protocol.blocks_by_range_v2.requestWeight(&by_range));

    const roots = [_]u8{7} ** 96;
    try std.testing.expectEqual(@as(u32, 3), Protocol.blocks_by_root_v2.requestWeight(&roots));
    try std.testing.expectEqual(@as(u32, 1), Protocol.blocks_by_root_v2.requestWeight(roots[0..0]));

    const ids = [_]u8{1} ** 80;
    try std.testing.expectEqual(@as(u32, 2), Protocol.blob_sidecars_by_root_v1.requestWeight(&ids));

    var columns_by_range: [20 + 4 * 8]u8 = undefined;
    std.mem.writeInt(u64, columns_by_range[0..8], 9, .little);
    std.mem.writeInt(u64, columns_by_range[8..16], 2, .little);
    std.mem.writeInt(u32, columns_by_range[16..20], 20, .little);
    for (0..4) |column| std.mem.writeInt(u64, columns_by_range[20 + column * 8 ..][0..8], column, .little);
    try std.testing.expectEqual(@as(u32, 8), Protocol.data_column_sidecars_by_range_v1.requestWeight(&columns_by_range));

    var columns_by_root: [8 + 2 * 36 + 3 * 8]u8 = undefined;
    std.mem.writeInt(u32, columns_by_root[0..4], 8, .little);
    std.mem.writeInt(u32, columns_by_root[4..8], 8 + 36 + 8, .little);
    @memset(columns_by_root[8..], 0);
    std.mem.writeInt(u32, columns_by_root[8 + 32 ..][0..4], 36, .little);
    std.mem.writeInt(u32, columns_by_root[8 + 36 + 8 + 32 ..][0..4], 36, .little);
    try std.testing.expectEqual(@as(u32, 3), Protocol.data_column_sidecars_by_root_v1.requestWeight(&columns_by_root));

    try std.testing.expectEqual(@as(u32, 1), Protocol.ping_v1.requestWeight(&[_]u8{0} ** 8));
}
