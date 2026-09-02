const std = @import("std");
const enr = @import("identity/enr.zig");
const protocol = @import("protocol.zig");
const routing = @import("routing.zig");
const types = @import("types.zig");

test "routing table revalidates the least recent entry before replacement" {
    const local_id = [_]u8{0} ** 32;
    var table: routing.Table = undefined;
    try table.init(std.testing.allocator, local_id);
    defer table.deinit();

    var ids: [routing.bucket_size + 2]types.NodeId = undefined;
    for (0..routing.bucket_size) |index| {
        ids[index] = nodeAtDistance(256, @intCast(index + 1));
        const address = address4(10, @intCast(index + 1), 0, 1, @intCast(9_000 + index));
        var record = makeRecord(ids[index], address, 1);
        const peer = types.Endpoint{ .node_id = ids[index], .address = address };
        try std.testing.expectEqual(
            routing.PutResult.inserted,
            try table.upsertVerified(&peer, &record, @intCast(index)),
        );
    }
    try std.testing.expectEqual(routing.bucket_size, table.count());

    ids[routing.bucket_size] = nodeAtDistance(256, 17);
    const candidate_address = address4(10, 17, 0, 1, 9_017);
    var candidate_record = makeRecord(ids[routing.bucket_size], candidate_address, 1);
    const candidate_peer = types.Endpoint{
        .node_id = ids[routing.bucket_size],
        .address = candidate_address,
    };
    const first_pending = try table.upsertVerified(&candidate_peer, &candidate_record, 20);
    try expectPending(first_pending, &ids[0]);
    try std.testing.expectEqual(@as(usize, 1), table.pendingCount());
    const first_target = table.revalidationTarget().?;
    try std.testing.expectEqualSlices(u8, &ids[0], &first_target.peer.node_id);

    var first_record = makeRecord(ids[0], address4(10, 1, 0, 1, 9_000), 1);
    const first_peer = types.Endpoint{ .node_id = ids[0], .address = first_record.endpoint().? };
    try std.testing.expectEqual(
        routing.PutResult.refreshed,
        try table.upsertVerified(&first_peer, &first_record, 21),
    );
    try std.testing.expectEqual(@as(usize, 0), table.pendingCount());
    try std.testing.expect(table.revalidationTarget() == null);

    const second_pending = try table.upsertVerified(&candidate_peer, &candidate_record, 22);
    try expectPending(second_pending, &ids[1]);
    ids[routing.bucket_size + 1] = nodeAtDistance(256, 18);
    const busy_address = address4(10, 18, 0, 1, 9_018);
    var busy_record = makeRecord(ids[routing.bucket_size + 1], busy_address, 1);
    const busy_peer = types.Endpoint{
        .node_id = ids[routing.bucket_size + 1],
        .address = busy_address,
    };
    try std.testing.expectEqual(
        routing.PutResult.pending_busy,
        try table.upsertVerified(&busy_peer, &busy_record, 23),
    );

    try std.testing.expectEqual(
        routing.ResolveResult.retained,
        try table.resolveRevalidation(&ids[1], true, 24),
    );
    const third_pending = try table.upsertVerified(&candidate_peer, &candidate_record, 25);
    try expectPending(third_pending, &ids[2]);
    candidate_record.sequence = 2;
    const updated_pending = try table.upsertVerified(&candidate_peer, &candidate_record, 26);
    try expectPending(updated_pending, &ids[2]);
    const resolution = try table.resolveRevalidation(&ids[2], false, 27);
    switch (resolution) {
        .replaced => |node_id| try std.testing.expectEqualSlices(
            u8,
            &ids[routing.bucket_size],
            &node_id,
        ),
        .retained => return error.TestUnexpectedResult,
    }
    try std.testing.expect(!table.contains(&ids[2]));
    try std.testing.expect(table.contains(&ids[routing.bucket_size]));
    try std.testing.expectEqual(@as(u64, 2), table.get(&ids[routing.bucket_size]).?.record.sequence);
    try std.testing.expectEqual(routing.bucket_size, table.count());
    try std.testing.expectError(
        routing.Error.NoPendingRevalidation,
        table.resolveRevalidation(&ids[2], false, 28),
    );
}

test "routing table enforces bucket and table subnet limits" {
    const local_id = [_]u8{0} ** 32;
    var table: routing.Table = undefined;
    try table.init(std.testing.allocator, local_id);
    defer table.deinit();

    for (1..routing.bucket_subnet_limit + 1) |salt| {
        const node_id = nodeAtDistance(256, @intCast(salt));
        const address = address4(192, 0, 2, @intCast(salt), @intCast(9_000 + salt));
        var record = makeRecord(node_id, address, 1);
        const peer = types.Endpoint{ .node_id = node_id, .address = address };
        _ = try table.upsertVerified(&peer, &record, 1);
    }
    const rejected_id = nodeAtDistance(256, 3);
    const rejected_address = address4(192, 0, 2, 3, 9_003);
    var rejected_record = makeRecord(rejected_id, rejected_address, 1);
    const rejected_peer = types.Endpoint{
        .node_id = rejected_id,
        .address = rejected_address,
    };
    try std.testing.expectError(
        routing.Error.AddressLimit,
        table.upsertVerified(&rejected_peer, &rejected_record, 1),
    );

    var other_table: routing.Table = undefined;
    try other_table.init(std.testing.allocator, local_id);
    defer other_table.deinit();
    for (0..routing.table_subnet_limit) |index| {
        const node_id = nodeAtDistance(@intCast(241 + index), @intCast(index + 1));
        const address = address4(198, 51, 100, @intCast(index + 1), @intCast(10_000 + index));
        var record = makeRecord(node_id, address, 1);
        const peer = types.Endpoint{ .node_id = node_id, .address = address };
        _ = try other_table.upsertVerified(&peer, &record, 1);
    }
    const table_rejected_id = nodeAtDistance(251, 11);
    const table_rejected_address = address4(198, 51, 100, 11, 10_011);
    var table_rejected_record = makeRecord(table_rejected_id, table_rejected_address, 1);
    const table_rejected_peer = types.Endpoint{
        .node_id = table_rejected_id,
        .address = table_rejected_address,
    };
    try std.testing.expectError(
        routing.Error.AddressLimit,
        other_table.upsertVerified(&table_rejected_peer, &table_rejected_record, 1),
    );
}

test "routing table compresses distances one through 240 into one bucket" {
    const local_id = [_]u8{0} ** 32;
    var table: routing.Table = undefined;
    try table.init(std.testing.allocator, local_id);
    defer table.deinit();

    var oldest: types.NodeId = undefined;
    for (0..routing.bucket_size) |index| {
        const distance: u16 = @intCast(225 + index);
        const node_id = nodeAtDistance(distance, @intCast(index + 1));
        if (index == 0) oldest = node_id;
        const address = address4(10, @intCast(index + 1), 1, 1, @intCast(11_000 + index));
        var record = makeRecord(node_id, address, 1);
        const peer = types.Endpoint{ .node_id = node_id, .address = address };
        try std.testing.expectEqual(
            routing.PutResult.inserted,
            try table.upsertVerified(&peer, &record, 1),
        );
    }
    const candidate_id = nodeAtDistance(224, 17);
    const candidate_address = address4(10, 17, 1, 1, 11_017);
    var candidate_record = makeRecord(candidate_id, candidate_address, 1);
    const candidate_peer = types.Endpoint{
        .node_id = candidate_id,
        .address = candidate_address,
    };
    try expectPending(
        try table.upsertVerified(&candidate_peer, &candidate_record, 2),
        &oldest,
    );
}

test "routing table applies ENR updates atomically and ignores stale endpoints" {
    const local_id = [_]u8{0} ** 32;
    var table: routing.Table = undefined;
    try table.init(std.testing.allocator, local_id);
    defer table.deinit();

    const node_id = nodeAtDistance(256, 1);
    const original_address = address4(203, 0, 113, 1, 9_000);
    var original_record = makeRecord(node_id, original_address, 2);
    const original_peer = types.Endpoint{ .node_id = node_id, .address = original_address };
    _ = try table.upsertVerified(&original_peer, &original_record, 1);

    const stale_address = address4(198, 51, 100, 1, 9_001);
    var stale_record = makeRecord(node_id, stale_address, 1);
    const stale_peer = types.Endpoint{ .node_id = node_id, .address = stale_address };
    try std.testing.expectEqual(
        routing.PutResult.refreshed,
        try table.upsertVerified(&stale_peer, &stale_record, 2),
    );
    try std.testing.expect(std.meta.eql(
        original_address,
        table.get(&node_id).?.peer.address,
    ));

    var updated_record = makeRecord(node_id, stale_address, 3);
    try std.testing.expectEqual(
        routing.PutResult.updated,
        try table.upsertVerified(&stale_peer, &updated_record, 3),
    );
    const updated = table.get(&node_id).?;
    try std.testing.expect(std.meta.eql(stale_address, updated.peer.address));
    try std.testing.expectEqual(@as(u64, 3), updated.record.sequence);
}

test "routing table applies subnet limits to IPv6 prefixes" {
    const local_id = [_]u8{0} ** 32;
    var table: routing.Table = undefined;
    try table.init(std.testing.allocator, local_id);
    defer table.deinit();

    for (1..routing.bucket_subnet_limit + 1) |salt| {
        const node_id = nodeAtDistance(256, @intCast(salt));
        var octets = [_]u8{0} ** 16;
        octets[0..8].* = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 1 };
        octets[15] = @intCast(salt);
        const address = types.Address{ .ip6 = .{
            .octets = octets,
            .port = @intCast(9_000 + salt),
        } };
        var record = makeRecord(node_id, address, 1);
        const peer = types.Endpoint{ .node_id = node_id, .address = address };
        _ = try table.upsertVerified(&peer, &record, 1);
    }
    const rejected_id = nodeAtDistance(256, 3);
    var rejected_octets = [_]u8{0} ** 16;
    rejected_octets[0..8].* = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 1 };
    rejected_octets[15] = 3;
    const rejected_address = types.Address{ .ip6 = .{
        .octets = rejected_octets,
        .port = 9_003,
    } };
    var rejected_record = makeRecord(rejected_id, rejected_address, 1);
    const rejected_peer = types.Endpoint{
        .node_id = rejected_id,
        .address = rejected_address,
    };
    try std.testing.expectError(
        routing.Error.AddressLimit,
        table.upsertVerified(&rejected_peer, &rejected_record, 1),
    );
}

test "routing FINDNODE selection filters exact distances and caps the aggregate" {
    const local_id = [_]u8{0} ** 32;
    var table: routing.Table = undefined;
    try table.init(std.testing.allocator, local_id);
    defer table.deinit();

    var local_record = makeRecord(local_id, address4(127, 0, 0, 1, 9_000), 1);
    for (0..routing.bucket_size) |index| {
        const node_id = nodeAtDistance(256, @intCast(index + 1));
        const address = address4(10, @intCast(index + 1), 0, 1, @intCast(9_001 + index));
        var record = makeRecord(node_id, address, 1);
        const peer = types.Endpoint{ .node_id = node_id, .address = address };
        _ = try table.upsertVerified(&peer, &record, 1);
    }
    const distance_241_id = nodeAtDistance(241, 1);
    const distance_241_address = address4(172, 16, 1, 1, 10_001);
    var distance_241_record = makeRecord(distance_241_id, distance_241_address, 1);
    const distance_241_peer = types.Endpoint{
        .node_id = distance_241_id,
        .address = distance_241_address,
    };
    _ = try table.upsertVerified(&distance_241_peer, &distance_241_record, 1);

    var out: [protocol.findnode_result_max + 4]enr.Record = undefined;
    const selected = try table.findNodes(&local_record, null, &.{ 0, 241, 241, 256 }, &out);
    try std.testing.expectEqual(protocol.findnode_result_max, selected.len);
    try std.testing.expectEqualSlices(u8, &local_id, &selected[0].node_id);
    try std.testing.expectEqualSlices(u8, &distance_241_id, &selected[1].node_id);
    for (selected[2..]) |record| {
        try std.testing.expectEqual(@as(u16, 256), types.logDistance(&local_id, &record.node_id));
    }
    const sparse = try table.findNodes(&local_record, null, &.{241}, &out);
    try std.testing.expectEqual(@as(usize, 1), sparse.len);
    try std.testing.expectEqualSlices(u8, &distance_241_id, &sparse[0].node_id);

    try std.testing.expectError(
        routing.Error.InvalidDistance,
        table.findNodes(&local_record, null, &.{ 0, 257 }, &out),
    );
    var too_many = [_]u16{0} ** (protocol.distance_count + 1);
    try std.testing.expectError(
        routing.Error.TooManyDistances,
        table.findNodes(&local_record, null, &too_many, &out),
    );
}

test "routing closest selection is sorted and bounded" {
    const local_id = [_]u8{0} ** 32;
    var table: routing.Table = undefined;
    try table.init(std.testing.allocator, local_id);
    defer table.deinit();

    for (0..routing.bucket_size + 2) |index| {
        const distance: u16 = @intCast(239 + index);
        const node_id = nodeAtDistance(distance, @intCast(index + 1));
        const address = address4(10, @intCast(index + 1), 2, 1, @intCast(12_000 + index));
        var record = makeRecord(node_id, address, 1);
        const peer = types.Endpoint{ .node_id = node_id, .address = address };
        _ = try table.upsertVerified(&peer, &record, 1);
    }

    var out: [routing.bucket_size + 4]routing.Entry = undefined;
    const selected = table.closest(&local_id, &out);
    try std.testing.expectEqual(routing.bucket_size, selected.len);
    for (selected[1..], selected[0 .. selected.len - 1]) |entry, previous| {
        try std.testing.expect(std.mem.order(
            u8,
            &previous.peer.node_id,
            &entry.peer.node_id,
        ) == .lt);
    }
    try std.testing.expectEqual(@as(u16, 239), types.logDistance(
        &local_id,
        &selected[0].peer.node_id,
    ));
    try std.testing.expectEqual(@as(u16, 254), types.logDistance(
        &local_id,
        &selected[selected.len - 1].peer.node_id,
    ));
}

test "routing FINDNODE does not relay special-scope addresses" {
    const local_id = [_]u8{0} ** 32;
    var table: routing.Table = undefined;
    try table.init(std.testing.allocator, local_id);
    defer table.deinit();

    var local_record = makeRecord(local_id, address4(127, 0, 0, 1, 9_000), 1);
    const private_id = nodeAtDistance(256, 1);
    const private_address = address4(10, 0, 0, 1, 9_001);
    var private_record = makeRecord(private_id, private_address, 1);
    const private_peer = types.Endpoint{ .node_id = private_id, .address = private_address };
    _ = try table.upsertVerified(&private_peer, &private_record, 1);
    const public_id = nodeAtDistance(255, 2);
    const public_address = address4(198, 51, 100, 1, 9_002);
    var public_record = makeRecord(public_id, public_address, 1);
    const public_peer = types.Endpoint{ .node_id = public_id, .address = public_address };
    _ = try table.upsertVerified(&public_peer, &public_record, 1);

    var out: [3]enr.Record = undefined;
    const selected = try table.findNodes(
        &local_record,
        address4(203, 0, 113, 1, 9_003),
        &.{ 0, 255, 256 },
        &out,
    );
    try std.testing.expectEqual(@as(usize, 1), selected.len);
    try std.testing.expectEqual(public_id, selected[0].node_id);
}

test "routing table rejects inconsistent records and unusable endpoints" {
    const local_id = [_]u8{0} ** 32;
    var table: routing.Table = undefined;
    try table.init(std.testing.allocator, local_id);
    defer table.deinit();

    const remote_id = nodeAtDistance(256, 1);
    const address = address4(203, 0, 113, 1, 9_000);
    var record = makeRecord(remote_id, address, 1);
    var peer = types.Endpoint{ .node_id = local_id, .address = address };
    try std.testing.expectError(
        routing.Error.SelfEntry,
        table.upsertVerified(&peer, &record, 1),
    );

    peer.node_id = remote_id;
    record.node_id = nodeAtDistance(255, 2);
    try std.testing.expectError(
        routing.Error.InvalidRemoteRecord,
        table.upsertVerified(&peer, &record, 1),
    );
    record.node_id = remote_id;
    peer.address = address4(203, 0, 113, 2, 9_000);
    try std.testing.expectError(
        routing.Error.InvalidRemoteRecord,
        table.upsertVerified(&peer, &record, 1),
    );
    peer.address = address4(203, 0, 113, 1, 0);
    record.udp = 0;
    try std.testing.expectError(
        routing.Error.InvalidRemoteRecord,
        table.upsertVerified(&peer, &record, 1),
    );
}

fn expectPending(result: routing.PutResult, expected: *const types.NodeId) !void {
    switch (result) {
        .pending => |node_id| try std.testing.expectEqualSlices(u8, expected, &node_id),
        else => return error.TestUnexpectedResult,
    }
}

fn nodeAtDistance(distance: u16, salt: u8) types.NodeId {
    std.debug.assert(distance > 8 and distance <= protocol.distance_max);
    var node_id = [_]u8{0} ** 32;
    const leading_index = protocol.distance_max - distance;
    const byte_index = leading_index / 8;
    const bit_index: u3 = @intCast(7 - leading_index % 8);
    node_id[byte_index] = @as(u8, 1) << bit_index;
    node_id[31] = salt;
    return node_id;
}

fn address4(a: u8, b: u8, c: u8, d: u8, port: u16) types.Address {
    return .{ .ip4 = .{ .octets = .{ a, b, c, d }, .port = port } };
}

fn makeRecord(node_id: types.NodeId, address: types.Address, sequence: u64) enr.Record {
    var record = std.mem.zeroes(enr.Record);
    record.node_id = node_id;
    record.sequence = sequence;
    switch (address) {
        .ip4 => |value| {
            record.ip4 = value.octets;
            record.udp = value.port;
        },
        .ip6 => |value| {
            record.ip6 = value.octets;
            record.udp6 = value.port;
        },
    }
    return record;
}

test "relay policy does not cross special address scopes" {
    const public = address4(203, 0, 113, 1, 9_000);
    const other_public = address4(198, 51, 100, 1, 9_000);
    const private = address4(10, 0, 0, 1, 9_000);
    const other_private = address4(192, 168, 1, 1, 9_000);
    const loopback = address4(127, 0, 0, 1, 9_000);
    const unspecified = address4(0, 0, 0, 0, 9_000);
    try std.testing.expect(routing.relayAllowed(public, other_public));
    try std.testing.expect(!routing.relayAllowed(public, private));
    try std.testing.expect(routing.relayAllowed(private, other_private));
    try std.testing.expect(routing.relayAllowed(loopback, loopback));
    try std.testing.expect(!routing.relayAllowed(private, loopback));
    try std.testing.expect(!routing.relayAllowed(public, unspecified));

    const public6 = address6(.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });
    const private6 = address6(.{ 0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });
    const other_private6 = address6(.{ 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 });
    const multicast6 = address6(.{ 0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });
    try std.testing.expect(!routing.relayAllowed(public6, private6));
    try std.testing.expect(routing.relayAllowed(private6, other_private6));
    try std.testing.expect(!routing.relayAllowed(private, private6));
    try std.testing.expect(!routing.relayAllowed(public6, multicast6));
}

fn address6(octets: [16]u8) types.Address {
    return .{ .ip6 = .{ .octets = octets, .port = 9_000 } };
}
