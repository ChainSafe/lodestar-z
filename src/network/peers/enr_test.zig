const std = @import("std");
const d = @import("discv5");
const adapter = @import("enr.zig");
const types = @import("types.zig");
const vectors = @import("enr_vectors.zig").vectors;
const context = types.ForkContext{ .digest = .{ 1, 2, 3, 4 }, .custody_groups = 128 };

test "peer ENR independent signed Ethereum fields and same-key identity" {
    inline for (vectors, 0..) |fixture, index| {
        var record = try d.identity.enr.Record.initText(fixture.text);
        if (index == 3) {
            try std.testing.expectError(error.InvalidField, adapter.decode(&record, &context));
        } else if (index == 4 or index == 6) {
            try std.testing.expectError(error.InvalidField, adapter.decode(&record, &context));
        } else if (index == 7 or index == 8) {
            try std.testing.expectError(error.InvalidField, adapter.decode(&record, &context));
        } else if (index == 10) {
            try std.testing.expectError(error.IncompatibleFork, adapter.decode(&record, &context));
        } else {
            const candidate = try adapter.decode(&record, &context);
            const expected = try types.PeerId.fromText("16Uiu2HAm3cuhhRL2msUuLF62KRSfneFDx94RsuouyW25Ho42cFMq");
            try std.testing.expect(candidate.peer.eql(&expected));
            try std.testing.expectEqual(@as(u64, 7), candidate.sequence);
            try std.testing.expectEqual(@as(?u64, if (index == 5) 0 else 4), candidate.custody_group_count);
            try std.testing.expectEqual(@as(?u8, 5), candidate.syncnets);
            try std.testing.expectEqual(@as(u8, 0x80), candidate.attnets.?[7]);
            try std.testing.expectEqual(@as(u8, if (index == 2) 0 else if (index == 1) 2 else 1), candidate.address_count);
            if (index != 2) try std.testing.expectEqual(@as(u16, 9001), candidate.addresses[0].port());
            if (index == 1) try std.testing.expectEqual(@as(u16, 9101), candidate.addresses[1].port());
            record.bytes = @splat(0);
            try std.testing.expect(candidate.peer.eql(&expected));
        }
    }
}

fn signingKey() !d.identity.crypto.KeyPair {
    return d.identity.crypto.keyPairFromSecret(&(.{0} ** 31 ++ .{1}));
}

fn advertisement() adapter.LocalAdvertisement {
    return .{
        .fork = .{ .digest = .{ 1, 2, 3, 4 }, .next_version = .{ 5, 0, 0, 0 }, .next_epoch = std.math.maxInt(u64) },
        .ip4 = .{ 127, 0, 0, 1 },
        .udp = 9000,
        .quic = 9001,
        .next_fork_digest = .{ 9, 10, 11, 12 },
        .attnets = .{ 1, 0, 0, 0, 0, 0, 0, 128 },
        .syncnets = 5,
        .custody_group_count = 4,
    };
}

test "peer ENR mapped IPv6 projection preserves signed content and IPv4 fallback" {
    const key = try signingKey();
    var local = advertisement();
    const mapped = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff, 127, 0, 0, 2 };
    const original = try adapter.build(&key, 7, &local, &context);
    local.ip6 = mapped;
    local.udp6 = 9100;
    local.quic6 = 9101;
    try std.testing.expectError(error.InvalidField, adapter.build(&key, 7, &local, &context));
    const fields = [_]d.identity.enr.Field{
        .{ .key = "eth2", .value = .{ .raw = (try original.field("eth2")).? } },
        .{ .key = "id", .value = .{ .bytes = "v4" } },
        .{ .key = "ip", .value = .{ .bytes = &local.ip4.? } },
        .{ .key = "ip6", .value = .{ .bytes = &mapped } },
        .{ .key = "quic", .value = .{ .uint = local.quic.? } },
        .{ .key = "quic6", .value = .{ .uint = local.quic6.? } },
        .{ .key = "secp256k1", .value = .{ .bytes = &original.public_key } },
        .{ .key = "udp", .value = .{ .uint = local.udp.? } },
        .{ .key = "udp6", .value = .{ .uint = local.udp6.? } },
    };
    const record = try d.identity.enr.Record.createFields(&key, 7, &fields);
    const candidate = try adapter.decode(&record, &context);
    try std.testing.expectEqual(@as(u8, 1), candidate.address_count);
    try std.testing.expectEqualDeep(types.Address{ .ip4 = .{ .octets = local.ip4.?, .port = local.quic.? } }, candidate.addresses[0]);
    try std.testing.expectEqual(try record.contentHash(), candidate.record_hash);
    try std.testing.expectEqualSlices(u8, &mapped, (try record.fieldBytes("ip6")).?);
    const no_fallback = try d.identity.enr.Record.createFields(&key, 7, &(fields[0..2].* ++ fields[3..].*));
    try std.testing.expectEqual(@as(u8, 0), (try adapter.decode(&no_fallback, &context)).address_count);
}

test "peer ENR builder matches independent bytes and refuses invalid local preparation" {
    const key = try signingKey();
    var local = advertisement();
    const record = try adapter.build(&key, 7, &local, &context);
    const expected = try d.identity.enr.Record.initText(vectors[0].text);
    try std.testing.expectEqualSlices(u8, expected.slice(), record.slice());
    local.ip6 = .{0} ** 15 ++ .{1};
    local.udp6 = 9100;
    local.quic6 = 9101;
    const dual = try adapter.build(&key, 7, &local, &context);
    const dual_expected = try d.identity.enr.Record.initText(vectors[1].text);
    try std.testing.expectEqualSlices(u8, dual_expected.slice(), dual.slice());
    local.ip4 = null;
    const ipv6 = try adapter.build(&key, 8, &local, &context);
    try std.testing.expectEqual(@as(u16, 9101), (try adapter.decode(&ipv6, &context)).addresses[0].port());
    local.quic6 = null;
    const no_fallback = try adapter.build(&key, 8, &local, &context);
    try std.testing.expectEqual(@as(u8, 0), (try adapter.decode(&no_fallback, &context)).address_count);
    local = advertisement();
    local.syncnets = 0x10;
    try std.testing.expectError(error.InvalidField, adapter.build(&key, 8, &local, &context));
    local = advertisement();
    local.custody_group_count = 0;
    try std.testing.expectError(error.InvalidField, adapter.build(&key, 8, &local, &context));
    try std.testing.expectEqualSlices(u8, expected.slice(), record.slice());
    try std.testing.expectEqual(std.math.maxInt(u64), try adapter.nextSequence(std.math.maxInt(u64) - 1));
    try std.testing.expectError(error.SequenceExhausted, adapter.nextSequence(std.math.maxInt(u64)));
    local = advertisement();
    const exhausted = try adapter.build(&key, std.math.maxInt(u64), &local, &context);
    try std.testing.expectEqual(std.math.maxInt(u64), exhausted.sequence);
    const candidate = try adapter.decode(&record, &context);
    try adapter.requireIdentity(&record, &candidate.peer);
    const other = try @import("../wire/keys.zig").KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{2}));
    try std.testing.expectError(error.IdentityMismatch, adapter.requireIdentity(&record, &types.PeerId.fromPublicKey(&other.publicKey())));
    local.attnets = null;
    local.syncnets = null;
    local.custody_group_count = null;
    local.next_fork_digest = null;
    local.quic = null;
    const absent = try adapter.build(&key, 8, &local, &context);
    const decoded = try adapter.decode(&absent, &context);
    try std.testing.expect(decoded.attnets == null and decoded.syncnets == null and decoded.custody_group_count == null and decoded.next_fork_digest == null);
    try std.testing.expectEqual(@as(u8, 0), decoded.address_count);
}

fn changedRecord(name: []const u8, replacement: ?d.identity.enr.Field.Value) !d.identity.enr.Record {
    const record = try d.identity.enr.Record.initText(vectors[0].text);
    const key = try signingKey();
    var fields: [11]d.identity.enr.Field = undefined;
    var count: usize = 0;
    for ([_][]const u8{ "attnets", "cgc", "eth2", "id", "ip", "nfd", "quic", "secp256k1", "syncnets", "udp" }) |field_name| {
        const value = if (std.mem.eql(u8, name, field_name)) replacement orelse continue else d.identity.enr.Field.Value{ .raw = (try record.field(field_name)).? };
        fields[count] = .{ .key = field_name, .value = value };
        count += 1;
    }
    if (std.mem.eql(u8, name, "x-test")) {
        fields[count] = .{ .key = name, .value = replacement.? };
        count += 1;
    }
    return d.identity.enr.Record.createFields(&key, 8, fields[0..count]);
}

test "peer ENR canonical fingerprint rejects equal sequence changes outside dial hints" {
    const key = try signingKey();
    const original = try adapter.build(&key, 8, &advertisement(), &context);
    const candidate = try adapter.decode(&original, &context);
    const Queue = @import("dialing.zig").Dialing;
    var queue = try Queue.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 1 });
    var catalog = try @import("catalog.zig").Catalog.initWithIntents(std.testing.allocator, .{}, 1, 1024, 1);
    defer catalog.deinit(std.testing.allocator);
    try queue.enqueueDiscovered(&catalog, &candidate, &context, &.{}, 0);
    @memset(catalog.rows[0].intent.addresses[catalog.rows[0].intent.address_count..], .unspecified);
    const before = catalog.rows[0];
    for ([_]struct { name: []const u8, value: d.identity.enr.Field.Value }{
        .{ .name = "udp", .value = .{ .uint = 9002 } },
        .{ .name = "x-test", .value = .{ .bytes = "extra signed content" } },
    }) |change| {
        const changed = try changedRecord(change.name, change.value);
        const conflicting = try adapter.decode(&changed, &context);
        try std.testing.expectEqual(candidate.sequence, conflicting.sequence);
        try std.testing.expectEqualDeep(candidate.addresses, conflicting.addresses);
        try std.testing.expect(!std.mem.eql(u8, &candidate.record_hash, &conflicting.record_hash));
        try std.testing.expectError(error.StaleRecord, queue.enqueueDiscovered(&catalog, &conflicting, &context, &.{}, 100));
        try std.testing.expectEqualDeep(before, catalog.rows[0]);
    }
    try queue.enqueueDiscovered(&catalog, &candidate, &context, &.{}, 200);
    try std.testing.expectEqual(@as(u64, 200), catalog.rows[0].intent.hints_at_ms);
}

test "peer ENR zero custody remains dialable for subnet demand without custody credit" {
    const record = try d.identity.enr.Record.initText(vectors[5].text);
    const candidate = try adapter.decode(&record, &context);
    const Catalog = @import("catalog.zig").Catalog;
    var catalog = try Catalog.initWithIntents(std.testing.allocator, .{}, 1, 1024, 1);
    defer catalog.deinit(std.testing.allocator);
    var queue = try @import("dialing.zig").Dialing.init(.{ .capacity = 1, .concurrent_max = 1, .seed = 1 });
    const wanted: types.Coverage = .{ .syncnets = 1 };
    var fork = context;
    fork.fork = .fulu;
    fork.custody_requirement = 4;
    try queue.enqueueDiscovered(&catalog, &candidate, &fork, &wanted, 0);
    var budget: u16 = 64;
    try std.testing.expect(!catalog.advanceCustody(&fork, 0, 60_000, &budget));
    try std.testing.expectEqual(@as(u16, 64), budget);
    const row = catalog.rowFor(catalog.find(&candidate.peer).?).?;
    try std.testing.expectEqual(@as(?u64, 0), row.intent.hints.?.custody_group_count);
    const coverage = Catalog.candidateCoverage(row, &fork, 0);
    try std.testing.expectEqual(@as(u64, 0x8000000000000001), coverage.attnets);
    try std.testing.expectEqual(@as(u4, 5), coverage.syncnets);
    try std.testing.expectEqual(@as(usize, 0), coverage.groups.count());
    try std.testing.expectEqual(@as(usize, 0), coverage.custody_groups.count());
    queue.configureSelection(&catalog, &wanted, false, &fork, 0);
    var out: [1]@import("dialing.zig").DialIntent = undefined;
    try std.testing.expectEqual(@as(usize, 1), queue.poll(&catalog, 0, &out));
    try std.testing.expect(out[0].peer.eql(&candidate.peer));
}

test "peer ENR strict known optional field shapes integer bounds and missing mandatory field" {
    for ([_][]const u8{ "attnets", "syncnets", "eth2", "nfd", "cgc", "quic" }) |name| {
        const list = try changedRecord(name, .{ .raw = &.{0xc0} });
        try std.testing.expectError(error.InvalidField, adapter.decode(&list, &context));
    }
    const missing = try changedRecord("eth2", null);
    try std.testing.expectError(error.MissingEth2, adapter.decode(&missing, &context));
    var bytes: [17]u8 = @splat(0);
    @memcpy(bytes[0..4], &context.digest);
    for ([_]struct { name: []const u8, length: usize }{ .{ .name = "eth2", .length = 16 }, .{ .name = "nfd", .length = 4 }, .{ .name = "attnets", .length = 8 }, .{ .name = "syncnets", .length = 1 } }) |field| {
        for ([_]usize{ field.length - 1, field.length + 1 }) |length| {
            const bad = try changedRecord(field.name, .{ .bytes = bytes[0..length] });
            try std.testing.expectError(error.InvalidField, adapter.decode(&bad, &context));
        }
    }
    for ([_][]const u8{ &.{0}, &.{ 0, 1 }, &.{129}, &.{ 1, 0, 0, 0, 0, 0, 0, 0 }, &.{ 1, 0, 0, 0, 0, 0, 0, 0, 0 } }) |value| {
        const bad = try changedRecord("cgc", .{ .bytes = value });
        try std.testing.expectError(error.InvalidField, adapter.decode(&bad, &context));
    }
    for ([_]u64{ 0, 1, 128 }) |value| {
        const valid = try changedRecord("cgc", .{ .uint = value });
        try std.testing.expectEqual(@as(?u64, value), (try adapter.decode(&valid, &context)).custody_group_count);
    }
    for ([_]u64{ 0, 1, 65535 }) |port| {
        const valid = try changedRecord("quic", .{ .uint = port });
        const candidate = try adapter.decode(&valid, &context);
        try std.testing.expectEqual(@as(u8, if (port == 0) 0 else 1), candidate.address_count);
        if (port != 0) try std.testing.expectEqual(port, candidate.addresses[0].port());
    }
    const large_port = try changedRecord("quic", .{ .uint = 65536 });
    try std.testing.expectError(error.InvalidField, adapter.decode(&large_port, &context));
}
