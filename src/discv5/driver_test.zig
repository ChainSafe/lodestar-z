const std = @import("std");
const calls = @import("calls.zig");
const crypto = @import("identity/crypto.zig");
const driver = @import("driver.zig");
const engine = @import("engine.zig");
const enr = @import("identity/enr.zig");
const routing = @import("routing.zig");
const runtime = @import("runtime.zig");
const session = @import("session.zig");
const test_support = @import("test_support.zig");
const types = @import("types.zig");

const net = std.Io.net;

test "driver rejects invalid polling and missing expiry storage" {
    var core: engine.Engine = undefined;
    var udp = runtime.Udp.init(undefined);
    try std.testing.expectError(
        error.InvalidPollInterval,
        driver.Driver.initWithConfig(&core, &udp, .{ .poll_interval_ms = 0 }),
    );
    var instance = driver.Driver.init(&core, &udp);
    try std.testing.expectError(
        error.MissingExpiryStorage,
        instance.step(undefined, &.{}),
    );
}

test "driver retains a routing incumbent that answers revalidation" {
    var pair: Pair = undefined;
    try pair.init(1_000);
    defer pair.deinit();
    try pair.fillBucket();

    var expired: [4]calls.Expired = undefined;
    const started = try pair.driver_a.step(std.testing.io, &expired);
    try std.testing.expect(started.maintenance_started);
    try std.testing.expectEqual(@as(usize, 0), started.calls_expired);
    try std.testing.expectEqual(@as(usize, 0), started.maintenance_expired);

    const answered = try pair.driver_b.step(std.testing.io, &expired);
    try std.testing.expectEqual(@as(u8, 1), answered.standard_responses);
    try std.testing.expect(answered.event == .none);

    const completed = try pair.driver_a.step(std.testing.io, &expired);
    try std.testing.expect(completed.event == .none);
    try std.testing.expectEqual(@as(usize, 0), completed.calls_expired);
    try std.testing.expectEqual(@as(usize, 0), completed.maintenance_expired);
    try std.testing.expectEqual(@as(usize, 0), pair.node_a.routing.pendingCount());
    try std.testing.expect(pair.node_a.routing.contains(&pair.record_b.node_id));
    try std.testing.expect(!pair.node_a.routing.contains(&pair.candidate_id));
    try std.testing.expectEqual(@as(usize, 0), pair.node_a.calls.count());
}

test "driver replaces a routing incumbent when revalidation expires" {
    var pair: Pair = undefined;
    try pair.init(1);
    defer pair.deinit();
    try pair.fillBucket();

    var expired: [4]calls.Expired = undefined;
    const result = try pair.driver_a.step(std.testing.io, &expired);
    try std.testing.expect(result.maintenance_started);
    try std.testing.expectEqual(@as(usize, 0), result.calls_expired);
    try std.testing.expectEqual(@as(usize, 1), result.maintenance_expired);
    try std.testing.expectEqual(@as(usize, 0), pair.node_a.routing.pendingCount());
    try std.testing.expect(!pair.node_a.routing.contains(&pair.record_b.node_id));
    try std.testing.expect(pair.node_a.routing.contains(&pair.candidate_id));
    try std.testing.expectEqual(@as(usize, 0), pair.node_a.calls.count());
}

const Pair = struct {
    udp_a: runtime.Udp,
    udp_b: runtime.Udp,
    record_a: enr.Record,
    record_b: enr.Record,
    node_a: engine.Engine,
    node_b: engine.Engine,
    driver_a: driver.Driver,
    driver_b: driver.Driver,
    candidate_id: types.NodeId,

    fn init(self: *Pair, request_timeout_ms: u64) !void {
        const loopback = net.IpAddress{ .ip4 = .loopback(0) };
        self.udp_a = try runtime.Udp.bind(std.testing.io, loopback);
        errdefer self.udp_a.close(std.testing.io);
        self.udp_b = try runtime.Udp.bind(std.testing.io, loopback);
        errdefer self.udp_b.close(std.testing.io);

        const key_a = try crypto.keyPairFromSecret(&([_]u8{0x11} ** 32));
        const key_b = try crypto.keyPairFromSecret(&([_]u8{0x22} ** 32));
        self.record_a = try test_support.buildRecord(&key_a, 1, self.udp_a.localAddress());
        self.record_b = try test_support.buildRecord(&key_b, 1, self.udp_b.localAddress());
        const config = engine.Config{
            .session_capacity = 4,
            .challenge_capacity = 4,
            .call_capacity = 4,
            .request_timeout_ms = request_timeout_ms,
            .challenge_timeout_ms = 1_000,
            .session_idle_timeout_ms = std.math.maxInt(u64),
        };
        try self.node_a.initWithConfig(std.testing.allocator, key_a, self.record_a, config);
        errdefer self.node_a.deinit();
        try self.node_b.initWithConfig(std.testing.allocator, key_b, self.record_b, config);
        errdefer self.node_b.deinit();

        const peer_a = endpoint(&self.record_a);
        const peer_b = endpoint(&self.record_b);
        const session_key = [_]u8{0x55} ** 16;
        const active = session.Session{ .read_key = session_key, .write_key = session_key };
        self.node_a.sessions.install(peer_b, &active, 0);
        self.node_b.sessions.install(peer_a, &active, 0);
        self.driver_a = try driver.Driver.initWithConfig(
            &self.node_a,
            &self.udp_a,
            .{ .poll_interval_ms = 10 },
        );
        self.driver_b = try driver.Driver.initWithConfig(
            &self.node_b,
            &self.udp_b,
            .{ .poll_interval_ms = 10 },
        );
    }

    fn deinit(self: *Pair) void {
        self.node_b.deinit();
        self.node_a.deinit();
        self.udp_b.close(std.testing.io);
        self.udp_a.close(std.testing.io);
    }

    fn fillBucket(self: *Pair) !void {
        const incumbent_peer = endpoint(&self.record_b);
        try std.testing.expect(types.logDistance(
            &self.record_a.node_id,
            &self.record_b.node_id,
        ) > 8);
        try std.testing.expectEqual(
            routing.PutResult.inserted,
            try self.node_a.confirmPeer(&incumbent_peer, &self.record_b, 0),
        );
        for (1..routing.bucket_size) |index| {
            const node_id = variantNodeId(self.record_b.node_id, @intCast(index));
            const address = address4(10, @intCast(index), 0, 1, @intCast(10_000 + index));
            var record = fakeRecord(node_id, address);
            const peer = types.Endpoint{ .node_id = node_id, .address = address };
            try std.testing.expectEqual(
                routing.PutResult.inserted,
                try self.node_a.confirmPeer(&peer, &record, @intCast(index)),
            );
        }
        self.candidate_id = variantNodeId(self.record_b.node_id, routing.bucket_size);
        const candidate_address = address4(10, 200, 0, 1, 10_200);
        var candidate_record = fakeRecord(self.candidate_id, candidate_address);
        const candidate_peer = types.Endpoint{
            .node_id = self.candidate_id,
            .address = candidate_address,
        };
        const pending = try self.node_a.confirmPeer(&candidate_peer, &candidate_record, 20);
        switch (pending) {
            .pending => |node_id| try std.testing.expectEqualSlices(
                u8,
                &self.record_b.node_id,
                &node_id,
            ),
            else => return error.TestUnexpectedResult,
        }
    }
};

fn endpoint(record: *const enr.Record) types.Endpoint {
    return .{ .node_id = record.node_id, .address = record.endpoint().? };
}

fn variantNodeId(base: types.NodeId, salt: u8) types.NodeId {
    var result = base;
    result[31] ^= salt;
    return result;
}

fn fakeRecord(node_id: types.NodeId, address: types.Address) enr.Record {
    var record = std.mem.zeroes(enr.Record);
    record.node_id = node_id;
    switch (address) {
        .ip4 => |value| {
            record.ip4 = value.octets;
            record.udp = value.port;
        },
        .ip6 => unreachable,
    }
    return record;
}

fn address4(a: u8, b: u8, c: u8, d: u8, port: u16) types.Address {
    return .{ .ip4 = .{ .octets = .{ a, b, c, d }, .port = port } };
}
