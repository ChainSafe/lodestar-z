const std = @import("std");
const ct = @import("consensus_types");
const limiter = @import("limiter.zig");
const protocol = @import("protocol.zig");
const reqresp = @import("reqresp.zig");
const service = @import("service.zig");
const engine_mod = @import("../quic/engine.zig");
const support = @import("../test_support.zig");
const harness = @import("reqresp_test.zig");

const Event = reqresp.Event;
const Protocol = protocol.Protocol;
const Service = service.Service;
const deneb_digest = harness.deneb_digest;
const fulu_digest = harness.fulu_digest;
const statusBytes = harness.statusBytes;

const forks = [_]reqresp.ForkEntry{
    .{ .digest = deneb_digest, .fork = .deneb },
    .{ .digest = fulu_digest, .fork = .fulu },
};

const ServicePair = struct {
    pair: support.Pair = .{},
    client: Service = undefined,
    server: Service = undefined,
    handles: struct { client: engine_mod.Handle, server: engine_mod.Handle } = undefined,
    sinks: []u8 = &.{},
    client_events: [16]Event = undefined,
    client_count: usize = 0,
    server_events: [16]Event = undefined,
    server_count: usize = 0,

    fn options(quotas: ?limiter.Quotas) service.Options {
        return .{ .reqresp = .{
            .outbound_max = 4,
            .inbound_max = 4,
            .inbound_per_peer_max = 4,
            .progress_timeout_ms = 10_000,
            .forks = &forks,
            .quotas = quotas,
        } };
    }

    fn init(self: *ServicePair, quotas: ?limiter.Quotas) !void {
        try self.pair.init(.{}, .{});
        errdefer self.pair.deinit();
        self.client = try Service.init(std.testing.allocator, options(quotas));
        errdefer self.client.deinit();
        self.server = try Service.init(std.testing.allocator, options(quotas));
        errdefer self.server.deinit();
        self.sinks = try std.testing.allocator.alloc(u8, 4 * protocol.requestMaxAll());
        const handles = try support.connectPair(&self.pair);
        self.handles = .{ .client = handles.client, .server = handles.server };
    }

    fn deinit(self: *ServicePair) void {
        std.testing.allocator.free(self.sinks);
        self.server.deinit();
        self.client.deinit();
        self.pair.deinit();
    }

    fn sink(self: *ServicePair, index: usize) []u8 {
        const size = protocol.requestMaxAll();
        return self.sinks[index * size ..][0..size];
    }

    fn pumpOnce(self: *ServicePair) !void {
        try self.pair.pump();
        const now = self.pair.now;
        var server_storage: [16]engine_mod.Event = undefined;
        const server_ev = self.pair.events(&self.pair.server, &server_storage);
        self.server_count = self.server.process(&self.pair.server, server_ev, now, &self.server_events);
        var client_storage: [16]engine_mod.Event = undefined;
        const client_ev = self.pair.events(&self.pair.client, &client_storage);
        self.client_count = self.client.process(&self.pair.client, client_ev, now, &self.client_events);
        try self.pair.pump();
    }

    fn clientEvents(self: *const ServicePair) []const Event {
        return self.client_events[0..self.client_count];
    }

    fn serverEvents(self: *const ServicePair) []const Event {
        return self.server_events[0..self.server_count];
    }
};

fn roundTrip(setup: *ServicePair, seed: u8) !void {
    const request_ssz = statusBytes(seed);
    _ = try setup.client.request(
        &setup.pair.client,
        setup.handles.client,
        .status_v1,
        &request_ssz,
        setup.sink(0),
        .{},
        setup.pair.now,
    );
    const reply = statusBytes(seed +% 1);
    var done = false;
    var rounds: usize = 0;
    while (rounds < 40 and !done) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .request => |incoming| {
                try std.testing.expectEqual(Protocol.status_v1, incoming.protocol);
                try setup.server.respond(incoming.request, &reply, null, setup.pair.now);
            },
            .chunk_sent => |sent| try std.testing.expect(setup.server.finish(sent.request)),
            else => {},
        };
        for (setup.clientEvents()) |event| switch (event) {
            .chunk => |chunk| {
                try std.testing.expectEqualSlices(u8, &reply, chunk.bytes);
                try std.testing.expect(setup.client.consume(chunk.request));
            },
            .done => done = true,
            .failed => return error.TestUnexpectedResult,
            else => {},
        };
    }
    try std.testing.expect(done);
}

test "service round trips a status request through the collapsed host loop" {
    var setup: ServicePair = .{};
    try setup.init(null);
    defer setup.deinit();

    try roundTrip(&setup, 5);
    try std.testing.expectEqual(@as(u16, 0), setup.client.registry.active().outbound);
    try std.testing.expectEqual(@as(u16, 0), setup.server.registry.active().inbound);
}

test "service reclaims inbound sinks across more requests than it has slots" {
    var quotas = limiter.defaultQuotas();
    quotas[@intFromEnum(Protocol.status_v1)] = .{ .tokens = 1_000, .period_ms = 1_000 };
    var setup: ServicePair = .{};
    try setup.init(quotas);
    defer setup.deinit();

    var seed: u8 = 0;
    while (seed < 12) : (seed += 1) try roundTrip(&setup, seed);
    try std.testing.expectEqual(@as(u64, 12), setup.server.counters().requests_served);
    try std.testing.expectEqual(@as(u16, 0), setup.server.registry.active().inbound);
}

test "service fails in-flight requests when the connection closes" {
    var setup: ServicePair = .{};
    try setup.init(null);
    defer setup.deinit();

    const request_ssz = statusBytes(1);
    _ = try setup.client.request(
        &setup.pair.client,
        setup.handles.client,
        .status_v1,
        &request_ssz,
        setup.sink(0),
        .{},
        setup.pair.now,
    );
    var seen = false;
    var rounds: usize = 0;
    while (rounds < 12 and !seen) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| {
            if (event == .request) seen = true;
        }
    }
    try std.testing.expect(seen);

    try std.testing.expect(setup.pair.client.close(setup.handles.client, 0));
    var client_failed = false;
    var server_failed = false;
    rounds = 0;
    while (rounds < 20 and !(client_failed and server_failed)) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.clientEvents()) |event| {
            if (event == .failed and event.failed.reason == .connection_closed) client_failed = true;
        }
        for (setup.serverEvents()) |event| {
            if (event == .failed and event.failed.reason == .connection_closed) server_failed = true;
        }
    }
    try std.testing.expect(client_failed);
    try std.testing.expect(server_failed);
    try std.testing.expectEqual(@as(u16, 0), setup.server.registry.active().inbound);
}
