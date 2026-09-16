const std = @import("std");
const ct = @import("consensus_types");
const reqresp = @import("reqresp.zig");
const protocol = @import("protocol.zig");
const engine_mod = @import("../quic/engine.zig");
const Service = @import("../service.zig").Service;
const support = @import("../test_support.zig");
const multistream = @import("../wire/multistream.zig");
const Event = reqresp.Event;

pub const deneb_digest = [4]u8{ 0x6a, 0x95, 0xa1, 0xa9 };
pub const fulu_digest = [4]u8{ 0x2f, 0x2f, 0x2f, 0x2f };
pub const Overrides = struct {
    outbound_max: u16 = 8,
    inbound_max: u16 = 8,
    inbound_per_peer_max: u8 = 8,
    progress_timeout_ms: u64 = 10_000,
    host_timeout_ms: u64 = 60_000,
    quota_timeout_ms: u64 = 60_000,
    quotas: ?@import("limiter.zig").Quotas = null,
    forks: ?[]const reqresp.ForkEntry = null,
    request_fork: @import("config").ForkSeq = .phase0,
    admission: ?reqresp.AdmissionOptions = null,
};

pub const Pair = struct {
    pair: support.Pair = .{},
    client: Service = undefined,
    server: Service = undefined,
    handles: struct { client: engine_mod.Handle, server: engine_mod.Handle } = undefined,
    forks: [2]reqresp.ForkEntry = .{
        .{ .digest = deneb_digest, .fork = .deneb },
        .{ .digest = fulu_digest, .fork = .fulu },
    },
    client_events: [32]Event = undefined,
    client_count: usize = 0,
    server_events: [32]Event = undefined,
    server_count: usize = 0,
    server_event_capacity: usize = 16,

    pub fn init(self: *Pair, client: Overrides, server: Overrides) !void {
        try self.pair.init(.{}, .{});
        errdefer self.pair.deinit();
        self.client = try Service.init(std.testing.allocator, .{ .reqresp = options(client, &self.forks), .router = .{ .negotiations_max = 16 }, .gossipsub = .{ .random_seed = 1, .connected_capacity = 4, .retained_capacity = 8, .retained_outbound_reserve = 1, .seen_capacity = 128, .mcache_capacity = 16, .validation_capacity = 8 }, .automatic_gossip_admission = false });
        errdefer self.client.deinit();
        self.server = try Service.init(std.testing.allocator, .{ .reqresp = options(server, &self.forks), .router = .{ .negotiations_max = 16 }, .gossipsub = .{ .random_seed = 1, .connected_capacity = 4, .retained_capacity = 8, .retained_outbound_reserve = 1, .seen_capacity = 128, .mcache_capacity = 16, .validation_capacity = 8 }, .automatic_gossip_admission = false });
        errdefer self.server.deinit();
        const handles = try support.connectPair(&self.pair);
        self.handles = .{ .client = handles.client, .server = handles.server };
    }

    fn options(overrides: Overrides, forks: []const reqresp.ForkEntry) reqresp.Options {
        return .{
            .peers = 128,
            .outbound_max = overrides.outbound_max,
            .inbound_max = overrides.inbound_max,
            .inbound_per_peer_max = overrides.inbound_per_peer_max,
            .progress_timeout_ms = overrides.progress_timeout_ms,
            .forks = overrides.forks orelse forks,
            .quotas = overrides.quotas,
            .request_fork = overrides.request_fork,
            .policy = if (overrides.admission == null) @import("policy_fixture.zig").config() else null,
            .admission = overrides.admission,
            .host_timeout_ms = overrides.host_timeout_ms,
            .quota_timeout_ms = overrides.quota_timeout_ms,
        };
    }

    pub fn deinit(self: *Pair) void {
        self.client.reqresp.shutdown(&self.pair.client, &self.client.router);
        self.server.reqresp.shutdown(&self.pair.server, &self.server.router);
        self.server.deinit();
        self.client.deinit();
        self.pair.deinit();
    }

    pub fn pumpOnce(self: *Pair) !void {
        try self.pair.pump();
        var events: [16]engine_mod.Event = undefined;
        var activity: [128]engine_mod.Handle = undefined;
        const server_activity = self.pair.server.takeActivity(&activity);
        const server_counts = self.server.process(&self.pair.server, self.pair.events(&self.pair.server, &events), activity[0..server_activity], self.pair.now, .{
            .application = self.server_events[0..self.server_event_capacity],
            .control = self.server_events[16..][0..self.server_event_capacity],
        });
        std.mem.copyForwards(Event, self.server_events[server_counts.application..], self.server_events[16..][0..server_counts.control]);
        self.server_count = server_counts.application + server_counts.control;
        const client_activity = self.pair.client.takeActivity(&activity);
        const client_counts = self.client.process(&self.pair.client, self.pair.events(&self.pair.client, &events), activity[0..client_activity], self.pair.now, .{
            .application = self.client_events[0..16],
            .control = self.client_events[16..],
        });
        std.mem.copyForwards(Event, self.client_events[client_counts.application..], self.client_events[16..][0..client_counts.control]);
        self.client_count = client_counts.application + client_counts.control;
        try self.pair.pump();
    }

    pub fn openRaw(self: *Pair, which: protocol.Protocol) !engine_mod.StreamHandle {
        const stream = try self.pair.client.openStream(self.handles.client);
        var dialer = try multistream.Dialer.init(which.id());
        var bytes: [2 * multistream.message_length_max]u8 = undefined;
        const proposal = try dialer.initialWrite(&bytes);
        try std.testing.expectEqual(proposal.len, try self.pair.client.write(stream, proposal, false));
        return stream;
    }

    pub fn awaitRawSelection(self: *Pair, stream: engine_mod.StreamHandle, which: protocol.Protocol) !void {
        var dialer = try multistream.Dialer.init(which.id());
        var bytes: [2 * multistream.message_length_max]u8 = undefined;
        var buffered: usize = 0;
        for (0..20) |_| {
            try self.pumpOnce();
            const read = try self.pair.client.read(stream, bytes[buffered..]);
            buffered += read.len;
            const outcome = try dialer.feed(bytes[0..buffered]);
            std.mem.copyForwards(u8, &bytes, bytes[outcome.consumed..buffered]);
            buffered -= outcome.consumed;
            if (outcome.status == .accepted) {
                try std.testing.expectEqual(@as(usize, 0), buffered);
                return;
            }
            try std.testing.expectEqual(.pending, outcome.status);
        }
        return error.TestUnexpectedResult;
    }

    pub fn clientEvents(self: *const Pair) []const Event {
        return self.client_events[0..self.client_count];
    }

    pub fn serverEvents(self: *const Pair) []const Event {
        return self.server_events[0..self.server_count];
    }
};

pub fn statusBytes(seed: u8) [ct.phase0.Status.fixed_size]u8 {
    const status = ct.phase0.Status.Type{
        .fork_digest = deneb_digest,
        .finalized_root = [_]u8{seed} ** 32,
        .finalized_epoch = seed,
        .head_root = [_]u8{seed +% 1} ** 32,
        .head_slot = @as(u64, seed) * 32,
    };
    var bytes: [ct.phase0.Status.fixed_size]u8 = undefined;
    _ = ct.phase0.Status.serializeIntoBytes(&status, &bytes);
    return bytes;
}
