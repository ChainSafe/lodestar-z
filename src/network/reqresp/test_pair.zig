const std = @import("std");
const ct = @import("consensus_types");
const reqresp = @import("reqresp.zig");
const protocol = @import("protocol.zig");
const engine_mod = @import("../quic/engine.zig");
const multistream = @import("../wire/multistream.zig");
const Event = reqresp.Event;

pub const deneb_digest = [4]u8{ 0x6a, 0x95, 0xa1, 0xa9 };
pub const fulu_digest = [4]u8{ 0x2f, 0x2f, 0x2f, 0x2f };
pub const Overrides = struct {
    outbound_max: u16 = 8,
    inbound_max: u16 = 8,
    inbound_per_peer_max: u8 = 8,
    inbound_control_reserved: u16 = 0,
    serving_per_peer_max: u8 = 4,
    progress_timeout_ms: u64 = 10_000,
    host_timeout_ms: u64 = 60_000,
    quota_timeout_ms: u64 = 60_000,
    quotas: ?@import("limiter.zig").Quotas = null,
    forks: ?[]const reqresp.ForkEntry = null,
    request_fork: @import("config").ForkSeq = .phase0,
    admission: ?reqresp.AdmissionOptions = null,
};

pub const Pair = struct {
    shared: @import("../service_test_support.zig").ServicePair = .{},
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
        try self.shared.init(try serviceOptions(client, &self.forks), try serviceOptions(server, &self.forks));
    }

    fn serviceOptions(overrides: Overrides, forks: []const reqresp.ForkEntry) !@import("../service.zig").Options {
        return .{ .reqresp = try options(overrides, forks), .router = .{ .negotiations_max = 16 }, .gossipsub = .{ .random_seed = 1, .connected_capacity = 4, .retained_capacity = 8, .retained_outbound_reserve = 1, .seen_capacity = 128, .mcache_capacity = 16, .validation_capacity = 8 } };
    }

    /// Admission defaults over the fixture policy unless the caller supplies admission.
    fn options(overrides: Overrides, forks: []const reqresp.ForkEntry) !reqresp.Options {
        const peers = 128;
        return .{
            .peers = peers,
            .outbound_max = overrides.outbound_max,
            .inbound_max = overrides.inbound_max,
            .inbound_per_peer_max = overrides.inbound_per_peer_max,
            .inbound_control_reserved = overrides.inbound_control_reserved,
            .serving_per_peer_max = overrides.serving_per_peer_max,
            .progress_timeout_ms = overrides.progress_timeout_ms,
            .forks = overrides.forks orelse forks,
            .quotas = overrides.quotas,
            .request_fork = overrides.request_fork,
            .admission = overrides.admission orelse try reqresp.AdmissionOptions.defaults(&@import("policy_fixture.zig").config(), peers, peers, overrides.inbound_max -| overrides.inbound_control_reserved),
            .host_timeout_ms = overrides.host_timeout_ms,
            .quota_timeout_ms = overrides.quota_timeout_ms,
        };
    }

    pub fn deinit(self: *Pair) void {
        self.shared.deinit();
    }

    pub fn forwardActivity(self: *Pair) void {
        var activity: [128]engine_mod.Handle = undefined;
        for (activity[0..self.shared.pair.client.takeActivity(&activity)]) |conn| {
            self.shared.client.router.connectionActivity(conn);
            self.shared.client.reqresp.connectionActivity(conn);
        }
        for (activity[0..self.shared.pair.server.takeActivity(&activity)]) |conn| {
            self.shared.server.router.connectionActivity(conn);
            self.shared.server.reqresp.connectionActivity(conn);
        }
    }

    pub fn pumpOnce(self: *Pair) !void {
        const counts = try self.shared.step(.{ .application = self.client_events[0..16], .control = self.client_events[16..] }, .{ .application = self.server_events[0..self.server_event_capacity], .control = self.server_events[16..][0..self.server_event_capacity] });
        std.mem.copyForwards(Event, self.server_events[counts.server.application..], self.server_events[16..][0..counts.server.control]);
        self.server_count = counts.server.application + counts.server.control;
        std.mem.copyForwards(Event, self.client_events[counts.client.application..], self.client_events[16..][0..counts.client.control]);
        self.client_count = counts.client.application + counts.client.control;
    }

    pub fn openRaw(self: *Pair, which: protocol.Protocol) !engine_mod.StreamHandle {
        const stream = try self.shared.pair.client.openStream(self.shared.handles.client);
        var dialer = try multistream.Dialer.init(which.id());
        var bytes: [2 * multistream.message_length_max]u8 = undefined;
        const proposal = try dialer.initialWrite(&bytes);
        try std.testing.expectEqual(proposal.len, try self.shared.pair.client.write(stream, proposal, false));
        return stream;
    }

    pub fn awaitRawSelection(self: *Pair, stream: engine_mod.StreamHandle, which: protocol.Protocol) !void {
        var dialer = try multistream.Dialer.init(which.id());
        var bytes: [2 * multistream.message_length_max]u8 = undefined;
        var buffered: usize = 0;
        for (0..20) |_| {
            try self.pumpOnce();
            const read = try self.shared.pair.client.read(stream, bytes[buffered..]);
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
