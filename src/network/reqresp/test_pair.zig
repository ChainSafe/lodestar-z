const std = @import("std");
const ct = @import("consensus_types");
const reqresp = @import("ReqResp.zig");
const protocol = @import("protocol.zig");
const Engine = @import("../quic/Engine.zig");
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
    forks: ?[]const @import("../types.zig").ForkEntry = null,
    request_fork: @import("config").ForkSeq = .phase0,
    admission: ?reqresp.Options.Admission = null,
};

pub const Pair = struct {
    shared: @import("../service_test_support.zig").ServicePair = .{},
    forks: [2]@import("../types.zig").ForkEntry = .{
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

    fn serviceOptions(overrides: Overrides, forks: []const @import("../types.zig").ForkEntry) !@import("../service.zig").Service.Options {
        return .{ .reqresp = try options(overrides, forks), .router = .{ .negotiations_max = 16 }, .gossipsub = .{ .random_seed = 1, .connected_capacity = 4, .retained_capacity = 8, .retained_outbound_reserve = 1, .seen_capacity = 128, .mcache_capacity = 16, .validation_capacity = 8 } };
    }

    /// Admission defaults over the fixture policy unless the caller supplies admission.
    fn options(overrides: Overrides, forks: []const @import("../types.zig").ForkEntry) !reqresp.Options {
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
            .request_fork = overrides.request_fork,
            .admission = overrides.admission orelse try reqresp.Options.Admission.defaults(&@import("policy_fixture.zig").config(), peers, peers, overrides.inbound_max -| overrides.inbound_control_reserved),
            .host_timeout_ms = overrides.host_timeout_ms,
            .quota_timeout_ms = overrides.quota_timeout_ms,
        };
    }

    pub fn deinit(self: *Pair) void {
        self.shared.deinit();
    }

    /// Routes both sides' stream events to their negotiators and reqresp owners.
    pub fn forwardEvents(self: *Pair) void {
        @import("../service_test_support.zig").forward(&self.shared.pair, &self.shared.pair.client, .{ .negotiator = &self.shared.client.router.negotiator, .reqresp = &self.shared.client.reqresp });
        @import("../service_test_support.zig").forward(&self.shared.pair, &self.shared.pair.server, .{ .negotiator = &self.shared.server.router.negotiator, .reqresp = &self.shared.server.reqresp });
    }

    pub fn pumpOnce(self: *Pair) !void {
        const counts = try self.shared.step(.{ .application = self.client_events[0..16], .control = self.client_events[16..] }, .{ .application = self.server_events[0..self.server_event_capacity], .control = self.server_events[16..][0..self.server_event_capacity] });
        std.mem.copyForwards(Event, self.server_events[counts.server.application..], self.server_events[16..][0..counts.server.control]);
        self.server_count = counts.server.application + counts.server.control;
        std.mem.copyForwards(Event, self.client_events[counts.client.application..], self.client_events[16..][0..counts.client.control]);
        self.client_count = counts.client.application + counts.client.control;
    }

    pub fn openRaw(self: *Pair, which: protocol.Protocol) !Engine.StreamHandle {
        return self.openRawOn(self.shared.handles.client, which);
    }

    pub fn openRawOn(self: *Pair, conn: Engine.Handle, which: protocol.Protocol) !Engine.StreamHandle {
        const stream = try self.shared.pair.client.openStream(conn);
        var dialer = try multistream.Dialer.init(which.id());
        var bytes: [2 * multistream.message_length_max]u8 = undefined;
        const proposal = try dialer.initialWrite(&bytes);
        try std.testing.expectEqual(proposal.len, try self.shared.pair.client.write(stream, proposal, false));
        return stream;
    }

    pub fn awaitRawSelection(self: *Pair, stream: Engine.StreamHandle, which: protocol.Protocol) !void {
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

pub fn requestStatus(setup: *Pair, request_ssz: *[ct.phase0.Status.fixed_size]u8, sink: []u8) !reqresp.RequestHandle {
    request_ssz.* = statusBytes(5);
    return setup.shared.client.reqresp.request(
        &setup.shared.pair.client,
        &setup.shared.client.router,
        setup.shared.handles.client,
        .status_v1,
        request_ssz,
        sink,
        .{},
        setup.shared.pair.now,
    );
}

pub fn requestBlocks(setup: *Pair, request_ssz: *[24]u8, count: u64, sink: []u8) !reqresp.RequestHandle {
    const Request = ct.phase0.BeaconBlocksByRangeRequest;
    const request = Request.Type{ .start_slot = 1, .count = count, .step = 1 };
    _ = Request.serializeIntoBytes(&request, request_ssz);
    return setup.shared.client.reqresp.request(
        &setup.shared.pair.client,
        &setup.shared.client.router,
        setup.shared.handles.client,
        .blocks_by_range_v2,
        request_ssz,
        sink,
        .{},
        setup.shared.pair.now,
    );
}

pub fn firstFailure(events: []const Event) ?reqresp.Failure {
    for (events) |event| {
        if (event == .failed) return event.failed.reason;
    }
    return null;
}

pub fn waitForRequest(setup: *Pair) !void {
    var request_seen = false;
    var rounds: usize = 0;
    while (rounds < 10 and !request_seen) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| {
            if (event == .request) request_seen = true;
        }
    }
    try std.testing.expect(request_seen);
}
