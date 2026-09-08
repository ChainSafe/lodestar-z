const std = @import("std");
const network = @import("network");
const control = @import("peer_control.zig");
const snapshot = @import("peer_snapshot.zig");
const Gossip = network.gossipsub;
const Engine = network.quic.engine;
const max_payload = 10 * 1024 * 1024;
const topic = "/eth2/01000000/beacon_block/ssz_snappy";
const ping = [_]u8{ 1, 0, 0, 0, 0, 0, 0, 0 };
const identify_status = [_]u8{1} ++ [_]u8{0} ** 91;
const range = [_]u8{0} ** 8 ++ ping ++ ping;

pub const Peer = struct {
    transport: network.Transport = .{},
    service: network.Service,
    io: std.Io,
    allocator: std.mem.Allocator,
    conn: ?Engine.Handle = null,
    now: network.Now = .{ .mono_ms = 0, .unix_s = 0 },
    clock_offset: u64 = 0,
    event_capacity: usize = 16,
    emitted: usize = 0,
    steps: usize = 0,
    sink: []u8,
    response: []u8,
    response_seed: u32 = 0x6d2b79f5,
    response_size: usize = max_payload,
    outbound: bool = false,
    paused: bool = false,
    hold_fin: bool = false,
    held_finish: ?network.reqresp.RequestHandle = null,
    held_since: ?u64 = null,
    finish_calls: usize = 0,
    quit: bool = false,
    status_accepted: bool = false,
    application: bool = false,
    control_responses: [8][92]u8 = undefined,

    pub fn pump(self: *Peer) !void {
        if (self.steps >= 10_000_000) return error.StepBound;
        self.steps += 1;
        var events: [32]Engine.Event = undefined;
        var activity: [4]Engine.Handle = undefined;
        var requests: [16]network.reqresp.Event = undefined;
        var messages: [16]Gossip.Event = undefined;
        const result = try self.transport.step(self.io, &events, &activity, .{ .wait_max_ms = 1 });
        self.now = result.now;
        self.now.mono_ms += self.clock_offset;
        if (self.held_since) |since| if (self.now.mono_ms -| since >= 10_000) return error.FinHoldTimeout;
        for (events[0..result.events]) |event| switch (event) {
            .connected => |c| {
                self.conn = c.conn;
                var text: [network.wire.peer_id.text_length_max]u8 = undefined;
                try control.emit(self.allocator, .{ .event = "connected", .peer = c.peer_id.toText(&text), .generation = c.conn.generation });
            },
            .closed => |c| {
                if (self.conn) |conn| if (std.meta.eql(conn, c.conn)) {
                    self.conn = null;
                };
                const slot = &self.transport.engine.registry.slots[c.conn.index];
                try control.emit(self.allocator, .{ .event = "closed", .reason = @tagName(c.reason), .tls = if (slot.handshake.failure) |failure| @errorName(failure) else null });
            },
            else => {},
        };
        var controls: [16]network.reqresp.Event = undefined;
        var identified: [4]network.identify.Result = undefined;
        const counts = self.service.processOutputs(&self.transport.engine, events[0..result.events], activity[0..result.activity], self.now, .{ .application = &requests, .control = &controls, .gossipsub = messages[0..self.event_capacity], .identify = &identified });
        for (requests[0..counts.application]) |event| try self.requestEvent(event);
        for (controls[0..counts.control]) |event| try self.requestEvent(event);
        for (identified[0..counts.identify]) |*completion| switch (completion.outcome) {
            .success => |*metadata| try control.emit(self.allocator, .{ .event = "identified", .agent = if (metadata.agent) |*agent| agent.slice() else null, .identify = metadata.protocols.contains(.identify), .meshsub = metadata.protocols.contains(.{ .meshsub = .v1_2 }), .status2 = metadata.protocols.contains(.{ .reqresp = .status_v2 }) }),
            .failed => |failure| try control.emit(self.allocator, .{ .event = "identifyFailed", .reason = @tagName(failure) }),
        };
        for (messages[0..counts.gossipsub]) |event| switch (event) {
            .message => |m| {
                self.emitted += 1;
                try control.emit(self.allocator, .{ .event = "message", .topic = m.topic, .length = m.bytes.len, .sha256 = hash(m.bytes), .messageId = std.fmt.bytesToHex(m.id, .lower) });
                const report = self.service.gossipsub.report(m.handle, .accept, self.now);
                std.debug.assert(report == .applied);
            },
            .subscription_change => |s| try control.emit(self.allocator, .{ .event = "subscription", .topic = s.topic, .subscribed = s.subscribed }),
        };
    }

    fn requestEvent(self: *Peer, event: network.reqresp.Event) !void {
        switch (event) {
            .request => |r| {
                if (self.application and r.protocol.isControl()) {
                    if (r.protocol == .goodbye_v1) {
                        std.debug.assert(self.service.reqresp.finish(r.request, self.now));
                        return;
                    }
                    const out = &self.control_responses[r.request.index];
                    @memset(out, 0);
                    const len: usize = switch (r.protocol) {
                        .status_v1, .status_v2, .ping_v1 => blk: {
                            @memcpy(out[0..r.bytes.len], r.bytes);
                            break :blk r.bytes.len;
                        },
                        .metadata_v1 => 16,
                        .metadata_v2 => 17,
                        .metadata_v3 => blk: {
                            out[17] = 1;
                            break :blk 25;
                        },
                        else => unreachable,
                    };
                    try self.service.reqresp.respond(r.request, out[0..len], null, self.now);
                    return;
                }
                if (r.protocol == .status_v2 and self.service.identify != null) {
                    const remote = try network.peers.control_wire.decodeStatus(.status_v2, r.bytes);
                    const local = try network.peers.control_wire.decodeStatus(.status_v2, &identify_status);
                    if (!std.meta.eql(remote, local)) return error.InvalidStatus;
                    try self.service.reqresp.respond(r.request, &identify_status, null, self.now);
                    self.status_accepted = true;
                    try control.emit(self.allocator, .{ .event = "statusAccepted", .protocol = r.protocol.id() });
                    return;
                }
                if (r.protocol != .ping_v1 and r.protocol != .blocks_by_range_v2) return error.UnexpectedProtocol;
                if (!std.mem.eql(u8, r.bytes, if (r.protocol == .ping_v1) &ping else &range)) return error.InvalidRequestBytes;
                try control.emit(self.allocator, .{ .event = "request", .protocol = r.protocol.id(), .length = r.bytes.len, .sha256 = hash(r.bytes) });
                if (r.protocol == .ping_v1) {
                    try self.service.reqresp.respond(r.request, &ping, null, self.now);
                } else {
                    generate(self.response[0..self.response_size], self.response_seed);
                    try self.service.reqresp.respond(r.request, self.response[0..self.response_size], .{ .digest = .{ 1, 0, 0, 0 }, .fork = .deneb }, self.now);
                }
            },
            .chunk => |c| {
                try control.emit(self.allocator, .{ .event = "chunk", .length = c.bytes.len, .sha256 = hash(c.bytes), .context = if (c.fork != null) @as(?[]const u8, "01000000") else null, .result = 0 });
                std.debug.assert(self.service.reqresp.consume(c.request, self.now));
            },
            .done => {
                self.outbound = false;
                try control.emit(self.allocator, .{ .event = "done" });
            },
            .failed => |f| {
                self.outbound = false;
                try control.emit(self.allocator, .{ .event = "failed", .reason = @tagName(f.reason) });
            },
            .chunk_sent => |c| {
                if (self.hold_fin) {
                    self.held_finish = c.request;
                    self.held_since = self.now.mono_ms;
                } else {
                    self.finish_calls += 1;
                    std.debug.assert(self.service.reqresp.finish(c.request, self.now));
                }
            },
            else => {},
        }
    }

    pub fn command(self: *Peer, c: control.Command) !void {
        if (std.mem.eql(u8, c.op, "listen")) {
            var text: [network.wire.multiaddr.text_length_max]u8 = undefined;
            const addr = self.transport.localMultiaddr();
            return control.emit(self.allocator, .{ .id = c.id, .ok = true, .address = try addr.toText(&text), .peer = &std.fmt.bytesToHex(addr.peer.?.bytes, .lower) });
        }
        if (std.mem.eql(u8, c.op, "snapshot")) return snapshot.emit(self, c.id);
        if (std.mem.eql(u8, c.op, "dial")) {
            const target = try network.wire.multiaddr.Multiaddr.parse(c.address orelse return error.MissingAddress);
            switch (target.address) {
                .ip4 => |a| if (!std.mem.eql(u8, &a.octets, &.{ 127, 0, 0, 1 })) return error.NotLoopback,
                else => return error.NotLoopback,
            }
            self.conn = try self.transport.dial(self.io, &target);
        } else if (std.mem.eql(u8, c.op, "identifyMode") or std.mem.eql(u8, c.op, "enableGossipRequest")) {
            if (self.service.identify == null) return error.IdentifyDisabled;
            var active = network.capabilities.withIdentify(try network.capabilities.forFork(.fulu, true, &.{ .v1_2, .v1_1 }));
            if (std.mem.eql(u8, c.op, "identifyMode")) {
                active.request = .initEmpty();
                for (std.enums.values(network.reqresp.Protocol)) |protocol| if (active.receive.contains(.{ .reqresp = protocol })) {
                    active.request.insert(.{ .reqresp = protocol });
                };
                active.request.insert(.identify);
            }
            try self.service.router.validateCapabilities(active);
            self.service.router.setCapabilities(active);
        } else if (std.mem.eql(u8, c.op, "identify")) {
            if (!self.status_accepted) return error.StatusRequired;
            const conn = self.conn orelse return error.NoConnection;
            const identify = if (self.service.identify) |*value| value else return error.IdentifyDisabled;
            try identify.start(&self.service.router, &self.transport.engine, .{ .index = 0, .generation = conn.generation }, conn, self.now);
        } else if (std.mem.eql(u8, c.op, "subscribe")) {
            if (!self.service.gossipsub.subscribe(c.topic orelse topic)) return error.SubscriptionFailed;
        } else if (std.mem.eql(u8, c.op, "publish")) {
            const size = c.size orelse 65537;
            if (size > max_payload) return error.MessageTooLarge;
            const bytes = try self.allocator.alloc(u8, size);
            defer self.allocator.free(bytes);
            generate(bytes, c.seed orelse 0x6d2b79f5);
            const outcome = try self.service.gossipsub.publish(c.topic orelse topic, bytes, self.now);
            return control.emit(self.allocator, .{ .id = c.id, .ok = true, .queued = outcome.queued, .pressured = outcome.pressured });
        } else if (std.mem.eql(u8, c.op, "request")) {
            if (self.outbound) return error.Busy;
            const large = c.large orelse false;
            _ = try self.service.request(&self.transport.engine, self.conn orelse return error.NoConnection, if (large) .blocks_by_range_v2 else .ping_v1, if (large) &range else &ping, self.sink, .{ .expected_chunks = 1 }, self.now);
            self.outbound = true;
        } else return self.schedule(c);
        try control.emit(self.allocator, .{ .id = c.id, .ok = true });
    }

    fn schedule(self: *Peer, c: control.Command) !void {
        if (std.mem.eql(u8, c.op, "holdFin")) {
            self.hold_fin = true;
        } else if (std.mem.eql(u8, c.op, "releaseFin")) {
            const request = self.held_finish orelse return error.NoHeldFin;
            self.finish_calls += 1;
            _ = self.service.reqresp.finish(request, self.now);
            self.held_finish = null;
            self.held_since = null;
            self.hold_fin = false;
        } else if (std.mem.eql(u8, c.op, "setEventCapacity")) {
            const capacity = c.capacity orelse return error.MissingCapacity;
            if (capacity > 16) return error.CapacityBound;
            self.event_capacity = capacity;
        } else if (std.mem.eql(u8, c.op, "pause")) {
            self.paused = c.paused orelse return error.MissingPause;
        } else if (std.mem.eql(u8, c.op, "advance")) {
            const ms = c.ms orelse return error.MissingTime;
            if (ms > 120_000 or self.clock_offset + ms > 2_000_000) return error.ClockBound;
            self.clock_offset += ms;
        } else if (std.mem.eql(u8, c.op, "pump")) {
            const turns = c.turns orelse 8;
            if (turns > 1024) return error.TurnBound;
            for (0..turns) |_| try self.pump();
        } else if (std.mem.eql(u8, c.op, "respond")) {
            self.response_size = c.size orelse max_payload;
            if (self.response_size > max_payload) return error.MessageTooLarge;
            self.response_seed = c.seed orelse 0x6d2b79f5;
        } else if (std.mem.eql(u8, c.op, "disconnect")) {
            if (self.conn) |conn| {
                _ = self.transport.engine.close(conn, 0);
            }
        } else if (std.mem.eql(u8, c.op, "ids")) {
            return snapshot.ids(self.allocator, c.id);
        } else if (std.mem.eql(u8, c.op, "shutdown")) {
            self.quit = true;
        } else return error.UnknownOperation;
        try control.emit(self.allocator, .{ .id = c.id, .ok = true });
    }
};

pub fn hash(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}
pub fn generate(bytes: []u8, seed: u32) void {
    std.debug.assert(bytes.len <= max_payload);
    var x = seed;
    for (bytes) |*byte| {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        byte.* = @truncate(x);
    }
}
pub fn main(init: std.process.Init) !void {
    var gpa: std.heap.DebugAllocator(.{}) = .{};
    defer std.debug.assert(gpa.deinit() == .ok);
    const a = gpa.allocator();
    var quotas = network.reqresp.limiter.defaultQuotas();
    quotas[@intFromEnum(network.reqresp.Protocol.ping_v1)] = .{ .tokens = 16, .period_ms = 30_000 };
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const application = args.len == 2 and std.mem.eql(u8, args[1], "--application");
    const identify_enabled = application or (args.len == 2 and std.mem.eql(u8, args[1], "--identify"));
    const peer = try a.create(Peer);
    defer a.destroy(peer);
    peer.* = .{ .application = application, .allocator = a, .io = init.io, .service = try network.Service.init(a, .{ .identify = if (identify_enabled) .{ .agent = "lodestar-z-identify" } else null, .reqresp = .{ .peers = 4, .outbound_max = 1, .inbound_max = if (application) 8 else 1, .inbound_per_peer_max = if (application) 8 else 1, .inbound_control_reserved = if (application) 2 else 0, .forks = &.{.{ .digest = .{ 1, 0, 0, 0 }, .fork = .deneb }}, .progress_timeout_ms = 5000, .quotas = quotas }, .router = .{ .negotiations_max = 16 }, .gossipsub = .{ .message_id_policy = .{ .phase0_digest = .{ 1, 0, 0, 0 } }, .random_seed = 0x6d2b79f5 } }), .sink = undefined, .response = undefined };
    defer peer.service.deinit();
    peer.sink = try a.alloc(u8, max_payload);
    defer a.free(peer.sink);
    peer.response = try a.alloc(u8, max_payload);
    defer a.free(peer.response);
    const key = try network.wire.keys.KeyPair.fromSecretKey(&([_]u8{0} ** 31 ++ .{31}));
    try peer.transport.init(a, init.io, .{ .host = &key, .bind = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } }, .limits = .{ .connections_max = 4, .handshaking_max = 4, .dialing_max = 2, .outbound_max = 3 } });
    defer peer.transport.deinit(init.io);
    defer if (peer.service.identify) |*identify| identify.shutdown(&peer.service.router, &peer.transport.engine);
    defer peer.service.reqresp.shutdown(&peer.service.router, &peer.transport.engine);
    try control.run(peer);
}
