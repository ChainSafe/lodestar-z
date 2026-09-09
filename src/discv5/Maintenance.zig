//! Host-owned periodic work. Calls retain engine-owned deadlines; the controller borrows
//! bootstrap records and one lookup's candidate storage for its entire lifetime.

const std = @import("std");
const CallTable = @import("CallTable.zig");
const Engine = @import("Engine.zig");
const enr = @import("identity/enr.zig");
const Lookup = @import("Lookup.zig");
const message = @import("wire/message.zig");
const RoutingTable = @import("RoutingTable.zig");
const types = @import("types.zig");

pub const bootstrap_max: usize = 16;
pub const probe_attempts_max: u8 = 2;
pub const Error = Lookup.Error || error{ InvalidConfig, InvalidBootstrap, TooManyBootstraps };
pub const Failure = enum { expired, local };
pub const Config = struct {
    probe_interval_ms: u64 = 30_000,
    stale_after_ms: u64 = 300_000,
    refresh_interval_ms: u64 = 60_000,
    bootstrap_interval_ms: u64 = 60_000,
    discovery_stall_ms: u64 = 300_000,
    retry_interval_ms: u64 = 1_000,
};

const Pending = struct {
    entry: RoutingTable.Entry,
    handle: ?CallTable.Handle = null,
    kind: enum { ping, enr } = .ping,
    attempts: u8 = 0,
    ready_ms: u64,
    bootstrap: bool = false,
};

const Maintenance = @This();
config: Config,
ipv6_enabled: bool = true,
bootstrap: []const enr.Record,
candidates: *Lookup.Candidates,
lookup: Lookup = undefined,
lookup_active: bool = false,
pending: ?Pending = null,
probe_cursor: usize = 0,
bootstrap_cursor: usize = 0,
bucket_cursor: u8 = 0,
probe_due_ms: u64,
refresh_due_ms: u64,
bootstrap_due_ms: u64,
last_growth_ms: u64,
observed_peers: usize = 0,
next_start_ms: ?u64,

pub fn init(
    self: *Maintenance,
    candidates: *Lookup.Candidates,
    bootstrap: []const enr.Record,
    now_ms: u64,
    config: Config,
) Error!void {
    if (bootstrap.len > bootstrap_max) return Error.TooManyBootstraps;
    inline for (std.meta.fields(Config)) |field| {
        if (@field(config, field.name) == 0) return Error.InvalidConfig;
    }
    for (bootstrap) |*record| {
        const address = record.endpoint() orelse return Error.InvalidBootstrap;
        if (!address.isUsable()) return Error.InvalidBootstrap;
    }
    const probe_due_ms = now_ms +| config.probe_interval_ms;
    const refresh_due_ms = now_ms +| config.refresh_interval_ms;
    self.* = .{
        .config = config,
        .bootstrap = bootstrap,
        .candidates = candidates,
        .probe_due_ms = probe_due_ms,
        .refresh_due_ms = refresh_due_ms,
        .bootstrap_due_ms = now_ms,
        .last_growth_ms = now_ms,
        .next_start_ms = if (bootstrap.len > 0) now_ms else @min(probe_due_ms, refresh_due_ms),
    };
}

pub fn nextDeadlineMs(self: *const Maintenance) ?u64 {
    return self.next_start_ms;
}

/// Starts at most one call. The host sends the returned packet, forwards owned events and
/// expiries, and retries at this controller's deadline or after an event releases a call.
pub fn startNext(
    self: *Maintenance,
    core: *Engine,
    out: []u8,
    request_id: message.RequestId,
    now_ms: u64,
    entropy: *const Engine.StartEntropy,
) Error!?Lookup.Started {
    if (now_ms < (self.next_start_ms orelse return null)) return null;
    self.next_start_ms = now_ms +| self.config.retry_interval_ms;
    self.observeGrowth(core, now_ms);
    if (self.lookup_active and self.lookup.isFinished()) self.lookup_active = false;
    self.selectProbe(core, now_ms);
    if (self.pending) |*pending| {
        if (pending.handle == null and now_ms >= pending.ready_ms and
            !core.isPeerBusy(&pending.entry.peer.node_id))
        {
            const request = switch (pending.kind) {
                .ping => message.Message{ .ping = .{
                    .request_id = request_id,
                    .enr_sequence = core.localRecord().sequence,
                } },
                .enr => message.Message{ .find_node = .{
                    .request_id = request_id,
                    .distances = &.{0},
                } },
            };
            const call = core.startCall(
                out,
                pending.entry.peer,
                &pending.entry.record,
                &request,
                now_ms,
                entropy,
            ) catch |err| switch (err) {
                error.PeerBusy, error.TableFull => return null,
                else => return err,
            };
            pending.handle = call.handle;
            pending.attempts += 1;
            self.next_start_ms = now_ms;
            return .{ .peer = pending.entry.peer, .call = call };
        }
    }
    if (!self.lookup_active and now_ms >= self.refresh_due_ms)
        try self.startRefresh(core, now_ms, entropy);
    if (self.lookup_active) {
        const next = self.lookup.startNext(
            core,
            out,
            request_id,
            now_ms,
            entropy,
        ) catch |err| switch (err) {
            error.PeerBusy, error.TableFull => return null,
            else => return err,
        };
        if (next) |started| {
            self.next_start_ms = now_ms;
            return started;
        }
        if (self.lookup.isFinished()) self.lookup_active = false;
    }
    self.scheduleNext(core, now_ms);
    return null;
}

pub fn knownRecord(self: *const Maintenance, handle: CallTable.Handle) ?*const enr.Record {
    if (self.pending) |*pending| if (std.meta.eql(pending.handle, handle)) return &pending.entry.record;
    if (self.lookup_active) return self.lookup.knownRecord(handle);
    return null;
}

pub fn onEvent(
    self: *Maintenance,
    core: *Engine,
    event: *const Engine.Event,
    now_ms: u64,
) Error!bool {
    switch (event.*) {
        .response => |*response| {
            if (self.pending) |*pending| {
                if (pending.handle) |handle| {
                    if (std.meta.eql(handle, response.matched.handle)) {
                        self.onProbeResponse(core, response, now_ms);
                        self.next_start_ms = now_ms;
                        return true;
                    }
                }
            }
            if (self.lookup_active and self.lookup.ownsCall(response.matched.handle)) {
                try self.lookup.onResponse(core, response, now_ms);
                self.next_start_ms = now_ms;
                self.observeGrowth(core, now_ms);
                return true;
            }
            if (self.pending == null and self.next_start_ms != null and
                response.matched.response == .pong)
            {
                const entry = core.peerRecord(&response.peer.node_id) orelse return false;
                if (!std.meta.eql(entry.peer, response.peer)) return false;
                if (response.matched.response.pong.enr_sequence > entry.record.sequence) {
                    self.pending = .{ .entry = entry, .kind = .enr, .ready_ms = now_ms };
                    self.next_start_ms = now_ms;
                }
            }
        },
        .failed => |failed| return self.onFailure(core, failed.handle, now_ms, .local),
        else => {},
    }
    return false;
}

pub fn onFailure(
    self: *Maintenance,
    core: *Engine,
    handle: CallTable.Handle,
    now_ms: u64,
    reason: Failure,
) bool {
    if (self.pending) |*pending| {
        if (pending.handle) |owned| {
            if (std.meta.eql(handle, owned)) {
                _ = core.cancelCall(handle);
                if (reason == .expired and pending.kind == .ping) {
                    if (pending.attempts < probe_attempts_max) {
                        pending.handle = null;
                        pending.ready_ms = now_ms +| self.config.retry_interval_ms;
                        self.next_start_ms = pending.ready_ms;
                        return true;
                    }
                    _ = core.forgetPeerIfStale(
                        &pending.entry.peer.node_id,
                        pending.entry.last_verified_ms,
                    );
                }
                self.pending = null;
                self.next_start_ms = now_ms;
                return true;
            }
        }
    }
    if (self.lookup_active and self.lookup.ownsCall(handle)) {
        self.lookup.onFailure(core, handle) catch unreachable;
        self.next_start_ms = now_ms;
        return true;
    }
    return false;
}

pub fn cancel(self: *Maintenance, core: *Engine) void {
    if (self.pending) |pending| {
        if (pending.handle) |handle| _ = core.cancelCall(handle);
    }
    if (self.lookup_active) self.lookup.cancel(core);
    self.pending = null;
    self.lookup_active = false;
    self.next_start_ms = null;
}

fn selectProbe(self: *Maintenance, core: *Engine, now_ms: u64) void {
    if (self.pending) |pending| {
        if (pending.handle != null) return;
        if (!core.isPeerBusy(&pending.entry.peer.node_id)) return;
        if (pending.bootstrap) self.bootstrap_due_ms = now_ms;
        self.pending = null;
        self.probe_due_ms = @min(self.probe_due_ms, now_ms);
    }
    if (self.bootstrap.len > 0 and now_ms >= self.bootstrap_due_ms and
        (core.peerCount() == 0 or now_ms -| self.last_growth_ms >= self.config.discovery_stall_ms))
    {
        for (0..self.bootstrap.len) |_| {
            const record = self.bootstrap[self.bootstrap_cursor];
            self.bootstrap_cursor = (self.bootstrap_cursor + 1) % self.bootstrap.len;
            if (!self.ipv6_enabled and record.endpoint().? == .ip6) continue;
            if (std.mem.eql(u8, &record.node_id, &core.localRecord().node_id)) continue;
            if (core.isPeerBusy(&record.node_id)) continue;
            self.bootstrap_due_ms = now_ms +| self.config.bootstrap_interval_ms;
            self.pending = .{ .entry = .{
                .peer = .{ .node_id = record.node_id, .address = record.endpoint().? },
                .record = record,
                .last_verified_ms = 0,
            }, .ready_ms = now_ms, .bootstrap = true };
            return;
        }
        self.bootstrap_due_ms = now_ms +| self.config.retry_interval_ms;
    }
    if (now_ms < self.probe_due_ms) return;
    self.probe_due_ms = now_ms +| self.config.probe_interval_ms;
    const entry = core.maintenanceTarget(
        &self.probe_cursor,
        now_ms,
        self.config.stale_after_ms,
    ) orelse return;
    if (!self.ipv6_enabled and entry.peer.address == .ip6) return;
    if (core.isPeerBusy(&entry.peer.node_id)) return;
    self.pending = .{ .entry = entry, .ready_ms = now_ms };
}

fn onProbeResponse(
    self: *Maintenance,
    core: *Engine,
    response: *const Engine.AuthenticatedResponse,
    now_ms: u64,
) void {
    const pending = &self.pending.?;
    std.debug.assert(std.meta.eql(pending.entry.peer, response.peer));
    switch (pending.kind) {
        .ping => {
            std.debug.assert(response.matched.response == .pong);
            const record = response.record orelse pending.entry.record;
            _ = core.confirmPeer(&response.peer, &record, now_ms) catch {};
            if (pending.bootstrap) self.refresh_due_ms = now_ms;
            self.observeGrowth(core, now_ms);
            const known = core.peerRecord(&response.peer.node_id);
            const sequence = if (known) |entry| entry.record.sequence else record.sequence;
            if (response.matched.response.pong.enr_sequence > sequence) {
                pending.kind = .enr;
                pending.handle = null;
                pending.ready_ms = now_ms;
                pending.attempts = 0;
                return;
            }
        },
        .enr => {
            std.debug.assert(response.matched.response == .nodes);
            for (response.node_records) |*record| {
                if (!std.mem.eql(u8, &record.node_id, &response.peer.node_id)) continue;
                if (record.sequence <= pending.entry.record.sequence) continue;
                _ = core.confirmPeer(&response.peer, record, now_ms) catch {};
            }
            if (!response.matched.terminal) return;
        },
    }
    self.pending = null;
}

fn startRefresh(
    self: *Maintenance,
    core: *Engine,
    now_ms: u64,
    entropy: *const Engine.StartEntropy,
) Error!void {
    self.refresh_due_ms = now_ms +| self.config.refresh_interval_ms;
    var target = core.localRecord().node_id;
    const distance: u16 = @as(u16, 240) + self.bucket_cursor;
    self.bucket_cursor = @intCast((self.bucket_cursor + 1) % RoutingTable.bucket_count);
    const byte_index: usize = (types.distance_max - distance) / 8;
    const mask: u8 = @as(u8, 1) << @as(u3, @intCast((distance - 1) % 8));
    target[byte_index] ^= mask | (entropy.masking_iv[0] & (mask - 1));
    for (byte_index + 1..target.len) |index| target[index] ^= entropy.masking_iv[index % 16];
    var seeds: [Lookup.result_max]RoutingTable.Entry = undefined;
    const closest = core.closestNodes(&target, &seeds);
    if (closest.len == 0) return;
    try self.lookup.init(self.candidates, core.localRecord().node_id, target, closest);
    self.lookup.ipv6_enabled = self.ipv6_enabled;
    self.lookup_active = true;
}

fn observeGrowth(self: *Maintenance, core: *const Engine, now_ms: u64) void {
    const peers = core.peerCount();
    if (peers > self.observed_peers) self.last_growth_ms = now_ms;
    self.observed_peers = peers;
}

fn scheduleNext(self: *Maintenance, core: *const Engine, now_ms: u64) void {
    var next: u64 = std.math.maxInt(u64);
    if (self.pending) |pending| {
        if (pending.handle == null)
            next = @max(pending.ready_ms, now_ms +| self.config.retry_interval_ms);
    } else {
        next = self.probe_due_ms;
        if (self.bootstrap.len > 0) {
            const eligible = if (core.peerCount() == 0)
                self.bootstrap_due_ms
            else
                @max(self.bootstrap_due_ms, self.last_growth_ms +| self.config.discovery_stall_ms);
            next = @min(next, eligible);
        }
    }
    const refresh = if (self.lookup_active)
        now_ms +| self.config.retry_interval_ms
    else
        self.refresh_due_ms;
    next = @min(next, refresh);
    self.next_start_ms = @max(next, now_ms +| 1);
}

comptime {
    std.debug.assert(@sizeOf(Maintenance) <= 1_024);
}
