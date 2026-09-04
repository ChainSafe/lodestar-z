const std = @import("std");
const engine_mod = @import("../quic/engine.zig");
const negotiate = @import("../negotiate.zig");
const types = @import("../types.zig");
const gossipsub_mod = @import("gossipsub.zig");
const constants = @import("constants.zig");

const Allocator = std.mem.Allocator;
const Engine = engine_mod.Engine;
const Handle = engine_mod.Handle;
const StreamHandle = engine_mod.StreamHandle;
const TransportEvent = engine_mod.Event;
const Now = types.Now;
const Gossipsub = gossipsub_mod.Gossipsub;
const Event = gossipsub_mod.Event;
const MessageId = gossipsub_mod.MessageId;
const Verdict = gossipsub_mod.Verdict;
const meshsub_ids = gossipsub_mod.meshsub_ids;

pub const outcomes_per_pump: usize = 16;

pub const Options = struct {
    gossipsub: gossipsub_mod.Options = .{},
    negotiations_max: u16 = 512,
};

pub const InitError = negotiate.Error || gossipsub_mod.InitError;

/// Composes the multistream negotiator with the gossipsub engine over the
/// persistent per-peer meshsub streams, so a host pumps transport events
/// straight to gossip events. The negotiator lives here today; the shared
/// router of sub-project 4 hoists it up and calls `acceptNegotiated`.
pub const Service = struct {
    allocator: Allocator,
    negotiator: negotiate.Negotiator,
    inner: Gossipsub,
    pending_out: []?StreamHandle,

    pub fn init(allocator: Allocator, options: Options) InitError!Service {
        var negotiator = try negotiate.Negotiator.init(allocator, options.negotiations_max);
        errdefer negotiator.deinit();
        var inner = try Gossipsub.init(allocator, options.gossipsub);
        errdefer inner.deinit();
        const pending_out = try allocator.alloc(?StreamHandle, constants.peers_cap);
        errdefer allocator.free(pending_out);
        @memset(pending_out, null);
        return .{
            .allocator = allocator,
            .negotiator = negotiator,
            .inner = inner,
            .pending_out = pending_out,
        };
    }

    pub fn deinit(self: *Service) void {
        self.allocator.free(self.pending_out);
        self.inner.deinit();
        self.negotiator.deinit();
        self.* = undefined;
    }

    pub fn subscribe(self: *Service, topic: []const u8) bool {
        return self.inner.subscribe(topic);
    }

    pub fn unsubscribe(self: *Service, topic: []const u8) bool {
        return self.inner.unsubscribe(topic);
    }

    pub fn publish(
        self: *Service,
        topic: []const u8,
        ssz: []const u8,
        now: Now,
    ) Gossipsub.PublishError!void {
        return self.inner.publish(topic, ssz, now);
    }

    pub fn report(self: *Service, handle: MessageId, verdict: Verdict) void {
        self.inner.report(handle, verdict);
    }

    pub fn setPeerScore(self: *Service, conn: Handle, value: f64) void {
        self.inner.setPeerScore(conn, value);
    }

    pub fn markDirect(self: *Service, conn: Handle) void {
        self.inner.markDirect(conn);
    }

    pub fn counters(self: *const Service) Gossipsub.Counters {
        return self.inner.counters;
    }

    /// Registers a newly connected peer and opens our outbound meshsub stream.
    pub fn peerConnected(self: *Service, engine: *Engine, conn: Handle, now: Now) void {
        const handle = self.inner.addPeer(conn, .v1_2) orelse return;
        const neg = &self.negotiator;
        const stream = neg.beginOutbound(engine, conn, meshsub_ids[0], now) catch return;
        self.pending_out[handle.index] = stream;
    }

    /// Routes one ready meshsub stream: our own outbound stream becomes the send
    /// side, the peer's stream our receive side. Returns whether it was claimed,
    /// so a shared router can offer the stream to the next protocol otherwise.
    pub fn acceptNegotiated(self: *Service, outcome: negotiate.Outcome) bool {
        const ready = switch (outcome.result) {
            .ready => |r| r,
            else => return false,
        };
        const index = self.inner.state.findPeer(outcome.stream.conn) orelse return false;
        self.inner.setPeerVersion(index, gossipsub_mod.versionFor(ready.protocol_index));
        if (self.pending_out[index]) |out| {
            if (std.meta.eql(out, outcome.stream)) {
                self.inner.setStreams(index, outcome.stream, null);
                self.pending_out[index] = null;
                return true;
            }
        }
        if (!self.inner.receiveHandoff(index, ready.leftover, ready.fin)) return false;
        self.inner.setStreams(index, null, outcome.stream);
        return true;
    }

    pub fn process(
        self: *Service,
        engine: *Engine,
        events: []const TransportEvent,
        now: Now,
        out: []Event,
    ) usize {
        for (events) |event| switch (event) {
            .connected => |connected| self.peerConnected(engine, connected.conn, now),
            .stream_opened => |stream| self.listen(engine, stream, now),
            .closed => |closed| self.inner.connectionClosed(closed.conn),
            else => {},
        };
        var outcomes: [outcomes_per_pump]negotiate.Outcome = undefined;
        const ready = self.negotiator.pump(engine, now, &outcomes);
        for (outcomes[0..ready]) |outcome| switch (outcome.result) {
            .ready => if (!self.acceptNegotiated(outcome)) engine.closeStream(outcome.stream, 0),
            else => {},
        };
        return self.inner.pump(engine, now, out);
    }

    fn listen(self: *Service, engine: *Engine, stream: StreamHandle, now: Now) void {
        self.negotiator.acceptInbound(stream, &meshsub_ids, now) catch {
            engine.closeStream(stream, 0);
        };
    }
};
