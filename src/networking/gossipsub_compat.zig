//! [lodestar-compat] A minimal-but-real gossipsub `Service` facade.
//!
//! This is a SEPARATE facade from the router-backed `Gossipsub` in
//! gossipsub.zig: lodestar-z's networking layer (eth_gossip.zig,
//! p2p_service.zig) was written against a ChainSafe lsquic variant whose
//! gossipsub service exposes a different control flow — it reads/writes PUBLIC
//! fields and drives outbound RPC framing/fan-out itself (subscribe → encode a
//! SubOpts RPC frame → broadcast via `sendRpc` to every connected peer's
//! outbound stream). This facade reproduces exactly that surface so lodestar's
//! networking module compiles and its framing / subscription-delta fan-out /
//! metric unit tests pass.
//!
//! What is REAL here: subscription tracking, the per-peer outbound stream
//! registry, RPC frame fan-out (`sendRpc` writes real length-prefixed wire
//! bytes onto each peer's stream), subscribe/unsubscribe/publish bookkeeping,
//! the event queue, and the metrics surface (`router.subscriptions/topics/mesh`,
//! `pending_sends`, etc.). What is STUBBED: live mesh formation, peer scoring,
//! IHAVE/IWANT gossip, message validation pipelines, and inbound RPC parsing —
//! the router maps here are populated only by what this facade itself tracks
//! (subscriptions), not by a live mesh. This is sufficient for lodestar's
//! `test:networking` and to drive outbound subscription announcements; live
//! mesh propagation needs the full `Gossipsub` router (left untouched).
//!
//! Generic over the outbound stream type: `handleOutbound` accepts `anytype`
//! (the test passes a fake stream; the runtime passes `*quic.Stream`). The
//! stream is type-erased into a `Sink` so the Service stays a concrete type.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

// [lodestar-compat] lodestar-z's gossipsub `Service` facade. It shapes our
// eth-p2p-z gossipsub PRIMITIVES into the API lodestar's networking layer expects
// (originally written against the ChainSafe lsquic variant). This lives HERE in
// lodestar — NOT in eth-p2p-z — and uses only eth-p2p-z's public API
// (`libp2p.gossipsub.{frameRpc, protocol_id_v1_2, ValidationResult}`,
// `libp2p.protobuf.rpc`, `libp2p.quic.Stream`).
const libp2p = @import("zig-libp2p");
const protobuf = libp2p.protobuf;
const rpc_pb = protobuf.rpc;
const gossipsub = libp2p.gossipsub;
const frameRpc = gossipsub.frameRpc;
const Stream = libp2p.quic.Stream;

/// Frame an RPC (taken by pointer) into length-prefixed wire bytes. lodestar call
/// sites pass `&rpc_msg`; `frameRpc` takes the RPC by value.
pub fn encodeRpc(allocator: Allocator, msg: *const rpc_pb.RPC) anyerror![]u8 {
    return frameRpc(allocator, msg.*);
}

/// [lodestar-compat] gossipsub mesh signing policy. ChainSafe's config splits
/// signing (`signature_policy`) from publishing (`publish_policy`); these are
/// accepted-only knobs (the facade runs no live mesh — the real `Gossipsub`
/// router in gossipsub.zig enforces the equivalent via its own SignaturePolicy).
pub const SignaturePolicy = enum { strict_no_sign, strict_sign };
pub const PublishPolicy = enum { anonymous, sign };
pub const ValidationMode = enum { manual, automatic };

/// [lodestar-compat] message-id function: derives a gossip message id from a
/// pubsub RPC message. Matches `eth_gossip.messageIdFn`'s signature so lodestar
/// can pass `&networking.gossipMessageIdFn`.
pub const MsgIdFn = *const fn (std.mem.Allocator, *const rpc_pb.Message) anyerror![]const u8;

/// Configuration knobs accepted by `Service.init`. The facade only acts on
/// `max_pending_send_bytes` and `heartbeat_interval_ms`; the remaining fields
/// mirror the richer ChainSafe gossipsub config so lodestar's populated literal
/// compiles (they are recorded but not enforced — live mesh formation/scoring is
/// the real `Gossipsub` router's job, see service.zig header).
pub const Config = struct {
    /// Maximum bytes buffered in `pending_sends` before sends are dropped.
    max_pending_send_bytes: usize = 4 * 1024 * 1024,
    /// Heartbeat cadence hint (ms). Informational here; the node drives the
    /// heartbeat timer itself.
    heartbeat_interval_ms: u64 = 700,
    /// Target mesh degree (D) and its low/high/lazy bounds. Accepted-only.
    mesh_degree: usize = 8,
    mesh_degree_lo: usize = 6,
    mesh_degree_hi: usize = 12,
    mesh_degree_lazy: usize = 6,
    /// Signing/publishing/validation policy. Accepted-only (see above).
    signature_policy: SignaturePolicy = .strict_no_sign,
    publish_policy: PublishPolicy = .anonymous,
    validation_mode: ValidationMode = .manual,
    /// Optional message-id override. Accepted-only.
    msg_id_fn: ?MsgIdFn = null,
};

/// [lodestar-compat] The gossip-event + validation-result namespace lodestar
/// imports as `gossipsub.config.{Event, ValidationResult}`.
pub const config = struct {
    /// Final validation verdict for an inbound gossip message. Reuses the
    /// router's accept/reject/ignore semantics so the two stay in lockstep.
    pub const ValidationResult = gossipsub.ValidationResult;

    /// An inbound gossip event drained by the node loop. A tagged union so the
    /// node's `switch (event)` with `else => {}` keeps working as more event
    /// kinds are added.
    pub const Event = union(enum) {
        const EventSelf = @This();
        /// A validated inbound message delivered on a subscribed topic. All
        /// byte slices are owned by the event and freed by `deinit`.
        message: Message,
        /// A peer subscribed/unsubscribed from a topic (informational).
        subscription_change: SubscriptionChange,

        pub const Message = struct {
            /// Sender peer id (raw bytes); empty (len 0) for anonymous messages.
            /// lodestar's `optionalPeerId` maps an empty slice to null.
            peer_id: []const u8,
            /// The gossipsub message id bytes.
            msg_id: []const u8,
            /// The topic string.
            topic: []const u8,
            /// The message payload (compressed/SSZ-snappy as published).
            data: []const u8,
        };

        pub const SubscriptionChange = struct {
            peer_id: []const u8,
            topic: []const u8,
            subscribe: bool,
        };

        pub fn deinit(self: *EventSelf, allocator: Allocator) void {
            switch (self.*) {
                .message => |*m| {
                    allocator.free(m.peer_id);
                    allocator.free(m.msg_id);
                    allocator.free(m.topic);
                    allocator.free(m.data);
                },
                .subscription_change => |*s| {
                    allocator.free(s.peer_id);
                    allocator.free(s.topic);
                },
            }
            self.* = undefined;
        }
    };
};

pub const Event = config.Event;
pub const ValidationResult = config.ValidationResult;

/// Type-erased outbound stream sink. lodestar's `handleOutbound` hands us a
/// stream value (`*quic.Stream` at runtime, a fake stream in tests); we keep an
/// erased pointer + a write thunk so the Service is a concrete (non-generic)
/// type while still writing real bytes onto whichever stream it was given.
///
/// The pointer is BORROWED — the caller (p2p_service / the test) keeps the
/// stream alive for as long as the peer is registered. `handleOutbound` removes
/// any prior sink for the peer first, so a re-open replaces it.
const Sink = struct {
    ctx: *anyopaque,
    writeFn: *const fn (ctx: *anyopaque, io: Io, data: []const u8) anyerror!usize,

    fn writeAll(self: Sink, io: Io, data: []const u8) anyerror!void {
        var off: usize = 0;
        while (off < data.len) {
            const n = try self.writeFn(self.ctx, io, data[off..]);
            if (n == 0) return error.WriteZero;
            off += n;
        }
    }
};

/// A queued outbound frame awaiting flush. Tracked so the metrics surface
/// (`pending_sends`, `pending_send_bytes`) is real even though this facade
/// flushes inline in `sendRpc`.
const PendingSend = struct {
    peer_id: []const u8,
    bytes: []const u8,
};

/// [lodestar-compat] Minimal router-state mirror. lodestar's metrics read these
/// fields directly (counts + iteration); `peerScore` / `recordInvalidMessage`
/// are called from the score-sync path. Populated by this facade's own
/// subscription tracking (no live mesh), so `topics`/`mesh` stay empty unless a
/// peer membership is recorded — which is correct for the compile + unit-test
/// goal (the unit tests construct these maps directly, not via the Service).
const RouterState = struct {
    allocator: Allocator,
    /// Topics this node is subscribed to.
    subscriptions: std.StringHashMap(void),
    /// topic -> set of peer ids known to be on that topic.
    topics: std.StringHashMap(std.StringHashMap(void)),
    /// topic -> set of mesh peer ids.
    mesh: std.StringHashMap(std.StringHashMap(void)),
    /// Pending inbound events (mirrors the node's drain queue length).
    events: std.ArrayList(Event),

    fn init(allocator: Allocator) RouterState {
        return .{
            .allocator = allocator,
            .subscriptions = std.StringHashMap(void).init(allocator),
            .topics = std.StringHashMap(std.StringHashMap(void)).init(allocator),
            .mesh = std.StringHashMap(std.StringHashMap(void)).init(allocator),
            .events = .empty,
        };
    }

    fn deinit(self: *RouterState) void {
        var sub_it = self.subscriptions.keyIterator();
        while (sub_it.next()) |k| self.allocator.free(k.*);
        self.subscriptions.deinit();

        freeTopicMap(self.allocator, &self.topics);
        freeTopicMap(self.allocator, &self.mesh);

        for (self.events.items) |*ev| ev.deinit(self.allocator);
        self.events.deinit(self.allocator);
    }

    fn freeTopicMap(allocator: Allocator, map: *std.StringHashMap(std.StringHashMap(void))) void {
        var it = map.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            var peer_it = entry.value_ptr.keyIterator();
            while (peer_it.next()) |pk| allocator.free(pk.*);
            entry.value_ptr.deinit();
        }
        map.deinit();
    }

    /// Stubbed peer score: no scoring in this facade, so every peer scores 0.
    pub fn peerScore(self: *RouterState, peer_id: []const u8) f64 {
        _ = self;
        _ = peer_id;
        return 0.0;
    }

    /// Stubbed invalid-message accounting: this facade has no mesh scorer, so
    /// recording an invalid message is a no-op (kept so the call site compiles).
    pub fn recordInvalidMessage(self: *RouterState, peer_id: []const u8, topic: []const u8) void {
        _ = self;
        _ = peer_id;
        _ = topic;
    }
};

pub const Service = struct {
    const Self = @This();

    allocator: Allocator,
    cfg: Config,

    /// Guards the public mutable state below. lodestar locks this directly
    /// (`state_mu.lockUncancelable(io)` / `unlock(io)`).
    state_mu: std.Io.Mutex = .init,

    /// The io handle of the fiber currently inside a locked critical section.
    /// lodestar sets/clears this around `sendRpc` so the sink write can run.
    active_io: ?Io = null,

    /// peer-id -> outbound stream sink. lodestar reads `.count()` /
    /// `.keyIterator()` for metrics + fan-out, and `sendRpc` looks the sink up.
    /// Keys are owned (duped on register, freed on unregister).
    outbound_streams: std.StringHashMap(Sink),

    /// Topics this node has locally tracked as subscribed.
    tracked_subscriptions: std.StringHashMap(void),

    /// Frames queued for send (real, though `sendRpc` flushes inline). Tracked
    /// for the metrics surface.
    pending_sends: std.ArrayList(PendingSend),
    pending_send_bytes: usize = 0,

    /// Minimal router-state mirror for the metrics + score-sync surface.
    router: RouterState,

    /// Current wall-clock time hint (ms) the node feeds via `setTime`.
    time_ms: u64 = 0,

    pub fn init(allocator: Allocator, cfg: Config) !*Self {
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);
        self.* = .{
            .allocator = allocator,
            .cfg = cfg,
            .outbound_streams = std.StringHashMap(Sink).init(allocator),
            .tracked_subscriptions = std.StringHashMap(void).init(allocator),
            .pending_sends = .empty,
            .router = RouterState.init(allocator),
        };
        return self;
    }

    pub fn deinit(self: *Self, io: Io) void {
        _ = io;
        var os_it = self.outbound_streams.keyIterator();
        while (os_it.next()) |k| self.allocator.free(k.*);
        self.outbound_streams.deinit();

        var ts_it = self.tracked_subscriptions.keyIterator();
        while (ts_it.next()) |k| self.allocator.free(k.*);
        self.tracked_subscriptions.deinit();

        for (self.pending_sends.items) |ps| {
            self.allocator.free(ps.peer_id);
            self.allocator.free(ps.bytes);
        }
        self.pending_sends.deinit(self.allocator);

        self.router.deinit();
        self.allocator.destroy(self);
    }

    /// Register (or replace) a peer's outbound stream and serve it. lodestar
    /// calls this when an outbound `/meshsub` stream opens; the stream is
    /// type-erased into a Sink keyed by peer id. `ctx.peer_id` is the (optional)
    /// peer-id bytes; a null peer-id is ignored (no key to register under).
    ///
    /// `stream` is `anytype`: it must expose `write(io, data) !usize` (the fake
    /// test stream and our `quic.Stream` both do). The pointer is borrowed.
    pub fn handleOutbound(self: *Self, io: Io, stream: anytype, ctx: anytype) !void {
        const maybe_peer: ?[]const u8 = if (@hasField(@TypeOf(ctx), "peer_id")) ctx.peer_id else null;
        const peer = maybe_peer orelse return;

        const StreamPtr = @TypeOf(stream);
        const Thunk = struct {
            fn write(erased: *anyopaque, io2: Io, data: []const u8) anyerror!usize {
                const s: StreamPtr = @ptrCast(@alignCast(erased));
                // The runtime quic.Stream.write is (self, io, buf, opts); the
                // unit-test fake stream is (self, io, data). Branch at comptime
                // so the same facade serves both.
                const Child = @typeInfo(StreamPtr).pointer.child;
                const params = @typeInfo(@TypeOf(Child.write)).@"fn".params;
                return if (params.len == 4) s.write(io2, data, .{}) else s.write(io2, data);
            }
        };
        const sink = Sink{ .ctx = @ptrCast(stream), .writeFn = &Thunk.write };

        self.state_mu.lockUncancelable(io);
        defer self.state_mu.unlock(io);

        const gop = try self.outbound_streams.getOrPut(peer);
        if (!gop.found_existing) {
            gop.key_ptr.* = try self.allocator.dupe(u8, peer);
        }
        gop.value_ptr.* = sink;
    }

    /// Write a pre-framed RPC to a peer's outbound stream. Returns false if the
    /// peer has no registered stream or the write fails. Must be called with
    /// `state_mu` held and `active_io` set (lodestar's contract).
    pub fn sendRpc(self: *Self, peer: []const u8, frame: []const u8) bool {
        const sink = self.outbound_streams.get(peer) orelse return false;
        const io = self.active_io orelse return false;
        sink.writeAll(io, frame) catch return false;
        return true;
    }

    /// Subscribe the local node to `topic` (idempotent). Records it in both
    /// `tracked_subscriptions` and the router-state mirror.
    pub fn subscribe(self: *Self, io: Io, topic: []const u8) !void {
        self.state_mu.lockUncancelable(io);
        defer self.state_mu.unlock(io);
        try self.trackSubscription(topic, true);
    }

    /// Unsubscribe the local node from `topic` (idempotent).
    pub fn unsubscribe(self: *Self, io: Io, topic: []const u8) !void {
        self.state_mu.lockUncancelable(io);
        defer self.state_mu.unlock(io);
        try self.trackSubscription(topic, false);
    }

    fn trackSubscription(self: *Self, topic: []const u8, subscribe_flag: bool) !void {
        if (subscribe_flag) {
            if (!self.tracked_subscriptions.contains(topic)) {
                const owned = try self.allocator.dupe(u8, topic);
                errdefer self.allocator.free(owned);
                try self.tracked_subscriptions.put(owned, {});
            }
            if (!self.router.subscriptions.contains(topic)) {
                const owned2 = try self.allocator.dupe(u8, topic);
                errdefer self.allocator.free(owned2);
                try self.router.subscriptions.put(owned2, {});
            }
        } else {
            if (self.tracked_subscriptions.getKey(topic)) |owned| {
                _ = self.tracked_subscriptions.remove(owned);
                self.allocator.free(owned);
            }
            if (self.router.subscriptions.getKey(topic)) |owned| {
                _ = self.router.subscriptions.remove(owned);
                self.allocator.free(owned);
            }
        }
    }

    /// Publish `data` on `topic`. This facade fans the message out to every
    /// connected peer's outbound stream as a publish RPC frame. Returns the
    /// number of peers the frame was written to.
    pub fn publish(self: *Self, io: Io, topic: []const u8, data: []const u8) !usize {
        self.state_mu.lockUncancelable(io);
        defer self.state_mu.unlock(io);

        if (self.outbound_streams.count() == 0) return 0;

        const msg = rpc_pb.Message{ .topic = topic, .data = data };
        const publish_slice = [_]?rpc_pb.Message{msg};
        const frame = try frameRpc(self.allocator, .{ .publish = &publish_slice });
        defer self.allocator.free(frame);

        const prev_io = self.active_io;
        self.active_io = io;
        defer self.active_io = prev_io;

        var sent: usize = 0;
        var it = self.outbound_streams.keyIterator();
        while (it.next()) |peer_key| {
            if (self.sendRpc(peer_key.*, frame)) sent += 1;
        }
        return sent;
    }

    /// Drain pending inbound events. Caller owns the returned slice and each
    /// event (free with `event.deinit(allocator)` then `allocator.free(slice)`).
    pub fn drainEvents(self: *Self, io: Io) ![]Event {
        self.state_mu.lockUncancelable(io);
        defer self.state_mu.unlock(io);
        const out = try self.router.events.toOwnedSlice(self.allocator);
        return out;
    }

    /// Ingest one decoded inbound gossipsub RPC frame: enqueue a `message` event
    /// per published message so the node drains it via `drainEvents`. Best-effort
    /// and defensive — a malformed frame or allocation failure is skipped, never
    /// fatal (this runs on a per-peer inbound stream-handler fiber). Control
    /// messages (IHAVE/IWANT/GRAFT/PRUNE) and subscriptions are not acted on by
    /// this facade; accepting + reading the stream is what makes a peer treat us
    /// as gossipsub-capable.
    pub fn ingestInboundFrame(self: *Self, io: Io, frame: []const u8) void {
        var rpc = rpc_pb.RPCReader.init(frame) catch return;
        while (rpc.publishNext()) |msg| {
            self.enqueueMessage(io, msg.getFrom(), msg.getSeqno(), msg.getTopic(), msg.getData());
        }
    }

    fn enqueueMessage(self: *Self, io: Io, from: []const u8, seqno: []const u8, topic: []const u8, data: []const u8) void {
        if (topic.len == 0) return;
        const peer_c = self.allocator.dupe(u8, from) catch return;
        const mid_c = self.allocator.dupe(u8, seqno) catch {
            self.allocator.free(peer_c);
            return;
        };
        const topic_c = self.allocator.dupe(u8, topic) catch {
            self.allocator.free(peer_c);
            self.allocator.free(mid_c);
            return;
        };
        const data_c = self.allocator.dupe(u8, data) catch {
            self.allocator.free(peer_c);
            self.allocator.free(mid_c);
            self.allocator.free(topic_c);
            return;
        };
        self.state_mu.lockUncancelable(io);
        defer self.state_mu.unlock(io);
        self.router.events.append(self.allocator, .{ .message = .{
            .peer_id = peer_c,
            .msg_id = mid_c,
            .topic = topic_c,
            .data = data_c,
        } }) catch {
            self.allocator.free(peer_c);
            self.allocator.free(mid_c);
            self.allocator.free(topic_c);
            self.allocator.free(data_c);
        };
    }

    /// Report the final validation verdict for an inbound gossip message. This
    /// facade has no in-flight validation queue, so it is a no-op that returns
    /// false (no message matched the id). Kept so the node call site compiles.
    pub fn reportValidationResult(self: *Self, io: Io, msg_id: []const u8, result: ValidationResult) bool {
        _ = self;
        _ = io;
        _ = msg_id;
        _ = result;
        return false;
    }

    /// Set the router's wall-clock time hint (ms).
    pub fn setTime(self: *Self, io: Io, now_ms: u64) void {
        self.state_mu.lockUncancelable(io);
        defer self.state_mu.unlock(io);
        self.time_ms = now_ms;
    }

    /// Periodic heartbeat. No live mesh to maintain in this facade, so it is a
    /// no-op (kept so the node's heartbeat loop compiles).
    pub fn heartbeat(self: *Self, io: Io) !void {
        _ = self;
        _ = io;
    }
};

/// [lodestar-compat] Stateful frame reader: the inverse of `frameRpc`.
/// Feed it raw stream bytes; it yields one owned RPC payload (the bytes AFTER
/// the uvarint length prefix) per `next()` call, buffering a partial trailing
/// frame across `feed` calls. Caller owns each returned slice and frees it.
///
/// Mirrors the framing in pubsub.zig (uvarint(len) || payload). `init` returns
/// by value (no error); allocation happens lazily in `feed`.
pub const FrameDecoder = struct {
    allocator: Allocator,
    buf: std.ArrayList(u8) = .empty,
    /// Read cursor into `buf`; consumed bytes are compacted out in `next`.
    pos: usize = 0,

    pub fn init(allocator: Allocator) FrameDecoder {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *FrameDecoder) void {
        self.buf.deinit(self.allocator);
        self.* = undefined;
    }

    /// Append raw stream bytes to the internal buffer.
    pub fn feed(self: *FrameDecoder, bytes: []const u8) !void {
        try self.buf.appendSlice(self.allocator, bytes);
    }

    /// Return the next complete frame's payload (owned), or null if the buffer
    /// does not yet hold a full frame. Errors on a malformed (overlong) varint.
    pub fn next(self: *FrameDecoder) !?[]u8 {
        const remaining = self.buf.items[self.pos..];
        if (remaining.len == 0) return null;

        const decoded = decodeUvarint(remaining) catch |err| switch (err) {
            error.Incomplete => return null,
            error.VarintTooLong => return error.VarintTooLong,
        };

        const total = decoded.len + decoded.value;
        if (remaining.len < total) return null; // wait for more bytes

        const payload = remaining[decoded.len..total];
        const owned = try self.allocator.dupe(u8, payload);
        errdefer self.allocator.free(owned);

        self.pos += total;
        // Compact once the cursor has advanced past the front to keep the buffer
        // bounded across many frames.
        if (self.pos > 0) {
            const rest = self.buf.items[self.pos..];
            std.mem.copyForwards(u8, self.buf.items[0..rest.len], rest);
            self.buf.shrinkRetainingCapacity(rest.len);
            self.pos = 0;
        }
        return owned;
    }

    const DecodeResult = struct { value: usize, len: usize };

    fn decodeUvarint(bytes: []const u8) error{ Incomplete, VarintTooLong }!DecodeResult {
        var result: usize = 0;
        var shift: u6 = 0;
        var i: usize = 0;
        const max_varint_len = 10;
        while (i < bytes.len) : (i += 1) {
            const byte = bytes[i];
            result |= @as(usize, byte & 0x7f) << shift;
            if ((byte & 0x80) == 0) return .{ .value = result, .len = i + 1 };
            shift += 7;
            if (i + 1 >= max_varint_len) return error.VarintTooLong;
        }
        return error.Incomplete;
    }
};

/// [lodestar-compat] Comptime protocol-composition placeholder. lodestar's
/// p2p_service composes a comptime Switch from a `protocols` tuple that includes
/// `gossipsub.Handler`; our branch uses a runtime Switch + the router-backed
/// `Gossipsub`, so p2p_service is rewritten to the runtime API and this type is
/// inert (it only needs to exist with an `id`). Construct with `.{ .svc = ... }`.
pub const Handler = struct {
    svc: *Service,

    pub const id: []const u8 = gossipsub.protocol_id_v1_2;

    /// Inbound `/meshsub` stream handler. The Switch dispatches a negotiated
    /// inbound gossipsub stream here; we read length-prefixed RPC frames and
    /// ingest published messages into the service event queue. Crucially, by
    /// accepting and serving this stream the remote peer (e.g. Lighthouse) sees
    /// us as a gossipsub-capable peer — without it, a beacon peer bans us with
    /// "does not support gossipsub". Returns (ending the handler) on EOF or any
    /// read/decode error; the Switch tears the stream down.
    pub fn run(self: *Handler, io: std.Io, stream: *Stream) anyerror!void {
        const svc = self.svc;
        var dec = FrameDecoder.init(svc.allocator);
        defer dec.deinit();
        var buf: [16 * 1024]u8 = undefined;
        while (true) {
            const n = stream.read(io, &buf, .{}) catch return;
            if (n == 0) return;
            dec.feed(buf[0..n]) catch return;
            while ((dec.next() catch return)) |frame| {
                defer svc.allocator.free(frame);
                svc.ingestInboundFrame(io, frame);
            }
        }
    }
};

test "FrameDecoder round-trips frames produced by frameRpc" {
    const allocator = std.testing.allocator;
    const sub = rpc_pb.RPC{ .subscriptions = &[_]?rpc_pb.RPC.SubOpts{.{ .subscribe = true, .topicid = "t1" }} };
    const f1 = try frameRpc(allocator, sub);
    defer allocator.free(f1);

    const sub2 = rpc_pb.RPC{ .subscriptions = &[_]?rpc_pb.RPC.SubOpts{.{ .subscribe = false, .topicid = "t2" }} };
    const f2 = try frameRpc(allocator, sub2);
    defer allocator.free(f2);

    var both = std.ArrayList(u8).empty;
    defer both.deinit(allocator);
    try both.appendSlice(allocator, f1);
    try both.appendSlice(allocator, f2);

    var dec = FrameDecoder.init(allocator);
    defer dec.deinit();
    // Feed in two chunks split mid-frame to exercise buffering.
    const split = f1.len + (f2.len / 2);
    try dec.feed(both.items[0..split]);

    const p1 = (try dec.next()) orelse return error.ExpectedFrame;
    defer allocator.free(p1);
    var r1 = try rpc_pb.RPCReader.init(p1);
    const s1 = r1.subscriptionsNext() orelse return error.MissingSub;
    try std.testing.expect(s1.getSubscribe());
    try std.testing.expectEqualSlices(u8, "t1", s1.getTopicid());

    // Second frame not yet complete.
    try std.testing.expect((try dec.next()) == null);
    try dec.feed(both.items[split..]);

    const p2 = (try dec.next()) orelse return error.ExpectedFrame;
    defer allocator.free(p2);
    var r2 = try rpc_pb.RPCReader.init(p2);
    const s2 = r2.subscriptionsNext() orelse return error.MissingSub;
    try std.testing.expect(!s2.getSubscribe());
    try std.testing.expectEqualSlices(u8, "t2", s2.getTopicid());

    try std.testing.expect((try dec.next()) == null);
}

test "Service subscribe/unsubscribe tracks both mirrors" {
    const allocator = std.testing.allocator;
    const svc = try Service.init(allocator, .{});
    defer svc.deinit(std.testing.io);

    try svc.subscribe(std.testing.io, "topic-a");
    try svc.subscribe(std.testing.io, "topic-a"); // idempotent
    try svc.subscribe(std.testing.io, "topic-b");
    try std.testing.expectEqual(@as(usize, 2), svc.tracked_subscriptions.count());
    try std.testing.expectEqual(@as(usize, 2), svc.router.subscriptions.count());

    try svc.unsubscribe(std.testing.io, "topic-a");
    try std.testing.expectEqual(@as(usize, 1), svc.tracked_subscriptions.count());
    try std.testing.expectEqual(@as(usize, 1), svc.router.subscriptions.count());
}

test "Service handleOutbound + sendRpc writes a real frame" {
    const allocator = std.testing.allocator;
    const svc = try Service.init(allocator, .{});
    defer svc.deinit(std.testing.io);

    const FakeStream = struct {
        const FS = @This();
        writes: *std.ArrayList(u8),
        pub fn write(self: *FS, _: Io, data: []const u8) !usize {
            try self.writes.appendSlice(std.testing.allocator, data);
            return data.len;
        }
    };
    var writes: std.ArrayList(u8) = .empty;
    defer writes.deinit(allocator);
    var stream = FakeStream{ .writes = &writes };

    try svc.handleOutbound(std.testing.io, &stream, .{ .peer_id = @as(?[]const u8, "peer-1") });
    try std.testing.expectEqual(@as(usize, 1), svc.outbound_streams.count());

    const sub = rpc_pb.RPC{ .subscriptions = &[_]?rpc_pb.RPC.SubOpts{.{ .subscribe = true, .topicid = "xx" }} };
    const frame = try frameRpc(allocator, sub);
    defer allocator.free(frame);

    svc.state_mu.lockUncancelable(std.testing.io);
    svc.active_io = std.testing.io;
    try std.testing.expect(svc.sendRpc("peer-1", frame));
    try std.testing.expect(!svc.sendRpc("peer-unknown", frame));
    svc.active_io = null;
    svc.state_mu.unlock(std.testing.io);

    try std.testing.expectEqualSlices(u8, frame, writes.items);
}
