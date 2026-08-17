const std = @import("std");
const scoped_log = std.log.scoped(.discv5_runtime_service);
const Allocator = std.mem.Allocator;
const Io = std.Io;

const messages = @import("protocol/message.zig");
const protocol_mod = @import("protocol.zig");
const service_mod = @import("service.zig");
const ingress_mod = @import("service/ingress_queue.zig");

const Address = service_mod.Address;
const Config = service_mod.Config;
const Event = service_mod.Event;
const IngressPacket = ingress_mod.IngressPacket;
const NodeId = service_mod.NodeId;
const Service = service_mod.Service;

pub const RuntimeService = struct {
    service: Service,
    command_queue: CommandQueue,
    command_buffer: []Command,
    event_queue: EventQueue,
    event_buffer: []Event,
    group: Io.Group = .init,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    closed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    dropped_event_count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub const Options = struct {
        command_queue_capacity: usize = 1024,
        event_queue_capacity: usize = 1024,
        maintenance_interval_ms: u64 = 100,
    };

    pub const Error = error{
        AlreadyRunning,
        InvalidQueueCapacity,
        ServiceNotRunning,
        ServiceStopped,
        TooManyDistances,
    };

    const ReqIdResult = anyerror!messages.ReqId;
    const LookupIdResult = anyerror!u32;
    const BoolResult = anyerror!bool;
    const VoidResult = anyerror!void;

    const ReqIdReply = Io.Queue(ReqIdResult);
    const LookupIdReply = Io.Queue(LookupIdResult);
    const BoolReply = Io.Queue(BoolResult);
    const VoidReply = Io.Queue(VoidResult);

    const CommandQueue = Io.Queue(Command);
    const EventQueue = Io.Queue(Event);

    const MAX_FINDNODE_DISTANCES: usize = 127;

    const AddNodeCommand = struct {
        node_id: NodeId,
        pubkey: ?[33]u8,
        addr: Address,
        enr: ?[]u8,
        reply: *VoidReply,
    };

    const AddEnrCommand = struct {
        enr: []u8,
        reply: *BoolReply,
    };

    const SetLocalEnrCommand = struct {
        enr: []u8,
        reply: *VoidReply,
    };

    const SendPingCommand = struct {
        node_id: NodeId,
        pubkey: [33]u8,
        addr: Address,
        enr_seq: u64,
        reply: *ReqIdReply,
    };

    const SendFindNodeCommand = struct {
        node_id: NodeId,
        pubkey: [33]u8,
        addr: Address,
        distances: [MAX_FINDNODE_DISTANCES]u16,
        distances_len: usize,
        reply: *ReqIdReply,
    };

    const SendTalkRequestCommand = struct {
        node_id: NodeId,
        pubkey: [33]u8,
        addr: Address,
        protocol_name: []u8,
        request: []u8,
        reply: *ReqIdReply,
    };

    const SendTalkResponseCommand = struct {
        node_id: NodeId,
        addr: Address,
        req_id: messages.ReqId,
        response: []u8,
        reply: *VoidReply,
    };

    const StartLookupCommand = struct {
        target: NodeId,
        reply: *LookupIdReply,
    };

    const Command = union(enum) {
        inbound_packet: IngressPacket,
        maintenance_tick,
        shutdown,
        add_node: AddNodeCommand,
        add_enr: AddEnrCommand,
        set_local_enr: SetLocalEnrCommand,
        send_ping: SendPingCommand,
        send_findnode: SendFindNodeCommand,
        send_talk_request: SendTalkRequestCommand,
        send_talk_response: SendTalkResponseCommand,
        start_lookup: StartLookupCommand,
        start_random_lookup: *LookupIdReply,
    };

    pub fn init(io: Io, allocator: Allocator, config: Config) !RuntimeService {
        return initWithOptions(io, allocator, config, .{});
    }

    pub fn initWithOptions(io: Io, allocator: Allocator, config: Config, options: Options) !RuntimeService {
        if (options.command_queue_capacity == 0 or options.event_queue_capacity == 0) {
            return Error.InvalidQueueCapacity;
        }

        var service = try Service.init(io, allocator, config);
        errdefer service.deinit();

        const command_buffer = try allocator.alloc(Command, options.command_queue_capacity);
        errdefer allocator.free(command_buffer);

        const event_buffer = try allocator.alloc(Event, options.event_queue_capacity);
        errdefer allocator.free(event_buffer);

        return .{
            .service = service,
            .command_queue = CommandQueue.init(command_buffer),
            .command_buffer = command_buffer,
            .event_queue = EventQueue.init(event_buffer),
            .event_buffer = event_buffer,
        };
    }

    pub fn deinit(self: *RuntimeService) void {
        std.debug.assert(!self.running.load(.acquire));
        self.stop();
        self.event_queue.close(self.service.io);
        self.drainQueuedEvents();
        self.service.allocator.free(self.event_buffer);
        self.service.allocator.free(self.command_buffer);
        self.service.deinit();
    }

    /// Runs the discv5 actor on the caller task and starts concurrent receive
    /// and maintenance loops in the supplied `std.Io` implementation. Schedule
    /// this function with `std.Io.Group.concurrent` when other tasks must call
    /// the service; do not move it to an unrelated OS thread while sharing an
    /// event-loop-backed `std.Io`.
    ///
    /// To shut down, call `stop`, await the caller-owned group so the actor can
    /// drain every accepted command, and then call `deinit`. Do not immediately
    /// cancel the caller-owned group after `stop`; `run` cancels and joins its
    /// own receive and maintenance workers.
    ///
    /// `RuntimeService` is single-shot: after `run` returns, construct a new
    /// instance to restart the runtime.
    pub fn run(self: *RuntimeService, options: Options) (Error || Io.ConcurrentError || Io.Cancelable)!void {
        if (self.closed.load(.acquire)) return Error.ServiceStopped;
        if (self.running.swap(true, .acq_rel)) return Error.AlreadyRunning;
        errdefer self.running.store(false, .release);
        errdefer self.stop();
        errdefer self.event_queue.close(self.service.io);
        errdefer self.group.cancel(self.service.io);

        if (self.service.socketForFamily(.ip4) != null) {
            try self.group.concurrent(self.service.io, receiveLoop, .{ self, Address.Family.ip4 });
        }
        if (self.service.socketForFamily(.ip6) != null) {
            try self.group.concurrent(self.service.io, receiveLoop, .{ self, Address.Family.ip6 });
        }
        try self.group.concurrent(self.service.io, maintenanceLoop, .{ self, options.maintenance_interval_ms });

        self.actorLoop() catch |err| switch (err) {
            error.Canceled => return error.Canceled,
        };

        self.stop();
        self.group.cancel(self.service.io);
        self.event_queue.close(self.service.io);
        self.running.store(false, .release);
    }

    pub fn stop(self: *RuntimeService) void {
        self.closed.store(true, .release);
        self.command_queue.close(self.service.io);
    }

    pub fn isRunning(self: *const RuntimeService) bool {
        return self.running.load(.acquire);
    }

    pub fn droppedEventCount(self: *const RuntimeService) u64 {
        return self.dropped_event_count.load(.acquire);
    }

    pub fn isClosed(self: *const RuntimeService) bool {
        return self.closed.load(.acquire);
    }

    pub fn boundAddress(self: *const RuntimeService, family: Address.Family) ?Address {
        return self.service.boundAddress(family);
    }

    pub fn nextEvent(self: *RuntimeService) (Io.QueueClosedError || Io.Cancelable)!Event {
        return self.event_queue.getOne(self.service.io);
    }

    pub fn popEvent(self: *RuntimeService) ?Event {
        var buffer: [1]Event = undefined;
        const received = self.event_queue.getUncancelable(self.service.io, &buffer, 0) catch return null;
        if (received == 0) return null;
        return buffer[0];
    }

    pub fn addNode(
        self: *RuntimeService,
        node_id: NodeId,
        pubkey: ?*const [33]u8,
        addr: Address,
        enr: ?[]const u8,
    ) !void {
        try self.ensureRunning();

        var owned_enr: ?[]u8 = if (enr) |bytes| try self.service.allocator.dupe(u8, bytes) else null;
        errdefer if (owned_enr) |bytes| self.service.allocator.free(bytes);

        var reply_buffer: [1]VoidResult = undefined;
        var reply = VoidReply.init(&reply_buffer);
        try self.command_queue.putOne(self.service.io, .{ .add_node = .{
            .node_id = node_id,
            .pubkey = if (pubkey) |pk| pk.* else null,
            .addr = addr,
            .enr = owned_enr,
            .reply = &reply,
        } });
        owned_enr = null;

        return try reply.getOneUncancelable(self.service.io);
    }

    pub fn addEnr(self: *RuntimeService, enr: []const u8) !bool {
        try self.ensureRunning();

        var owned_enr: ?[]u8 = try self.service.allocator.dupe(u8, enr);
        errdefer if (owned_enr) |bytes| self.service.allocator.free(bytes);

        var reply_buffer: [1]BoolResult = undefined;
        var reply = BoolReply.init(&reply_buffer);
        try self.command_queue.putOne(self.service.io, .{ .add_enr = .{
            .enr = owned_enr.?,
            .reply = &reply,
        } });
        owned_enr = null;

        return try reply.getOneUncancelable(self.service.io);
    }

    pub fn setLocalEnr(self: *RuntimeService, enr: []const u8) !void {
        try self.ensureRunning();

        var owned_enr: ?[]u8 = try self.service.allocator.dupe(u8, enr);
        errdefer if (owned_enr) |bytes| self.service.allocator.free(bytes);

        var reply_buffer: [1]VoidResult = undefined;
        var reply = VoidReply.init(&reply_buffer);
        try self.command_queue.putOne(self.service.io, .{ .set_local_enr = .{
            .enr = owned_enr.?,
            .reply = &reply,
        } });
        owned_enr = null;

        return try reply.getOneUncancelable(self.service.io);
    }

    pub fn sendPing(
        self: *RuntimeService,
        node_id: *const NodeId,
        pubkey: *const [33]u8,
        addr: Address,
        enr_seq: u64,
    ) !messages.ReqId {
        try self.ensureRunning();

        var reply_buffer: [1]ReqIdResult = undefined;
        var reply = ReqIdReply.init(&reply_buffer);
        try self.command_queue.putOne(self.service.io, .{ .send_ping = .{
            .node_id = node_id.*,
            .pubkey = pubkey.*,
            .addr = addr,
            .enr_seq = enr_seq,
            .reply = &reply,
        } });

        return try reply.getOneUncancelable(self.service.io);
    }

    pub fn sendFindNode(
        self: *RuntimeService,
        node_id: *const NodeId,
        pubkey: *const [33]u8,
        addr: Address,
        distances: []const u16,
    ) !messages.ReqId {
        try self.ensureRunning();
        if (distances.len > MAX_FINDNODE_DISTANCES) return Error.TooManyDistances;

        var copied_distances = [_]u16{0} ** MAX_FINDNODE_DISTANCES;
        @memcpy(copied_distances[0..distances.len], distances);

        var reply_buffer: [1]ReqIdResult = undefined;
        var reply = ReqIdReply.init(&reply_buffer);
        try self.command_queue.putOne(self.service.io, .{ .send_findnode = .{
            .node_id = node_id.*,
            .pubkey = pubkey.*,
            .addr = addr,
            .distances = copied_distances,
            .distances_len = distances.len,
            .reply = &reply,
        } });

        return try reply.getOneUncancelable(self.service.io);
    }

    pub fn sendTalkRequest(
        self: *RuntimeService,
        node_id: *const NodeId,
        pubkey: *const [33]u8,
        addr: Address,
        protocol_name: []const u8,
        request: []const u8,
    ) !messages.ReqId {
        try self.ensureRunning();

        var owned_protocol: ?[]u8 = try self.service.allocator.dupe(u8, protocol_name);
        errdefer if (owned_protocol) |bytes| self.service.allocator.free(bytes);
        var owned_request: ?[]u8 = try self.service.allocator.dupe(u8, request);
        errdefer if (owned_request) |bytes| self.service.allocator.free(bytes);

        var reply_buffer: [1]ReqIdResult = undefined;
        var reply = ReqIdReply.init(&reply_buffer);
        try self.command_queue.putOne(self.service.io, .{ .send_talk_request = .{
            .node_id = node_id.*,
            .pubkey = pubkey.*,
            .addr = addr,
            .protocol_name = owned_protocol.?,
            .request = owned_request.?,
            .reply = &reply,
        } });
        owned_protocol = null;
        owned_request = null;

        return try reply.getOneUncancelable(self.service.io);
    }

    pub fn sendTalkResponse(
        self: *RuntimeService,
        node_id: NodeId,
        addr: Address,
        req_id: messages.ReqId,
        response: []const u8,
    ) !void {
        try self.ensureRunning();

        var owned_response: ?[]u8 = try self.service.allocator.dupe(u8, response);
        errdefer if (owned_response) |bytes| self.service.allocator.free(bytes);

        var reply_buffer: [1]VoidResult = undefined;
        var reply = VoidReply.init(&reply_buffer);
        try self.command_queue.putOne(self.service.io, .{ .send_talk_response = .{
            .node_id = node_id,
            .addr = addr,
            .req_id = req_id,
            .response = owned_response.?,
            .reply = &reply,
        } });
        owned_response = null;

        return try reply.getOneUncancelable(self.service.io);
    }

    pub fn startLookup(self: *RuntimeService, target: *const NodeId) !u32 {
        try self.ensureRunning();

        var reply_buffer: [1]LookupIdResult = undefined;
        var reply = LookupIdReply.init(&reply_buffer);
        try self.command_queue.putOne(self.service.io, .{ .start_lookup = .{
            .target = target.*,
            .reply = &reply,
        } });

        return try reply.getOneUncancelable(self.service.io);
    }

    pub fn startRandomLookup(self: *RuntimeService) !u32 {
        try self.ensureRunning();

        var reply_buffer: [1]LookupIdResult = undefined;
        var reply = LookupIdReply.init(&reply_buffer);
        try self.command_queue.putOne(self.service.io, .{ .start_random_lookup = &reply });

        return try reply.getOneUncancelable(self.service.io);
    }

    fn ensureRunning(self: *RuntimeService) Error!void {
        if (self.closed.load(.acquire)) return Error.ServiceStopped;
        if (!self.running.load(.acquire)) return Error.ServiceNotRunning;
    }

    fn actorLoop(self: *RuntimeService) Io.Cancelable!void {
        while (true) {
            const command = self.command_queue.getOne(self.service.io) catch |err| switch (err) {
                error.Closed => return,
                error.Canceled => return error.Canceled,
            };
            try self.handleCommand(command);
            self.publishServiceEvents() catch return;
        }
    }

    fn handleCommand(self: *RuntimeService, command: Command) Io.Cancelable!void {
        // The reply-driven commands below all mutate protocol state and then
        // surface the resulting protocol events as service events. That drain
        // is hoisted to a single call after the switch. The three arms that
        // return early either drain internally (inbound_packet,
        // maintenance_tick) or intentionally skip it (shutdown).
        switch (command) {
            .inbound_packet => |packet_value| {
                self.service.handleRuntimeInboundPacket(packet_value);
                return;
            },
            .maintenance_tick => {
                self.service.runtimeMaintenanceTick();
                return;
            },
            .shutdown => {
                self.stop();
                return;
            },
            .add_node => |cmd| {
                defer if (cmd.enr) |bytes| self.service.allocator.free(bytes);
                var pubkey = cmd.pubkey;
                self.service.addNode(cmd.node_id, if (pubkey) |*pk| pk else null, cmd.addr, cmd.enr);
                cmd.reply.putOneUncancelable(self.service.io, {}) catch {};
            },
            .add_enr => |cmd| {
                defer self.service.allocator.free(cmd.enr);
                cmd.reply.putOneUncancelable(self.service.io, self.service.addEnr(cmd.enr)) catch {};
            },
            .set_local_enr => |cmd| {
                defer self.service.allocator.free(cmd.enr);
                cmd.reply.putOneUncancelable(self.service.io, self.service.setLocalEnr(cmd.enr)) catch {};
            },
            .send_ping => |cmd| {
                const result = self.service.sendPing(&cmd.node_id, &cmd.pubkey, cmd.addr, cmd.enr_seq);
                cmd.reply.putOneUncancelable(self.service.io, result) catch {};
            },
            .send_findnode => |cmd| {
                var distances = cmd.distances;
                const result = self.service.sendFindNode(
                    &cmd.node_id,
                    &cmd.pubkey,
                    cmd.addr,
                    distances[0..cmd.distances_len],
                );
                cmd.reply.putOneUncancelable(self.service.io, result) catch {};
            },
            .send_talk_request => |cmd| {
                defer self.service.allocator.free(cmd.protocol_name);
                defer self.service.allocator.free(cmd.request);
                const result = self.service.sendTalkRequest(
                    &cmd.node_id,
                    &cmd.pubkey,
                    cmd.addr,
                    cmd.protocol_name,
                    cmd.request,
                );
                cmd.reply.putOneUncancelable(self.service.io, result) catch {};
            },
            .send_talk_response => |cmd| {
                defer self.service.allocator.free(cmd.response);
                const result = self.service.sendTalkResponse(cmd.node_id, cmd.addr, cmd.req_id, cmd.response);
                cmd.reply.putOneUncancelable(self.service.io, result) catch {};
            },
            .start_lookup => |cmd| {
                cmd.reply.putOneUncancelable(self.service.io, self.service.startLookup(&cmd.target)) catch {};
            },
            .start_random_lookup => |reply| {
                reply.putOneUncancelable(self.service.io, self.service.startRandomLookup()) catch {};
            },
        }
        self.service.drainRuntimeProtocolEvents();
    }

    fn publishServiceEvents(self: *RuntimeService) Io.QueueClosedError!void {
        while (self.service.popEvent()) |event| {
            // Never let an undrained consumer stall the actor and strand
            // accepted synchronous commands. Runtime events use an explicit
            // drop-on-full policy, matching the bounded inner service queue.
            const queued = self.event_queue.putUncancelable(self.service.io, &.{event}, 0) catch |err| {
                var owned = event;
                owned.deinit(self.service.allocator);
                self.dropServiceEvents();
                return err;
            };
            if (queued == 0) {
                var owned = event;
                owned.deinit(self.service.allocator);
                const total = self.dropped_event_count.fetchAdd(1, .acq_rel) + 1;
                scoped_log.warn("dropped runtime event under queue pressure (total dropped={d})", .{total});
            }
        }
    }

    fn dropServiceEvents(self: *RuntimeService) void {
        while (self.service.popEvent()) |event| {
            var owned = event;
            owned.deinit(self.service.allocator);
        }
    }

    fn drainQueuedEvents(self: *RuntimeService) void {
        var buffer: [16]Event = undefined;
        while (true) {
            const received = self.event_queue.getUncancelable(self.service.io, &buffer, 0) catch break;
            if (received == 0) break;
            for (buffer[0..received]) |*event| event.deinit(self.service.allocator);
        }
    }

    fn receiveLoop(self: *RuntimeService, family: Address.Family) Io.Cancelable!void {
        const socket = self.service.socketForFamily(family) orelse return;

        var recv_buf: [protocol_mod.MAX_PACKET_SIZE]u8 = undefined;
        while (!self.closed.load(.acquire)) {
            const result = socket.receive(self.service.io, &recv_buf) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => {
                    scoped_log.warn("evented receive failed for {s}: {}", .{ @tagName(family), err });
                    std.Io.sleep(self.service.io, std.Io.Duration.fromMilliseconds(10), .awake) catch return error.Canceled;
                    continue;
                },
            };

            if (!self.service.acceptRuntimeIngress(result.from)) continue;

            var packet = IngressPacket{
                .from = result.from,
                .len = result.data.len,
                .data = undefined,
            };
            @memcpy(packet.data[0..result.data.len], result.data);

            self.command_queue.putOne(self.service.io, .{ .inbound_packet = packet }) catch |err| switch (err) {
                error.Closed => return,
                error.Canceled => return error.Canceled,
            };
        }
    }

    fn maintenanceLoop(self: *RuntimeService, interval_ms: u64) Io.Cancelable!void {
        const sleep_ms = @max(interval_ms, 1);
        while (!self.closed.load(.acquire)) {
            try std.Io.sleep(self.service.io, std.Io.Duration.fromMilliseconds(@intCast(sleep_ms)), .awake);
            self.command_queue.putOne(self.service.io, .maintenance_tick) catch |err| switch (err) {
                error.Closed => return,
                error.Canceled => return error.Canceled,
            };
        }
    }
};

test "runtime stop keeps event queue open until actor teardown" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const secp = @import("secp256k1.zig");
    const enr_mod = @import("enr.zig");

    const sk = [_]u8{0x45} ** 32;
    const key_pair = try secp.keyPairFromSecret(&sk);
    const pk = secp.compressedPubkey(&key_pair);
    const node_id = enr_mod.nodeIdFromCompressedPubkey(&pk);
    var runtime = try RuntimeService.initWithOptions(io, alloc, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .protocol_config = .{ .local_key_pair = key_pair, .local_node_id = node_id },
    }, .{ .command_queue_capacity = 2, .event_queue_capacity = 2 });
    defer runtime.deinit();

    runtime.stop();
    var events: [1]Event = undefined;
    const received = try runtime.event_queue.getUncancelable(io, &events, 0);
    try std.testing.expectEqual(@as(usize, 0), received);
}

test "discv5 runtime service requires concurrent std.Io" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const secp = @import("secp256k1.zig");
    const enr_mod = @import("enr.zig");

    const sk = [_]u8{0x44} ** 32;
    const key_pair = try secp.keyPairFromSecret(&sk);
    const pk = secp.compressedPubkey(&key_pair);
    const node_id = enr_mod.nodeIdFromCompressedPubkey(&pk);

    var runtime = try RuntimeService.initWithOptions(io, alloc, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .protocol_config = .{
            .local_key_pair = key_pair,
            .local_node_id = node_id,
        },
    }, .{
        .command_queue_capacity = 4,
        .event_queue_capacity = 4,
        .maintenance_interval_ms = 1,
    });
    defer runtime.deinit();

    try std.testing.expectError(error.ConcurrencyUnavailable, runtime.run(.{
        .command_queue_capacity = 4,
        .event_queue_capacity = 4,
        .maintenance_interval_ms = 1,
    }));
}
