//! Higher-level discv5 service with integrated lookup orchestration.

const std = @import("std");
const scoped_log = std.log.scoped(.discv5_service);
const Allocator = std.mem.Allocator;
const Io = std.Io;

const enr_mod = @import("enr.zig");
const kbucket = @import("kbucket.zig");
const messages = @import("protocol/message.zig");
const metrics_mod = @import("metrics.zig");
const protocol_mod = @import("protocol.zig");
const rate_limit = @import("rate_limit.zig");
const secp = @import("secp256k1.zig");
const event_queue_mod = @import("event_queue.zig");
const addr_votes_mod = @import("service/addr_votes.zig");
const ingress_mod = @import("service/ingress_queue.zig");
const lookup_mod = @import("service/lookup.zig");
const service_events = @import("service/events.zig");
const util = @import("util.zig");
const net = Io.net;

const bindDatagramSocket = util.bindDatagramSocket;
const shortNodeId = util.shortNodeId;
const currentTimestampNs = util.nowNs;
const currentUnixTimeMs = util.nowMs;

pub const Address = net.IpAddress;
pub const NodeId = enr_mod.NodeId;
pub const Protocol = protocol_mod.Protocol;
pub const DiscoveredEnrEvent = service_events.DiscoveredEnrEvent;
pub const EnrAddedEvent = service_events.EnrAddedEvent;
pub const Event = service_events.Event;
pub const EventKind = service_events.EventKind;
pub const IngressPacket = ingress_mod.IngressPacket;
pub const IngressStatsSnapshot = ingress_mod.IngressStatsSnapshot;
pub const LocalEnrUpdatedEvent = service_events.LocalEnrUpdatedEvent;
pub const LookupFinishedEvent = service_events.LookupFinishedEvent;
pub const PeerConnectedEvent = service_events.PeerConnectedEvent;
pub const PeerDisconnectedEvent = service_events.PeerDisconnectedEvent;

const AddrVotes = addr_votes_mod.AddrVotes;
const IngressQueue = ingress_mod.IngressQueue;
const Lookup = lookup_mod.Lookup;

pub const MAX_LOOKUP_RESULTS: usize = lookup_mod.MAX_RESULTS;

pub const BindAddresses = struct {
    ip4: ?Address = null,
    ip6: ?Address = null,

    fn count(self: *const BindAddresses) usize {
        var total: usize = 0;
        if (self.ip4 != null) total += 1;
        if (self.ip6 != null) total += 1;
        return total;
    }
};

pub const Config = struct {
    bind_addresses: BindAddresses,
    protocol_config: protocol_mod.Config,
    lookup_num_results: usize = MAX_LOOKUP_RESULTS,
    lookup_parallelism: usize = 3,
    lookup_request_limit: usize = 3,
    lookup_timeout_ms: u64 = 60_000,
    receive_timeout_ms: u64 = 1,
    ping_interval_ms: u64 = 30_000,
    enr_update: bool = true,
    addr_votes_to_update_enr: usize = 10,
    ingress_queue_capacity: usize = 1024,
    max_packets_per_poll: usize = 64,
    ingress_worker_timeout_ms: u64 = 50,
    rate_limiter: ?rate_limit.Config = .{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 256 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 64 },
    },
};

const LookupRequestKey = struct {
    peer_id: NodeId,
    req_id: messages.ReqId,

    fn from(peer_id: NodeId, req_id: messages.ReqId) LookupRequestKey {
        return .{
            .peer_id = peer_id,
            .req_id = req_id,
        };
    }
};

const ConnectedPeer = struct {
    addr: Address,
    next_ping_at_ns: i64,
    awaiting_ping_response: bool = false,
};

pub const SetLocalEnrError = Allocator.Error || enr_mod.Error || error{
    WrongNodeId,
    StaleEnrSeq,
    QueueFull,
};

pub const Service = struct {
    allocator: Allocator,
    io: Io,
    config: Config,
    socket_ip4: ?net.Socket = null,
    socket_ip6: ?net.Socket = null,
    protocol: Protocol,
    next_lookup_id: u32 = 1,
    lookup_count: u64 = 0,
    active_lookups: std.AutoHashMap(u32, Lookup),
    request_lookup_ids: std.AutoHashMap(LookupRequestKey, u32),
    expected_response_requests: std.AutoHashMap(LookupRequestKey, Address),
    connected_peers: std.AutoHashMap(NodeId, ConnectedPeer),
    owned_local_enr: ?[]u8 = null,
    addr_votes_ip4: AddrVotes,
    addr_votes_ip6: AddrVotes,
    event_queue: event_queue_mod.EventQueue(Event) = .{},
    dropped_event_count: u64 = 0,
    ingress_queue: IngressQueue,
    ingress_shutdown_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    ingress_thread_ip4: ?std.Thread = null,
    ingress_thread_ip6: ?std.Thread = null,
    ingress_workers_started: bool = false,
    next_socket_poll_family: Address.Family = .ip4,

    pub fn init(io: Io, allocator: Allocator, config: Config) !Service {
        if (config.lookup_num_results == 0 or config.lookup_num_results > lookup_mod.MAX_RESULTS) {
            return error.InvalidLookupNumResults;
        }
        if (config.lookup_parallelism == 0 or config.lookup_parallelism > lookup_mod.MAX_PARALLELISM) {
            return error.InvalidLookupParallelism;
        }
        if (config.bind_addresses.count() == 0) return error.NoBindAddresses;
        if (config.bind_addresses.ip4) |addr| switch (addr) {
            .ip4 => {},
            .ip6 => return error.InvalidBindAddressFamily,
        };
        if (config.bind_addresses.ip6) |addr| switch (addr) {
            .ip4 => return error.InvalidBindAddressFamily,
            .ip6 => {},
        };

        var service_config = config;
        const owned_local_enr = if (service_config.protocol_config.local_enr) |local_enr|
            try allocator.dupe(u8, local_enr)
        else
            null;
        errdefer if (owned_local_enr) |local_enr| allocator.free(local_enr);
        if (owned_local_enr) |local_enr| service_config.protocol_config.local_enr = local_enr;

        var socket_ip4: ?net.Socket = null;
        errdefer if (socket_ip4) |*socket| socket.close(io);
        if (config.bind_addresses.ip4) |addr| {
            socket_ip4 = try bindDatagramSocket(io, addr);
        }

        var socket_ip6: ?net.Socket = null;
        errdefer if (socket_ip6) |*socket| socket.close(io);
        if (config.bind_addresses.ip6) |addr| {
            socket_ip6 = try bindDatagramSocket(io, addr);
        }

        var protocol = try Protocol.init(io, allocator, service_config.protocol_config);
        errdefer protocol.deinit();

        var ingress_queue = try IngressQueue.init(allocator, service_config.ingress_queue_capacity, service_config.rate_limiter);
        errdefer ingress_queue.deinit();

        return .{
            .allocator = allocator,
            .io = io,
            .config = service_config,
            .socket_ip4 = socket_ip4,
            .socket_ip6 = socket_ip6,
            .protocol = protocol,
            .lookup_count = 0,
            .active_lookups = std.AutoHashMap(u32, Lookup).init(allocator),
            .request_lookup_ids = std.AutoHashMap(LookupRequestKey, u32).init(allocator),
            .expected_response_requests = std.AutoHashMap(LookupRequestKey, Address).init(allocator),
            .connected_peers = std.AutoHashMap(NodeId, ConnectedPeer).init(allocator),
            .owned_local_enr = owned_local_enr,
            .addr_votes_ip4 = AddrVotes.init(allocator, service_config.addr_votes_to_update_enr),
            .addr_votes_ip6 = AddrVotes.init(allocator, service_config.addr_votes_to_update_enr),
            .ingress_queue = ingress_queue,
        };
    }

    pub fn deinit(self: *Service) void {
        self.stopIngressWorkers();
        var lookups = self.active_lookups.iterator();
        while (lookups.next()) |entry| entry.value_ptr.deinit(self.allocator);
        self.active_lookups.deinit();
        self.request_lookup_ids.deinit();
        self.expected_response_requests.deinit();
        self.connected_peers.deinit();
        self.addr_votes_ip4.deinit();
        self.addr_votes_ip6.deinit();
        self.event_queue.deinit(self.allocator);
        self.ingress_queue.deinit();
        if (self.owned_local_enr) |local_enr| self.allocator.free(local_enr);
        self.protocol.deinit();
        if (self.socket_ip4) |*socket| socket.close(self.io);
        if (self.socket_ip6) |*socket| socket.close(self.io);
    }

    pub fn addNode(self: *Service, node_id: NodeId, pubkey: ?*const [33]u8, addr: Address, enr: ?[]const u8) void {
        scoped_log.debug("adding node={s} addr={any} has_pubkey={} has_enr={}", .{
            &shortNodeId(&node_id),
            addr,
            pubkey != null,
            enr != null,
        });
        self.protocol.addNode(node_id, pubkey, addr, enr);
    }

    pub fn addEnr(self: *Service, enr_bytes: []const u8) bool {
        const parsed = enr_mod.decode(enr_bytes) catch |err| {
            scoped_log.debug("rejecting ENR: decode failed: {}", .{err});
            return false;
        };

        const node_id = parsed.nodeId() orelse {
            scoped_log.debug("rejecting ENR: missing node id", .{});
            return false;
        };
        const pubkey = parsed.pubkey orelse {
            scoped_log.debug("rejecting ENR for node={s}: missing pubkey", .{&shortNodeId(&node_id)});
            return false;
        };
        const addr = self.contactAddressFromParsedEnr(&parsed) orelse {
            scoped_log.debug("rejecting ENR for node={s}: missing contact address", .{&shortNodeId(&node_id)});
            return false;
        };

        const previous_enr = self.dupeEnr(self.allocator, &node_id) catch null;
        errdefer if (previous_enr) |bytes| self.allocator.free(bytes);

        self.addNode(node_id, &pubkey, addr, enr_bytes);

        const stored_enr = self.findEnr(&node_id) orelse {
            if (previous_enr) |bytes| self.allocator.free(bytes);
            scoped_log.debug("failed to store ENR for node={s} addr={any}", .{ &shortNodeId(&node_id), addr });
            return false;
        };
        if (!std.mem.eql(u8, stored_enr, enr_bytes)) {
            if (previous_enr) |bytes| self.allocator.free(bytes);
            scoped_log.debug("stored ENR for node={s} addr={any} did not match input", .{ &shortNodeId(&node_id), addr });
            return false;
        }
        if (previous_enr) |bytes| {
            if (std.mem.eql(u8, bytes, enr_bytes)) {
                self.allocator.free(bytes);
                scoped_log.debug("ENR already known for node={s} addr={any}", .{ &shortNodeId(&node_id), addr });
                return true;
            }
        }

        const event_enr = self.allocator.dupe(u8, enr_bytes) catch {
            if (previous_enr) |bytes| self.allocator.free(bytes);
            return true;
        };
        scoped_log.debug("accepted ENR for node={s} addr={any} replaced={}", .{
            &shortNodeId(&node_id),
            addr,
            previous_enr != null,
        });
        self.emitEvent(.{
            .enr_added = .{
                .node_id = node_id,
                .addr = addr,
                .enr = event_enr,
                .replaced_enr = previous_enr,
            },
        });
        return true;
    }

    pub fn localEnr(self: *const Service) ?[]const u8 {
        return self.protocol.config.local_enr;
    }

    pub fn localEnrSeq(self: *const Service) u64 {
        return self.protocol.config.local_enr_seq;
    }

    pub fn dupeLocalEnr(self: *const Service, alloc: Allocator) Allocator.Error!?[]u8 {
        const local_enr = self.localEnr() orelse return null;
        return try alloc.dupe(u8, local_enr);
    }

    pub fn setLocalEnr(self: *Service, enr_bytes: []const u8) SetLocalEnrError!void {
        const parsed = try enr_mod.decode(enr_bytes);

        const node_id = parsed.nodeId() orelse return error.InvalidEnr;
        if (!std.mem.eql(u8, &node_id, &self.protocol.config.local_node_id)) return error.WrongNodeId;

        if (self.protocol.config.local_enr) |current| {
            if (std.mem.eql(u8, current, enr_bytes)) return;
        }
        if (parsed.seq <= self.protocol.config.local_enr_seq) return error.StaleEnrSeq;

        try self.commitLocalEnrBytes(try self.allocator.dupe(u8, enr_bytes), parsed.seq, true);
    }

    pub fn findEnr(self: *const Service, node_id: *const NodeId) ?[]const u8 {
        if (std.mem.eql(u8, node_id, &self.protocol.config.local_node_id)) {
            return self.localEnr();
        }
        return self.protocol.findEnr(node_id);
    }

    pub fn dupeEnr(self: *const Service, alloc: Allocator, node_id: *const NodeId) Allocator.Error!?[]u8 {
        const enr_bytes = self.findEnr(node_id) orelse return null;
        return try alloc.dupe(u8, enr_bytes);
    }

    pub fn boundAddress(self: *const Service, family: Address.Family) ?Address {
        return switch (family) {
            .ip4 => if (self.socket_ip4) |socket| socket.address else null,
            .ip6 => if (self.socket_ip6) |socket| socket.address else null,
        };
    }

    pub fn boundPort(self: *const Service, family: Address.Family) ?u16 {
        const addr = self.boundAddress(family) orelse return null;
        return addr.getPort();
    }

    pub fn popEvent(self: *Service) ?Event {
        return self.event_queue.pop();
    }

    /// Publish a completed event to consumers. On allocation or queue pressure the event
    /// is dropped rather than propagated — these call sites run in void
    /// event-draining paths with nothing to unwind to — but the drop is made
    /// observable: the event's owned memory is released, the loss is logged,
    /// and `dropped_event_count` is bumped so embedders can alarm on it.
    fn emitEvent(self: *Service, event: Event) void {
        self.event_queue.push(self.allocator, event) catch {
            var dropped = event;
            dropped.deinit(self.allocator);
            self.dropped_event_count += 1;
            scoped_log.warn("dropped {s} event under queue pressure (total dropped={d})", .{
                @tagName(std.meta.activeTag(event)),
                self.dropped_event_count,
            });
        };
    }

    pub fn knownPeerCount(self: *const Service) usize {
        return self.protocol.routing_table.nodeCount();
    }

    pub fn connectedPeerCount(self: *const Service) usize {
        return self.connected_peers.count();
    }

    fn lookupConfig(self: *const Service) lookup_mod.Config {
        return .{
            .num_results = self.config.lookup_num_results,
            .parallelism = self.config.lookup_parallelism,
            .request_limit = self.config.lookup_request_limit,
            .timeout_ms = self.config.lookup_timeout_ms,
        };
    }

    pub fn metricsSnapshot(self: *Service) metrics_mod.MetricsSnapshot {
        const ingress_stats = self.ingress_queue.snapshot();
        const protocol_metrics = self.protocol.metricsSnapshot();
        return .{
            .kad_table_size = self.knownPeerCount(),
            .active_session_count = self.protocol.activeSessionCount(),
            .connected_peer_count = self.connectedPeerCount(),
            .lookup_count = self.lookup_count,
            .rate_limit_hit_ip = ingress_stats.rate_limit_hit_ip_total,
            .rate_limit_hit_total = ingress_stats.rate_limit_hit_total,
            .sent_message_count = protocol_metrics.sent_message_count,
            .rcvd_message_count = protocol_metrics.rcvd_message_count,
            .dropped_event_count = self.dropped_event_count,
        };
    }

    /// Starts blocking ingress workers on operating-system threads.
    ///
    /// The supplied `std.Io` implementation must be safe to use from those
    /// threads (for example, `std.Io.Threaded`). Event-loop-backed `std.Io`
    /// implementations should use `RuntimeService`, which schedules receive
    /// loops with `std.Io.Group` instead.
    pub fn startIngressWorkers(self: *Service) !void {
        if (self.ingress_workers_started) return;
        self.ingress_shutdown_requested.store(false, .release);
        errdefer self.stopIngressWorkers();
        if (self.socket_ip4 != null) {
            self.ingress_thread_ip4 = try std.Thread.spawn(.{}, ingressWorkerMain, .{ self, Address.Family.ip4 });
        }
        if (self.socket_ip6 != null) {
            self.ingress_thread_ip6 = try std.Thread.spawn(.{}, ingressWorkerMain, .{ self, Address.Family.ip6 });
        }
        self.ingress_workers_started = true;
    }

    pub fn stopIngressWorkers(self: *Service) void {
        self.ingress_shutdown_requested.store(true, .release);
        if (self.ingress_thread_ip4) |thread| {
            thread.join();
            self.ingress_thread_ip4 = null;
        }
        if (self.ingress_thread_ip6) |thread| {
            thread.join();
            self.ingress_thread_ip6 = null;
        }
        self.ingress_workers_started = false;
    }

    pub fn ingressStatsSnapshot(self: *const Service) IngressStatsSnapshot {
        return @constCast(&self.ingress_queue).snapshot();
    }

    pub fn queuedIngressPackets(self: *Service) usize {
        return self.ingress_queue.queuedLen();
    }

    pub fn queueInboundPacketForTest(self: *Service, from: Address, data: []const u8) !void {
        if (!self.ingress_queue.enqueueForTest(from, data)) return error.QueueFull;
    }

    /// Run a received packet through the protocol handler, logging (not
    /// propagating) handler errors. Shared by every ingress path.
    fn dispatchPacket(self: *Service, from: Address, data: []u8, socket: *const net.Socket) void {
        self.protocol.handlePacket(data, from, socket) catch |err| {
            scoped_log.debug("handlePacket failed for {any}: {}", .{ from, err });
        };
    }

    pub fn processQueuedPackets(self: *Service, max_packets: usize) usize {
        var processed: usize = 0;
        while (processed < max_packets) {
            var packet = self.ingress_queue.pop() orelse break;
            const socket = self.socketForAddress(packet.from) orelse continue;
            self.dispatchPacket(packet.from, packet.data[0..packet.len], socket);
            processed += 1;
        }
        const budget_exhausted = processed == max_packets and self.queuedIngressPackets() > 0;
        self.ingress_queue.noteProcessed(processed, budget_exhausted);
        return processed;
    }

    pub fn acceptRuntimeIngress(self: *Service, from: Address) bool {
        return self.ingress_queue.acceptReceived(from, currentUnixTimeMs(self.io));
    }

    pub fn handleRuntimeInboundPacket(self: *Service, packet_value: IngressPacket) void {
        var packet = packet_value;
        const socket = self.socketForAddress(packet.from) orelse return;
        self.dispatchPacket(packet.from, packet.data[0..packet.len], socket);
        self.ingress_queue.noteProcessed(1, false);
        self.drainProtocolEvents();
    }

    pub fn runtimeMaintenanceTick(self: *Service) void {
        self.protocol.pruneExpiredState();
        self.pruneTimedOutLookups();
        self.syncConnectedPeers();
        self.pingDueConnectedPeers();
        self.drainProtocolEvents();
    }

    pub fn drainRuntimeProtocolEvents(self: *Service) void {
        self.drainProtocolEvents();
    }

    pub fn pollIngress(self: *Service) usize {
        const processed = if (self.ingress_workers_started)
            self.processQueuedPackets(self.config.max_packets_per_poll)
        else
            self.pollSocketIngressBudgeted(self.config.max_packets_per_poll);
        self.drainProtocolEvents();
        return processed;
    }

    pub fn poll(self: *Service) void {
        self.drainProtocolEvents();
        _ = self.pollIngress();
        self.protocol.pruneExpiredState();
        self.pruneTimedOutLookups();
        self.syncConnectedPeers();
        self.pingDueConnectedPeers();
        self.drainProtocolEvents();
    }

    pub fn sendPing(self: *Service, node_id: *const NodeId, pubkey: *const [33]u8, addr: Address, enr_seq: u64) !messages.ReqId {
        const socket = self.socketForAddress(addr) orelse return error.NoSocketForAddressFamily;
        const req_id = try self.protocol.sendPing(node_id, pubkey, addr, enr_seq, socket);
        self.noteExpectedResponse(node_id.*, req_id, addr);
        return req_id;
    }

    pub fn sendFindNode(self: *Service, node_id: *const NodeId, pubkey: *const [33]u8, addr: Address, distances: []const u16) !messages.ReqId {
        const socket = self.socketForAddress(addr) orelse return error.NoSocketForAddressFamily;
        const req_id = try self.protocol.sendFindNode(node_id, pubkey, addr, distances, socket);
        self.noteExpectedResponse(node_id.*, req_id, addr);
        return req_id;
    }

    pub fn sendTalkRequest(self: *Service, node_id: *const NodeId, pubkey: *const [33]u8, addr: Address, protocol_name: []const u8, request: []const u8) !messages.ReqId {
        const socket = self.socketForAddress(addr) orelse return error.NoSocketForAddressFamily;
        const req_id = try self.protocol.sendTalkRequest(node_id, pubkey, addr, protocol_name, request, socket);
        self.noteExpectedResponse(node_id.*, req_id, addr);
        return req_id;
    }

    pub fn sendTalkResponse(self: *Service, node_id: NodeId, addr: Address, req_id: messages.ReqId, response: []const u8) !void {
        const socket = self.socketForAddress(addr) orelse return error.NoSocketForAddressFamily;
        try self.protocol.sendTalkResponse(node_id, addr, req_id, response, socket);
    }

    fn noteExpectedResponse(self: *Service, peer_id: NodeId, req_id: messages.ReqId, addr: Address) void {
        self.expected_response_requests.put(LookupRequestKey.from(peer_id, req_id), addr) catch {};
        self.ingress_queue.addExpectedResponse(addr);
    }

    fn removeExpectedResponse(self: *Service, peer_id: NodeId, req_id: messages.ReqId, fallback_addr: ?Address) void {
        const key = LookupRequestKey.from(peer_id, req_id);
        if (self.expected_response_requests.fetchRemove(key)) |entry| {
            self.ingress_queue.removeExpectedResponse(entry.value);
        } else if (fallback_addr) |addr| {
            self.ingress_queue.removeExpectedResponse(addr);
        }
    }

    fn maybeUpdateLocalEnrFromVote(self: *Service, voter_addr: Address, observed_addr: Address) void {
        if (!self.config.enr_update) return;
        if (self.protocol.config.local_enr == null) return;

        const normalized_addr = normalizeObservedAddress(observed_addr);
        var votes = switch (normalized_addr) {
            .ip4 => &self.addr_votes_ip4,
            .ip6 => &self.addr_votes_ip6,
        };

        const is_winning_vote = votes.addVote(normalizeObservedAddress(voter_addr), normalized_addr) catch return;
        if (!is_winning_vote) return;

        const current_addr = self.currentLocalAddressForFamily(switch (normalized_addr) {
            .ip4 => Address.Family.ip4,
            .ip6 => Address.Family.ip6,
        }) orelse {
            self.updateLocalEnrAddress(normalized_addr) catch return;
            return;
        };
        if (current_addr.eql(&normalized_addr)) return;

        self.updateLocalEnrAddress(normalized_addr) catch return;
    }

    fn currentLocalAddressForFamily(self: *Service, family: Address.Family) ?Address {
        const local_enr = self.protocol.config.local_enr orelse return null;
        const parsed = enr_mod.decode(local_enr) catch return null;

        return switch (family) {
            .ip4 => parsed.udpAddress4(),
            .ip6 => parsed.udpAddress6(),
        };
    }

    fn updateLocalEnrAddress(self: *Service, addr: Address) !void {
        const current_enr = self.protocol.config.local_enr orelse return;
        const parsed = try enr_mod.decode(current_enr);

        const next_seq = @max(parsed.seq, self.protocol.config.local_enr_seq) + 1;
        var builder = enr_mod.Builder.init(self.allocator, self.protocol.config.local_key_pair, next_seq);
        builder.ip = parsed.ip;
        builder.udp = parsed.udp;
        builder.tcp = parsed.tcp;
        builder.quic = parsed.quic;
        builder.ip6 = parsed.ip6;
        builder.udp6 = parsed.udp6;
        builder.tcp6 = parsed.tcp6;
        builder.quic6 = parsed.quic6;
        builder.attnets = parsed.attnets;
        builder.syncnets = parsed.syncnets;
        builder.custody_group_count = parsed.custody_group_count;
        builder.eth2 = parsed.eth2_raw;

        switch (addr) {
            .ip4 => |ip4| {
                builder.ip = ip4.bytes;
                builder.udp = ip4.port;
            },
            .ip6 => |ip6| {
                builder.ip6 = ip6.bytes;
                builder.udp6 = ip6.port;
            },
        }

        const updated_enr = try builder.encode();
        try self.commitLocalEnrBytes(updated_enr, next_seq, false);
    }

    fn pingConnectedPeers(self: *Service) void {
        self.syncConnectedPeers();
        const now_ns = currentTimestampNs(self.io);
        var it = self.connected_peers.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.next_ping_at_ns = now_ns;
        }
        self.pingDueConnectedPeers();
    }

    pub fn startLookup(self: *Service, target: *const NodeId) !u32 {
        var closest: [MAX_LOOKUP_RESULTS]kbucket.Entry = undefined;
        const found = self.protocol.routing_table.findClosest(target, MAX_LOOKUP_RESULTS, &closest);

        var seeds: std.ArrayListUnmanaged(NodeId) = .empty;
        defer seeds.deinit(self.allocator);
        for (closest[0..found]) |entry| {
            try seeds.append(self.allocator, entry.node_id);
        }

        const lookup_id = self.next_lookup_id;
        self.next_lookup_id +%= 1;
        if (self.next_lookup_id == 0) self.next_lookup_id = 1;

        {
            var lookup = try Lookup.init(self.allocator, target.*, seeds.items, currentTimestampNs(self.io), self.lookupConfig());
            errdefer lookup.deinit(self.allocator);
            try self.active_lookups.put(lookup_id, lookup);
        }
        self.lookup_count += 1;
        scoped_log.debug("started lookup id={d} target={s} seeds={d}", .{
            lookup_id,
            &shortNodeId(target),
            seeds.items.len,
        });
        self.pumpLookup(lookup_id);
        if (self.active_lookups.getPtr(lookup_id)) |active| {
            if (active.state == .finished) {
                try self.finishLookup(lookup_id, false);
            }
        }
        return lookup_id;
    }

    pub fn startRandomLookup(self: *Service) !u32 {
        var target: NodeId = undefined;
        self.io.random(&target);
        scoped_log.debug("starting random lookup target={s}", .{&shortNodeId(&target)});
        return self.startLookup(&target);
    }

    fn ingressWorkerMain(self: *Service, family: Address.Family) void {
        var recv_buf: [protocol_mod.MAX_PACKET_SIZE]u8 = undefined;
        while (!self.ingress_shutdown_requested.load(.acquire)) {
            const socket = switch (family) {
                .ip4 => if (self.socket_ip4) |*bound| bound else return,
                .ip6 => if (self.socket_ip6) |*bound| bound else return,
            };
            const result = socket.receiveTimeout(self.io, &recv_buf, .{
                .duration = .{
                    .raw = Io.Duration.fromMilliseconds(@intCast(self.config.ingress_worker_timeout_ms)),
                    .clock = .awake,
                },
            }) catch |err| switch (err) {
                error.Timeout => continue,
                else => {
                    scoped_log.warn("discv5 ingress worker receive failed for {s}: {}", .{ @tagName(family), err });
                    std.Io.sleep(self.io, std.Io.Duration.fromMilliseconds(10), .awake) catch {};
                    continue;
                },
            };
            _ = self.ingress_queue.enqueueReceived(result.from, result.data, currentUnixTimeMs(self.io));
        }
    }

    fn pollSocketIngressBudgeted(self: *Service, max_packets: usize) usize {
        if (max_packets == 0) return 0;

        var recv_buf: [protocol_mod.MAX_PACKET_SIZE]u8 = undefined;
        const first_family = self.next_socket_poll_family;
        self.next_socket_poll_family = switch (self.next_socket_poll_family) {
            .ip4 => .ip6,
            .ip6 => .ip4,
        };

        var processed = self.pollSocketIngressFamily(first_family, max_packets, &recv_buf);
        if (processed < max_packets) {
            const second_family: Address.Family = switch (first_family) {
                .ip4 => .ip6,
                .ip6 => .ip4,
            };
            processed += self.pollSocketIngressFamily(second_family, max_packets - processed, &recv_buf);
        }
        return processed;
    }

    fn pollSocketIngressFamily(self: *Service, family: Address.Family, max_packets: usize, recv_buf: []u8) usize {
        if (max_packets == 0) return 0;
        const socket = switch (family) {
            .ip4 => if (self.socket_ip4) |*bound| bound else return 0,
            .ip6 => if (self.socket_ip6) |*bound| bound else return 0,
        };

        var processed: usize = 0;
        while (processed < max_packets) {
            const result = socket.receiveTimeout(self.io, recv_buf, .{
                .duration = .{
                    .raw = Io.Duration.fromMilliseconds(@intCast(self.receiveTimeoutPerSocketMs())),
                    .clock = .awake,
                },
            }) catch |err| switch (err) {
                error.Timeout => break,
                else => break,
            };

            if (!self.ingress_queue.acceptReceived(result.from, currentUnixTimeMs(self.io))) continue;
            self.dispatchPacket(result.from, result.data, socket);
            processed += 1;
        }
        return processed;
    }

    fn drainProtocolEvents(self: *Service) void {
        while (self.protocol.popEvent()) |protocol_event| {
            switch (protocol_event) {
                .pong => |pong| {
                    self.removeExpectedResponse(pong.peer_id, pong.req_id, pong.peer_addr);
                    self.maybeUpdateLocalEnrFromVote(pong.peer_addr, recipientAddress(pong.recipient_ip, pong.recipient_port));
                    self.notePeerResponsive(pong.peer_id, pong.peer_addr);
                    self.maybeRequestPeerEnrUpdate(pong.peer_id, pong.peer_addr, pong.enr_seq);
                    self.emitEvent(.{ .pong = pong });
                },
                .nodes => |nodes| {
                    self.removeExpectedResponse(nodes.peer_id, nodes.req_id, nodes.peer_addr);
                    self.notePeerResponsive(nodes.peer_id, nodes.peer_addr);
                    const lookup_id = self.lookupIdForNodes(&nodes);
                    var discovered_enrs = self.collectDiscoveredEnrs(&nodes);
                    defer discovered_enrs.deinit(self.allocator);
                    self.emitDiscoveredEnrs(&nodes, discovered_enrs.items);
                    self.handleLookupNodes(&nodes, lookup_id, discovered_enrs.items);
                    self.emitEvent(.{ .nodes = nodes });
                },
                .talkreq => |talkreq| {
                    self.notePeerResponsive(talkreq.peer_id, talkreq.peer_addr);
                    self.emitEvent(.{ .talkreq = talkreq });
                },
                .talkresp => |talkresp| {
                    self.removeExpectedResponse(talkresp.peer_id, talkresp.req_id, talkresp.peer_addr);
                    self.notePeerResponsive(talkresp.peer_id, talkresp.peer_addr);
                    self.emitEvent(.{ .talkresp = talkresp });
                },
                .request_timeout => |timeout| {
                    self.removeExpectedResponse(timeout.peer_id, timeout.req_id, null);
                    self.handleLookupTimeout(&timeout);
                    self.handlePeerTimeout(&timeout);
                    self.emitEvent(.{ .request_timeout = timeout });
                },
            }
        }
    }

    fn lookupIdForNodes(self: *const Service, nodes: *const protocol_mod.NodesEvent) ?u32 {
        return self.request_lookup_ids.get(LookupRequestKey.from(nodes.peer_id, nodes.req_id));
    }

    /// A decoded, validated discovered ENR plus its (already computed) node id, so
    /// the lookup feed does not have to recompute `nodeId()` (secp + keccak) per ENR.
    const DiscoveredEnr = struct {
        raw: enr_mod.RawEnr,
        enr: enr_mod.Enr,
        node_id: NodeId,
    };

    fn collectDiscoveredEnrs(self: *Service, nodes: *const protocol_mod.NodesEvent) std.ArrayListUnmanaged(DiscoveredEnr) {
        var discovered_enrs: std.ArrayListUnmanaged(DiscoveredEnr) = .empty;
        for (nodes.enrs) |raw_enr| {
            const parsed = enr_mod.decode(raw_enr) catch continue;

            const node_id = parsed.nodeId() orelse continue;
            if (std.mem.eql(u8, &node_id, &self.protocol.config.local_node_id)) continue;

            if (parsed.udpAddress4() == null and parsed.udpAddress6() == null) continue;

            const raw = enr_mod.RawEnr.init(raw_enr) catch continue;
            discovered_enrs.append(self.allocator, .{ .raw = raw, .enr = parsed, .node_id = node_id }) catch continue;
        }
        return discovered_enrs;
    }

    fn emitDiscoveredEnrs(self: *Service, nodes: *const protocol_mod.NodesEvent, discovered_enrs: []const DiscoveredEnr) void {
        scoped_log.debug("emitting {d} ENRs from {any}", .{
            discovered_enrs.len,
            nodes.peer_addr,
        });
        for (discovered_enrs) |discovered| {
            self.emitEvent(.{ .discovered_enr = .{ .raw = discovered.raw, .enr = discovered.enr } });
        }
    }

    fn handleLookupNodes(self: *Service, nodes: *const protocol_mod.NodesEvent, lookup_id: ?u32, discovered_enrs: []const DiscoveredEnr) void {
        const actual_lookup_id = lookup_id orelse return;
        const key = LookupRequestKey.from(nodes.peer_id, nodes.req_id);
        const removed = self.request_lookup_ids.fetchRemove(key) orelse return;
        if (removed.value != actual_lookup_id) return;
        const lookup_id_value = removed.value;
        const lookup = self.active_lookups.getPtr(lookup_id_value) orelse return;

        var closer_peers: std.ArrayListUnmanaged(NodeId) = .empty;
        defer closer_peers.deinit(self.allocator);
        for (discovered_enrs) |discovered| {
            closer_peers.append(self.allocator, discovered.node_id) catch continue;
        }

        scoped_log.debug("lookup id={d} received {d} candidate ENRs from node={s} addr={any}", .{
            lookup_id_value,
            closer_peers.items.len,
            &shortNodeId(&nodes.peer_id),
            nodes.peer_addr,
        });
        lookup.onSuccess(&nodes.peer_id, closer_peers.items, self.lookupConfig());
        self.pumpLookup(lookup_id_value);
        if (lookup.state == .finished) {
            self.finishLookup(lookup_id_value, false) catch {};
        }
    }

    fn handleLookupTimeout(self: *Service, timeout: *const protocol_mod.RequestTimeoutEvent) void {
        if (timeout.kind != .findnode) return;

        const key = LookupRequestKey.from(timeout.peer_id, timeout.req_id);
        const removed = self.request_lookup_ids.fetchRemove(key) orelse return;
        const lookup_id = removed.value;
        const lookup = self.active_lookups.getPtr(lookup_id) orelse return;

        scoped_log.debug("lookup id={d} request timed out for node={s}", .{
            lookup_id,
            &shortNodeId(&timeout.peer_id),
        });
        lookup.onFailure(&timeout.peer_id, self.lookupConfig());
        self.pumpLookup(lookup_id);
        if (lookup.state == .finished) {
            self.finishLookup(lookup_id, false) catch {};
        }
    }

    fn handlePeerTimeout(self: *Service, timeout: *const protocol_mod.RequestTimeoutEvent) void {
        self.disconnectPeer(timeout.peer_id);
    }

    fn pruneTimedOutLookups(self: *Service) void {
        const now_ns = currentTimestampNs(self.io);

        var timed_out_ids: std.ArrayListUnmanaged(u32) = .empty;
        defer timed_out_ids.deinit(self.allocator);

        var it = self.active_lookups.iterator();
        while (it.next()) |entry| {
            if (!entry.value_ptr.isTimedOut(now_ns, self.lookupConfig())) continue;
            timed_out_ids.append(self.allocator, entry.key_ptr.*) catch break;
        }

        for (timed_out_ids.items) |lookup_id| {
            scoped_log.debug("lookup id={d} reached service timeout", .{lookup_id});
            self.finishLookup(lookup_id, true) catch {};
        }
    }

    fn pumpLookup(self: *Service, lookup_id: u32) void {
        const lookup = self.active_lookups.getPtr(lookup_id) orelse return;

        const lookup_config = self.lookupConfig();
        while (lookup.nextPeer(lookup_config)) |peer_id| {
            const known = self.protocol.getKnownNode(&peer_id) orelse {
                scoped_log.debug("lookup id={d} missing known node={s}", .{ lookup_id, &shortNodeId(&peer_id) });
                lookup.onFailure(&peer_id, lookup_config);
                continue;
            };

            var distances: [127]u16 = undefined;
            const count = lookup_mod.findNodeLogDistances(&lookup.target, &peer_id, @min(lookup_config.request_limit, distances.len), &distances);
            if (count == 0) {
                scoped_log.debug("lookup id={d} no useful distances for node={s}", .{ lookup_id, &shortNodeId(&peer_id) });
                lookup.onFailure(&peer_id, lookup_config);
                continue;
            }

            const req_id = self.protocol.sendFindNode(
                &known.node_id,
                &known.pubkey,
                known.addr,
                distances[0..count],
                self.socketForAddress(known.addr) orelse {
                    scoped_log.debug("lookup id={d} no socket for node={s} addr={any}", .{
                        lookup_id,
                        &shortNodeId(&peer_id),
                        known.addr,
                    });
                    lookup.onFailure(&peer_id, lookup_config);
                    continue;
                },
            ) catch {
                scoped_log.debug("lookup id={d} failed to send FINDNODE to node={s} addr={any}", .{
                    lookup_id,
                    &shortNodeId(&peer_id),
                    known.addr,
                });
                lookup.onFailure(&peer_id, lookup_config);
                continue;
            };
            scoped_log.debug("lookup id={d} sent FINDNODE req_id={x} to node={s} addr={any} distances={d}", .{
                lookup_id,
                req_id.slice(),
                &shortNodeId(&peer_id),
                known.addr,
                count,
            });
            self.request_lookup_ids.put(LookupRequestKey.from(peer_id, req_id), lookup_id) catch {
                scoped_log.debug("lookup id={d} failed to track FINDNODE req_id={x} for node={s}", .{
                    lookup_id,
                    req_id.slice(),
                    &shortNodeId(&peer_id),
                });
                lookup.onFailure(&peer_id, lookup_config);
                continue;
            };
            self.noteExpectedResponse(peer_id, req_id, known.addr);
        }
    }

    fn finishLookup(self: *Service, lookup_id: u32, timed_out: bool) !void {
        const removed = self.active_lookups.fetchRemove(lookup_id) orelse return;
        var lookup = removed.value;
        defer lookup.deinit(self.allocator);

        var stale_requests: std.ArrayListUnmanaged(LookupRequestKey) = .empty;
        defer stale_requests.deinit(self.allocator);
        var request_it = self.request_lookup_ids.iterator();
        while (request_it.next()) |entry| {
            if (entry.value_ptr.* != lookup_id) continue;
            try stale_requests.append(self.allocator, entry.key_ptr.*);
        }
        for (stale_requests.items) |request_key| {
            _ = self.request_lookup_ids.remove(request_key);
        }

        var enrs: std.ArrayListUnmanaged([]u8) = .empty;
        defer {
            for (enrs.items) |enr| self.allocator.free(enr);
            enrs.deinit(self.allocator);
        }

        var succeeded: usize = 0;
        for (lookup.peers.items) |peer| {
            if (peer.state != .succeeded) continue;
            if (succeeded >= self.config.lookup_num_results) break;

            const enr_bytes = self.findEnr(&peer.node_id) orelse continue;
            try enrs.append(self.allocator, try self.allocator.dupe(u8, enr_bytes));
            succeeded += 1;
        }

        const owned_enrs = try enrs.toOwnedSlice(self.allocator);
        enrs = .empty;

        scoped_log.debug("finished lookup id={d} target={s} succeeded={d} enrs={d} timed_out={}", .{
            lookup_id,
            &shortNodeId(&lookup.target),
            succeeded,
            owned_enrs.len,
            timed_out,
        });
        self.emitEvent(.{
            .lookup_finished = .{
                .lookup_id = lookup_id,
                .target = lookup.target,
                .enrs = owned_enrs,
                .timed_out = timed_out,
            },
        });
    }

    fn syncConnectedPeers(self: *Service) void {
        const now_ns = currentTimestampNs(self.io);

        var stale_peers: std.ArrayListUnmanaged(NodeId) = .empty;
        defer stale_peers.deinit(self.allocator);

        var tracked_it = self.connected_peers.iterator();
        while (tracked_it.next()) |entry| {
            const routing_entry = self.routingEntry(&entry.key_ptr.*) orelse {
                stale_peers.append(self.allocator, entry.key_ptr.*) catch continue;
                continue;
            };
            if (routing_entry.status != .connected) {
                stale_peers.append(self.allocator, entry.key_ptr.*) catch continue;
                continue;
            }
            entry.value_ptr.addr = routing_entry.addr;
        }

        for (stale_peers.items) |peer_id| {
            const removed = self.connected_peers.fetchRemove(peer_id) orelse continue;
            self.emitEvent(.{
                .peer_disconnected = .{
                    .peer_id = removed.key,
                    .peer_addr = removed.value.addr,
                },
            });
        }

        for (self.protocol.routing_table.buckets) |*bucket| {
            for (bucket.entries[0..bucket.count]) |entry| {
                if (entry.status != .connected) continue;
                if (self.connected_peers.getPtr(entry.node_id)) |tracked| {
                    tracked.addr = entry.addr;
                    continue;
                }
                self.connected_peers.put(entry.node_id, .{
                    .addr = entry.addr,
                    .next_ping_at_ns = now_ns,
                }) catch continue;
                self.emitEvent(.{
                    .peer_connected = .{
                        .peer_id = entry.node_id,
                        .peer_addr = entry.addr,
                    },
                });
            }
        }
    }

    fn pingDueConnectedPeers(self: *Service) void {
        if (self.config.ping_interval_ms == 0) return;
        const now_ns = currentTimestampNs(self.io);
        const interval_ns: i64 = @intCast(@as(i128, self.config.ping_interval_ms) * std.time.ns_per_ms);

        var it = self.connected_peers.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.awaiting_ping_response) continue;
            if (entry.value_ptr.next_ping_at_ns > now_ns) continue;

            const peer = self.protocol.getKnownNode(&entry.key_ptr.*) orelse {
                entry.value_ptr.next_ping_at_ns = now_ns + interval_ns;
                continue;
            };

            _ = self.protocol.sendPing(
                &peer.node_id,
                &peer.pubkey,
                peer.addr,
                self.protocol.config.local_enr_seq,
                self.socketForAddress(peer.addr) orelse {
                    entry.value_ptr.next_ping_at_ns = now_ns + interval_ns;
                    continue;
                },
            ) catch {
                entry.value_ptr.next_ping_at_ns = now_ns + interval_ns;
                continue;
            };
            entry.value_ptr.addr = peer.addr;
            entry.value_ptr.awaiting_ping_response = true;
            entry.value_ptr.next_ping_at_ns = now_ns + interval_ns;
        }
    }

    fn notePeerResponsive(self: *Service, peer_id: NodeId, peer_addr: Address) void {
        if (self.connected_peers.getPtr(peer_id)) |tracked| {
            tracked.addr = peer_addr;
            tracked.awaiting_ping_response = false;
            tracked.next_ping_at_ns = currentTimestampNs(self.io) +
                @as(i64, @intCast(@as(i128, self.config.ping_interval_ms) * std.time.ns_per_ms));
        }
    }

    fn maybeRequestPeerEnrUpdate(self: *Service, peer_id: NodeId, peer_addr: Address, advertised_seq: u64) void {
        const current_enr = self.findEnr(&peer_id) orelse return;
        const parsed = enr_mod.decode(current_enr) catch return;
        if (parsed.seq >= advertised_seq) return;
        if (self.protocol.hasActiveFindNodeRequest(&peer_id)) return;

        const known = self.protocol.getKnownNode(&peer_id) orelse return;
        const distances = [_]u16{0};
        const req_id = self.protocol.sendFindNode(
            &known.node_id,
            &known.pubkey,
            peer_addr,
            &distances,
            self.socketForAddress(peer_addr) orelse return,
        ) catch return;
        self.noteExpectedResponse(peer_id, req_id, peer_addr);
    }

    fn routingEntry(self: *const Service, node_id: *const NodeId) ?kbucket.Entry {
        const entry = self.protocol.routing_table.getEntry(node_id) orelse return null;
        return entry.*;
    }

    fn disconnectPeer(self: *Service, peer_id: NodeId) void {
        const addr = if (self.connected_peers.get(peer_id)) |tracked|
            tracked.addr
        else if (self.protocol.getKnownNode(&peer_id)) |known|
            known.addr
        else
            return;

        if (self.protocol.routing_table.getEntryWithPending(&peer_id)) |existing| {
            var entry = existing.*;
            entry.addr = addr;
            entry.last_seen = currentTimestampNs(self.io);
            entry.status = .disconnected;
            _ = self.protocol.routing_table.insert(entry);
        }

        const removed = self.connected_peers.fetchRemove(peer_id) orelse return;
        self.emitEvent(.{
            .peer_disconnected = .{
                .peer_id = removed.key,
                .peer_addr = removed.value.addr,
            },
        });
    }

    fn commitLocalEnrBytes(self: *Service, updated_enr: []u8, next_seq: u64, clear_votes: bool) !void {
        errdefer self.allocator.free(updated_enr);

        // Do all fallible work before mutating any state, so a failure here
        // leaves the current local ENR intact and `updated_enr` reclaimed by the
        // errdefer above — never a half-applied update or a freed-but-referenced
        // ENR.
        const event_enr = try self.allocator.dupe(u8, updated_enr);
        errdefer self.allocator.free(event_enr);
        try self.event_queue.push(self.allocator, .{
            .local_enr_updated = .{
                .seq = next_seq,
                .enr = event_enr,
            },
        });

        // From here on nothing can fail: take ownership of `updated_enr` and
        // publish it as the single source of truth for the local ENR. The
        // protocol reads these fields when deciding whether to attach our ENR to
        // handshakes; the service's own `config` snapshot is not consulted at
        // runtime, so it is intentionally not updated here.
        if (clear_votes) {
            self.addr_votes_ip4.clear();
            self.addr_votes_ip6.clear();
        }
        if (self.owned_local_enr) |owned| self.allocator.free(owned);
        self.owned_local_enr = updated_enr;
        self.protocol.config.local_enr = updated_enr;
        self.protocol.config.local_enr_seq = next_seq;

        self.pingConnectedPeers();
    }

    pub fn socketForFamily(self: *Service, family: Address.Family) ?*net.Socket {
        return switch (family) {
            .ip4 => if (self.socket_ip4) |*socket| socket else null,
            .ip6 => if (self.socket_ip6) |*socket| socket else null,
        };
    }

    fn socketForAddress(self: *Service, addr: Address) ?*net.Socket {
        return switch (addr) {
            .ip4 => if (self.socket_ip4) |*socket| socket else null,
            .ip6 => if (self.socket_ip6) |*socket| socket else null,
        };
    }

    fn socketCount(self: *const Service) usize {
        var total: usize = 0;
        if (self.socket_ip4 != null) total += 1;
        if (self.socket_ip6 != null) total += 1;
        return total;
    }

    fn receiveTimeoutPerSocketMs(self: *const Service) u64 {
        if (self.config.receive_timeout_ms == 0) return 0;
        const count = self.socketCount();
        if (count <= 1) return self.config.receive_timeout_ms;
        return @max(self.config.receive_timeout_ms / count, 1);
    }

    fn contactAddressFromParsedEnr(self: *const Service, parsed: *const enr_mod.Enr) ?Address {
        const addr_ip4 = parsed.udpAddress4();
        const addr_ip6 = parsed.udpAddress6();

        if (self.socket_ip4 != null and self.socket_ip6 == null) return addr_ip4 orelse addr_ip6;
        if (self.socket_ip6 != null and self.socket_ip4 == null) return addr_ip6 orelse addr_ip4;
        return addr_ip4 orelse addr_ip6;
    }
};

fn normalizeObservedAddress(addr: Address) Address {
    return switch (addr) {
        .ip4 => addr,
        .ip6 => |ip6| Address.fromIp6(ip6),
    };
}

fn recipientAddress(recipient_ip: messages.Pong.RecipientIp, port: u16) Address {
    return switch (recipient_ip) {
        .ip4 => |ip4| .{ .ip4 = .{ .bytes = ip4, .port = port } },
        .ip6 => |ip6| .{ .ip6 = .{ .bytes = ip6, .port = port } },
    };
}

const TestService = struct {
    service: Service,
    pubkey: [33]u8,
    node_id: NodeId,

    fn init(alloc: Allocator, io: Io, secret_key: [32]u8) !TestService {
        const key_pair = try secp.keyPairFromSecret(&secret_key);
        const pubkey = secp.compressedPubkey(&key_pair);
        const node_id = enr_mod.nodeIdFromCompressedPubkey(&pubkey);

        var service = try Service.init(io, alloc, .{
            .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
            .protocol_config = .{
                .local_key_pair = key_pair,
                .local_node_id = node_id,
            },
            .lookup_timeout_ms = 2_000,
        });
        errdefer service.deinit();

        var builder = enr_mod.Builder.init(alloc, key_pair, 1);
        builder.ip = .{ 127, 0, 0, 1 };
        builder.udp = service.boundPort(.ip4) orelse return error.MissingBindAddress;
        const local_enr = try builder.encode();
        defer alloc.free(local_enr);
        try service.setLocalEnr(local_enr);

        return .{
            .service = service,
            .pubkey = pubkey,
            .node_id = node_id,
        };
    }

    fn deinit(self: *TestService) void {
        self.service.deinit();
    }

    fn addr(self: *const TestService) Address {
        return self.service.boundAddress(.ip4) orelse unreachable;
    }

    fn enr(self: *const TestService) []const u8 {
        return self.service.localEnr() orelse unreachable;
    }

    fn addKnownEnr(self: *TestService, other: *const TestService) !void {
        try std.testing.expect(self.service.addEnr(other.enr()));
    }
};

fn pollServices(services: []const *Service) void {
    for (services) |service| {
        service.poll();
    }
}

fn initServiceForAllocationFailureTest(allocator: Allocator) !void {
    const io = std.Options.debug_io;
    const hex = @import("hex");
    const secret_key = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const key_pair = try secp.keyPairFromSecret(&secret_key);
    const pubkey = secp.compressedPubkey(&key_pair);
    const node_id = enr_mod.nodeIdFromCompressedPubkey(&pubkey);

    var service = try Service.init(io, allocator, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .protocol_config = .{
            .local_key_pair = key_pair,
            .local_node_id = node_id,
            .local_enr = "local-enr",
            .local_enr_seq = 1,
            .session_cache_capacity = 2,
            .challenge_cache_capacity = 2,
            .whoareyou_rate_capacity = 2,
        },
        .ingress_queue_capacity = 2,
        .rate_limiter = null,
    });
    defer service.deinit();
}

test "service init cleans up every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, initServiceForAllocationFailureTest, .{});
}

test "service init validates bind addresses before copying local ENR" {
    const io = std.Options.debug_io;
    const hex = @import("hex");
    const secret_key = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const key_pair = try secp.keyPairFromSecret(&secret_key);
    const pubkey = secp.compressedPubkey(&key_pair);
    const node_id = enr_mod.nodeIdFromCompressedPubkey(&pubkey);
    const protocol_config = protocol_mod.Config{
        .local_key_pair = key_pair,
        .local_node_id = node_id,
        .local_enr = "local-enr",
        .local_enr_seq = 1,
    };

    try std.testing.expectError(error.NoBindAddresses, Service.init(io, std.testing.allocator, .{
        .bind_addresses = .{},
        .protocol_config = protocol_config,
    }));
    try std.testing.expectError(error.InvalidBindAddressFamily, Service.init(io, std.testing.allocator, .{
        .bind_addresses = .{ .ip4 = .{ .ip6 = .{ .bytes = [_]u8{0} ** 16, .port = 0 } } },
        .protocol_config = protocol_config,
    }));
}

test "lookup emits lookup_finished" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex");

    const sk_a = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const key_pair_a = try secp.keyPairFromSecret(&sk_a);
    const pk_a = secp.compressedPubkey(&key_pair_a);
    const node_id_a = enr_mod.nodeIdFromCompressedPubkey(&pk_a);

    const sk_b = hex.hexToBytesComptime(32, "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb14571f7");
    const key_pair_b = try secp.keyPairFromSecret(&sk_b);
    const pk_b = secp.compressedPubkey(&key_pair_b);
    const node_id_b = enr_mod.nodeIdFromCompressedPubkey(&pk_b);

    const sk_c = hex.hexToBytesComptime(32, "7e8107fe766b7f1821c3a7fbc56d18f734f0ebf898f0b85f82412b6d1fa7f4d3");
    const key_pair_c = try secp.keyPairFromSecret(&sk_c);
    const pk_c = secp.compressedPubkey(&key_pair_c);
    const node_id_c = enr_mod.nodeIdFromCompressedPubkey(&pk_c);

    var service_a = try Service.init(io, alloc, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .protocol_config = .{
            .local_key_pair = key_pair_a,
            .local_node_id = node_id_a,
            .request_retries = 0,
        },
        .lookup_timeout_ms = 1_000,
    });
    defer service_a.deinit();

    var socket_b = try bindDatagramSocket(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
    defer socket_b.close(io);

    const addr_b = socket_b.address;
    const addr_c = Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 30305 } };

    var a_builder = enr_mod.Builder.init(alloc, key_pair_a, 1);
    a_builder.ip = .{ 127, 0, 0, 1 };
    const addr_a = service_a.boundAddress(.ip4) orelse return error.MissingBindAddress;
    a_builder.udp = addr_a.getPort();
    const a_enr = try a_builder.encode();
    defer alloc.free(a_enr);
    service_a.protocol.config.local_enr = a_enr;
    service_a.protocol.config.local_enr_seq = 1;

    var b_builder = enr_mod.Builder.init(alloc, key_pair_b, 1);
    b_builder.ip = .{ 127, 0, 0, 1 };
    b_builder.udp = addr_b.getPort();
    const b_enr = try b_builder.encode();
    defer alloc.free(b_enr);

    var c_builder = enr_mod.Builder.init(alloc, key_pair_c, 1);
    c_builder.ip = .{ 127, 0, 0, 1 };
    c_builder.udp = addr_c.getPort();
    const c_enr = try c_builder.encode();
    defer alloc.free(c_enr);

    var proto_b = try Protocol.init(io, alloc, .{
        .local_key_pair = key_pair_b,
        .local_node_id = node_id_b,
        .local_enr = b_enr,
        .local_enr_seq = 1,
    });
    defer proto_b.deinit();

    service_a.addNode(node_id_b, &pk_b, addr_b, b_enr);
    proto_b.addNode(node_id_a, &pk_a, addr_a, a_enr);
    proto_b.addNode(node_id_c, &pk_c, addr_c, c_enr);

    _ = try service_a.startLookup(&node_id_c);

    var recv_buf_a: [protocol_mod.MAX_PACKET_SIZE]u8 = undefined;
    var recv_buf_b: [protocol_mod.MAX_PACKET_SIZE]u8 = undefined;

    const inbound_a = try socket_b.receiveTimeout(io, &recv_buf_b, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_b.handlePacket(inbound_a.data, inbound_a.from, &socket_b);

    service_a.poll();

    const handshake = try socket_b.receiveTimeout(io, &recv_buf_b, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_b.handlePacket(handshake.data, handshake.from, &socket_b);

    const socket_a = service_a.socketForAddress(addr_a) orelse return error.MissingBindAddress;
    const nodes_packet = try socket_a.receiveTimeout(io, &recv_buf_a, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try service_a.protocol.handlePacket(nodes_packet.data, nodes_packet.from, socket_a);
    service_a.poll();

    var saw_lookup_finished = false;
    var saw_discovered_c = false;
    while (service_a.popEvent()) |event| {
        var owned = event;
        defer owned.deinit(alloc);

        switch (owned) {
            .discovered_enr => |discovered| {
                const discovered_node_id = discovered.enr.nodeId() orelse continue;
                if (std.mem.eql(u8, &discovered_node_id, &node_id_c)) {
                    saw_discovered_c = true;
                }
            },
            .lookup_finished => |lookup_finished| {
                saw_lookup_finished = true;
                try std.testing.expect(!lookup_finished.timed_out);

                var saw_b = false;
                for (lookup_finished.enrs) |raw_enr| {
                    const parsed = try enr_mod.decode(raw_enr);
                    const node_id = parsed.nodeId() orelse continue;
                    if (std.mem.eql(u8, &node_id, &node_id_b)) saw_b = true;
                }
                try std.testing.expect(saw_b);
            },
            else => {},
        }
    }

    service_a.protocol.requests.forceAllActiveStartedAtForTest(0);
    service_a.poll();

    while (service_a.popEvent()) |event| {
        var owned = event;
        defer owned.deinit(alloc);

        switch (owned) {
            .discovered_enr => |discovered| {
                const discovered_node_id = discovered.enr.nodeId() orelse continue;
                if (std.mem.eql(u8, &discovered_node_id, &node_id_c)) {
                    saw_discovered_c = true;
                }
            },
            .lookup_finished => |lookup_finished| {
                saw_lookup_finished = true;
                try std.testing.expect(!lookup_finished.timed_out);

                var saw_b = false;
                for (lookup_finished.enrs) |raw_enr| {
                    const parsed = try enr_mod.decode(raw_enr);
                    const node_id = parsed.nodeId() orelse continue;
                    if (std.mem.eql(u8, &node_id, &node_id_b)) saw_b = true;
                }
                try std.testing.expect(saw_b);
            },
            else => {},
        }
    }

    const known_c = service_a.findEnr(&node_id_c) orelse return error.MissingDiscoveredEnr;
    try std.testing.expectEqualSlices(u8, c_enr, known_c);
    try std.testing.expect(saw_discovered_c);
    try std.testing.expect(saw_lookup_finished);
}

test "connected peers are pinged and disconnected on timeout" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex");

    const sk_a = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const key_pair_a = try secp.keyPairFromSecret(&sk_a);
    const pk_a = secp.compressedPubkey(&key_pair_a);
    const node_id_a = enr_mod.nodeIdFromCompressedPubkey(&pk_a);

    const sk_b = hex.hexToBytesComptime(32, "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb14571f7");
    const key_pair_b = try secp.keyPairFromSecret(&sk_b);
    const pk_b = secp.compressedPubkey(&key_pair_b);
    const node_id_b = enr_mod.nodeIdFromCompressedPubkey(&pk_b);

    var service_a = try Service.init(io, alloc, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .protocol_config = .{
            .local_key_pair = key_pair_a,
            .local_node_id = node_id_a,
            .request_timeout_ms = 1_000,
            .request_retries = 0,
        },
        .ping_interval_ms = 30_000,
    });
    defer service_a.deinit();

    var socket_b = try bindDatagramSocket(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
    defer socket_b.close(io);

    const addr_b = socket_b.address;

    var a_builder = enr_mod.Builder.init(alloc, key_pair_a, 1);
    a_builder.ip = .{ 127, 0, 0, 1 };
    const addr_a = service_a.boundAddress(.ip4) orelse return error.MissingBindAddress;
    a_builder.udp = addr_a.getPort();
    const a_enr = try a_builder.encode();
    defer alloc.free(a_enr);
    try service_a.setLocalEnr(a_enr);

    var b_builder = enr_mod.Builder.init(alloc, key_pair_b, 1);
    b_builder.ip = .{ 127, 0, 0, 1 };
    b_builder.udp = addr_b.getPort();
    const b_enr = try b_builder.encode();
    defer alloc.free(b_enr);

    var proto_b = try Protocol.init(io, alloc, .{
        .local_key_pair = key_pair_b,
        .local_node_id = node_id_b,
        .local_enr = b_enr,
        .local_enr_seq = 1,
    });
    defer proto_b.deinit();

    service_a.addNode(node_id_b, &pk_b, addr_b, b_enr);
    proto_b.addNode(node_id_a, &pk_a, addr_a, a_enr);

    _ = try service_a.sendPing(&node_id_b, &pk_b, addr_b, service_a.localEnrSeq());

    var recv_buf_a: [protocol_mod.MAX_PACKET_SIZE]u8 = undefined;
    var recv_buf_b: [protocol_mod.MAX_PACKET_SIZE]u8 = undefined;

    const inbound_a = try socket_b.receiveTimeout(io, &recv_buf_b, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_b.handlePacket(inbound_a.data, inbound_a.from, &socket_b);
    service_a.poll();

    const handshake = try socket_b.receiveTimeout(io, &recv_buf_b, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_b.handlePacket(handshake.data, handshake.from, &socket_b);

    const socket_a = service_a.socketForAddress(addr_a) orelse return error.MissingBindAddress;
    const pong_packet = try socket_a.receiveTimeout(io, &recv_buf_a, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try service_a.protocol.handlePacket(pong_packet.data, pong_packet.from, socket_a);
    service_a.poll();

    try std.testing.expectEqual(@as(usize, 1), service_a.connectedPeerCount());

    var saw_connected = false;
    while (service_a.popEvent()) |event| {
        var owned = event;
        defer owned.deinit(alloc);

        switch (owned) {
            .peer_connected => |connected| {
                saw_connected = true;
                try std.testing.expectEqual(node_id_b, connected.peer_id);
                try std.testing.expectEqual(addr_b, connected.peer_addr);
            },
            else => {},
        }
    }
    try std.testing.expect(saw_connected);

    try std.testing.expect(service_a.protocol.requests.activeCount() > 0);
    service_a.protocol.requests.forceAllActiveStartedAtForTest(0);

    service_a.poll();

    try std.testing.expectEqual(@as(usize, 0), service_a.connectedPeerCount());

    var saw_timeout = false;
    var saw_disconnected = false;
    while (service_a.popEvent()) |event| {
        var owned = event;
        defer owned.deinit(alloc);

        switch (owned) {
            .request_timeout => |timeout| {
                if (std.mem.eql(u8, &timeout.peer_id, &node_id_b)) {
                    saw_timeout = true;
                    try std.testing.expectEqual(protocol_mod.RequestKind.ping, timeout.kind);
                }
            },
            .peer_disconnected => |disconnected| {
                saw_disconnected = true;
                try std.testing.expectEqual(node_id_b, disconnected.peer_id);
                try std.testing.expectEqual(addr_b, disconnected.peer_addr);
            },
            else => {},
        }
    }

    try std.testing.expect(saw_timeout);
    try std.testing.expect(saw_disconnected);
}

test "setLocalEnr exposes current local ENR" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex");

    const sk = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const key_pair = try secp.keyPairFromSecret(&sk);
    const pk = secp.compressedPubkey(&key_pair);
    const node_id = enr_mod.nodeIdFromCompressedPubkey(&pk);

    var builder = enr_mod.Builder.init(alloc, key_pair, 1);
    builder.ip = .{ 10, 0, 0, 1 };
    builder.udp = 9000;
    builder.tcp = 9000;
    const local_enr = try builder.encode();
    defer alloc.free(local_enr);

    var service = try Service.init(io, alloc, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .protocol_config = .{
            .local_key_pair = key_pair,
            .local_node_id = node_id,
            .local_enr = local_enr,
            .local_enr_seq = 1,
        },
    });
    defer service.deinit();

    try std.testing.expectEqualSlices(u8, local_enr, service.localEnr().?);

    var updated_builder = enr_mod.Builder.init(alloc, key_pair, 2);
    updated_builder.ip = .{ 203, 0, 113, 9 };
    updated_builder.udp = 30303;
    updated_builder.tcp = 9000;
    updated_builder.ip6 = [_]u8{0} ** 16;
    updated_builder.udp6 = 9001;
    const updated_enr = try updated_builder.encode();
    defer alloc.free(updated_enr);

    try service.setLocalEnr(updated_enr);
    try std.testing.expectEqualSlices(u8, updated_enr, service.localEnr().?);
    try std.testing.expectEqual(@as(u64, 2), service.localEnrSeq());

    const local_enr_copy = (try service.dupeLocalEnr(alloc)) orelse return error.MissingLocalEnr;
    defer alloc.free(local_enr_copy);
    try std.testing.expectEqualSlices(u8, updated_enr, local_enr_copy);

    var stale_builder = enr_mod.Builder.init(alloc, key_pair, 2);
    stale_builder.ip = .{ 198, 51, 100, 2 };
    stale_builder.udp = 40404;
    const stale_enr = try stale_builder.encode();
    defer alloc.free(stale_enr);
    try std.testing.expectError(error.StaleEnrSeq, service.setLocalEnr(stale_enr));

    const other_sk = hex.hexToBytesComptime(32, "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb14571f7");
    const other_key_pair = try secp.keyPairFromSecret(&other_sk);
    var foreign_builder = enr_mod.Builder.init(alloc, other_key_pair, 3);
    foreign_builder.ip = .{ 192, 0, 2, 10 };
    foreign_builder.udp = 50505;
    const foreign_enr = try foreign_builder.encode();
    defer alloc.free(foreign_enr);
    try std.testing.expectError(error.WrongNodeId, service.setLocalEnr(foreign_enr));

    var saw_update_event = false;
    while (service.popEvent()) |event| {
        var owned = event;
        defer owned.deinit(alloc);
        if (owned == .local_enr_updated) {
            saw_update_event = true;
            try std.testing.expectEqual(@as(u64, 2), owned.local_enr_updated.seq);
            try std.testing.expectEqualSlices(u8, updated_enr, owned.local_enr_updated.enr);
        }
    }
    try std.testing.expect(saw_update_event);
}

test "dual bind exposes both listener families" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex");

    const sk = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const key_pair = try secp.keyPairFromSecret(&sk);
    const pk = secp.compressedPubkey(&key_pair);
    const node_id = enr_mod.nodeIdFromCompressedPubkey(&pk);

    var service = try Service.init(io, alloc, .{
        .bind_addresses = .{
            .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } },
            .ip6 = .{ .ip6 = .{ .bytes = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, .port = 0 } },
        },
        .protocol_config = .{
            .local_key_pair = key_pair,
            .local_node_id = node_id,
        },
    });
    defer service.deinit();

    try std.testing.expect(service.boundPort(.ip4) != null);
    try std.testing.expect(service.boundPort(.ip6) != null);
    try std.testing.expect(service.boundAddress(.ip4) != null);
    try std.testing.expect(service.boundAddress(.ip6) != null);
}

test "addEnr prefers available bind family" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex");

    const sk_local = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const key_pair_local = try secp.keyPairFromSecret(&sk_local);
    const pk_local = secp.compressedPubkey(&key_pair_local);
    const node_id_local = enr_mod.nodeIdFromCompressedPubkey(&pk_local);

    const sk_peer = hex.hexToBytesComptime(32, "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb14571f7");
    const key_pair_peer = try secp.keyPairFromSecret(&sk_peer);
    const loopback6 = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    var builder = enr_mod.Builder.init(alloc, key_pair_peer, 1);
    builder.ip = .{ 127, 0, 0, 1 };
    builder.udp = 30303;
    builder.ip6 = loopback6;
    builder.udp6 = 30304;
    const peer_enr = try builder.encode();
    defer alloc.free(peer_enr);

    var service = try Service.init(io, alloc, .{
        .bind_addresses = .{
            .ip6 = .{ .ip6 = .{ .bytes = loopback6, .port = 0 } },
        },
        .protocol_config = .{
            .local_key_pair = key_pair_local,
            .local_node_id = node_id_local,
        },
    });
    defer service.deinit();

    try std.testing.expect(service.addEnr(peer_enr));

    const parsed = try enr_mod.decode(peer_enr);
    const peer_id = parsed.nodeId() orelse return error.MissingNodeId;
    const known = service.protocol.getKnownNode(&peer_id) orelse return error.UnknownNode;
    switch (known.addr) {
        .ip6 => |ip6| {
            try std.testing.expectEqual(loopback6, ip6.bytes);
            try std.testing.expectEqual(@as(u16, 30304), ip6.port);
        },
        .ip4 => return error.WrongAddressFamily,
    }
}

test "discovered nodes use discv5 UDP ports and retain QUIC availability" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex");

    const local_sk = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const local_key_pair = try secp.keyPairFromSecret(&local_sk);
    const local_pk = secp.compressedPubkey(&local_key_pair);
    const local_node_id = enr_mod.nodeIdFromCompressedPubkey(&local_pk);
    const source_sk = hex.hexToBytesComptime(32, "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb14571f7");
    const source_key_pair = try secp.keyPairFromSecret(&source_sk);
    const source_pk = secp.compressedPubkey(&source_key_pair);
    const source_node_id = enr_mod.nodeIdFromCompressedPubkey(&source_pk);

    const loopback6 = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

    var service = try Service.init(io, alloc, .{
        .bind_addresses = .{
            .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } },
            .ip6 = .{ .ip6 = .{ .bytes = loopback6, .port = 0 } },
        },
        .protocol_config = .{
            .local_key_pair = local_key_pair,
            .local_node_id = local_node_id,
        },
    });
    defer service.deinit();

    var peer_builder = enr_mod.Builder.init(alloc, source_key_pair, 1);
    peer_builder.ip = .{ 127, 0, 0, 1 };
    peer_builder.udp = 30303;
    peer_builder.tcp = 30304;
    peer_builder.quic = 30305;
    peer_builder.ip6 = loopback6;
    peer_builder.udp6 = 30403;
    peer_builder.tcp6 = 30404;
    peer_builder.quic6 = 30405;
    const peer_enr = try peer_builder.encode();
    defer alloc.free(peer_enr);

    var owned_enrs = try alloc.alloc([]u8, 1);
    defer {
        for (owned_enrs) |enr| alloc.free(enr);
        alloc.free(owned_enrs);
    }
    owned_enrs[0] = try alloc.dupe(u8, peer_enr);

    const source_addr = Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9000 } };
    var nodes = protocol_mod.NodesEvent{
        .peer_id = source_node_id,
        .peer_addr = source_addr,
        .req_id = .{ .bytes = [8]u8{ 0, 0, 0, 1, 0, 0, 0, 0 }, .len = 4 },
        .enrs = owned_enrs,
    };

    var discovered_enrs = service.collectDiscoveredEnrs(&nodes);
    defer discovered_enrs.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 1), discovered_enrs.items.len);
    const parsed = discovered_enrs.items[0].enr;
    try std.testing.expectEqualSlices(u8, peer_enr, discovered_enrs.items[0].raw.slice());
    try std.testing.expect(parsed.quic != null or parsed.quic6 != null);
    try std.testing.expectEqual(@as(?u16, 30303), parsed.udp);
    try std.testing.expectEqual(@as(?u16, 30403), parsed.udp6);
}

test "addr votes update local ENR" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex");

    const sk = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const key_pair = try secp.keyPairFromSecret(&sk);
    const pk = secp.compressedPubkey(&key_pair);
    const node_id = enr_mod.nodeIdFromCompressedPubkey(&pk);

    var builder = enr_mod.Builder.init(alloc, key_pair, 1);
    builder.ip = .{ 10, 0, 0, 1 };
    builder.udp = 9000;
    builder.tcp = 9000;
    builder.ip6 = [_]u8{0} ** 16;
    builder.udp6 = 9001;
    const local_enr = try builder.encode();
    defer alloc.free(local_enr);

    var service = try Service.init(io, alloc, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .protocol_config = .{
            .local_key_pair = key_pair,
            .local_node_id = node_id,
            .local_enr = local_enr,
            .local_enr_seq = 1,
        },
        .addr_votes_to_update_enr = 2,
    });
    defer service.deinit();

    service.maybeUpdateLocalEnrFromVote(.{ .ip4 = .{ .bytes = .{ 198, 51, 100, 11 }, .port = 1001 } }, .{ .ip4 = .{ .bytes = .{ 203, 0, 113, 1 }, .port = 30303 } });
    try std.testing.expectEqual(@as(u64, 1), service.localEnrSeq());

    service.maybeUpdateLocalEnrFromVote(.{ .ip4 = .{ .bytes = .{ 198, 51, 100, 22 }, .port = 1002 } }, .{ .ip4 = .{ .bytes = .{ 203, 0, 113, 1 }, .port = 30303 } });
    try std.testing.expectEqual(@as(u64, 2), service.localEnrSeq());

    const updated = try enr_mod.decode(service.localEnr().?);
    try std.testing.expectEqual([4]u8{ 203, 0, 113, 1 }, updated.ip.?);
    try std.testing.expectEqual(@as(?u16, 30303), updated.udp);
    try std.testing.expectEqual(@as(?u16, 9000), updated.tcp);
    try std.testing.expectEqual(@as(?u16, 9001), updated.udp6);

    var saw_update_event = false;
    while (service.popEvent()) |event| {
        var owned = event;
        defer owned.deinit(alloc);
        if (owned == .local_enr_updated) {
            saw_update_event = true;
            try std.testing.expectEqual(@as(u64, 2), owned.local_enr_updated.seq);
        }
    }
    try std.testing.expect(saw_update_event);
}

test "ipv4-mapped ipv6 vote normalizes to ipv4" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex");

    const sk = hex.hexToBytesComptime(32, "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb14571f7");
    const key_pair = try secp.keyPairFromSecret(&sk);
    const pk = secp.compressedPubkey(&key_pair);
    const node_id = enr_mod.nodeIdFromCompressedPubkey(&pk);

    var builder = enr_mod.Builder.init(alloc, key_pair, 1);
    builder.ip = .{ 10, 0, 0, 1 };
    builder.udp = 9000;
    const local_enr = try builder.encode();
    defer alloc.free(local_enr);

    var service = try Service.init(io, alloc, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .protocol_config = .{
            .local_key_pair = key_pair,
            .local_node_id = node_id,
            .local_enr = local_enr,
            .local_enr_seq = 1,
        },
        .addr_votes_to_update_enr = 1,
    });
    defer service.deinit();

    service.maybeUpdateLocalEnrFromVote(.{ .ip4 = .{ .bytes = .{ 198, 51, 100, 33 }, .port = 1003 } }, .{
        .ip6 = .{
            .bytes = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 198, 51, 100, 2 },
            .port = 40404,
        },
    });

    const updated = try enr_mod.decode(service.localEnr().?);
    try std.testing.expectEqual([4]u8{ 198, 51, 100, 2 }, updated.ip.?);
    try std.testing.expectEqual(@as(?u16, 40404), updated.udp);
}

test "live lookup discovers node through intermediary" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex");

    const sk_0 = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const sk_1 = hex.hexToBytesComptime(32, "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb14571f7");
    const sk_2 = hex.hexToBytesComptime(32, "7e8107fe766b7f1821c3a7fbc56d18f734f0ebf898f0b85f82412b6d1fa7f4d3");

    var node_0 = try TestService.init(alloc, io, sk_0);
    defer node_0.deinit();
    var node_1 = try TestService.init(alloc, io, sk_1);
    defer node_1.deinit();
    var node_2 = try TestService.init(alloc, io, sk_2);
    defer node_2.deinit();

    try node_0.addKnownEnr(&node_1);
    try node_1.addKnownEnr(&node_2);
    const lookup_id = try node_0.service.startLookup(&node_2.node_id);
    const services = [_]*Service{ &node_0.service, &node_1.service, &node_2.service };

    var saw_discovered_target = false;
    var saw_lookup_finished = false;
    var lookup_included_intermediary = false;

    for (0..192) |_| {
        pollServices(services[0..]);

        while (node_0.service.popEvent()) |event| {
            var owned = event;
            defer owned.deinit(alloc);

            switch (owned) {
                .discovered_enr => |discovered| {
                    const discovered_node_id = discovered.enr.nodeId() orelse continue;
                    if (std.mem.eql(u8, &discovered_node_id, &node_2.node_id)) {
                        saw_discovered_target = true;
                    }
                },
                .lookup_finished => |lookup_finished| {
                    saw_lookup_finished = true;
                    try std.testing.expectEqual(lookup_id, lookup_finished.lookup_id);
                    try std.testing.expect(!lookup_finished.timed_out);

                    for (lookup_finished.enrs) |raw_enr| {
                        const parsed = try enr_mod.decode(raw_enr);
                        const node_id = parsed.nodeId() orelse continue;
                        if (std.mem.eql(u8, &node_id, &node_1.node_id)) {
                            lookup_included_intermediary = true;
                        }
                    }
                },
                else => {},
            }
        }

        while (node_1.service.popEvent()) |event| {
            var owned = event;
            defer owned.deinit(alloc);
        }
        while (node_2.service.popEvent()) |event| {
            var owned = event;
            defer owned.deinit(alloc);
        }

        if (saw_discovered_target and saw_lookup_finished) break;
    }

    const discovered_enr = node_0.service.findEnr(&node_2.node_id) orelse return error.MissingDiscoveredEnr;
    try std.testing.expectEqualSlices(u8, node_2.enr(), discovered_enr);
    try std.testing.expect(saw_discovered_target);
    try std.testing.expect(saw_lookup_finished);
    try std.testing.expect(lookup_included_intermediary);
}

test "live TALKREQ TALKRESP round-trip" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex");

    const sk_0 = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const sk_1 = hex.hexToBytesComptime(32, "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb14571f7");

    var node_0 = try TestService.init(alloc, io, sk_0);
    defer node_0.deinit();
    var node_1 = try TestService.init(alloc, io, sk_1);
    defer node_1.deinit();

    try node_0.addKnownEnr(&node_1);

    const req_id = try node_0.service.sendTalkRequest(
        &node_1.node_id,
        &node_1.pubkey,
        node_1.addr(),
        "/eth2/test",
        "ping",
    );

    const services = [_]*Service{ &node_0.service, &node_1.service };
    var saw_request = false;
    var saw_response = false;

    for (0..192) |_| {
        pollServices(services[0..]);

        while (node_1.service.popEvent()) |event| {
            var owned = event;
            defer owned.deinit(alloc);

            switch (owned) {
                .talkreq => |talkreq| {
                    saw_request = true;
                    try std.testing.expectEqual(node_0.node_id, talkreq.peer_id);
                    try std.testing.expectEqualSlices(u8, req_id.slice(), talkreq.req_id.slice());
                    try std.testing.expectEqualStrings("/eth2/test", talkreq.protocol);
                    try std.testing.expectEqualStrings("ping", talkreq.request);
                    try node_1.service.sendTalkResponse(talkreq.peer_id, talkreq.peer_addr, talkreq.req_id, "pong");
                },
                else => {},
            }
        }

        while (node_0.service.popEvent()) |event| {
            var owned = event;
            defer owned.deinit(alloc);

            switch (owned) {
                .talkresp => |talkresp| {
                    saw_response = true;
                    try std.testing.expectEqual(node_1.node_id, talkresp.peer_id);
                    try std.testing.expectEqualSlices(u8, req_id.slice(), talkresp.req_id.slice());
                    try std.testing.expectEqualStrings("pong", talkresp.response);
                },
                else => {},
            }
        }

        if (saw_request and saw_response) break;
    }

    try std.testing.expect(saw_request);
    try std.testing.expect(saw_response);
}

test "discv5 service ingress uses TS-style rate limiter" {
    const io = std.Options.debug_io;
    const hex = @import("hex");
    const secret = hex.hexToBytesComptime(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
    var fixture = try TestService.init(std.testing.allocator, io, secret);
    defer fixture.deinit();

    fixture.service.ingress_queue.deinit();
    fixture.service.ingress_queue = try IngressQueue.init(std.testing.allocator, 4, .{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 100 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 1 },
    });

    const from = Address{ .ip4 = .{ .bytes = .{ 203, 0, 113, 9 }, .port = 9000 } };
    const payload = [_]u8{0xaa} ** 16;
    try std.testing.expect(fixture.service.ingress_queue.enqueueReceived(from, &payload, 0));
    try std.testing.expect(!fixture.service.ingress_queue.enqueueReceived(from, &payload, 0));

    const stats = fixture.service.ingressStatsSnapshot();
    try std.testing.expectEqual(@as(u64, 2), stats.received_total);
    try std.testing.expectEqual(@as(u64, 1), stats.filtered_total);
    try std.testing.expectEqual(@as(u64, 1), stats.rate_limit_hit_ip_total);
}

test "discv5 service ingress expected response bypasses rate limit" {
    const io = std.Options.debug_io;
    const hex = @import("hex");
    const secret = hex.hexToBytesComptime(32, "b71c71a67e1177ad42eb5a1d7d0892b262a09b10d06c26fbb05d4eb671838a75");
    var fixture = try TestService.init(std.testing.allocator, io, secret);
    defer fixture.deinit();

    fixture.service.ingress_queue.deinit();
    fixture.service.ingress_queue = try IngressQueue.init(std.testing.allocator, 4, .{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 1 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 1 },
    });

    const from = Address{ .ip4 = .{ .bytes = .{ 203, 0, 113, 10 }, .port = 9000 } };
    const payload = [_]u8{0xbb} ** 16;
    try std.testing.expect(fixture.service.ingress_queue.enqueueReceived(from, &payload, 0));
    fixture.service.ingress_queue.addExpectedResponse(from);
    try std.testing.expect(fixture.service.ingress_queue.enqueueReceived(from, &payload, 0));
    fixture.service.ingress_queue.removeExpectedResponse(from);
    try std.testing.expect(!fixture.service.ingress_queue.enqueueReceived(from, &payload, 0));
}

test "discv5 service addEnr emits TS-style enrAdded API event" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;

    var service_a = try TestService.init(alloc, io, [_]u8{0x11} ** 32);
    defer service_a.deinit();
    var service_b = try TestService.init(alloc, io, [_]u8{0x12} ** 32);
    defer service_b.deinit();

    while (service_a.service.popEvent()) |startup_event_value| {
        var startup_event = startup_event_value;
        startup_event.deinit(alloc);
    }
    try std.testing.expect(service_a.service.addEnr(service_b.enr()));

    var event = service_a.service.popEvent() orelse return error.MissingEnrAddedEvent;
    defer event.deinit(alloc);
    try std.testing.expectEqual(EventKind.enr_added, event.kind());
    try std.testing.expectEqualStrings("enrAdded", event.tsEventName());
    switch (event) {
        .enr_added => |enr_added| {
            try std.testing.expectEqual(service_b.node_id, enr_added.node_id);
            try std.testing.expectEqualSlices(u8, service_b.enr(), enr_added.enr);
            try std.testing.expect(enr_added.replaced_enr == null);
        },
        else => return error.UnexpectedEvent,
    }
    try std.testing.expect(service_a.service.popEvent() == null);
}

test "discv5 service API event names mirror ChainSafe TS surface" {
    const alloc = std.testing.allocator;
    const node_id = [_]u8{0x22} ** 32;
    const addr = Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9000 } };

    var talkreq = Event{ .talkreq = .{
        .peer_id = node_id,
        .peer_addr = addr,
        .req_id = .{ .bytes = [_]u8{0x01} ** 8, .len = 8 },
        .protocol = try alloc.dupe(u8, "eth2"),
        .request = try alloc.dupe(u8, "payload"),
    } };
    defer talkreq.deinit(alloc);
    try std.testing.expectEqual(EventKind.talk_req_received, talkreq.kind());
    try std.testing.expectEqualStrings("talkReqReceived", talkreq.tsEventName());

    var timeout = Event{ .request_timeout = .{
        .peer_id = node_id,
        .req_id = .{ .bytes = [_]u8{0x02} ** 8, .len = 8 },
        .kind = .ping,
    } };
    defer timeout.deinit(alloc);
    try std.testing.expectEqual(EventKind.request_failed, timeout.kind());
    try std.testing.expectEqualStrings("requestFailed", timeout.tsEventName());

    var local = Event{ .local_enr_updated = .{
        .seq = 2,
        .enr = try alloc.dupe(u8, "enr"),
    } };
    defer local.deinit(alloc);
    try std.testing.expectEqual(EventKind.multiaddr_updated, local.kind());
    try std.testing.expectEqualStrings("multiaddrUpdated", local.tsEventName());
}

test "discv5 service metrics snapshot mirrors TS gauges and rate-limit counters" {
    const io = std.Options.debug_io;
    const sk = [_]u8{0x02} ** 32;
    var fixture = try TestService.init(std.testing.allocator, io, sk);
    defer fixture.deinit();

    fixture.service.ingress_queue.deinit();
    fixture.service.ingress_queue = try IngressQueue.init(std.testing.allocator, 4, .{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 100 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 1 },
    });

    const from = Address{ .ip4 = .{ .bytes = .{ 203, 0, 113, 11 }, .port = 9000 } };
    const payload = [_]u8{0xcc} ** 16;
    try std.testing.expect(fixture.service.ingress_queue.enqueueReceived(from, &payload, 0));
    try std.testing.expect(!fixture.service.ingress_queue.enqueueReceived(from, &payload, 0));

    var target = [_]u8{0x42} ** 32;
    _ = try fixture.service.startLookup(&target);

    const snapshot = fixture.service.metricsSnapshot();
    try std.testing.expectEqual(fixture.service.knownPeerCount(), snapshot.kad_table_size);
    try std.testing.expectEqual(fixture.service.connectedPeerCount(), snapshot.connected_peer_count);
    try std.testing.expectEqual(fixture.service.protocol.activeSessionCount(), snapshot.active_session_count);
    try std.testing.expectEqual(@as(u64, 1), snapshot.lookup_count);
    try std.testing.expectEqual(@as(u64, 1), snapshot.rate_limit_hit_ip);
    try std.testing.expectEqual(@as(u64, 0), snapshot.rate_limit_hit_total);
}

test "queued ingress respects processing budget" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex");

    const sk = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    var node = try TestService.init(alloc, io, sk);
    defer node.deinit();

    try node.service.queueInboundPacketForTest(node.addr(), &[_]u8{0x00});
    try node.service.queueInboundPacketForTest(node.addr(), &[_]u8{0x01});

    try std.testing.expectEqual(@as(usize, 2), node.service.queuedIngressPackets());
    try std.testing.expectEqual(@as(usize, 1), node.service.processQueuedPackets(1));
    try std.testing.expectEqual(@as(usize, 1), node.service.queuedIngressPackets());
    try std.testing.expectEqual(@as(usize, 1), node.service.processQueuedPackets(8));
    try std.testing.expectEqual(@as(usize, 0), node.service.queuedIngressPackets());
}
