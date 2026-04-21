//! Higher-level discv5 service with integrated lookup orchestration.

const std = @import("std");
const scoped_log = std.log.scoped(.discv5_service);
const Allocator = std.mem.Allocator;
const Io = std.Io;

const enr_mod = @import("enr.zig");
const kbucket = @import("kbucket.zig");
const messages = @import("messages.zig");
const protocol_mod = @import("protocol.zig");
const udp_socket = @import("udp_socket.zig");

pub const Address = udp_socket.Address;
pub const NodeId = enr_mod.NodeId;
pub const Protocol = protocol_mod.Protocol;

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
    lookup_num_results: usize = 16,
    lookup_parallelism: usize = 3,
    lookup_request_limit: usize = 3,
    lookup_timeout_ms: u64 = 60_000,
    receive_timeout_ms: u64 = 1,
    ping_interval_ms: u64 = 30_000,
    enr_update: bool = true,
    addr_votes_to_update_enr: usize = 10,
    socket_recv_buffer_bytes: ?u32 = 4 * 1024 * 1024,
    socket_send_buffer_bytes: ?u32 = 256 * 1024,
    ingress_queue_capacity: usize = 1024,
    max_packets_per_poll: usize = 64,
    ingress_worker_timeout_ms: u64 = 50,
    ingress_filter_enabled: bool = true,
    ingress_total_packets_per_second: u32 = 256,
    ingress_packets_per_ip_per_second: u32 = 64,
};

const MAX_ADDR_VOTES: usize = 200;

const VoteKey = struct {
    family: Address.Family,
    bytes: [16]u8,
    port: u16,

    fn fromAddress(addr: Address) VoteKey {
        return switch (addr) {
            .ip4 => |ip4| blk: {
                var bytes = [_]u8{0} ** 16;
                @memcpy(bytes[0..4], &ip4.bytes);
                break :blk .{ .family = .ip4, .bytes = bytes, .port = ip4.port };
            },
            .ip6 => |ip6| .{ .family = .ip6, .bytes = ip6.bytes, .port = ip6.port },
        };
    }
};

const VoterRecord = struct {
    vote_key: VoteKey,
};

const VoteOrderEntry = struct {
    voter: NodeId,
    vote_key: VoteKey,
};

const AddrVotes = struct {
    allocator: Allocator,
    threshold: usize,
    voters: std.AutoHashMap(NodeId, VoterRecord),
    tallies: std.AutoHashMap(VoteKey, usize),
    order: std.ArrayListUnmanaged(VoteOrderEntry) = .empty,

    fn init(allocator: Allocator, threshold: usize) AddrVotes {
        return .{
            .allocator = allocator,
            .threshold = threshold,
            .voters = std.AutoHashMap(NodeId, VoterRecord).init(allocator),
            .tallies = std.AutoHashMap(VoteKey, usize).init(allocator),
        };
    }

    fn deinit(self: *AddrVotes) void {
        self.voters.deinit();
        self.tallies.deinit();
        self.order.deinit(self.allocator);
    }

    fn clear(self: *AddrVotes) void {
        self.voters.clearRetainingCapacity();
        self.tallies.clearRetainingCapacity();
        self.order.clearRetainingCapacity();
    }

    fn addVote(self: *AddrVotes, voter: NodeId, addr: Address) !bool {
        const vote_key = VoteKey.fromAddress(addr);

        if (self.voters.get(voter)) |prev| {
            if (std.meta.eql(prev.vote_key, vote_key)) {
                return false;
            }
            self.decrementTally(prev.vote_key);
        }

        const tally = (self.tallies.get(vote_key) orelse 0) + 1;
        if (tally >= self.threshold) {
            self.clear();
            return true;
        }

        try self.tallies.put(vote_key, tally);
        try self.voters.put(voter, .{ .vote_key = vote_key });
        try self.order.append(self.allocator, .{ .voter = voter, .vote_key = vote_key });
        self.evictOverflow();
        return false;
    }

    fn currentVoteCount(self: *const AddrVotes) usize {
        return self.voters.count();
    }

    fn decrementTally(self: *AddrVotes, vote_key: VoteKey) void {
        const next = (self.tallies.get(vote_key) orelse return) - 1;
        if (next == 0) {
            _ = self.tallies.remove(vote_key);
        } else {
            self.tallies.put(vote_key, next) catch {};
        }
    }

    fn evictOverflow(self: *AddrVotes) void {
        while (self.voters.count() > MAX_ADDR_VOTES and self.order.items.len > 0) {
            const evicted = self.order.orderedRemove(0);
            const current = self.voters.get(evicted.voter) orelse continue;
            if (!std.meta.eql(current.vote_key, evicted.vote_key)) continue;
            _ = self.voters.remove(evicted.voter);
            self.decrementTally(evicted.vote_key);
        }
    }
};

const LookupPeerState = enum {
    not_contacted,
    waiting,
    succeeded,
    failed,
};

const LookupPeer = struct {
    node_id: NodeId,
    peers_returned: usize = 0,
    state: LookupPeerState = .not_contacted,
};

const LookupState = enum {
    iterating,
    stalled,
    finished,
};

const Lookup = struct {
    target: NodeId,
    started_at_ns: i64,
    state: LookupState = .iterating,
    no_progress: usize = 0,
    num_waiting: usize = 0,
    peers: std.ArrayListUnmanaged(LookupPeer) = .empty,

    fn init(alloc: Allocator, target: NodeId, seeds: []const NodeId, started_at_ns: i64) !Lookup {
        var lookup = Lookup{
            .target = target,
            .started_at_ns = started_at_ns,
        };
        errdefer lookup.deinit(alloc);

        for (seeds) |seed| {
            _ = try lookup.insertCandidate(alloc, seed);
        }
        return lookup;
    }

    fn deinit(self: *Lookup, alloc: Allocator) void {
        self.peers.deinit(alloc);
    }

    fn isTimedOut(self: *const Lookup, now_ns: i64, timeout_ms: u64) bool {
        const elapsed_ns: i128 = @as(i128, now_ns) - @as(i128, self.started_at_ns);
        return elapsed_ns >= @as(i128, timeout_ms) * std.time.ns_per_ms;
    }

    fn atCapacity(self: *const Lookup, config: *const Config) bool {
        return switch (self.state) {
            .iterating => self.num_waiting >= config.lookup_parallelism,
            .stalled => self.num_waiting >= config.lookup_num_results,
            .finished => true,
        };
    }

    fn insertCandidate(self: *Lookup, alloc: Allocator, node_id: NodeId) !?usize {
        for (self.peers.items) |peer| {
            if (std.mem.eql(u8, &peer.node_id, &node_id)) return null;
        }

        const candidate_distance = kbucket.xorDistance(&self.target, &node_id);
        var insert_at = self.peers.items.len;
        for (self.peers.items, 0..) |peer, i| {
            const peer_distance = kbucket.xorDistance(&self.target, &peer.node_id);
            if (std.mem.lessThan(u8, &candidate_distance, &peer_distance)) {
                insert_at = i;
                break;
            }
        }

        try self.peers.insert(alloc, insert_at, .{ .node_id = node_id });
        return insert_at;
    }

    fn findPeerIndex(self: *const Lookup, node_id: *const NodeId) ?usize {
        for (self.peers.items, 0..) |peer, i| {
            if (std.mem.eql(u8, &peer.node_id, node_id)) return i;
        }
        return null;
    }

    fn onSuccess(self: *Lookup, alloc: Allocator, node_id: *const NodeId, closer_peers: []const NodeId, config: *const Config) !void {
        if (self.state == .finished) return;

        if (self.findPeerIndex(node_id)) |index| {
            if (self.peers.items[index].state == .waiting) {
                self.num_waiting -= 1;
                self.peers.items[index].peers_returned += closer_peers.len;
                self.peers.items[index].state = .succeeded;
            }
        }

        const had_few_results = self.peers.items.len < config.lookup_num_results;
        var progress = false;
        for (closer_peers) |peer_id| {
            if (try self.insertCandidate(alloc, peer_id)) |insert_index| {
                if (insert_index == 0 or had_few_results) progress = true;
            }
        }

        switch (self.state) {
            .iterating => {
                self.no_progress = if (progress) 0 else self.no_progress + 1;
                if (self.no_progress >= config.lookup_parallelism) self.state = .stalled;
            },
            .stalled => {
                if (progress) {
                    self.state = .iterating;
                    self.no_progress = 0;
                }
            },
            .finished => {},
        }

        self.maybeFinish(config);
    }

    fn onFailure(self: *Lookup, node_id: *const NodeId, config: *const Config) void {
        if (self.state == .finished) return;

        if (self.findPeerIndex(node_id)) |index| {
            if (self.peers.items[index].state == .waiting) {
                self.num_waiting -= 1;
                self.peers.items[index].state = .failed;
            }
        }

        self.maybeFinish(config);
    }

    fn nextPeer(self: *Lookup, config: *const Config) ?NodeId {
        if (self.state == .finished or self.atCapacity(config)) return null;

        for (self.peers.items) |*peer| {
            if (peer.state != .not_contacted) continue;
            peer.state = .waiting;
            self.num_waiting += 1;
            return peer.node_id;
        }

        self.maybeFinish(config);
        return null;
    }

    fn maybeFinish(self: *Lookup, config: *const Config) void {
        if (self.state == .finished) return;

        const limit = @min(config.lookup_num_results, self.peers.items.len);
        var blocked = false;
        var succeeded: usize = 0;
        for (self.peers.items[0..limit]) |peer| {
            switch (peer.state) {
                .succeeded => succeeded += 1,
                .waiting, .not_contacted => {
                    blocked = true;
                    break;
                },
                .failed => {},
            }
        }
        if (!blocked and succeeded == limit) {
            self.state = .finished;
            return;
        }

        if (self.num_waiting == 0) {
            for (self.peers.items) |peer| {
                if (peer.state == .not_contacted) return;
            }
            self.state = .finished;
        }
    }
};

const LookupRequestKey = struct {
    peer_id: NodeId,
    req_id: [8]u8,
    req_id_len: u8,

    fn from(peer_id: NodeId, req_id: messages.ReqId) LookupRequestKey {
        return .{
            .peer_id = peer_id,
            .req_id = req_id.bytes,
            .req_id_len = req_id.len,
        };
    }
};

const ConnectedPeer = struct {
    addr: Address,
    next_ping_at_ns: i64,
    awaiting_ping_response: bool = false,
};

pub const LookupFinishedEvent = struct {
    lookup_id: u32,
    target: NodeId,
    enrs: [][]u8,
    timed_out: bool,

    fn deinit(self: *LookupFinishedEvent, alloc: Allocator) void {
        for (self.enrs) |enr| alloc.free(enr);
        alloc.free(self.enrs);
    }
};

pub const DiscoveredEnrEvent = struct {
    source_peer_id: NodeId,
    source_peer_addr: Address,
    lookup_id: ?u32,
    node_id: NodeId,
    addr_ip4: ?Address,
    addr_ip6: ?Address,
    pubkey: ?[33]u8,
    has_quic: bool,
    attnets: [8]u8,
    syncnets: [1]u8,
    custody_group_count: ?u64,
    fork_digest: ?[4]u8,

    fn deinit(_: *DiscoveredEnrEvent, _: Allocator) void {}
};

pub const LocalEnrUpdatedEvent = struct {
    seq: u64,
    enr: []u8,

    fn deinit(self: *LocalEnrUpdatedEvent, alloc: Allocator) void {
        alloc.free(self.enr);
    }
};

pub const PeerConnectedEvent = struct {
    peer_id: NodeId,
    peer_addr: Address,
};

pub const PeerDisconnectedEvent = struct {
    peer_id: NodeId,
    peer_addr: Address,
};

pub const Event = union(enum) {
    pong: protocol_mod.PongEvent,
    nodes: protocol_mod.NodesEvent,
    talkreq: protocol_mod.TalkReqEvent,
    talkresp: protocol_mod.TalkRespEvent,
    request_timeout: protocol_mod.RequestTimeoutEvent,
    discovered_enr: DiscoveredEnrEvent,
    lookup_finished: LookupFinishedEvent,
    local_enr_updated: LocalEnrUpdatedEvent,
    peer_connected: PeerConnectedEvent,
    peer_disconnected: PeerDisconnectedEvent,

    pub fn deinit(self: *Event, alloc: Allocator) void {
        switch (self.*) {
            .pong => {},
            .nodes => |*nodes| {
                var protocol_event = protocol_mod.Event{ .nodes = nodes.* };
                protocol_event.deinit(alloc);
            },
            .talkreq => |*talkreq| {
                var protocol_event = protocol_mod.Event{ .talkreq = talkreq.* };
                protocol_event.deinit(alloc);
            },
            .talkresp => |*talkresp| {
                var protocol_event = protocol_mod.Event{ .talkresp = talkresp.* };
                protocol_event.deinit(alloc);
            },
            .request_timeout => {},
            .discovered_enr => |*discovered_enr| discovered_enr.deinit(alloc),
            .lookup_finished => |*lookup_finished| lookup_finished.deinit(alloc),
            .local_enr_updated => |*local_enr_updated| local_enr_updated.deinit(alloc),
            .peer_connected => {},
            .peer_disconnected => {},
        }
    }
};

const IngressFilterAddressKey = struct {
    family: Address.Family,
    bytes: [16]u8,

    fn fromAddress(addr: Address) IngressFilterAddressKey {
        return switch (addr) {
            .ip4 => |ip4| blk: {
                var bytes = [_]u8{0} ** 16;
                @memcpy(bytes[0..4], &ip4.bytes);
                break :blk .{ .family = .ip4, .bytes = bytes };
            },
            .ip6 => |ip6| .{ .family = .ip6, .bytes = ip6.bytes },
        };
    }
};

const IngressPacket = struct {
    from: Address,
    len: usize,
    data: [protocol_mod.MAX_PACKET_SIZE]u8,
};

pub const IngressStatsSnapshot = struct {
    received_total: u64 = 0,
    filtered_total: u64 = 0,
    dropped_queue_full_total: u64 = 0,
    processed_total: u64 = 0,
    budget_exhausted_total: u64 = 0,
    queue_depth: usize = 0,
    max_queue_depth: usize = 0,
    recv_buffer_bytes_ip4: u32 = 0,
    recv_buffer_bytes_ip6: u32 = 0,
    send_buffer_bytes_ip4: u32 = 0,
    send_buffer_bytes_ip6: u32 = 0,
};

const IngressQueue = struct {
    allocator: Allocator,
    packets: []IngressPacket,
    head: usize = 0,
    len: usize = 0,
    filter_window_started_ms: u64 = 0,
    filter_total: u32 = 0,
    filter_by_ip: std.AutoHashMap(IngressFilterAddressKey, u32),
    mutex: std.atomic.Mutex = .unlocked,
    stats: IngressStatsSnapshot = .{},

    fn acquire(self: *IngressQueue) void {
        while (!self.mutex.tryLock()) {
            std.atomic.spinLoopHint();
        }
    }

    fn init(allocator: Allocator, capacity: usize) !IngressQueue {
        std.debug.assert(capacity > 0);
        return .{
            .allocator = allocator,
            .packets = try allocator.alloc(IngressPacket, capacity),
            .filter_by_ip = std.AutoHashMap(IngressFilterAddressKey, u32).init(allocator),
        };
    }

    fn deinit(self: *IngressQueue) void {
        self.filter_by_ip.deinit();
        self.allocator.free(self.packets);
    }

    fn snapshot(self: *IngressQueue) IngressStatsSnapshot {
        self.acquire();
        defer self.mutex.unlock();
        return self.stats;
    }

    fn queuedLen(self: *IngressQueue) usize {
        self.acquire();
        defer self.mutex.unlock();
        return self.len;
    }

    fn setSocketBuffers(self: *IngressQueue, family: Address.Family, recv_buffer_bytes: u32, send_buffer_bytes: u32) void {
        self.acquire();
        defer self.mutex.unlock();
        switch (family) {
            .ip4 => {
                self.stats.recv_buffer_bytes_ip4 = recv_buffer_bytes;
                self.stats.send_buffer_bytes_ip4 = send_buffer_bytes;
            },
            .ip6 => {
                self.stats.recv_buffer_bytes_ip6 = recv_buffer_bytes;
                self.stats.send_buffer_bytes_ip6 = send_buffer_bytes;
            },
        }
    }

    fn enqueueReceived(self: *IngressQueue, from: Address, data: []const u8, config: *const Config, now_ms: u64) bool {
        self.acquire();
        defer self.mutex.unlock();

        self.stats.received_total += 1;
        if (config.ingress_filter_enabled) {
            if (self.filter_windowStartedExpired(now_ms)) {
                self.filter_window_started_ms = now_ms;
                self.filter_total = 0;
                self.filter_by_ip.clearRetainingCapacity();
            }

            if (self.filter_total >= config.ingress_total_packets_per_second) {
                self.stats.filtered_total += 1;
                return false;
            }

            const key = IngressFilterAddressKey.fromAddress(from);
            const entry = self.filter_by_ip.getOrPut(key) catch {
                self.stats.filtered_total += 1;
                return false;
            };
            if (!entry.found_existing) entry.value_ptr.* = 0;
            if (entry.value_ptr.* >= config.ingress_packets_per_ip_per_second) {
                self.stats.filtered_total += 1;
                return false;
            }
            entry.value_ptr.* += 1;
            self.filter_total += 1;
        }

        return self.enqueueUnlocked(from, data);
    }

    fn enqueueForTest(self: *IngressQueue, from: Address, data: []const u8) bool {
        self.acquire();
        defer self.mutex.unlock();
        return self.enqueueUnlocked(from, data);
    }

    fn enqueueUnlocked(self: *IngressQueue, from: Address, data: []const u8) bool {
        if (self.len >= self.packets.len) {
            self.stats.dropped_queue_full_total += 1;
            return false;
        }

        const index = (self.head + self.len) % self.packets.len;
        self.packets[index].from = from;
        self.packets[index].len = data.len;
        @memcpy(self.packets[index].data[0..data.len], data);
        self.len += 1;
        self.stats.queue_depth = self.len;
        if (self.len > self.stats.max_queue_depth) self.stats.max_queue_depth = self.len;
        return true;
    }

    fn pop(self: *IngressQueue) ?IngressPacket {
        self.acquire();
        defer self.mutex.unlock();
        if (self.len == 0) return null;

        const packet = self.packets[self.head];
        self.head = (self.head + 1) % self.packets.len;
        self.len -= 1;
        self.stats.queue_depth = self.len;
        return packet;
    }

    fn noteProcessed(self: *IngressQueue, processed: usize, budget_exhausted: bool) void {
        if (processed == 0 and !budget_exhausted) return;
        self.acquire();
        defer self.mutex.unlock();
        self.stats.processed_total += processed;
        if (budget_exhausted) self.stats.budget_exhausted_total += 1;
    }

    fn filter_windowStartedExpired(self: *const IngressQueue, now_ms: u64) bool {
        return self.filter_window_started_ms == 0 or now_ms - self.filter_window_started_ms >= 1_000;
    }
};

pub const SetLocalEnrError = Allocator.Error || enr_mod.Error || error{
    WrongNodeId,
    StaleEnrSeq,
};

pub const Service = struct {
    allocator: Allocator,
    io: Io,
    config: Config,
    socket_ip4: ?udp_socket.Socket = null,
    socket_ip6: ?udp_socket.Socket = null,
    protocol: Protocol,
    next_lookup_id: u32 = 1,
    active_lookups: std.AutoHashMap(u32, Lookup),
    request_lookup_ids: std.AutoHashMap(LookupRequestKey, u32),
    connected_peers: std.AutoHashMap(NodeId, ConnectedPeer),
    owned_local_enr: ?[]u8 = null,
    addr_votes_ip4: AddrVotes,
    addr_votes_ip6: AddrVotes,
    completed_events: std.ArrayListUnmanaged(Event) = .empty,
    completed_events_head: usize = 0,
    ingress_queue: IngressQueue,
    ingress_shutdown_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    ingress_thread_ip4: ?std.Thread = null,
    ingress_thread_ip6: ?std.Thread = null,
    ingress_workers_started: bool = false,
    next_socket_poll_family: Address.Family = .ip4,

    pub fn init(io: Io, allocator: Allocator, config: Config) !Service {
        var service_config = config;
        var owned_local_enr: ?[]u8 = null;
        if (service_config.protocol_config.local_enr) |local_enr| {
            owned_local_enr = try allocator.dupe(u8, local_enr);
            service_config.protocol_config.local_enr = owned_local_enr.?;
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

        var socket_ip4: ?udp_socket.Socket = null;
        errdefer if (socket_ip4) |*socket| socket.close();
        if (config.bind_addresses.ip4) |addr| {
            socket_ip4 = try udp_socket.Socket.bind(io, addr);
            socket_ip4.?.configureBuffers(.{
                .recv_buffer_bytes = service_config.socket_recv_buffer_bytes,
                .send_buffer_bytes = service_config.socket_send_buffer_bytes,
            });
        }

        var socket_ip6: ?udp_socket.Socket = null;
        errdefer if (socket_ip6) |*socket| socket.close();
        if (config.bind_addresses.ip6) |addr| {
            socket_ip6 = try udp_socket.Socket.bind(io, addr);
            socket_ip6.?.configureBuffers(.{
                .recv_buffer_bytes = service_config.socket_recv_buffer_bytes,
                .send_buffer_bytes = service_config.socket_send_buffer_bytes,
            });
        }

        var service = Service{
            .allocator = allocator,
            .io = io,
            .config = service_config,
            .socket_ip4 = socket_ip4,
            .socket_ip6 = socket_ip6,
            .protocol = try Protocol.init(io, allocator, service_config.protocol_config),
            .active_lookups = std.AutoHashMap(u32, Lookup).init(allocator),
            .request_lookup_ids = std.AutoHashMap(LookupRequestKey, u32).init(allocator),
            .connected_peers = std.AutoHashMap(NodeId, ConnectedPeer).init(allocator),
            .owned_local_enr = owned_local_enr,
            .addr_votes_ip4 = AddrVotes.init(allocator, service_config.addr_votes_to_update_enr),
            .addr_votes_ip6 = AddrVotes.init(allocator, service_config.addr_votes_to_update_enr),
            .ingress_queue = try IngressQueue.init(allocator, service_config.ingress_queue_capacity),
        };
        errdefer service.ingress_queue.deinit();
        if (service.socket_ip4) |socket| {
            service.ingress_queue.setSocketBuffers(.ip4, socket.recv_buffer_bytes, socket.send_buffer_bytes);
        }
        if (service.socket_ip6) |socket| {
            service.ingress_queue.setSocketBuffers(.ip6, socket.recv_buffer_bytes, socket.send_buffer_bytes);
        }
        return service;
    }

    pub fn deinit(self: *Service) void {
        self.stopIngressWorkers();
        var lookups = self.active_lookups.iterator();
        while (lookups.next()) |entry| entry.value_ptr.deinit(self.allocator);
        self.active_lookups.deinit();
        self.request_lookup_ids.deinit();
        self.connected_peers.deinit();
        self.addr_votes_ip4.deinit();
        self.addr_votes_ip6.deinit();
        for (self.completed_events.items[self.completed_events_head..]) |*event| event.deinit(self.allocator);
        self.completed_events.deinit(self.allocator);
        self.ingress_queue.deinit();
        if (self.owned_local_enr) |local_enr| self.allocator.free(local_enr);
        self.protocol.deinit();
        if (self.socket_ip4) |*socket| socket.close();
        if (self.socket_ip6) |*socket| socket.close();
    }

    pub fn addNode(self: *Service, node_id: NodeId, pubkey: ?*const [33]u8, addr: Address, enr: ?[]const u8) void {
        self.protocol.addNode(node_id, pubkey, addr, enr);
    }

    pub fn addEnr(self: *Service, enr_bytes: []const u8) bool {
        var parsed = enr_mod.decode(self.allocator, enr_bytes) catch return false;
        defer parsed.deinit();

        const node_id = parsed.nodeId() orelse return false;
        const pubkey = parsed.pubkey orelse return false;
        const addr = self.contactAddressFromParsedEnr(&parsed) orelse return false;

        self.addNode(node_id, &pubkey, addr, enr_bytes);
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
        var parsed = try enr_mod.decode(self.allocator, enr_bytes);
        defer parsed.deinit();

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
        const record = self.protocol.node_records.get(node_id.*) orelse return null;
        return record.enr;
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
        if (self.completed_events_head >= self.completed_events.items.len) {
            self.completed_events.clearRetainingCapacity();
            self.completed_events_head = 0;
            return null;
        }

        const event = self.completed_events.items[self.completed_events_head];
        self.completed_events_head += 1;
        self.compactCompletedEvents();
        return event;
    }

    fn compactCompletedEvents(self: *Service) void {
        if (self.completed_events_head == 0) return;
        const remaining = self.completed_events.items.len - self.completed_events_head;
        if (remaining == 0) {
            self.completed_events.clearRetainingCapacity();
            self.completed_events_head = 0;
            return;
        }
        if (self.completed_events_head < 64 and self.completed_events_head * 2 < self.completed_events.items.len) return;

        std.mem.copyForwards(
            Event,
            self.completed_events.items[0..remaining],
            self.completed_events.items[self.completed_events_head..],
        );
        self.completed_events.items.len = remaining;
        self.completed_events_head = 0;
    }

    pub fn knownPeerCount(self: *const Service) usize {
        return self.protocol.routing_table.nodeCount();
    }

    pub fn connectedPeerCount(self: *const Service) usize {
        return self.connected_peers.count();
    }

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

    pub fn processQueuedPackets(self: *Service, max_packets: usize) usize {
        var processed: usize = 0;
        while (processed < max_packets) {
            const packet = self.ingress_queue.pop() orelse break;
            const socket = self.socketForAddress(packet.from) orelse continue;
            self.protocol.handlePacket(packet.data[0..packet.len], packet.from, socket) catch |err| {
                scoped_log.debug("discv5: handlePacket failed for queued packet from {any}: {}", .{ packet.from, err });
            };
            processed += 1;
        }
        const budget_exhausted = processed == max_packets and self.queuedIngressPackets() > 0;
        self.ingress_queue.noteProcessed(processed, budget_exhausted);
        return processed;
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
        _ = self.pollIngress();
        self.protocol.pruneExpiredState();
        self.pruneTimedOutLookups();
        self.syncConnectedPeers();
        self.pingDueConnectedPeers();
        self.drainProtocolEvents();
    }

    pub fn sendPing(self: *Service, node_id: *const NodeId, pubkey: *const [33]u8, addr: Address, enr_seq: u64) !messages.ReqId {
        const socket = self.socketForAddress(addr) orelse return error.NoSocketForAddressFamily;
        return self.protocol.sendPing(node_id, pubkey, addr, enr_seq, socket);
    }

    pub fn sendFindNode(self: *Service, node_id: *const NodeId, pubkey: *const [33]u8, addr: Address, distances: []const u16) !messages.ReqId {
        const socket = self.socketForAddress(addr) orelse return error.NoSocketForAddressFamily;
        return self.protocol.sendFindNode(node_id, pubkey, addr, distances, socket);
    }

    pub fn sendTalkRequest(self: *Service, node_id: *const NodeId, pubkey: *const [33]u8, addr: Address, protocol_name: []const u8, request: []const u8) !messages.ReqId {
        const socket = self.socketForAddress(addr) orelse return error.NoSocketForAddressFamily;
        return self.protocol.sendTalkRequest(node_id, pubkey, addr, protocol_name, request, socket);
    }

    pub fn sendTalkResponse(self: *Service, node_id: NodeId, addr: Address, req_id: messages.ReqId, response: []const u8) !void {
        const socket = self.socketForAddress(addr) orelse return error.NoSocketForAddressFamily;
        try self.protocol.sendTalkResponse(node_id, addr, req_id, response, socket);
    }

    fn maybeUpdateLocalEnrFromVote(self: *Service, voter: NodeId, observed_addr: Address) void {
        if (!self.config.enr_update) return;
        if (self.protocol.config.local_enr == null) return;

        const normalized_addr = normalizeObservedAddress(observed_addr);
        var votes = switch (normalized_addr) {
            .ip4 => &self.addr_votes_ip4,
            .ip6 => &self.addr_votes_ip6,
        };

        const is_winning_vote = votes.addVote(voter, normalized_addr) catch return;
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
        var parsed = enr_mod.decode(self.allocator, local_enr) catch return null;
        defer parsed.deinit();

        return switch (family) {
            .ip4 => if (parsed.ip) |ip|
                if (parsed.udp) |port|
                    Address{ .ip4 = .{ .bytes = ip, .port = port } }
                else
                    null
            else
                null,
            .ip6 => if (parsed.ip6) |ip6|
                if (parsed.udp6) |port|
                    Address{ .ip6 = .{ .bytes = ip6, .port = port } }
                else
                    null
            else
                null,
        };
    }

    fn updateLocalEnrAddress(self: *Service, addr: Address) !void {
        const current_enr = self.protocol.config.local_enr orelse return;
        var parsed = try enr_mod.decode(self.allocator, current_enr);
        defer parsed.deinit();

        const next_seq = @max(parsed.seq, self.protocol.config.local_enr_seq) + 1;
        var builder = enr_mod.Builder.init(self.allocator, self.protocol.config.local_secret_key, next_seq);
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
        var closest: [16]kbucket.Entry = undefined;
        const found = self.protocol.routing_table.findClosest(target, 16, &closest);

        var seeds: std.ArrayListUnmanaged(NodeId) = .empty;
        defer seeds.deinit(self.allocator);
        for (closest[0..found]) |entry| {
            try seeds.append(self.allocator, entry.node_id);
        }

        const lookup_id = self.next_lookup_id;
        self.next_lookup_id +%= 1;
        if (self.next_lookup_id == 0) self.next_lookup_id = 1;

        const lookup = try Lookup.init(self.allocator, target.*, seeds.items, currentTimestampNs(self.io));
        try self.active_lookups.put(lookup_id, lookup);
        try self.pumpLookup(lookup_id);
        if (self.active_lookups.getPtr(lookup_id)) |active| {
            if (active.state == .finished) {
                try self.finishLookup(lookup_id, false);
            }
        }
        return lookup_id;
    }

    pub fn startRandomLookup(self: *Service) !u32 {
        var target: NodeId = undefined;
        self.protocol.rng.random().bytes(&target);
        return self.startLookup(&target);
    }

    fn ingressWorkerMain(self: *Service, family: Address.Family) void {
        var recv_buf: [protocol_mod.MAX_PACKET_SIZE]u8 = undefined;
        while (!self.ingress_shutdown_requested.load(.acquire)) {
            const socket = switch (family) {
                .ip4 => if (self.socket_ip4) |*bound| bound else return,
                .ip6 => if (self.socket_ip6) |*bound| bound else return,
            };
            const result = socket.receiveTimeout(&recv_buf, .{
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
            _ = self.ingress_queue.enqueueReceived(result.from, result.data, &self.config, currentUnixTimeMs(self.io));
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
            const result = socket.receiveTimeout(recv_buf, .{
                .duration = .{
                    .raw = Io.Duration.fromMilliseconds(@intCast(self.receiveTimeoutPerSocketMs())),
                    .clock = .awake,
                },
            }) catch |err| switch (err) {
                error.Timeout => break,
                else => break,
            };

            self.protocol.handlePacket(result.data, result.from, socket) catch |err| {
                scoped_log.debug("discv5: handlePacket failed for {any}: {}", .{ result.from, err });
            };
            processed += 1;
        }
        return processed;
    }

    fn drainProtocolEvents(self: *Service) void {
        while (self.protocol.popEvent()) |protocol_event| {
            switch (protocol_event) {
                .pong => |pong| {
                    self.maybeUpdateLocalEnrFromVote(pong.peer_id, recipientAddress(pong.recipient_ip, pong.recipient_port));
                    self.notePeerResponsive(pong.peer_id, pong.peer_addr);
                    self.completed_events.append(self.allocator, .{ .pong = pong }) catch {};
                },
                .nodes => |nodes| {
                    self.notePeerResponsive(nodes.peer_id, nodes.peer_addr);
                    const lookup_id = self.lookupIdForNodes(&nodes);
                    var parsed_nodes = self.collectDiscoveredNodes(&nodes);
                    defer parsed_nodes.deinit(self.allocator);
                    self.emitDiscoveredEnrs(&nodes, lookup_id, parsed_nodes.items);
                    self.handleLookupNodes(&nodes, lookup_id, parsed_nodes.items);
                    self.completed_events.append(self.allocator, .{ .nodes = nodes }) catch {
                        var owned = Event{ .nodes = nodes };
                        owned.deinit(self.allocator);
                    };
                },
                .talkreq => |talkreq| {
                    self.notePeerResponsive(talkreq.peer_id, talkreq.peer_addr);
                    self.completed_events.append(self.allocator, .{ .talkreq = talkreq }) catch {
                        var owned = Event{ .talkreq = talkreq };
                        owned.deinit(self.allocator);
                    };
                },
                .talkresp => |talkresp| {
                    self.notePeerResponsive(talkresp.peer_id, talkresp.peer_addr);
                    self.completed_events.append(self.allocator, .{ .talkresp = talkresp }) catch {
                        var owned = Event{ .talkresp = talkresp };
                        owned.deinit(self.allocator);
                    };
                },
                .request_timeout => |timeout| {
                    self.handleLookupTimeout(&timeout);
                    self.handlePeerTimeout(&timeout);
                    self.completed_events.append(self.allocator, .{ .request_timeout = timeout }) catch {};
                },
            }
        }
    }

    fn lookupIdForNodes(self: *const Service, nodes: *const protocol_mod.NodesEvent) ?u32 {
        return self.request_lookup_ids.get(LookupRequestKey.from(nodes.peer_id, nodes.req_id));
    }

    const ParsedDiscoveredNode = struct {
        node_id: NodeId,
        addr_ip4: ?Address,
        addr_ip6: ?Address,
        pubkey: ?[33]u8,
        has_quic: bool,
        attnets: [8]u8,
        syncnets: [1]u8,
        custody_group_count: ?u64,
        fork_digest: ?[4]u8,
    };

    fn collectDiscoveredNodes(self: *Service, nodes: *const protocol_mod.NodesEvent) std.ArrayListUnmanaged(ParsedDiscoveredNode) {
        var parsed_nodes: std.ArrayListUnmanaged(ParsedDiscoveredNode) = .empty;
        for (nodes.enrs) |raw_enr| {
            var parsed = enr_mod.decode(self.allocator, raw_enr) catch continue;
            defer parsed.deinit();

            const node_id = parsed.nodeId() orelse continue;
            if (std.mem.eql(u8, &node_id, &self.protocol.config.local_node_id)) continue;

            const addr_ip4 = if (parsed.ip) |ip|
                if (parsed.quic orelse parsed.udp orelse parsed.tcp) |port|
                    Address{ .ip4 = .{ .bytes = ip, .port = port } }
                else
                    null
            else
                null;
            const addr_ip6 = if (parsed.ip6) |ip6|
                if (parsed.quic6 orelse parsed.udp6 orelse parsed.tcp6) |port|
                    Address{ .ip6 = .{ .bytes = ip6, .port = port } }
                else
                    null
            else
                null;
            if (addr_ip4 == null and addr_ip6 == null) continue;

            parsed_nodes.append(self.allocator, .{
                .node_id = node_id,
                .addr_ip4 = addr_ip4,
                .addr_ip6 = addr_ip6,
                .pubkey = parsed.pubkey,
                .has_quic = parsed.quic != null or parsed.quic6 != null,
                .attnets = parsed.attnets orelse [_]u8{0} ** 8,
                .syncnets = parsed.syncnets orelse [_]u8{0} ** 1,
                .custody_group_count = parsed.custody_group_count,
                .fork_digest = parsed.eth2_fork_digest,
            }) catch continue;
        }
        return parsed_nodes;
    }

    fn emitDiscoveredEnrs(self: *Service, nodes: *const protocol_mod.NodesEvent, lookup_id: ?u32, parsed_nodes: []const ParsedDiscoveredNode) void {
        scoped_log.debug("discv5 service: emitting {d} ENRs from {any} (lookup_id={any})", .{
            parsed_nodes.len,
            nodes.peer_addr,
            lookup_id,
        });
        for (parsed_nodes) |parsed| {
            self.completed_events.append(self.allocator, .{
                .discovered_enr = .{
                    .source_peer_id = nodes.peer_id,
                    .source_peer_addr = nodes.peer_addr,
                    .lookup_id = lookup_id,
                    .node_id = parsed.node_id,
                    .addr_ip4 = parsed.addr_ip4,
                    .addr_ip6 = parsed.addr_ip6,
                    .pubkey = parsed.pubkey,
                    .has_quic = parsed.has_quic,
                    .attnets = parsed.attnets,
                    .syncnets = parsed.syncnets,
                    .custody_group_count = parsed.custody_group_count,
                    .fork_digest = parsed.fork_digest,
                },
            }) catch {};
        }
    }

    fn handleLookupNodes(self: *Service, nodes: *const protocol_mod.NodesEvent, lookup_id: ?u32, parsed_nodes: []const ParsedDiscoveredNode) void {
        const actual_lookup_id = lookup_id orelse return;
        const key = LookupRequestKey.from(nodes.peer_id, nodes.req_id);
        const removed = self.request_lookup_ids.fetchRemove(key) orelse return;
        if (removed.value != actual_lookup_id) return;
        const lookup_id_value = removed.value;
        const lookup = self.active_lookups.getPtr(lookup_id_value) orelse return;

        var closer_peers: std.ArrayListUnmanaged(NodeId) = .empty;
        defer closer_peers.deinit(self.allocator);
        for (parsed_nodes) |parsed| {
            closer_peers.append(self.allocator, parsed.node_id) catch continue;
        }

        lookup.onSuccess(self.allocator, &nodes.peer_id, closer_peers.items, &self.config) catch {};
        self.pumpLookup(lookup_id_value) catch {};
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

        lookup.onFailure(&timeout.peer_id, &self.config);
        self.pumpLookup(lookup_id) catch {};
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
            if (!entry.value_ptr.isTimedOut(now_ns, self.config.lookup_timeout_ms)) continue;
            timed_out_ids.append(self.allocator, entry.key_ptr.*) catch break;
        }

        for (timed_out_ids.items) |lookup_id| {
            self.finishLookup(lookup_id, true) catch {};
        }
    }

    fn pumpLookup(self: *Service, lookup_id: u32) !void {
        const lookup = self.active_lookups.getPtr(lookup_id) orelse return;

        while (lookup.nextPeer(&self.config)) |peer_id| {
            const known = self.protocol.getKnownNode(&peer_id) orelse {
                lookup.onFailure(&peer_id, &self.config);
                continue;
            };

            var distances: [127]u16 = undefined;
            const count = findNodeLogDistances(&lookup.target, &peer_id, @min(self.config.lookup_request_limit, distances.len), &distances);
            if (count == 0) {
                lookup.onFailure(&peer_id, &self.config);
                continue;
            }

            const req_id = self.protocol.sendFindNode(
                &known.node_id,
                &known.pubkey,
                known.addr,
                distances[0..count],
                self.socketForAddress(known.addr) orelse {
                    lookup.onFailure(&peer_id, &self.config);
                    continue;
                },
            ) catch {
                lookup.onFailure(&peer_id, &self.config);
                continue;
            };
            try self.request_lookup_ids.put(LookupRequestKey.from(peer_id, req_id), lookup_id);
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

            const record = self.protocol.node_records.get(peer.node_id) orelse continue;
            const enr_bytes = record.enr orelse continue;
            try enrs.append(self.allocator, try self.allocator.dupe(u8, enr_bytes));
            succeeded += 1;
        }

        const owned_enrs = try enrs.toOwnedSlice(self.allocator);
        enrs = .empty;

        try self.completed_events.append(self.allocator, .{
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
            self.completed_events.append(self.allocator, .{
                .peer_disconnected = .{
                    .peer_id = removed.key,
                    .peer_addr = removed.value.addr,
                },
            }) catch {};
        }

        for (&self.protocol.routing_table.buckets) |*bucket| {
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
                self.completed_events.append(self.allocator, .{
                    .peer_connected = .{
                        .peer_id = entry.node_id,
                        .peer_addr = entry.addr,
                    },
                }) catch {};
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

    fn routingEntry(self: *const Service, node_id: *const NodeId) ?kbucket.Entry {
        const distance = kbucket.logDistance(&self.protocol.config.local_node_id, node_id) orelse return null;
        for (self.protocol.routing_table.getBucket(distance)) |entry| {
            if (std.mem.eql(u8, &entry.node_id, node_id)) return entry;
        }
        return null;
    }

    fn disconnectPeer(self: *Service, peer_id: NodeId) void {
        const addr = if (self.connected_peers.get(peer_id)) |tracked|
            tracked.addr
        else if (self.protocol.node_records.get(peer_id)) |record|
            record.addr
        else
            return;

        _ = self.protocol.routing_table.insert(.{
            .node_id = peer_id,
            .addr = addr,
            .last_seen = currentTimestampNs(self.io),
            .status = .disconnected,
        });

        const removed = self.connected_peers.fetchRemove(peer_id) orelse return;
        self.completed_events.append(self.allocator, .{
            .peer_disconnected = .{
                .peer_id = removed.key,
                .peer_addr = removed.value.addr,
            },
        }) catch {};
    }

    fn commitLocalEnrBytes(self: *Service, updated_enr: []u8, next_seq: u64, clear_votes: bool) !void {
        errdefer self.allocator.free(updated_enr);

        if (clear_votes) {
            self.addr_votes_ip4.clear();
            self.addr_votes_ip6.clear();
        }

        if (self.owned_local_enr) |owned| self.allocator.free(owned);
        self.owned_local_enr = updated_enr;
        self.protocol.config.local_enr = updated_enr;
        self.protocol.config.local_enr_seq = next_seq;
        self.config.protocol_config.local_enr = updated_enr;
        self.config.protocol_config.local_enr_seq = next_seq;

        try self.completed_events.append(self.allocator, .{
            .local_enr_updated = .{
                .seq = next_seq,
                .enr = try self.allocator.dupe(u8, updated_enr),
            },
        });

        self.pingConnectedPeers();
    }

    fn socketForAddress(self: *Service, addr: Address) ?*udp_socket.Socket {
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

    fn drainIncomingPacketsFrom(self: *Service, socket: *udp_socket.Socket, recv_buf: []u8) void {
        while (true) {
            const result = socket.receiveTimeout(recv_buf, .{
                .duration = .{
                    .raw = Io.Duration.fromMilliseconds(@intCast(self.receiveTimeoutPerSocketMs())),
                    .clock = .awake,
                },
            }) catch |err| switch (err) {
                error.Timeout => return,
                else => return,
            };

            scoped_log.debug("discv5: received UDP packet len={d} from={any}", .{
                result.data.len,
                result.from,
            });
            self.protocol.handlePacket(result.data, result.from, socket) catch |err| {
                scoped_log.debug("discv5: handlePacket failed for {any}: {}", .{ result.from, err });
            };
        }
    }

    fn contactAddressFromParsedEnr(self: *const Service, parsed: *const enr_mod.Enr) ?Address {
        const addr_ip4 = if (parsed.ip) |ip|
            if (parsed.udp orelse parsed.tcp) |port|
                Address{ .ip4 = .{ .bytes = ip, .port = port } }
            else
                null
        else
            null;
        const addr_ip6 = if (parsed.ip6) |ip6|
            if (parsed.udp6) |port|
                Address{ .ip6 = .{ .bytes = ip6, .port = port } }
            else
                null
        else
            null;

        if (self.socket_ip4 != null and self.socket_ip6 == null) return addr_ip4 orelse addr_ip6;
        if (self.socket_ip6 != null and self.socket_ip4 == null) return addr_ip6 orelse addr_ip4;
        return addr_ip4 orelse addr_ip6;
    }
};

fn currentTimestampNs(io: Io) i64 {
    return @intCast(Io.Timestamp.now(io, .real).toNanoseconds());
}

fn currentUnixTimeMs(io: Io) u64 {
    const ms = Io.Timestamp.now(io, .real).toMilliseconds();
    return if (ms < 0) 0 else @intCast(ms);
}

fn appendUniqueDistance(out: []u16, len: *usize, distance: u16) void {
    for (out[0..len.*]) |existing| {
        if (existing == distance) return;
    }
    out[len.*] = distance;
    len.* += 1;
}

fn findNodeLogDistances(target: *const NodeId, peer_id: *const NodeId, max_distances: usize, out: []u16) usize {
    if (max_distances == 0) return 0;

    var len: usize = 0;
    var wire_distance: u16 = 1;
    if (kbucket.logDistance(target, peer_id)) |distance| {
        wire_distance = @as(u16, distance) + 1;
    }

    appendUniqueDistance(out, &len, wire_distance);

    var diff: u16 = 1;
    while (len < max_distances and diff <= 256) : (diff += 1) {
        if (wire_distance + diff <= 256) appendUniqueDistance(out, &len, wire_distance + diff);
        if (len >= max_distances) break;
        if (wire_distance > diff) appendUniqueDistance(out, &len, wire_distance - diff);
    }
    return len;
}

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
        const secp = @import("secp256k1.zig");
        const pubkey = try secp.pubkeyFromSecret(&secret_key);
        const node_id = enr_mod.nodeIdFromCompressedPubkey(&pubkey);

        var service = try Service.init(io, alloc, .{
            .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
            .protocol_config = .{
                .local_secret_key = secret_key,
                .local_node_id = node_id,
            },
            .lookup_timeout_ms = 2_000,
        });
        errdefer service.deinit();

        var builder = enr_mod.Builder.init(alloc, secret_key, 1);
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

test "discv5 service: lookup emits lookup_finished" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex.zig");
    const secp = @import("secp256k1.zig");

    const sk_a = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const pk_a = try secp.pubkeyFromSecret(&sk_a);
    const node_id_a = enr_mod.nodeIdFromCompressedPubkey(&pk_a);

    const sk_b = hex.hexToBytesComptime(32, "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb14571f7");
    const pk_b = try secp.pubkeyFromSecret(&sk_b);
    const node_id_b = enr_mod.nodeIdFromCompressedPubkey(&pk_b);

    const sk_c = hex.hexToBytesComptime(32, "7e8107fe766b7f1821c3a7fbc56d18f734f0ebf898f0b85f82412b6d1fa7f4d3");
    const pk_c = try secp.pubkeyFromSecret(&sk_c);
    const node_id_c = enr_mod.nodeIdFromCompressedPubkey(&pk_c);

    var service_a = try Service.init(io, alloc, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .protocol_config = .{
            .local_secret_key = sk_a,
            .local_node_id = node_id_a,
        },
        .lookup_timeout_ms = 1_000,
    });
    defer service_a.deinit();

    var socket_b = try udp_socket.Socket.bind(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
    defer socket_b.close();

    const addr_b = socket_b.address;
    const addr_c = Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 30305 } };

    var a_builder = enr_mod.Builder.init(alloc, sk_a, 1);
    a_builder.ip = .{ 127, 0, 0, 1 };
    const addr_a = service_a.boundAddress(.ip4) orelse return error.MissingBindAddress;
    a_builder.udp = addr_a.getPort();
    const a_enr = try a_builder.encode();
    defer alloc.free(a_enr);
    service_a.protocol.config.local_enr = a_enr;
    service_a.protocol.config.local_enr_seq = 1;

    var b_builder = enr_mod.Builder.init(alloc, sk_b, 1);
    b_builder.ip = .{ 127, 0, 0, 1 };
    b_builder.udp = addr_b.getPort();
    const b_enr = try b_builder.encode();
    defer alloc.free(b_enr);

    var c_builder = enr_mod.Builder.init(alloc, sk_c, 1);
    c_builder.ip = .{ 127, 0, 0, 1 };
    c_builder.udp = addr_c.getPort();
    const c_enr = try c_builder.encode();
    defer alloc.free(c_enr);

    var proto_b = try Protocol.init(io, alloc, .{
        .local_secret_key = sk_b,
        .local_node_id = node_id_b,
        .local_enr = b_enr,
        .local_enr_seq = 1,
    });
    defer proto_b.deinit();

    service_a.addNode(node_id_b, &pk_b, addr_b, b_enr);
    proto_b.addNode(node_id_a, &pk_a, addr_a, a_enr);
    proto_b.addNode(node_id_c, &pk_c, addr_c, c_enr);

    const lookup_id = try service_a.startLookup(&node_id_c);

    var recv_buf_a: [protocol_mod.MAX_PACKET_SIZE]u8 = undefined;
    var recv_buf_b: [protocol_mod.MAX_PACKET_SIZE]u8 = undefined;

    const inbound_a = try socket_b.receiveTimeout(&recv_buf_b, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_b.handlePacket(inbound_a.data, inbound_a.from, &socket_b);

    service_a.poll();

    const handshake = try socket_b.receiveTimeout(&recv_buf_b, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_b.handlePacket(handshake.data, handshake.from, &socket_b);

    const socket_a = service_a.socketForAddress(addr_a) orelse return error.MissingBindAddress;
    const nodes_packet = try socket_a.receiveTimeout(&recv_buf_a, .{
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
                if (std.mem.eql(u8, &discovered.node_id, &node_id_c)) {
                    saw_discovered_c = true;
                    try std.testing.expectEqual(node_id_b, discovered.source_peer_id);
                    try std.testing.expectEqual(addr_b, discovered.source_peer_addr);
                    try std.testing.expectEqual(@as(?u32, lookup_id), discovered.lookup_id);
                }
            },
            .lookup_finished => |lookup_finished| {
                saw_lookup_finished = true;
                try std.testing.expect(!lookup_finished.timed_out);

                var saw_b = false;
                for (lookup_finished.enrs) |raw_enr| {
                    var parsed = try enr_mod.decode(alloc, raw_enr);
                    defer parsed.deinit();
                    const node_id = parsed.nodeId() orelse continue;
                    if (std.mem.eql(u8, &node_id, &node_id_b)) saw_b = true;
                }
                try std.testing.expect(saw_b);
            },
            else => {},
        }
    }

    var active_request_it = service_a.protocol.active_requests.iterator();
    while (active_request_it.next()) |entry| {
        entry.value_ptr.started_at_ns = 0;
    }
    service_a.poll();

    while (service_a.popEvent()) |event| {
        var owned = event;
        defer owned.deinit(alloc);

        switch (owned) {
            .discovered_enr => |discovered| {
                if (std.mem.eql(u8, &discovered.node_id, &node_id_c)) {
                    saw_discovered_c = true;
                    try std.testing.expectEqual(@as(?u32, lookup_id), discovered.lookup_id);
                }
            },
            .lookup_finished => |lookup_finished| {
                saw_lookup_finished = true;
                try std.testing.expect(!lookup_finished.timed_out);

                var saw_b = false;
                for (lookup_finished.enrs) |raw_enr| {
                    var parsed = try enr_mod.decode(alloc, raw_enr);
                    defer parsed.deinit();
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

test "discv5 service: connected peers are pinged and disconnected on timeout" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex.zig");
    const secp = @import("secp256k1.zig");

    const sk_a = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const pk_a = try secp.pubkeyFromSecret(&sk_a);
    const node_id_a = enr_mod.nodeIdFromCompressedPubkey(&pk_a);

    const sk_b = hex.hexToBytesComptime(32, "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb14571f7");
    const pk_b = try secp.pubkeyFromSecret(&sk_b);
    const node_id_b = enr_mod.nodeIdFromCompressedPubkey(&pk_b);

    var service_a = try Service.init(io, alloc, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .protocol_config = .{
            .local_secret_key = sk_a,
            .local_node_id = node_id_a,
            .request_timeout_ms = 1_000,
        },
        .ping_interval_ms = 30_000,
    });
    defer service_a.deinit();

    var socket_b = try udp_socket.Socket.bind(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
    defer socket_b.close();

    const addr_b = socket_b.address;

    var a_builder = enr_mod.Builder.init(alloc, sk_a, 1);
    a_builder.ip = .{ 127, 0, 0, 1 };
    const addr_a = service_a.boundAddress(.ip4) orelse return error.MissingBindAddress;
    a_builder.udp = addr_a.getPort();
    const a_enr = try a_builder.encode();
    defer alloc.free(a_enr);
    try service_a.setLocalEnr(a_enr);

    var b_builder = enr_mod.Builder.init(alloc, sk_b, 1);
    b_builder.ip = .{ 127, 0, 0, 1 };
    b_builder.udp = addr_b.getPort();
    const b_enr = try b_builder.encode();
    defer alloc.free(b_enr);

    var proto_b = try Protocol.init(io, alloc, .{
        .local_secret_key = sk_b,
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

    const inbound_a = try socket_b.receiveTimeout(&recv_buf_b, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_b.handlePacket(inbound_a.data, inbound_a.from, &socket_b);
    service_a.poll();

    const handshake = try socket_b.receiveTimeout(&recv_buf_b, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_b.handlePacket(handshake.data, handshake.from, &socket_b);

    const socket_a = service_a.socketForAddress(addr_a) orelse return error.MissingBindAddress;
    const pong_packet = try socket_a.receiveTimeout(&recv_buf_a, .{
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

    try std.testing.expect(service_a.protocol.active_requests.count() > 0);
    var active_request_it = service_a.protocol.active_requests.iterator();
    while (active_request_it.next()) |entry| {
        entry.value_ptr.started_at_ns = 0;
    }

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

test "discv5 service: setLocalEnr exposes current local ENR" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex.zig");
    const secp = @import("secp256k1.zig");

    const sk = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const pk = try secp.pubkeyFromSecret(&sk);
    const node_id = enr_mod.nodeIdFromCompressedPubkey(&pk);

    var builder = enr_mod.Builder.init(alloc, sk, 1);
    builder.ip = .{ 10, 0, 0, 1 };
    builder.udp = 9000;
    builder.tcp = 9000;
    const local_enr = try builder.encode();
    defer alloc.free(local_enr);

    var service = try Service.init(io, alloc, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .protocol_config = .{
            .local_secret_key = sk,
            .local_node_id = node_id,
            .local_enr = local_enr,
            .local_enr_seq = 1,
        },
    });
    defer service.deinit();

    try std.testing.expectEqualSlices(u8, local_enr, service.localEnr().?);

    var updated_builder = enr_mod.Builder.init(alloc, sk, 2);
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

    var stale_builder = enr_mod.Builder.init(alloc, sk, 2);
    stale_builder.ip = .{ 198, 51, 100, 2 };
    stale_builder.udp = 40404;
    const stale_enr = try stale_builder.encode();
    defer alloc.free(stale_enr);
    try std.testing.expectError(error.StaleEnrSeq, service.setLocalEnr(stale_enr));

    const other_sk = hex.hexToBytesComptime(32, "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb14571f7");
    var foreign_builder = enr_mod.Builder.init(alloc, other_sk, 3);
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

test "discv5 service: dual bind exposes both listener families" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex.zig");
    const secp = @import("secp256k1.zig");

    const sk = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const pk = try secp.pubkeyFromSecret(&sk);
    const node_id = enr_mod.nodeIdFromCompressedPubkey(&pk);

    var service = try Service.init(io, alloc, .{
        .bind_addresses = .{
            .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } },
            .ip6 = .{ .ip6 = .{ .bytes = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, .port = 0 } },
        },
        .protocol_config = .{
            .local_secret_key = sk,
            .local_node_id = node_id,
        },
    });
    defer service.deinit();

    try std.testing.expect(service.boundPort(.ip4) != null);
    try std.testing.expect(service.boundPort(.ip6) != null);
    try std.testing.expect(service.boundAddress(.ip4) != null);
    try std.testing.expect(service.boundAddress(.ip6) != null);
}

test "discv5 service: addEnr prefers available bind family" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex.zig");
    const secp = @import("secp256k1.zig");

    const sk_local = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const pk_local = try secp.pubkeyFromSecret(&sk_local);
    const node_id_local = enr_mod.nodeIdFromCompressedPubkey(&pk_local);

    const sk_peer = hex.hexToBytesComptime(32, "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb14571f7");
    const loopback6 = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    var builder = enr_mod.Builder.init(alloc, sk_peer, 1);
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
            .local_secret_key = sk_local,
            .local_node_id = node_id_local,
        },
    });
    defer service.deinit();

    try std.testing.expect(service.addEnr(peer_enr));

    var parsed = try enr_mod.decode(alloc, peer_enr);
    defer parsed.deinit();
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

test "discv5 service: discovered nodes preserve QUIC-preferred dial ports" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex.zig");
    const secp = @import("secp256k1.zig");

    const local_sk = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const local_pk = try secp.pubkeyFromSecret(&local_sk);
    const local_node_id = enr_mod.nodeIdFromCompressedPubkey(&local_pk);
    const source_sk = hex.hexToBytesComptime(32, "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb14571f7");
    const source_pk = try secp.pubkeyFromSecret(&source_sk);
    const source_node_id = enr_mod.nodeIdFromCompressedPubkey(&source_pk);

    const loopback6 = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

    var service = try Service.init(io, alloc, .{
        .bind_addresses = .{
            .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } },
            .ip6 = .{ .ip6 = .{ .bytes = loopback6, .port = 0 } },
        },
        .protocol_config = .{
            .local_secret_key = local_sk,
            .local_node_id = local_node_id,
        },
    });
    defer service.deinit();

    var peer_builder = enr_mod.Builder.init(alloc, source_sk, 1);
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

    var parsed_nodes = service.collectDiscoveredNodes(&nodes);
    defer parsed_nodes.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 1), parsed_nodes.items.len);
    const parsed = parsed_nodes.items[0];
    try std.testing.expect(parsed.has_quic);
    try std.testing.expectEqual(@as(u16, 30305), parsed.addr_ip4.?.ip4.port);
    try std.testing.expectEqual(@as(u16, 30405), parsed.addr_ip6.?.ip6.port);
}

test "discv5 service: addr votes update local ENR" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex.zig");

    const sk = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const pk = try @import("secp256k1.zig").pubkeyFromSecret(&sk);
    const node_id = enr_mod.nodeIdFromCompressedPubkey(&pk);

    var builder = enr_mod.Builder.init(alloc, sk, 1);
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
            .local_secret_key = sk,
            .local_node_id = node_id,
            .local_enr = local_enr,
            .local_enr_seq = 1,
        },
        .addr_votes_to_update_enr = 2,
    });
    defer service.deinit();

    service.maybeUpdateLocalEnrFromVote([_]u8{0x11} ** 32, .{ .ip4 = .{ .bytes = .{ 203, 0, 113, 1 }, .port = 30303 } });
    try std.testing.expectEqual(@as(u64, 1), service.localEnrSeq());

    service.maybeUpdateLocalEnrFromVote([_]u8{0x22} ** 32, .{ .ip4 = .{ .bytes = .{ 203, 0, 113, 1 }, .port = 30303 } });
    try std.testing.expectEqual(@as(u64, 2), service.localEnrSeq());

    var updated = try enr_mod.decode(alloc, service.localEnr().?);
    defer updated.deinit();
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

test "discv5 service: ipv4-mapped ipv6 vote normalizes to ipv4" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex.zig");

    const sk = hex.hexToBytesComptime(32, "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb14571f7");
    const pk = try @import("secp256k1.zig").pubkeyFromSecret(&sk);
    const node_id = enr_mod.nodeIdFromCompressedPubkey(&pk);

    var builder = enr_mod.Builder.init(alloc, sk, 1);
    builder.ip = .{ 10, 0, 0, 1 };
    builder.udp = 9000;
    const local_enr = try builder.encode();
    defer alloc.free(local_enr);

    var service = try Service.init(io, alloc, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .protocol_config = .{
            .local_secret_key = sk,
            .local_node_id = node_id,
            .local_enr = local_enr,
            .local_enr_seq = 1,
        },
        .addr_votes_to_update_enr = 1,
    });
    defer service.deinit();

    service.maybeUpdateLocalEnrFromVote([_]u8{0x33} ** 32, .{
        .ip6 = .{
            .bytes = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 198, 51, 100, 2 },
            .port = 40404,
        },
    });

    var updated = try enr_mod.decode(alloc, service.localEnr().?);
    defer updated.deinit();
    try std.testing.expectEqual([4]u8{ 198, 51, 100, 2 }, updated.ip.?);
    try std.testing.expectEqual(@as(?u16, 40404), updated.udp);
}

test "discv5 service: live lookup discovers node through intermediary" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex.zig");

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
                    if (std.mem.eql(u8, &discovered.node_id, &node_2.node_id)) {
                        saw_discovered_target = true;
                        try std.testing.expectEqual(@as(?u32, lookup_id), discovered.lookup_id);
                    }
                },
                .lookup_finished => |lookup_finished| {
                    saw_lookup_finished = true;
                    try std.testing.expectEqual(lookup_id, lookup_finished.lookup_id);
                    try std.testing.expect(!lookup_finished.timed_out);

                    for (lookup_finished.enrs) |raw_enr| {
                        var parsed = try enr_mod.decode(alloc, raw_enr);
                        defer parsed.deinit();
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

test "discv5 service: live TALKREQ TALKRESP round-trip" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex.zig");

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

test "discv5 service: queued ingress respects processing budget" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex.zig");

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
