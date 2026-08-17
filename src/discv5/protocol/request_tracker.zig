//! Request lifecycle state for discv5 protocol traffic.
//!
//! Active requests are in-flight packets retained for retry and response
//! matching. WHOAREYOU probes are indexed separately by `(source address,
//! request nonce)` because WHOAREYOU packets are unauthenticated and do not
//! carry the remote node id. Requests not yet sent are durable request intents
//! held in bounded FIFO queues per peer endpoint.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const net = Io.net;
const Address = net.IpAddress;

const messages = @import("message.zig");
const NodeId = @import("../enr.zig").NodeId;
const packet = @import("packet.zig");
const state = @import("state.zig");

pub const Error = error{
    BufferTooSmall,
    TooManyActiveRequests,
    TooManyQueuedRequests,
    TooManyQueuedRequestsForEndpoint,
    MissingActiveRequest,
    InvalidChallenge,
    EndpointEstablishing,
} || Allocator.Error;

pub const Limits = struct {
    max_active_requests: usize = 1024,
    max_queued_requests: usize = 1024,
    max_queued_requests_per_endpoint: usize = 16,
};

pub const PacketBytes = struct {
    bytes: [packet.MAX_PACKET_SIZE]u8 = undefined,
    len: u16 = 0,

    pub fn init(data: []const u8) error{BufferTooSmall}!PacketBytes {
        var out = PacketBytes{};
        try out.set(data);
        return out;
    }

    pub fn set(self: *PacketBytes, data: []const u8) error{BufferTooSmall}!void {
        if (data.len > self.bytes.len) return error.BufferTooSmall;
        @memcpy(self.bytes[0..data.len], data);
        self.len = @intCast(data.len);
    }

    pub fn slice(self: *const PacketBytes) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const RequestKind = enum {
    ping,
    findnode,
    talkreq,
};

pub const Endpoint = struct {
    node_id: NodeId,
    addr: Address,
};

pub const RequestKey = struct {
    endpoint: Endpoint,
    req_id: messages.ReqId,

    pub fn from(endpoint: Endpoint, req_id: messages.ReqId) RequestKey {
        return .{ .endpoint = endpoint, .req_id = req_id };
    }
};

pub const EndpointContext = struct {
    pub fn hash(_: EndpointContext, endpoint: Endpoint) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(endpoint.node_id[0..]);
        hashAddressPort(&hasher, endpoint.addr);
        return hasher.final();
    }

    pub fn eql(_: EndpointContext, a: Endpoint, b: Endpoint) bool {
        return std.mem.eql(u8, &a.node_id, &b.node_id) and Address.eql(&a.addr, &b.addr);
    }
};

const RequestKeyContext = struct {
    pub fn hash(_: RequestKeyContext, key: RequestKey) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(key.endpoint.node_id[0..]);
        hashAddressPort(&hasher, key.endpoint.addr);
        hasher.update(key.req_id.slice());
        std.hash.autoHash(&hasher, key.req_id.len);
        return hasher.final();
    }

    pub fn eql(_: RequestKeyContext, a: RequestKey, b: RequestKey) bool {
        return EndpointContext.eql(.{}, a.endpoint, b.endpoint) and
            a.req_id.len == b.req_id.len and
            std.mem.eql(u8, a.req_id.slice(), b.req_id.slice());
    }
};

fn hashAddressPort(hasher: *std.hash.Wyhash, addr: Address) void {
    switch (addr) {
        .ip4 => |ip4| {
            hasher.update(&[_]u8{4});
            hasher.update(ip4.bytes[0..]);
            std.hash.autoHash(hasher, ip4.port);
        },
        .ip6 => |ip6| {
            hasher.update(&[_]u8{6});
            hasher.update(ip6.bytes[0..]);
            std.hash.autoHash(hasher, ip6.port);
        },
    }
}

const AddressPortKey = struct {
    family: Address.Family,
    bytes: [16]u8,
    port: u16,

    fn fromAddress(addr: Address) AddressPortKey {
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

const ChallengeKey = struct {
    addr: AddressPortKey,
    nonce: [packet.NONCE_SIZE]u8,

    fn from(nonce: *const [packet.NONCE_SIZE]u8, addr: Address) ChallengeKey {
        return .{ .addr = AddressPortKey.fromAddress(addr), .nonce = nonce.* };
    }
};

pub const ActiveFindNodeRequest = struct {
    enrs: std.ArrayListUnmanaged([]u8) = .empty,
    total_responses: ?u64 = null,
    responses_received: u64 = 0,
    requested_distances: [127]u16 = undefined,
    requested_distances_len: usize = 0,

    pub fn deinit(self: *ActiveFindNodeRequest, alloc: Allocator) void {
        for (self.enrs.items) |enr| alloc.free(enr);
        self.enrs.deinit(alloc);
    }
};

pub const ActiveRequestKind = union(enum) {
    ping: void,
    findnode: ActiveFindNodeRequest,
    talkreq: void,

    pub fn deinit(self: *ActiveRequestKind, alloc: Allocator) void {
        switch (self.*) {
            .ping => {},
            .findnode => |*findnode| findnode.deinit(alloc),
            .talkreq => {},
        }
    }
};

pub const ProbeState = struct {
    nonce: [packet.NONCE_SIZE]u8,
    dest_pubkey: [33]u8,
    plaintext: PacketBytes,
};

pub const ResponseState = struct {
    pending_session: ?state.PendingSessionKeys = null,
    challenge_probe: ?ProbeState = null,
};

pub const ActiveRequestPhase = union(enum) {
    awaiting_whoareyou: ProbeState,
    awaiting_response: ResponseState,
};

pub const ActiveRequest = struct {
    endpoint: Endpoint,
    started_at_ns: i64,
    attempts: u32 = 0,
    socket: *const net.Socket,
    retry_packet: PacketBytes,
    phase: ActiveRequestPhase,
    kind: ActiveRequestKind,

    pub fn deinit(self: *ActiveRequest, alloc: Allocator) void {
        self.kind.deinit(alloc);
    }

    pub fn requestKind(self: *const ActiveRequest) RequestKind {
        return switch (self.kind) {
            .ping => .ping,
            .findnode => .findnode,
            .talkreq => .talkreq,
        };
    }
};

pub const RequestIntent = struct {
    queued_at_ns: i64,
    endpoint: Endpoint,
    dest_pubkey: [33]u8,
    req_id: messages.ReqId,
    request_kind: RequestKind,
    requested_distances: [127]u16 = undefined,
    requested_distances_len: usize = 0,
    plaintext: PacketBytes,

    pub fn init(
        endpoint: Endpoint,
        dest_pubkey: *const [33]u8,
        req_id: messages.ReqId,
        request_kind: RequestKind,
        distance_values: []const u16,
        plaintext: []const u8,
        queued_at_ns: i64,
    ) Error!RequestIntent {
        return .{
            .queued_at_ns = queued_at_ns,
            .endpoint = endpoint,
            .dest_pubkey = dest_pubkey.*,
            .req_id = req_id,
            .request_kind = request_kind,
            .requested_distances = pendingDistances(distance_values),
            .requested_distances_len = @min(distance_values.len, 127),
            .plaintext = try PacketBytes.init(plaintext),
        };
    }

    pub fn distances(self: *const RequestIntent) []const u16 {
        return self.requested_distances[0..self.requested_distances_len];
    }

    pub fn plaintextSlice(self: *const RequestIntent) []const u8 {
        return self.plaintext.slice();
    }
};

const RequestQueue = struct {
    items: std.ArrayListUnmanaged(RequestIntent) = .empty,
    head: usize = 0,

    fn deinit(self: *RequestQueue, alloc: Allocator) void {
        self.items.deinit(alloc);
    }

    fn len(self: *const RequestQueue) usize {
        return self.items.items.len - self.head;
    }

    fn isEmpty(self: *const RequestQueue) bool {
        return self.len() == 0;
    }

    fn liveItems(self: *const RequestQueue) []const RequestIntent {
        return self.items.items[self.head..];
    }

    fn append(self: *RequestQueue, alloc: Allocator, intent: RequestIntent) Allocator.Error!void {
        self.compactIfSparse();
        try self.items.append(alloc, intent);
    }

    fn prepend(self: *RequestQueue, alloc: Allocator, intent: RequestIntent) Allocator.Error!void {
        if (self.head > 0) {
            self.head -= 1;
            self.items.items[self.head] = intent;
            return;
        }
        try self.items.insert(alloc, 0, intent);
    }

    fn popFront(self: *RequestQueue) RequestIntent {
        std.debug.assert(!self.isEmpty());
        const intent = self.items.items[self.head];
        self.head += 1;
        self.compactIfSparse();
        return intent;
    }

    fn orderedRemoveLiveIndex(self: *RequestQueue, index: usize) RequestIntent {
        std.debug.assert(index < self.len());
        const intent = self.items.orderedRemove(self.head + index);
        self.compactIfSparse();
        return intent;
    }

    fn clear(self: *RequestQueue) void {
        self.items.clearRetainingCapacity();
        self.head = 0;
    }

    fn compactIfSparse(self: *RequestQueue) void {
        if (self.head == 0) return;
        const live_len = self.len();
        if (live_len == 0) {
            self.clear();
            return;
        }
        if (self.head < live_len) return;
        std.mem.copyForwards(RequestIntent, self.items.items[0..live_len], self.items.items[self.head..]);
        self.items.shrinkRetainingCapacity(live_len);
        self.head = 0;
    }
};

const PendingRequests = struct {
    // Per-endpoint pending state includes both requests that have not been sent
    // yet and, at most, one active request that is establishing a session. The
    // active request lives in `active`; this key only blocks the endpoint queue
    // until the WHOAREYOU/handshake exchange resolves.
    establishing: ?RequestKey = null,
    queue: RequestQueue = .{},

    fn deinit(self: *PendingRequests, alloc: Allocator) void {
        self.queue.deinit(alloc);
    }

    fn isEmpty(self: *const PendingRequests) bool {
        return self.establishing == null and self.queue.isEmpty();
    }
};

pub const ProbeView = struct {
    key: RequestKey,
    endpoint: Endpoint,
    req_id: messages.ReqId,
    request_kind: RequestKind,
    dest_pubkey: *const [33]u8,
    plaintext: []const u8,
};

pub const ExpiredRequest = struct {
    endpoint: Endpoint,
    req_id: messages.ReqId,
    kind: RequestKind,
    socket: ?*const net.Socket = null,
};

const ActiveRequestMap = std.HashMap(RequestKey, ActiveRequest, RequestKeyContext, std.hash_map.default_max_load_percentage);
const PendingRequestsMap = std.HashMap(Endpoint, PendingRequests, EndpointContext, std.hash_map.default_max_load_percentage);

pub const RequestTracker = struct {
    alloc: Allocator,
    limits: Limits,
    active: ActiveRequestMap,
    challenge_index: std.AutoHashMap(ChallengeKey, RequestKey),
    queued: PendingRequestsMap,
    queued_total: usize = 0,

    pub fn init(alloc: Allocator, limits: Limits) RequestTracker {
        return .{
            .alloc = alloc,
            .limits = limits,
            .active = ActiveRequestMap.init(alloc),
            .challenge_index = std.AutoHashMap(ChallengeKey, RequestKey).init(alloc),
            .queued = PendingRequestsMap.init(alloc),
        };
    }

    pub fn deinit(self: *RequestTracker) void {
        var active_it = self.active.iterator();
        while (active_it.next()) |entry| entry.value_ptr.deinit(self.alloc);
        self.active.deinit();
        self.challenge_index.deinit();
        var queued_it = self.queued.iterator();
        while (queued_it.next()) |entry| entry.value_ptr.deinit(self.alloc);
        self.queued.deinit();
    }

    pub fn activeCount(self: *const RequestTracker) usize {
        return self.active.count();
    }

    pub fn pendingCount(self: *const RequestTracker) usize {
        return self.challenge_index.count() + self.queued_total;
    }

    pub fn hasActiveFindNodeRequest(self: *const RequestTracker, peer_id: *const NodeId) bool {
        var it = self.active.iterator();
        while (it.next()) |entry| {
            if (!std.mem.eql(u8, &entry.value_ptr.endpoint.node_id, peer_id)) continue;
            if (entry.value_ptr.kind == .findnode) return true;
        }
        return false;
    }

    pub fn shouldQueueForEndpoint(self: *const RequestTracker, endpoint: Endpoint) bool {
        const endpoint_key = endpoint;
        const pending = self.queued.get(endpoint_key) orelse return false;
        return pending.establishing != null or !pending.queue.isEmpty();
    }

    pub fn pendingSessionKeysForEndpoint(self: *const RequestTracker, endpoint: Endpoint) ?state.PendingSessionKeys {
        const endpoint_key = endpoint;
        const pending = self.queued.get(endpoint_key) orelse return null;
        const key = pending.establishing orelse return null;
        const active = self.active.get(key) orelse return null;
        return switch (active.phase) {
            .awaiting_whoareyou => null,
            .awaiting_response => |response| response.pending_session,
        };
    }

    pub fn putActiveAwaitingResponse(
        self: *RequestTracker,
        endpoint: Endpoint,
        req_id: messages.ReqId,
        request_kind: RequestKind,
        distances: []const u16,
        socket: *const net.Socket,
        packet_bytes: []const u8,
        started_at_ns: i64,
        pending_session: ?state.PendingSessionKeys,
    ) Error!void {
        const key = RequestKey.from(endpoint, req_id);
        // Reserve a queued slot for the establishing marker before mutating.
        if (pending_session != null and !self.queued.contains(endpoint)) {
            try self.queued.ensureUnusedCapacity(1);
        }

        try self.putActive(key, endpoint, request_kind, distances, socket, packet_bytes, started_at_ns, .{
            .awaiting_response = .{ .pending_session = pending_session },
        });

        if (pending_session != null) {
            self.indexEstablishingAssumeCapacity(endpoint, key);
        }
    }

    /// Track an authenticated request so a matching WHOAREYOU can recover when
    /// the remote endpoint has forgotten the established session.
    pub fn putActiveAwaitingResponseWithChallenge(
        self: *RequestTracker,
        endpoint: Endpoint,
        req_id: messages.ReqId,
        request_kind: RequestKind,
        distances: []const u16,
        socket: *const net.Socket,
        packet_bytes: []const u8,
        started_at_ns: i64,
        nonce: [packet.NONCE_SIZE]u8,
        dest_pubkey: *const [33]u8,
        plaintext: []const u8,
    ) Error!void {
        const key = RequestKey.from(endpoint, req_id);
        try self.challenge_index.ensureUnusedCapacity(1);
        const plaintext_copy = try PacketBytes.init(plaintext);
        try self.putActive(key, endpoint, request_kind, distances, socket, packet_bytes, started_at_ns, .{
            .awaiting_response = .{
                .challenge_probe = .{
                    .nonce = nonce,
                    .dest_pubkey = dest_pubkey.*,
                    .plaintext = plaintext_copy,
                },
            },
        });
        self.challenge_index.putAssumeCapacityNoClobber(ChallengeKey.from(&nonce, endpoint.addr), key);
    }

    pub fn putActiveProbe(
        self: *RequestTracker,
        endpoint: Endpoint,
        req_id: messages.ReqId,
        request_kind: RequestKind,
        distances: []const u16,
        socket: *const net.Socket,
        packet_bytes: []const u8,
        started_at_ns: i64,
        nonce: [packet.NONCE_SIZE]u8,
        dest_pubkey: *const [33]u8,
        plaintext: []const u8,
    ) Error!void {
        const key = RequestKey.from(endpoint, req_id);
        // At most one in-flight handshake (establishing request) per endpoint.
        if (self.queued.get(endpoint)) |pending| {
            if (pending.establishing != null) return error.TooManyActiveRequests;
        } else {
            try self.queued.ensureUnusedCapacity(1);
        }
        try self.challenge_index.ensureUnusedCapacity(1);
        const plaintext_copy = try PacketBytes.init(plaintext);

        try self.putActive(key, endpoint, request_kind, distances, socket, packet_bytes, started_at_ns, .{
            .awaiting_whoareyou = .{
                .nonce = nonce,
                .dest_pubkey = dest_pubkey.*,
                .plaintext = plaintext_copy,
            },
        });

        self.challenge_index.putAssumeCapacityNoClobber(ChallengeKey.from(&nonce, endpoint.addr), key);
        self.indexEstablishingAssumeCapacity(endpoint, key);
    }

    /// Insert an active request for `key`, replacing any existing entry and
    /// reserving the active-table slot. Phase-specific reservations (queued
    /// establishing marker, challenge index) and post-insert indexing are the
    /// caller's responsibility. Everything fallible here runs before the table
    /// is mutated, so a failure leaves the tracker unchanged.
    fn putActive(
        self: *RequestTracker,
        key: RequestKey,
        endpoint: Endpoint,
        request_kind: RequestKind,
        distances: []const u16,
        socket: *const net.Socket,
        packet_bytes: []const u8,
        started_at_ns: i64,
        phase: ActiveRequestPhase,
    ) Error!void {
        if (!self.active.contains(key)) try self.ensureActiveInsertCapacity();
        const retry_packet = try PacketBytes.init(packet_bytes);

        self.removeActiveByKey(key);
        self.active.putAssumeCapacityNoClobber(key, .{
            .endpoint = endpoint,
            .started_at_ns = started_at_ns,
            .attempts = 0,
            .socket = socket,
            .retry_packet = retry_packet,
            .phase = phase,
            .kind = activeKindFromRequestKind(request_kind, distances),
        });
    }

    pub fn cancelActive(self: *RequestTracker, endpoint: Endpoint, req_id: messages.ReqId) void {
        self.removeActiveByKey(RequestKey.from(endpoint, req_id));
    }

    pub fn queueRequest(
        self: *RequestTracker,
        endpoint: Endpoint,
        dest_pubkey: *const [33]u8,
        req_id: messages.ReqId,
        request_kind: RequestKind,
        distances: []const u16,
        plaintext: []const u8,
        queued_at_ns: i64,
    ) Error!void {
        if (self.queued_total >= self.limits.max_queued_requests) return error.TooManyQueuedRequests;
        const intent = try RequestIntent.init(endpoint, dest_pubkey, req_id, request_kind, distances, plaintext, queued_at_ns);
        const endpoint_key = endpoint;
        const gop = try self.queued.getOrPut(endpoint_key);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        errdefer if (!gop.found_existing and gop.value_ptr.isEmpty()) {
            gop.value_ptr.deinit(self.alloc);
            _ = self.queued.remove(endpoint_key);
        };
        if (gop.value_ptr.queue.len() >= self.limits.max_queued_requests_per_endpoint) {
            return error.TooManyQueuedRequestsForEndpoint;
        }
        try gop.value_ptr.queue.append(self.alloc, intent);
        self.queued_total += 1;
    }

    pub fn probeForChallenge(
        self: *RequestTracker,
        nonce: *const [packet.NONCE_SIZE]u8,
        from: Address,
    ) ?ProbeView {
        const challenge_key = ChallengeKey.from(nonce, from);
        const key = self.challenge_index.get(challenge_key) orelse return null;
        const active = self.active.getPtr(key) orelse return null;
        if (!Address.eql(&active.endpoint.addr, &from)) return null;
        return switch (active.phase) {
            .awaiting_response => |*response| blk: {
                const probe = if (response.challenge_probe) |*value| value else break :blk null;
                if (!std.mem.eql(u8, &probe.nonce, nonce)) break :blk null;
                break :blk .{
                    .key = key,
                    .endpoint = active.endpoint,
                    .req_id = key.req_id,
                    .request_kind = active.requestKind(),
                    .dest_pubkey = &probe.dest_pubkey,
                    .plaintext = probe.plaintext.slice(),
                };
            },
            .awaiting_whoareyou => |*probe| blk: {
                if (!std.mem.eql(u8, &probe.nonce, nonce)) break :blk null;
                break :blk .{
                    .key = key,
                    .endpoint = active.endpoint,
                    .req_id = key.req_id,
                    .request_kind = active.requestKind(),
                    .dest_pubkey = &probe.dest_pubkey,
                    .plaintext = probe.plaintext.slice(),
                };
            },
        };
    }

    pub fn acceptChallenge(
        self: *RequestTracker,
        key: RequestKey,
        nonce: *const [packet.NONCE_SIZE]u8,
        from: Address,
        packet_bytes: []const u8,
        pending_session: state.PendingSessionKeys,
        now_ns: i64,
    ) Error!void {
        const challenge_key = ChallengeKey.from(nonce, from);
        const indexed_key = self.challenge_index.get(challenge_key) orelse return error.InvalidChallenge;
        if (!std.meta.eql(indexed_key, key)) return error.InvalidChallenge;

        const active = self.active.getPtr(key) orelse return error.MissingActiveRequest;
        if (!Address.eql(&active.endpoint.addr, &from)) return error.InvalidChallenge;
        const probe = switch (active.phase) {
            .awaiting_response => |response| response.challenge_probe orelse return error.InvalidChallenge,
            .awaiting_whoareyou => |value| value,
        };
        if (!std.mem.eql(u8, &probe.nonce, nonce)) return error.InvalidChallenge;

        // An established-session request does not already have an establishing
        // queue marker; reserve it before mutating the active request.
        if (self.queued.get(active.endpoint)) |pending| {
            if (pending.establishing) |existing| {
                if (!std.meta.eql(existing, key)) return error.EndpointEstablishing;
            }
        } else {
            try self.queued.ensureUnusedCapacity(1);
        }

        const retry_packet = try PacketBytes.init(packet_bytes);
        active.retry_packet = retry_packet;
        active.started_at_ns = now_ns;
        active.attempts = 0;
        active.phase = .{ .awaiting_response = .{ .pending_session = pending_session } };
        _ = self.challenge_index.remove(challenge_key);
        self.indexEstablishingAssumeCapacity(active.endpoint, key);
    }

    pub fn getActivePtr(self: *RequestTracker, endpoint: Endpoint, req_id: messages.ReqId) ?*ActiveRequest {
        return self.active.getPtr(RequestKey.from(endpoint, req_id));
    }

    pub fn finishActive(self: *RequestTracker, endpoint: Endpoint, req_id: messages.ReqId) ?ActiveRequest {
        const key = RequestKey.from(endpoint, req_id);
        const removed = self.active.fetchRemove(key) orelse return null;
        var active = removed.value;
        self.unindexActive(key, &active);
        return active;
    }

    /// Remove and return the active request for (endpoint, req_id) only when it
    /// exists and its kind matches `expected`; otherwise leave the tracker
    /// unchanged and return null. Collapses the lookup + kind guard + removal that
    /// single-response handlers (PONG, TALKRESP) would otherwise open-code.
    pub fn finishActiveExpectingKind(
        self: *RequestTracker,
        endpoint: Endpoint,
        req_id: messages.ReqId,
        expected: std.meta.Tag(ActiveRequestKind),
    ) ?ActiveRequest {
        const key = RequestKey.from(endpoint, req_id);
        const entry = self.active.getPtr(key) orelse return null;
        if (std.meta.activeTag(entry.kind) != expected) return null;
        var active = self.active.fetchRemove(key).?.value;
        self.unindexActive(key, &active);
        return active;
    }

    pub fn popNextQueued(self: *RequestTracker, endpoint: Endpoint) Error!?RequestIntent {
        const endpoint_key = endpoint;
        const pending = self.queued.getPtr(endpoint_key) orelse return null;
        if (pending.establishing != null) return null;
        if (pending.queue.isEmpty()) {
            var removed = self.queued.fetchRemove(endpoint_key).?.value;
            removed.deinit(self.alloc);
            return null;
        }

        if (self.active.count() >= self.limits.max_active_requests) return error.TooManyActiveRequests;

        const intent = pending.queue.popFront();
        self.queued_total -= 1;
        if (pending.isEmpty()) {
            var removed = self.queued.fetchRemove(endpoint_key).?.value;
            removed.deinit(self.alloc);
        }
        return intent;
    }

    pub fn pushFrontQueued(self: *RequestTracker, intent: RequestIntent) Error!void {
        if (self.queued_total >= self.limits.max_queued_requests) return error.TooManyQueuedRequests;
        const endpoint_key = intent.endpoint;
        const gop = try self.queued.getOrPut(endpoint_key);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        errdefer if (!gop.found_existing and gop.value_ptr.isEmpty()) {
            gop.value_ptr.deinit(self.alloc);
            _ = self.queued.remove(endpoint_key);
        };
        if (gop.value_ptr.queue.len() >= self.limits.max_queued_requests_per_endpoint) {
            return error.TooManyQueuedRequestsForEndpoint;
        }
        try gop.value_ptr.queue.prepend(self.alloc, intent);
        self.queued_total += 1;
    }

    pub fn pruneExpiredActive(
        self: *RequestTracker,
        io: Io,
        now_ns: i64,
        timeout_ms: u64,
        retries: u32,
        out: *std.ArrayListUnmanaged(ExpiredRequest),
    ) Allocator.Error!void {
        var expired: std.ArrayListUnmanaged(RequestKey) = .empty;
        defer expired.deinit(self.alloc);

        var it = self.active.iterator();
        while (it.next()) |entry| {
            if (!requestTimedOut(entry.value_ptr.started_at_ns, now_ns, timeout_ms)) continue;
            if (entry.value_ptr.attempts < retries) {
                const addr = entry.value_ptr.endpoint.addr;
                entry.value_ptr.socket.send(io, &addr, entry.value_ptr.retry_packet.slice()) catch {
                    try expired.append(self.alloc, entry.key_ptr.*);
                    continue;
                };
                entry.value_ptr.attempts += 1;
                entry.value_ptr.started_at_ns = now_ns;
                continue;
            }
            try expired.append(self.alloc, entry.key_ptr.*);
        }

        try out.ensureUnusedCapacity(self.alloc, expired.items.len);
        for (expired.items) |key| {
            const removed = self.active.fetchRemove(key) orelse continue;
            var active = removed.value;
            self.unindexActive(key, &active);
            out.appendAssumeCapacity(.{
                .endpoint = active.endpoint,
                .req_id = key.req_id,
                .kind = active.requestKind(),
                .socket = active.socket,
            });
            active.deinit(self.alloc);
        }
    }

    pub fn pruneExpiredQueued(
        self: *RequestTracker,
        now_ns: i64,
        timeout_ms: u64,
        out: *std.ArrayListUnmanaged(ExpiredRequest),
    ) Allocator.Error!void {
        var expired_count: usize = 0;
        var count_it = self.queued.iterator();
        while (count_it.next()) |entry| {
            for (entry.value_ptr.queue.liveItems()) |*intent| {
                if (requestTimedOut(intent.queued_at_ns, now_ns, timeout_ms)) expired_count += 1;
            }
        }
        try out.ensureUnusedCapacity(self.alloc, expired_count);

        var empty_keys: std.ArrayListUnmanaged(Endpoint) = .empty;
        defer empty_keys.deinit(self.alloc);
        try empty_keys.ensureTotalCapacity(self.alloc, self.queued.count());

        var it = self.queued.iterator();
        while (it.next()) |entry| {
            var i: usize = 0;
            while (i < entry.value_ptr.queue.len()) {
                if (!requestTimedOut(entry.value_ptr.queue.liveItems()[i].queued_at_ns, now_ns, timeout_ms)) {
                    i += 1;
                    continue;
                }
                const queued = entry.value_ptr.queue.orderedRemoveLiveIndex(i);
                self.queued_total -= 1;
                out.appendAssumeCapacity(.{
                    .endpoint = queued.endpoint,
                    .req_id = queued.req_id,
                    .kind = queued.request_kind,
                });
            }
            if (entry.value_ptr.isEmpty()) empty_keys.appendAssumeCapacity(entry.key_ptr.*);
        }

        for (empty_keys.items) |key| {
            var removed = self.queued.fetchRemove(key).?.value;
            removed.deinit(self.alloc);
        }
    }

    pub fn dropQueuedForEndpoint(
        self: *RequestTracker,
        endpoint: Endpoint,
        out: *std.ArrayListUnmanaged(ExpiredRequest),
    ) Allocator.Error!void {
        const endpoint_key = endpoint;
        const pending = self.queued.getPtr(endpoint_key) orelse return;
        const dropped_count = pending.queue.len();
        try out.ensureUnusedCapacity(self.alloc, dropped_count);
        for (pending.queue.liveItems()) |intent| {
            out.appendAssumeCapacity(.{
                .endpoint = intent.endpoint,
                .req_id = intent.req_id,
                .kind = intent.request_kind,
            });
        }
        self.queued_total -= dropped_count;
        pending.queue.clear();
        if (pending.isEmpty()) {
            var removed = self.queued.fetchRemove(endpoint_key).?.value;
            removed.deinit(self.alloc);
        }
    }

    pub fn forceAllActiveStartedAtForTest(self: *RequestTracker, started_at_ns: i64) void {
        var it = self.active.iterator();
        while (it.next()) |entry| entry.value_ptr.started_at_ns = started_at_ns;
    }

    pub fn forceAllQueuedAtForTest(self: *RequestTracker, queued_at_ns: i64) void {
        var it = self.queued.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.queue.items.items[entry.value_ptr.queue.head..]) |*queued| {
                queued.queued_at_ns = queued_at_ns;
            }
        }
    }

    pub fn forceFirstProbeNonceForTest(self: *RequestTracker, nonce: [packet.NONCE_SIZE]u8) bool {
        var it = self.active.iterator();
        while (it.next()) |entry| {
            switch (entry.value_ptr.phase) {
                .awaiting_response => {},
                .awaiting_whoareyou => |*probe| {
                    probe.nonce = nonce;
                    return true;
                },
            }
        }
        return false;
    }

    fn ensureActiveInsertCapacity(self: *RequestTracker) Error!void {
        if (self.active.count() >= self.limits.max_active_requests) return error.TooManyActiveRequests;
        try self.active.ensureUnusedCapacity(1);
    }

    fn indexEstablishingAssumeCapacity(self: *RequestTracker, endpoint_key: Endpoint, key: RequestKey) void {
        const gop = self.queued.getOrPutAssumeCapacity(endpoint_key);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        if (gop.value_ptr.establishing) |existing| {
            std.debug.assert(std.meta.eql(existing, key));
        }
        gop.value_ptr.establishing = key;
    }

    fn removeActiveByKey(self: *RequestTracker, key: RequestKey) void {
        const removed = self.active.fetchRemove(key) orelse return;
        var active = removed.value;
        self.unindexActive(key, &active);
        active.deinit(self.alloc);
    }

    fn unindexActive(self: *RequestTracker, key: RequestKey, active: *const ActiveRequest) void {
        switch (active.phase) {
            .awaiting_response => |response| if (response.challenge_probe) |probe| {
                _ = self.challenge_index.remove(ChallengeKey.from(&probe.nonce, active.endpoint.addr));
            },
            .awaiting_whoareyou => |probe| {
                _ = self.challenge_index.remove(ChallengeKey.from(&probe.nonce, active.endpoint.addr));
            },
        }
        const endpoint_key = active.endpoint;
        if (self.queued.getPtr(endpoint_key)) |pending| {
            if (pending.establishing) |existing| {
                if (std.meta.eql(existing, key)) pending.establishing = null;
            }
            if (pending.isEmpty()) {
                var removed = self.queued.fetchRemove(endpoint_key).?.value;
                removed.deinit(self.alloc);
            }
        }
    }
};

fn pendingDistances(distances: []const u16) [127]u16 {
    var out: [127]u16 = undefined;
    const len = @min(distances.len, out.len);
    if (len > 0) @memcpy(out[0..len], distances[0..len]);
    return out;
}

fn activeKindFromRequestKind(request_kind: RequestKind, distances: []const u16) ActiveRequestKind {
    return switch (request_kind) {
        .ping => .{ .ping = {} },
        .talkreq => .{ .talkreq = {} },
        .findnode => blk: {
            var findnode = ActiveFindNodeRequest{};
            const len = @min(distances.len, findnode.requested_distances.len);
            if (len > 0) @memcpy(findnode.requested_distances[0..len], distances[0..len]);
            findnode.requested_distances_len = len;
            break :blk .{ .findnode = findnode };
        },
    };
}

fn requestTimedOut(started_at_ns: i64, now_ns: i64, timeout_ms: u64) bool {
    const elapsed_ns: i128 = @as(i128, now_ns) - @as(i128, started_at_ns);
    const timeout_ns: i128 = @as(i128, timeout_ms) * std.time.ns_per_ms;
    return elapsed_ns >= timeout_ns;
}

test "request tracker enforces global and per-endpoint queue caps" {
    const alloc = std.testing.allocator;
    var tracker = RequestTracker.init(alloc, .{
        .max_active_requests = 4,
        .max_queued_requests = 2,
        .max_queued_requests_per_endpoint = 1,
    });
    defer tracker.deinit();

    const peer_a = [_]u8{0x11} ** 32;
    const peer_b = [_]u8{0x22} ** 32;
    const peer_c = [_]u8{0x33} ** 32;
    const pubkey = [_]u8{0x02} ++ [_]u8{0x44} ** 32;
    const req_id = try messages.ReqId.fromSlice(&[_]u8{0x01});
    const plaintext = [_]u8{ messages.MSG_PING, 0x01 };

    const endpoint_a = Endpoint{ .node_id = peer_a, .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 30303 } } };
    const endpoint_b = Endpoint{ .node_id = peer_b, .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 30304 } } };
    const endpoint_c = Endpoint{ .node_id = peer_c, .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 30305 } } };

    try tracker.queueRequest(endpoint_a, &pubkey, req_id, .ping, &.{}, &plaintext, 0);
    try std.testing.expectError(
        error.TooManyQueuedRequestsForEndpoint,
        tracker.queueRequest(endpoint_a, &pubkey, req_id, .ping, &.{}, &plaintext, 0),
    );

    try tracker.queueRequest(endpoint_b, &pubkey, req_id, .ping, &.{}, &plaintext, 0);
    try std.testing.expectError(
        error.TooManyQueuedRequests,
        tracker.queueRequest(endpoint_c, &pubkey, req_id, .ping, &.{}, &plaintext, 0),
    );
    try std.testing.expectEqual(@as(usize, 2), tracker.pendingCount());
}

test "endpoint stores node id and address directly" {
    const node_id = [_]u8{0x11} ** 32;
    const ip4 = Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 30303 } };
    const endpoint = Endpoint{ .node_id = node_id, .addr = ip4 };

    try std.testing.expectEqual(node_id, endpoint.node_id);
    try std.testing.expect(Address.eql(&endpoint.addr, &ip4));
}

test "endpoint contexts use semantic address identity" {
    const alloc = std.testing.allocator;
    const node_id = [_]u8{0x11} ** 32;
    const req_id = try messages.ReqId.fromSlice(&[_]u8{0x01});
    const addr_a = Address{ .ip6 = .{
        .bytes = [_]u8{0xaa} ** 16,
        .port = 30303,
        .flow = 1,
    } };
    const addr_b = Address{ .ip6 = .{
        .bytes = [_]u8{0xaa} ** 16,
        .port = 30303,
        .flow = 2,
    } };
    const endpoint_a = Endpoint{ .node_id = node_id, .addr = addr_a };
    const endpoint_b = Endpoint{ .node_id = node_id, .addr = addr_b };

    var endpoints = std.HashMap(Endpoint, u8, EndpointContext, std.hash_map.default_max_load_percentage).init(alloc);
    defer endpoints.deinit();
    try endpoints.put(endpoint_a, 7);
    try std.testing.expectEqual(@as(?u8, 7), endpoints.get(endpoint_b));

    var requests = std.HashMap(RequestKey, u8, RequestKeyContext, std.hash_map.default_max_load_percentage).init(alloc);
    defer requests.deinit();
    try requests.put(RequestKey.from(endpoint_a, req_id), 9);
    try std.testing.expectEqual(@as(?u8, 9), requests.get(RequestKey.from(endpoint_b, req_id)));
}

test "request keys support empty request IDs" {
    const alloc = std.testing.allocator;
    const endpoint = Endpoint{
        .node_id = [_]u8{0x11} ** 32,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 30303 } },
    };
    const empty_req_id = try messages.ReqId.fromSlice(&.{});
    const nonempty_req_id = try messages.ReqId.fromSlice(&.{0x00});

    var requests = std.HashMap(RequestKey, u8, RequestKeyContext, std.hash_map.default_max_load_percentage).init(alloc);
    defer requests.deinit();
    try requests.put(RequestKey.from(endpoint, empty_req_id), 7);

    try std.testing.expectEqual(@as(?u8, 7), requests.get(RequestKey.from(endpoint, empty_req_id)));
    try std.testing.expect(requests.get(RequestKey.from(endpoint, nonempty_req_id)) == null);
}

test "request tracker popped queued intents can be restored to the front" {
    const alloc = std.testing.allocator;
    var tracker = RequestTracker.init(alloc, .{
        .max_active_requests = 4,
        .max_queued_requests = 4,
        .max_queued_requests_per_endpoint = 4,
    });
    defer tracker.deinit();

    const peer = [_]u8{0x55} ** 32;
    const pubkey = [_]u8{0x02} ++ [_]u8{0x66} ** 32;
    const endpoint = Endpoint{ .node_id = peer, .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 30303 } } };
    const first_req_id = try messages.ReqId.fromSlice(&[_]u8{0x01});
    const second_req_id = try messages.ReqId.fromSlice(&[_]u8{0x02});
    const plaintext = [_]u8{ messages.MSG_PING, 0x01 };

    try tracker.queueRequest(endpoint, &pubkey, first_req_id, .ping, &.{}, &plaintext, 0);
    try tracker.queueRequest(endpoint, &pubkey, second_req_id, .ping, &.{}, &plaintext, 1);

    const intent = (try tracker.popNextQueued(endpoint)) orelse return error.MissingQueuedRequest;
    try std.testing.expectEqualSlices(u8, first_req_id.slice(), intent.req_id.slice());
    try std.testing.expectEqual(@as(usize, 1), tracker.pendingCount());

    try tracker.pushFrontQueued(intent);
    try std.testing.expectEqual(@as(usize, 2), tracker.pendingCount());

    const restored = (try tracker.popNextQueued(endpoint)) orelse return error.MissingQueuedRequest;
    try std.testing.expectEqualSlices(u8, first_req_id.slice(), restored.req_id.slice());
}

test "authenticated request retains WHOAREYOU recovery metadata" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    var tracker = RequestTracker.init(alloc, .{});
    defer tracker.deinit();

    var socket = try net.IpAddress.bind(&.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } }, io, .{ .mode = .dgram });
    defer socket.close(io);

    const endpoint = Endpoint{
        .node_id = [_]u8{0x55} ** 32,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 30303 } },
    };
    const req_id = try messages.ReqId.fromSlice(&[_]u8{0x01});
    const nonce = [_]u8{0x22} ** packet.NONCE_SIZE;
    const pubkey = [_]u8{0x02} ++ [_]u8{0x66} ** 32;
    const plaintext = [_]u8{ messages.MSG_PING, 0x01 };

    try tracker.putActiveAwaitingResponseWithChallenge(
        endpoint,
        req_id,
        .ping,
        &.{},
        &socket,
        &[_]u8{0x99},
        0,
        nonce,
        &pubkey,
        &plaintext,
    );

    const probe = tracker.probeForChallenge(&nonce, endpoint.addr) orelse return error.MissingActiveRequest;
    try std.testing.expectEqualSlices(u8, &pubkey, probe.dest_pubkey);
    try std.testing.expectEqualSlices(u8, &plaintext, probe.plaintext);
}

test "only one established-session request can re-establish an endpoint" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    var tracker = RequestTracker.init(alloc, .{});
    defer tracker.deinit();

    var socket = try net.IpAddress.bind(&.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } }, io, .{ .mode = .dgram });
    defer socket.close(io);

    const endpoint = Endpoint{ .node_id = [_]u8{0x51} ** 32, .addr = socket.address };
    const req_a = try messages.ReqId.fromSlice(&[_]u8{0xa1});
    const req_b = try messages.ReqId.fromSlice(&[_]u8{0xb1});
    const nonce_a = [_]u8{0x61} ** packet.NONCE_SIZE;
    const nonce_b = [_]u8{0x62} ** packet.NONCE_SIZE;
    const pubkey = [_]u8{0x63} ** 33;
    const plaintext = [_]u8{ messages.MSG_PING, 0xc0 };
    try tracker.putActiveAwaitingResponseWithChallenge(endpoint, req_a, .ping, &.{}, &socket, &[_]u8{0x71}, 1, nonce_a, &pubkey, &plaintext);
    try tracker.putActiveAwaitingResponseWithChallenge(endpoint, req_b, .ping, &.{}, &socket, &[_]u8{0x72}, 1, nonce_b, &pubkey, &plaintext);

    const keys = state.PendingSessionKeys{
        .initiator_key = [_]u8{0x81} ** 16,
        .recipient_key = [_]u8{0x82} ** 16,
    };
    try tracker.acceptChallenge(RequestKey.from(endpoint, req_a), &nonce_a, endpoint.addr, &[_]u8{0x91}, keys, 2);
    try std.testing.expectError(error.EndpointEstablishing, tracker.acceptChallenge(RequestKey.from(endpoint, req_b), &nonce_b, endpoint.addr, &[_]u8{0x92}, keys, 2));
}

test "request tracker commits queued intents as authenticated sends or probes" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;

    var tracker = RequestTracker.init(alloc, .{
        .max_active_requests = 4,
        .max_queued_requests = 4,
        .max_queued_requests_per_endpoint = 2,
    });
    defer tracker.deinit();

    var socket = try net.IpAddress.bind(&.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } }, io, .{
        .mode = .dgram,
    });
    defer socket.close(io);

    const peer = [_]u8{0x55} ** 32;
    const pubkey = [_]u8{0x02} ++ [_]u8{0x66} ** 32;
    const endpoint = Endpoint{ .node_id = peer, .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 30303 } } };
    const first_req_id = try messages.ReqId.fromSlice(&[_]u8{0x01});
    const second_req_id = try messages.ReqId.fromSlice(&[_]u8{0x02});
    const plaintext = [_]u8{ messages.MSG_PING, 0x01 };
    const packet_bytes = try PacketBytes.init(&[_]u8{0x99});

    try tracker.queueRequest(endpoint, &pubkey, first_req_id, .ping, &.{}, &plaintext, 0);
    var intent = (try tracker.popNextQueued(endpoint)) orelse return error.MissingQueuedRequest;
    try tracker.putActiveAwaitingResponse(
        intent.endpoint,
        intent.req_id,
        intent.request_kind,
        intent.distances(),
        &socket,
        packet_bytes.slice(),
        10,
        null,
    );

    try std.testing.expectEqual(@as(usize, 1), tracker.activeCount());
    try std.testing.expectEqual(@as(usize, 0), tracker.pendingCount());

    try tracker.queueRequest(endpoint, &pubkey, second_req_id, .ping, &.{}, &plaintext, 20);
    intent = (try tracker.popNextQueued(endpoint)) orelse return error.MissingQueuedRequest;
    try tracker.putActiveProbe(
        intent.endpoint,
        intent.req_id,
        intent.request_kind,
        intent.distances(),
        &socket,
        packet_bytes.slice(),
        30,
        [_]u8{0xaa} ** packet.NONCE_SIZE,
        &intent.dest_pubkey,
        intent.plaintextSlice(),
    );

    try std.testing.expectEqual(@as(usize, 2), tracker.activeCount());
    try std.testing.expectEqual(@as(usize, 1), tracker.pendingCount());
    try std.testing.expect(tracker.shouldQueueForEndpoint(endpoint));
    try std.testing.expect(tracker.pendingSessionKeysForEndpoint(endpoint) == null);
}
