const std = @import("std");
const storage = @import("message_store.zig");
const protobuf = @import("protobuf.zig");
const frame = @import("frame.zig");
const constants = @import("constants.zig");
const topic = @import("topic.zig");
const assert = std.debug.assert;
pub const data_capacity = 16;
pub const control_frames = 128;
pub const QueueResult = enum { queued, full };

pub const ControlQueue = struct {
    bytes: []u8,
    lengths: [control_frames]u32 = undefined,
    tokens: [control_frames]u64 = undefined,
    enqueued_ms: [control_frames]u64 = undefined,
    head: usize = 0,
    count: usize = 0,
    read_at: usize = 0,
    write_at: usize = 0,
    used: usize = 0,

    pub fn append(self: *ControlQueue, bytes: []const u8, token: u64, now_ms: u64) QueueResult {
        if (self.count == control_frames or bytes.len > self.bytes.len - self.used) return .full;
        assert(bytes.len > 0);
        const n = @min(bytes.len, self.bytes.len - self.write_at);
        @memcpy(self.bytes[self.write_at..][0..n], bytes[0..n]);
        @memcpy(self.bytes[0 .. bytes.len - n], bytes[n..]);
        const slot = (self.head + self.count) % control_frames;
        self.lengths[slot] = @intCast(bytes.len);
        self.tokens[slot] = token;
        self.enqueued_ms[slot] = now_ms;
        self.count += 1;
        self.used += bytes.len;
        self.write_at = (self.write_at + bytes.len) % self.bytes.len;
        return .queued;
    }
    pub fn segment(self: *const ControlQueue) []const u8 {
        if (self.count == 0) return &.{};
        return self.bytes[self.read_at..][0..@min(self.lengths[self.head], self.bytes.len - self.read_at)];
    }
    pub fn advance(self: *ControlQueue, len: usize) ?u64 {
        assert(len > 0 and len <= self.segment().len);
        self.lengths[self.head] -= @intCast(len);
        self.used -= len;
        self.read_at = (self.read_at + len) % self.bytes.len;
        if (self.lengths[self.head] != 0) return null;
        const token = self.tokens[self.head];
        self.head = (self.head + 1) % control_frames;
        self.count -= 1;
        return token;
    }
    pub fn reset(self: *ControlQueue) void {
        self.* = .{ .bytes = self.bytes };
    }
};

pub const DataTx = struct {
    message: storage.Handle,
    enqueued_ms: u64,
    page: storage.Cursor,
    prefix: [32]u8 = undefined,
    prefix_len: u8,
    trailer: [topic.topic_max_len + 2]u8 = undefined,
    trailer_len: u8,
    stage: enum { prefix, data, trailer, done } = .prefix,
    offset: usize = 0,
    wire_len: usize,

    pub fn init(store: *const storage.Store, h: storage.Handle, now_ms: u64) DataTx {
        const e = store.get(h).?;
        var tx: DataTx = .{ .message = h, .enqueued_ms = now_ms, .page = store.cursor(h), .prefix_len = 0, .trailer_len = 0, .wire_len = 0 };
        const lengths = encodePrefix(&tx.prefix, &tx.trailer, e.len, e.topicString());
        tx.prefix_len = @intCast(lengths.prefix);
        tx.trailer_len = @intCast(lengths.trailer);
        tx.wire_len = lengths.prefix + e.len + lengths.trailer;
        return tx;
    }
    pub fn segment(self: *const DataTx, store: *const storage.Store) []const u8 {
        return switch (self.stage) {
            .prefix => self.prefix[self.offset..self.prefix_len],
            .data => store.segment(self.message, self.page),
            .trailer => self.trailer[self.offset..self.trailer_len],
            .done => &.{},
        };
    }
    pub fn advance(self: *DataTx, store: *const storage.Store, len: usize) void {
        assert(len > 0 and len <= self.segment(store).len);
        switch (self.stage) {
            .prefix, .trailer => {
                self.offset += len;
                const end = if (self.stage == .prefix) self.prefix_len else self.trailer_len;
                if (self.offset == end) {
                    self.stage = if (self.stage == .trailer) .done else if (self.page.remaining == 0) .trailer else .data;
                    self.offset = 0;
                }
            },
            .data => {
                store.advance(&self.page, len);
                if (self.page.remaining == 0) self.stage = .trailer;
            },
            .done => unreachable,
        }
    }
};

pub fn encodePrefix(prefix: []u8, trailer: []u8, len: usize, name: []const u8) struct { prefix: usize, trailer: usize } {
    assert(len <= constants.maxCompressedLen(constants.MAX_PAYLOAD_SIZE));
    assert(name.len <= topic.topic_max_len);
    var tail = protobuf.Writer.init(trailer);
    tail.bytesField(4, name);
    const message_len = 1 + protobuf.varintLen(len) + len + tail.len;
    const rpc_len = 1 + protobuf.varintLen(message_len) + message_len;
    assert(rpc_len <= constants.GOSSIP_MAX_SIZE);
    var head = protobuf.Writer.init(prefix);
    head.varint(rpc_len);
    head.tag(2, protobuf.wire_len);
    head.varint(message_len);
    head.tag(2, protobuf.wire_len);
    head.varint(len);
    return .{ .prefix = head.len, .trailer = tail.len };
}

pub const Pool = struct {
    peers: []PeerIo,
    arena: []u8,

    pub fn init(a: std.mem.Allocator, options: *const @import("options.zig").Options) !Pool {
        const per_peer = options.control_bytes + options.critical_bytes + options.body_buffer_bytes + constants.read_scratch_len;
        const arena = try a.alloc(u8, @as(usize, options.connected_capacity) * per_peer);
        errdefer a.free(arena);
        const peers = try a.alloc(PeerIo, options.connected_capacity);
        errdefer a.free(peers);
        for (peers, 0..) |*peer, i| {
            const base = i * per_peer;
            const critical = base + options.control_bytes;
            const body = critical + options.critical_bytes;
            const unread = body + options.body_buffer_bytes;
            peer.* = .{
                .control = .{ .bytes = arena[base..critical] },
                .critical = .{ .bytes = arena[critical..body] },
                .body = arena[body..unread],
                .unread = arena[unread..][0..constants.read_scratch_len],
            };
        }
        return .{ .peers = peers, .arena = arena };
    }
    pub fn deinit(self: *Pool, a: std.mem.Allocator) void {
        a.free(self.peers);
        a.free(self.arena);
        self.* = undefined;
    }
};

pub const PeerIo = struct {
    calls_pump: usize = 0,
    write_first: bool = false,
    control: ControlQueue,
    critical: ControlQueue,
    data: [data_capacity]DataTx = undefined,
    data_head: usize = 0,
    data_count: usize = 0,
    data_bytes: usize = 0,
    active: enum { none, critical, control, data } = .none,
    control_burst: u8 = 0,
    sequence: u64 = 0,
    body: []u8,
    unread: []u8,
    unread_start: usize = 0,
    unread_end: usize = 0,
    reader: frame.Reader = .{},
    rpc: ?protobuf.RpcReader = null,
    item: ?protobuf.Item = null,
    subscriptions: usize = 0,
    messages: usize = 0,
    controls: usize = 0,
    fin_seen: bool = false,
    large_slot: ?u8 = null,
    progress_ms: u64 = 0,
    frame_since: ?u64 = null,
    tx_progress_ms: ?u64 = null,
    pressure_since: ?u64 = null,
    rx_ready: bool = true,
    tx_ready: bool = true,
    blocked: enum { none, events, storage } = .none,
    subscription_since: ?u64 = null,
    subscription_dirty: std.StaticBitSet(constants.topics_cap) = .initEmpty(),
    subscription_cursor: usize = 0,
    decompressed_pump: usize = 0,
    fields_pump: usize = 0,
    ihave_recv: u16 = 0,
    iwant_ids_sent: u16 = 0,
    idontwant_recv: u16 = 0,

    pub fn feedUnread(self: *PeerIo, body: []u8, limit: usize, now_ms: u64) frame.Error!struct { consumed: usize, complete: bool } {
        assert(limit > 0 and limit <= self.unread_end - self.unread_start);
        const result = try self.reader.feed(self.unread[self.unread_start..][0..limit], body);
        if (result.consumed > 0) {
            if (self.frame_since == null) self.frame_since = now_ms;
            self.progress_ms = now_ms;
            self.pressure_since = null;
            self.unread_start += result.consumed;
        }
        if (result.frame) |rpc| {
            self.rpc = protobuf.RpcReader.init(rpc);
            self.subscriptions = 0;
            self.messages = 0;
            self.controls = 0;
        }
        return .{ .consumed = result.consumed, .complete = result.frame != null };
    }

    pub fn resetHeartbeat(self: *PeerIo) void {
        self.ihave_recv = 0;
        self.iwant_ids_sent = 0;
        self.idontwant_recv = 0;
    }
    pub fn append(self: *PeerIo, bytes: []const u8, now_ms: u64) bool {
        return self.appendControl(bytes, false, now_ms) != null;
    }
    pub fn appendControl(self: *PeerIo, bytes: []const u8, critical: bool, now_ms: u64) ?u64 {
        if (self.sequence == std.math.maxInt(u64)) return null;
        const token = self.sequence + 1;
        const queue = if (critical) &self.critical else &self.control;
        if (queue.append(bytes, token, now_ms) == .full) return null;
        self.sequence = token;
        self.tx_ready = true;
        return token;
    }
    pub fn queueData(self: *PeerIo, store: *storage.Store, h: storage.Handle, byte_limit: usize, now_ms: u64) QueueResult {
        const e = store.get(h).?;
        if (self.data_count == data_capacity or e.len > byte_limit - self.data_bytes) return .full;
        self.data[(self.data_head + self.data_count) % data_capacity] = DataTx.init(store, h, now_ms);
        self.data_count += 1;
        self.data_bytes += e.len;
        store.retainTx(h);
        self.tx_ready = true;
        return .queued;
    }
    pub fn pending(self: *const PeerIo) bool {
        return self.data_count != 0 or self.control.count != 0 or self.critical.count != 0;
    }
    pub fn segment(self: *PeerIo, store: *const storage.Store) []const u8 {
        if (self.active == .none) {
            if (self.data_count > 0 and self.control_burst >= 4) {
                self.active = .data;
            } else if (self.critical.count > 0) {
                self.active = .critical;
            } else if (self.control.count > 0) {
                self.active = .control;
            } else if (self.data_count > 0) {
                self.active = .data;
            }
        }
        return switch (self.active) {
            .none => &.{},
            .critical => self.critical.segment(),
            .control => self.control.segment(),
            .data => self.data[self.data_head].segment(store),
        };
    }
    pub fn advance(self: *PeerIo, store: *storage.Store, len: usize) ?u64 {
        switch (self.active) {
            .none => unreachable,
            .critical, .control => {
                const q = if (self.active == .critical) &self.critical else &self.control;
                if (q.advance(len)) |token| {
                    self.active = .none;
                    self.tx_progress_ms = null;
                    self.control_burst +|= 1;
                    return token;
                }
            },
            .data => {
                const tx = &self.data[self.data_head];
                tx.advance(store, len);
                if (tx.stage == .done) {
                    self.data_bytes -= store.get(tx.message).?.len;
                    store.releaseTx(tx.message);
                    self.data_head = (self.data_head + 1) % data_capacity;
                    self.data_count -= 1;
                    self.active = .none;
                    self.tx_progress_ms = null;
                    self.control_burst = 0;
                }
            },
        }
        return null;
    }
    pub fn oldestTx(self: *const PeerIo) ?u64 {
        var oldest: ?u64 = null;
        if (self.data_count > 0) oldest = self.data[self.data_head].enqueued_ms;
        if (self.control.count > 0) oldest = @min(oldest orelse std.math.maxInt(u64), self.control.enqueued_ms[self.control.head]);
        if (self.critical.count > 0) oldest = @min(oldest orelse std.math.maxInt(u64), self.critical.enqueued_ms[self.critical.head]);
        return oldest;
    }

    pub fn resetTx(self: *PeerIo, store: *storage.Store) void {
        for (0..self.data_count) |i| store.releaseTx(self.data[(self.data_head + i) % data_capacity].message);
        self.data_head = 0;
        self.data_count = 0;
        self.data_bytes = 0;
        self.active = .none;
        self.control.reset();
        self.critical.reset();
        self.tx_progress_ms = null;
        self.tx_ready = false;
    }
    pub fn resetRx(self: *PeerIo) void {
        assert(self.large_slot == null);
        self.reader = .{};
        self.rpc = null;
        self.item = null;
        self.unread_start = 0;
        self.unread_end = 0;
        self.fin_seen = false;
        self.rx_ready = false;
        self.pressure_since = null;
        self.frame_since = null;
        self.blocked = .none;
    }
};

test "gossip segmented prefix agrees with independent JS varint oracles" {
    const vectors = .{
        .{ @as(usize, 127), "ac0112a901127f" },
        .{ @as(usize, 128), "ae0112ab01128001" },
        .{ @as(usize, 16383), "ae800112aa800112ff7f" },
        .{ @as(usize, 16384), "b0800112ac800112808001" },
        .{ @as(usize, 12233418), "fcd5ea0512f7d5ea0512cad5ea05" },
    };
    inline for (vectors) |v| {
        var prefix: [32]u8 = undefined;
        var trailer: [128]u8 = undefined;
        const lens = encodePrefix(&prefix, &trailer, v[0], "/eth2/01000000/beacon_block/ssz_snappy");
        var expected: [32]u8 = undefined;
        const bytes = try std.fmt.hexToBytes(&expected, v[1]);
        try std.testing.expectEqualSlices(u8, bytes, prefix[0..lens.prefix]);
        try std.testing.expectEqualStrings("\x22\x26/eth2/01000000/beacon_block/ssz_snappy", trailer[0..lens.trailer]);
    }
}

test "gossip transmit retains pages and never interleaves control into partial data" {
    var store = try storage.Store.init(std.testing.allocator, 2, 8192);
    defer store.deinit(std.testing.allocator);
    var normal: [64]u8 = undefined;
    var critical: [64]u8 = undefined;
    var body: [1]u8 = undefined;
    var unread: [1]u8 = undefined;
    var io: PeerIo = .{ .control = .{ .bytes = &normal }, .critical = .{ .bytes = &critical }, .body = &body, .unread = &unread };
    const h = store.put([_]u8{1} ** 20, "topic", "payload").?;
    store.retainHistory(h);
    store.seal(h);
    try std.testing.expectEqual(QueueResult.queued, io.queueData(&store, h, 8192, 0));
    store.releaseHistory(h);
    var out: [128]u8 = undefined;
    var n: usize = 0;
    out[n] = io.segment(&store)[0];
    n += 1;
    _ = io.advance(&store, 1);
    const token = io.appendControl("\x01x", true, 0).?;
    for (0..127) |_| {
        const segment = io.segment(&store);
        if (segment.len == 0) break;
        out[n] = segment[0];
        n += 1;
        if (io.advance(&store, 1)) |done| try std.testing.expectEqual(token, done);
    }
    try std.testing.expect(!io.pending());
    try std.testing.expectEqual(@as(usize, 0), store.used_entries);
    var expected: [128]u8 = undefined;
    var writer = protobuf.Writer.init(&expected);
    writer.varint(protobuf.messageSize("payload", "topic"));
    protobuf.writeMessage(&writer, "payload", "topic");
    writer.bytes("\x01x");
    try std.testing.expectEqualSlices(u8, writer.written(), out[0..n]);
}

test "gossip critical capacity and data queue pressure are independent and release on reset" {
    var store = try storage.Store.init(std.testing.allocator, 1, 4096);
    defer store.deinit(std.testing.allocator);
    var normal: [8]u8 = undefined;
    var critical: [8]u8 = undefined;
    var body: [1]u8 = undefined;
    var unread: [1]u8 = undefined;
    var io: PeerIo = .{ .control = .{ .bytes = &normal }, .critical = .{ .bytes = &critical }, .body = &body, .unread = &unread };
    const h = store.put([_]u8{1} ** 20, "t", "x").?;
    store.retainHistory(h);
    store.seal(h);
    for (0..data_capacity) |_| try std.testing.expectEqual(QueueResult.queued, io.queueData(&store, h, 8192, 0));
    try std.testing.expectEqual(QueueResult.full, io.queueData(&store, h, 8192, 0));
    try std.testing.expect(io.append("12345678", 0));
    try std.testing.expect(!io.append("x", 0));
    try std.testing.expect(io.appendControl("critical", true, 0) != null);
    store.releaseHistory(h);
    io.resetTx(&store);
    try std.testing.expectEqual(@as(usize, 0), store.used_entries);
    try std.testing.expectEqual(@as(usize, 1), store.free_pages);
}
