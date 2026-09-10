const std = @import("std");
const storage = @import("message_store.zig");
const protobuf = @import("protobuf.zig");
const constants = @import("constants.zig");
const topic = @import("topic.zig");
const assert = std.debug.assert;
const ItemKind = std.meta.Tag(protobuf.Item);
const delivery = @import("delivery.zig");
pub const data_capacity = delivery.per_peer_limit;
pub const control_frames = 128;
pub const QueueResult = enum { queued, full };
pub const DropReason = enum { data_descriptors, data_pool, data_bytes, control_frames, control_bytes, critical_frames, critical_bytes, token_exhausted };
pub const drop_reason_count = @typeInfo(DropReason).@"enum".fields.len;

pub const Control = union(enum) {
    subscription: struct { topic: []const u8, subscribed: bool },
    graft: []const u8,
    prune: struct { topic: []const u8, backoff_s: u64 },
    ihave: struct { topic: []const u8, ids: []const topic.MessageId },
    iwant: []const topic.MessageId,
    idontwant: []const topic.MessageId,

    fn encode(self: *const Control, bytes: []u8) []const u8 {
        var writer = protobuf.Writer.init(bytes);
        switch (self.*) {
            .subscription => |sub| {
                assert(sub.topic.len <= topic.topic_max_len);
                writer.varint(protobuf.subscriptionSize(sub.topic));
                protobuf.writeSubscription(&writer, sub.subscribed, sub.topic);
            },
            .graft => |name| {
                assert(name.len <= topic.topic_max_len);
                writer.varint(protobuf.graftRpcSize(name));
                protobuf.writeGraftRpc(&writer, name);
            },
            .prune => |prune| {
                assert(prune.topic.len <= topic.topic_max_len);
                writer.varint(protobuf.pruneRpcSize(prune.topic, prune.backoff_s));
                protobuf.writePruneRpc(&writer, prune.topic, prune.backoff_s);
            },
            .ihave => |have| {
                assert(have.topic.len <= topic.topic_max_len and have.ids.len <= constants.gossip_ids_max);
                writer.varint(protobuf.ihaveRpcSize(have.topic, have.ids.len, constants.message_id_length));
                protobuf.beginIhaveRpc(&writer, have.topic, have.ids.len, constants.message_id_length);
                for (have.ids) |id| protobuf.writeIhaveId(&writer, &id);
            },
            .iwant => |ids| {
                assert(ids.len <= constants.gossip_ids_max);
                writer.varint(protobuf.iwantRpcSize(ids.len, constants.message_id_length));
                protobuf.beginIwantRpc(&writer, ids.len, constants.message_id_length);
                for (ids) |id| protobuf.writeIwantId(&writer, &id);
            },
            .idontwant => |ids| {
                assert(ids.len <= constants.gossip_ids_max);
                writer.varint(protobuf.idontwantRpcSize(ids.len, constants.message_id_length));
                protobuf.beginIdontwantRpc(&writer, ids.len, constants.message_id_length);
                for (ids) |id| protobuf.writeIdontwantId(&writer, &id);
            },
        }
        return writer.written();
    }
};

pub const ControlReceipt = struct { token: u64, kind: ?ItemKind };
pub const Completion = union(enum) {
    control: ControlReceipt,
    data,

    pub fn itemKind(self: Completion) ?ItemKind {
        return switch (self) {
            .control => |receipt| receipt.kind,
            .data => .message,
        };
    }
};

pub const ControlQueue = struct {
    bytes: []u8,
    lengths: [control_frames]u32 = undefined,
    tokens: [control_frames]u64 = undefined,
    // Native encoders queue one item per RPC; preserve its kind through partial writes.
    kinds: [control_frames]?ItemKind = @splat(null),
    enqueued_ms: [control_frames]u64 = undefined,
    head: usize = 0,
    count: usize = 0,
    read_at: usize = 0,
    write_at: usize = 0,
    used: usize = 0,
    bytes_high_water: usize = 0,
    frames_high_water: usize = 0,

    pub fn append(self: *ControlQueue, bytes: []const u8, token: u64, kind: ?ItemKind, now_ms: u64) QueueResult {
        if (self.count == control_frames or bytes.len > self.bytes.len - self.used) return .full;
        assert(bytes.len > 0);
        const n = @min(bytes.len, self.bytes.len - self.write_at);
        @memcpy(self.bytes[self.write_at..][0..n], bytes[0..n]);
        @memcpy(self.bytes[0 .. bytes.len - n], bytes[n..]);
        const slot = (self.head + self.count) % control_frames;
        self.lengths[slot] = @intCast(bytes.len);
        self.tokens[slot] = token;
        self.kinds[slot] = kind;
        self.enqueued_ms[slot] = now_ms;
        self.count += 1;
        self.used += bytes.len;
        self.bytes_high_water = @max(self.bytes_high_water, self.used);
        self.frames_high_water = @max(self.frames_high_water, self.count);
        self.write_at = (self.write_at + bytes.len) % self.bytes.len;
        return .queued;
    }
    pub fn segment(self: *const ControlQueue) []const u8 {
        if (self.count == 0) return &.{};
        return self.bytes[self.read_at..][0..@min(self.lengths[self.head], self.bytes.len - self.read_at)];
    }
    pub fn advance(self: *ControlQueue, len: usize) ?ControlReceipt {
        assert(len > 0 and len <= self.segment().len);
        self.lengths[self.head] -= @intCast(len);
        self.used -= len;
        self.read_at = (self.read_at + len) % self.bytes.len;
        if (self.lengths[self.head] != 0) return null;
        const receipt: ControlReceipt = .{ .token = self.tokens[self.head], .kind = self.kinds[self.head] };
        self.head = (self.head + 1) % control_frames;
        self.count -= 1;
        return receipt;
    }
    pub fn reset(self: *ControlQueue) void {
        self.* = .{ .bytes = self.bytes, .bytes_high_water = self.bytes_high_water, .frames_high_water = self.frames_high_water };
    }
};

pub const encodePrefix = storage.encodePrefix;

pub const Outbox = struct {
    control: ControlQueue,
    critical: ControlQueue,
    data: delivery.Queue,
    active: enum { none, critical, control, data } = .none,
    control_burst: u8 = 0,
    sequence: u64 = 0,
    progress_ms: ?u64 = null,
    ready: bool = true,
    subscription_since: ?u64 = null,
    subscription_dirty: std.StaticBitSet(constants.topics_cap) = .initEmpty(),
    subscription_cursor: usize = 0,
    pending_prunes: std.StaticBitSet(constants.topics_cap) = .initEmpty(),
    prune_since: ?u64 = null,
    drops: [drop_reason_count]u64 = @splat(0),
    pressure_pending: bool = false,
    pressure_log_due_ms: u64 = 0,
    last_drop: DropReason = .data_descriptors,

    pub fn subscriptionChanged(self: *Outbox, index: usize, now: u64) void {
        self.subscription_dirty.set(index);
        self.subscription_since = self.subscription_since orelse now;
        self.ready = true;
    }

    pub fn synchronize(self: *Outbox, subscribed: *const std.StaticBitSet(constants.topics_cap), now: u64) void {
        self.subscription_dirty = subscribed.*;
        self.subscription_since = if (subscribed.count() == 0) null else self.subscription_since orelse now;
        self.ready = true;
    }

    pub fn nextSubscription(self: *Outbox) ?u16 {
        if (self.subscription_dirty.count() == 0) return null;
        for (0..constants.topics_cap) |_| {
            const index = self.subscription_cursor;
            if (self.subscription_dirty.isSet(index)) return @intCast(index);
            self.subscription_cursor = (index + 1) % constants.topics_cap;
        }
        return null;
    }

    pub fn announce(self: *Outbox, index: u16, name: []const u8, subscribed: bool, now: u64) bool {
        assert(self.subscription_dirty.isSet(index));
        if (self.submit(&.{ .subscription = .{ .topic = name, .subscribed = subscribed } }, now) == null) return false;
        self.subscription_dirty.unset(index);
        self.subscription_cursor = (index + 1) % constants.topics_cap;
        if (self.subscription_dirty.count() == 0) self.subscription_since = null;
        return true;
    }

    pub fn deferPrune(self: *Outbox, index: usize, now: u64) void {
        self.pending_prunes.set(index);
        self.prune_since = self.prune_since orelse now;
    }

    pub fn pruneQueued(self: *Outbox, index: usize) void {
        self.pending_prunes.unset(index);
        if (self.pending_prunes.count() == 0) self.prune_since = null;
    }

    pub fn forgetIntent(self: *Outbox) void {
        self.subscription_dirty = .initEmpty();
        self.subscription_since = null;
        self.pending_prunes = .initEmpty();
        self.prune_since = null;
    }

    pub fn pruneExpired(self: *const Outbox, now: u64, timeout: u64) bool {
        if (self.prune_since) |since| if (now >= since +| timeout) return true;
        return false;
    }

    pub fn submit(self: *Outbox, control: *const Control, now_ms: u64) ?u64 {
        var bytes: [32 + topic.topic_max_len + constants.gossip_ids_max * (constants.message_id_length + 2)]u8 = undefined;
        const critical = switch (control.*) {
            .subscription, .graft, .prune => true,
            else => false,
        };
        const kind: ItemKind = switch (control.*) {
            inline else => |_, tag| @field(ItemKind, @tagName(tag)),
        };
        return self.appendControl(control.encode(&bytes), critical, kind, now_ms);
    }

    pub fn inject(self: *Outbox, bytes: []const u8, now_ms: u64) bool {
        comptime assert(@import("builtin").is_test);
        return self.appendControl(bytes, false, null, now_ms) != null;
    }

    pub fn injectFrame(self: *Outbox, bytes: []const u8, critical: bool, kind: ?ItemKind, now_ms: u64) ?u64 {
        comptime assert(@import("builtin").is_test);
        return self.appendControl(bytes, critical, kind, now_ms);
    }

    fn appendControl(self: *Outbox, bytes: []const u8, critical: bool, kind: ?ItemKind, now_ms: u64) ?u64 {
        if (self.sequence == std.math.maxInt(u64)) {
            self.dropped(.token_exhausted);
            return null;
        }
        const token = self.sequence + 1;
        const queue = if (critical) &self.critical else &self.control;
        if (queue.append(bytes, token, kind, now_ms) == .full) {
            self.dropped(if (queue.count == control_frames)
                (if (critical) .critical_frames else .control_frames)
            else
                (if (critical) .critical_bytes else .control_bytes));
            return null;
        }
        self.sequence = token;
        self.ready = true;
        return token;
    }

    pub fn queueData(self: *Outbox, store: *storage.Store, h: storage.Handle, byte_limit: usize, now_ms: u64) QueueResult {
        self.data.append(store, h, byte_limit, now_ms) catch |err| {
            self.dropped(switch (err) {
                error.Descriptors => .data_descriptors,
                error.PoolFull => .data_pool,
                error.Bytes => .data_bytes,
            });
            return .full;
        };
        self.ready = true;
        return .queued;
    }
    fn dropped(self: *Outbox, reason: DropReason) void {
        self.drops[@intFromEnum(reason)] +|= 1;
        self.pressure_pending = true;
        self.last_drop = reason;
    }
    pub fn pending(self: *const Outbox) bool {
        return self.data.count != 0 or self.control.count != 0 or self.critical.count != 0;
    }
    pub fn segment(self: *Outbox, store: *const storage.Store) []const u8 {
        if (self.active == .none) {
            if (self.data.count > 0 and self.control_burst >= 4) {
                self.active = .data;
            } else if (self.critical.count > 0) {
                self.active = .critical;
            } else if (self.control.count > 0) {
                self.active = .control;
            } else if (self.data.count > 0) {
                self.active = .data;
            }
        }
        return switch (self.active) {
            .none => &.{},
            .critical => self.critical.segment(),
            .control => self.control.segment(),
            .data => self.data.first().?.segment(store),
        };
    }
    pub fn advance(self: *Outbox, store: *storage.Store, len: usize) ?Completion {
        switch (self.active) {
            .none => unreachable,
            .critical, .control => {
                const q = if (self.active == .critical) &self.critical else &self.control;
                if (q.advance(len)) |receipt| {
                    self.active = .none;
                    self.progress_ms = null;
                    self.control_burst +|= 1;
                    return .{ .control = receipt };
                }
            },
            .data => {
                if (self.data.advance(store, len)) {
                    self.active = .none;
                    self.progress_ms = null;
                    self.control_burst = 0;
                    return .data;
                }
            },
        }
        return null;
    }
    pub fn oldest(self: *const Outbox) ?u64 {
        var first: ?u64 = null;
        if (self.data.count > 0) first = self.data.first().?.enqueued_ms;
        if (self.control.count > 0) first = @min(first orelse std.math.maxInt(u64), self.control.enqueued_ms[self.control.head]);
        if (self.critical.count > 0) first = @min(first orelse std.math.maxInt(u64), self.critical.enqueued_ms[self.critical.head]);
        return first;
    }

    pub fn reset(self: *Outbox, store: *storage.Store) void {
        self.data.reset(store);
        self.pressure_pending = false;
        self.active = .none;
        self.control.reset();
        self.critical.reset();
        self.progress_ms = null;
        self.ready = false;
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
    var deliveries = try delivery.Pool.init(std.testing.allocator, 1, data_capacity);
    defer deliveries.deinit(std.testing.allocator);
    var io: Outbox = .{ .data = .{ .pool = &deliveries }, .control = .{ .bytes = &normal }, .critical = .{ .bytes = &critical } };
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
    const token = io.appendControl("\x01x", true, null, 0).?;
    for (0..127) |_| {
        const segment = io.segment(&store);
        if (segment.len == 0) break;
        out[n] = segment[0];
        n += 1;
        if (io.advance(&store, 1)) |done| switch (done) {
            .control => |receipt| try std.testing.expectEqual(token, receipt.token),
            .data => try std.testing.expectEqual(@as(usize, 0), store.used_entries),
        };
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
    var deliveries = try delivery.Pool.init(std.testing.allocator, 1, data_capacity);
    defer deliveries.deinit(std.testing.allocator);
    var io: Outbox = .{ .data = .{ .pool = &deliveries }, .control = .{ .bytes = &normal }, .critical = .{ .bytes = &critical } };
    const h = store.put([_]u8{1} ** 20, "t", "x").?;
    store.retainHistory(h);
    store.seal(h);
    for (0..data_capacity) |_| try std.testing.expectEqual(QueueResult.queued, io.queueData(&store, h, 8192, 0));
    try std.testing.expectEqual(QueueResult.full, io.queueData(&store, h, 8192, 0));
    try std.testing.expectEqual(@as(usize, data_capacity), io.data.bytes_high_water);
    try std.testing.expectEqual(@as(usize, data_capacity), io.data.descriptors_high_water);
    try std.testing.expect(io.inject("12345678", 0));
    try std.testing.expect(!io.inject("x", 0));
    try std.testing.expect(io.appendControl("critical", true, null, 0) != null);
    store.releaseHistory(h);
    io.reset(&store);
    try std.testing.expectEqual(@as(usize, 0), store.used_entries);
    try std.testing.expectEqual(@as(usize, 1), store.free_pages);
    try std.testing.expectEqual(@as(u64, 1), io.drops[@intFromEnum(DropReason.data_descriptors)]);
    try std.testing.expectEqual(@as(u64, 1), io.drops[@intFromEnum(DropReason.control_bytes)]);
    try std.testing.expect(!io.pressure_pending);
}

test "gossip queues a full validation burst in order and preserves byte bounds" {
    const burst = 64;
    var store = try storage.Store.init(std.testing.allocator, burst, burst * 4096);
    defer store.deinit(std.testing.allocator);
    var normal: [8]u8 = undefined;
    var critical: [8]u8 = undefined;
    var deliveries = try delivery.Pool.init(std.testing.allocator, 1, data_capacity);
    defer deliveries.deinit(std.testing.allocator);
    var io: Outbox = .{ .data = .{ .pool = &deliveries }, .control = .{ .bytes = &normal }, .critical = .{ .bytes = &critical } };
    defer io.reset(&store);
    var expected: [4096]u8 = undefined;
    var writer = protobuf.Writer.init(&expected);
    for (0..burst) |i| {
        const payload = [_]u8{@intCast(i)};
        const h = store.put([_]u8{@intCast(i)} ** 20, "topic", &payload).?;
        store.retainHistory(h);
        store.seal(h);
        try std.testing.expectEqual(QueueResult.queued, io.queueData(&store, h, burst, 0));
        writer.varint(protobuf.messageSize(&payload, "topic"));
        protobuf.writeMessage(&writer, &payload, "topic");
        if (i == burst - 1) try std.testing.expectEqual(QueueResult.full, io.queueData(&store, h, burst, 0));
        store.releaseHistory(h);
    }
    var actual: [4096]u8 = undefined;
    var used: usize = 0;
    for (0..burst * 3) |_| {
        const segment = io.segment(&store);
        if (segment.len == 0) break;
        @memcpy(actual[used..][0..segment.len], segment);
        used += segment.len;
        _ = io.advance(&store, segment.len);
    }
    try std.testing.expect(!io.pending());
    try std.testing.expectEqualSlices(u8, writer.written(), actual[0..used]);
    try std.testing.expectEqual(@as(usize, 0), store.used_entries);
    try std.testing.expectEqual(@as(usize, burst), store.free_pages);
    try std.testing.expectEqual(@as(u64, 1), io.drops[@intFromEnum(DropReason.data_bytes)]);
    try std.testing.expectEqual(@as(u64, 0), io.drops[@intFromEnum(DropReason.data_descriptors)]);
}

test "metrics control kinds survive partial writes ring reuse and refused frames" {
    var store = try storage.Store.init(std.testing.allocator, 1, 4096);
    defer store.deinit(std.testing.allocator);
    var normal: [4]u8 = undefined;
    var critical: [4]u8 = undefined;
    var deliveries = try delivery.Pool.init(std.testing.allocator, 1, data_capacity);
    defer deliveries.deinit(std.testing.allocator);
    var io: Outbox = .{ .data = .{ .pool = &deliveries }, .control = .{ .bytes = &normal }, .critical = .{ .bytes = &critical } };
    var metrics: @import("metrics.zig").Rpc = .{};
    const kinds = [_]ItemKind{ .subscription, .ihave, .iwant, .graft, .prune, .idontwant };
    for (0..control_frames * kinds.len) |index| {
        const kind = kinds[index % kinds.len];
        const token = io.appendControl("abc", false, kind, 1).?;
        try std.testing.expect(io.appendControl("ab", false, .prune, 1) == null);
        for (0..3) |byte| {
            _ = io.segment(&store);
            const receipt = io.advance(&store, 1);
            if (byte < 2) try std.testing.expect(receipt == null) else {
                try std.testing.expectEqual(token, receipt.?.control.token);
                try std.testing.expectEqual(kind, receipt.?.itemKind().?);
            }
            if (receipt) |done| metrics.observeSent(done.itemKind());
            try std.testing.expectEqual(index + @intFromBool(byte == 2), metrics.sent_frames);
        }
    }
    for (kinds) |kind| try std.testing.expectEqual(@as(u64, control_frames), metrics.sent_items[@intFromEnum(kind)]);
    try std.testing.expectEqual(@as(u64, control_frames * 5), metrics.control_frames_sent);
    _ = io.appendControl("abc", false, .prune, 1).?;
    _ = io.segment(&store);
    _ = io.advance(&store, 1);
    io.reset(&store);
    try std.testing.expectEqual(@as(u64, control_frames), metrics.sent_items[@intFromEnum(ItemKind.prune)]);
}

test "gossip control high water survives partial write refusal and reset" {
    var bytes: [4]u8 = undefined;
    var queue: ControlQueue = .{ .bytes = &bytes };
    try std.testing.expectEqual(QueueResult.queued, queue.append("abc", 1, null, 7));
    try std.testing.expectEqual(QueueResult.full, queue.append("ab", 2, null, 8));
    try std.testing.expectEqual(@as(usize, 3), queue.bytes_high_water);
    try std.testing.expectEqual(@as(usize, 1), queue.frames_high_water);
    try std.testing.expect(queue.advance(1) == null);
    try std.testing.expectEqual(@as(usize, 3), queue.bytes_high_water);
    queue.reset();
    try std.testing.expectEqual(@as(usize, 3), queue.bytes_high_water);
    try std.testing.expectEqual(@as(usize, 0), queue.count);
}

test "gossip typed controls preserve maximum ID lists and completion kinds" {
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    const ids: [constants.gossip_ids_max]topic.MessageId = @splat(@splat(7));
    const controls = [_]Control{
        .{ .subscription = .{ .topic = name, .subscribed = true } },
        .{ .graft = name },
        .{ .prune = .{ .topic = name, .backoff_s = std.math.maxInt(u64) } },
        .{ .ihave = .{ .topic = name, .ids = &ids } },
        .{ .iwant = &ids },
        .{ .idontwant = &ids },
    };
    var bytes: [8192]u8 = undefined;
    var deliveries = try delivery.Pool.init(std.testing.allocator, 1, data_capacity);
    defer deliveries.deinit(std.testing.allocator);
    var outbox: Outbox = .{ .data = .{ .pool = &deliveries }, .control = .{ .bytes = bytes[0..4096] }, .critical = .{ .bytes = bytes[4096..] } };
    var store = try storage.Store.init(std.testing.allocator, 1, 4096);
    defer store.deinit(std.testing.allocator);
    for (&controls) |*control| {
        const token = outbox.submit(control, 1).?;
        var reader: @import("frame.zig").Reader = .{};
        var body: [4096]u8 = undefined;
        var received: ?[]const u8 = null;
        var completion: ?Completion = null;
        for (0..2) |_| {
            const segment = outbox.segment(&store);
            if (segment.len == 0) break;
            const parsed = try reader.feed(segment, &body);
            received = parsed.frame;
            completion = outbox.advance(&store, segment.len);
            if (completion != null) break;
        }
        var rpc = protobuf.RpcReader.init(received.?);
        const item = (try rpc.next()).?;
        const expected: ItemKind = switch (control.*) {
            inline else => |_, tag| @field(ItemKind, @tagName(tag)),
        };
        try std.testing.expectEqual(expected, @as(ItemKind, item));
        var iterator: ?protobuf.IdIterator = switch (item) {
            .ihave => |have| have.ids(),
            .iwant, .idontwant => |want| want.ids(),
            else => null,
        };
        if (iterator) |*it| {
            for (ids) |id| try std.testing.expectEqualSlices(u8, &id, (try it.next()).?);
            try std.testing.expect(try it.next() == null);
        }
        try std.testing.expect(try rpc.next() == null);
        try std.testing.expectEqual(token, completion.?.control.token);
        try std.testing.expectEqual(expected, completion.?.itemKind().?);
        try std.testing.expect(!outbox.pending());
    }
}
