const std = @import("std");
const frame = @import("frame.zig");
const protobuf = @import("protobuf.zig");
const constants = @import("constants.zig");
const assert = std.debug.assert;
const receive = @import("receive_pool.zig");
const Outbox = @import("outbox.zig").Outbox;

pub const TimeoutReason = enum { subscriptions, receive_pressure, receive_frame, send_queue, send_progress };

pub const ActiveRpc = struct {
    reader: protobuf.RpcReader,
    item: ?protobuf.RpcReader.ItemRange = null,
    item_observed: bool = false,
    had_control: bool = false,
    subscriptions: usize = 0,
    messages: usize = 0,
    controls: usize = 0,

    pub fn permitsItem(self: *const ActiveRpc) bool {
        return switch (self.item.?.kind) {
            .subscription => self.subscriptions < constants.max_subscriptions_per_rpc,
            .message => self.messages < constants.max_publish_per_rpc,
            else => self.controls < constants.max_control_per_rpc,
        };
    }

    pub fn consumeItem(self: *ActiveRpc) void {
        if (self.permitsItem()) switch (self.item.?.kind) {
            .subscription => self.subscriptions += 1,
            .message => self.messages += 1,
            else => self.controls += 1,
        };
        self.item = null;
        self.item_observed = false;
    }
};

pub const Deadlines = struct {
    values: [@typeInfo(TimeoutReason).@"enum".fields.len]?u64 = @splat(null),

    pub fn next(self: *const Deadlines) ?u64 {
        var result: ?u64 = null;
        for (self.values) |value| if (value) |deadline| {
            result = @min(result orelse deadline, deadline);
        };
        return result;
    }

    pub fn expired(self: *const Deadlines, now_ms: u64) ?TimeoutReason {
        for (self.values, 0..) |value, index| if (value) |deadline| {
            if (now_ms >= deadline) return @enumFromInt(index);
        };
        return null;
    }
};

pub const PeerIo = struct {
    pub fn bufferBytes(options: *const @import("options.zig").Options) usize {
        return options.control_bytes + options.critical_bytes + options.body_buffer_bytes + constants.read_scratch_len;
    }

    pub fn init(bytes: []u8, options: *const @import("options.zig").Options, deliveries: *@import("delivery.zig").Pool) PeerIo {
        assert(bytes.len == bufferBytes(options));
        const critical = options.control_bytes;
        const body = critical + options.critical_bytes;
        const unread = body + options.body_buffer_bytes;
        return .{ .tx = .{ .data = .{ .pool = deliveries }, .control = .{ .bytes = bytes[0..critical] }, .critical = .{ .bytes = bytes[critical..body] } }, .body = bytes[body..unread], .unread = bytes[unread..] };
    }

    write_first: bool = false,
    tx: Outbox,
    body: []u8,
    unread: []u8,
    unread_start: usize = 0,
    unread_end: usize = 0,
    reader: frame.Reader = .{},
    rpc: ?ActiveRpc = null,
    fin_seen: bool = false,
    overflow: receive.Chain = .{},
    progress_ms: u64 = 0,
    frame_since: ?u64 = null,
    pressure_since: ?u64 = null,
    rx_ready: bool = true,
    blocked: enum { none, events } = .none,
    ihave_recv: u16 = 0,
    iwant_ids_sent: u16 = 0,
    idontwant_recv: u16 = 0,

    pub fn startSession(self: *PeerIo) void {
        assert(self.overflow.pages == 0 and self.rpc == null);
        self.tx.startSession();
        self.* = .{ .tx = self.tx, .body = self.body, .unread = self.unread, .rx_ready = false };
    }

    pub fn feedUnread(self: *PeerIo, pool: *receive.ReceivePool, limit: usize, now_ms: u64) (frame.Error || error{ReceiveCapacity})!struct { consumed: usize, complete: bool } {
        assert(self.rpc == null);
        assert(limit > 0 and limit <= self.unread_end - self.unread_start);
        const input = self.unread[self.unread_start..][0..limit];
        var consumed: usize = 0;
        if (self.reader.declared == null) {
            consumed = try self.reader.readPrefix(input);
        }
        if (self.reader.declared != null and self.reader.filled < self.reader.declared.? and consumed < input.len) {
            const overflow = self.reader.filled >= self.body.len;
            const target = if (overflow) pool.writable(&self.overflow) orelse return error.ReceiveCapacity else self.body[self.reader.filled..];
            const take = @min(input.len - consumed, target.len, self.reader.declared.? - self.reader.filled);
            assert(take > 0);
            @memcpy(target[0..take], input[consumed..][0..take]);
            self.reader.filled += take;
            if (overflow) self.overflow.len += take;
            consumed += take;
        }
        if (consumed > 0) {
            if (self.frame_since == null) self.frame_since = now_ms;
            self.progress_ms = now_ms;
            self.pressure_since = null;
            self.unread_start += consumed;
        }
        const complete = self.reader.declared != null and self.reader.filled == self.reader.declared.?;
        if (complete) self.rpc = .{ .reader = protobuf.RpcReader.initView(.{
            .prefix = self.body[0..@min(self.reader.filled, self.body.len)],
            .pool = pool,
            .first = self.overflow.first,
            .len = self.reader.filled,
        }) };
        return .{ .consumed = consumed, .complete = complete };
    }

    pub fn startRpc(self: *PeerIo, bytes: []const u8) void {
        assert(self.rpc == null);
        self.rpc = .{ .reader = protobuf.RpcReader.init(bytes) };
    }

    pub fn finishFrame(self: *PeerIo) void {
        assert(self.overflow.pages == 0);
        self.rpc = null;
        self.reader = .{};
        self.frame_since = null;
        self.pressure_since = null;
        self.blocked = .none;
    }

    pub fn resetHeartbeat(self: *PeerIo) void {
        self.ihave_recv = 0;
        self.iwant_ids_sent = 0;
        self.idontwant_recv = 0;
    }
    pub fn deadlines(self: *const PeerIo, options: *const @import("options.zig").Options) Deadlines {
        var result: Deadlines = .{};
        if (self.tx.subscription_since) |since| result.values[@intFromEnum(TimeoutReason.subscriptions)] = since +| options.pressure_timeout_ms;
        if (self.pressure_since) |since| result.values[@intFromEnum(TimeoutReason.receive_pressure)] = since +| options.pressure_timeout_ms;
        if (self.frame_since) |since| {
            result.values[@intFromEnum(TimeoutReason.receive_frame)] = if (self.pressure_since == null and self.rpc == null)
                @min(since +| (if ((self.reader.declaredLen() orelse 0) > self.body.len) options.large_frame_timeout_ms else options.pressure_timeout_ms), self.progress_ms +| options.large_frame_timeout_ms)
            else
                since +| options.pressure_timeout_ms;
        }
        if (self.tx.oldest()) |since| {
            result.values[@intFromEnum(TimeoutReason.send_queue)] = since +| options.tx_timeout_ms;
            if (self.tx.progress_ms) |progress| result.values[@intFromEnum(TimeoutReason.send_progress)] = progress +| options.large_frame_timeout_ms;
        }
        return result;
    }
};

test "gossip deadlines track pressure and progress through partial frame reset" {
    var pool = try @import("test_support.zig").sessions(std.testing.allocator, 1);
    defer pool.deinit(std.testing.allocator);
    const io = &pool.rows[0].io;
    const options: @import("options.zig").Options = .{ .pressure_timeout_ms = 100, .large_frame_timeout_ms = 50, .tx_timeout_ms = 100 };
    io.frame_since = 0;
    io.progress_ms = 20;
    try std.testing.expectEqual(@as(?u64, 70), io.deadlines(&options).next());
    io.pressure_since = 30;
    try std.testing.expect(io.deadlines(&options).expired(70) == null);
    try std.testing.expectEqual(@as(?u64, 100), io.deadlines(&options).next());
    try std.testing.expectEqual(TimeoutReason.receive_frame, io.deadlines(&options).expired(100).?);
    try std.testing.expect(!pool.resetRx(0));
    try std.testing.expect(io.deadlines(&options).next() == null);
    _ = io.tx.injectFrame("abc", false, .iwant, 0).?;
    io.tx.progress_ms = 20;
    try std.testing.expectEqual(TimeoutReason.send_progress, io.deadlines(&options).expired(70).?);
    io.tx.progress_ms = 50;
    try std.testing.expectEqual(@as(?u64, 100), io.deadlines(&options).next());
    try std.testing.expectEqual(TimeoutReason.send_queue, io.deadlines(&options).expired(100).?);
}

test "gossip active RPC completion discard and reset clear frame borrows and limits" {
    var sessions = try @import("test_support.zig").sessions(std.testing.allocator, 1);
    defer sessions.deinit(std.testing.allocator);
    const io = &sessions.rows[0].io;
    var bytes: [64]u8 = undefined;
    var writer = protobuf.Writer.init(&bytes);
    protobuf.writeSubscription(&writer, true, "topic");
    var framed: [65]u8 = undefined;
    const wire = frame.writeFrame(&framed, writer.written());

    const Finish = enum { complete, discard, reset };
    for ([_]Finish{ .complete, .discard, .reset }) |finish| {
        @memcpy(io.unread[0..wire.len], wire);
        io.unread_start = 0;
        io.unread_end = wire.len;
        try std.testing.expect((try io.feedUnread(&sessions.receive_pool, wire.len, 1)).complete);
        const rpc = &io.rpc.?;
        try std.testing.expect(rpc.item == null and !rpc.had_control);
        try std.testing.expectEqual(@as(usize, 0), rpc.subscriptions);
        try std.testing.expectEqual(@as(usize, 0), rpc.messages);
        try std.testing.expectEqual(@as(usize, 0), rpc.controls);
        var fields: usize = 65536;
        rpc.item = (try rpc.reader.step(&fields)).item;
        try std.testing.expectEqualStrings("topic", (try rpc.reader.decode(rpc.item.?, &.{})).subscription.topic);
        if (finish == .complete) {
            rpc.consumeItem();
            try std.testing.expect(rpc.item == null);
            try std.testing.expectEqual(@as(usize, 1), rpc.subscriptions);
            try std.testing.expect(try rpc.reader.next() == null);
        }
        rpc.had_control = true;
        rpc.messages = 3;
        rpc.controls = 4;
        io.pressure_since = 1;
        io.blocked = .events;
        try std.testing.expect(!if (finish == .reset) sessions.resetRx(0) else sessions.finishFrame(io));
        try std.testing.expect(io.rpc == null and io.reader.declaredLen() == null);
        try std.testing.expect(io.frame_since == null and io.pressure_since == null);
        try std.testing.expectEqual(.none, io.blocked);
        const unread = if (finish == .reset) 0 else wire.len;
        try std.testing.expectEqual(unread, io.unread_start);
        try std.testing.expectEqual(unread, io.unread_end);
    }
}

test "gossip active RPC item limits stop at each independent frame bound" {
    var rpc: ActiveRpc = .{ .reader = protobuf.RpcReader.init(&.{}) };
    const cases = .{
        .{ protobuf.Item{ .subscription = .{} }, constants.max_subscriptions_per_rpc },
        .{ protobuf.Item{ .message = .{} }, constants.max_publish_per_rpc },
        .{ protobuf.Item{ .graft = "topic" }, constants.max_control_per_rpc },
    };
    inline for (cases) |case| {
        for (0..case[1]) |_| {
            rpc.item = .{ .kind = std.meta.activeTag(case[0]), .bytes = .{ .start = .{}, .len = 0 } };
            try std.testing.expect(rpc.permitsItem());
            rpc.consumeItem();
            try std.testing.expect(rpc.item == null);
        }
        for (0..2) |_| {
            rpc.item = .{ .kind = std.meta.activeTag(case[0]), .bytes = .{ .start = .{}, .len = 0 } };
            try std.testing.expect(!rpc.permitsItem());
            rpc.consumeItem();
            try std.testing.expect(rpc.item == null);
        }
    }
    try std.testing.expectEqual(constants.max_subscriptions_per_rpc, rpc.subscriptions);
    try std.testing.expectEqual(constants.max_publish_per_rpc, rpc.messages);
    try std.testing.expectEqual(constants.max_control_per_rpc, rpc.controls);
}
