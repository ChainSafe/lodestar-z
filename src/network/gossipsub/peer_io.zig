const std = @import("std");
const frame = @import("frame.zig");
const protobuf = @import("protobuf.zig");
const constants = @import("constants.zig");
const assert = std.debug.assert;
const Outbox = @import("outbox.zig").Outbox;

pub const TimeoutReason = enum { subscriptions, receive_pressure, receive_frame, send_queue, send_progress, prunes };
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
    rpc: ?protobuf.RpcReader = null,
    rpc_had_control: bool = false,
    item: ?protobuf.Item = null,
    subscriptions: usize = 0,
    messages: usize = 0,
    controls: usize = 0,
    fin_seen: bool = false,
    large_slot: ?@import("receive_pool.zig").Lease = null,
    progress_ms: u64 = 0,
    frame_since: ?u64 = null,
    pressure_since: ?u64 = null,
    rx_ready: bool = true,
    blocked: enum { none, events, storage } = .none,
    ihave_recv: u16 = 0,
    iwant_ids_sent: u16 = 0,
    idontwant_recv: u16 = 0,

    pub fn startSession(self: *PeerIo) void {
        assert(self.large_slot == null);
        self.tx.startSession();
        self.* = .{ .tx = self.tx, .body = self.body, .unread = self.unread, .rx_ready = false };
    }

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
            self.rpc_had_control = false;
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
    pub fn deadlines(self: *const PeerIo, options: *const @import("options.zig").Options) Deadlines {
        var result: Deadlines = .{};
        if (self.tx.prune_since) |since| result.values[@intFromEnum(TimeoutReason.prunes)] = since +| options.pressure_timeout_ms;
        if (self.tx.subscription_since) |since| result.values[@intFromEnum(TimeoutReason.subscriptions)] = since +| options.pressure_timeout_ms;
        if (self.pressure_since) |since| result.values[@intFromEnum(TimeoutReason.receive_pressure)] = since +| options.pressure_timeout_ms;
        if (self.frame_since) |since| {
            result.values[@intFromEnum(TimeoutReason.receive_frame)] = if (self.pressure_since == null)
                @min(since +| options.pressure_timeout_ms, self.progress_ms +| options.large_frame_timeout_ms)
            else
                since +| options.pressure_timeout_ms;
        }
        if (self.tx.oldest()) |since| {
            result.values[@intFromEnum(TimeoutReason.send_queue)] = since +| options.tx_timeout_ms;
            if (self.tx.progress_ms) |progress| result.values[@intFromEnum(TimeoutReason.send_progress)] = progress +| options.large_frame_timeout_ms;
        }
        return result;
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

test "gossip deadlines track pressure and progress through partial frame reset" {
    var pool = try @import("sessions.zig").Sessions.init(std.testing.allocator, 1);
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
    io.resetRx();
    try std.testing.expect(io.deadlines(&options).next() == null);
    _ = io.tx.injectFrame("abc", false, .iwant, 0).?;
    io.tx.progress_ms = 20;
    try std.testing.expectEqual(TimeoutReason.send_progress, io.deadlines(&options).expired(70).?);
    io.tx.progress_ms = 50;
    try std.testing.expectEqual(@as(?u64, 100), io.deadlines(&options).next());
    try std.testing.expectEqual(TimeoutReason.send_queue, io.deadlines(&options).expired(100).?);
}
