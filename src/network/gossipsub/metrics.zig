const prom = @import("../metrics/registry.zig");
const std = @import("std");
const policy = @import("topic_policy.zig");
const topic = @import("topic.zig");
const Item = @import("protobuf.zig").Item;
const ItemKind = std.meta.Tag(Item);

pub const ValidationTime = @import("../metrics/histogram.zig").Duration(&.{ 10, 30, 100, 300, 1000, 3000, 10000 });

pub const Counters = struct {
    accepted: u64 = 0,
    rejected: u64 = 0,
    ignored: u64 = 0,
    published: u64 = 0,
    published_bytes: u64 = 0,
    prevalidation: u64 = 0,
    ihave_ids: u64 = 0,
    /// Unique unknown IDs selected for an IWANT attempt, excluding pending requests.
    ihave_unseen: u64 = 0,
    iwant_ids: u64 = 0,
    published_peers: u64 = 0,
    forwarded: u64 = 0,
    forwarded_peers: u64 = 0,
    admitted: u64 = 0,
    duplicates: u64 = 0,
};

pub const Topics = struct {
    counts: [policy.kind_count + 1]Counters = @splat(.{}),

    pub fn get(self: *Topics, wire: []const u8) *Counters {
        const parsed = topic.parse(wire) orelse return &self.counts[policy.kind_count];
        const known = topic.Name.parse(parsed.name) orelse return &self.counts[policy.kind_count];
        return &self.counts[@intFromEnum(known.kind)];
    }
};

pub const IhaveIgnore = enum { low_score, limit, capacity, unsubscribed, no_new_ids, peer_capacity };

pub const Rpc = struct {
    invalid_messages: [std.meta.fields(@import("messages.zig").InvalidReason).len]u64 = @splat(0),
    received_bytes: u64 = 0,
    sent_bytes: u64 = 0,
    sent_frames: u64 = 0,
    sent_items: [std.meta.fields(ItemKind).len]u64 = @splat(0),
    control_frames_sent: u64 = 0,
    control_frames_received: u64 = 0,
    graylist_dropped: u64 = 0,
    items: [std.meta.fields(ItemKind).len]u64 = @splat(0),
    ihave_ignored: [std.meta.fields(IhaveIgnore).len]u64 = @splat(0),
    iwant_unknown: u64 = 0,
    idontwant_ids: u64 = 0,
    idontwant_unknown: u64 = 0,

    pub fn ignoreIhave(self: *Rpc, reason: IhaveIgnore) void {
        self.ihave_ignored[@intFromEnum(reason)] +|= 1;
    }

    pub fn observeSent(self: *Rpc, kind: ?ItemKind) void {
        self.sent_frames +|= 1;
        if (kind) |item| {
            self.sent_items[@intFromEnum(item)] +|= 1;
            switch (item) {
                .subscription, .message => {},
                else => self.control_frames_sent +|= 1,
            }
        }
    }

    pub fn observeItem(self: *Rpc, item: Item, had_control: *bool) void {
        self.items[@intFromEnum(item)] +|= 1;
        switch (item) {
            .subscription, .message => {},
            else => if (!had_control.*) {
                self.control_frames_received +|= 1;
                had_control.* = true;
            },
        }
    }

    pub fn write(self: *const Rpc, w: *prom.Encoder) prom.Error!void {
        inline for (.{
            .{ "gossipsub_rpc_recv_bytes_total", "received_bytes", "RPC stream bytes consumed by the frame decoder, including length prefixes and partial frames" },
            .{ "gossipsub_rpc_sent_bytes_total", "sent_bytes", "RPC stream bytes accepted by QUIC, including length prefixes and partial frames" },
            .{ "gossipsub_rpc_sent_count_total", "sent_frames", "Complete RPC frames accepted by QUIC" },
            .{ "gossipsub_rpc_sent_control_total", "control_frames_sent", "Complete control RPCs accepted by QUIC" },
            .{ "gossipsub_rpc_recv_control_total", "control_frames_received", "Received RPC frames with at least one decoded control item" },
            .{ "gossipsub_rpc_rcv_not_accepted_total", "graylist_dropped", "Received RPCs discarded by the graylist threshold" },
            .{ "gossipsub_iwant_rcv_dont_have_msgids_total", "iwant_unknown", "Examined valid IWANT IDs absent from message history" },
            .{ "gossipsub_idontwant_rcv_msgids_total", "idontwant_ids", "Examined valid IDONTWANT IDs within processing limits" },
            .{ "gossipsub_idontwant_rcv_dont_have_msgids_total", "idontwant_unknown", "Examined valid IDONTWANT IDs absent from message history" },
        }) |metric| try w.scalar(.{
            .name = metric[0],
            .kind = .counter,
            .help = metric[2],
        }, @field(self, metric[1]));
        inline for (std.meta.fields(ItemKind)) |field|
            try w.scalar(.{
                .name = "gossipsub_rpc_recv_" ++ field.name ++ "_total",
                .kind = .counter,
                .help = "Decoded RPC " ++ field.name ++ " items, counted once before handling",
            }, self.items[field.value]);
        inline for (std.meta.fields(ItemKind)) |field|
            try w.scalar(.{
                .name = "gossipsub_rpc_sent_" ++ field.name ++ "_total",
                .kind = .counter,
                .help = "RPC " ++ field.name ++ " items in complete frames accepted by QUIC",
            }, self.sent_items[field.value]);
        try w.enums(.{
            .name = "gossipsub_pre_validation_invalid_total",
            .kind = .counter,
            .help = "Subscribed publications rejected before host validation",
            .labels = &.{"reason"},
        }, @import("messages.zig").InvalidReason, &self.invalid_messages);
        try w.enums(.{
            .name = "gossipsub_ihave_rcv_ignored_total",
            .kind = .counter,
            .help = "IHAVE items producing no request at an admission boundary",
            .labels = &.{"reason"},
        }, IhaveIgnore, &self.ihave_ignored);
    }
};

pub const Recovery = struct {
    batches_sent: u64 = 0,
    expired_ids: u64 = 0,
    sent: u64 = 0,
    resolved: u64 = 0,
    resolved_duplicate: u64 = 0,
    delivery: @import("../metrics/histogram.zig").Duration(&.{ 100, 500, 1000, 3000, 6000, 12000 }) = .{},

    pub fn write(self: *const Recovery, w: *prom.Encoder) prom.Error!void {
        try w.scalar(.{
            .name = "gossipsub_iwant_batches_sent_total",
            .kind = .counter,
            .help = "IWANT batches with one scoring sample and a completed write receipt",
        }, self.batches_sent);
        try w.scalar(.{
            .name = "gossipsub_iwant_expired_ids_total",
            .kind = .counter,
            .help = "Requested IDs still missing when their batch expires",
        }, self.expired_ids);
        try w.scalar(.{
            .name = "gossipsub_iwant_promise_sent_total",
            .kind = .counter,
            .help = "Per-peer IWANT promises whose request frame was fully written",
        }, self.sent);
        try w.scalar(.{
            .name = "gossipsub_iwant_promise_resolved_total",
            .kind = .counter,
            .help = "Sent per-peer IWANT promises fulfilled by incoming gossip",
        }, self.resolved);
        try w.scalar(.{
            .name = "gossipsub_iwant_promise_resolved_from_duplicate_total",
            .kind = .counter,
            .help = "Sent per-peer IWANT promises fulfilled by duplicate incoming gossip",
        }, self.resolved_duplicate);
        const delivery = try w.histograms(.{
            .name = "gossipsub_iwant_promise_delivery_seconds",
            .kind = .histogram,
            .help = "Time from completed IWANT write to incoming message, per peer promise",
            .labels = &.{},
            .unit = .seconds,
        }, @TypeOf(self.delivery));
        try delivery.histogram(.{}, &self.delivery);
    }
};

test {
    _ = @import("metrics_test.zig");
}
