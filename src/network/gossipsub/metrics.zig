const prom = @import("../metrics/registry.zig");
const std = @import("std");
const policy = @import("topic_policy.zig");
const topic = @import("topic.zig");
const Item = @import("protobuf.zig").Item;
const ItemKind = std.meta.Tag(Item);

pub const Io = struct {
    const Budget = @import("turn.zig").Budget;
    turns_exhausted: [std.meta.fields(Budget).len]u64 = @splat(0),
    ready_deferred: [std.meta.fields(Budget).len]u64 = @splat(0),
    read_calls: u64 = 0,
    write_calls: u64 = 0,
    write_would_block: u64 = 0,
    write_zero: u64 = 0,

    pub fn write(self: *const Io, w: *prom.Encoder) prom.Error!void {
        try w.enums(.{ .name = "lodestar_native_gossip_turns_exhausted_total", .kind = .counter, .help = "Gossip turns ending with an exhausted shared budget", .labels = &.{"budget"} }, Budget, &self.turns_exhausted);
        try w.enums(.{ .name = "lodestar_native_gossip_ready_deferred_total", .kind = .counter, .help = "Ready peers remaining after the relevant shared budget was exhausted, including partially serviced peers", .labels = &.{"budget"} }, Budget, &self.ready_deferred);
        try w.counters("lodestar_native_gossip_io_", &.{ .read_calls = self.read_calls, .write_calls = self.write_calls, .write_would_block = self.write_would_block, .write_zero = self.write_zero });
    }
};

pub const ValidationTime = @import("../metrics/histogram.zig").Duration(&.{ 10, 30, 100, 300, 1000, 3000, 10000 });

/// Data frame outcomes by delivery origin: selected recipients and their admission, the later
/// completion or cancellation of queued frames, refused admissions with their queue limit and the
/// peer's client, refusals by slot second, and the residence of each frame QUIC accepted in full.
pub const Delivery = struct {
    const delivery = @import("delivery.zig");
    const Client = @import("../peers/client.zig").Client;
    const DataDrop = enum { data_descriptors, data_pool, data_bytes };
    /// A selected recipient is queued, pressured or unavailable. A queued frame later completes
    /// when QUIC accepts its last byte, which is not delivery, or is cancelled by a stream reset.
    pub const Outcome = enum { selected, queued, pressured, unavailable, completed, cancelled };
    const WriteTime = @import("../metrics/histogram.zig").Duration(&.{ 1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000 });
    const Queued = @import("../metrics/histogram.zig").Histogram(u64, &.{ 0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 384, 448, 480, 511 }, .{});
    const slots = @import("../slot_clock.zig");

    recipients: [delivery.origin_count][@typeInfo(Outcome).@"enum".fields.len]u64 = @splat(@splat(0)),
    drops: [@typeInfo(Client).@"enum".fields.len][delivery.origin_count][@typeInfo(DataDrop).@"enum".fields.len]u64 = @splat(@splat(@splat(0))),
    /// Cumulative by slot phase, which scrape timing cannot alias.
    drops_by_phase: [slots.phase_buckets]u64 = @splat(0),
    write_time: [delivery.origin_count]WriteTime = @splat(.{}),
    /// The recipient's queued data frames when each admission is attempted, and the age of the
    /// oldest one when there is one.
    queued: Queued = .{},
    oldest_age: WriteTime = .{},

    /// Samples the recipient's queue as it was before an admission attempt.
    pub fn admitted(self: *Delivery, queue: *const delivery.Queue, now_ms: u64, queued: bool) void {
        const before = queue.count - @intFromBool(queued);
        self.queued.observe(before);
        if (before > 0) self.oldest_age.observe(now_ms -| queue.oldest().?);
    }

    pub fn recipient(self: *Delivery, origin: delivery.Origin, outcome: Outcome) void {
        if (outcome != .completed and outcome != .cancelled) self.recipients[@intFromEnum(origin)][@intFromEnum(Outcome.selected)] +|= 1;
        self.recipients[@intFromEnum(origin)][@intFromEnum(outcome)] +|= 1;
    }

    pub fn cancelled(self: *Delivery, queued: *const [delivery.origin_count]usize) void {
        for (&self.recipients, queued) |*outcomes, count| outcomes[@intFromEnum(Outcome.cancelled)] +|= count;
    }

    pub fn dropped(self: *Delivery, origin: delivery.Origin, reason: @import("outbox.zig").DropReason, client: Client, phase_bps: ?u16) void {
        const data: DataDrop = switch (reason) {
            .data_descriptors => .data_descriptors,
            .data_pool => .data_pool,
            .data_bytes => .data_bytes,
            else => unreachable,
        };
        self.drops[@intFromEnum(client)][@intFromEnum(origin)][@intFromEnum(data)] +|= 1;
        if (phase_bps) |bps| self.drops_by_phase[slots.SlotClock.bucket(bps)] +|= 1;
    }

    pub fn written(self: *Delivery, receipt: delivery.Receipt, now_ms: u64) void {
        self.recipient(receipt.origin, .completed);
        self.write_time[@intFromEnum(receipt.origin)].observe(now_ms -| receipt.enqueued_ms);
    }

    pub fn write(self: *const Delivery, w: *prom.Encoder) prom.Error!void {
        const recipients = try w.family(.{ .name = "lodestar_native_gossip_data_recipients_total", .kind = .counter, .help = "Data frame recipients by delivery origin: selected, then queued, pressured or unavailable; queued frames later complete when QUIC accepts their last byte, which is not delivery, or are cancelled by a stream reset", .labels = &.{ "origin", "outcome" } });
        inline for (@typeInfo(delivery.Origin).@"enum".fields) |origin| {
            inline for (@typeInfo(Outcome).@"enum".fields) |outcome| try recipients.sample(.{ origin.name, outcome.name }, self.recipients[origin.value][outcome.value]);
        }
        const drops = try w.family(.{ .name = "lodestar_native_gossip_data_drops_total", .kind = .counter, .help = "Refused data frame admissions by delivery origin, the queue limit that refused them and the peer's client", .labels = &.{ "origin", "reason", "client" } });
        inline for (@typeInfo(delivery.Origin).@"enum".fields) |origin| {
            inline for (@typeInfo(DataDrop).@"enum".fields) |reason| {
                inline for (@typeInfo(Client).@"enum".fields) |client| try drops.sample(.{ origin.name, reason.name, client.name }, self.drops[client.value][origin.value][reason.value]);
            }
        }
        const phases = try w.family(.{ .name = "lodestar_native_gossip_data_drops_by_slot_phase_total", .kind = .counter, .help = "Refused data frame admissions by slot phase, in 16 equal buckets labeled by their first basis point of the slot duration; counted only with the chain's genesis time and slot duration", .labels = &.{"phase_bps"} });
        for (slots.bucket_labels, self.drops_by_phase) |label, count| try phases.sample(.{label}, count);
        const times = try w.histograms(.{ .name = "lodestar_native_gossip_data_write_seconds", .kind = .histogram, .help = "Data frame residence from queue admission until QUIC accepted its last byte, by delivery origin", .labels = &.{"origin"}, .unit = .seconds }, WriteTime);
        inline for (@typeInfo(delivery.Origin).@"enum".fields) |origin| try times.histogram(.{origin.name}, &self.write_time[origin.value]);
        const queued = try w.histograms(.{ .name = "lodestar_native_gossip_data_admission_queued", .kind = .histogram, .help = "The recipient's queued data frames when a data frame admission is attempted" }, Queued);
        try queued.histogram(.{}, &self.queued);
        const oldest = try w.histograms(.{ .name = "lodestar_native_gossip_data_admission_oldest_seconds", .kind = .histogram, .help = "Age of the recipient's oldest queued data frame when a data frame admission is attempted behind it", .unit = .seconds }, WriteTime);
        try oldest.histogram(.{}, &self.oldest_age);
    }
};

/// Verdict application by the owner. An apply is the verdicts reported between two pumps, which
/// is the host apply of one owner turn.
pub const Apply = struct {
    const H = @import("../metrics/histogram.zig");
    const Count = H.Histogram(u64, &.{ 0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 4096, 16384 }, .{});
    const Bytes = H.Histogram(u64, &.{ 1 << 10, 1 << 13, 1 << 16, 1 << 18, 1 << 20, 1 << 22, 1 << 24, 1 << 26 }, .{});
    const Elapsed = H.Histogram(u64, &.{ 10_000, 50_000, 100_000, 250_000, 500_000, 1_000_000, 2_500_000, 5_000_000, 10_000_000, 50_000_000 }, .{ .unit = .nanoseconds });
    const Spacing = H.Duration(&.{ 1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 5000 });
    pub const Recipient = enum { selected, queued, refused };
    const Open = struct { verdicts: u64 = 0, recipients: [3]u64 = @splat(0), bytes: u64 = 0, elapsed_ns: u64 = 0 };

    verdicts: Count = .{},
    elapsed: Elapsed = .{},
    spacing: Spacing = .{},
    recipients: [3]Count = @splat(.{}),
    bytes: Bytes = .{},
    /// Data frames QUIC accepted in full since the previous apply.
    service: Count = .{},
    open: ?Open = null,
    last_start_ms: ?u64 = null,
    frames: u64 = 0,

    /// One reported verdict, the recipients its forward selected and the bytes it queued.
    pub fn verdict(self: *Apply, now_ms: u64, elapsed_ns: u64, forward: ?@import("gossipsub.zig").Gossipsub.PublishOutcome, bytes: u64) void {
        if (self.open == null) {
            if (self.last_start_ms) |last| self.spacing.observe(now_ms -| last);
            self.last_start_ms = now_ms;
            self.open = .{};
        }
        const open = &self.open.?;
        open.verdicts += 1;
        open.elapsed_ns +|= elapsed_ns;
        if (forward) |outcome| {
            open.recipients[@intFromEnum(Recipient.selected)] += outcome.selected;
            open.recipients[@intFromEnum(Recipient.queued)] += outcome.queued;
            open.recipients[@intFromEnum(Recipient.refused)] += outcome.pressured;
            open.bytes +|= bytes;
        }
    }

    pub fn frameCompleted(self: *Apply) void {
        self.frames +|= 1;
    }

    pub fn close(self: *Apply) void {
        const open = self.open orelse return;
        self.verdicts.observe(open.verdicts);
        self.elapsed.observe(open.elapsed_ns);
        for (&self.recipients, open.recipients) |*histogram, count| histogram.observe(count);
        self.bytes.observe(open.bytes);
        self.service.observe(self.frames);
        self.frames = 0;
        self.open = null;
    }

    pub fn write(self: *const Apply, w: *prom.Encoder) prom.Error!void {
        const verdicts = try w.histograms(.{ .name = "lodestar_native_gossip_apply_verdicts", .kind = .histogram, .help = "Verdicts the owner reported in one host apply" }, Count);
        try verdicts.histogram(.{}, &self.verdicts);
        const elapsed = try w.histograms(.{ .name = "lodestar_native_gossip_apply_seconds", .kind = .histogram, .help = "Time the owner spent reporting one host apply's verdicts, forwarding included", .unit = .seconds }, Elapsed);
        try elapsed.histogram(.{}, &self.elapsed);
        const spacing = try w.histograms(.{ .name = "lodestar_native_gossip_apply_spacing_seconds", .kind = .histogram, .help = "Time between the starts of consecutive host applies that reported verdicts", .unit = .seconds }, Spacing);
        try spacing.histogram(.{}, &self.spacing);
        const recipients = try w.histograms(.{ .name = "lodestar_native_gossip_apply_forward_recipients", .kind = .histogram, .help = "Forward recipients one host apply selected, queued, or refused for queue pressure", .labels = &.{"outcome"} }, Count);
        inline for (@typeInfo(Recipient).@"enum".fields) |field| try recipients.histogram(.{field.name}, &self.recipients[field.value]);
        const bytes = try w.histograms(.{ .name = "lodestar_native_gossip_apply_forward_bytes", .kind = .histogram, .help = "Compressed payload bytes one host apply queued for forwarding, summed over recipients" }, Bytes);
        try bytes.histogram(.{}, &self.bytes);
        const service = try w.histograms(.{ .name = "lodestar_native_gossip_apply_service_frames", .kind = .histogram, .help = "Data frames QUIC accepted in full between one host apply and the previous one" }, Count);
        try service.histogram(.{}, &self.service);
    }
};

/// Queued data frames across peers and peers with a full ordinary allowance, integrated over
/// time by slot phase. The owner integrates before every change and at every pump, so intervals
/// without changes count too.
pub const Occupancy = struct {
    const slots = @import("../slot_clock.zig");
    /// Phase buckets, then time without a known phase.
    const spans = slots.phase_buckets + 1;

    last_ms: ?u64 = null,
    observed_ms: [spans]u64 = @splat(0),
    descriptor_ms: [spans]u64 = @splat(0),
    full_ms: [spans]u64 = @splat(0),

    pub fn integrate(self: *Occupancy, clock: ?*const slots.SlotClock, now_ms: u64, descriptors: usize, full: usize) void {
        const last = self.last_ms orelse now_ms;
        self.last_ms = @max(last, now_ms);
        if (now_ms <= last) return;
        var phases: [slots.phase_buckets]u64 = @splat(0);
        const known = if (clock) |value| value.split(last, now_ms, &phases) else false;
        if (!known) {
            self.add(slots.phase_buckets, now_ms - last, descriptors, full);
            return;
        }
        for (phases, 0..) |ms, index| if (ms > 0) self.add(index, ms, descriptors, full);
    }

    fn add(self: *Occupancy, index: usize, ms: u64, descriptors: usize, full: usize) void {
        self.observed_ms[index] +|= ms;
        self.descriptor_ms[index] +|= ms * descriptors;
        self.full_ms[index] +|= ms * full;
    }

    pub fn write(self: *const Occupancy, w: *prom.Encoder) prom.Error!void {
        inline for (.{
            .{ "lodestar_native_gossip_outbox_observed_seconds_total", "observed_ms", "Time over which data queue occupancy was integrated, by slot phase bucket labeled by its first basis point of the slot, or unknown without the chain's genesis time" },
            .{ "lodestar_native_gossip_outbox_descriptor_seconds_total", "descriptor_ms", "Queued data frames across all peers, integrated over time, by slot phase bucket; divide by observed seconds for the mean" },
            .{ "lodestar_native_gossip_outbox_full_peer_seconds_total", "full_ms", "Peers whose queue refused ordinary data frames for want of a descriptor, integrated over time, by slot phase bucket" },
        }) |metric| {
            const family = try w.family(.{ .name = metric[0], .kind = .counter, .help = metric[2], .labels = &.{"phase_bps"}, .unit = .seconds });
            for (@field(self, metric[1]), 0..) |ms, index| try family.sample(.{if (index < slots.phase_buckets) slots.bucket_labels[index] else "unknown"}, @as(f64, @floatFromInt(ms)) / 1000);
        }
    }
};

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
/// An IWANT ID absent from history, or present and then suppressed by IDONTWANT, over its
/// retransmission limit, queued or refused for queue pressure.
pub const IwantOutcome = enum { miss, suppressed, limited, queued, refused };

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
    iwant: [std.meta.fields(IwantOutcome).len]u64 = @splat(0),
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
            .name = "lodestar_native_gossip_iwant_ids_total",
            .kind = .counter,
            .help = "Examined valid IWANT IDs by outcome: absent from history, or present and then suppressed by IDONTWANT, over the retransmission limit, queued, or refused for queue pressure",
            .labels = &.{"outcome"},
        }, IwantOutcome, &self.iwant);
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
