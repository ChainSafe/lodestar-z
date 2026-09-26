const prom = @import("../metrics/registry.zig");
const std = @import("std");
const policy = @import("topic_policy.zig");
const topic = @import("topic.zig");

pub const Io = struct {
    const Budget = @import("turn.zig").Budget;
    const budget_count = @import("turn.zig").budget_count;
    turns_exhausted: [budget_count]u64 = @splat(0),
    ready_deferred: [budget_count]u64 = @splat(0),
    /// Turns that stopped on a budget with ready sessions they took still unvisited, by that budget.
    stops: [budget_count]u64 = @splat(0),
    /// The sessions those turns left unvisited, by the stopping budget; writable ones second.
    skipped: [budget_count][2]u64 = @splat(@splat(0)),
    read_calls: u64 = 0,
    write_calls: u64 = 0,
    write_would_block: u64 = 0,
    write_zero: u64 = 0,

    pub fn write(self: *const Io, w: *prom.Encoder) prom.Error!void {
        try w.enums(.{ .name = "lodestar_native_gossip_turns_exhausted_total", .kind = .counter, .help = "Gossip turns ending with an exhausted shared budget", .labels = &.{"budget"} }, Budget, &self.turns_exhausted);
        try w.enums(.{ .name = "lodestar_native_gossip_ready_deferred_total", .kind = .counter, .help = "Ready peers remaining after the relevant shared budget was exhausted, including partially serviced peers", .labels = &.{"budget"} }, Budget, &self.ready_deferred);
        try w.enums(.{ .name = "lodestar_native_gossip_turn_stops_total", .kind = .counter, .help = "Gossip turns that stopped on an exhausted shared budget before visiting every ready session they took, by that budget: calls, else output, else the first exhausted receive budget", .labels = &.{"budget"} }, Budget, &self.stops);
        const skipped = try w.family(.{ .name = "lodestar_native_gossip_turn_stop_skipped_peers_total", .kind = .counter, .help = "Ready sessions a stopped gossip turn took but did not visit, by the budget that stopped it and whether each was writable: output queued on a stream that takes writes, which a blocked write stops until the next writable event", .labels = &.{ "budget", "output" } });
        inline for (@typeInfo(Budget).@"enum".fields) |budget| {
            inline for (.{ "not_writable", "writable" }, 0..) |output, index| try skipped.sample(.{ budget.name, output }, self.skipped[budget.value][index]);
        }
        try w.counters("lodestar_native_gossip_io_", &.{ .read_calls = self.read_calls, .write_calls = self.write_calls, .write_would_block = self.write_would_block, .write_zero = self.write_zero });
    }
};

pub const ValidationTime = @import("../metrics/histogram.zig").Duration(&.{ 10, 30, 100, 300, 1000, 3000, 10000 });

/// Data frame outcomes by delivery origin: selected recipients and their admission, the later
/// completion or cancellation of queued frames, refused admissions with their queue limit and the
/// peer's client, and the residence of each frame QUIC accepted in full. Each refusal for want of
/// a descriptor samples the refusing peer's queue and stream.
pub const Delivery = struct {
    const delivery = @import("delivery.zig");
    const Client = @import("../peers/client.zig").Client;
    const DataDrop = enum { data_descriptors, data_pool, data_bytes };
    /// A selected recipient is queued, pressured or unavailable. A queued frame later completes
    /// when QUIC accepts its last byte, which is not delivery, or is cancelled by a stream reset.
    pub const Outcome = enum { selected, queued, pressured, unavailable, completed, cancelled };
    /// The refusing peer's write history: would_block from a write that blocked until a write QUIC
    /// takes in full, even after a writable event; accepted otherwise, including a stream without
    /// writes. It is not by itself a split of owner service from transport.
    pub const LastWrite = enum { accepted, would_block };
    const WriteTime = @import("../metrics/histogram.zig").Duration(&.{ 1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000 });
    const Queued = @import("../metrics/histogram.zig").Histogram(u64, &.{ 0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 384, 448, 480, 511 }, .{});
    const QueuedBytes = @import("../metrics/histogram.zig").Histogram(u64, &.{ 1 << 16, 1 << 17, 1 << 18, 1 << 19, 1 << 20, 1 << 21, 1 << 22, 1 << 23, 1 << 24 }, .{});
    const Refusal = struct { bytes: QueuedBytes = .{}, oldest: WriteTime = .{} };

    recipients: [delivery.origin_count][@typeInfo(Outcome).@"enum".fields.len]u64 = @splat(@splat(0)),
    drops: [@typeInfo(Client).@"enum".fields.len][delivery.origin_count][@typeInfo(DataDrop).@"enum".fields.len]u64 = @splat(@splat(@splat(0))),
    write_time: [delivery.origin_count]WriteTime = @splat(.{}),
    /// The recipient's queued data frames when each admission is attempted, and the age of the
    /// oldest one when there is one.
    queued: Queued = .{},
    oldest_age: WriteTime = .{},
    /// At each refusal for want of a descriptor: the peer's queued data bytes and oldest frame age
    /// by its last write, and how long its stream has been blocked when no writable event followed.
    refusals: [@typeInfo(LastWrite).@"enum".fields.len]Refusal = @splat(.{}),
    refusal_blocked: WriteTime = .{},

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

    /// A data frame the peer's outbox refused, with the reason in its `last_drop`.
    pub fn dropped(self: *Delivery, origin: delivery.Origin, outbox: *const @import("outbox.zig").Outbox, client: Client, now_ms: u64) void {
        const data: DataDrop = switch (outbox.last_drop) {
            .data_descriptors => .data_descriptors,
            .data_pool => .data_pool,
            .data_bytes => .data_bytes,
            else => unreachable,
        };
        self.drops[@intFromEnum(client)][@intFromEnum(origin)][@intFromEnum(data)] +|= 1;
        if (data != .data_descriptors) return;
        const refusal = &self.refusals[@intFromBool(outbox.last_write_blocked)];
        refusal.bytes.observe(outbox.data.bytes);
        // A descriptor refusal leaves at most the local reserve free, so a frame is queued.
        refusal.oldest.observe(now_ms -| outbox.data.oldest().?);
        if (outbox.blocked_since) |since| self.refusal_blocked.observe(now_ms -| since);
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
        const times = try w.histograms(.{ .name = "lodestar_native_gossip_data_write_seconds", .kind = .histogram, .help = "Data frame residence from queue admission until QUIC accepted its last byte, by delivery origin", .labels = &.{"origin"}, .unit = .seconds }, WriteTime);
        inline for (@typeInfo(delivery.Origin).@"enum".fields) |origin| try times.histogram(.{origin.name}, &self.write_time[origin.value]);
        const queued = try w.histograms(.{ .name = "lodestar_native_gossip_data_admission_queued", .kind = .histogram, .help = "The recipient's queued data frames when a data frame admission is attempted" }, Queued);
        try queued.histogram(.{}, &self.queued);
        const oldest = try w.histograms(.{ .name = "lodestar_native_gossip_data_admission_oldest_seconds", .kind = .histogram, .help = "Age of the recipient's oldest queued data frame when a data frame admission is attempted behind it", .unit = .seconds }, WriteTime);
        try oldest.histogram(.{}, &self.oldest_age);
        const refused_bytes = try w.histograms(.{ .name = "lodestar_native_gossip_descriptor_refusal_queued_bytes", .kind = .histogram, .help = "The refusing peer's queued data bytes at each data frame refusal for want of a descriptor, by write history: would_block after a write that blocked, even once the stream is writable again, and accepted after a write QUIC took in full or before any write", .labels = &.{"last_write"} }, QueuedBytes);
        inline for (@typeInfo(LastWrite).@"enum".fields) |field| try refused_bytes.histogram(.{field.name}, &self.refusals[field.value].bytes);
        const refused_oldest = try w.histograms(.{ .name = "lodestar_native_gossip_descriptor_refusal_oldest_seconds", .kind = .histogram, .help = "Age of the refusing peer's oldest queued data frame at each data frame refusal for want of a descriptor, by write history: would_block after a write that blocked, even once the stream is writable again, and accepted after a write QUIC took in full or before any write", .labels = &.{"last_write"}, .unit = .seconds }, WriteTime);
        inline for (@typeInfo(LastWrite).@"enum".fields) |field| try refused_oldest.histogram(.{field.name}, &self.refusals[field.value].oldest);
        const blocked = try w.histograms(.{ .name = "lodestar_native_gossip_descriptor_refusal_blocked_seconds", .kind = .histogram, .help = "How long the refusing peer's stream has been blocked, from the write that took fewer bytes than offered, at each data frame refusal for want of a descriptor before a writable event", .unit = .seconds }, WriteTime);
        try blocked.histogram(.{}, &self.refusal_blocked);
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

/// Applied verdicts, and accepted messages handed to forwarding, for one topic kind.
pub const Counters = struct {
    accepted: u64 = 0,
    rejected: u64 = 0,
    ignored: u64 = 0,
    forwarded: u64 = 0,
};

pub const Topics = struct {
    counts: [policy.kind_count + 1]Counters = @splat(.{}),

    pub fn get(self: *Topics, wire: []const u8) *Counters {
        const parsed = topic.parse(wire) orelse return &self.counts[policy.kind_count];
        const known = topic.Name.parse(parsed.name) orelse return &self.counts[policy.kind_count];
        return &self.counts[@intFromEnum(known.kind)];
    }
};

/// An IWANT ID absent from history, or present and then suppressed by IDONTWANT, over its
/// retransmission limit, queued or refused for queue pressure.
pub const IwantOutcome = enum { miss, suppressed, limited, queued, refused };
pub const iwant_outcome_count = @typeInfo(IwantOutcome).@"enum".fields.len;

test {
    _ = @import("metrics_test.zig");
}
