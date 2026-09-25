const prom = @import("../metrics/registry.zig");
const std = @import("std");
const policy = @import("topic_policy.zig");
const topic = @import("topic.zig");
const Item = @import("protobuf.zig").Item;
const ItemKind = std.meta.Tag(Item);

/// The label of an integration span: a slot phase bucket, then time without a known phase.
fn spanLabel(index: usize) []const u8 {
    const slots = @import("../slot_clock.zig");
    return if (index < slots.phase_buckets) slots.bucket_labels[index] else "unknown";
}

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
    transport: Transport = .{},

    pub fn write(self: *const Io, w: *prom.Encoder) prom.Error!void {
        try w.enums(.{ .name = "lodestar_native_gossip_turns_exhausted_total", .kind = .counter, .help = "Gossip turns ending with an exhausted shared budget", .labels = &.{"budget"} }, Budget, &self.turns_exhausted);
        try w.enums(.{ .name = "lodestar_native_gossip_ready_deferred_total", .kind = .counter, .help = "Ready peers remaining after the relevant shared budget was exhausted, including partially serviced peers", .labels = &.{"budget"} }, Budget, &self.ready_deferred);
        try w.enums(.{ .name = "lodestar_native_gossip_turn_stops_total", .kind = .counter, .help = "Gossip turns that stopped on an exhausted shared budget before visiting every ready session they took, by that budget: calls, else output, else the first exhausted receive budget", .labels = &.{"budget"} }, Budget, &self.stops);
        const skipped = try w.family(.{ .name = "lodestar_native_gossip_turn_stop_skipped_peers_total", .kind = .counter, .help = "Ready sessions a stopped gossip turn took but did not visit, by the budget that stopped it and whether each was writable: output queued on a stream that takes writes, which a blocked write stops until the next writable event", .labels = &.{ "budget", "output" } });
        inline for (@typeInfo(Budget).@"enum".fields) |budget| {
            inline for (.{ "not_writable", "writable" }, 0..) |output, index| try skipped.sample(.{ budget.name, output }, self.skipped[budget.value][index]);
        }
        try w.counters("lodestar_native_gossip_io_", &.{ .read_calls = self.read_calls, .write_calls = self.write_calls, .write_would_block = self.write_would_block, .write_zero = self.write_zero });
        try self.transport.write(w);
    }
};

/// The QUIC send state of gossip out streams when their write state changes: a write that blocks,
/// the first data refusal before the next writable event, and the first write QUIC takes in full
/// after a block. Nothing is labeled by peer.
pub const Transport = struct {
    const H = @import("../metrics/histogram.zig");
    const quic = @import("../quic/engine.zig");
    const Counts = @import("../quic/connection.zig").Transport.Counts;
    pub const Transition = enum { blocked, refused, recovered };
    /// quiche's stream capacity and its parts, the armed watermark, the congestion window, and the
    /// outbox's queued bytes.
    pub const Quantity = enum { capacity, watermark, cwnd, cwnd_available, tx_cap, connection_credit, stream_credit, stream_unsent, queued };
    const transition_count = @typeInfo(Transition).@"enum".fields.len;
    const limit_count = @typeInfo(quic.SendLimit).@"enum".fields.len;
    const signal_count = @typeInfo(Counts).@"struct".fields.len;
    const Bytes = H.Histogram(u64, &.{ 0, 1024, @import("../quic/limits.zig").write_lowat_max, 4096, 1 << 14, 1 << 16, 1 << 18, 1 << 20, 1 << 22, 1 << 24, 1 << 26 }, .{});
    const Rtt = H.Histogram(u64, &.{ 100_000, 250_000, 500_000, 1_000_000, 2_500_000, 5_000_000, 10_000_000, 25_000_000, 50_000_000, 100_000_000, 250_000_000, 500_000_000, 1_000_000_000 }, .{ .unit = .nanoseconds });
    const Rate = H.Histogram(u64, &.{ 1 << 14, 1 << 16, 1 << 18, 1 << 20, 1 << 22, 1 << 24, 1 << 26, 1 << 28, 1 << 30 }, .{});
    const Signal = H.Histogram(u64, &.{ 0, 1, 2, 4, 8, 16, 64, 256 }, .{});
    const log_interval_ms = 1_000;

    /// By the limit below what the stream waits for, and whether a writable edge was undelivered.
    transitions: [transition_count][limit_count][2]u64 = @splat(@splat(@splat(0))),
    bytes: [transition_count][@typeInfo(Quantity).@"enum".fields.len]Bytes = @splat(@splat(.{})),
    rtt: [transition_count]Rtt = @splat(.{}),
    delivery_rate: [transition_count]Rate = @splat(.{}),
    /// Counts since the session's previous snapshot, or since its connection opened.
    signals: [transition_count][signal_count]Signal = @splat(@splat(.{})),
    log_due_ms: [transition_count]u64 = @splat(0),

    pub fn observe(self: *Transport, transition: Transition, state: *const quic.SendState, queued: u64, since: *const Counts) void {
        const index = @intFromEnum(transition);
        self.transitions[index][@intFromEnum(state.limit())][@intFromBool(state.writable_pending)] +|= 1;
        const bytes = &self.bytes[index];
        bytes[@intFromEnum(Quantity.watermark)].observe(state.watermark);
        bytes[@intFromEnum(Quantity.cwnd)].observe(state.transport.cwnd);
        bytes[@intFromEnum(Quantity.queued)].observe(queued);
        if (state.capacity) |parts| {
            bytes[@intFromEnum(Quantity.capacity)].observe(state.available().?);
            // quiche ignores the congestion window while probes are due.
            bytes[@intFromEnum(Quantity.cwnd_available)].observe(if (parts.cwnd_available == std.math.maxInt(usize)) state.transport.cwnd else parts.cwnd_available);
            bytes[@intFromEnum(Quantity.tx_cap)].observe(parts.tx_cap);
            bytes[@intFromEnum(Quantity.connection_credit)].observe(parts.connection_credit);
            bytes[@intFromEnum(Quantity.stream_credit)].observe(parts.stream_credit);
            bytes[@intFromEnum(Quantity.stream_unsent)].observe(parts.stream_unsent);
        }
        self.rtt[index].observe(state.transport.rtt_ns);
        self.delivery_rate[index].observe(state.transport.delivery_rate);
        inline for (@typeInfo(Counts).@"struct".fields, 0..) |field, signal| self.signals[index][signal].observe(@field(since, field.name));
    }

    /// True at most once per interval for each transition.
    pub fn logDue(self: *Transport, transition: Transition, now_ms: u64) bool {
        const due = &self.log_due_ms[@intFromEnum(transition)];
        if (now_ms < due.*) return false;
        due.* = now_ms +| log_interval_ms;
        return true;
    }

    pub fn write(self: *const Transport, w: *prom.Encoder) prom.Error!void {
        const transitions = try w.family(.{ .name = "lodestar_native_gossip_stream_transitions_total", .kind = .counter, .help = "Gossip out stream write-state transitions: a write that blocked, the first data refusal before the next writable event, and the first write QUIC took in full after a block. Limit names what held quiche's stream capacity below the armed watermark, or below one byte with none armed: stream credit, then connection credit, then the congestion window; none when capacity reached it, unknown when quiche had stopped or freed the stream. Writable_pending says whether the engine held an undelivered writable edge", .labels = &.{ "transition", "limit", "writable_pending" } });
        inline for (@typeInfo(Transition).@"enum".fields) |transition| {
            inline for (@typeInfo(quic.SendLimit).@"enum".fields) |limit| {
                inline for (.{ "false", "true" }, 0..) |pending, flag| try transitions.sample(.{ transition.name, limit.name, pending }, self.transitions[transition.value][limit.value][flag]);
            }
        }
        const bytes = try w.histograms(.{ .name = "lodestar_native_gossip_stream_transition_bytes", .kind = .histogram, .help = "Byte quantities at gossip out stream transitions: capacity is the lesser of tx_cap, quiche's connection send capacity, and stream_credit; connection_credit and stream_credit are the peer's flow-control limits less the data buffered; cwnd_available is the congestion window less bytes in flight; stream_unsent is data buffered in quiche awaiting transmission; watermark is the armed write threshold; queued is the outbox's frame bytes. The parts of capacity are absent once quiche stopped or freed the stream", .labels = &.{ "transition", "quantity" } }, Bytes);
        inline for (@typeInfo(Transition).@"enum".fields) |transition| {
            inline for (@typeInfo(Quantity).@"enum".fields) |quantity| try bytes.histogram(.{ transition.name, quantity.name }, &self.bytes[transition.value][quantity.value]);
        }
        const rtt = try w.histograms(.{ .name = "lodestar_native_gossip_stream_transition_rtt_seconds", .kind = .histogram, .help = "Smoothed RTT of the connection's active path at gossip out stream transitions", .labels = &.{"transition"}, .unit = .seconds }, Rtt);
        inline for (@typeInfo(Transition).@"enum".fields) |transition| try rtt.histogram(.{transition.name}, &self.rtt[transition.value]);
        const rate = try w.histograms(.{ .name = "lodestar_native_gossip_stream_transition_delivery_rate_bytes_per_second", .kind = .histogram, .help = "quiche's delivery rate estimate for the connection's active path at gossip out stream transitions", .labels = &.{"transition"} }, Rate);
        inline for (@typeInfo(Transition).@"enum".fields) |transition| try rate.histogram(.{transition.name}, &self.delivery_rate[transition.value]);
        const signals = try w.histograms(.{ .name = "lodestar_native_gossip_stream_transition_quic_events", .kind = .histogram, .help = "QUIC events on the connection since the session's previous transition, or since the connection opened: packets lost and retransmitted, probe timeouts on the active path, and DATA_BLOCKED and STREAM_DATA_BLOCKED frames sent", .labels = &.{ "transition", "event" } }, Signal);
        inline for (@typeInfo(Transition).@"enum".fields) |transition| {
            inline for (@typeInfo(Counts).@"struct".fields, 0..) |event, signal| try signals.histogram(.{ transition.name, event.name }, &self.signals[transition.value][signal]);
        }
    }
};

pub const ValidationTime = @import("../metrics/histogram.zig").Duration(&.{ 10, 30, 100, 300, 1000, 3000, 10000 });

/// Data frame outcomes by delivery origin: selected recipients and their admission, the later
/// completion or cancellation of queued frames, refused admissions with their queue limit and the
/// peer's client, refusals by slot second, and the residence of each frame QUIC accepted in full.
/// Forward and publication recipients also count by message kind and slot phase, and each refusal
/// for want of a descriptor samples the refusing peer's queue and stream.
pub const Delivery = struct {
    const delivery = @import("delivery.zig");
    const Client = @import("../peers/client.zig").Client;
    const Kind = @import("topic.zig").Kind;
    const kind_count = @typeInfo(Kind).@"enum".fields.len;
    const DataDrop = enum { data_descriptors, data_pool, data_bytes };
    /// A selected recipient is queued, pressured or unavailable. A queued frame later completes
    /// when QUIC accepts its last byte, which is not delivery, or is cancelled by a stream reset.
    pub const Outcome = enum { selected, queued, pressured, unavailable, completed, cancelled };
    /// The outcomes counted by kind and phase. Selected includes recipients without an out
    /// stream, and pressured counts refusals by any queue limit.
    pub const KindOutcome = enum { selected, pressured };
    /// The refusing peer's write history: would_block from a write that blocked until a write QUIC
    /// takes in full, even after a writable event; accepted otherwise, including a stream without
    /// writes. It is not by itself a split of owner service from transport.
    pub const LastWrite = enum { accepted, would_block };
    const WriteTime = @import("../metrics/histogram.zig").Duration(&.{ 1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000 });
    const Queued = @import("../metrics/histogram.zig").Histogram(u64, &.{ 0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 384, 448, 480, 511 }, .{});
    const QueuedBytes = @import("../metrics/histogram.zig").Histogram(u64, &.{ 1 << 16, 1 << 17, 1 << 18, 1 << 19, 1 << 20, 1 << 21, 1 << 22, 1 << 23, 1 << 24 }, .{});
    const slots = @import("../slot_clock.zig");
    const Refusal = struct { bytes: QueuedBytes = .{}, oldest: WriteTime = .{} };

    recipients: [delivery.origin_count][@typeInfo(Outcome).@"enum".fields.len]u64 = @splat(@splat(0)),
    /// Forward and publication recipients by kind, then unknown, and by slot phase bucket, then
    /// unknown.
    by_kind: [kind_count + 1][slots.phase_buckets + 1][@typeInfo(KindOutcome).@"enum".fields.len]u64 = @splat(@splat(@splat(0))),
    drops: [@typeInfo(Client).@"enum".fields.len][delivery.origin_count][@typeInfo(DataDrop).@"enum".fields.len]u64 = @splat(@splat(@splat(0))),
    /// Cumulative by slot phase, which scrape timing cannot alias.
    drops_by_phase: [slots.phase_buckets]u64 = @splat(0),
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

    /// One forward's or publication's recipients, selected and refused for queue pressure.
    pub fn selectedByKind(self: *Delivery, kind: ?Kind, phase_bps: ?u16, selected: u64, pressured: u64) void {
        std.debug.assert(pressured <= selected);
        const outcomes = &self.by_kind[if (kind) |known| @intFromEnum(known) else kind_count][if (phase_bps) |bps| slots.SlotClock.bucket(bps) else slots.phase_buckets];
        outcomes[@intFromEnum(KindOutcome.selected)] +|= selected;
        outcomes[@intFromEnum(KindOutcome.pressured)] +|= pressured;
    }

    /// A data frame the peer's outbox refused, with the reason in its `last_drop`.
    pub fn dropped(self: *Delivery, origin: delivery.Origin, outbox: *const @import("outbox.zig").Outbox, client: Client, phase_bps: ?u16, now_ms: u64) void {
        const data: DataDrop = switch (outbox.last_drop) {
            .data_descriptors => .data_descriptors,
            .data_pool => .data_pool,
            .data_bytes => .data_bytes,
            else => unreachable,
        };
        self.drops[@intFromEnum(client)][@intFromEnum(origin)][@intFromEnum(data)] +|= 1;
        if (phase_bps) |bps| self.drops_by_phase[slots.SlotClock.bucket(bps)] +|= 1;
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
        const kinds = try w.family(.{ .name = "lodestar_native_gossip_data_recipients_by_kind_total", .kind = .counter, .help = "Forward and publication data frame recipients by message kind and the slot phase bucket of their selection: selected, including recipients without an out stream, and pressured, refused by any queue limit. Phase buckets are labeled by their first basis point of the slot, or unknown without the chain's genesis time", .labels = &.{ "kind", "phase_bps", "outcome" } });
        for (&self.by_kind, 0..) |*phases, index| {
            const kind = if (index < kind_count) @tagName(@as(Kind, @enumFromInt(index))) else "unknown";
            for (phases, 0..) |outcomes, span| {
                inline for (@typeInfo(KindOutcome).@"enum".fields) |outcome| try kinds.sample(.{ kind, spanLabel(span), outcome.name }, outcomes[outcome.value]);
            }
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

/// Queued data frames across peers, peers with a full ordinary allowance and writable sessions a
/// stopped turn left unvisited, integrated over time by slot phase. The owner integrates before
/// every change and at every pump, so intervals without changes count too.
pub const Occupancy = struct {
    const slots = @import("../slot_clock.zig");
    const Budget = @import("turn.zig").Budget;
    const budget_count = @import("turn.zig").budget_count;
    /// Phase buckets, then time without a known phase.
    const spans = slots.phase_buckets + 1;

    last_ms: ?u64 = null,
    observed_ms: [spans]u64 = @splat(0),
    descriptor_ms: [spans]u64 = @splat(0),
    full_ms: [spans]u64 = @splat(0),
    /// By the budget that stopped the turn.
    unserved_ms: [budget_count][spans]u64 = @splat(@splat(0)),

    /// The occupancy held since the previous integration.
    pub const Level = struct { descriptors: usize, full: usize, unserved: *const [budget_count]usize };

    pub fn integrate(self: *Occupancy, clock: ?*const slots.SlotClock, now_ms: u64, level: Level) void {
        const last = self.last_ms orelse now_ms;
        self.last_ms = @max(last, now_ms);
        if (now_ms <= last) return;
        var phases: [slots.phase_buckets]u64 = @splat(0);
        const known = if (clock) |value| value.split(last, now_ms, &phases) else false;
        if (!known) {
            self.add(slots.phase_buckets, now_ms - last, level);
            return;
        }
        for (phases, 0..) |ms, index| if (ms > 0) self.add(index, ms, level);
    }

    fn add(self: *Occupancy, index: usize, ms: u64, level: Level) void {
        self.observed_ms[index] +|= ms;
        self.descriptor_ms[index] +|= ms * level.descriptors;
        self.full_ms[index] +|= ms * level.full;
        for (&self.unserved_ms, level.unserved) |*budget, sessions| budget[index] +|= ms * sessions;
    }

    pub fn write(self: *const Occupancy, w: *prom.Encoder) prom.Error!void {
        inline for (.{
            .{ "lodestar_native_gossip_outbox_observed_seconds_total", "observed_ms", "Time over which data queue occupancy was integrated, by slot phase bucket labeled by its first basis point of the slot, or unknown without the chain's genesis time" },
            .{ "lodestar_native_gossip_outbox_descriptor_seconds_total", "descriptor_ms", "Queued data frames across all peers, integrated over time, by slot phase bucket; divide by observed seconds for the mean" },
            .{ "lodestar_native_gossip_outbox_full_peer_seconds_total", "full_ms", "Peers whose per-peer descriptor allowance refused ordinary data frames, integrated over time, by slot phase bucket; the byte limit and the shared pool are not counted" },
        }) |metric| {
            const family = try w.family(.{ .name = metric[0], .kind = .counter, .help = metric[2], .labels = &.{"phase_bps"}, .unit = .seconds });
            for (@field(self, metric[1]), 0..) |ms, index| try family.sample(.{spanLabel(index)}, @as(f64, @floatFromInt(ms)) / 1000);
        }
        const unserved = try w.family(.{ .name = "lodestar_native_gossip_turn_stop_unserved_seconds_total", .kind = .counter, .help = "Writable sessions a gossip turn stopped before visiting, integrated over time until their next visit or cancelled output, by the budget that stopped the turn and slot phase bucket", .labels = &.{ "budget", "phase_bps" }, .unit = .seconds });
        inline for (@typeInfo(Budget).@"enum".fields) |budget| {
            for (self.unserved_ms[budget.value], 0..) |ms, index| try unserved.sample(.{ budget.name, spanLabel(index) }, @as(f64, @floatFromInt(ms)) / 1000);
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
