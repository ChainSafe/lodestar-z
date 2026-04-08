//! Deterministic network simulator for consensus testing.
//!
//! Simulates gossip and req/resp message delivery between nodes with
//! configurable fault injection: packet loss, duplication, reordering,
//! latency, and network partitions.
//!
//! All randomness comes from a seeded PRNG — same seed = identical delivery.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Order = std.math.Order;
const networking = @import("networking");

const ResponseCode = networking.ResponseCode;

pub const MessageType = enum {
    gossip,
    gossip_attestation,
    req_resp_request,
    req_resp_response,
};

pub const PendingMessage = struct {
    from: u8,
    to: u8,
    deliver_at_ns: u64,
    data: []const u8,
    message_type: MessageType,
    /// Sequence number for deterministic tie-breaking.
    sequence: u64,
};

pub const DeliveredMessage = struct {
    from: u8,
    to: u8,
    deliver_at_ns: u64,
    data: []const u8,
    message_type: MessageType,
};

pub fn encodeReqRespResponse(allocator: Allocator, result: ResponseCode, payload: []const u8) ![]u8 {
    const encoded = try allocator.alloc(u8, 1 + payload.len);
    encoded[0] = @intFromEnum(result);
    @memcpy(encoded[1..], payload);
    return encoded;
}

pub const DecodedReqRespResponse = struct {
    result: ResponseCode,
    payload: []const u8,
};

pub fn decodeReqRespResponse(bytes: []const u8) !DecodedReqRespResponse {
    if (bytes.len == 0) return error.InvalidReqRespResponse;
    const result = ResponseCode.fromByte(bytes[0]) orelse return error.InvalidReqRespResponse;
    return .{
        .result = result,
        .payload = bytes[1..],
    };
}

pub const Config = struct {
    /// Probability of dropping a packet (0.0 - 1.0).
    packet_loss_rate: f64 = 0.0,
    /// Probability of duplicating a packet.
    packet_duplicate_rate: f64 = 0.0,
    /// Probability of reordering packets (adds random extra latency).
    packet_reorder_rate: f64 = 0.0,
    /// Min one-way latency in simulated ms.
    min_latency_ms: u64 = 1,
    /// Max one-way latency in simulated ms.
    max_latency_ms: u64 = 50,
};

fn comparePending(_: void, a: PendingMessage, b: PendingMessage) Order {
    // Primary: deliver_at_ns ascending.
    if (a.deliver_at_ns < b.deliver_at_ns) return .lt;
    if (a.deliver_at_ns > b.deliver_at_ns) return .gt;
    // Tie-break: sequence number (FIFO for same-time messages).
    if (a.sequence < b.sequence) return .lt;
    if (a.sequence > b.sequence) return .gt;
    return .eq;
}

pub const SimNetwork = struct {
    allocator: Allocator,
    prng: *std.Random.DefaultPrng,

    config: Config,

    /// Priority queue ordered by delivery time.
    pending: std.PriorityQueue(PendingMessage, void, comparePending),

    /// Monotonically increasing sequence number for deterministic ordering.
    next_sequence: u64 = 0,

    /// Active network partitions: partition_set[nodeA][nodeB] = true means
    /// nodeA cannot send to nodeB.
    partition_set: [256][256]bool = [_][256]bool{[_]bool{false} ** 256} ** 256,

    /// Delivered messages buffer (reused across tick calls).
    delivered_buf: std.ArrayListUnmanaged(DeliveredMessage),

    /// Stats for test assertions.
    stats: Stats = .{},

    pub const Stats = struct {
        messages_sent: u64 = 0,
        messages_delivered: u64 = 0,
        messages_dropped: u64 = 0,
        messages_duplicated: u64 = 0,
    };

    pub fn init(allocator: Allocator, prng: *std.Random.DefaultPrng, config: Config) SimNetwork {
        return .{
            .allocator = allocator,
            .prng = prng,
            .config = config,
            .pending = .{ .items = &.{}, .cap = 0, .context = {} },
            .delivered_buf = .empty,
        };
    }

    pub fn deinit(self: *SimNetwork) void {
        // Free all pending message data.
        while (self.pending.peek()) |_| {
            const msg = self.pending.pop().?;
            self.allocator.free(msg.data);
        }
        self.pending.deinit(self.allocator);
        self.delivered_buf.deinit(self.allocator);
    }

    /// Send a message from one node to another.
    /// The message is queued for future delivery based on configured latency.
    /// Returns false if the message was dropped (partition or packet loss).
    pub fn send(
        self: *SimNetwork,
        from: u8,
        to: u8,
        data: []const u8,
        msg_type: MessageType,
        current_time_ns: u64,
    ) !bool {
        self.stats.messages_sent += 1;

        // Check for partition.
        if (self.partition_set[from][to]) {
            self.stats.messages_dropped += 1;
            return false;
        }

        // Check for packet loss.
        if (self.config.packet_loss_rate > 0.0) {
            if (self.randomFloat() < self.config.packet_loss_rate) {
                self.stats.messages_dropped += 1;
                return false;
            }
        }

        // Calculate delivery time with latency.
        var latency_ms = self.randomLatency();

        // Reordering: add extra random latency.
        if (self.config.packet_reorder_rate > 0.0) {
            if (self.randomFloat() < self.config.packet_reorder_rate) {
                latency_ms += self.randomLatency();
            }
        }

        const deliver_at_ns = current_time_ns + latency_ms * std.time.ns_per_ms;

        // Copy data for the pending message.
        const data_copy = try self.allocator.dupe(u8, data);
        errdefer self.allocator.free(data_copy);

        try self.pending.push(self.allocator, .{
            .from = from,
            .to = to,
            .deliver_at_ns = deliver_at_ns,
            .data = data_copy,
            .message_type = msg_type,
            .sequence = self.next_sequence,
        });
        self.next_sequence += 1;

        // Check for packet duplication.
        if (self.config.packet_duplicate_rate > 0.0) {
            if (self.randomFloat() < self.config.packet_duplicate_rate) {
                const dup_data = try self.allocator.dupe(u8, data);
                errdefer self.allocator.free(dup_data);

                const dup_latency_ms = self.randomLatency();
                try self.pending.push(self.allocator, .{
                    .from = from,
                    .to = to,
                    .deliver_at_ns = current_time_ns + dup_latency_ms * std.time.ns_per_ms,
                    .data = dup_data,
                    .message_type = msg_type,
                    .sequence = self.next_sequence,
                });
                self.next_sequence += 1;
                self.stats.messages_duplicated += 1;
            }
        }

        return true;
    }

    /// Deliver all messages that should arrive by `current_time_ns`.
    /// Returns a slice of delivered messages. The slice is valid until the
    /// next call to `tick`.
    pub fn tick(self: *SimNetwork, current_time_ns: u64) ![]const DeliveredMessage {
        self.delivered_buf.clearRetainingCapacity();

        while (self.pending.peek()) |msg| {
            if (msg.deliver_at_ns > current_time_ns) break;

            const delivered = self.pending.pop().?;

            // Check if a partition was created after the message was sent.
            if (self.partition_set[delivered.from][delivered.to]) {
                self.allocator.free(delivered.data);
                self.stats.messages_dropped += 1;
                continue;
            }

            try self.delivered_buf.append(self.allocator, .{
                .from = delivered.from,
                .to = delivered.to,
                .deliver_at_ns = delivered.deliver_at_ns,
                .data = delivered.data,
                .message_type = delivered.message_type,
            });
            self.stats.messages_delivered += 1;
        }

        return self.delivered_buf.items;
    }

    /// Create a bidirectional network partition between two nodes.
    pub fn partition(self: *SimNetwork, node_a: u8, node_b: u8) void {
        self.partition_set[node_a][node_b] = true;
        self.partition_set[node_b][node_a] = true;
    }

    /// Heal a bidirectional partition between two nodes.
    pub fn heal(self: *SimNetwork, node_a: u8, node_b: u8) void {
        self.partition_set[node_a][node_b] = false;
        self.partition_set[node_b][node_a] = false;
    }

    /// Heal all network partitions.
    pub fn healAll(self: *SimNetwork) void {
        self.partition_set = [_][256]bool{[_]bool{false} ** 256} ** 256;
    }

    /// Number of messages still pending delivery.
    pub fn pendingCount(self: *const SimNetwork) usize {
        return self.pending.count();
    }

    // ── Internal helpers ─────────────────────────────────────────────

    fn randomLatency(self: *SimNetwork) u64 {
        const min = self.config.min_latency_ms;
        const max = self.config.max_latency_ms;
        if (min >= max) return min;
        const range: u64 = max - min;
        return min + self.prng.random().intRangeAtMost(u64, 0, range);
    }

    fn randomFloat(self: *SimNetwork) f64 {
        const val = self.prng.random().int(u32);
        return @as(f64, @floatFromInt(val)) / @as(f64, @floatFromInt(std.math.maxInt(u32)));
    }
};

// ── Tests ────────────────────────────────────────────────────────────

test "SimNetwork: basic send and deliver" {
    var prng = std.Random.DefaultPrng.init(42);
    var net = SimNetwork.init(std.testing.allocator, &prng, .{
        .min_latency_ms = 10,
        .max_latency_ms = 10,
    });
    defer net.deinit();

    const sent = try net.send(0, 1, "hello", .gossip, 0);
    try std.testing.expect(sent);

    // Too early.
    const early = try net.tick(5 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(usize, 0), early.len);

    // Right on time.
    const on_time = try net.tick(10 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(usize, 1), on_time.len);
    try std.testing.expectEqualStrings("hello", on_time[0].data);
    try std.testing.expectEqual(@as(u8, 0), on_time[0].from);
    try std.testing.expectEqual(@as(u8, 1), on_time[0].to);

    // Free delivered data.
    for (on_time) |msg| std.testing.allocator.free(msg.data);
}

test "SimNetwork: partition blocks delivery" {
    var prng = std.Random.DefaultPrng.init(42);
    var net = SimNetwork.init(std.testing.allocator, &prng, .{
        .min_latency_ms = 5,
        .max_latency_ms = 5,
    });
    defer net.deinit();

    net.partition(0, 1);

    const sent = try net.send(0, 1, "blocked", .gossip, 0);
    try std.testing.expect(!sent); // Dropped by partition.
    try std.testing.expectEqual(@as(u64, 1), net.stats.messages_dropped);
}

test "SimNetwork: heal partition allows delivery" {
    var prng = std.Random.DefaultPrng.init(42);
    var net = SimNetwork.init(std.testing.allocator, &prng, .{
        .min_latency_ms = 5,
        .max_latency_ms = 5,
    });
    defer net.deinit();

    net.partition(0, 1);
    const sent1 = try net.send(0, 1, "blocked", .gossip, 0);
    try std.testing.expect(!sent1);

    net.heal(0, 1);
    const sent2 = try net.send(0, 1, "unblocked", .gossip, 100 * std.time.ns_per_ms);
    try std.testing.expect(sent2);

    const delivered = try net.tick(200 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(usize, 1), delivered.len);
    try std.testing.expectEqualStrings("unblocked", delivered[0].data);

    for (delivered) |msg| std.testing.allocator.free(msg.data);
}

test "SimNetwork: deterministic with same seed" {
    // Run the same scenario twice with the same seed.
    var results: [2][3]u64 = undefined;

    for (0..2) |run| {
        var prng = std.Random.DefaultPrng.init(99);
        var net = SimNetwork.init(std.testing.allocator, &prng, .{
            .min_latency_ms = 1,
            .max_latency_ms = 100,
        });
        defer net.deinit();

        _ = try net.send(0, 1, "msg1", .gossip, 0);
        _ = try net.send(1, 2, "msg2", .req_resp_request, 0);
        _ = try net.send(2, 0, "msg3", .gossip, 0);

        // Deliver everything.
        const delivered = try net.tick(1_000 * std.time.ns_per_ms);

        for (delivered, 0..) |msg, i| {
            if (i < 3) results[run][i] = msg.from;
            std.testing.allocator.free(msg.data);
        }
    }

    // Same seed → same delivery order.
    try std.testing.expectEqualSlices(u64, &results[0], &results[1]);
}

test "SimNetwork: packet loss drops messages" {
    var prng = std.Random.DefaultPrng.init(42);
    var net = SimNetwork.init(std.testing.allocator, &prng, .{
        .packet_loss_rate = 1.0, // 100% loss.
        .min_latency_ms = 5,
        .max_latency_ms = 5,
    });
    defer net.deinit();

    const sent = try net.send(0, 1, "dropped", .gossip, 0);
    try std.testing.expect(!sent);
    try std.testing.expectEqual(@as(u64, 1), net.stats.messages_dropped);
}

test "SimNetwork: latency is bounded" {
    var prng = std.Random.DefaultPrng.init(42);
    const min_ms: u64 = 10;
    const max_ms: u64 = 50;
    var net = SimNetwork.init(std.testing.allocator, &prng, .{
        .min_latency_ms = min_ms,
        .max_latency_ms = max_ms,
    });
    defer net.deinit();

    // Send 100 messages and verify delivery times are bounded.
    for (0..100) |i| {
        _ = try net.send(0, 1, "test", .gossip, i * 1000 * std.time.ns_per_ms);
    }

    // All should be deliverable within max_ms of their send time.
    // The last message was sent at 99_000ms, so by 99_000 + max_ms ms all should arrive.
    const delivered = try net.tick((99_000 + max_ms) * std.time.ns_per_ms);

    // Should have exactly 100 messages.
    try std.testing.expectEqual(@as(usize, 100), delivered.len);

    for (delivered) |msg| std.testing.allocator.free(msg.data);
}

test "SimNetwork: message types preserved" {
    var prng = std.Random.DefaultPrng.init(42);
    var net = SimNetwork.init(std.testing.allocator, &prng, .{
        .min_latency_ms = 1,
        .max_latency_ms = 1,
    });
    defer net.deinit();

    _ = try net.send(0, 1, "req", .req_resp_request, 0);
    _ = try net.send(1, 0, "resp", .req_resp_response, 0);
    _ = try net.send(0, 2, "gossip", .gossip, 0);

    const delivered = try net.tick(10 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(usize, 3), delivered.len);

    // Verify types (order is deterministic with fixed latency and sequence numbers).
    try std.testing.expectEqual(MessageType.req_resp_request, delivered[0].message_type);
    try std.testing.expectEqual(MessageType.req_resp_response, delivered[1].message_type);
    try std.testing.expectEqual(MessageType.gossip, delivered[2].message_type);

    for (delivered) |msg| std.testing.allocator.free(msg.data);
}
