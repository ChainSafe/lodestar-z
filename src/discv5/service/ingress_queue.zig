const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Address = Io.net.IpAddress;

const protocol_mod = @import("../protocol.zig");
const rate_limit = @import("../rate_limit.zig");

pub const IngressPacket = struct {
    from: Address,
    len: usize,
    data: [protocol_mod.MAX_PACKET_SIZE]u8,
};

pub const IngressStatsSnapshot = struct {
    received_total: u64 = 0,
    filtered_total: u64 = 0,
    dropped_queue_full_total: u64 = 0,
    processed_total: u64 = 0,
    budget_exhausted_total: u64 = 0,
    queue_depth: usize = 0,
    max_queue_depth: usize = 0,
    rate_limit_hit_ip_total: u64 = 0,
    rate_limit_hit_total: u64 = 0,
};

pub const IngressQueue = struct {
    allocator: Allocator,
    packets: []IngressPacket,
    head: usize = 0,
    len: usize = 0,
    rate_limiter: ?rate_limit.RateLimiter = null,
    mutex: std.atomic.Mutex = .unlocked,
    stats: IngressStatsSnapshot = .{},

    fn acquire(self: *IngressQueue) void {
        while (!self.mutex.tryLock()) {
            std.atomic.spinLoopHint();
        }
    }

    pub fn init(allocator: Allocator, capacity: usize, rate_limiter_config: ?rate_limit.Config) !IngressQueue {
        if (capacity == 0) return error.InvalidQueueCapacity;
        const packets = try allocator.alloc(IngressPacket, capacity);
        errdefer allocator.free(packets);
        return .{
            .allocator = allocator,
            .packets = packets,
            .rate_limiter = if (rate_limiter_config) |cfg| try rate_limit.RateLimiter.init(allocator, cfg) else null,
        };
    }

    pub fn deinit(self: *IngressQueue) void {
        if (self.rate_limiter) |*limiter| limiter.deinit();
        self.allocator.free(self.packets);
    }

    pub fn snapshot(self: *IngressQueue) IngressStatsSnapshot {
        self.acquire();
        defer self.mutex.unlock();
        return self.stats;
    }

    pub fn queuedLen(self: *IngressQueue) usize {
        self.acquire();
        defer self.mutex.unlock();
        return self.len;
    }

    pub fn enqueueReceived(self: *IngressQueue, from: Address, data: []const u8, now_ms: u64) bool {
        self.acquire();
        defer self.mutex.unlock();

        return self.acceptReceivedUnlocked(from, now_ms) and self.enqueueUnlocked(from, data);
    }

    pub fn acceptReceived(self: *IngressQueue, from: Address, now_ms: u64) bool {
        self.acquire();
        defer self.mutex.unlock();
        return self.acceptReceivedUnlocked(from, now_ms);
    }

    fn acceptReceivedUnlocked(self: *IngressQueue, from: Address, now_ms: u64) bool {
        self.stats.received_total += 1;
        if (self.rate_limiter) |*limiter| {
            if (!limiter.allowEncodedPacket(from, now_ms)) {
                self.stats.filtered_total += 1;
                const rate_stats = limiter.statsSnapshot();
                self.stats.rate_limit_hit_ip_total = rate_stats.rate_limit_hit_ip_total;
                self.stats.rate_limit_hit_total = rate_stats.rate_limit_hit_total;
                return false;
            }
        }
        return true;
    }

    pub fn addExpectedResponse(self: *IngressQueue, addr: Address) void {
        self.acquire();
        defer self.mutex.unlock();
        if (self.rate_limiter) |*limiter| limiter.addExpectedResponse(addr) catch {};
    }

    pub fn removeExpectedResponse(self: *IngressQueue, addr: Address) void {
        self.acquire();
        defer self.mutex.unlock();
        if (self.rate_limiter) |*limiter| limiter.removeExpectedResponse(addr);
    }

    pub fn enqueueForTest(self: *IngressQueue, from: Address, data: []const u8) bool {
        self.acquire();
        defer self.mutex.unlock();
        return self.enqueueUnlocked(from, data);
    }

    fn enqueueUnlocked(self: *IngressQueue, from: Address, data: []const u8) bool {
        if (data.len > protocol_mod.MAX_PACKET_SIZE) return false;
        if (self.len >= self.packets.len) {
            self.stats.dropped_queue_full_total += 1;
            return false;
        }

        const index = (self.head + self.len) % self.packets.len;
        self.packets[index].from = from;
        self.packets[index].len = data.len;
        @memcpy(self.packets[index].data[0..data.len], data);
        self.len += 1;
        self.stats.queue_depth = self.len;
        if (self.len > self.stats.max_queue_depth) self.stats.max_queue_depth = self.len;
        return true;
    }

    pub fn pop(self: *IngressQueue) ?IngressPacket {
        self.acquire();
        defer self.mutex.unlock();
        if (self.len == 0) return null;

        const packet = self.packets[self.head];
        self.head = (self.head + 1) % self.packets.len;
        self.len -= 1;
        self.stats.queue_depth = self.len;
        return packet;
    }

    pub fn noteProcessed(self: *IngressQueue, processed: usize, budget_exhausted: bool) void {
        if (processed == 0 and !budget_exhausted) return;
        self.acquire();
        defer self.mutex.unlock();
        self.stats.processed_total += processed;
        if (budget_exhausted) self.stats.budget_exhausted_total += 1;
    }
};

test "ingress queue rejects invalid capacity and oversized packets" {
    try std.testing.expectError(error.InvalidQueueCapacity, IngressQueue.init(std.testing.allocator, 0, null));

    var queue = try IngressQueue.init(std.testing.allocator, 1, null);
    defer queue.deinit();

    const from: Address = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9000 } };
    const oversized = [_]u8{0} ** (protocol_mod.MAX_PACKET_SIZE + 1);
    try std.testing.expect(!queue.enqueueForTest(from, &oversized));
    try std.testing.expectEqual(@as(usize, 0), queue.queuedLen());
}
