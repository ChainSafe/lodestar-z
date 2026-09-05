const std = @import("std");
const t = @import("types.zig");
pub const Token = struct { index: u16, generation: u64 };
pub const DialIntent = struct { token: Token, peer: t.PeerId, address: t.Address };
pub const Options = struct {
    capacity: u16 = 256,
    concurrent_max: u16 = 4,
    engine_dialing_max: u16 = 16,
    seed: u64,
};
const Row = struct {
    occupied: bool = false,
    generation: u64 = 0,
    peer: t.PeerId = undefined,
    addresses: [2]t.Address = undefined,
    address_count: u8 = 0,
    address_index: u8 = 0,
    direct: bool = false,
    connected: bool = false,
    attempt: bool = false,
    conn: ?t.Handle = null,
    deadline_ms: u64 = 0,
    failures: u8 = 0,
};
pub const DialQueue = struct {
    rows: []Row,
    options: Options,
    cursor: usize = 0,
    random: std.Random.DefaultPrng,

    pub fn init(a: std.mem.Allocator, options: Options) !DialQueue {
        if (options.capacity == 0 or options.capacity > 4096 or options.concurrent_max == 0 or
            options.concurrent_max > 4 or options.concurrent_max > options.engine_dialing_max or
            options.concurrent_max > options.capacity) return error.InvalidOptions;
        const rows = try a.alloc(Row, options.capacity);
        @memset(rows, .{});
        return .{ .rows = rows, .options = options, .random = .init(options.seed) };
    }
    pub fn deinit(self: *DialQueue, a: std.mem.Allocator) void {
        a.free(self.rows);
        self.* = undefined;
    }
    pub fn memoryPlan(self: *const DialQueue) struct {
        inline_bytes: usize,
        allocated_bytes: usize,
    } {
        return .{
            .inline_bytes = @sizeOf(DialQueue),
            .allocated_bytes = self.rows.len * @sizeOf(Row),
        };
    }
    pub fn enqueue(
        self: *DialQueue,
        peer: *const t.PeerId,
        addresses: []const t.Address,
        direct: bool,
        now_ms: u64,
    ) !void {
        if (addresses.len == 0 or addresses.len > 2) return error.InvalidAddress;
        for (addresses) |address| if (address.port() == 0) return error.InvalidAddress;
        var free: ?*Row = null;
        for (self.rows) |*row| {
            if (row.occupied and row.peer.eql(peer)) {
                for (addresses) |address| {
                    var found = false;
                    for (row.addresses[0..row.address_count]) |known| {
                        found = found or known.eql(address);
                    }
                    if (!found and row.address_count < 2) {
                        row.addresses[row.address_count] = address;
                        row.address_count += 1;
                    }
                }
                row.direct = row.direct or direct;
                return;
            }
            if (!row.occupied and row.generation < std.math.maxInt(u64) and free == null) {
                free = row;
            }
        }
        const row = free orelse return error.Capacity;
        row.* = .{
            .occupied = true,
            .generation = row.generation,
            .peer = peer.*,
            .direct = direct,
            .deadline_ms = now_ms,
            .address_count = @intCast(addresses.len),
        };
        @memcpy(row.addresses[0..addresses.len], addresses);
    }
    pub fn isDirect(self: *const DialQueue, peer: *const t.PeerId) bool {
        for (self.rows) |row| if (row.occupied and row.peer.eql(peer)) return row.direct;
        return false;
    }
    pub fn removeDirect(self: *DialQueue, peer: *const t.PeerId) void {
        for (self.rows) |*row| if (row.occupied and row.peer.eql(peer)) {
            row.direct = false;
        };
    }
    pub fn remove(self: *DialQueue, peer: *const t.PeerId) bool {
        for (self.rows) |*row| if (row.occupied and row.peer.eql(peer)) {
            if (row.attempt) return false;
            row.occupied = false;
            return true;
        };
        return false;
    }
    pub fn connection(self: *DialQueue, peer: *const t.PeerId, connected: bool, now_ms: u64) void {
        for (self.rows) |*row| if (row.occupied and row.peer.eql(peer)) {
            if (row.conn != null) return;
            row.attempt = false;
            row.conn = null;
            row.connected = connected;
            row.deadline_ms = now_ms +| 1_000;
            if (connected) row.failures = 0;
        };
    }
    pub fn accepted(
        self: *DialQueue,
        peer: *const t.PeerId,
        conn: t.Handle,
        now_ms: u64,
    ) void {
        for (self.rows) |*row| {
            if (!row.occupied or !row.peer.eql(peer)) continue;
            if (row.conn) |attempt| {
                if (!std.meta.eql(attempt, conn)) {
                    row.connected = true;
                    return;
                }
            }
            row.conn = null;
            self.connection(peer, true, now_ms);
            return;
        }
    }

    /// The caller supplies an observed canonical transport close, including its full generation.
    pub fn dialClosed(self: *DialQueue, conn: t.Handle, now_ms: u64) bool {
        for (self.rows) |*row| {
            if (!row.occupied or !row.attempt or !std.meta.eql(row.conn, conn)) continue;
            self.failed(row, now_ms);
            return true;
        }
        return false;
    }

    fn closeAttempt(engine: *@import("../quic/engine.zig").Engine, conn: t.Handle) void {
        if (engine.peerId(conn) != null) {
            _ = engine.close(conn, 0);
        } else {
            _ = engine.abandon(conn);
        }
    }

    pub fn syncConnection(
        self: *DialQueue,
        peer: *const t.PeerId,
        connected: bool,
        now_ms: u64,
    ) void {
        for (self.rows) |row| {
            if (!row.occupied or !row.peer.eql(peer)) continue;
            if (row.connected != connected) self.connection(peer, connected, now_ms);
            return;
        }
    }
    pub fn deferPeer(self: *DialQueue, peer: *const t.PeerId, deadline_ms: u64) void {
        for (self.rows) |*row| if (row.occupied and row.peer.eql(peer)) {
            row.deadline_ms = @max(row.deadline_ms, deadline_ms);
        };
    }
    fn rowFor(self: *DialQueue, token: Token) ?*Row {
        if (token.index >= self.rows.len) return null;
        const row = &self.rows[token.index];
        if (!row.occupied or !row.attempt or row.generation != token.generation) return null;
        return row;
    }
    pub fn dialStarted(self: *DialQueue, token: Token, conn: t.Handle) bool {
        const row = self.rowFor(token) orelse return false;
        if (row.conn != null) return false;
        row.conn = conn;
        return true;
    }
    /// Reports failure before dialStarted. Started owners retire through dialClosed or expire.
    pub fn dialFailed(self: *DialQueue, token: Token, now_ms: u64) bool {
        const row = self.rowFor(token) orelse return false;
        if (row.conn != null) return false;
        self.failed(row, now_ms);
        return true;
    }
    fn failed(self: *DialQueue, row: *Row, now_ms: u64) void {
        row.attempt = false;
        row.conn = null;
        row.failures = @min(row.failures +| 1, 7);
        const base: u64 = @min(@as(u64, 1_000) << @intCast(row.failures - 1), 60_000);
        const jitter = self.random.random().int(u16) % 1_001;
        row.deadline_ms = now_ms +| @min(base + jitter, 60_000);
        row.address_index = (row.address_index + 1) % row.address_count;
    }
    pub fn expire(
        self: *DialQueue,
        engine: ?*@import("../quic/engine.zig").Engine,
        now_ms: u64,
    ) void {
        for (self.rows) |*row| if (row.occupied and row.attempt and now_ms >= row.deadline_ms) {
            if (row.conn) |conn| {
                const owner = engine orelse continue;
                closeAttempt(owner, conn);
            }
            self.failed(row, now_ms);
        };
    }
    /// Started expiry requires expire(engine, now); polling alone preserves the native owner.
    pub fn poll(self: *DialQueue, now_ms: u64, out: []DialIntent) usize {
        self.expire(null, now_ms);
        var active: usize = 0;
        for (self.rows) |row| if (row.occupied and row.attempt) {
            active += 1;
        };
        var count: usize = 0;
        for (0..self.rows.len) |_| {
            if (count == out.len or active >= self.options.concurrent_max) break;
            const index = self.cursor;
            self.cursor = (index + 1) % self.rows.len;
            const row = &self.rows[index];
            if (!row.occupied or row.connected or row.attempt or now_ms < row.deadline_ms or
                row.generation == std.math.maxInt(u64)) continue;
            row.generation += 1;
            row.attempt = true;
            row.deadline_ms = now_ms +| 10_000;
            out[count] = .{
                .token = .{ .index = @intCast(index), .generation = row.generation },
                .peer = row.peer,
                .address = row.addresses[row.address_index],
            };
            count += 1;
            active += 1;
        }
        return count;
    }
    pub fn nextWakeup(self: *const DialQueue, now_ms: u64, output_capacity: usize) ?u64 {
        var active: usize = 0;
        for (self.rows) |row| if (row.occupied and row.attempt) {
            active += 1;
        };
        var due: ?u64 = null;
        for (self.rows) |row| {
            if (!row.occupied or (row.connected and !row.attempt)) continue;
            if (!row.attempt and (output_capacity == 0 or active >= self.options.concurrent_max or
                row.generation == std.math.maxInt(u64))) continue;
            const next = @max(now_ms, row.deadline_ms);
            due = @min(due orelse next, next);
        }
        return due;
    }
    pub fn shutdown(self: *DialQueue, engine: *@import("../quic/engine.zig").Engine) void {
        for (self.rows) |*row| {
            if (row.attempt) if (row.conn) |conn| {
                closeAttempt(engine, conn);
            };
            row.occupied = false;
            row.attempt = false;
        }
    }
};
