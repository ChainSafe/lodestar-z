const std = @import("std");
const topic = @import("topic.zig");
const protobuf = @import("protobuf.zig");
const constants = @import("constants.zig");
const assert = std.debug.assert;

pub const page_bytes: usize = 4096;
comptime {
    assert(topic.topic_max_len < 128);
}
pub const none: u32 = std.math.maxInt(u32);
pub const Handle = struct { index: u32, generation: u64 };
pub const Cursor = struct { page: u32, offset: u32 = 0, remaining: u32 };
pub const Entry = struct {
    generation: u64 = 0,
    active: bool = false,
    provisional: bool = false,
    validation: bool = false,
    history: bool = false,
    tx: u32 = 0,
    first: u32 = none,
    len: u32 = 0,
    id: topic.MessageId = undefined,
    prefix: [32]u8 = undefined,
    prefix_len: u8 = 0,
    trailer: [topic.topic_max_len + 2]u8 = undefined,
    topic_len: u8 = 0,

    pub fn topicString(self: *const Entry) []const u8 {
        return self.trailer[2..][0..self.topic_len];
    }
};

pub fn encodePrefix(prefix: []u8, trailer: []u8, len: usize, name: []const u8) struct { prefix: usize, trailer: usize } {
    assert(len <= constants.maxCompressedLen(constants.MAX_PAYLOAD_SIZE));
    assert(name.len <= topic.topic_max_len);
    var tail = protobuf.Writer.init(trailer);
    tail.bytesField(4, name);
    const message_len = 1 + protobuf.varintLen(len) + len + tail.len;
    const rpc_len = 1 + protobuf.varintLen(message_len) + message_len;
    assert(rpc_len <= constants.GOSSIP_MAX_SIZE);
    var head = protobuf.Writer.init(prefix);
    head.varint(rpc_len);
    head.tag(2, protobuf.wire_len);
    head.varint(message_len);
    head.tag(2, protobuf.wire_len);
    head.varint(len);
    return .{ .prefix = head.len, .trailer = tail.len };
}

pub const Store = struct {
    bytes: []u8,
    next: []u32,
    entries: []Entry,
    free_page: u32,
    free_pages: usize,
    used_entries: usize = 0,
    retired_entries: usize = 0,
    entry_cursor: usize = 0,
    released: bool = false,

    pub fn init(a: std.mem.Allocator, capacity: usize, byte_capacity: usize) !Store {
        if (capacity == 0 or capacity >= none or byte_capacity < page_bytes or byte_capacity / page_bytes >= none)
            return error.InvalidLimits;
        const pages = byte_capacity / page_bytes;
        const bytes = try a.alloc(u8, pages * page_bytes);
        errdefer a.free(bytes);
        const next = try a.alloc(u32, pages);
        errdefer a.free(next);
        const entries = try a.alloc(Entry, capacity);
        errdefer a.free(entries);
        @memset(entries, .{});
        for (next, 0..) |*n, i| n.* = if (i + 1 == pages) none else @intCast(i + 1);
        return .{ .bytes = bytes, .next = next, .entries = entries, .free_page = 0, .free_pages = pages };
    }

    pub fn deinit(self: *Store, a: std.mem.Allocator) void {
        a.free(self.entries);
        a.free(self.next);
        a.free(self.bytes);
        self.* = undefined;
    }

    pub fn get(self: *const Store, handle: Handle) ?*const Entry {
        if (handle.index >= self.entries.len) return null;
        const entry = &self.entries[handle.index];
        if (!entry.active or entry.generation != handle.generation) return null;
        return entry;
    }

    pub fn canReserve(self: *const Store, len: usize) bool {
        return self.used_entries + self.retired_entries < self.entries.len and pagesFor(len) <= self.free_pages;
    }

    pub fn pagesFor(len: usize) usize {
        assert(len <= constants.maxCompressedLen(constants.MAX_PAYLOAD_SIZE));
        return (len + page_bytes - 1) / page_bytes;
    }

    pub fn put(self: *Store, id: topic.MessageId, name: []const u8, data: []const u8) ?Handle {
        assert(name.len <= topic.topic_max_len);
        if (!self.canReserve(data.len)) return null;
        for (0..self.entries.len) |_| {
            const index = self.entry_cursor;
            self.entry_cursor = (index + 1) % self.entries.len;
            const entry = &self.entries[index];
            if (entry.active or entry.generation == std.math.maxInt(u64)) continue;
            entry.* = .{
                .generation = entry.generation + 1,
                .active = true,
                .provisional = true,
                .id = id,
                .len = @intCast(data.len),
                .topic_len = @intCast(name.len),
            };
            entry.prefix_len = @intCast(encodePrefix(&entry.prefix, &entry.trailer, data.len, name).prefix);
            var link = &entry.first;
            var offset: usize = 0;
            for (0..pagesFor(data.len)) |_| {
                const page = self.free_page;
                assert(page != none);
                self.free_page = self.next[page];
                self.free_pages -= 1;
                link.* = page;
                link = &self.next[page];
                const take = @min(page_bytes, data.len - offset);
                @memcpy(self.bytes[@as(usize, page) * page_bytes ..][0..take], data[offset..][0..take]);
                offset += take;
            }
            link.* = none;
            self.used_entries += 1;
            return .{ .index = @intCast(index), .generation = entry.generation };
        }
        return null;
    }

    pub fn cursor(self: *const Store, handle: Handle) Cursor {
        const entry = self.get(handle).?;
        return .{ .page = entry.first, .remaining = entry.len };
    }

    pub fn segment(self: *const Store, handle: Handle, at: Cursor) []const u8 {
        const entry = self.get(handle).?;
        assert(!entry.provisional and at.remaining <= entry.len);
        if (at.remaining == 0) return &.{};
        assert(at.page < self.next.len and at.offset < page_bytes);
        const len = @min(at.remaining, page_bytes - at.offset);
        return self.bytes[@as(usize, at.page) * page_bytes + at.offset ..][0..len];
    }

    pub fn advance(self: *const Store, at: *Cursor, len: usize) void {
        assert(len <= @min(at.remaining, page_bytes - at.offset));
        at.remaining -= @intCast(len);
        at.offset += @intCast(len);
        if (at.offset == page_bytes) {
            at.page = self.next[at.page];
            at.offset = 0;
        }
    }

    pub fn seal(self: *Store, h: Handle) void {
        const e = self.mutable(h);
        assert(e.provisional);
        e.provisional = false;
        self.collect(h);
    }
    pub fn retainValidation(self: *Store, h: Handle) void {
        const e = self.mutable(h);
        assert(!e.validation);
        e.validation = true;
    }
    pub fn releaseValidation(self: *Store, h: Handle) void {
        const e = self.mutable(h);
        assert(e.validation);
        e.validation = false;
        self.collect(h);
    }
    pub fn retainHistory(self: *Store, h: Handle) void {
        const e = self.mutable(h);
        assert(!e.history);
        e.history = true;
    }
    pub fn releaseHistory(self: *Store, h: Handle) void {
        const e = self.mutable(h);
        assert(e.history);
        e.history = false;
        self.collect(h);
    }
    pub fn retainTx(self: *Store, h: Handle) void {
        const e = self.mutable(h);
        assert(!e.provisional and e.tx < std.math.maxInt(u32));
        e.tx += 1;
    }
    pub fn releaseTx(self: *Store, h: Handle) void {
        const e = self.mutable(h);
        assert(e.tx > 0);
        e.tx -= 1;
        self.collect(h);
    }
    fn mutable(self: *Store, h: Handle) *Entry {
        assert(self.get(h) != null);
        return &self.entries[h.index];
    }
    fn collect(self: *Store, h: Handle) void {
        const e = self.mutable(h);
        if (e.provisional or e.validation or e.history or e.tx != 0) return;
        var page = e.first;
        for (0..pagesFor(e.len)) |_| {
            assert(page != none);
            const next = self.next[page];
            self.next[page] = self.free_page;
            self.free_page = page;
            self.free_pages += 1;
            page = next;
        }
        assert(page == none);
        e.active = false;
        self.released = true;
        self.used_entries -= 1;
        if (e.generation == std.math.maxInt(u64)) self.retired_entries += 1;
    }
};

test "gossip store independent retains pages and stale handles" {
    var store = try Store.init(std.testing.allocator, 1, 3 * page_bytes);
    defer store.deinit(std.testing.allocator);
    const h = store.put([_]u8{1} ** 20, "topic", &([_]u8{9} ** (page_bytes + 1))).?;
    store.retainValidation(h);
    store.retainHistory(h);
    store.seal(h);
    store.retainTx(h);
    store.releaseHistory(h);
    store.releaseValidation(h);
    try std.testing.expectEqual(@as(usize, 1), store.free_pages);
    var c = store.cursor(h);
    try std.testing.expectEqual(page_bytes, store.segment(h, c).len);
    store.advance(&c, page_bytes);
    try std.testing.expectEqualSlices(u8, &.{9}, store.segment(h, c));
    store.releaseTx(h);
    try std.testing.expectEqual(@as(usize, 3), store.free_pages);
    const replacement = store.put([_]u8{2} ** 20, "next", "x").?;
    try std.testing.expect(store.get(h) == null);
    try std.testing.expect(replacement.generation != h.generation);
    store.seal(replacement);
    try std.testing.expectEqual(@as(usize, 0), store.used_entries);
}

test "gossip store small messages use four KiB and roll back allocation failures" {
    const a = std.testing.allocator;
    var store = try Store.init(a, 2048, 2048 * page_bytes);
    defer store.deinit(a);
    for (0..2048) |i| {
        var id = [_]u8{0} ** 20;
        std.mem.writeInt(u64, id[0..8], i, .little);
        const h = store.put(id, "t", &([_]u8{1} ** 200)).?;
        store.retainValidation(h);
        store.seal(h);
    }
    try std.testing.expectEqual(@as(usize, 0), store.free_pages);
    try std.testing.expectEqual(@as(usize, 2048), store.used_entries);
    try std.testing.checkAllAllocationFailures(a, allocationProbe, .{});
}
fn allocationProbe(a: std.mem.Allocator) !void {
    var store = try Store.init(a, 8, 8 * page_bytes);
    defer store.deinit(a);
}
