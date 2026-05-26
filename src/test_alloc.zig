//! Test-only allocators shared across module test suites.
const std = @import("std");

/// Wraps std.testing.FailingAllocator for OOM injection (fails the Nth alloc; resize_fail_index = 0
/// forces all growth through alloc) and adds double-free detection: freeing a non-live address sets
/// a flag instead of forwarding to the GPA (which would panic). Liveness is by raw address, so it is
/// a narrow oracle — adequate for sweeping OOM points in a loop without aborting on the first free.
pub const OomDoubleFree = struct {
    failing: std.testing.FailingAllocator,
    live: std.AutoHashMap(usize, void),
    double_free: bool = false,

    pub fn init(backing: std.mem.Allocator, fail_after: usize) OomDoubleFree {
        return .{
            .failing = std.testing.FailingAllocator.init(backing, .{ .fail_index = fail_after, .resize_fail_index = 0 }),
            .live = std.AutoHashMap(usize, void).init(std.heap.page_allocator),
        };
    }
    pub fn deinit(self: *OomDoubleFree) void {
        self.live.deinit();
    }
    pub fn allocator(self: *OomDoubleFree) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = allocFn, .resize = resizeFn, .remap = remapFn, .free = freeFn } };
    }
    fn allocFn(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *OomDoubleFree = @ptrCast(@alignCast(ctx));
        const p = self.failing.allocator().rawAlloc(len, a, ra) orelse return null;
        self.live.put(@intFromPtr(p), {}) catch {};
        return p;
    }
    fn resizeFn(ctx: *anyopaque, memory: []u8, a: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const self: *OomDoubleFree = @ptrCast(@alignCast(ctx));
        return self.failing.allocator().rawResize(memory, a, new_len, ra);
    }
    fn remapFn(ctx: *anyopaque, memory: []u8, a: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const self: *OomDoubleFree = @ptrCast(@alignCast(ctx));
        return self.failing.allocator().rawRemap(memory, a, new_len, ra);
    }
    fn freeFn(ctx: *anyopaque, memory: []u8, a: std.mem.Alignment, ra: usize) void {
        const self: *OomDoubleFree = @ptrCast(@alignCast(ctx));
        if (self.live.remove(@intFromPtr(memory.ptr))) {
            self.failing.allocator().rawFree(memory, a, ra);
        } else {
            self.double_free = true; // freeing memory that is not currently live
        }
    }
};
