const std = @import("std");

/// Counts requested bytes through the caller allocator, including dependency-owned tables.
/// Keep this owner stationary until every allocation has been returned.
pub const Reservations = struct {
    backing: std.mem.Allocator,
    bytes: usize = 0,
    byte_limit: ?usize = null,
    allocation_calls: usize = 0,

    pub fn allocator(self: *Reservations) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = allocate,
            .resize = resize,
            .remap = remap,
            .free = free,
        } };
    }
    fn allocate(context: *anyopaque, len: usize, alignment: std.mem.Alignment, ret: usize) ?[*]u8 {
        const self: *Reservations = @ptrCast(@alignCast(context));
        const total = std.math.add(usize, self.bytes, len) catch return null;
        if (self.byte_limit) |limit| if (total > limit) return null;
        const result = self.backing.rawAlloc(len, alignment, ret) orelse return null;
        self.bytes = total;
        self.allocation_calls += 1;
        return result;
    }
    fn resize(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, len: usize, ret: usize) bool {
        const self: *Reservations = @ptrCast(@alignCast(context));
        std.debug.assert(self.bytes >= memory.len);
        const total = std.math.add(usize, self.bytes - memory.len, len) catch return false;
        if (self.byte_limit) |limit| if (total > limit) return false;
        if (!self.backing.rawResize(memory, alignment, len, ret)) return false;
        self.bytes = total;
        return true;
    }
    fn remap(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, len: usize, ret: usize) ?[*]u8 {
        const self: *Reservations = @ptrCast(@alignCast(context));
        std.debug.assert(self.bytes >= memory.len);
        const total = std.math.add(usize, self.bytes - memory.len, len) catch return null;
        if (self.byte_limit) |limit| if (total > limit) return null;
        const result = self.backing.rawRemap(memory, alignment, len, ret) orelse return null;
        self.bytes = total;
        return result;
    }
    fn free(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret: usize) void {
        const self: *Reservations = @ptrCast(@alignCast(context));
        std.debug.assert(self.bytes >= memory.len);
        self.backing.rawFree(memory, alignment, ret);
        self.bytes -= memory.len;
    }
};

test "reservation byte limit rejects growth without losing ownership" {
    var ledger: Reservations = .{ .backing = std.testing.allocator, .byte_limit = 16 };
    const a = ledger.allocator();
    const bytes = try a.alloc(u8, 16);
    try std.testing.expectError(error.OutOfMemory, a.alloc(u8, 1));
    try std.testing.expect(!a.resize(bytes, 17));
    try std.testing.expect(a.remap(bytes, 17) == null);
    try std.testing.expectEqual(@as(usize, 16), ledger.bytes);
    a.free(bytes);
    try std.testing.expectEqual(@as(usize, 0), ledger.bytes);
}
