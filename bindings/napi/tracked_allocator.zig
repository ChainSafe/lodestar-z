const std = @import("std");
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;
const TrackedAllocator = @This();

backing: Allocator,
bytes_in_use: usize = 0,

pub fn allocator(self: *TrackedAllocator) Allocator {
    return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
}

fn alloc(ctx: *anyopaque, len: usize, alignment: Alignment, return_address: usize) ?[*]u8 {
    const self: *TrackedAllocator = @ptrCast(@alignCast(ctx));
    const result = self.backing.rawAlloc(len, alignment, return_address) orelse return null;
    self.bytes_in_use += len;
    return result;
}

fn resize(ctx: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, return_address: usize) bool {
    const self: *TrackedAllocator = @ptrCast(@alignCast(ctx));
    if (!self.backing.rawResize(memory, alignment, new_len, return_address)) return false;
    self.bytes_in_use = self.bytes_in_use - memory.len + new_len;
    return true;
}

fn remap(ctx: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, return_address: usize) ?[*]u8 {
    const self: *TrackedAllocator = @ptrCast(@alignCast(ctx));
    const result = self.backing.rawRemap(memory, alignment, new_len, return_address) orelse return null;
    self.bytes_in_use = self.bytes_in_use - memory.len + new_len;
    return result;
}

fn free(ctx: *anyopaque, memory: []u8, alignment: Alignment, return_address: usize) void {
    const self: *TrackedAllocator = @ptrCast(@alignCast(ctx));
    self.backing.rawFree(memory, alignment, return_address);
    self.bytes_in_use -= memory.len;
}

test {
    _ = @import("tracked_allocator_test.zig");
}
