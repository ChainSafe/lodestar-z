const std = @import("std");
const n = @import("network");
const r = @import("network_runtime.zig");

pub const Export = struct {
    buffers: [2][]u8 = .{ &.{}, &.{} },
    lengths: [2]usize = .{ 0, 0 },
    published: u1 = 0,
    failure: ?n.metrics.registry.Error = null,

    pub fn init(capacity: usize) !Export {
        const first = try r.allocator.alloc(u8, capacity);
        errdefer r.allocator.free(first);
        const second = try r.allocator.alloc(u8, capacity);
        return .{ .buffers = .{ first, second } };
    }

    pub fn deinit(self: *Export) void {
        for (self.buffers) |buffer| r.allocator.free(buffer);
        self.* = .{};
    }

    pub fn allocatedBytes(self: *const Export) usize {
        return self.buffers[0].len + self.buffers[1].len;
    }

    /// The owner renders into the unpublished buffer. Publication and readers hold the runtime mutex.
    pub fn render(self: *Export, context: *const n.metrics.Context) n.metrics.registry.Error!u1 {
        const index = 1 - self.published;
        var writer = std.Io.Writer.fixed(self.buffers[index]);
        try n.metrics.write(context, &writer);
        self.lengths[index] = writer.buffered().len;
        return index;
    }

    pub fn finish(self: *Export) void {
        const index = 1 - self.published;
        r.allocator.free(self.buffers[index]);
        self.buffers[index] = &.{};
        self.lengths[index] = 0;
    }

    /// The caller holds the runtime mutex. Log delivery continues after the network owner stops.
    pub fn text(self: *Export, logs: *const n.logging.Stats) n.metrics.registry.Error![]const u8 {
        if (self.failure) |err| return err;
        var writer = std.Io.Writer.fixed(self.buffers[self.published]);
        writer.end = self.lengths[self.published];
        var encoder: n.metrics.registry.Encoder = .{ .writer = &writer };
        try logs.write(&encoder);
        return writer.buffered();
    }
};
