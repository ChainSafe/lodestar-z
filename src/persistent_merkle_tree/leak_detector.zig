const std = @import("std");

const log = std.log.scoped(.leak_detector);

/// Leak detection levels:
/// - disabled: No leak detection, zero overhead (for production)
/// - simple: Samples ~1% of allocations, only records allocation location
/// - advanced: Samples ~1% of allocations, records full ref/unref history
/// - paranoid: Tracks 100% of allocations with full ref/unref history (for testing)
pub const Level = enum { disabled, simple, advanced, paranoid };

/// Default sampling interval (1 in N allocations will be tracked)
/// 128 by default for simple/advanced modes
pub const default_sampling_interval: u32 = 128;

pub const NodeId = u32;

pub const EventType = enum {
    alloc,
    ref,
    unref,
};

pub const Event = struct {
    event_type: EventType,
    src: std.builtin.SourceLocation,
    refcount: u32,
};

pub const TrackRecord = struct {
    node_id: NodeId,
    alloc_src: std.builtin.SourceLocation,
    events: std.ArrayListUnmanaged(Event),
    freed: bool,
};

allocator: std.mem.Allocator,
level: Level,
records: std.AutoHashMapUnmanaged(NodeId, TrackRecord),
/// Counter for sampling - only track every Nth allocation
sampling_counter: u32,
/// Sampling interval (1 means track all, 128 means track 1 in 128)
sampling_interval: u32,

const Self = @This();

pub const Options = struct {
    level: Level = .paranoid,
    sampling_interval: u32 = default_sampling_interval,
};

pub fn init(allocator: std.mem.Allocator, options: Options) Self {
    const actual_interval: u32 = switch (options.level) {
        .disabled => 0,
        .simple, .advanced => options.sampling_interval,
        .paranoid => 1, // Track everything in paranoid mode
    };
    return Self{
        .allocator = allocator,
        .level = options.level,
        .records = .{},
        .sampling_counter = 0,
        .sampling_interval = actual_interval,
    };
}

pub fn deinit(self: *Self) void {
    var it = self.records.valueIterator();
    while (it.next()) |rec| {
        rec.events.deinit(self.allocator);
    }
    self.records.deinit(self.allocator);
}

/// Check if this allocation should be sampled
fn shouldSample(self: *Self) bool {
    if (self.sampling_interval == 0) return false;

    self.sampling_counter += 1;
    if (self.sampling_counter >= self.sampling_interval) {
        self.sampling_counter = 0;
        return true;
    }
    return false;
}

pub fn track(self: *Self, node_id: NodeId, src: std.builtin.SourceLocation, refcount: u32) void {
    const sampled = self.shouldSample();

    // Always clear stale record when node is reused, even if not sampled
    // This prevents old freed=true from masking leaks in the new lifetime
    if (self.records.fetchRemove(node_id)) |old_kv| {
        var old_rec = old_kv.value;
        old_rec.events.deinit(self.allocator);
    }

    if (!sampled) return;

    var new_rec = TrackRecord{
        .node_id = node_id,
        .alloc_src = src,
        .events = .{},
        .freed = false,
    };

    new_rec.events.append(self.allocator, Event{ .event_type = .alloc, .src = src, .refcount = refcount }) catch |err| {
        log.err("failed to append alloc event for node {d}: {}", .{ node_id, err });
        return;
    };

    self.records.put(self.allocator, node_id, new_rec) catch |err| {
        new_rec.events.deinit(self.allocator);
        log.err("failed to track node {d}: {}", .{ node_id, err });
        return;
    };
}

pub fn record(self: *Self, node_id: NodeId, event_type: EventType, src: std.builtin.SourceLocation, refcount: u32) void {
    if (self.level == .disabled) return;
    if (self.records.getPtr(node_id)) |rec| {
        rec.events.append(self.allocator, Event{ .event_type = event_type, .src = src, .refcount = refcount }) catch |err| {
            log.err("failed to append {s} event for node {d}: {}", .{ @tagName(event_type), node_id, err });
        };
    }
}

pub fn close(self: *Self, node_id: NodeId) void {
    // Mark the node as properly closed (freed with refcount reaching 0)
    // Don't remove the record so we can detect "unref after free"
    if (self.records.getPtr(node_id)) |rec| {
        rec.freed = true;
    }
}

/// Called when unref is attempted on an already-freed node
/// This is called from Node.unref when it detects isFree() is true
pub fn recordUnrefAfterFree(self: *Self, node_id: NodeId, src: std.builtin.SourceLocation) void {
    if (self.level == .disabled) return;
    if (self.records.getPtr(node_id)) |rec| {
        std.debug.print("\nUNREF AFTER FREE DETECTED: node_id={d}\n  Allocated at {s}:{d} in {s}\n", .{
            rec.node_id, rec.alloc_src.file, rec.alloc_src.line, rec.alloc_src.fn_name,
        });
        std.debug.print("  Unref attempted at {s}:{d} in {s}\n", .{ src.file, src.line, src.fn_name });
        std.debug.print("  Event history:\n", .{});
        for (rec.events.items) |ev| {
            std.debug.print("    {s} at {s}:{d} in {s} (refcount={d})\n", .{
                @tagName(ev.event_type), ev.src.file, ev.src.line, ev.src.fn_name, ev.refcount,
            });
        }
        @panic("Unref after free detected in persistent merkle tree");
    }
}

pub fn reportLeaks(self: *Self) void {
    var it = self.records.valueIterator();
    var found = false;
    while (it.next()) |rec| {
        if (!rec.freed) {
            found = true;
            std.debug.print("\nLEAK DETECTED: node_id={d}\n  Allocated at {s}:{d} in {s}\n", .{
                rec.node_id, rec.alloc_src.file, rec.alloc_src.line, rec.alloc_src.fn_name,
            });
            for (rec.events.items) |ev| {
                std.debug.print("    {s} at {s}:{d} in {s} (refcount={d})\n", .{
                    @tagName(ev.event_type), ev.src.file, ev.src.line, ev.src.fn_name, ev.refcount,
                });
            }
        }
    }
    if (found) {
        @panic("Memory leaks detected in persistent merkle tree");
    }
}
