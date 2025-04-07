const std = @import("std");
const Allocator = std.mem.Allocator;

var thread_pool: ?*std.Thread.Pool = null;
var gpa = std.heap.GeneralPurposeAllocator(.{}){};

/// a zig application may want to call this with a provided allocator
/// a bun init() call should call this with null, ie, use the default allocator
pub fn initializeThreadPool(inAllocator: ?Allocator) !void {
    if (thread_pool != null) {
        return;
    }
    const allocator = inAllocator orelse gpa.allocator();
    var pool = try allocator.create(std.Thread.Pool);
    try pool.init(.{ .allocator = allocator });
    thread_pool = pool;
}

pub fn deinitializeThreadPool() void {
    if (thread_pool) |pool| {
        const allocator = pool.allocator;
        pool.deinit();
        allocator.destroy(pool);
    }
    thread_pool = null;
}

pub fn spawnTask(comptime func: anytype, args: anytype) !void {
    if (thread_pool) |pool| {
        try pool.spawn(func, args);
    } else {
        @panic("Thread pool is not initialized");
    }
}

test "thread pool with allocator" {
    const allocator = std.testing.allocator;
    try performTest(allocator);
}

test "thread pool with no allocator" {
    try performTest(null);
}

fn performTest(allocator: ?Allocator) !void {
    try initializeThreadPool(allocator);
    defer deinitializeThreadPool();
    var m = std.Thread.Mutex{};
    var c = std.Thread.Condition{};
    var total_finished: usize = 0;

    const Task = struct {
        fn run(wait_ms: usize, mutex: *std.Thread.Mutex, cond: *std.Thread.Condition, finished: *usize) void {
            mutex.lock();
            defer mutex.unlock();
            std.time.sleep(wait_ms * std.time.ns_per_ms);
            finished.* += 1;
            cond.signal();
        }
    };

    try spawnTask(Task.run, .{ 10, &m, &c, &total_finished });
    try spawnTask(Task.run, .{ 11, &m, &c, &total_finished });
    try spawnTask(Task.run, .{ 12, &m, &c, &total_finished });
    try spawnTask(Task.run, .{ 13, &m, &c, &total_finished });

    m.lock();
    defer m.unlock();
    while (total_finished < 4) {
        c.wait(&m);
    }
}
