const std = @import("std");
const Allocator = std.mem.Allocator;
const WaitGroup = std.Thread.WaitGroup;

threadlocal var thread_pool: ?*std.Thread.Pool = null;
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

/// Spawn a new thread with a WaitGroup so that we can wait for the whole WaitGroup to finish
pub fn spawnTaskWg(wg: *WaitGroup, comptime func: anytype, args: anytype) void {
    if (thread_pool) |pool| {
        pool.spawnWg(wg, func, args);
    } else {
        @panic("Thread pool is not initialized");
    }
}

/// Wait for all tasks that's spawned with the same WaitGroup
pub fn waitAndWork(wg: *WaitGroup) void {
    if (thread_pool) |pool| {
        pool.waitAndWork(wg);
    } else {
        @panic("Thread pool is not initialized");
    }
}

test "thread pool - spawnTask with allocator" {
    const allocator = std.testing.allocator;
    try performSpawnTaskTest(allocator);
}

test "thread pool - spawnTask with no allocator" {
    try performSpawnTaskTest(null);
}

test "thread pool - spawnTaskWg with allocator" {
    const allocator = std.testing.allocator;
    try performSpawnTaskWgTest(allocator);
}

test "thread pool - spawnTaskWg with no allocator" {
    try performSpawnTaskWgTest(null);
}

fn performSpawnTaskTest(allocator: ?Allocator) !void {
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

fn performSpawnTaskWgTest(allocator: ?Allocator) !void {
    try initializeThreadPool(allocator);
    defer deinitializeThreadPool();
    var wg = WaitGroup{};
    var m = std.Thread.Mutex{};
    var total_finished: usize = 0;

    const Task = struct {
        fn run(wait_ms: usize, mutex: *std.Thread.Mutex, finished: *usize) void {
            mutex.lock();
            defer mutex.unlock();
            std.time.sleep(wait_ms * std.time.ns_per_ms);
            finished.* += 1;
        }
    };

    spawnTaskWg(&wg, Task.run, .{ 10, &m, &total_finished });
    spawnTaskWg(&wg, Task.run, .{ 11, &m, &total_finished });
    spawnTaskWg(&wg, Task.run, .{ 12, &m, &total_finished });
    spawnTaskWg(&wg, Task.run, .{ 13, &m, &total_finished });

    waitAndWork(&wg);

    try std.testing.expectEqual(total_finished, 4);
}
