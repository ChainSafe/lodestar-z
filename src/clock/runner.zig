const std = @import("std");
const xev = @import("xev");
const Clock = @import("./clock.zig").Clock;
const Slot = @import("consensus_types").primitive.Slot.Type;
const Epoch = @import("consensus_types").primitive.Epoch.Type;

pub const ClockCallbacks = struct {
    onSlot: ?*const fn (slot: Slot, ctx: ?*anyopaque) void = null,
    onEpoch: ?*const fn (epoch: Epoch, ctx: ?*anyopaque) void = null,
    ctx: ?*anyopaque = null,
};

pub const ClockRunner = struct {
    clock: *Clock,
    callbacks: ClockCallbacks,
    loop: xev.Loop,
    timer: xev.Timer,
    completion: xev.Completion = undefined,
    allocator: std.mem.Allocator,
    running: std.atomic.Value(bool),

    pub fn init(allocator: std.mem.Allocator, clock: *Clock, callbacks: ClockCallbacks) !*ClockRunner {
        const self = try allocator.create(ClockRunner);
        errdefer allocator.destroy(self);

        self.* = .{
            .clock = clock,
            .callbacks = callbacks,
            .loop = try xev.Loop.init(.{}),
            .timer = try xev.Timer.init(),
            .allocator = allocator,
            .running = std.atomic.Value(bool).init(false),
        };

        return self;
    }

    pub fn deinit(self: *ClockRunner) void {
        if (self.running.load(.acquire)) {
            self.stop();
        }
        self.timer.deinit();
        self.loop.deinit();
        self.allocator.destroy(self);
    }

    pub fn start(self: *ClockRunner) !void {
        if (self.running.load(.acquire)) return error.AlreadyRunning;

        self.running.store(true, .release);

        const ms_until_next = self.clock.msUntilNextSlot();
        self.timer.run(&self.loop, &self.completion, ms_until_next, ClockRunner, self, timerCallback);

        // this runs until there's no completion.
        try self.loop.run(.until_done);
    }

    pub fn stop(self: *ClockRunner) void {
        self.running.store(false, .release);
        self.loop.stop();
    }

    pub fn isRunning(self: *ClockRunner) bool {
        return self.running.load(.acquire);
    }

    fn timerCallback(
        self: ?*ClockRunner,
        loop: *xev.Loop,
        comp: *xev.Completion,
        result: xev.Timer.RunError!void,
    ) xev.CallbackAction {
        _ = result catch unreachable;

        const runner = self orelse return .disarm;
        if (!runner.running.load(.acquire)) return .disarm;

        runner.clock.onNextSlot(&runner.callbacks) catch |err| {
            std.log.err("Clock onNextSlot error: {}", .{err});
            return .disarm;
        };

        const ms_until_next = runner.clock.msUntilNextSlot();
        runner.timer.run(loop, comp, ms_until_next, ClockRunner, runner, timerCallback);

        return .disarm;
    }
};
