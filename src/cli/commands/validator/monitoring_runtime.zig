const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;

const validator_mod = @import("validator");

pub const Runtime = struct {
    const Task = std.Io.Future(anyerror!void);

    io: Io,
    service: validator_mod.MonitoringService,
    task: ?Task = null,

    pub fn init(
        io: Io,
        allocator: Allocator,
        client: *validator_mod.ValidatorClient,
        metrics: *validator_mod.ValidatorMetrics,
        options: validator_mod.MonitoringOptions,
        client_version: []const u8,
    ) !Runtime {
        return .{
            .io = io,
            .service = try validator_mod.MonitoringService.init(
                allocator,
                io,
                client,
                metrics,
                options,
                client_version,
            ),
        };
    }

    pub fn start(self: *Runtime) !void {
        std.debug.assert(self.task == null);
        self.task = try self.io.concurrent(runService, .{self});
    }

    pub fn stop(self: *Runtime) void {
        self.service.requestShutdown();
        if (self.task) |*task| {
            _ = task.cancel(self.io) catch |err| switch (err) {
                error.Canceled => {},
                else => std.log.warn("validator monitoring task exited during shutdown: {s}", .{@errorName(err)}),
            };
            self.task = null;
        }
        self.service.deinit();
    }

    fn runService(self: *Runtime) anyerror!void {
        try self.service.run();
    }
};
