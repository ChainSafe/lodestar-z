const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;

const validator_mod = @import("validator");

pub const default_address = "127.0.0.1";
pub const default_port: u16 = 5064;

pub const Config = struct {
    address: []const u8,
    port: u16,
};

pub const Runtime = struct {
    const Task = std.Io.Future(anyerror!void);

    io: Io,
    server: validator_mod.MetricsServer,
    task: ?Task = null,

    pub fn init(
        io: Io,
        allocator: Allocator,
        metrics: *validator_mod.ValidatorMetrics,
        config: Config,
    ) Runtime {
        return .{
            .io = io,
            .server = validator_mod.MetricsServer.init(
                allocator,
                metrics,
                config.address,
                config.port,
            ),
        };
    }

    pub fn start(self: *Runtime) !void {
        std.debug.assert(self.task == null);
        self.task = try self.io.concurrent(runServer, .{self});
        errdefer {
            if (self.task) |*task| {
                _ = task.await(self.io) catch {};
                self.task = null;
            }
        }

        while (true) {
            switch (self.server.startupStatus()) {
                .idle => try self.io.sleep(.{ .nanoseconds = 10 * std.time.ns_per_ms }, .real),
                .started => break,
                .failed => return error.ValidatorMetricsServerStartFailed,
            }
        }
    }

    pub fn stop(self: *Runtime) void {
        self.server.shutdown(self.io);
        if (self.task) |*task| {
            _ = task.cancel(self.io) catch |err| switch (err) {
                error.Canceled => {},
                else => std.log.warn("validator metrics task exited during shutdown: {s}", .{@errorName(err)}),
            };
            self.task = null;
        }
    }

    fn runServer(self: *Runtime) anyerror!void {
        try self.server.serve(self.io);
    }
};
