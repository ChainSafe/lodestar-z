const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const Config = struct {
    address: []const u8,
    port: u16,
};

pub fn Runtime(comptime ServerType: type, comptime MetricsType: type, comptime runtime_label: []const u8) type {
    return struct {
        const Self = @This();
        const Task = std.Io.Future(anyerror!void);

        io: Io,
        server: ServerType,
        task: ?Task = null,

        pub fn init(
            io: Io,
            allocator: Allocator,
            metrics: *MetricsType,
            config: Config,
        ) Self {
            return .{
                .io = io,
                .server = ServerType.init(
                    allocator,
                    metrics,
                    config.address,
                    config.port,
                ),
            };
        }

        pub fn start(self: *Self) !void {
            std.debug.assert(self.task == null);
            self.task = try self.io.concurrent(runServer, .{self});
            errdefer {
                if (self.task) |*task| {
                    _ = task.await(self.io) catch {};
                    self.task = null;
                }
            }

            try self.server.waitReady(self.io);
            switch (self.server.startupStatus()) {
                .started => {},
                .failed => return error.MetricsServerStartFailed,
                .idle => unreachable,
            }
        }

        pub fn stop(self: *Self) void {
            self.server.shutdown(self.io);
            if (self.task) |*task| {
                _ = task.cancel(self.io) catch |err| switch (err) {
                    error.Canceled => {},
                    else => std.log.warn("{s} metrics task exited during shutdown: {s}", .{ runtime_label, @errorName(err) }),
                };
                self.task = null;
            }
        }

        fn runServer(self: *Self) anyerror!void {
            try self.server.serve(self.io);
        }
    };
}
