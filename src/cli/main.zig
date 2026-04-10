//! CLI parse-and-dispatch entrypoint.

const std = @import("std");

const cli = @import("zig_cli");
const log_mod = @import("log");

const common = @import("spec_common.zig");
const commands = @import("commands/root.zig");
const rc_config = @import("rc_config.zig");

pub const std_options: std.Options = .{
    .logFn = log_mod.stdLogFn,
    .log_level = .debug,
};

const app_spec = cli.app(.{
    .name = "lodestar-z",
    .version = common.VERSION,
    .description = "Ethereum consensus client in Zig",
    .commands = .{
        .beacon = commands.beacon.spec.spec,
        .validator = commands.validator.spec.spec,
        .lightclient = commands.lightclient.spec.spec,
        .dev = commands.dev.spec.spec,
        .bootnode = commands.bootnode.spec.spec,
    },
    .global_options = common.global_options,
});

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.gpa;
    defer rc_config.deinit();

    {
        var scanner = init.minimal.args.iterate();
        _ = scanner.skip();
        while (scanner.next()) |arg| {
            if (std.mem.eql(u8, arg, "--rc-config")) {
                if (scanner.next()) |config_path| {
                    rc_config.load(allocator, io, config_path) catch |err| {
                        std.log.err("Failed to load RC config '{s}': {}", .{ config_path, err });
                        std.process.exit(1);
                    };
                    std.log.debug("loaded RC config from {s}", .{config_path});
                }
                break;
            }
        }
    }

    var args_iter = init.minimal.args.iterate();
    const result = if (rc_config.hasLoadedConfig())
        cli.parseAppWithResolver(app_spec, &args_iter, allocator, rc_config.resolver)
    else
        cli.parseApp(app_spec, &args_iter, allocator);

    const parsed = result catch |err| switch (err) {
        error.HelpRequested, error.VersionRequested => return,
        else => {
            std.debug.print("Try 'lodestar-z --help' for usage information.\n", .{});
            std.process.exit(1);
        },
    };

    switch (std.meta.activeTag(parsed)) {
        .beacon => {
            try commands.beacon.command.run(io, allocator, &parsed.beacon);
        },
        .validator => {
            try commands.validator.command.run(io, allocator, &parsed.validator);
        },
        .lightclient => try commands.lightclient.command.run(&parsed.lightclient),
        .dev => try commands.dev.command.run(&parsed.dev),
        .bootnode => try commands.bootnode.command.run(io, allocator, &parsed.bootnode),
    }
}
