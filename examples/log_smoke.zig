//! Log integration smoke example.
//!
//! Demonstrates the V2 structured Logger API, std.log bridge,
//! all three async builder configs, and all three layout formats.
//!
//! Run:
//!   zig build run:log_smoke
//!
//! Expected output: structured log lines on stderr from each dispatcher/layout.

const std = @import("std");
const log_mod = @import("log");

/// Re-export std_options so std.log calls route through the V2 pipeline.
pub const std_options = log_mod.std_options;

const Logger = log_mod.Logger;
const Attr = log_mod.Attr;
const Dispatch = log_mod.Dispatch;
const Dispatcher = log_mod.Dispatcher;
const LevelFilter = log_mod.LevelFilter;
const FlushableWriter = log_mod.FlushableWriter;
const WriterAppend = log_mod.WriterAppend;
const TextLayout = log_mod.TextLayout;
const JsonLayout = log_mod.JsonLayout;
const LogfmtLayout = log_mod.LogfmtLayout;

/// Helper: emit a standard set of log lines through `log`.
fn emitSample(log: anytype) void {
    log.err("error msg", .{ .code = @as(u64, 500) });
    log.warn("warn msg", .{});
    log.info("info msg", .{ .slot = @as(u64, 42) });
    log.debug("debug msg", .{ .flag = true });
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // ── 1. Default (sync stderr, TextLayout) ─────────────────

    std.debug.print("\n=== 1. Default (sync stderr, TextLayout) ===\n", .{});
    {
        const std_log = std.log.scoped(.smoke);
        std_log.err("std.log bridge err", .{});
        std_log.info("std.log bridge info", .{});

        const log = Logger(4).init(.smoke, log_mod.getGlobalDispatcher());
        emitSample(log);

        const child = log.with(&[_]Attr{Attr.str("module", "fc")});
        child.info("child log", .{ .epoch = @as(u64, 7) });
    }

    // ── 2. Console builder (async stderr, TextLayout) ────────

    std.debug.print("\n=== 2. Console builder (async stderr, TextLayout) ===\n", .{});
    {
        try log_mod.initConsoleDispatcher(allocator, .{ .min_level = .debug });
        defer log_mod.deinitGlobalDispatcher();

        const log = Logger(4).init(.smoke, log_mod.getGlobalDispatcher());
        emitSample(log);
        log_mod.flushGlobalDispatcher();
    }

    // ── 3. File builder (async rolling file, TextLayout) ─────

    std.debug.print("\n=== 3. File builder (async rolling file, TextLayout) ===\n", .{});
    {
        try log_mod.initFileDispatcher(allocator, .{
            .min_level = .debug,
            .dir = std.fs.cwd(),
            .base_name = "smoke.log",
            .rolling = .{ .rotation = .never, .max_bytes = 1024 * 1024 },
        });
        defer log_mod.deinitGlobalDispatcher();

        const log = Logger(4).init(.smoke, log_mod.getGlobalDispatcher());
        emitSample(log);
        log_mod.flushGlobalDispatcher();
        std.debug.print("  → wrote smoke.log\n", .{});
    }

    // ── 4. Combined builder (async stderr + file, TextLayout) ─

    std.debug.print("\n=== 4. Combined builder (async stderr + file, TextLayout) ===\n", .{});
    {
        try log_mod.initCombinedDispatcher(allocator, .{
            .min_level = .debug,
            .dir = std.fs.cwd(),
            .base_name = "smoke_combined.log",
            .rolling = .{ .rotation = .never, .max_bytes = 1024 * 1024 },
        });
        defer log_mod.deinitGlobalDispatcher();

        const log = Logger(4).init(.smoke, log_mod.getGlobalDispatcher());
        emitSample(log);
        log_mod.flushGlobalDispatcher();
        std.debug.print("  → wrote smoke_combined.log\n", .{});
    }

    // ── 5. Custom pipeline — JsonLayout (sync stderr) ────────

    std.debug.print("\n=== 5. JsonLayout (sync stderr) ===\n", .{});
    {
        const WA = WriterAppend(JsonLayout);
        const D = Dispatch(struct { LevelFilter }, struct {}, struct { WA });
        const Disp = Dispatcher(struct { D });

        var dispatcher = Disp{
            .dispatches = .{
                D{
                    .filters = .{LevelFilter.init(.debug)},
                    .diagnostics = .{},
                    .appenders = .{WA.init(allocator, JsonLayout{}, FlushableWriter.stderrWriter())},
                },
            },
        };

        const log = Logger(4).init(.smoke, dispatcher.any());
        emitSample(log);
    }

    // ── 6. Custom pipeline — LogfmtLayout (sync stderr) ──────

    std.debug.print("\n=== 6. LogfmtLayout (sync stderr) ===\n", .{});
    {
        const WA = WriterAppend(LogfmtLayout);
        const D = Dispatch(struct { LevelFilter }, struct {}, struct { WA });
        const Disp = Dispatcher(struct { D });

        var dispatcher = Disp{
            .dispatches = .{
                D{
                    .filters = .{LevelFilter.init(.debug)},
                    .diagnostics = .{},
                    .appenders = .{WA.init(allocator, LogfmtLayout{}, FlushableWriter.stderrWriter())},
                },
            },
        };

        const log = Logger(4).init(.smoke, dispatcher.any());
        emitSample(log);
    }

    // cleanup generated files
    std.fs.cwd().deleteFile("smoke.log") catch {};
    std.fs.cwd().deleteFile("smoke_combined.log") catch {};

    std.debug.print("\n=== All 6 configurations OK ===\n", .{});
}
