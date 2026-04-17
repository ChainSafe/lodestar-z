//! Log integration smoke example.
//!
//! Demonstrates the structured Logger API, std.log bridge,
//! caller-owned async pipelines, and all three layout formats.
//!
//! Run:
//!   zig build run:log_smoke
//!
//! Expected output: structured log lines on stderr from each dispatcher/layout.

const std = @import("std");
const log_mod = @import("log");

/// Re-export std_options so std.log calls route through the pipeline.
pub const std_options = log_mod.std_options;

const Logger = log_mod.Logger;
const Attr = log_mod.Attr;
const Dispatch = log_mod.Dispatch;
const Dispatcher = log_mod.Dispatcher;
const LevelFilter = log_mod.LevelFilter;
const FlushableWriter = log_mod.FlushableWriter;
const WriterAppend = log_mod.WriterAppend;
const AsyncAppend = log_mod.AsyncAppend;
const TextLayout = log_mod.TextLayout;
const JsonLayout = log_mod.JsonLayout;
const LogfmtLayout = log_mod.LogfmtLayout;
const RollingFileWriter = log_mod.RollingFileWriter;

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

    // ── 1. Sync stderr pipeline (explicit TextLayout) ─────────────

    std.debug.print("\n=== 1. Sync stderr pipeline (explicit TextLayout) ===\n", .{});
    {
        var filter = LevelFilter.init(.debug);
        var sync_appender = WriterAppend(TextLayout).init(allocator, TextLayout{ .color = true }, FlushableWriter.stderrWriter());

        var d = Dispatch.init();
        d.addFilter(filter.any());
        d.addAppend(sync_appender.any());

        var dispatcher = Dispatcher.init();
        dispatcher.addDispatch(d);
        log_mod.setGlobalDispatcher(dispatcher.any());

        const std_log = std.log.scoped(.smoke);
        std_log.err("std.log bridge err", .{});
        std_log.info("std.log bridge info", .{});

        const log = Logger(4).init(.smoke, log_mod.getGlobalDispatcher());
        emitSample(log);

        const child = log.with(&[_]Attr{Attr.str("module", "fc")});
        child.info("child log", .{ .epoch = @as(u64, 7) });

        log_mod.resetGlobalDispatcher();
    }

    // ── 2. Async console pipeline (caller-owned) ────────────

    std.debug.print("\n=== 2. Async console pipeline (caller-owned) ===\n", .{});
    {
        var filter = LevelFilter.init(.debug);
        var appender = try AsyncAppend(TextLayout).init(
            allocator,
            1024,
            FlushableWriter.stderrWriter(),
            TextLayout{ .color = true },
            .block,
        );
        try appender.start();

        var d = Dispatch.init();
        d.addFilter(filter.any());
        d.addAppend(appender.any());

        var dispatcher = Dispatcher.init();
        dispatcher.addDispatch(d);
        log_mod.setGlobalDispatcher(dispatcher.any());

        const log = Logger(4).init(.smoke, log_mod.getGlobalDispatcher());
        emitSample(log);
        log_mod.flushGlobalDispatcher();

        dispatcher.deinit();
        log_mod.resetGlobalDispatcher();
    }

    // ── 3. Async file pipeline (caller-owned) ─────

    std.debug.print("\n=== 3. Async file pipeline (caller-owned) ===\n", .{});
    {
        var rolling = try RollingFileWriter.init(std.fs.cwd(), "smoke.log", .{ .rotation = .never, .max_bytes = 1024 * 1024 });

        var filter = LevelFilter.init(.debug);
        var appender = try AsyncAppend(TextLayout).init(
            allocator,
            1024,
            FlushableWriter.fromFlushable(&rolling),
            TextLayout{},
            .block,
        );
        try appender.start();

        var d = Dispatch.init();
        d.addFilter(filter.any());
        d.addAppend(appender.any());

        var dispatcher = Dispatcher.init();
        dispatcher.addDispatch(d);
        log_mod.setGlobalDispatcher(dispatcher.any());

        const log = Logger(4).init(.smoke, log_mod.getGlobalDispatcher());
        emitSample(log);
        log_mod.flushGlobalDispatcher();

        dispatcher.deinit();
        rolling.deinit();
        log_mod.resetGlobalDispatcher();
        std.debug.print("  → wrote smoke.log\n", .{});
    }

    // ── 4. Combined pipeline: console + file (caller-owned) ─

    std.debug.print("\n=== 4. Combined pipeline: console + file (caller-owned) ===\n", .{});
    {
        var rolling = try RollingFileWriter.init(std.fs.cwd(), "smoke_combined.log", .{ .rotation = .never, .max_bytes = 1024 * 1024 });

        var filter = LevelFilter.init(.debug);
        var console_appender = try AsyncAppend(TextLayout).init(
            allocator,
            1024,
            FlushableWriter.stderrWriter(),
            TextLayout{ .color = true },
            .block,
        );
        var file_appender = try AsyncAppend(TextLayout).init(
            allocator,
            1024,
            FlushableWriter.fromFlushable(&rolling),
            TextLayout{},
            .block,
        );
        try console_appender.start();
        try file_appender.start();

        var d = Dispatch.init();
        d.addFilter(filter.any());
        d.addAppend(console_appender.any());
        d.addAppend(file_appender.any());

        var dispatcher = Dispatcher.init();
        dispatcher.addDispatch(d);
        log_mod.setGlobalDispatcher(dispatcher.any());

        const log = Logger(4).init(.smoke, log_mod.getGlobalDispatcher());
        emitSample(log);
        log_mod.flushGlobalDispatcher();

        dispatcher.deinit();
        rolling.deinit();
        log_mod.resetGlobalDispatcher();
        std.debug.print("  → wrote smoke_combined.log\n", .{});
    }

    // ── 5. Custom pipeline — JsonLayout (sync stderr) ────────

    std.debug.print("\n=== 5. JsonLayout (sync stderr) ===\n", .{});
    {
        var debug_filter = LevelFilter.init(.debug);
        var json_appender = WriterAppend(JsonLayout).init(allocator, JsonLayout{}, FlushableWriter.stderrWriter());

        var d = Dispatch.init();
        d.addFilter(debug_filter.any());
        d.addAppend(json_appender.any());

        var dispatcher = Dispatcher.init();
        dispatcher.addDispatch(d);

        const log = Logger(4).init(.smoke, dispatcher.any());
        emitSample(log);
    }

    // ── 6. Custom pipeline — LogfmtLayout (sync stderr) ──────

    std.debug.print("\n=== 6. LogfmtLayout (sync stderr) ===\n", .{});
    {
        var debug_filter = LevelFilter.init(.debug);
        var logfmt_appender = WriterAppend(LogfmtLayout).init(allocator, LogfmtLayout{}, FlushableWriter.stderrWriter());

        var d = Dispatch.init();
        d.addFilter(debug_filter.any());
        d.addAppend(logfmt_appender.any());

        var dispatcher = Dispatcher.init();
        dispatcher.addDispatch(d);

        const log = Logger(4).init(.smoke, dispatcher.any());
        emitSample(log);
    }

    // cleanup generated files
    std.fs.cwd().deleteFile("smoke.log") catch {};
    std.fs.cwd().deleteFile("smoke_combined.log") catch {};

    std.debug.print("\n=== All 6 configurations OK ===\n", .{});
}
