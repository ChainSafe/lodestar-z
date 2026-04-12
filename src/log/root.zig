//! Structured logging library for lodestar-z.
//!
//! Architecture: Filter → Diagnostic → Append pipeline with comptime static
//! dispatch. Each appender owns its own Layout and formats Records internally.
//! One indirect call per log statement (AnyDispatcher), everything else is
//! direct/inlineable.
//!
//! Quick start (development — sync, immediate stderr output):
//!
//!   const log_mod = @import("log");
//!   const Logger = log_mod.Logger;
//!   const log = Logger(4).init(.fork_choice, log_mod.getGlobalDispatcher());
//!   log.info("block applied", .{ .slot = slot });
//!
//! Production setup — pick one of three async builders:
//!
//!   // Console only (async, stderr):
//!   try log_mod.initConsoleDispatcher(allocator, .{});
//!   defer log_mod.deinitGlobalDispatcher();
//!
//!   // Rolling file only (async, daily rotation):
//!   try log_mod.initFileDispatcher(allocator, .{ .dir = std.fs.cwd() });
//!   defer log_mod.deinitGlobalDispatcher();
//!
//!   // Combined (async, console stderr + rolling file):
//!   try log_mod.initCombinedDispatcher(allocator, .{ .dir = std.fs.cwd() });
//!   defer log_mod.deinitGlobalDispatcher();
//!
//! Custom pipeline (advanced):
//!
//!   // Build a Dispatcher with custom filters, diagnostics, and appenders.
//!   log_mod.setGlobalDispatcher(my_dispatcher.any());

const std = @import("std");
const rec = @import("record.zig");
const filt = @import("filter.zig");
const diag = @import("diagnostic.zig");
const lay = @import("layout.zig");
const ap = @import("append.zig");
const disp = @import("dispatch.zig");

// -- Re-exports: record.zig (foundation) --

pub const Attr = rec.Attr;
pub const Record = rec.Record;
pub const Scope = rec.Scope;
pub const scopeName = rec.scopeName;
pub const Level = rec.Level;
pub const asText = rec.asText;
pub const parseLevel = rec.parseLevel;
pub const FilterResult = rec.FilterResult;
pub const hasDeclSafe = rec.hasDeclSafe;
pub const isFilter = rec.isFilter;
pub const isDiagnostic = rec.isDiagnostic;
pub const isLayout = rec.isLayout;
pub const isAppend = rec.isAppend;
pub const assertFilter = rec.assertFilter;
pub const assertDiagnostic = rec.assertDiagnostic;
pub const assertLayout = rec.assertLayout;
pub const assertAppend = rec.assertAppend;

// -- Re-exports: filter.zig --

pub const LevelFilter = filt.LevelFilter;
pub const ScopeFilter = filt.ScopeFilter;
pub const EnvFilter = filt.EnvFilter;
pub const parseEnvFilter = filt.parse;
pub const envFilterFromEnv = filt.fromEnv;

// -- Re-exports: diagnostic.zig --

pub const StaticDiagnostic = diag.StaticDiagnostic;
pub const ThreadLocalDiagnostic = diag.ThreadLocalDiagnostic;

// -- Re-exports: layout.zig --

pub const TextLayout = lay.TextLayout;
pub const JsonLayout = lay.JsonLayout;
pub const LogfmtLayout = lay.LogfmtLayout;

// -- Re-exports: append.zig --

pub const NullAppend = ap.NullAppend;
pub const WriterAppend = ap.WriterAppend;
pub const TestingAppend = ap.TestingAppend;
pub const Rotation = ap.Rotation;
pub const RollingPolicy = ap.RollingPolicy;
pub const RollingFileWriter = ap.RollingFileWriter;
pub const FileAppend = ap.FileAppend;
pub const OpenTelemetryAppend = ap.OpenTelemetryAppend;
pub const AsyncAppend = ap.AsyncAppend;
pub const Overflow = ap.Overflow;
pub const FlushableWriter = ap.FlushableWriter;

// -- Re-exports: dispatch.zig --

pub const Dispatch = disp.Dispatch;
pub const Dispatcher = disp.Dispatcher;
pub const AnyDispatcher = disp.AnyDispatcher;
pub const Logger = disp.Logger;

// -- Re-exports: ring_buffer.zig (shared primitive) --

const ring_buffer = @import("ring_buffer");
pub const RingBuffer = ring_buffer.RingBuffer;
pub const ByteMessage = ring_buffer.ByteMessage;

// ──────────────── Global Dispatcher Infrastructure ────────────────

/// Dev default: sync WriterAppend → stderr (immediate output for development).
/// Follows Unix convention: stdout = program data, stderr = diagnostics/logs.
const DefaultAppend = WriterAppend(TextLayout);
const DefaultDispatch = Dispatch(
    struct { LevelFilter },
    struct {},
    struct { DefaultAppend },
);
const DefaultDispatcher = Dispatcher(struct { DefaultDispatch });

var default_dispatch_storage: DefaultDispatcher = .{
    .dispatches = .{
        DefaultDispatch{
            .filters = .{LevelFilter.init(.info)},
            .diagnostics = .{},
            .appenders = .{DefaultAppend.init(
                std.heap.page_allocator,
                TextLayout{ .color = true },
                FlushableWriter.stderrWriter(),
            )},
        },
    },
};

var default_any_slot: AnyDispatcher = default_dispatch_storage.any();
var user_any_slot: AnyDispatcher = AnyDispatcher.noop();

/// Atomic pointer to the active AnyDispatcher slot.
var global_dispatcher_ptr: std.atomic.Value(*AnyDispatcher) = std.atomic.Value(*AnyDispatcher).init(&default_any_slot);

/// Set the global dispatcher. Thread-safe for concurrent get.
/// Call once at startup — the user slot is overwritten without guarding
/// against readers who cached a prior by-value copy.
pub fn setGlobalDispatcher(dispatcher: AnyDispatcher) void {
    user_any_slot = dispatcher;
    global_dispatcher_ptr.store(&user_any_slot, .release);
}

/// Get the current global dispatcher (by value). Thread-safe.
pub fn getGlobalDispatcher() AnyDispatcher {
    return global_dispatcher_ptr.load(.acquire).*;
}

/// Flush the global dispatcher (blocks until all pending logs are written).
pub fn flushGlobalDispatcher() void {
    getGlobalDispatcher().flush();
}

// ──────────── Async Builder Types ────────────

/// Shared async appender type (all builders use TextLayout).
const AA = AsyncAppend(TextLayout);

/// Console-only: single async appender → stderr.
const ConsoleDispatch = Dispatch(struct { LevelFilter }, struct {}, struct { AA });
const ConsoleDispatcherT = Dispatcher(struct { ConsoleDispatch });

/// File-only: single async appender → rolling file.
const FileDispatch = Dispatch(struct { LevelFilter }, struct {}, struct { AA });
const FileDispatcherT = Dispatcher(struct { FileDispatch });

/// Combined: two async appenders → stderr + rolling file.
const CombinedDispatch = Dispatch(struct { LevelFilter }, struct {}, struct { AA, AA });
const CombinedDispatcherT = Dispatcher(struct { CombinedDispatch });

// ──────────── Global Async State ────────────

const DispatcherVariant = enum { none, console, file, combined };

var g_variant: DispatcherVariant = .none;
var g_console: ConsoleDispatcherT = undefined;
var g_file: FileDispatcherT = undefined;
var g_combined: CombinedDispatcherT = undefined;
var g_rolling: RollingFileWriter = undefined;

// ──────────── Console Dispatcher ────────────

pub const ConsoleConfig = struct {
    min_level: std.log.Level = .info,
    ring_size: u32 = 1024,
    overflow: Overflow = .block,
    layout: TextLayout = TextLayout{ .color = true },
};

/// Initialize the global dispatcher with an async console appender (stderr).
pub fn initConsoleDispatcher(allocator: std.mem.Allocator, config: ConsoleConfig) !void {
    std.debug.assert(g_variant == .none);

    g_console = ConsoleDispatcherT{
        .dispatches = .{
            ConsoleDispatch{
                .filters = .{LevelFilter.init(config.min_level)},
                .diagnostics = .{},
                .appenders = .{try AA.init(
                    allocator,
                    config.ring_size,
                    FlushableWriter.stderrWriter(),
                    config.layout,
                    config.overflow,
                )},
            },
        },
    };

    try g_console.dispatches[0].appenders[0].start();
    setGlobalDispatcher(g_console.any());
    g_variant = .console;
}

// ──────────── File Dispatcher ────────────

pub const FileConfig = struct {
    min_level: std.log.Level = .info,
    ring_size: u32 = 1024,
    overflow: Overflow = .block,
    layout: TextLayout = TextLayout{}, // no color for file
    dir: std.fs.Dir,
    base_name: []const u8 = "app.log",
    rolling: RollingPolicy = .{ .rotation = .daily },
};

/// Initialize the global dispatcher with an async file appender (rolling).
/// The `dir` handle must outlive the dispatcher.
pub fn initFileDispatcher(allocator: std.mem.Allocator, config: FileConfig) !void {
    std.debug.assert(g_variant == .none);

    g_rolling = try RollingFileWriter.init(config.dir, config.base_name, config.rolling);
    errdefer g_rolling.deinit();

    g_file = FileDispatcherT{
        .dispatches = .{
            FileDispatch{
                .filters = .{LevelFilter.init(config.min_level)},
                .diagnostics = .{},
                .appenders = .{try AA.init(
                    allocator,
                    config.ring_size,
                    FlushableWriter.fromFlushable(&g_rolling),
                    config.layout,
                    config.overflow,
                )},
            },
        },
    };

    try g_file.dispatches[0].appenders[0].start();
    setGlobalDispatcher(g_file.any());
    g_variant = .file;
}

// ──────────── Combined Dispatcher ────────────

pub const CombinedConfig = struct {
    min_level: std.log.Level = .info,
    ring_size: u32 = 1024,
    overflow: Overflow = .block,
    console_layout: TextLayout = TextLayout{ .color = true },
    file_layout: TextLayout = TextLayout{}, // no color for file
    dir: std.fs.Dir,
    base_name: []const u8 = "app.log",
    rolling: RollingPolicy = .{ .rotation = .daily },
};

/// Initialize the global dispatcher with console (stderr) + rolling file.
/// The `dir` handle must outlive the dispatcher.
pub fn initCombinedDispatcher(allocator: std.mem.Allocator, config: CombinedConfig) !void {
    std.debug.assert(g_variant == .none);

    g_rolling = try RollingFileWriter.init(config.dir, config.base_name, config.rolling);
    errdefer g_rolling.deinit();

    const console_appender = try AA.init(
        allocator,
        config.ring_size,
        FlushableWriter.stderrWriter(),
        config.console_layout,
        config.overflow,
    );

    const file_appender = try AA.init(
        allocator,
        config.ring_size,
        FlushableWriter.fromFlushable(&g_rolling),
        config.file_layout,
        config.overflow,
    );

    g_combined = CombinedDispatcherT{
        .dispatches = .{
            CombinedDispatch{
                .filters = .{LevelFilter.init(config.min_level)},
                .diagnostics = .{},
                .appenders = .{ console_appender, file_appender },
            },
        },
    };

    try g_combined.dispatches[0].appenders[0].start();
    try g_combined.dispatches[0].appenders[1].start();
    setGlobalDispatcher(g_combined.any());
    g_variant = .combined;
}

// ──────────── Shared Deinit ────────────

/// Shutdown the global async dispatcher. Flushes pending logs and joins consumer threads.
/// Call at application exit (via `defer`).
pub fn deinitGlobalDispatcher() void {
    switch (g_variant) {
        .none => return,
        .console => {
            g_console.dispatches[0].appenders[0].deinit();
        },
        .file => {
            g_file.dispatches[0].appenders[0].deinit();
            g_rolling.deinit();
        },
        .combined => {
            g_combined.dispatches[0].appenders[0].deinit();
            g_combined.dispatches[0].appenders[1].deinit();
            g_rolling.deinit();
        },
    }
    g_variant = .none;
    global_dispatcher_ptr.store(&default_any_slot, .release);
}

// ──────────── std.log bridge ────────────

/// std.log compatibility: converts std.log calls → Record → global AnyDispatcher.
/// Library code can keep using `std.log.scoped(.x)` during migration.
pub fn stdLogBridge(
    comptime message_level: std.log.Level,
    comptime scope: @TypeOf(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    var buf: [4096]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, format, args) catch "<fmt error>";
    var record = Record{
        .timestamp_us = std.time.microTimestamp(),
        .level = message_level,
        .scope_name = scopeName(scope),
        .message = msg,
    };
    getGlobalDispatcher().emit(&record);
}

/// Drop-in value for every executable's `pub const std_options`.
pub const std_options: std.Options = .{
    .log_level = .debug,
    .logFn = stdLogBridge,
};

// -- Transitive test references --

comptime {
    _ = @import("record.zig");
    _ = @import("filter.zig");
    _ = @import("diagnostic.zig");
    _ = @import("layout.zig");
    _ = @import("append.zig");
    _ = @import("dispatch.zig");
    _ = @import("ring_buffer");
}

// ──────────────────────────── Tests ────────────────────────────

test "global dispatcher default emits to stderr" {
    const log = Logger(4).init(.default, getGlobalDispatcher());
    log.debug("root.zig test — this goes to stderr", .{});
}

test "setGlobalDispatcher swaps dispatcher" {
    const saved = getGlobalDispatcher();
    defer setGlobalDispatcher(saved);

    setGlobalDispatcher(AnyDispatcher.noop());
    const log = Logger(4).init(.default, getGlobalDispatcher());
    log.info("discarded by noop", .{});
}

test "initConsoleDispatcher and deinit" {
    const saved = getGlobalDispatcher();
    defer setGlobalDispatcher(saved);

    try initConsoleDispatcher(std.testing.allocator, .{
        .min_level = .debug,
        .ring_size = 16,
        .overflow = .drop_incoming,
    });
    defer deinitGlobalDispatcher();

    const log = Logger(4).init(.default, getGlobalDispatcher());
    log.info("async console test", .{});
    flushGlobalDispatcher();
}

test "initFileDispatcher and deinit" {
    const saved = getGlobalDispatcher();
    defer setGlobalDispatcher(saved);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try initFileDispatcher(std.testing.allocator, .{
        .min_level = .debug,
        .ring_size = 16,
        .overflow = .drop_incoming,
        .dir = tmp.dir,
        .base_name = "test.log",
        .rolling = .{ .rotation = .never, .max_bytes = 1024 * 1024 },
    });
    defer deinitGlobalDispatcher();

    const log = Logger(4).init(.default, getGlobalDispatcher());
    log.info("async file test", .{});
    flushGlobalDispatcher();

    // Allow consumer thread to process.
    std.time.sleep(50_000_000);

    const content = try tmp.dir.readFileAlloc(std.testing.allocator, "test.log", 8192);
    defer std.testing.allocator.free(content);
    try std.testing.expect(std.mem.indexOf(u8, content, "async file test") != null);
}

test "initCombinedDispatcher and deinit" {
    const saved = getGlobalDispatcher();
    defer setGlobalDispatcher(saved);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try initCombinedDispatcher(std.testing.allocator, .{
        .min_level = .debug,
        .ring_size = 16,
        .overflow = .drop_incoming,
        .dir = tmp.dir,
        .base_name = "combined.log",
        .rolling = .{ .rotation = .never, .max_bytes = 1024 * 1024 },
    });
    defer deinitGlobalDispatcher();

    const log = Logger(4).init(.default, getGlobalDispatcher());
    log.info("combined test", .{});
    flushGlobalDispatcher();

    std.time.sleep(50_000_000);

    const content = try tmp.dir.readFileAlloc(std.testing.allocator, "combined.log", 8192);
    defer std.testing.allocator.free(content);
    try std.testing.expect(std.mem.indexOf(u8, content, "combined test") != null);
}

test "end-to-end pipeline with TestingAppend" {
    const TA = TestingAppend(TextLayout);
    const TestDispatch = Dispatch(
        struct { LevelFilter },
        struct {},
        struct { TA },
    );

    const TestDispatcher = Dispatcher(struct { TestDispatch });

    var test_dispatcher = TestDispatcher{
        .dispatches = .{
            TestDispatch{
                .filters = .{LevelFilter.init(.debug)},
                .diagnostics = .{},
                .appenders = .{TA.init(std.testing.allocator, TextLayout{})},
            },
        },
    };

    const log = Logger(4).init(.fork_choice, test_dispatcher.any());
    log.info("block applied", .{ .slot = @as(u64, 42) });

    try std.testing.expect(test_dispatcher.dispatches[0].appenders[0].contains("block applied"));
    try std.testing.expect(test_dispatcher.dispatches[0].appenders[0].contains("slot=42"));
    try std.testing.expect(test_dispatcher.dispatches[0].appenders[0].contains("(fork_choice)"));
}
