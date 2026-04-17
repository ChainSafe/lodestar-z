//! Structured logging library for lodestar-z.
//!
//! Architecture: Filter → Diagnostic → Append pipeline with runtime dispatch.
//! Each appender owns its Layout and formats Records internally.
//! One indirect call per log statement (AnyDispatcher), pipeline stages use
//! type-erased interfaces (AnyFilter, AnyDiagnostic, AnyAppend).
//!
//! Quick start (development — sync, immediate stderr output):
//!
//!   const log_mod = @import("log");
//!   const Logger = log_mod.Logger;
//!   const log = Logger(4).init(.fork_choice, log_mod.getGlobalDispatcher());
//!   log.info("block applied", .{ .slot = slot });
//!
//! Production setup — caller builds and owns the pipeline:
//!
//!   var filter = LevelFilter.init(.info);
//!   var appender = try AsyncAppend(TextLayout).init(
//!       allocator, 1024, FlushableWriter.stderrWriter(),
//!       TextLayout{ .color = true }, .block,
//!   );
//!   try appender.start();
//!
//!   var d = Dispatch.init();
//!   d.addFilter(filter.any());
//!   d.addAppend(appender.any());
//!
//!   var dispatcher = Dispatcher.init();
//!   dispatcher.addDispatch(d);
//!   log_mod.setGlobalDispatcher(dispatcher.any());
//!   defer {
//!       dispatcher.deinit();
//!       log_mod.resetGlobalDispatcher();
//!   }

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
pub const AnyFilter = rec.AnyFilter;
pub const AnyDiagnostic = rec.AnyDiagnostic;
pub const AnyAppend = rec.AnyAppend;
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
pub const max_filters = disp.max_filters;
pub const max_diagnostics = disp.max_diagnostics;
pub const max_appenders = disp.max_appenders;
pub const max_dispatches = disp.max_dispatches;

// -- Re-exports: ring_buffer.zig (shared primitive) --

const ring_buffer = @import("ring_buffer");
pub const RingBuffer = ring_buffer.RingBuffer;
pub const ByteMessage = ring_buffer.ByteMessage;

// ──────────────── Global Dispatcher Infrastructure ────────────────

/// The single slot backing the global dispatcher pointer.
/// Starts as noop — the caller must call setGlobalDispatcher() to enable logging.
var global_any_slot: AnyDispatcher = AnyDispatcher.noop();

/// Atomic pointer to the active AnyDispatcher slot.
var global_dispatcher_ptr: std.atomic.Value(*AnyDispatcher) = std.atomic.Value(*AnyDispatcher).init(&global_any_slot);

/// Set the global dispatcher. Thread-safe for concurrent get.
/// Call once at startup — the slot is overwritten without guarding
/// against readers who cached a prior by-value copy.
pub fn setGlobalDispatcher(dispatcher: AnyDispatcher) void {
    global_any_slot = dispatcher;
    global_dispatcher_ptr.store(&global_any_slot, .release);
}

/// Get the current global dispatcher (by value). Thread-safe.
pub fn getGlobalDispatcher() AnyDispatcher {
    return global_dispatcher_ptr.load(.acquire).*;
}

/// Flush the global dispatcher (blocks until all pending logs are written).
pub fn flushGlobalDispatcher() void {
    getGlobalDispatcher().flush();
}

/// Reset the global dispatcher to noop (silently drops all log output).
/// Call after deiniting a caller-owned dispatcher.
pub fn resetGlobalDispatcher() void {
    global_any_slot = AnyDispatcher.noop();
    global_dispatcher_ptr.store(&global_any_slot, .release);
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

test {
    std.testing.refAllDeclsRecursive(@This());
}

// ──────────────────────────── Tests ────────────────────────────

test "global dispatcher default is noop" {
    // Before any setGlobalDispatcher, the global dispatcher is noop.
    const d = getGlobalDispatcher();
    try std.testing.expect(!d.enabled(.info, "default"));
    // emit is safe — noop silently drops.
    var record = Record{
        .timestamp_us = std.time.microTimestamp(),
        .level = .info,
        .scope_name = "default",
        .message = "should be silently dropped",
    };
    d.emit(&record);
}

test "setGlobalDispatcher swaps dispatcher" {
    const saved = getGlobalDispatcher();
    defer setGlobalDispatcher(saved);

    setGlobalDispatcher(AnyDispatcher.noop());
    const log = Logger(4).init(.default, getGlobalDispatcher());
    log.info("discarded by noop", .{});
}

test "resetGlobalDispatcher restores noop" {
    const saved = getGlobalDispatcher();
    defer setGlobalDispatcher(saved);

    // Set a real dispatcher, then reset — should be noop again.
    var debug_filter = filt.LevelFilter.init(.debug);
    var ta = ap.TestingAppend(lay.TextLayout).init(std.testing.allocator, lay.TextLayout{});
    var d = Dispatch.init();
    d.addFilter(debug_filter.any());
    d.addAppend(ta.any());
    var dispatcher = Dispatcher.init();
    dispatcher.addDispatch(d);
    setGlobalDispatcher(dispatcher.any());

    try std.testing.expect(getGlobalDispatcher().enabled(.info, "default"));

    resetGlobalDispatcher();
    try std.testing.expect(!getGlobalDispatcher().enabled(.info, "default"));
}

test "caller-owned async console pipeline" {
    const saved = getGlobalDispatcher();
    defer setGlobalDispatcher(saved);

    var level_filter = filt.LevelFilter.init(.debug);
    var async_appender = try AsyncAppend(TextLayout).init(
        std.testing.allocator,
        16,
        FlushableWriter.stderrWriter(),
        TextLayout{ .color = true },
        .drop_incoming,
    );
    try async_appender.start();

    var d = Dispatch.init();
    d.addFilter(level_filter.any());
    d.addAppend(async_appender.any());

    var dispatcher = Dispatcher.init();
    dispatcher.addDispatch(d);
    setGlobalDispatcher(dispatcher.any());

    const log = Logger(4).init(.default, getGlobalDispatcher());
    log.info("async console test", .{});
    flushGlobalDispatcher();

    dispatcher.deinit();
    resetGlobalDispatcher();
}

test "caller-owned async file pipeline" {
    const saved = getGlobalDispatcher();
    defer setGlobalDispatcher(saved);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var rolling = try RollingFileWriter.init(tmp.dir, "test.log", .{ .rotation = .never, .max_bytes = 1024 * 1024 });

    var level_filter = filt.LevelFilter.init(.debug);
    var async_appender = try AsyncAppend(TextLayout).init(
        std.testing.allocator,
        16,
        FlushableWriter.fromFlushable(&rolling),
        TextLayout{},
        .drop_incoming,
    );
    try async_appender.start();

    var d = Dispatch.init();
    d.addFilter(level_filter.any());
    d.addAppend(async_appender.any());

    var dispatcher = Dispatcher.init();
    dispatcher.addDispatch(d);
    setGlobalDispatcher(dispatcher.any());

    const log = Logger(4).init(.default, getGlobalDispatcher());
    log.info("async file test", .{});
    flushGlobalDispatcher();

    std.time.sleep(50_000_000);

    dispatcher.deinit();
    rolling.deinit();
    resetGlobalDispatcher();

    const content = try tmp.dir.readFileAlloc(std.testing.allocator, "test.log", 8192);
    defer std.testing.allocator.free(content);
    try std.testing.expect(std.mem.indexOf(u8, content, "async file test") != null);
}

test "caller-owned combined pipeline" {
    const saved = getGlobalDispatcher();
    defer setGlobalDispatcher(saved);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var rolling = try RollingFileWriter.init(tmp.dir, "combined.log", .{ .rotation = .never, .max_bytes = 1024 * 1024 });

    var level_filter = filt.LevelFilter.init(.debug);
    var console_appender = try AsyncAppend(TextLayout).init(
        std.testing.allocator,
        16,
        FlushableWriter.stderrWriter(),
        TextLayout{ .color = true },
        .drop_incoming,
    );
    var file_appender = try AsyncAppend(TextLayout).init(
        std.testing.allocator,
        16,
        FlushableWriter.fromFlushable(&rolling),
        TextLayout{},
        .drop_incoming,
    );
    try console_appender.start();
    try file_appender.start();

    var d = Dispatch.init();
    d.addFilter(level_filter.any());
    d.addAppend(console_appender.any());
    d.addAppend(file_appender.any());

    var dispatcher = Dispatcher.init();
    dispatcher.addDispatch(d);
    setGlobalDispatcher(dispatcher.any());

    const log = Logger(4).init(.default, getGlobalDispatcher());
    log.info("combined test", .{});
    flushGlobalDispatcher();

    std.time.sleep(50_000_000);

    dispatcher.deinit();
    rolling.deinit();
    resetGlobalDispatcher();

    const content = try tmp.dir.readFileAlloc(std.testing.allocator, "combined.log", 8192);
    defer std.testing.allocator.free(content);
    try std.testing.expect(std.mem.indexOf(u8, content, "combined test") != null);
}

test "end-to-end pipeline with TestingAppend" {
    const TA = TestingAppend(TextLayout);

    var debug_filter = filt.LevelFilter.init(.debug);
    var ta = TA.init(std.testing.allocator, TextLayout{});

    var d = Dispatch.init();
    d.addFilter(debug_filter.any());
    d.addAppend(ta.any());

    var dispatcher = Dispatcher.init();
    dispatcher.addDispatch(d);

    const log = Logger(4).init(.fork_choice, dispatcher.any());
    log.info("block applied", .{ .slot = @as(u64, 42) });

    try std.testing.expect(ta.contains("block applied"));
    try std.testing.expect(ta.contains("slot=42"));
    try std.testing.expect(ta.contains("(fork_choice)"));
}
