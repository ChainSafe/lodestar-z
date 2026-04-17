//! Pipeline orchestration: Dispatch, Dispatcher, and Logger.
//!
//! Dispatch — single pipeline stage (runtime-configurable).
//! Dispatcher — fan-out to N dispatch pipelines.
//! AnyDispatcher — the ONLY type-erasure boundary (3 fn pointers).
//! Logger(max_attrs) — user-facing frontend.

const std = @import("std");
const rec = @import("record.zig");
const Record = rec.Record;
const Attr = rec.Attr;
const FilterResult = rec.FilterResult;
const AnyFilter = rec.AnyFilter;
const AnyDiagnostic = rec.AnyDiagnostic;
const AnyAppend = rec.AnyAppend;

// ──────────────────────── Bounds ────────────────────────

pub const max_filters = 8;
pub const max_diagnostics = 4;
pub const max_appenders = 8;
pub const max_dispatches = 8;

// ──────────────────────── Dispatch ────────────────────────

/// Runtime-configurable dispatch pipeline.
///
/// Pipeline order (aligned with logforth):
///   1. Diagnostic enrichment (before filtering).
///   2. Filter gate — first non-neutral result wins (short-circuit).
///   3. Append fan-out — each appender owns its Layout.
pub const Dispatch = struct {
    const Self = @This();

    filters: std.BoundedArray(AnyFilter, max_filters) = .{},
    diagnostics: std.BoundedArray(AnyDiagnostic, max_diagnostics) = .{},
    appenders: std.BoundedArray(AnyAppend, max_appenders) = .{},

    pub fn init() Dispatch {
        return .{};
    }

    pub fn addFilter(self: *Self, filter: AnyFilter) void {
        self.filters.append(filter) catch {};
    }

    pub fn addDiagnostic(self: *Self, diagnostic: AnyDiagnostic) void {
        self.diagnostics.append(diagnostic) catch {};
    }

    pub fn addAppend(self: *Self, appender: AnyAppend) void {
        self.appenders.append(appender) catch {};
    }

    /// Fast pre-check: first non-neutral result wins (short-circuit).
    pub fn enabled(self: *const Self, level: std.log.Level, scope_name: []const u8) FilterResult {
        for (self.filters.constSlice()) |f| {
            const result = f.enabled(level, scope_name);
            if (result != .neutral) return result;
        }
        return .neutral;
    }

    /// Process a record through the pipeline: diagnose → filter → append.
    pub fn process(self: *Self, record: *Record) void {
        for (self.diagnostics.constSlice()) |d| {
            d.enrich(record);
        }

        const should_proceed = blk: {
            for (self.filters.constSlice()) |f| {
                const result = f.matches(record);
                if (result != .neutral) break :blk result.shouldProceed();
            }
            break :blk true; // all neutral → proceed
        };
        if (!should_proceed) return;

        for (self.appenders.constSlice()) |a| {
            a.append(record);
        }
    }

    /// Flush all appenders.
    pub fn flush(self: *Self) void {
        for (self.appenders.constSlice()) |a| {
            a.flush();
        }
    }

    /// Deinit all appenders that have a deinit_fn.
    pub fn deinit(self: *Self) void {
        for (self.appenders.constSlice()) |a| {
            a.deinit();
        }
    }
};

// ─────────────────────── Dispatcher ─────────────────────────

/// Runtime fan-out dispatcher. Routes records to N dispatch pipelines.
pub const Dispatcher = struct {
    const Self = @This();

    dispatches: std.BoundedArray(Dispatch, max_dispatches) = .{},

    pub fn init() Dispatcher {
        return .{};
    }

    pub fn addDispatch(self: *Self, dispatch: Dispatch) void {
        self.dispatches.append(dispatch) catch {};
    }

    /// Fast pre-check: returns true if ANY dispatch pipeline might accept.
    pub fn enabled(self: *Self, level: std.log.Level, scope_name: []const u8) bool {
        for (self.dispatches.constSlice()) |*d| {
            if (d.enabled(level, scope_name).shouldProceed()) {
                return true;
            }
        }
        return false;
    }

    /// Fan-out: emit to all dispatch pipelines.
    pub fn emit(self: *Self, record: *Record) void {
        const saved_diag_len = record.diag_attrs.len;
        for (self.dispatches.slice()) |*d| {
            record.diag_attrs.len = saved_diag_len;
            d.process(record);
        }
    }

    /// Flush all dispatch pipelines (and their appenders).
    pub fn flush(self: *Self) void {
        for (self.dispatches.slice()) |*d| {
            d.flush();
        }
    }

    /// Deinit all dispatch pipelines (and their appenders).
    pub fn deinit(self: *Self) void {
        for (self.dispatches.slice()) |*d| {
            d.deinit();
        }
    }

    /// Type-erase to AnyDispatcher for use in Logger.
    pub fn any(self: *Self) AnyDispatcher {
        return AnyDispatcher.init(self, emitThunk, flushThunk, enabledThunk);
    }

    fn emitThunk(ptr: *anyopaque, record: *Record) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.emit(record);
    }

    fn flushThunk(ptr: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.flush();
    }

    fn enabledThunk(ptr: *anyopaque, level: std.log.Level, scope_name: []const u8) bool {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.enabled(level, scope_name);
    }
};

// ─────────────────────── AnyDispatcher ─────────────────────────

/// The ONLY type-erased boundary in the logging system.
/// Three function pointer calls: emit, flush, enabled.
pub const AnyDispatcher = struct {
    ptr: *anyopaque,
    emit_fn: *const fn (*anyopaque, *Record) void,
    flush_fn: *const fn (*anyopaque) void,
    enabled_fn: *const fn (*anyopaque, std.log.Level, []const u8) bool,

    pub fn init(
        dispatcher: anytype,
        emit_fn: *const fn (*anyopaque, *Record) void,
        flush_fn: *const fn (*anyopaque) void,
        enabled_fn: *const fn (*anyopaque, std.log.Level, []const u8) bool,
    ) AnyDispatcher {
        return .{
            .ptr = @ptrCast(dispatcher),
            .emit_fn = emit_fn,
            .flush_fn = flush_fn,
            .enabled_fn = enabled_fn,
        };
    }

    pub inline fn enabled(self: AnyDispatcher, level: std.log.Level, scope_name: []const u8) bool {
        return self.enabled_fn(self.ptr, level, scope_name);
    }

    pub inline fn emit(self: AnyDispatcher, record: *Record) void {
        self.emit_fn(self.ptr, record);
    }

    pub inline fn flush(self: AnyDispatcher) void {
        self.flush_fn(self.ptr);
    }

    /// No-op dispatcher that discards all records. Used as default/sentinel.
    pub fn noop() AnyDispatcher {
        const S = struct {
            fn noopEmit(_: *anyopaque, _: *Record) void {}
            fn noopFlush(_: *anyopaque) void {}
            fn noopEnabled(_: *anyopaque, _: std.log.Level, _: []const u8) bool {
                return false;
            }
            var sentinel: u8 = 0;
        };
        return .{
            .ptr = @ptrCast(&S.sentinel),
            .emit_fn = S.noopEmit,
            .flush_fn = S.noopFlush,
            .enabled_fn = S.noopEnabled,
        };
    }
};

// ──────────────────────── Logger ────────────────────────

/// Create a Logger type with a maximum number of pre-bound attributes.
///
/// Usage:
///   const log = Logger(8).init(.fork_choice, &global_dispatcher);
///   log.info("block applied", .{ .slot = slot });
pub fn Logger(comptime max_attrs: usize) type {
    return struct {
        const Self = @This();

        dispatcher: AnyDispatcher,
        scope_name: []const u8,
        prefix_attrs: std.BoundedArray(Attr, max_attrs),

        pub fn init(comptime scope: rec.Scope, dispatcher: AnyDispatcher) Self {
            return .{
                .dispatcher = dispatcher,
                .scope_name = rec.scopeName(scope),
                .prefix_attrs = .{},
            };
        }

        /// Create a child logger with additional pre-bound attributes.
        pub fn with(self: Self, attrs: []const Attr) Self {
            var new = self;
            for (attrs) |attr| new.prefix_attrs.append(attr) catch break;
            return new;
        }

        pub fn err(self: *const Self, comptime msg: []const u8, attrs: anytype) void {
            self.log(.err, msg, attrs);
        }

        pub fn warn(self: *const Self, comptime msg: []const u8, attrs: anytype) void {
            self.log(.warn, msg, attrs);
        }

        pub fn info(self: *const Self, comptime msg: []const u8, attrs: anytype) void {
            self.log(.info, msg, attrs);
        }

        pub fn debug(self: *const Self, comptime msg: []const u8, attrs: anytype) void {
            self.log(.debug, msg, attrs);
        }

        /// Log with explicit source location.
        pub fn logSrc(self: *const Self, level: std.log.Level, comptime msg: []const u8, attrs: anytype, src: std.builtin.SourceLocation) void {
            self.logImpl(level, msg, attrs, src);
        }

        /// Flush all downstream appenders via the dispatcher chain.
        pub fn flush(self: *const Self) void {
            self.dispatcher.flush();
        }

        fn log(self: *const Self, level: std.log.Level, comptime msg: []const u8, attrs: anytype) void {
            self.logImpl(level, msg, attrs, null);
        }

        fn logImpl(self: *const Self, level: std.log.Level, comptime msg: []const u8, attrs: anytype, src: ?std.builtin.SourceLocation) void {
            if (!self.dispatcher.enabled(level, self.scope_name)) return;

            var record = Record{
                .timestamp_us = std.time.microTimestamp(),
                .level = level,
                .scope_name = self.scope_name,
                .message = msg,
                .src = src,
                .prefix_attrs = self.prefix_attrs.constSlice(),
            };

            const AttrType = @TypeOf(attrs);
            const fields = @typeInfo(AttrType).@"struct".fields;
            inline for (fields) |f| {
                record.pushEventAttr(Attr.from(f.name, @field(attrs, f.name)));
            }

            self.dispatcher.emit(&record);
        }
    };
}

// ──────────────────────────── Tests ────────────────────────────

test "Dispatch processes record through pipeline" {
    const filter_mod = @import("filter.zig");
    const layout = @import("layout.zig");
    const append_mod = @import("append.zig");

    var level_filter = filter_mod.LevelFilter.init(.info);
    var ta = append_mod.TestingAppend(layout.TextLayout).init(std.testing.allocator, layout.TextLayout{});

    var d = Dispatch.init();
    d.addFilter(level_filter.any());
    d.addAppend(ta.any());

    var record = Record{
        .timestamp_us = 1234,
        .level = .info,
        .scope_name = rec.scopeName(.fork_choice),
        .message = "block applied",
    };
    record.pushEventAttr(Attr.uint("slot", 42));

    d.process(&record);
    try std.testing.expect(ta.contains("block applied"));
    try std.testing.expect(ta.contains("slot=42"));
}

test "Dispatch rejects below-level records" {
    const filter_mod = @import("filter.zig");
    const layout = @import("layout.zig");
    const append_mod = @import("append.zig");

    var level_filter = filter_mod.LevelFilter.init(.warn);
    var ta = append_mod.TestingAppend(layout.TextLayout).init(std.testing.allocator, layout.TextLayout{});

    var d = Dispatch.init();
    d.addFilter(level_filter.any());
    d.addAppend(ta.any());

    var record = Record{
        .timestamp_us = 1234,
        .level = .info,
        .scope_name = rec.scopeName(.default),
        .message = "should be filtered",
    };

    d.process(&record);
    try std.testing.expectEqualStrings("", ta.getOutput());
}

test "Dispatch with no filters accepts all" {
    const layout = @import("layout.zig");
    const append_mod = @import("append.zig");

    var ta = append_mod.TestingAppend(layout.TextLayout).init(std.testing.allocator, layout.TextLayout{});

    var d = Dispatch.init();
    d.addAppend(ta.any());

    var record = Record{
        .timestamp_us = 0,
        .level = .debug,
        .scope_name = rec.scopeName(.default),
        .message = "accepted",
    };

    d.process(&record);
    try std.testing.expect(ta.contains("accepted"));
}

test "Dispatch with multiple appenders fans out" {
    const layout = @import("layout.zig");
    const append_mod = @import("append.zig");

    var text_ta = append_mod.TestingAppend(layout.TextLayout).init(std.testing.allocator, layout.TextLayout{});
    var json_ta = append_mod.TestingAppend(layout.JsonLayout).init(std.testing.allocator, layout.JsonLayout{});

    var d = Dispatch.init();
    d.addAppend(text_ta.any());
    d.addAppend(json_ta.any());

    var record = Record{
        .timestamp_us = 1000,
        .level = .info,
        .scope_name = rec.scopeName(.default),
        .message = "multi",
    };

    d.process(&record);
    try std.testing.expect(text_ta.contains("multi"));
    try std.testing.expect(json_ta.contains("\"msg\":\"multi\""));
}

test "Dispatch enabled fast-path" {
    const filter_mod = @import("filter.zig");

    var level_filter = filter_mod.LevelFilter.init(.warn);

    var d = Dispatch.init();
    d.addFilter(level_filter.any());

    try std.testing.expect(d.enabled(.err, "").shouldProceed());
    try std.testing.expect(!d.enabled(.info, "").shouldProceed());
}

test "Dispatch diagnostics run before filters" {
    const diagnostic = @import("diagnostic.zig");
    const layout = @import("layout.zig");
    const append_mod = @import("append.zig");

    // A filter that accepts only if a "network" diagnostic attr is present.
    const DiagAttrFilter = struct {
        const Self = @This();

        pub fn enabled(_: Self, _: std.log.Level, _: []const u8) FilterResult {
            return .neutral;
        }
        pub fn matches(_: Self, record: *const Record) FilterResult {
            for (record.diag_attrs.constSlice()) |attr| {
                if (std.mem.eql(u8, attr.key, "network")) return .accept;
            }
            return .reject;
        }
        pub fn any(self: *Self) AnyFilter {
            return .{
                .ptr = @ptrCast(self),
                .enabled_fn = struct {
                    fn f(ptr: *anyopaque, level: std.log.Level, scope_name: []const u8) FilterResult {
                        const s: *const Self = @ptrCast(@alignCast(ptr));
                        return s.enabled(level, scope_name);
                    }
                }.f,
                .matches_fn = struct {
                    fn f(ptr: *anyopaque, record: *const Record) FilterResult {
                        const s: *const Self = @ptrCast(@alignCast(ptr));
                        return s.matches(record);
                    }
                }.f,
            };
        }
    };

    const SD = diagnostic.StaticDiagnostic(4);
    var diag = SD.init();
    diag.add(Attr.str("network", "mainnet"));

    var diag_filter = DiagAttrFilter{};
    var ta = append_mod.TestingAppend(layout.TextLayout).init(std.testing.allocator, layout.TextLayout{});

    var d = Dispatch.init();
    d.addDiagnostic(diag.any());
    d.addFilter(diag_filter.any());
    d.addAppend(ta.any());

    var record = Record{
        .timestamp_us = 0,
        .level = .info,
        .scope_name = rec.scopeName(.default),
        .message = "diag-before-filter test",
    };

    d.process(&record);
    try std.testing.expect(ta.contains("diag-before-filter test"));
}

test "AnyDispatcher emit calls through function pointer" {
    const S = struct {
        var called: bool = false;
        var captured_msg: []const u8 = "";

        fn testEmit(_: *anyopaque, record: *Record) void {
            called = true;
            captured_msg = record.message;
        }

        fn testFlush(_: *anyopaque) void {}
        fn testEnabled(_: *anyopaque, _: std.log.Level, _: []const u8) bool {
            return true;
        }

        var sentinel: u8 = 0;
    };

    const dispatcher = AnyDispatcher{
        .ptr = @ptrCast(&S.sentinel),
        .emit_fn = S.testEmit,
        .flush_fn = S.testFlush,
        .enabled_fn = S.testEnabled,
    };

    var record = Record{
        .timestamp_us = 1000,
        .level = .info,
        .scope_name = rec.scopeName(.default),
        .message = "hello",
    };
    dispatcher.emit(&record);

    try std.testing.expect(S.called);
    try std.testing.expectEqualStrings("hello", S.captured_msg);
}

test "AnyDispatcher.noop does not crash" {
    const dispatcher = AnyDispatcher.noop();

    var record = Record{
        .timestamp_us = 0,
        .level = .debug,
        .scope_name = rec.scopeName(.default),
        .message = "discarded",
    };
    dispatcher.emit(&record);
    dispatcher.flush();
    try std.testing.expect(!dispatcher.enabled(.debug, "default"));
}

test "Dispatcher fans out to multiple dispatches" {
    const filter_mod = @import("filter.zig");
    const layout = @import("layout.zig");
    const append_mod = @import("append.zig");

    var info_filter = filter_mod.LevelFilter.init(.info);
    var err_filter = filter_mod.LevelFilter.init(.err);
    var ta1 = append_mod.TestingAppend(layout.TextLayout).init(std.testing.allocator, layout.TextLayout{});
    var ta2 = append_mod.TestingAppend(layout.TextLayout).init(std.testing.allocator, layout.TextLayout{});

    var d1 = Dispatch.init();
    d1.addFilter(info_filter.any());
    d1.addAppend(ta1.any());

    var d2 = Dispatch.init();
    d2.addFilter(err_filter.any());
    d2.addAppend(ta2.any());

    var dispatcher = Dispatcher.init();
    dispatcher.addDispatch(d1);
    dispatcher.addDispatch(d2);

    var record = Record{
        .timestamp_us = 1000,
        .level = .info,
        .scope_name = rec.scopeName(.default),
        .message = "hello",
    };
    record.pushEventAttr(Attr.uint("slot", 1));

    dispatcher.emit(&record);

    try std.testing.expect(ta1.contains("hello"));
    try std.testing.expectEqualStrings("", ta2.getOutput());
}

test "Dispatcher enabled returns true if any pipeline accepts" {
    const filter_mod = @import("filter.zig");

    var err_filter = filter_mod.LevelFilter.init(.err);
    var debug_filter = filter_mod.LevelFilter.init(.debug);

    var d1 = Dispatch.init();
    d1.addFilter(err_filter.any());

    var d2 = Dispatch.init();
    d2.addFilter(debug_filter.any());

    var dispatcher = Dispatcher.init();
    dispatcher.addDispatch(d1);
    dispatcher.addDispatch(d2);

    try std.testing.expect(dispatcher.enabled(.info, ""));
    try std.testing.expect(dispatcher.enabled(.err, ""));
}

test "AnyDispatcher type-erases Dispatcher" {
    const filter_mod = @import("filter.zig");
    const layout = @import("layout.zig");
    const append_mod = @import("append.zig");

    var debug_filter = filter_mod.LevelFilter.init(.debug);
    var ta = append_mod.TestingAppend(layout.TextLayout).init(std.testing.allocator, layout.TextLayout{});

    var d = Dispatch.init();
    d.addFilter(debug_filter.any());
    d.addAppend(ta.any());

    var dispatcher = Dispatcher.init();
    dispatcher.addDispatch(d);

    var any_d = dispatcher.any();

    try std.testing.expect(any_d.enabled(.debug, "ssz"));

    var record = Record{
        .timestamp_us = 0,
        .level = .debug,
        .scope_name = rec.scopeName(.ssz),
        .message = "type erased",
    };

    any_d.emit(&record);
    try std.testing.expect(ta.contains("type erased"));
}

test "AnyDispatcher noop" {
    var noop_d = AnyDispatcher.noop();
    var record = Record{
        .timestamp_us = 0,
        .level = .err,
        .scope_name = "test",
        .message = "discarded",
    };
    noop_d.emit(&record);
    noop_d.flush();
    try std.testing.expect(!noop_d.enabled(.err, "test"));
}

test "Logger basic emit" {
    const S = struct {
        var last_message: []const u8 = "";
        var last_level: std.log.Level = .debug;
        var event_attr_count: usize = 0;

        fn emit(ptr: *anyopaque, record: *Record) void {
            _ = ptr;
            last_message = record.message;
            last_level = record.level;
            event_attr_count = record.event_attrs.len;
        }

        fn noopFlush(_: *anyopaque) void {}
        fn alwaysEnabled(_: *anyopaque, _: std.log.Level, _: []const u8) bool {
            return true;
        }

        var sentinel: u8 = 0;
    };

    const dispatcher = AnyDispatcher{
        .ptr = @ptrCast(&S.sentinel),
        .emit_fn = S.emit,
        .flush_fn = S.noopFlush,
        .enabled_fn = S.alwaysEnabled,
    };

    const log = Logger(4).init(.fork_choice, dispatcher);
    log.info("block applied", .{ .slot = @as(u64, 42) });

    try std.testing.expectEqualStrings("block applied", S.last_message);
    try std.testing.expectEqual(std.log.Level.info, S.last_level);
    try std.testing.expectEqual(@as(usize, 1), S.event_attr_count);
}

test "Logger.with creates child with prefix attrs" {
    const S = struct {
        var prefix_count: usize = 0;

        fn emit(ptr: *anyopaque, record: *Record) void {
            _ = ptr;
            prefix_count = record.prefix_attrs.len;
        }

        fn noopFlush(_: *anyopaque) void {}
        fn alwaysEnabled(_: *anyopaque, _: std.log.Level, _: []const u8) bool {
            return true;
        }

        var sentinel: u8 = 0;
    };

    const dispatcher = AnyDispatcher{
        .ptr = @ptrCast(&S.sentinel),
        .emit_fn = S.emit,
        .flush_fn = S.noopFlush,
        .enabled_fn = S.alwaysEnabled,
    };

    const parent = Logger(4).init(.ssz, dispatcher);
    const child = parent.with(&[_]Attr{Attr.str("module", "container")});

    child.info("something", .{});
    try std.testing.expectEqual(@as(usize, 1), S.prefix_count);
}

test "Logger with noop dispatcher" {
    const log = Logger(4).init(.default, AnyDispatcher.noop());
    log.debug("discarded", .{});
    log.err("also discarded", .{ .code = @as(u64, 500) });
    log.flush();
}

test "Logger enabled pre-check skips emit" {
    const S = struct {
        var emit_count: usize = 0;

        fn emit(ptr: *anyopaque, _: *Record) void {
            _ = ptr;
            emit_count += 1;
        }

        fn noopFlush(_: *anyopaque) void {}
        fn errOnly(_: *anyopaque, level: std.log.Level, _: []const u8) bool {
            return level == .err;
        }

        var sentinel: u8 = 0;
    };

    const dispatcher = AnyDispatcher{
        .ptr = @ptrCast(&S.sentinel),
        .emit_fn = S.emit,
        .flush_fn = S.noopFlush,
        .enabled_fn = S.errOnly,
    };

    S.emit_count = 0;
    const log = Logger(4).init(.default, dispatcher);
    log.debug("skip", .{});
    log.info("skip", .{});
    log.warn("skip", .{});
    log.err("this one", .{});

    try std.testing.expectEqual(@as(usize, 1), S.emit_count);
}

test "Logger logSrc captures source location" {
    const S = struct {
        var captured_src: ?std.builtin.SourceLocation = null;

        fn emit(ptr: *anyopaque, record: *Record) void {
            _ = ptr;
            captured_src = record.src;
        }

        fn noopFlush(_: *anyopaque) void {}
        fn alwaysEnabled(_: *anyopaque, _: std.log.Level, _: []const u8) bool {
            return true;
        }

        var sentinel: u8 = 0;
    };

    const dispatcher = AnyDispatcher{
        .ptr = @ptrCast(&S.sentinel),
        .emit_fn = S.emit,
        .flush_fn = S.noopFlush,
        .enabled_fn = S.alwaysEnabled,
    };

    const log = Logger(4).init(.default, dispatcher);
    log.logSrc(.info, "with source", .{}, @src());

    try std.testing.expect(S.captured_src != null);
    try std.testing.expect(S.captured_src.?.line > 0);
}

// ──────── Integration: multi-appender fan-out with AsyncAppend ────────

test "Dispatch fans out to sync and async appenders" {
    const layout = @import("layout.zig");
    const append = @import("append.zig");
    const filter = @import("filter.zig");

    var debug_filter = filter.LevelFilter.init(.debug);
    var text_ta = append.TestingAppend(layout.TextLayout).init(std.testing.allocator, layout.TextLayout{});

    var json_out = std.ArrayList(u8).init(std.testing.allocator);
    defer json_out.deinit();

    var async_appender = try append.AsyncAppend(layout.JsonLayout).init(
        std.testing.allocator,
        16,
        append.FlushableWriter.noFlush(json_out.writer().any()),
        layout.JsonLayout{},
        .block,
    );
    try async_appender.start();

    var d = Dispatch.init();
    d.addFilter(debug_filter.any());
    d.addAppend(text_ta.any());
    d.addAppend(async_appender.any());

    var record = Record{
        .timestamp_us = 1234,
        .level = .info,
        .scope_name = rec.scopeName(.fork_choice),
        .message = "fan-out test",
    };
    record.pushEventAttr(Attr.uint("slot", 42));

    d.process(&record);

    std.time.sleep(50_000_000);

    // Sync appender (TextLayout) got the message.
    try std.testing.expect(text_ta.contains("fan-out test"));
    try std.testing.expect(text_ta.contains("slot=42"));

    async_appender.deinit();

    // Async appender (JsonLayout) also got the message.
    const json_output = json_out.items;
    try std.testing.expect(std.mem.indexOf(u8, json_output, "\"msg\":\"fan-out test\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_output, "\"slot\":42") != null);
}

// ──────── Integration: multi-pipeline scope routing ────────

test "Dispatcher routes scopes to different pipelines" {
    const layout = @import("layout.zig");
    const append = @import("append.zig");

    // Scope whitelist filter: accepts only the configured scope, rejects others.
    const ScopeWhitelist = struct {
        const Self = @This();

        scope: []const u8,

        pub fn enabled(self: Self, _: std.log.Level, scope_name: []const u8) FilterResult {
            return if (std.mem.eql(u8, scope_name, self.scope)) .accept else .reject;
        }

        pub fn matches(self: Self, record: *const Record) FilterResult {
            return self.enabled(record.level, record.scope_name);
        }

        pub fn any(self: *Self) AnyFilter {
            return .{
                .ptr = @ptrCast(self),
                .enabled_fn = struct {
                    fn f(ptr: *anyopaque, level: std.log.Level, scope_name: []const u8) FilterResult {
                        const s: *const Self = @ptrCast(@alignCast(ptr));
                        return s.enabled(level, scope_name);
                    }
                }.f,
                .matches_fn = struct {
                    fn f(ptr: *anyopaque, record: *const Record) FilterResult {
                        const s: *const Self = @ptrCast(@alignCast(ptr));
                        return s.matches(record);
                    }
                }.f,
            };
        }
    };

    var fc_filter = ScopeWhitelist{ .scope = rec.scopeName(.fork_choice) };
    var ssz_filter = ScopeWhitelist{ .scope = rec.scopeName(.ssz) };
    var text_ta = append.TestingAppend(layout.TextLayout).init(std.testing.allocator, layout.TextLayout{});
    var json_ta = append.TestingAppend(layout.JsonLayout).init(std.testing.allocator, layout.JsonLayout{});

    // Pipeline 1: fork_choice scope → TextLayout
    var d1 = Dispatch.init();
    d1.addFilter(fc_filter.any());
    d1.addAppend(text_ta.any());

    // Pipeline 2: ssz scope → JsonLayout
    var d2 = Dispatch.init();
    d2.addFilter(ssz_filter.any());
    d2.addAppend(json_ta.any());

    var dispatcher = Dispatcher.init();
    dispatcher.addDispatch(d1);
    dispatcher.addDispatch(d2);

    // Emit fork_choice record.
    var fc_record = Record{
        .timestamp_us = 1000,
        .level = .info,
        .scope_name = rec.scopeName(.fork_choice),
        .message = "block applied",
    };
    dispatcher.emit(&fc_record);

    // Emit ssz record.
    var ssz_record = Record{
        .timestamp_us = 2000,
        .level = .warn,
        .scope_name = rec.scopeName(.ssz),
        .message = "invalid encoding",
    };
    dispatcher.emit(&ssz_record);

    // fork_choice pipeline got only fork_choice message (TextLayout).
    try std.testing.expect(text_ta.contains("block applied"));
    try std.testing.expect(!text_ta.contains("invalid encoding"));

    // ssz pipeline got only ssz message (JsonLayout).
    try std.testing.expect(json_ta.contains("\"msg\":\"invalid encoding\""));
    try std.testing.expect(!json_ta.contains("block applied"));
}

// ──────── Integration: multi-thread concurrent emit ────────

test "Dispatcher handles concurrent multi-thread emit" {
    const layout = @import("layout.zig");
    const append = @import("append.zig");
    const filter = @import("filter.zig");

    var out_list = std.ArrayList(u8).init(std.testing.allocator);
    defer out_list.deinit();

    var debug_filter = filter.LevelFilter.init(.debug);
    var async_appender = try append.AsyncAppend(layout.TextLayout).init(
        std.testing.allocator,
        64,
        append.FlushableWriter.noFlush(out_list.writer().any()),
        layout.TextLayout{},
        .block,
    );
    try async_appender.start();

    var d = Dispatch.init();
    d.addFilter(debug_filter.any());
    d.addAppend(async_appender.any());

    var dispatcher = Dispatcher.init();
    dispatcher.addDispatch(d);

    const num_threads: usize = 4;
    const msgs_per_thread: usize = 50;

    var threads: [num_threads]std.Thread = undefined;
    for (&threads, 0..) |*t, tid| {
        t.* = try std.Thread.spawn(.{}, struct {
            fn run(disp: *Dispatcher, thread_id: usize, count: usize) void {
                for (0..count) |i| {
                    var buf: [64]u8 = undefined;
                    const msg = std.fmt.bufPrint(&buf, "t{d}-m{d}", .{ thread_id, i }) catch "?";
                    var record = Record{
                        .timestamp_us = @as(i64, @intCast(thread_id * count + i)),
                        .level = .info,
                        .scope_name = rec.scopeName(.default),
                        .message = msg,
                    };
                    disp.emit(&record);
                }
            }
        }.run, .{ &dispatcher, tid, msgs_per_thread });
    }

    for (&threads) |*t| t.join();

    std.time.sleep(100_000_000);
    async_appender.deinit();

    const output = out_list.items;
    // Verify at least some messages from each thread arrived.
    for (0..num_threads) |tid| {
        var buf: [16]u8 = undefined;
        const pattern = std.fmt.bufPrint(&buf, "t{d}-m0", .{tid}) catch "?";
        try std.testing.expect(std.mem.indexOf(u8, output, pattern) != null);
    }
    // Verify total output is non-trivial (not just a few msgs).
    try std.testing.expect(output.len > 1000);
}

// ──────── Integration: EnvFilter in Dispatch pipeline ────────

test "EnvFilter integrated into Dispatch pipeline" {
    const layout = @import("layout.zig");
    const append = @import("append.zig");
    const filter = @import("filter.zig");

    var env_filter = filter.parse("warn,fork_choice=debug").?;
    var ta = append.TestingAppend(layout.TextLayout).init(std.testing.allocator, layout.TextLayout{});

    var pipeline = Dispatch.init();
    pipeline.addFilter(env_filter.any());
    pipeline.addAppend(ta.any());

    // info from default scope → rejected (below warn threshold).
    var info_default = Record{
        .timestamp_us = 1000,
        .level = .info,
        .scope_name = rec.scopeName(.default),
        .message = "should be rejected",
    };
    pipeline.process(&info_default);
    try std.testing.expect(!ta.contains("should be rejected"));

    // warn from default scope → accepted.
    var warn_default = Record{
        .timestamp_us = 2000,
        .level = .warn,
        .scope_name = rec.scopeName(.default),
        .message = "warn passes",
    };
    pipeline.process(&warn_default);
    try std.testing.expect(ta.contains("warn passes"));

    // debug from fork_choice → accepted (scope override trumps base level).
    var debug_fc = Record{
        .timestamp_us = 3000,
        .level = .debug,
        .scope_name = rec.scopeName(.fork_choice),
        .message = "fc debug passes",
    };
    pipeline.process(&debug_fc);
    try std.testing.expect(ta.contains("fc debug passes"));

    // warn from fork_choice → accepted (above scope override threshold).
    var warn_fc = Record{
        .timestamp_us = 4000,
        .level = .warn,
        .scope_name = rec.scopeName(.fork_choice),
        .message = "fc warn passes",
    };
    pipeline.process(&warn_fc);
    try std.testing.expect(ta.contains("fc warn passes"));

    // err from any scope → accepted (above all thresholds).
    var err_default = Record{
        .timestamp_us = 5000,
        .level = .err,
        .scope_name = rec.scopeName(.ssz),
        .message = "error always passes",
    };
    pipeline.process(&err_default);
    try std.testing.expect(ta.contains("error always passes"));
}

// ──────── Integration: short-circuit filter semantics ────────

test "Short-circuit: ScopeFilter accept overrides LevelFilter reject" {
    const layout = @import("layout.zig");
    const append = @import("append.zig");
    const filter = @import("filter.zig");

    var scope_filter = filter.ScopeFilter.init();
    scope_filter.addOverride(rec.scopeName(.fork_choice), .debug);

    var level_filter = filter.LevelFilter.init(.warn);
    var ta = append.TestingAppend(layout.TextLayout).init(std.testing.allocator, layout.TextLayout{});

    var pipeline = Dispatch.init();
    pipeline.addFilter(scope_filter.any());
    pipeline.addFilter(level_filter.any());
    pipeline.addAppend(ta.any());

    // debug from fork_choice → ScopeFilter accepts (scope match) → short-circuits → passes
    var debug_fc = Record{
        .timestamp_us = 1000,
        .level = .debug,
        .scope_name = rec.scopeName(.fork_choice),
        .message = "scope override passes",
    };
    pipeline.process(&debug_fc);
    try std.testing.expect(ta.contains("scope override passes"));

    // debug from default → ScopeFilter neutral → LevelFilter rejects → blocked
    var debug_default = Record{
        .timestamp_us = 2000,
        .level = .debug,
        .scope_name = rec.scopeName(.default),
        .message = "should be blocked",
    };
    pipeline.process(&debug_default);
    try std.testing.expect(!ta.contains("should be blocked"));

    // warn from default → ScopeFilter neutral → LevelFilter accepts → passes
    var warn_default = Record{
        .timestamp_us = 3000,
        .level = .warn,
        .scope_name = rec.scopeName(.default),
        .message = "warn passes base",
    };
    pipeline.process(&warn_default);
    try std.testing.expect(ta.contains("warn passes base"));

    // enabled() also short-circuits
    try std.testing.expect(pipeline.enabled(.debug, rec.scopeName(.fork_choice)).shouldProceed());
    try std.testing.expect(!pipeline.enabled(.debug, rec.scopeName(.default)).shouldProceed());
}
