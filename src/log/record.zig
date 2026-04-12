//! Foundation types for the logging pipeline.
//!
//! Contains the core data model (Scope, Level, Attr, Record) and comptime
//! interface validation (FilterResult, isXxx, assertXxx).
//!
//! This module has ZERO intra-log dependencies — it only imports std.
//! All other log/ modules import record.zig, making it the foundation layer.

const std = @import("std");

// ──────────────────────────── Scope ────────────────────────────

/// Log scope — wraps an enum literal, consistent with std.log.scoped().
/// Usage: `const scope: Scope = .fork_choice;`
pub const Scope = @TypeOf(.enum_literal);

/// Returns the string name of a scope. `.default` → "default".
pub fn scopeName(scope: Scope) []const u8 {
    return @tagName(scope);
}

// ──────────────────────────── Level ────────────────────────────

pub const Level = std.log.Level;

/// Returns the human-readable name for a log level (padded to 5 chars).
pub fn asText(level: Level) []const u8 {
    return switch (level) {
        .err => "error",
        .warn => "warn ",
        .info => "info ",
        .debug => "debug",
    };
}

/// Case-insensitive level parser. Returns null for unknown input.
/// Accepts: err, error, warn, warning, info, debug.
pub fn parseLevel(text: []const u8) ?Level {
    var buf: [8]u8 = undefined;
    if (text.len == 0 or text.len >= buf.len) return null;
    for (text, 0..) |c, i| buf[i] = std.ascii.toLower(c);
    const lower = buf[0..text.len];

    if (std.mem.eql(u8, lower, "err")) return .err;
    if (std.mem.eql(u8, lower, "error")) return .err;
    if (std.mem.eql(u8, lower, "warn")) return .warn;
    if (std.mem.eql(u8, lower, "warning")) return .warn;
    if (std.mem.eql(u8, lower, "info")) return .info;
    if (std.mem.eql(u8, lower, "debug")) return .debug;
    return null;
}

// ───────────────────────────── Attr ─────────────────────────────

/// Structured key-value attribute for log records.
pub const Attr = struct {
    key: []const u8,
    value: Value,

    pub const Value = union(enum) {
        int: i64,
        uint: u64,
        float: f64,
        bool_val: bool,
        string: []const u8,
        /// For Ethereum hashes, pubkeys etc. Rendered as 0x-prefixed hex.
        hex_bytes: []const u8,
    };

    pub fn int(key: []const u8, val: i64) Attr {
        return .{ .key = key, .value = .{ .int = val } };
    }

    pub fn uint(key: []const u8, val: u64) Attr {
        return .{ .key = key, .value = .{ .uint = val } };
    }

    pub fn float(key: []const u8, val: f64) Attr {
        return .{ .key = key, .value = .{ .float = val } };
    }

    pub fn boolean(key: []const u8, val: bool) Attr {
        return .{ .key = key, .value = .{ .bool_val = val } };
    }

    pub fn str(key: []const u8, val: []const u8) Attr {
        return .{ .key = key, .value = .{ .string = val } };
    }

    pub fn hex(key: []const u8, val: []const u8) Attr {
        return .{ .key = key, .value = .{ .hex_bytes = val } };
    }

    /// Auto-convert a comptime-known field name + runtime value to an Attr.
    pub fn from(comptime key: []const u8, val: anytype) Attr {
        const T = @TypeOf(val);
        return switch (@typeInfo(T)) {
            .bool => .{ .key = key, .value = .{ .bool_val = val } },
            .int, .comptime_int => blk: {
                if (@typeInfo(T) == .comptime_int) {
                    if (val < 0) {
                        break :blk .{ .key = key, .value = .{ .int = @intCast(val) } };
                    } else {
                        break :blk .{ .key = key, .value = .{ .uint = @intCast(val) } };
                    }
                }
                const info = @typeInfo(T).int;
                if (info.signedness == .signed) {
                    break :blk .{ .key = key, .value = .{ .int = @intCast(val) } };
                } else {
                    break :blk .{ .key = key, .value = .{ .uint = @intCast(val) } };
                }
            },
            .float, .comptime_float => .{ .key = key, .value = .{ .float = @floatCast(val) } },
            .pointer => |ptr| {
                if (ptr.size == .slice and ptr.child == u8) {
                    return .{ .key = key, .value = .{ .string = val } };
                }
                if (ptr.size == .one) {
                    const child_info = @typeInfo(ptr.child);
                    if (child_info == .array and child_info.array.child == u8) {
                        return .{ .key = key, .value = .{ .string = val } };
                    }
                }
                @compileError("Unsupported pointer type for Attr.from: " ++ @typeName(T));
            },
            .@"enum" => .{ .key = key, .value = .{ .string = @tagName(val) } },
            else => {
                if (T == Attr) return val;
                @compileError("Unsupported type for Attr.from: " ++ @typeName(T));
            },
        };
    }

    /// Format the value into a writer. Used by layouts.
    pub fn formatValue(self: *const Attr, writer: anytype) void {
        switch (self.value) {
            .int => |v| writer.print("{d}", .{v}) catch {},
            .uint => |v| writer.print("{d}", .{v}) catch {},
            .float => |v| writer.print("{d:.6}", .{v}) catch {},
            .bool_val => |v| writer.print("{}", .{v}) catch {},
            .string => |v| writer.print("{s}", .{v}) catch {},
            .hex_bytes => |v| {
                writer.writeAll("0x") catch {};
                for (v) |byte| {
                    writer.print("{x:0>2}", .{byte}) catch {};
                }
            },
        }
    }
};

// ──────────────────────────── Record ────────────────────────────

/// Maximum number of diagnostic attributes per record.
pub const max_diag_attrs = 16;
/// Maximum number of per-event attributes per record.
pub const max_event_attrs = 32;

/// One log event. Created on the stack by Logger, passed through the pipeline.
pub const Record = struct {
    timestamp_us: i64,
    level: Level,
    /// Scope stored as its string name (Scope is comptime-only).
    scope_name: []const u8,
    message: []const u8,

    /// Source location of the log call site (file, line, function).
    src: ?std.builtin.SourceLocation = null,

    /// Pre-bound attributes from Logger.with() chain. Borrowed slice — owned by Logger.
    prefix_attrs: []const Attr = &.{},

    /// Per-event attributes from the log call site.
    event_attrs: std.BoundedArray(Attr, max_event_attrs) = .{},

    /// Diagnostic attributes injected by the Dispatch pipeline's Diagnostic stage.
    diag_attrs: std.BoundedArray(Attr, max_diag_attrs) = .{},

    /// Push a per-event attribute.
    pub fn pushEventAttr(self: *Record, attr: Attr) void {
        self.event_attrs.append(attr) catch {};
    }

    /// Push a diagnostic attribute (called by Diagnostic implementations).
    pub fn pushDiagAttr(self: *Record, attr: Attr) void {
        self.diag_attrs.append(attr) catch {};
    }

    /// Iterate all attributes in order: prefix → event → diagnostic.
    pub fn attrIterator(self: *const Record) AttrIterator {
        return .{ .record = self, .phase = .prefix, .index = 0 };
    }

    pub const AttrIterator = struct {
        record: *const Record,
        phase: enum { prefix, event, diag } = .prefix,
        index: usize = 0,

        pub fn next(self: *AttrIterator) ?Attr {
            while (true) {
                switch (self.phase) {
                    .prefix => {
                        if (self.index < self.record.prefix_attrs.len) {
                            const attr = self.record.prefix_attrs[self.index];
                            self.index += 1;
                            return attr;
                        }
                        self.phase = .event;
                        self.index = 0;
                    },
                    .event => {
                        if (self.index < self.record.event_attrs.len) {
                            const attr = self.record.event_attrs.constSlice()[self.index];
                            self.index += 1;
                            return attr;
                        }
                        self.phase = .diag;
                        self.index = 0;
                    },
                    .diag => {
                        if (self.index < self.record.diag_attrs.len) {
                            const attr = self.record.diag_attrs.constSlice()[self.index];
                            self.index += 1;
                            return attr;
                        }
                        return null;
                    },
                }
            }
        }
    };
};

// ────────────────────── FilterResult & Checks ──────────────────────

/// Three-way filter result matching logforth's FilterResult.
///
/// - `accept`:  explicitly accept the record.
/// - `reject`:  explicitly reject the record.
/// - `neutral`: no opinion — defer to other filters.
///
/// Folding semantics (via `combine`):
///   Reject beats everything; Accept beats Neutral; all-Neutral → accept.
pub const FilterResult = enum {
    accept,
    reject,
    neutral,

    /// Combine two results using strict AND semantics.
    /// Deprecated: Dispatch now uses short-circuit (first non-neutral wins)
    /// instead of combine-fold. Kept for external callers if needed.
    pub fn combine(self: FilterResult, other: FilterResult) FilterResult {
        if (self == .reject or other == .reject) return .reject;
        if (self == .accept or other == .accept) return .accept;
        return .neutral;
    }

    /// Convert to bool for the final gate decision.
    /// Both `.accept` and `.neutral` pass; only `.reject` blocks.
    pub fn shouldProceed(self: FilterResult) bool {
        return self != .reject;
    }
};

pub fn hasDeclSafe(comptime T: type, comptime name: []const u8) bool {
    return switch (@typeInfo(T)) {
        .@"struct", .@"union", .@"enum", .@"opaque" => @hasDecl(T, name),
        else => false,
    };
}

/// Validates that T satisfies the Filter interface.
pub fn isFilter(comptime T: type) bool {
    return hasDeclSafe(T, "enabled") and hasDeclSafe(T, "matches");
}

/// Validates that T satisfies the Diagnostic interface.
pub fn isDiagnostic(comptime T: type) bool {
    return hasDeclSafe(T, "enrich");
}

/// Validates that T satisfies the Layout interface.
pub fn isLayout(comptime T: type) bool {
    return hasDeclSafe(T, "format");
}

/// Validates that T satisfies the Append interface.
pub fn isAppend(comptime T: type) bool {
    return hasDeclSafe(T, "append") and hasDeclSafe(T, "flush");
}

pub fn assertFilter(comptime T: type) void {
    if (!isFilter(T)) {
        @compileError(@typeName(T) ++ " does not satisfy the Filter interface. " ++
            "Required: pub fn enabled(self, level, scope_name) FilterResult, " ++
            "pub fn matches(self, record) FilterResult");
    }
}

pub fn assertDiagnostic(comptime T: type) void {
    if (!isDiagnostic(T)) {
        @compileError(@typeName(T) ++ " does not satisfy the Diagnostic interface. " ++
            "Required: pub fn enrich(self: *const Self, record: *Record) void");
    }
}

pub fn assertLayout(comptime T: type) void {
    if (!isLayout(T)) {
        @compileError(@typeName(T) ++ " does not satisfy the Layout interface. " ++
            "Required: pub fn format(self: *const Self, record: *const Record, writer: anytype) void");
    }
}

pub fn assertAppend(comptime T: type) void {
    if (!isAppend(T)) {
        @compileError(@typeName(T) ++ " does not satisfy the Append interface. " ++
            "Required: pub fn append(self: *Self, record: *const Record) void, " ++
            "pub fn flush(self: *Self) void");
    }
}

// ──────────────────────────── Tests ────────────────────────────

test "scopeName" {
    try std.testing.expectEqualStrings("fork_choice", scopeName(.fork_choice));
    try std.testing.expectEqualStrings("default", scopeName(.default));
    try std.testing.expectEqualStrings("ssz", scopeName(.ssz));
}

test "asText returns padded names" {
    try std.testing.expectEqualStrings("error", asText(.err));
    try std.testing.expectEqualStrings("warn ", asText(.warn));
    try std.testing.expectEqualStrings("info ", asText(.info));
    try std.testing.expectEqualStrings("debug", asText(.debug));
}

test "parseLevel" {
    try std.testing.expectEqual(Level.err, parseLevel("error").?);
    try std.testing.expectEqual(Level.warn, parseLevel("warn").?);
    try std.testing.expectEqual(Level.info, parseLevel("info").?);
    try std.testing.expectEqual(Level.debug, parseLevel("debug").?);
    try std.testing.expectEqual(Level.err, parseLevel("ERROR").?);
    try std.testing.expectEqual(Level.err, parseLevel("err").?);
    try std.testing.expectEqual(Level.warn, parseLevel("warning").?);
    try std.testing.expect(parseLevel("") == null);
    try std.testing.expect(parseLevel("verbose") == null);
    try std.testing.expect(parseLevel("toolongstring") == null);
}

test "Attr convenience constructors" {
    const a = Attr.int("slot", 42);
    try std.testing.expectEqualStrings("slot", a.key);
    try std.testing.expectEqual(@as(i64, 42), a.value.int);

    const b = Attr.uint("epoch", 123);
    try std.testing.expectEqual(@as(u64, 123), b.value.uint);

    const c = Attr.str("module", "fork_choice");
    try std.testing.expectEqualStrings("fork_choice", c.value.string);

    const d = Attr.boolean("justified", true);
    try std.testing.expect(d.value.bool_val);
}

test "Attr.from auto-conversion" {
    const a = Attr.from("x", @as(i32, -5));
    try std.testing.expectEqual(@as(i64, -5), a.value.int);

    const b = Attr.from("y", @as(u64, 42));
    try std.testing.expectEqual(@as(u64, 42), b.value.uint);

    const c = Attr.from("ok", true);
    try std.testing.expect(c.value.bool_val);

    const s: []const u8 = "hello";
    const d = Attr.from("msg", s);
    try std.testing.expectEqualStrings("hello", d.value.string);

    const e = Attr.from("lit", "world");
    try std.testing.expectEqualStrings("world", e.value.string);

    const f = Attr.from("level", std.log.Level.info);
    try std.testing.expectEqualStrings("info", f.value.string);
}

test "Attr.formatValue" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const writer = fbs.writer();

    const a = Attr.uint("slot", 42);
    a.formatValue(writer);
    try std.testing.expectEqualStrings("42", fbs.getWritten());

    fbs.reset();
    const b = Attr.hex("root", &[_]u8{ 0xde, 0xad });
    b.formatValue(writer);
    try std.testing.expectEqualStrings("0xdead", fbs.getWritten());
}

test "Record attrIterator" {
    const prefix = [_]Attr{Attr.str("module", "fc")};
    var record = Record{
        .timestamp_us = 1000,
        .level = .info,
        .scope_name = scopeName(.fork_choice),
        .message = "test",
        .prefix_attrs = &prefix,
    };
    record.pushEventAttr(Attr.uint("slot", 42));
    record.pushDiagAttr(Attr.str("node", "abc"));

    var iter = record.attrIterator();
    const a1 = iter.next().?;
    try std.testing.expectEqualStrings("module", a1.key);
    const a2 = iter.next().?;
    try std.testing.expectEqualStrings("slot", a2.key);
    const a3 = iter.next().?;
    try std.testing.expectEqualStrings("node", a3.key);
    try std.testing.expect(iter.next() == null);
}

test "Record defaults" {
    const r = Record{
        .timestamp_us = 0,
        .level = .debug,
        .scope_name = scopeName(.default),
        .message = "hello",
    };
    try std.testing.expectEqual(@as(usize, 0), r.prefix_attrs.len);
    try std.testing.expectEqual(@as(usize, 0), r.event_attrs.len);
    try std.testing.expectEqual(@as(usize, 0), r.diag_attrs.len);
}

const MockFilter = struct {
    pub fn enabled(_: @This(), _: std.log.Level, _: []const u8) FilterResult {
        return .accept;
    }
    pub fn matches(_: @This(), _: *const Record) FilterResult {
        return .neutral;
    }
};

const MockDiagnostic = struct {
    pub fn enrich(_: *@This(), _: *Record) void {}
};

const MockLayout = struct {
    pub fn format(_: *const @This(), _: *const Record, _: anytype) void {}
};

const MockAppend = struct {
    pub fn append(_: *@This(), _: *const Record) void {}
    pub fn flush(_: *@This()) void {}
};

const NotAFilter = struct {
    x: u32 = 0,
};

test "isFilter accepts valid Filter and rejects non-Filter" {
    try std.testing.expect(isFilter(MockFilter));
    try std.testing.expect(!isFilter(NotAFilter));
    try std.testing.expect(!isFilter(u32));
}

test "isDiagnostic accepts valid Diagnostic and rejects non-Diagnostic" {
    try std.testing.expect(isDiagnostic(MockDiagnostic));
    try std.testing.expect(!isDiagnostic(NotAFilter));
}

test "isLayout accepts valid Layout and rejects non-Layout" {
    try std.testing.expect(isLayout(MockLayout));
    try std.testing.expect(!isLayout(NotAFilter));
}

test "isAppend accepts valid Append and rejects non-Append" {
    try std.testing.expect(isAppend(MockAppend));
    try std.testing.expect(!isAppend(NotAFilter));
}

test "FilterResult combine semantics" {
    try std.testing.expectEqual(FilterResult.reject, FilterResult.reject.combine(.accept));
    try std.testing.expectEqual(FilterResult.reject, FilterResult.accept.combine(.reject));
    try std.testing.expectEqual(FilterResult.reject, FilterResult.reject.combine(.neutral));
    try std.testing.expectEqual(FilterResult.reject, FilterResult.neutral.combine(.reject));
    try std.testing.expectEqual(FilterResult.accept, FilterResult.accept.combine(.neutral));
    try std.testing.expectEqual(FilterResult.accept, FilterResult.neutral.combine(.accept));
    try std.testing.expectEqual(FilterResult.accept, FilterResult.accept.combine(.accept));
    try std.testing.expectEqual(FilterResult.neutral, FilterResult.neutral.combine(.neutral));
}

test "FilterResult shouldProceed" {
    try std.testing.expect(FilterResult.accept.shouldProceed());
    try std.testing.expect(FilterResult.neutral.shouldProceed());
    try std.testing.expect(!FilterResult.reject.shouldProceed());
}
