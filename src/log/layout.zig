//! Layout formatters for the logging pipeline.
//!
//! Layouts convert a Record into a byte representation for output.
//! Each appender owns its own Layout instance.

const std = @import("std");
const epoch = std.time.epoch;
const rec = @import("record.zig");
const Record = rec.Record;
const Attr = rec.Attr;

// ───────────────── Timestamp Formatting ──────────────────────

/// Format a microsecond epoch timestamp as ISO 8601 UTC.
/// Output: `2024-08-11T22:44:57.172105Z` (27 bytes).
fn formatTimestamp(writer: anytype, timestamp_us: i64) void {
    if (timestamp_us < 0) {
        writer.print("{d}", .{timestamp_us}) catch return;
        return;
    }
    const us: u64 = @intCast(timestamp_us);
    const secs = us / 1_000_000;
    const micros: u32 = @intCast(us % 1_000_000);

    const es = epoch.EpochSeconds{ .secs = secs };
    const day = es.getEpochDay().calculateYearDay();
    const md = day.calculateMonthDay();
    const ds = es.getDaySeconds();

    writer.print("{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>6}Z", .{
        day.year,
        md.month.numeric(),
        @as(u16, md.day_index) + 1,
        ds.getHoursIntoDay(),
        ds.getMinutesIntoHour(),
        ds.getSecondsIntoMinute(),
        micros,
    }) catch return;
}

// ──────────────────────── TextLayout ────────────────────────

/// Human-readable text layout.
/// Format: `<ISO8601> <level> (<scope>): <message> key=value ...\n`
/// When `color` is true, the level text is wrapped in ANSI escape codes.
pub const TextLayout = struct {
    /// Enable ANSI color codes for level text. Default false for test compatibility.
    color: bool = false,

    const ansi_reset = "\x1b[0m";

    fn levelColor(level: std.log.Level) []const u8 {
        return switch (level) {
            .err => "\x1b[31m", // red
            .warn => "\x1b[33m", // yellow
            .info => "\x1b[32m", // green
            .debug => "\x1b[90m", // bright black (gray)
        };
    }

    pub fn format(self: *const TextLayout, record: *const Record, writer: anytype) void {
        formatTimestamp(writer, record.timestamp_us);
        writer.writeByte(' ') catch return;

        if (self.color) {
            writer.writeAll(levelColor(record.level)) catch return;
            writer.writeAll(rec.asText(record.level)) catch return;
            writer.writeAll(ansi_reset) catch return;
        } else {
            writer.writeAll(rec.asText(record.level)) catch return;
        }
        writer.writeByte(' ') catch return;

        if (!std.mem.eql(u8, record.scope_name, "default")) {
            writer.writeByte('(') catch return;
            writer.writeAll(record.scope_name) catch return;
            writer.writeAll("): ") catch return;
        } else {
            writer.writeAll(": ") catch return;
        }

        writer.writeAll(record.message) catch return;

        var iter = record.attrIterator();
        while (iter.next()) |attr| {
            writer.writeByte(' ') catch return;
            writer.writeAll(attr.key) catch return;
            writer.writeByte('=') catch return;
            attr.formatValue(writer);
        }

        writer.writeByte('\n') catch return;
    }
};

// ──────────────────────── JsonLayout ────────────────────────

/// JSON lines layout. Each record is a single JSON object followed by \n.
/// Format: {"ts":"2024-08-11T22:44:57.172Z","level":"info","scope":"fork_choice","msg":"block applied","slot":42}
pub const JsonLayout = struct {
    pub fn format(_: *const JsonLayout, record: *const Record, writer: anytype) void {
        writer.writeAll("{\"ts\":\"") catch return;
        formatTimestamp(writer, record.timestamp_us);
        writer.writeAll("\"") catch return;

        writer.writeAll(",\"level\":\"") catch return;
        writer.writeAll(std.mem.trimRight(u8, rec.asText(record.level), " ")) catch return;
        writer.writeAll("\"") catch return;

        if (!std.mem.eql(u8, record.scope_name, "default")) {
            writer.writeAll(",\"scope\":\"") catch return;
            writer.writeAll(record.scope_name) catch return;
            writer.writeAll("\"") catch return;
        }

        writer.writeAll(",\"msg\":\"") catch return;
        writeJsonEscaped(writer, record.message);
        writer.writeAll("\"") catch return;

        var iter = record.attrIterator();
        while (iter.next()) |attr| {
            writer.writeAll(",\"") catch return;
            writer.writeAll(attr.key) catch return;
            writer.writeAll("\":") catch return;
            writeJsonValue(writer, attr.value);
        }

        writer.writeAll("}\n") catch return;
    }

    fn writeJsonValue(writer: anytype, value: Attr.Value) void {
        switch (value) {
            .int => |v| writer.print("{d}", .{v}) catch {},
            .uint => |v| writer.print("{d}", .{v}) catch {},
            .float => |v| writer.print("{d:.6}", .{v}) catch {},
            .bool_val => |v| writer.print("{}", .{v}) catch {},
            .string => |v| {
                writer.writeByte('"') catch {};
                writeJsonEscaped(writer, v);
                writer.writeByte('"') catch {};
            },
            .hex_bytes => |v| {
                writer.writeAll("\"0x") catch {};
                for (v) |byte| {
                    writer.print("{x:0>2}", .{byte}) catch {};
                }
                writer.writeByte('"') catch {};
            },
        }
    }

    fn writeJsonEscaped(writer: anytype, s: []const u8) void {
        for (s) |c| {
            switch (c) {
                '"' => writer.writeAll("\\\"") catch {},
                '\\' => writer.writeAll("\\\\") catch {},
                '\n' => writer.writeAll("\\n") catch {},
                '\r' => writer.writeAll("\\r") catch {},
                '\t' => writer.writeAll("\\t") catch {},
                else => {
                    if (c < 0x20) {
                        writer.print("\\u{x:0>4}", .{c}) catch {};
                    } else {
                        writer.writeByte(c) catch {};
                    }
                },
            }
        }
    }
};

// ──────────────────────── LogfmtLayout ──────────────────────

/// Logfmt layout (Heroku/12-factor style).
/// Format: ts=2024-08-11T22:44:57.172Z level=info scope=fork_choice msg="block applied" slot=42
pub const LogfmtLayout = struct {
    pub fn format(_: *const LogfmtLayout, record: *const Record, writer: anytype) void {
        writer.writeAll("ts=") catch return;
        formatTimestamp(writer, record.timestamp_us);

        writer.writeAll(" level=") catch return;
        writer.writeAll(std.mem.trimRight(u8, rec.asText(record.level), " ")) catch return;

        if (!std.mem.eql(u8, record.scope_name, "default")) {
            writer.writeAll(" scope=") catch return;
            writer.writeAll(record.scope_name) catch return;
        }

        writer.writeAll(" msg=\"") catch return;
        writeLogfmtEscaped(writer, record.message);
        writer.writeByte('"') catch return;

        var iter = record.attrIterator();
        while (iter.next()) |attr| {
            writer.writeByte(' ') catch return;
            writer.writeAll(attr.key) catch return;
            writer.writeByte('=') catch return;
            writeLogfmtValue(writer, attr.value);
        }

        writer.writeByte('\n') catch return;
    }

    fn writeLogfmtValue(writer: anytype, value: Attr.Value) void {
        switch (value) {
            .int => |v| writer.print("{d}", .{v}) catch {},
            .uint => |v| writer.print("{d}", .{v}) catch {},
            .float => |v| writer.print("{d:.6}", .{v}) catch {},
            .bool_val => |v| writer.print("{}", .{v}) catch {},
            .string => |v| {
                if (needsQuoting(v)) {
                    writer.writeByte('"') catch {};
                    writeLogfmtEscaped(writer, v);
                    writer.writeByte('"') catch {};
                } else {
                    writer.writeAll(v) catch {};
                }
            },
            .hex_bytes => |v| {
                writer.writeAll("0x") catch {};
                for (v) |byte| {
                    writer.print("{x:0>2}", .{byte}) catch {};
                }
            },
        }
    }

    fn needsQuoting(s: []const u8) bool {
        if (s.len == 0) return true;
        for (s) |c| {
            if (c == ' ' or c == '"' or c == '=' or c == '\n' or c == '\r' or c == '\t') return true;
        }
        return false;
    }

    fn writeLogfmtEscaped(writer: anytype, s: []const u8) void {
        for (s) |c| {
            switch (c) {
                '"' => writer.writeAll("\\\"") catch {},
                '\\' => writer.writeAll("\\\\") catch {},
                '\n' => writer.writeAll("\\n") catch {},
                '\r' => writer.writeAll("\\r") catch {},
                '\t' => writer.writeAll("\\t") catch {},
                else => writer.writeByte(c) catch {},
            }
        }
    }
};

// ──────────────────────────── Tests ────────────────────────────

test "formatTimestamp ISO 8601 UTC" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    formatTimestamp(fbs.writer(), 1723416297172105); // 2024-08-11T22:44:57.172105Z
    try std.testing.expectEqualStrings("2024-08-11T22:44:57.172105Z", fbs.getWritten());

    fbs.reset();
    formatTimestamp(fbs.writer(), 0);
    try std.testing.expectEqualStrings("1970-01-01T00:00:00.000000Z", fbs.getWritten());

    fbs.reset();
    formatTimestamp(fbs.writer(), 1234567890123);
    try std.testing.expectEqualStrings("1970-01-15T06:56:07.890123Z", fbs.getWritten());
}

test "TextLayout basic" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    var record = Record{
        .timestamp_us = 1234567890123,
        .level = .info,
        .scope_name = "fork_choice",
        .message = "block applied",
    };
    record.pushEventAttr(Attr.uint("slot", 42));

    const layout = TextLayout{};
    layout.format(&record, fbs.writer());

    const output = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, output, "1970-01-15T06:56:07.890123Z") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "info") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "(fork_choice)") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "block applied") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "slot=42") != null);
    try std.testing.expect(output[output.len - 1] == '\n');
}

test "TextLayout default scope" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    const record = Record{
        .timestamp_us = 0,
        .level = .err,
        .scope_name = "default",
        .message = "oops",
    };

    const layout = TextLayout{};
    layout.format(&record, fbs.writer());

    const output = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, output, "(default)") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, ": oops") != null);
}

test "TextLayout color wraps level in ANSI codes" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    const record = Record{
        .timestamp_us = 0,
        .level = .err,
        .scope_name = "default",
        .message = "fail",
    };

    const layout = TextLayout{ .color = true };
    layout.format(&record, fbs.writer());

    const output = fbs.getWritten();
    // Red ANSI code before level, reset after.
    try std.testing.expect(std.mem.indexOf(u8, output, "\x1b[31merror\x1b[0m") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "fail") != null);
}

test "TextLayout color per level" {
    const cases = [_]struct { level: std.log.Level, code: []const u8 }{
        .{ .level = .err, .code = "\x1b[31m" },
        .{ .level = .warn, .code = "\x1b[33m" },
        .{ .level = .info, .code = "\x1b[32m" },
        .{ .level = .debug, .code = "\x1b[90m" },
    };
    for (cases) |tc| {
        var buf: [512]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        const record = Record{ .timestamp_us = 0, .level = tc.level, .scope_name = "default", .message = "x" };
        const layout = TextLayout{ .color = true };
        layout.format(&record, fbs.writer());
        const output = fbs.getWritten();
        try std.testing.expect(std.mem.indexOf(u8, output, tc.code) != null);
        try std.testing.expect(std.mem.indexOf(u8, output, "\x1b[0m") != null);
    }
}

test "JsonLayout basic" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    var record = Record{
        .timestamp_us = 1234567890123,
        .level = .info,
        .scope_name = "fork_choice",
        .message = "block applied",
    };
    record.pushEventAttr(Attr.uint("slot", 42));

    const layout = JsonLayout{};
    layout.format(&record, fbs.writer());

    const output = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, output, "\"ts\":\"1970-01-15T06:56:07.890123Z\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"level\":\"info\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"scope\":\"fork_choice\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"msg\":\"block applied\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"slot\":42") != null);
    try std.testing.expect(output[output.len - 1] == '\n');
}

test "JsonLayout default scope omitted" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    const record = Record{
        .timestamp_us = 0,
        .level = .err,
        .scope_name = "default",
        .message = "oops",
    };

    const layout = JsonLayout{};
    layout.format(&record, fbs.writer());

    const output = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, output, "\"scope\"") == null);
}

test "JsonLayout escapes special characters" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    var record = Record{
        .timestamp_us = 0,
        .level = .warn,
        .scope_name = "default",
        .message = "line1\nline2",
    };
    record.pushEventAttr(Attr.str("data", "has \"quotes\""));

    const layout = JsonLayout{};
    layout.format(&record, fbs.writer());

    const output = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, output, "line1\\nline2") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "has \\\"quotes\\\"") != null);
}

test "JsonLayout bool and hex values" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    var record = Record{
        .timestamp_us = 0,
        .level = .info,
        .scope_name = "default",
        .message = "test",
    };
    record.pushEventAttr(Attr.boolean("ok", true));
    record.pushEventAttr(Attr.hex("hash", &[_]u8{ 0xab, 0xcd }));

    const layout = JsonLayout{};
    layout.format(&record, fbs.writer());

    const output = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, output, "\"ok\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"hash\":\"0xabcd\"") != null);
}

test "LogfmtLayout basic" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    var record = Record{
        .timestamp_us = 1234567890123,
        .level = .info,
        .scope_name = "fork_choice",
        .message = "block applied",
    };
    record.pushEventAttr(Attr.uint("slot", 42));

    const layout = LogfmtLayout{};
    layout.format(&record, fbs.writer());

    const output = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, output, "ts=1970-01-15T06:56:07.890123Z") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "level=info") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "scope=fork_choice") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "msg=\"block applied\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "slot=42") != null);
    try std.testing.expect(output[output.len - 1] == '\n');
}

test "LogfmtLayout default scope omitted" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    const record = Record{
        .timestamp_us = 0,
        .level = .err,
        .scope_name = "default",
        .message = "oops",
    };

    const layout = LogfmtLayout{};
    layout.format(&record, fbs.writer());

    const output = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, output, "scope=") == null);
}

test "LogfmtLayout quotes strings with spaces" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    var record = Record{
        .timestamp_us = 0,
        .level = .info,
        .scope_name = "default",
        .message = "test",
    };
    record.pushEventAttr(Attr.str("path", "/hello world"));
    record.pushEventAttr(Attr.str("simple", "nospaces"));

    const layout = LogfmtLayout{};
    layout.format(&record, fbs.writer());

    const output = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, output, "path=\"/hello world\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "simple=nospaces") != null);
}
