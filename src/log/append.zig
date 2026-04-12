//! Appender implementations for the logging pipeline.
//!
//! Appenders consume formatted Records and write them to output destinations.
//! Each appender owns its Layout (if applicable) and handles formatting internally.

const std = @import("std");
const rec = @import("record.zig");
const Record = rec.Record;
const Attr = rec.Attr;

// ────────────────────── FlushableWriter ──────────────────────

/// Type-erased writer with optional flush support.
///
/// Wraps `std.io.AnyWriter` and adds an optional flush callback.
/// Appenders that write to external destinations (stderr, network, files)
/// use this instead of bare `AnyWriter` so that `flush()` can propagate
/// through the entire pipeline.
pub const FlushableWriter = struct {
    inner: std.io.AnyWriter,
    flush_ctx: ?*anyopaque = null,
    flush_fn: ?*const fn (ctx: *anyopaque) void = null,

    /// Write data through the underlying writer.
    pub fn writeAll(self: FlushableWriter, data: []const u8) !void {
        try self.inner.writeAll(data);
    }

    /// Flush the underlying writer. No-op if no flush callback was provided.
    pub fn flush(self: FlushableWriter) void {
        if (self.flush_fn) |f| {
            f(self.flush_ctx.?);
        }
    }

    /// Wrap a bare `AnyWriter` with no flush support.
    ///
    /// SAFETY: The AnyWriter's lifetime must exceed this FlushableWriter.
    /// For synchronous callers within the same stack frame this is fine.
    /// For async appenders prefer `stderrWriter` or `fromFlushable` to avoid
    /// dangling pointers from temporary GenericWriter chains.
    pub fn noFlush(w: std.io.AnyWriter) FlushableWriter {
        return .{ .inner = w };
    }

    /// Stateless stderr writer safe for async (cross-thread) use.
    /// Calls `std.io.getStdErr().write()` fresh on every write — no stored
    /// pointer, no lifetime concern, no global variable.
    pub fn stderrWriter() FlushableWriter {
        const gen = struct {
            fn writeErased(_: *const anyopaque, bytes: []const u8) anyerror!usize {
                return std.io.getStdErr().write(bytes);
            }
        };
        // context is unused but must be non-null; point to the function itself
        // (stable address in .text segment).
        return .{
            .inner = .{ .context = @ptrCast(&gen.writeErased), .writeFn = gen.writeErased },
        };
    }

    /// Create from a mutable pointer to any type that provides
    /// `.writer()` (returning a GenericWriter) and `.flush()`.
    ///
    /// NOTE: We construct the AnyWriter *directly* with `ptr` as context
    /// instead of calling `ptr.writer().any()`.  The latter chains two
    /// temporaries — `writer()` returns a stack-local GenericWriter and
    /// `any()` captures a pointer to it.  That pointer dangles as soon as
    /// the enclosing expression ends, which is harmless for synchronous
    /// callers (the stack frame is still warm) but corrupts reads when an
    /// async consumer thread dereferences it later.
    pub fn fromFlushable(ptr: anytype) FlushableWriter {
        const Ptr = @TypeOf(ptr);
        const gen = struct {
            fn writeErased(ctx: *const anyopaque, bytes: []const u8) anyerror!usize {
                const p: Ptr = @ptrCast(@alignCast(@constCast(ctx)));
                return p.writer().write(bytes);
            }
            fn flushErased(ctx: *anyopaque) void {
                const p: Ptr = @ptrCast(@alignCast(ctx));
                p.flush();
            }
        };
        return .{
            .inner = .{ .context = @ptrCast(ptr), .writeFn = gen.writeErased },
            .flush_fn = gen.flushErased,
            .flush_ctx = @ptrCast(ptr),
        };
    }
};

// ──────────────────────── NullAppend ────────────────────────

/// No-op appender. Discards all output. Useful for benchmarks.
pub const NullAppend = struct {
    pub fn append(_: *NullAppend, _: *const Record) void {}
    pub fn flush(_: *NullAppend) void {}
};

// ────────────────── Error Reporting (BestEffortTrap) ──────────────────

/// Per-thread re-entrancy guard to prevent infinite recursion when
/// stderr itself is the failing writer.
threadlocal var _in_report: bool = false;

/// Report an appender write error to stderr. Best-effort: if stderr
/// also fails, the error is silently dropped (no recursion).
fn reportAppendError(err: anyerror, comptime context: []const u8) void {
    if (_in_report) return;
    _in_report = true;
    defer _in_report = false;
    std.io.getStdErr().writer().print("[log] " ++ context ++ ": {s}\n", .{@errorName(err)}) catch {};
}

// ─────────────────────── WriterAppend ───────────────────────

/// Maximum size of the format buffer used between Layout and the underlying writer.
const format_buf_size = 4096;

/// Appender that formats a Record via a Layout and writes to a FlushableWriter.
/// Uses two-phase format: stack buffer fast path, heap ArrayList fallback for
/// messages exceeding format_buf_size (no silent truncation).
pub fn WriterAppend(comptime LayoutT: type) type {
    comptime {
        rec.assertLayout(LayoutT);
    }

    return struct {
        const Self = @This();

        layout: LayoutT,
        inner: FlushableWriter,
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator, layout: LayoutT, writer: FlushableWriter) Self {
            return .{ .allocator = allocator, .layout = layout, .inner = writer };
        }

        pub fn append(self: *Self, record: *const Record) void {
            var buf: [format_buf_size]u8 = undefined;
            var fbs = std.io.fixedBufferStream(&buf);
            self.layout.format(record, fbs.writer());
            const written = fbs.getWritten();

            if (written.len < format_buf_size) {
                self.inner.writeAll(written) catch |err| reportAppendError(err, "WriterAppend.writeAll");
                return;
            }

            // Possibly truncated — re-format into growable buffer.
            var list = std.ArrayList(u8).init(self.allocator);
            defer list.deinit();
            self.layout.format(record, list.writer());
            self.inner.writeAll(list.items) catch |err| reportAppendError(err, "WriterAppend.writeAll");
        }

        pub fn flush(self: *Self) void {
            self.inner.flush();
        }
    };
}

// ─────────────────────── TestingAppend ───────────────────────

/// Test appender that formats a Record via a Layout and captures output into a bounded buffer.
/// Uses two-phase format to avoid truncation of the formatted message.
/// Note: the capture buffer itself (max_capture) is still bounded — this prevents
/// format-stage truncation, not capture-stage truncation.
pub fn TestingAppend(comptime LayoutT: type) type {
    comptime {
        rec.assertLayout(LayoutT);
    }

    return struct {
        const Self = @This();

        pub const max_capture = 8192;

        layout: LayoutT,
        allocator: std.mem.Allocator,
        buf: [max_capture]u8 = undefined,
        len: usize = 0,

        pub fn init(allocator: std.mem.Allocator, layout: LayoutT) Self {
            return .{ .allocator = allocator, .layout = layout };
        }

        pub fn append(self: *Self, record: *const Record) void {
            var fmt_buf: [format_buf_size]u8 = undefined;
            var fbs = std.io.fixedBufferStream(&fmt_buf);
            self.layout.format(record, fbs.writer());
            const written = fbs.getWritten();

            if (written.len < format_buf_size) {
                self.capture(written);
                return;
            }

            // Possibly truncated — re-format into growable buffer.
            var list = std.ArrayList(u8).init(self.allocator);
            defer list.deinit();
            self.layout.format(record, list.writer());
            self.capture(list.items);
        }

        pub fn flush(_: *Self) void {}

        fn capture(self: *Self, bytes: []const u8) void {
            const remaining = max_capture - self.len;
            const to_copy = @min(bytes.len, remaining);
            if (to_copy > 0) {
                @memcpy(self.buf[self.len..][0..to_copy], bytes[0..to_copy]);
                self.len += to_copy;
            }
        }

        pub fn getOutput(self: *const Self) []const u8 {
            return self.buf[0..self.len];
        }

        pub fn contains(self: *const Self, needle: []const u8) bool {
            return std.mem.indexOf(u8, self.getOutput(), needle) != null;
        }

        pub fn reset(self: *Self) void {
            self.len = 0;
        }
    };
}

// ────────────────────── RollingFileWriter ──────────────────────

/// Time-based rotation interval, matching logforth's `Rotation` enum.
pub const Rotation = enum {
    /// Rotate every minute. Archive format: `name.YYYY-MM-DD-HH-MM.N`
    minutely,
    /// Rotate every hour. Archive format: `name.YYYY-MM-DD-HH.N`
    hourly,
    /// Rotate every day. Archive format: `name.YYYY-MM-DD.N`
    daily,
    /// No time-based rotation (size-only).
    never,

    /// Compute the next rollover boundary as epoch milliseconds.
    /// Returns null for `never`.
    pub fn nextDateTimestamp(self: Rotation, now_ms: i64) ?i64 {
        return switch (self) {
            .never => null,
            .minutely => blk: {
                // Truncate to current minute, add 60s.
                const s = @divFloor(now_ms, 60_000);
                break :blk (s + 1) * 60_000;
            },
            .hourly => blk: {
                const s = @divFloor(now_ms, 3_600_000);
                break :blk (s + 1) * 3_600_000;
            },
            .daily => blk: {
                const s = @divFloor(now_ms, 86_400_000);
                break :blk (s + 1) * 86_400_000;
            },
        };
    }

    /// Format a timestamp into the date suffix for archive file naming.
    /// Writes into the provided buffer and returns the slice.
    pub fn formatDate(self: Rotation, ms: i64, buf: *[24]u8) []const u8 {
        const epoch_secs: i64 = @divFloor(ms, 1_000);
        const es = std.time.epoch.EpochSeconds{ .secs = @intCast(@as(u64, @bitCast(epoch_secs))) };
        const day = es.getEpochDay();
        const yd = day.calculateYearDay();
        const md = yd.calculateMonthDay();
        const ds = es.getDaySeconds();

        const year: u16 = yd.year;
        const month: u8 = md.month.numeric();
        const mday: u8 = md.day_index + 1;
        const hour: u8 = ds.getHoursIntoDay();
        const minute: u8 = ds.getMinutesIntoHour();

        return switch (self) {
            .daily, .never => std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}", .{ year, month, mday }) catch buf[0..10],
            .hourly => std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}-{d:0>2}", .{ year, month, mday, hour }) catch buf[0..13],
            .minutely => std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}-{d:0>2}-{d:0>2}", .{ year, month, mday, hour, minute }) catch buf[0..16],
        };
    }
};

/// Rolling policy for file rotation (supports dual rollover: time + size).
pub const RollingPolicy = struct {
    /// Time-based rotation interval. Default: never (size-only).
    rotation: Rotation = .never,
    /// Maximum file size in bytes before rotation. 0 = no size limit.
    max_bytes: u64 = 10 * 1024 * 1024,
    /// Maximum number of backup files to keep. Default: 5.
    max_backups: u8 = 5,
};

/// Rotating file writer with dual rollover (time + size), matching logforth.
///
/// Rollover checks on every `write()`:
///   1. Time-based: if now >= next_date_timestamp, rotate with dated archive name.
///   2. Size-based: if current_size >= max_bytes, rotate.
/// Both can be active simultaneously. Time check runs first (logforth semantics).
///
/// Archive naming:
///   - time-based: `name.YYYY-MM-DD.1`, `name.YYYY-MM-DD.2`, ...
///   - size-only:  `name.1`, `name.2`, ...
pub const RollingFileWriter = struct {
    file: std.fs.File,
    current_size: u64,
    policy: RollingPolicy,
    base_name: []const u8,
    dir: std.fs.Dir,
    next_date_ts: ?i64,
    last_rotate_ms: i64,

    pub fn init(dir: std.fs.Dir, base_name: []const u8, policy: RollingPolicy) !RollingFileWriter {
        const file = try dir.createFile(base_name, .{ .truncate = false });
        const end_pos = try file.getEndPos();
        try file.seekTo(end_pos);

        const now_ms = std.time.milliTimestamp();

        return .{
            .file = file,
            .current_size = end_pos,
            .policy = policy,
            .base_name = base_name,
            .dir = dir,
            .next_date_ts = policy.rotation.nextDateTimestamp(now_ms),
            .last_rotate_ms = now_ms,
        };
    }

    /// Init with an explicit timestamp (for testing).
    pub fn initWithTimestamp(dir: std.fs.Dir, base_name: []const u8, policy: RollingPolicy, now_ms: i64) !RollingFileWriter {
        const file = try dir.createFile(base_name, .{ .truncate = false });
        const end_pos = try file.getEndPos();
        try file.seekTo(end_pos);

        return .{
            .file = file,
            .current_size = end_pos,
            .policy = policy,
            .base_name = base_name,
            .dir = dir,
            .next_date_ts = policy.rotation.nextDateTimestamp(now_ms),
            .last_rotate_ms = now_ms,
        };
    }

    pub fn flush(self: *RollingFileWriter) void {
        self.file.sync() catch {};
    }

    pub fn deinit(self: *RollingFileWriter) void {
        self.flush();
        self.file.close();
    }

    pub const Writer = std.io.GenericWriter(*RollingFileWriter, anyerror, write);

    pub fn writer(self: *RollingFileWriter) Writer {
        return .{ .context = self };
    }

    fn write(self: *RollingFileWriter, bytes: []const u8) anyerror!usize {
        const now_ms = std.time.milliTimestamp();

        // Check 1: time-based rollover (logforth: checked first).
        if (self.next_date_ts) |ndt| {
            if (now_ms >= ndt) {
                self.rotateWithDate(self.last_rotate_ms);
                self.next_date_ts = self.policy.rotation.nextDateTimestamp(now_ms);
                self.last_rotate_ms = now_ms;
            }
        }

        // Check 2: size-based rollover.
        if (self.policy.max_bytes > 0 and self.current_size + bytes.len > self.policy.max_bytes) {
            if (self.policy.rotation == .never) {
                self.rotateNumeric();
            } else {
                self.rotateWithDate(now_ms);
            }
        }

        try self.file.writeAll(bytes);
        self.current_size += bytes.len;
        return bytes.len;
    }

    /// Write with an explicit timestamp (for testing time-based rotation).
    pub fn writeWithTimestamp(self: *RollingFileWriter, bytes: []const u8, now_ms: i64) anyerror!usize {
        // Check 1: time-based rollover.
        if (self.next_date_ts) |ndt| {
            if (now_ms >= ndt) {
                self.rotateWithDate(self.last_rotate_ms);
                self.next_date_ts = self.policy.rotation.nextDateTimestamp(now_ms);
                self.last_rotate_ms = now_ms;
            }
        }

        // Check 2: size-based rollover.
        if (self.policy.max_bytes > 0 and self.current_size + bytes.len > self.policy.max_bytes) {
            if (self.policy.rotation == .never) {
                self.rotateNumeric();
            } else {
                self.rotateWithDate(now_ms);
            }
        }

        try self.file.writeAll(bytes);
        self.current_size += bytes.len;
        return bytes.len;
    }

    /// Numeric rotation (size-only, no date). `name.1`, `name.2`, ...
    fn rotateNumeric(self: *RollingFileWriter) void {
        self.file.close();

        var i: u8 = self.policy.max_backups;
        while (i > 0) : (i -= 1) {
            const from_name = numericBackupName(self.base_name, i - 1) catch continue;
            if (i >= self.policy.max_backups) {
                self.dir.deleteFile(from_name.constSlice()) catch {};
            } else {
                const to_name = numericBackupName(self.base_name, i) catch continue;
                self.dir.rename(from_name.constSlice(), to_name.constSlice()) catch {};
            }
        }

        const first = numericBackupName(self.base_name, 1) catch {
            self.file = self.dir.createFile(self.base_name, .{ .truncate = true }) catch return;
            self.current_size = 0;
            return;
        };
        self.dir.rename(self.base_name, first.constSlice()) catch {};

        self.file = self.dir.createFile(self.base_name, .{ .truncate = true }) catch return;
        self.current_size = 0;
    }

    /// Dated rotation. `name.YYYY-MM-DD.1`, `name.YYYY-MM-DD.2`, ...
    fn rotateWithDate(self: *RollingFileWriter, date_ms: i64) void {
        self.file.close();

        var date_buf: [24]u8 = undefined;
        const date_str = self.policy.rotation.formatDate(date_ms, &date_buf);

        // Shift existing archives: .3 → .4, .2 → .3, .1 → .2
        var i: u8 = self.policy.max_backups;
        while (i > 0) : (i -= 1) {
            const from_name = datedBackupName(self.base_name, date_str, i - 1) catch continue;
            if (i >= self.policy.max_backups) {
                self.dir.deleteFile(from_name.constSlice()) catch {};
            } else {
                const to_name = datedBackupName(self.base_name, date_str, i) catch continue;
                self.dir.rename(from_name.constSlice(), to_name.constSlice()) catch {};
            }
        }

        // Rename current → .date.1
        const first = datedBackupName(self.base_name, date_str, 1) catch {
            self.file = self.dir.createFile(self.base_name, .{ .truncate = true }) catch return;
            self.current_size = 0;
            return;
        };
        self.dir.rename(self.base_name, first.constSlice()) catch {};

        self.file = self.dir.createFile(self.base_name, .{ .truncate = true }) catch return;
        self.current_size = 0;
    }

    fn numericBackupName(base_name: []const u8, n: u8) !std.BoundedArray(u8, 256) {
        var name: std.BoundedArray(u8, 256) = .{};
        const w = name.writer();
        try w.writeAll(base_name);
        try w.print(".{d}", .{n});
        return name;
    }

    fn datedBackupName(base_name: []const u8, date_str: []const u8, n: u8) !std.BoundedArray(u8, 256) {
        var name: std.BoundedArray(u8, 256) = .{};
        const w = name.writer();
        try w.writeAll(base_name);
        try w.print(".{s}.{d}", .{ date_str, n });
        return name;
    }
};

// ────────────────────────── FileAppend ──────────────────────────

/// File appender with size-based rolling rotation.
/// Convenience wrapper: Layout + RollingFileWriter in one type.
/// Uses two-phase format (no silent truncation).
pub fn FileAppend(comptime LayoutT: type) type {
    comptime {
        rec.assertLayout(LayoutT);
    }

    return struct {
        const Self = @This();

        layout: LayoutT,
        rolling_writer: RollingFileWriter,
        allocator: std.mem.Allocator,

        pub fn init(
            allocator: std.mem.Allocator,
            layout: LayoutT,
            dir: std.fs.Dir,
            base_name: []const u8,
            policy: RollingPolicy,
        ) !Self {
            return .{
                .allocator = allocator,
                .layout = layout,
                .rolling_writer = try RollingFileWriter.init(dir, base_name, policy),
            };
        }

        pub fn append(self: *Self, record: *const Record) void {
            var buf: [format_buf_size]u8 = undefined;
            var fbs = std.io.fixedBufferStream(&buf);
            self.layout.format(record, fbs.writer());
            const written = fbs.getWritten();

            if (written.len < format_buf_size) {
                self.rolling_writer.writer().writeAll(written) catch return;
                return;
            }

            // Possibly truncated — re-format into growable buffer.
            var list = std.ArrayList(u8).init(self.allocator);
            defer list.deinit();
            self.layout.format(record, list.writer());
            self.rolling_writer.writer().writeAll(list.items) catch return;
        }

        pub fn flush(self: *Self) void {
            self.rolling_writer.flush();
        }

        pub fn deinit(self: *Self) void {
            self.rolling_writer.deinit();
        }
    };
}

// ─────────────────── OpenTelemetryAppend ───────────────────

/// OTLP JSON log appender.
///
/// Serializes log Records directly to OpenTelemetry Log Data Model JSON.
/// Does NOT use a Layout — it consumes the structured Record directly.
/// Uses two-phase format (no silent truncation).
pub const OpenTelemetryAppend = struct {
    inner: FlushableWriter,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, writer: FlushableWriter) OpenTelemetryAppend {
        return .{ .allocator = allocator, .inner = writer };
    }

    pub fn append(self: *OpenTelemetryAppend, record: *const Record) void {
        var buf: [format_buf_size]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        formatOtlp(record, fbs.writer());
        const written = fbs.getWritten();

        if (written.len < format_buf_size) {
            self.inner.writeAll(written) catch |err| reportAppendError(err, "OpenTelemetryAppend.writeAll");
            return;
        }

        // Possibly truncated — re-format into growable buffer.
        var list = std.ArrayList(u8).init(self.allocator);
        defer list.deinit();
        formatOtlp(record, list.writer());
        self.inner.writeAll(list.items) catch |err| reportAppendError(err, "OpenTelemetryAppend.writeAll");
    }

    pub fn flush(self: *OpenTelemetryAppend) void {
        self.inner.flush();
    }

    fn formatOtlp(record: *const Record, writer: anytype) void {
        writer.writeAll("{") catch return;

        writer.print("\"timeUnixNano\":{d}", .{@as(i128, record.timestamp_us) * 1_000}) catch return;

        const sev = severityNumber(record.level);
        writer.print(",\"severityNumber\":{d}", .{sev}) catch return;
        writer.writeAll(",\"severityText\":\"") catch return;
        writer.writeAll(severityText(record.level)) catch return;
        writer.writeAll("\"") catch return;

        writer.writeAll(",\"body\":{\"stringValue\":\"") catch return;
        writeOtlpJsonEscaped(writer, record.message);
        writer.writeAll("\"}") catch return;

        writer.writeAll(",\"attributes\":[") catch return;

        writer.writeAll("{\"key\":\"scope\",\"value\":{\"stringValue\":\"") catch return;
        writer.writeAll(record.scope_name) catch return;
        writer.writeAll("\"}}") catch return;

        var iter = record.attrIterator();
        while (iter.next()) |attr| {
            writer.writeAll(",{\"key\":\"") catch return;
            writer.writeAll(attr.key) catch return;
            writer.writeAll("\",\"value\":") catch return;
            writeOtlpValue(writer, attr.value);
            writer.writeAll("}") catch return;
        }

        writer.writeAll("]") catch return;
        writer.writeAll("}\n") catch return;
    }

    fn severityNumber(level: std.log.Level) u8 {
        return switch (level) {
            .err => 17,
            .warn => 13,
            .info => 9,
            .debug => 5,
        };
    }

    fn severityText(level: std.log.Level) []const u8 {
        return switch (level) {
            .err => "ERROR",
            .warn => "WARN",
            .info => "INFO",
            .debug => "DEBUG",
        };
    }

    fn writeOtlpValue(writer: anytype, value: Attr.Value) void {
        switch (value) {
            .int => |v| writer.print("{{\"intValue\":\"{d}\"}}", .{v}) catch {},
            .uint => |v| writer.print("{{\"intValue\":\"{d}\"}}", .{v}) catch {},
            .float => |v| writer.print("{{\"doubleValue\":{d:.6}}}", .{v}) catch {},
            .bool_val => |v| writer.print("{{\"boolValue\":{}}}", .{v}) catch {},
            .string => |v| {
                writer.writeAll("{\"stringValue\":\"") catch {};
                writeOtlpJsonEscaped(writer, v);
                writer.writeAll("\"}") catch {};
            },
            .hex_bytes => |v| {
                writer.writeAll("{\"stringValue\":\"0x") catch {};
                for (v) |byte| {
                    writer.print("{x:0>2}", .{byte}) catch {};
                }
                writer.writeAll("\"}") catch {};
            },
        }
    }

    fn writeOtlpJsonEscaped(writer: anytype, s: []const u8) void {
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

// ──────────────────────── AsyncAppend ────────────────────────

const ring_buffer = @import("ring_buffer");
const ByteMessage = ring_buffer.ByteMessage;
const ByteRing = ring_buffer.RingBuffer(ByteMessage);

pub const max_message_size = ring_buffer.max_message_size;

/// Overflow policy when the ring buffer is full.
pub const Overflow = enum {
    /// Block until space is available (default, no log loss).
    block,
    /// Drop the incoming message silently.
    drop_incoming,
};

/// Async appender: format a Record via an owned Layout, enqueue the
/// formatted bytes in a bounded MPMC ring buffer, and drain them on a
/// background consumer thread that forwards to an underlying writer.
///
/// Uses Small Buffer Optimization (SBO): messages ≤ 4096 bytes are formatted
/// into a stack buffer and enqueued inline (zero allocation). Larger messages
/// are re-formatted into a heap ArrayList and transferred via the ring.
pub fn AsyncAppend(comptime LayoutT: type) type {
    comptime {
        rec.assertLayout(LayoutT);
    }

    return struct {
        const Self = @This();

        layout: LayoutT,
        ring: ByteRing,
        thread: ?std.Thread = null,
        inner: FlushableWriter,
        overflow: Overflow,
        allocator: std.mem.Allocator,

        pub fn init(
            allocator: std.mem.Allocator,
            size: u32,
            writer: FlushableWriter,
            layout: LayoutT,
            overflow: Overflow,
        ) !Self {
            return .{
                .layout = layout,
                .ring = try ByteRing.init(allocator, size),
                .inner = writer,
                .overflow = overflow,
                .allocator = allocator,
            };
        }

        pub fn start(self: *Self) !void {
            self.thread = try std.Thread.spawn(.{}, consumerLoop, .{self});
        }

        pub fn append(self: *Self, record: *const Record) void {
            // Phase 1: try formatting into a stack buffer (zero-alloc fast path).
            var buf: [max_message_size]u8 = undefined;
            var fbs = std.io.fixedBufferStream(&buf);
            self.layout.format(record, fbs.writer());
            const written = fbs.getWritten();

            if (written.len < max_message_size) {
                // Fast path: fits inline. No allocation needed.
                self.enqueue(ByteMessage.fromSlice(written));
                return;
            }

            // Phase 2: message may have been truncated. Re-format into a
            // growable ArrayList to capture the full output, then use
            // fromSliceAlloc for SBO heap fallback.
            var list = std.ArrayList(u8).init(self.allocator);
            defer list.deinit();
            self.layout.format(record, list.writer());
            self.enqueue(ByteMessage.fromSliceAlloc(self.allocator, list.items));
        }

        /// Enqueue a message into the ring. On drop_incoming overflow, properly
        /// frees heap-backed messages that fail to enter the ring.
        fn enqueue(self: *Self, msg: ByteMessage) void {
            switch (self.overflow) {
                .block => _ = self.ring.send(msg),
                .drop_incoming => {
                    if (!self.ring.push(msg)) {
                        // Push failed — message is dropped. Free heap if allocated.
                        var dropped = msg;
                        dropped.deinit();
                    }
                },
            }
        }

        pub fn flush(self: *Self) void {
            self.drain();
            self.inner.flush();
        }

        pub fn deinit(self: *Self) void {
            self.ring.close();
            if (self.thread) |t| {
                t.join();
                self.thread = null;
            }
            self.drain();
            self.ring.deinit();
        }

        fn consumerLoop(self: *Self) void {
            while (self.ring.recv()) |msg| {
                self.inner.writeAll(msg.get().bytes()) catch |err| reportAppendError(err, "AsyncAppend.consumerLoop");
                msg.get().deinit();
                msg.release();
            }
        }

        fn drain(self: *Self) void {
            while (self.ring.tryPop()) |msg| {
                self.inner.writeAll(msg.get().bytes()) catch |err| reportAppendError(err, "AsyncAppend.drain");
                msg.get().deinit();
                msg.release();
            }
        }
    };
}

// ──────────────────────────── Tests ────────────────────────────

test "NullAppend discards output" {
    var null_append = NullAppend{};
    var record = Record{
        .timestamp_us = 0,
        .level = .info,
        .scope_name = rec.scopeName(.default),
        .message = "should be discarded",
    };
    null_append.append(&record);
    null_append.flush();
}

test "WriterAppend to buffer" {
    const layout = @import("layout.zig");
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    var wa = WriterAppend(layout.TextLayout).init(std.testing.allocator, layout.TextLayout{}, FlushableWriter.noFlush(fbs.writer().any()));

    var record = Record{
        .timestamp_us = 1234,
        .level = .info,
        .scope_name = rec.scopeName(.fork_choice),
        .message = "block applied",
    };
    record.pushEventAttr(Attr.uint("slot", 42));

    wa.append(&record);

    const output = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, output, "block applied") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "slot=42") != null);
}

test "WriterAppend with JsonLayout" {
    const layout = @import("layout.zig");
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    var wa = WriterAppend(layout.JsonLayout).init(std.testing.allocator, layout.JsonLayout{}, FlushableWriter.noFlush(fbs.writer().any()));

    var record = Record{
        .timestamp_us = 1000,
        .level = .warn,
        .scope_name = rec.scopeName(.ssz),
        .message = "test",
    };

    wa.append(&record);

    const output = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, output, "\"level\":\"warn\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"msg\":\"test\"") != null);
}

test "TestingAppend captures output" {
    const layout = @import("layout.zig");
    const TA = TestingAppend(layout.TextLayout);
    var ta = TA.init(std.testing.allocator, layout.TextLayout{});

    var record = Record{
        .timestamp_us = 1234,
        .level = .info,
        .scope_name = rec.scopeName(.fork_choice),
        .message = "block applied",
    };
    record.pushEventAttr(Attr.uint("slot", 42));

    ta.append(&record);
    try std.testing.expect(ta.contains("block applied"));
    try std.testing.expect(ta.contains("slot=42"));
    try std.testing.expect(ta.contains("(fork_choice)"));
}

test "TestingAppend contains" {
    const layout = @import("layout.zig");
    const TA = TestingAppend(layout.TextLayout);
    var ta = TA.init(std.testing.allocator, layout.TextLayout{});

    var record = Record{
        .timestamp_us = 1234,
        .level = .info,
        .scope_name = rec.scopeName(.fork_choice),
        .message = "block applied",
    };
    ta.append(&record);

    try std.testing.expect(ta.contains("block applied"));
    try std.testing.expect(!ta.contains("missing"));
}

test "TestingAppend reset" {
    const layout = @import("layout.zig");
    const TA = TestingAppend(layout.TextLayout);
    var ta = TA.init(std.testing.allocator, layout.TextLayout{});

    var record = Record{
        .timestamp_us = 0,
        .level = .debug,
        .scope_name = rec.scopeName(.default),
        .message = "some output",
    };
    ta.append(&record);
    try std.testing.expect(ta.len > 0);

    ta.reset();
    try std.testing.expectEqual(@as(usize, 0), ta.len);
    try std.testing.expectEqualStrings("", ta.getOutput());
}

test "TestingAppend with JsonLayout" {
    const layout = @import("layout.zig");
    const TA = TestingAppend(layout.JsonLayout);
    var ta = TA.init(std.testing.allocator, layout.JsonLayout{});

    var record = Record{
        .timestamp_us = 1000,
        .level = .info,
        .scope_name = rec.scopeName(.ssz),
        .message = "test",
    };
    record.pushEventAttr(Attr.boolean("ok", true));

    ta.append(&record);
    try std.testing.expect(ta.contains("\"level\":\"info\""));
    try std.testing.expect(ta.contains("\"ok\":true"));
}

test "RollingFileWriter basic write" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var rfw = try RollingFileWriter.init(tmp.dir, "test.log", .{ .max_bytes = 1024 * 1024, .max_backups = 3 });
    defer rfw.deinit();

    rfw.writer().writeAll("hello rolling\n") catch return;
    rfw.flush();

    const content = try tmp.dir.readFileAlloc(std.testing.allocator, "test.log", 4096);
    defer std.testing.allocator.free(content);
    try std.testing.expect(std.mem.indexOf(u8, content, "hello rolling") != null);
}

test "RollingFileWriter rotation" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var rfw = try RollingFileWriter.init(tmp.dir, "rotate.log", .{ .max_bytes = 50, .max_backups = 3 });
    defer rfw.deinit();

    for (0..20) |_| {
        rfw.writer().writeAll("rotation test message that fills up\n") catch {};
    }
    rfw.flush();

    const stat1 = tmp.dir.statFile("rotate.log.1") catch null;
    try std.testing.expect(stat1 != null);
}

test "RollingFileWriter as AnyWriter" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var rfw = try RollingFileWriter.init(tmp.dir, "any.log", .{});
    defer rfw.deinit();

    const any: std.io.AnyWriter = rfw.writer().any();
    any.writeAll("via any writer\n") catch {};
    rfw.flush();

    const content = try tmp.dir.readFileAlloc(std.testing.allocator, "any.log", 4096);
    defer std.testing.allocator.free(content);
    try std.testing.expect(std.mem.indexOf(u8, content, "via any writer") != null);
}

test "FileAppend basic write" {
    const layout = @import("layout.zig");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var fa = try FileAppend(layout.TextLayout).init(
        std.testing.allocator,
        layout.TextLayout{},
        tmp.dir,
        "test.log",
        .{ .max_bytes = 1024 * 1024, .max_backups = 3 },
    );
    defer fa.deinit();

    var record = Record{
        .timestamp_us = 1234,
        .level = .info,
        .scope_name = rec.scopeName(.fork_choice),
        .message = "block applied",
    };
    record.pushEventAttr(Attr.uint("slot", 42));

    fa.append(&record);
    fa.flush();

    try std.testing.expect(fa.rolling_writer.current_size > 0);

    const content = try tmp.dir.readFileAlloc(std.testing.allocator, "test.log", 4096);
    defer std.testing.allocator.free(content);
    try std.testing.expect(std.mem.indexOf(u8, content, "block applied") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "slot=42") != null);
}

test "FileAppend rotation" {
    const layout = @import("layout.zig");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var fa = try FileAppend(layout.TextLayout).init(
        std.testing.allocator,
        layout.TextLayout{},
        tmp.dir,
        "rotate.log",
        .{ .max_bytes = 100, .max_backups = 3 },
    );
    defer fa.deinit();

    for (0..20) |i| {
        var record = Record{
            .timestamp_us = @as(i64, @intCast(i)),
            .level = .info,
            .scope_name = rec.scopeName(.default),
            .message = "rotation test message that is fairly long to fill up the file",
        };
        fa.append(&record);
    }

    fa.flush();

    const stat1 = tmp.dir.statFile("rotate.log.1") catch null;
    try std.testing.expect(stat1 != null);
}

test "OpenTelemetryAppend basic" {
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    var ota = OpenTelemetryAppend.init(std.testing.allocator, FlushableWriter.noFlush(fbs.writer().any()));

    var record = Record{
        .timestamp_us = 1234567890,
        .level = .info,
        .scope_name = rec.scopeName(.fork_choice),
        .message = "block applied",
    };
    record.pushEventAttr(Attr.uint("slot", 42));

    ota.append(&record);

    const output = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, output, "\"timeUnixNano\":1234567890000") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"severityNumber\":9") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"severityText\":\"INFO\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"stringValue\":\"block applied\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"key\":\"scope\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"key\":\"slot\"") != null);
    try std.testing.expect(output[output.len - 1] == '\n');
}

test "OpenTelemetryAppend severity mapping" {
    const levels = [_]struct { level: std.log.Level, num: []const u8, text: []const u8 }{
        .{ .level = .err, .num = "\"severityNumber\":17", .text = "\"severityText\":\"ERROR\"" },
        .{ .level = .warn, .num = "\"severityNumber\":13", .text = "\"severityText\":\"WARN\"" },
        .{ .level = .info, .num = "\"severityNumber\":9", .text = "\"severityText\":\"INFO\"" },
        .{ .level = .debug, .num = "\"severityNumber\":5", .text = "\"severityText\":\"DEBUG\"" },
    };

    for (levels) |tc| {
        var buf: [2048]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        var ota = OpenTelemetryAppend.init(std.testing.allocator, FlushableWriter.noFlush(fbs.writer().any()));

        var record = Record{
            .timestamp_us = 0,
            .level = tc.level,
            .scope_name = rec.scopeName(.default),
            .message = "test",
        };
        ota.append(&record);

        const output = fbs.getWritten();
        try std.testing.expect(std.mem.indexOf(u8, output, tc.num) != null);
        try std.testing.expect(std.mem.indexOf(u8, output, tc.text) != null);
    }
}

test "OpenTelemetryAppend escapes special characters" {
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    var ota = OpenTelemetryAppend.init(std.testing.allocator, FlushableWriter.noFlush(fbs.writer().any()));

    var record = Record{
        .timestamp_us = 0,
        .level = .info,
        .scope_name = rec.scopeName(.default),
        .message = "line1\nline2",
    };
    ota.append(&record);

    const output = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, output, "line1\\nline2") != null);
}

test "AsyncAppend basic enqueue and drain" {
    const layout = @import("layout.zig");
    var out_buf: [4096]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&out_buf);
    var appender = try AsyncAppend(layout.TextLayout).init(
        std.testing.allocator,
        16,
        FlushableWriter.noFlush(fbs.writer().any()),
        layout.TextLayout{},
        .block,
    );

    try appender.start();

    var rec1 = Record{
        .timestamp_us = 1234,
        .level = .info,
        .scope_name = rec.scopeName(.default),
        .message = "hello async",
    };
    appender.append(&rec1);
    var rec2 = Record{
        .timestamp_us = 1234,
        .level = .info,
        .scope_name = rec.scopeName(.default),
        .message = "second message",
    };
    appender.append(&rec2);

    std.time.sleep(50_000_000);

    appender.deinit();

    const output = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, output, "hello async") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "second message") != null);
}

test "AsyncAppend shutdown drains remaining" {
    const layout = @import("layout.zig");
    var out_buf: [8192]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&out_buf);
    var appender = try AsyncAppend(layout.TextLayout).init(
        std.testing.allocator,
        16,
        FlushableWriter.noFlush(fbs.writer().any()),
        layout.TextLayout{},
        .block,
    );

    var rec1 = Record{ .timestamp_us = 1234, .level = .info, .scope_name = rec.scopeName(.default), .message = "msg1" };
    appender.append(&rec1);
    var rec2 = Record{ .timestamp_us = 1234, .level = .info, .scope_name = rec.scopeName(.default), .message = "msg2" };
    appender.append(&rec2);
    var rec3 = Record{ .timestamp_us = 1234, .level = .info, .scope_name = rec.scopeName(.default), .message = "msg3" };
    appender.append(&rec3);

    appender.deinit();

    const output = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, output, "msg1") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "msg2") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "msg3") != null);
}

test "AsyncAppend drops when full" {
    const layout = @import("layout.zig");
    var out_buf: [8192]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&out_buf);
    var appender = try AsyncAppend(layout.TextLayout).init(
        std.testing.allocator,
        4,
        FlushableWriter.noFlush(fbs.writer().any()),
        layout.TextLayout{},
        .drop_incoming,
    );

    for (0..10) |i| {
        var record = Record{
            .timestamp_us = @as(i64, @intCast(i)),
            .level = .info,
            .scope_name = rec.scopeName(.default),
            .message = "overflow",
        };
        appender.append(&record);
    }

    appender.deinit();

    const output = fbs.getWritten();
    try std.testing.expect(output.len > 0);
}

test "AsyncAppend large message SBO heap path" {
    const layout = @import("layout.zig");

    // Build a message that exceeds max_message_size after formatting.
    // TextLayout adds prefix (timestamp, level, scope) + attrs, so we need a
    // message body close to the limit. A 4000-byte body + prefix ≈ 4060 bytes
    // (inline), but a 5000-byte body will certainly exceed 4096 total.
    var long_body: [5000]u8 = undefined;
    @memset(&long_body, 'Q');

    // Use an ArrayList-backed writer to capture the full output.
    var out_list = std.ArrayList(u8).init(std.testing.allocator);
    defer out_list.deinit();

    var appender = try AsyncAppend(layout.TextLayout).init(
        std.testing.allocator,
        16,
        FlushableWriter.noFlush(out_list.writer().any()),
        layout.TextLayout{},
        .block,
    );

    try appender.start();

    var record = Record{
        .timestamp_us = 1234,
        .level = .info,
        .scope_name = rec.scopeName(.default),
        .message = &long_body,
    };
    appender.append(&record);

    // Also push a short message to verify interleaving works.
    var short_record = Record{
        .timestamp_us = 1234,
        .level = .debug,
        .scope_name = rec.scopeName(.default),
        .message = "short",
    };
    appender.append(&short_record);

    std.time.sleep(50_000_000);
    appender.deinit();

    const output = out_list.items;
    // The long message must appear UN-truncated (all 5000 Q's present).
    try std.testing.expect(std.mem.indexOf(u8, output, &long_body) != null);
    // Short message must also appear.
    try std.testing.expect(std.mem.indexOf(u8, output, "short") != null);
}

test "AsyncAppend drop_incoming frees heap on overflow" {
    const layout = @import("layout.zig");

    // Use a tiny ring (4 slots) with drop_incoming and push large messages.
    // This exercises the enqueue helper's deinit path for dropped heap messages.
    // If heap isn't freed, the testing allocator will catch the leak.
    var out_buf: [8192]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&out_buf);
    var appender = try AsyncAppend(layout.TextLayout).init(
        std.testing.allocator,
        4,
        FlushableWriter.noFlush(fbs.writer().any()),
        layout.TextLayout{},
        .drop_incoming,
    );
    // Don't start consumer thread — ring will fill immediately.

    var long_body: [5000]u8 = undefined;
    @memset(&long_body, 'H');

    for (0..8) |i| {
        var record = Record{
            .timestamp_us = @as(i64, @intCast(i)),
            .level = .info,
            .scope_name = rec.scopeName(.default),
            .message = &long_body,
        };
        appender.append(&record);
    }

    // Deinit drains remaining and frees the ring.
    appender.deinit();
}

// ──────────── AsyncAppend × Layout combinations ─────────────

test "AsyncAppend with JsonLayout" {
    const layout = @import("layout.zig");
    var out_list = std.ArrayList(u8).init(std.testing.allocator);
    defer out_list.deinit();

    var appender = try AsyncAppend(layout.JsonLayout).init(
        std.testing.allocator,
        16,
        FlushableWriter.noFlush(out_list.writer().any()),
        layout.JsonLayout{},
        .block,
    );
    try appender.start();

    var record = Record{
        .timestamp_us = 1000,
        .level = .warn,
        .scope_name = rec.scopeName(.ssz),
        .message = "json async test",
    };
    record.pushEventAttr(Attr.uint("slot", 99));
    appender.append(&record);

    std.time.sleep(50_000_000);
    appender.deinit();

    const output = out_list.items;
    try std.testing.expect(std.mem.indexOf(u8, output, "\"level\":\"warn\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"msg\":\"json async test\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"slot\":99") != null);
}

test "AsyncAppend with LogfmtLayout" {
    const layout = @import("layout.zig");
    var out_list = std.ArrayList(u8).init(std.testing.allocator);
    defer out_list.deinit();

    var appender = try AsyncAppend(layout.LogfmtLayout).init(
        std.testing.allocator,
        16,
        FlushableWriter.noFlush(out_list.writer().any()),
        layout.LogfmtLayout{},
        .block,
    );
    try appender.start();

    var record = Record{
        .timestamp_us = 2000,
        .level = .info,
        .scope_name = rec.scopeName(.fork_choice),
        .message = "logfmt async test",
    };
    record.pushEventAttr(Attr.uint("epoch", 7));
    appender.append(&record);

    std.time.sleep(50_000_000);
    appender.deinit();

    const output = out_list.items;
    try std.testing.expect(std.mem.indexOf(u8, output, "msg=\"logfmt async test\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "epoch=7") != null);
}

// ──────────── WriterAppend × LogfmtLayout ─────────────

test "WriterAppend with LogfmtLayout" {
    const layout = @import("layout.zig");
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    var wa = WriterAppend(layout.LogfmtLayout).init(std.testing.allocator, layout.LogfmtLayout{}, FlushableWriter.noFlush(fbs.writer().any()));

    var record = Record{
        .timestamp_us = 1234,
        .level = .debug,
        .scope_name = rec.scopeName(.ssz),
        .message = "logfmt writer test",
    };
    record.pushEventAttr(Attr.boolean("ok", true));

    wa.append(&record);

    const output = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, output, "msg=\"logfmt writer test\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "ok=true") != null);
}

// ──────────── FileAppend × Layout combinations ─────────────

test "FileAppend with JsonLayout" {
    const layout = @import("layout.zig");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var fa = try FileAppend(layout.JsonLayout).init(
        std.testing.allocator,
        layout.JsonLayout{},
        tmp.dir,
        "json.log",
        .{ .max_bytes = 1024 * 1024, .max_backups = 3 },
    );
    defer fa.deinit();

    var record = Record{
        .timestamp_us = 5000,
        .level = .err,
        .scope_name = rec.scopeName(.fork_choice),
        .message = "json file test",
    };
    record.pushEventAttr(Attr.uint("slot", 100));

    fa.append(&record);
    fa.flush();

    const content = try tmp.dir.readFileAlloc(std.testing.allocator, "json.log", 4096);
    defer std.testing.allocator.free(content);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"level\":\"error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"msg\":\"json file test\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"slot\":100") != null);
}

test "FileAppend with LogfmtLayout" {
    const layout = @import("layout.zig");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var fa = try FileAppend(layout.LogfmtLayout).init(
        std.testing.allocator,
        layout.LogfmtLayout{},
        tmp.dir,
        "logfmt.log",
        .{ .max_bytes = 1024 * 1024, .max_backups = 3 },
    );
    defer fa.deinit();

    var record = Record{
        .timestamp_us = 6000,
        .level = .warn,
        .scope_name = rec.scopeName(.ssz),
        .message = "logfmt file test",
    };
    record.pushEventAttr(Attr.str("key", "val"));

    fa.append(&record);
    fa.flush();

    const content = try tmp.dir.readFileAlloc(std.testing.allocator, "logfmt.log", 4096);
    defer std.testing.allocator.free(content);
    try std.testing.expect(std.mem.indexOf(u8, content, "msg=\"logfmt file test\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "key=val") != null);
}

// ──────────── SBO large message × Layout combinations ─────────────

test "AsyncAppend SBO large message with JsonLayout" {
    const layout = @import("layout.zig");

    var long_body: [5000]u8 = undefined;
    @memset(&long_body, 'J');

    var out_list = std.ArrayList(u8).init(std.testing.allocator);
    defer out_list.deinit();

    var appender = try AsyncAppend(layout.JsonLayout).init(
        std.testing.allocator,
        16,
        FlushableWriter.noFlush(out_list.writer().any()),
        layout.JsonLayout{},
        .block,
    );
    try appender.start();

    var record = Record{
        .timestamp_us = 1234,
        .level = .info,
        .scope_name = rec.scopeName(.default),
        .message = &long_body,
    };
    appender.append(&record);

    std.time.sleep(50_000_000);
    appender.deinit();

    const output = out_list.items;
    // Full 5000 J's must appear un-truncated in JSON value.
    try std.testing.expect(std.mem.indexOf(u8, output, &long_body) != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"level\":\"info\"") != null);
}

test "AsyncAppend SBO large message with LogfmtLayout" {
    const layout = @import("layout.zig");

    var long_body: [5000]u8 = undefined;
    @memset(&long_body, 'L');

    var out_list = std.ArrayList(u8).init(std.testing.allocator);
    defer out_list.deinit();

    var appender = try AsyncAppend(layout.LogfmtLayout).init(
        std.testing.allocator,
        16,
        FlushableWriter.noFlush(out_list.writer().any()),
        layout.LogfmtLayout{},
        .block,
    );
    try appender.start();

    var record = Record{
        .timestamp_us = 1234,
        .level = .info,
        .scope_name = rec.scopeName(.default),
        .message = &long_body,
    };
    appender.append(&record);

    std.time.sleep(50_000_000);
    appender.deinit();

    const output = out_list.items;
    try std.testing.expect(std.mem.indexOf(u8, output, &long_body) != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "level=info") != null);
}

// ──────────── Rotation and time-based rolling tests ─────────────

test "Rotation.nextDateTimestamp minutely" {
    // 2026-04-11 10:30:45.123 → next boundary = 10:31:00.000
    const ms: i64 = 1_776_000_000_000 + 37_845_123;
    const next = Rotation.minutely.nextDateTimestamp(ms).?;
    try std.testing.expect(next > ms);
    // Next boundary should be at most 60s ahead.
    try std.testing.expect(next - ms <= 60_000);
    // Must be exactly on a minute boundary.
    try std.testing.expectEqual(@as(i64, 0), @rem(next, 60_000));
}

test "Rotation.nextDateTimestamp hourly" {
    const ms: i64 = 1_776_000_000_000;
    const next = Rotation.hourly.nextDateTimestamp(ms).?;
    try std.testing.expect(next > ms);
    try std.testing.expect(next - ms <= 3_600_000);
    try std.testing.expectEqual(@as(i64, 0), @rem(next, 3_600_000));
}

test "Rotation.nextDateTimestamp daily" {
    const ms: i64 = 1_776_000_000_000;
    const next = Rotation.daily.nextDateTimestamp(ms).?;
    try std.testing.expect(next > ms);
    try std.testing.expect(next - ms <= 86_400_000);
    try std.testing.expectEqual(@as(i64, 0), @rem(next, 86_400_000));
}

test "Rotation.nextDateTimestamp never" {
    try std.testing.expect(Rotation.never.nextDateTimestamp(1_000_000) == null);
}

test "Rotation.formatDate daily" {
    // 2026-01-15 00:00:00 UTC = 1_768_435_200_000 ms
    const ms: i64 = 1_768_435_200_000;
    var buf: [24]u8 = undefined;
    const s = Rotation.daily.formatDate(ms, &buf);
    try std.testing.expectEqualStrings("2026-01-15", s);
}

test "Rotation.formatDate hourly" {
    // 2026-01-15 13:00:00 UTC
    const ms: i64 = 1_768_435_200_000 + 13 * 3_600_000;
    var buf: [24]u8 = undefined;
    const s = Rotation.hourly.formatDate(ms, &buf);
    try std.testing.expectEqualStrings("2026-01-15-13", s);
}

test "Rotation.formatDate minutely" {
    // 2026-01-15 13:45:00 UTC
    const ms: i64 = 1_768_435_200_000 + 13 * 3_600_000 + 45 * 60_000;
    var buf: [24]u8 = undefined;
    const s = Rotation.minutely.formatDate(ms, &buf);
    try std.testing.expectEqualStrings("2026-01-15-13-45", s);
}

test "RollingFileWriter time-based rotation creates dated archives" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Use daily rotation with explicit timestamp control.
    const t0: i64 = 1_768_435_200_000; // 2026-01-15 00:00:00 UTC
    var rfw = try RollingFileWriter.initWithTimestamp(tmp.dir, "app.log", .{
        .rotation = .daily,
        .max_bytes = 0, // no size limit
        .max_backups = 5,
    }, t0);
    defer rfw.deinit();

    // Write at t0 (day 1).
    _ = try rfw.writeWithTimestamp("day one data\n", t0 + 1000);

    // Advance to next day to trigger rotation.
    const t1 = t0 + 86_400_000; // 2026-01-16
    _ = try rfw.writeWithTimestamp("day two data\n", t1 + 1000);

    rfw.flush();

    // Archive from day 1 should exist as app.log.2026-01-15.1
    const archive = tmp.dir.statFile("app.log.2026-01-15.1") catch null;
    try std.testing.expect(archive != null);

    // Current file should have day two data.
    const content = try tmp.dir.readFileAlloc(std.testing.allocator, "app.log", 4096);
    defer std.testing.allocator.free(content);
    try std.testing.expect(std.mem.indexOf(u8, content, "day two data") != null);
}

test "RollingFileWriter dual rollover (time + size)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const t0: i64 = 1_768_435_200_000;
    var rfw = try RollingFileWriter.initWithTimestamp(tmp.dir, "dual.log", .{
        .rotation = .daily,
        .max_bytes = 50,
        .max_backups = 5,
    }, t0);
    defer rfw.deinit();

    // Write enough to trigger size-based rotation within same day.
    for (0..5) |_| {
        _ = try rfw.writeWithTimestamp("fill up the file with data!!\n", t0 + 1000);
    }

    rfw.flush();

    // Size-based archives with dated names should exist.
    const archive1 = tmp.dir.statFile("dual.log.2026-01-15.1") catch null;
    try std.testing.expect(archive1 != null);
}

// ──────────── Compile-time appender enforcement test ─────────────

test "Dispatch requires at least one appender (positive case)" {
    // This test verifies that compilation succeeds with one appender.
    const filter_mod = @import("filter.zig");
    const layout = @import("layout.zig");
    const dispatch_mod = @import("dispatch.zig");

    const TA = TestingAppend(layout.TextLayout);
    const MyDispatch = dispatch_mod.Dispatch(
        struct { filter_mod.LevelFilter },
        struct {},
        struct { TA },
    );

    var d = MyDispatch{
        .filters = .{filter_mod.LevelFilter.init(.debug)},
        .diagnostics = .{},
        .appenders = .{TA.init(std.testing.allocator, layout.TextLayout{})},
    };

    var record = Record{
        .timestamp_us = 0,
        .level = .info,
        .scope_name = rec.scopeName(.default),
        .message = "enforced",
    };
    d.process(&record);
    try std.testing.expect(d.appenders[0].contains("enforced"));
}
