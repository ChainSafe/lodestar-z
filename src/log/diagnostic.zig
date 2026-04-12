//! Diagnostic enrichment for the logging pipeline.
//!
//! Diagnostics inject contextual attributes (network, version, thread-local
//! state) into Records before filtering and output.

const std = @import("std");
const rec = @import("record.zig");
const Attr = rec.Attr;
const Record = rec.Record;

// ────────────────────── StaticDiagnostic ──────────────────────

/// App-wide static diagnostic attributes set at startup.
/// Example: node_id, network, version.
pub fn StaticDiagnostic(comptime max_attrs: usize) type {
    return struct {
        const Self = @This();

        attrs: std.BoundedArray(Attr, max_attrs),

        pub fn init() Self {
            return .{ .attrs = .{} };
        }

        pub fn add(self: *Self, attr: Attr) void {
            self.attrs.append(attr) catch {};
        }

        /// Diagnostic interface: push all static attrs into the record.
        pub fn enrich(self: *const Self, record: *Record) void {
            for (self.attrs.constSlice()) |attr| {
                record.pushDiagAttr(attr);
            }
        }

        /// Type-erase to AnyDiagnostic. Caller must keep `self` alive.
        pub fn any(self: *const Self) rec.AnyDiagnostic {
            return .{
                .ptr = @ptrCast(@constCast(self)),
                .enrich_fn = struct {
                    fn f(ptr: *anyopaque, record: *Record) void {
                        const s: *const Self = @ptrCast(@alignCast(ptr));
                        s.enrich(record);
                    }
                }.f,
            };
        }
    };
}

// ──────────────── ThreadLocalDiagnostic ──────────────────

/// Per-thread diagnostic context using Zig's `threadlocal` storage.
///
/// Each thread has its own independent set of attributes. Attributes set on
/// one thread are invisible to other threads.
pub fn ThreadLocalDiagnostic(comptime max_attrs: usize) type {
    return struct {
        const Self = @This();

        threadlocal var tls_attrs: std.BoundedArray(Attr, max_attrs) = .{};

        /// Set (append) a diagnostic attribute on the current thread.
        pub fn set(attr: Attr) void {
            tls_attrs.append(attr) catch {};
        }

        /// Clear all diagnostic attributes on the current thread.
        pub fn clear() void {
            tls_attrs.len = 0;
        }

        /// Diagnostic interface: push all thread-local attrs into the record.
        pub fn enrich(_: *const Self, record: *Record) void {
            for (tls_attrs.constSlice()) |attr| {
                record.pushDiagAttr(attr);
            }
        }

        /// Type-erase to AnyDiagnostic. Caller must keep `self` alive.
        pub fn any(self: *const Self) rec.AnyDiagnostic {
            return .{
                .ptr = @ptrCast(@constCast(self)),
                .enrich_fn = struct {
                    fn f(ptr: *anyopaque, record: *Record) void {
                        const s: *const Self = @ptrCast(@alignCast(ptr));
                        s.enrich(record);
                    }
                }.f,
            };
        }
    };
}

// ──────────────────────────── Tests ────────────────────────────

test "StaticDiagnostic enriches record" {
    var diag = StaticDiagnostic(4).init();
    diag.add(Attr.str("network", "mainnet"));
    diag.add(Attr.str("version", "1.0.0"));

    var record = Record{
        .timestamp_us = 0,
        .level = .info,
        .scope_name = "default",
        .message = "test",
    };

    diag.enrich(&record);
    try std.testing.expectEqual(@as(usize, 2), record.diag_attrs.len);
    try std.testing.expectEqualStrings("network", record.diag_attrs.constSlice()[0].key);
    try std.testing.expectEqualStrings("version", record.diag_attrs.constSlice()[1].key);
}

test "StaticDiagnostic empty" {
    const diag = StaticDiagnostic(4).init();
    var record = Record{
        .timestamp_us = 0,
        .level = .info,
        .scope_name = "default",
        .message = "test",
    };

    diag.enrich(&record);
    try std.testing.expectEqual(@as(usize, 0), record.diag_attrs.len);
}

test "ThreadLocalDiagnostic enriches record" {
    const TLD = ThreadLocalDiagnostic(4);
    TLD.clear();
    defer TLD.clear();

    TLD.set(Attr.uint("validator_index", 42));
    TLD.set(Attr.str("subnet", "attnets"));

    var record = Record{
        .timestamp_us = 0,
        .level = .info,
        .scope_name = rec.scopeName(.default),
        .message = "test",
    };

    const diag = TLD{};
    diag.enrich(&record);

    try std.testing.expectEqual(@as(usize, 2), record.diag_attrs.len);
    try std.testing.expectEqualStrings("validator_index", record.diag_attrs.constSlice()[0].key);
    try std.testing.expectEqualStrings("subnet", record.diag_attrs.constSlice()[1].key);
}

test "ThreadLocalDiagnostic clear" {
    const TLD = ThreadLocalDiagnostic(4);
    TLD.clear();
    defer TLD.clear();

    TLD.set(Attr.str("key", "value"));
    TLD.clear();

    var record = Record{
        .timestamp_us = 0,
        .level = .info,
        .scope_name = rec.scopeName(.default),
        .message = "test",
    };

    const diag = TLD{};
    diag.enrich(&record);

    try std.testing.expectEqual(@as(usize, 0), record.diag_attrs.len);
}

test "ThreadLocalDiagnostic cross-thread isolation" {
    const TLD = ThreadLocalDiagnostic(4);
    TLD.clear();
    defer TLD.clear();

    TLD.set(Attr.str("thread", "main"));

    var other_count = std.atomic.Value(usize).init(0);

    const thread = try std.Thread.spawn(.{}, struct {
        fn run(count: *std.atomic.Value(usize)) void {
            var record = Record{
                .timestamp_us = 0,
                .level = .info,
                .scope_name = rec.scopeName(.default),
                .message = "other",
            };
            const diag = TLD{};
            diag.enrich(&record);
            count.store(record.diag_attrs.len, .release);
        }
    }.run, .{&other_count});
    thread.join();

    try std.testing.expectEqual(@as(usize, 0), other_count.load(.acquire));
}

// ──────────────── .any() type-erasure tests ────────────────

test "StaticDiagnostic.any enriches through type erasure" {
    var diag = StaticDiagnostic(4).init();
    diag.add(Attr.str("network", "mainnet"));

    const any_diag = diag.any();

    var record = Record{
        .timestamp_us = 0,
        .level = .info,
        .scope_name = "default",
        .message = "test",
    };

    any_diag.enrich(&record);
    try std.testing.expectEqual(@as(usize, 1), record.diag_attrs.len);
    try std.testing.expectEqualStrings("network", record.diag_attrs.constSlice()[0].key);
}

test "ThreadLocalDiagnostic.any enriches through type erasure" {
    const TLD = ThreadLocalDiagnostic(4);
    TLD.clear();
    defer TLD.clear();

    TLD.set(Attr.uint("slot", 99));

    var diag = TLD{};
    const any_diag = diag.any();

    var record = Record{
        .timestamp_us = 0,
        .level = .info,
        .scope_name = rec.scopeName(.default),
        .message = "test",
    };

    any_diag.enrich(&record);
    try std.testing.expectEqual(@as(usize, 1), record.diag_attrs.len);
    try std.testing.expectEqualStrings("slot", record.diag_attrs.constSlice()[0].key);
}
