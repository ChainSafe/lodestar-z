//! Filter implementations for the logging pipeline.
//!
//! Filters decide whether a log record should proceed through the pipeline.
//! Each filter returns a FilterResult (accept/reject/neutral).

const std = @import("std");
const rec = @import("record.zig");
const Record = rec.Record;
const FilterResult = rec.FilterResult;

// ──────────────────────── LevelFilter ────────────────────────

/// Filter with 8 variants matching logforth's LevelFilter.
///
/// Zig level ordering: err(0) < warn(1) < info(2) < debug(3).
/// "More severe" = lower numeric value.
pub const LevelFilter = union(enum) {
    /// Always reject — disables logging entirely.
    off: void,
    /// Always accept — passes all levels.
    all: void,
    /// Accept only the exact level.
    equal: std.log.Level,
    /// Accept everything except the exact level.
    not_equal: std.log.Level,
    /// Accept levels strictly more severe (lower numeric) than the threshold.
    more_severe: std.log.Level,
    /// Accept levels at or more severe than the threshold (old default behavior).
    more_severe_equal: std.log.Level,
    /// Accept levels strictly more verbose (higher numeric) than the threshold.
    more_verbose: std.log.Level,
    /// Accept levels at or more verbose than the threshold.
    more_verbose_equal: std.log.Level,

    /// Backward-compatible factory — same semantics as old threshold.
    pub fn init(min_level: std.log.Level) LevelFilter {
        return .{ .more_severe_equal = min_level };
    }

    /// Extract the level from variants that carry one, or null for off/all.
    pub fn getLevel(self: LevelFilter) ?std.log.Level {
        return switch (self) {
            .off, .all => null,
            inline else => |lvl| lvl,
        };
    }

    /// Fast pre-check on level alone (scope is ignored).
    pub fn enabled(self: LevelFilter, level: std.log.Level, _: []const u8) FilterResult {
        return self.check(level);
    }

    /// Full record check — delegates to level comparison.
    pub fn matches(self: LevelFilter, record: *const Record) FilterResult {
        return self.check(record.level);
    }

    fn check(self: LevelFilter, level: std.log.Level) FilterResult {
        const lv = @intFromEnum(level);
        return switch (self) {
            .off => .reject,
            .all => .accept,
            inline else => |threshold| blk: {
                const tv = @intFromEnum(threshold);
                break :blk switch (self) {
                    .off, .all => unreachable,
                    .equal => if (lv == tv) .accept else .reject,
                    .not_equal => if (lv != tv) .accept else .reject,
                    .more_severe => if (lv < tv) .accept else .reject,
                    .more_severe_equal => if (lv <= tv) .accept else .reject,
                    .more_verbose => if (lv > tv) .accept else .reject,
                    .more_verbose_equal => if (lv >= tv) .accept else .reject,
                };
            },
        };
    }
};

// ──────────────────────── ScopeFilter ────────────────────────

pub const max_scopes = 32;

pub const Override = struct {
    scope_name: []const u8,
    min_level: std.log.Level,
};

/// Per-scope level override filter.
/// If a scope matches, applies its level threshold.
/// If no scope matches, returns neutral (defer to other filters).
pub const ScopeFilter = struct {
    overrides: std.BoundedArray(Override, max_scopes),

    pub fn init() ScopeFilter {
        return .{ .overrides = .{} };
    }

    pub fn addOverride(self: *ScopeFilter, scope_name: []const u8, min_level: std.log.Level) void {
        self.overrides.append(.{ .scope_name = scope_name, .min_level = min_level }) catch {};
    }

    /// Fast pre-check using level + scope_name.
    pub fn enabled(self: ScopeFilter, level: std.log.Level, scope_name: []const u8) FilterResult {
        for (self.overrides.constSlice()) |ovr| {
            if (std.mem.eql(u8, ovr.scope_name, scope_name)) {
                return if (@intFromEnum(level) <= @intFromEnum(ovr.min_level)) .accept else .reject;
            }
        }
        return .neutral;
    }

    /// Full record check — delegates to enabled() with record fields.
    pub fn matches(self: ScopeFilter, record: *const Record) FilterResult {
        return self.enabled(record.level, record.scope_name);
    }
};

// ──────────────────────── EnvFilter ────────────────────────

pub const env_var_name = "LODESTAR_Z_LOG";

/// Composite filter with scope-first semantics (matches logforth/tracing).
///
/// When evaluating a record:
///   1. Check scope overrides — if match found, use its level threshold.
///   2. Fall back to base level threshold.
///
/// This means `"warn,fork_choice=debug"` allows debug messages from
/// fork_choice, even though the base level is warn.
pub const EnvFilter = struct {
    base_level: LevelFilter,
    scope_filter: ScopeFilter,

    /// Fast pre-check: scope override wins over base level.
    pub fn enabled(self: EnvFilter, level: std.log.Level, scope_name: []const u8) FilterResult {
        const scope_result = self.scope_filter.enabled(level, scope_name);
        if (scope_result != .neutral) return scope_result;
        return self.base_level.enabled(level, scope_name);
    }

    /// Full record check: scope override wins over base level.
    pub fn matches(self: EnvFilter, record: *const Record) FilterResult {
        return self.enabled(record.level, record.scope_name);
    }
};

/// Parse the LODESTAR_Z_LOG environment variable.
/// Format: "level" or "level,scope1=level1,scope2=level2"
/// Returns null if env var is not set or unparseable.
pub fn fromEnv() ?EnvFilter {
    const raw_ptr = std.posix.getenv(env_var_name) orelse return null;
    const raw = std.mem.sliceTo(raw_ptr, 0);
    return parse(raw);
}

/// Parse a LODESTAR_Z_LOG-format string into an EnvFilter.
pub fn parse(input: []const u8) ?EnvFilter {
    if (input.len == 0) return null;

    var filter = EnvFilter{
        .base_level = LevelFilter.init(.info),
        .scope_filter = ScopeFilter.init(),
    };

    var iter = std.mem.splitScalar(u8, input, ',');
    var first = true;
    while (iter.next()) |segment| {
        const trimmed = std.mem.trim(u8, segment, " ");
        if (trimmed.len == 0) continue;

        if (std.mem.indexOfScalar(u8, trimmed, '=')) |eq_pos| {
            const scope_name = std.mem.trim(u8, trimmed[0..eq_pos], " ");
            const level_str = std.mem.trim(u8, trimmed[eq_pos + 1 ..], " ");
            if (rec.parseLevel(level_str)) |lvl| {
                filter.scope_filter.addOverride(scope_name, lvl);
            }
        } else {
            if (first) {
                if (rec.parseLevel(trimmed)) |lvl| {
                    filter.base_level = LevelFilter.init(lvl);
                }
            }
        }
        first = false;
    }

    return filter;
}

// ──────────────────────────── Tests ────────────────────────────

test "LevelFilter enabled" {
    const f = LevelFilter.init(.warn);
    try std.testing.expectEqual(FilterResult.accept, f.enabled(.err, ""));
    try std.testing.expectEqual(FilterResult.accept, f.enabled(.warn, ""));
    try std.testing.expectEqual(FilterResult.reject, f.enabled(.info, ""));
    try std.testing.expectEqual(FilterResult.reject, f.enabled(.debug, ""));
}

test "LevelFilter matches" {
    const f = LevelFilter.init(.warn);
    const err_rec = Record{ .timestamp_us = 0, .level = .err, .scope_name = "default", .message = "" };
    try std.testing.expectEqual(FilterResult.accept, f.matches(&err_rec));
    const info_rec = Record{ .timestamp_us = 0, .level = .info, .scope_name = "default", .message = "" };
    try std.testing.expectEqual(FilterResult.reject, f.matches(&info_rec));
}

test "LevelFilter debug accepts all" {
    const f = LevelFilter.init(.debug);
    try std.testing.expectEqual(FilterResult.accept, f.enabled(.err, ""));
    try std.testing.expectEqual(FilterResult.accept, f.enabled(.debug, ""));
}

test "ScopeFilter matches scope" {
    var f = ScopeFilter.init();
    f.addOverride("ssz", .debug);
    f.addOverride("fork_choice", .err);
    try std.testing.expectEqual(FilterResult.accept, f.enabled(.debug, "ssz"));
    try std.testing.expectEqual(FilterResult.reject, f.enabled(.info, "fork_choice"));
    try std.testing.expectEqual(FilterResult.accept, f.enabled(.err, "fork_choice"));
}

test "ScopeFilter neutral for unknown scope" {
    var f = ScopeFilter.init();
    f.addOverride("ssz", .err);
    try std.testing.expectEqual(FilterResult.neutral, f.enabled(.debug, "state_transition"));
}

test "ScopeFilter matches delegates to enabled" {
    var f = ScopeFilter.init();
    f.addOverride("ssz", .warn);
    const r1 = Record{ .timestamp_us = 0, .level = .info, .scope_name = "ssz", .message = "" };
    try std.testing.expectEqual(FilterResult.reject, f.matches(&r1));
    const r2 = Record{ .timestamp_us = 0, .level = .err, .scope_name = "ssz", .message = "" };
    try std.testing.expectEqual(FilterResult.accept, f.matches(&r2));
}

test "parse bare level" {
    const f = parse("debug").?;
    try std.testing.expectEqual(std.log.Level.debug, f.base_level.getLevel().?);
    try std.testing.expectEqual(@as(usize, 0), f.scope_filter.overrides.len);
}

test "parse level with scope overrides" {
    const f = parse("info,fork_choice=debug,ssz=warn").?;
    try std.testing.expectEqual(std.log.Level.info, f.base_level.getLevel().?);
    try std.testing.expectEqual(@as(usize, 2), f.scope_filter.overrides.len);
    const o1 = f.scope_filter.overrides.constSlice()[0];
    try std.testing.expectEqualStrings("fork_choice", o1.scope_name);
    try std.testing.expectEqual(std.log.Level.debug, o1.min_level);
    const o2 = f.scope_filter.overrides.constSlice()[1];
    try std.testing.expectEqualStrings("ssz", o2.scope_name);
    try std.testing.expectEqual(std.log.Level.warn, o2.min_level);
}

test "parse empty returns null" {
    try std.testing.expect(parse("") == null);
}

test "parse invalid level" {
    const f = parse("verbose").?;
    try std.testing.expectEqual(std.log.Level.info, f.base_level.getLevel().?);
}

test "EnvFilter scope override trumps base level" {
    // "warn,fork_choice=debug" — debug from fork_choice should PASS
    const f = parse("warn,fork_choice=debug").?;

    // debug from fork_choice → scope override match (debug threshold) → accept
    try std.testing.expectEqual(FilterResult.accept, f.enabled(.debug, "fork_choice"));
    // info from fork_choice → scope override match (debug threshold) → accept
    try std.testing.expectEqual(FilterResult.accept, f.enabled(.info, "fork_choice"));
    // debug from default → no scope match → fall back to base level (warn) → reject
    try std.testing.expectEqual(FilterResult.reject, f.enabled(.debug, "default"));
    // warn from default → no scope match → base level (warn) → accept
    try std.testing.expectEqual(FilterResult.accept, f.enabled(.warn, "default"));
    // err from any → always accept
    try std.testing.expectEqual(FilterResult.accept, f.enabled(.err, "whatever"));
}

test "EnvFilter matches delegates to enabled" {
    const f = parse("warn,ssz=debug").?;

    const debug_ssz = Record{ .timestamp_us = 0, .level = .debug, .scope_name = "ssz", .message = "" };
    try std.testing.expectEqual(FilterResult.accept, f.matches(&debug_ssz));

    const debug_other = Record{ .timestamp_us = 0, .level = .debug, .scope_name = "other", .message = "" };
    try std.testing.expectEqual(FilterResult.reject, f.matches(&debug_other));
}

// ──────────────── LevelFilter variant tests ────────────────

test "LevelFilter off rejects everything" {
    const f: LevelFilter = .off;
    try std.testing.expectEqual(FilterResult.reject, f.enabled(.err, ""));
    try std.testing.expectEqual(FilterResult.reject, f.enabled(.debug, ""));
}

test "LevelFilter all accepts everything" {
    const f: LevelFilter = .all;
    try std.testing.expectEqual(FilterResult.accept, f.enabled(.err, ""));
    try std.testing.expectEqual(FilterResult.accept, f.enabled(.debug, ""));
}

test "LevelFilter equal" {
    const f: LevelFilter = .{ .equal = .warn };
    try std.testing.expectEqual(FilterResult.reject, f.enabled(.err, ""));
    try std.testing.expectEqual(FilterResult.accept, f.enabled(.warn, ""));
    try std.testing.expectEqual(FilterResult.reject, f.enabled(.info, ""));
}

test "LevelFilter not_equal" {
    const f: LevelFilter = .{ .not_equal = .warn };
    try std.testing.expectEqual(FilterResult.accept, f.enabled(.err, ""));
    try std.testing.expectEqual(FilterResult.reject, f.enabled(.warn, ""));
    try std.testing.expectEqual(FilterResult.accept, f.enabled(.info, ""));
}

test "LevelFilter more_severe (strict)" {
    // more_severe(.warn) → only err passes (err=0 < warn=1)
    const f: LevelFilter = .{ .more_severe = .warn };
    try std.testing.expectEqual(FilterResult.accept, f.enabled(.err, ""));
    try std.testing.expectEqual(FilterResult.reject, f.enabled(.warn, ""));
    try std.testing.expectEqual(FilterResult.reject, f.enabled(.info, ""));
}

test "LevelFilter more_severe_equal (old threshold)" {
    // more_severe_equal(.warn) → err + warn pass
    const f: LevelFilter = .{ .more_severe_equal = .warn };
    try std.testing.expectEqual(FilterResult.accept, f.enabled(.err, ""));
    try std.testing.expectEqual(FilterResult.accept, f.enabled(.warn, ""));
    try std.testing.expectEqual(FilterResult.reject, f.enabled(.info, ""));
    try std.testing.expectEqual(FilterResult.reject, f.enabled(.debug, ""));
}

test "LevelFilter more_verbose (strict)" {
    // more_verbose(.warn) → info + debug pass (info=2 > warn=1)
    const f: LevelFilter = .{ .more_verbose = .warn };
    try std.testing.expectEqual(FilterResult.reject, f.enabled(.err, ""));
    try std.testing.expectEqual(FilterResult.reject, f.enabled(.warn, ""));
    try std.testing.expectEqual(FilterResult.accept, f.enabled(.info, ""));
    try std.testing.expectEqual(FilterResult.accept, f.enabled(.debug, ""));
}

test "LevelFilter more_verbose_equal" {
    // more_verbose_equal(.warn) → warn + info + debug pass
    const f: LevelFilter = .{ .more_verbose_equal = .warn };
    try std.testing.expectEqual(FilterResult.reject, f.enabled(.err, ""));
    try std.testing.expectEqual(FilterResult.accept, f.enabled(.warn, ""));
    try std.testing.expectEqual(FilterResult.accept, f.enabled(.info, ""));
    try std.testing.expectEqual(FilterResult.accept, f.enabled(.debug, ""));
}

test "LevelFilter getLevel" {
    try std.testing.expect((LevelFilter{ .off = {} }).getLevel() == null);
    try std.testing.expect((LevelFilter{ .all = {} }).getLevel() == null);
    try std.testing.expectEqual(std.log.Level.warn, (LevelFilter{ .equal = .warn }).getLevel().?);
    try std.testing.expectEqual(std.log.Level.info, LevelFilter.init(.info).getLevel().?);
}
