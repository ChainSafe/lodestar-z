const std = @import("std");
const Writer = std.Io.Writer;

pub const MetricType = enum { counter, gauge, histogram };
pub fn family(w: *Writer, comptime name: []const u8, comptime kind: MetricType, comptime help: []const u8) Writer.Error!void {
    try w.writeAll("# HELP " ++ name ++ " " ++ help ++ "\n# TYPE " ++ name ++ " " ++ @tagName(kind) ++ "\n");
}
pub fn scalar(w: *Writer, comptime name: []const u8, comptime kind: MetricType, comptime help: []const u8, value: anytype) Writer.Error!void {
    try family(w, name, kind, help);
    try w.print(name ++ " {d}\n", .{value});
}
pub fn sample(w: *Writer, comptime name: []const u8, comptime label: []const u8, value: []const u8, count: anytype) Writer.Error!void {
    try w.print(name ++ "{{" ++ label ++ "=\"{s}\"}} {d}\n", .{ value, count });
}
pub fn counterFields(w: *Writer, comptime prefix: []const u8, values: anytype) Writer.Error!void {
    inline for (@typeInfo(@TypeOf(values.*)).@"struct".fields) |field| {
        if (comptime std.mem.endsWith(u8, field.name, "_ms_total")) {
            try scalar(w, prefix ++ field.name[0 .. field.name.len - "_ms_total".len] ++ "_seconds_total", .counter, "Cumulative native " ++ field.name ++ " in seconds", @as(f64, @floatFromInt(@field(values, field.name))) / 1000);
        } else {
            const suffix = if (comptime std.mem.endsWith(u8, field.name, "_total")) "" else "_total";
            try scalar(w, prefix ++ field.name ++ suffix, .counter, "Native " ++ field.name, @field(values, field.name));
        }
    }
}

pub fn histogram(w: *Writer, comptime name: []const u8, comptime label: ?[]const u8, label_value: []const u8, value: anytype) Writer.Error!void {
    var cumulative: u64 = 0;
    const H = @TypeOf(value.*);
    for (H.bounds, value.buckets[0..H.bounds.len]) |bound, count| {
        cumulative +|= count;
        try w.writeAll(name ++ "_bucket{");
        if (label) |key| try w.print(key ++ "=\"{s}\",", .{label_value});
        try w.print("le=\"{d}\"}} {d}\n", .{ @as(f64, @floatFromInt(bound)) / 1000, cumulative });
    }
    try w.writeAll(name ++ "_bucket{");
    if (label) |key| try w.print(key ++ "=\"{s}\",", .{label_value});
    try w.print("le=\"+Inf\"}} {d}\n", .{value.count});
    inline for (.{ "sum", "count" }) |suffix| {
        try w.writeAll(name ++ "_" ++ suffix);
        if (label) |key| try w.print("{{" ++ key ++ "=\"{s}\"}}", .{label_value});
        if (comptime std.mem.eql(u8, suffix, "sum")) {
            try w.print(" {d}\n", .{@as(f64, @floatFromInt(value.sum_ms)) / 1000});
        } else try w.print(" {d}\n", .{value.count});
    }
}
