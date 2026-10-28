//! Translates the SSZ classes of an ssz-specs filler module into a Zig namespace. A class outside
//! the accepted subset fails instead of yielding a wrong schema. Unknown names are emitted as-is
//! and fail when the generated sources compile.

const std = @import("std");
const Allocator = std.mem.Allocator;

const max_active_fields = 256;

pub const prelude =
    \\const ssz = @import("ssz");
    \\const filler = @import("filler_types.zig");
    \\
;

const Attribute = enum { element, length, limit, fields, active_fields, options };

const bases: std.StaticStringMap(struct { []const u8, []const Attribute }) = .initComptime(.{
    .{ "ByteVector", .{ "ssz.ByteVectorType", &.{.length} } },
    .{ "ByteList", .{ "ssz.ByteListType", &.{.limit} } },
    .{ "BitVector", .{ "ssz.BitVectorType", &.{.length} } },
    .{ "BitList", .{ "ssz.BitListType", &.{.limit} } },
    .{ "Vector", .{ "filler.Vector", &.{ .element, .length } } },
    .{ "List", .{ "filler.List", &.{ .element, .limit } } },
    .{ "ProgressiveList", .{ "filler.ProgressiveList", &.{.element} } },
    .{ "Container", .{ "filler.Container", &.{.fields} } },
    .{ "ProgressiveContainer", .{ "filler.ProgressiveContainer", &.{ .fields, .active_fields } } },
    .{ "CompatibleUnion", .{ "ssz.CompatibleUnionType", &.{.options} } },
});

const builtins: std.StaticStringMap([]const u8) = .initComptime(.{
    .{ "Boolean", "ssz.BoolType()" },
    .{ "Uint8", "ssz.UintType(8)" },
    .{ "Uint16", "ssz.UintType(16)" },
    .{ "Uint32", "ssz.UintType(32)" },
    .{ "Uint64", "ssz.UintType(64)" },
    .{ "Uint128", "ssz.UintType(128)" },
    .{ "Uint256", "ssz.UintType(256)" },
    .{ "ProgressiveBitList", "ssz.ProgressiveBitListType(.{})" },
});

pub const Diagnostic = struct { line: usize = 0 };

/// `allocator` must be an arena. The output needs `prelude` in scope.
pub fn write(
    allocator: Allocator,
    writer: *std.Io.Writer,
    namespace: []const u8,
    source: []const u8,
    diagnostic: *Diagnostic,
) !void {
    var rest = try tokenize(allocator, source, diagnostic);
    try writer.print("pub const {f} = struct {{\n", .{std.zig.fmtId(namespace)});
    while (nextStatement(&rest)) |statement| {
        if (statement[0].indented) continue;
        diagnostic.line = statement[0].line;
        if (statement[0].is("from")) {
            try writeImport(writer, statement);
        } else if (statement[0].is("class")) {
            try writeClass(allocator, writer, statement, rest);
        }
    }
    try writer.writeAll("};\n");
}

fn writeImport(writer: *std.Io.Writer, tokens: []const Token) !void {
    if (tokens.len < 3 or !tokens[1].is("ssz") or !tokens[2].is("import")) return;
    var names = tokens[3..];
    if (names.len >= 2 and names[0].is("(") and names[names.len - 1].is(")")) {
        names = names[1 .. names.len - 1];
    }
    if (names.len == 0) return error.UnsupportedImport;
    var i: usize = 0;
    while (i < names.len) : (i += 2) {
        if (names[i].kind != .name) return error.UnsupportedImport;
        if (i + 1 < names.len and !names[i + 1].is(",")) return error.UnsupportedImport;
        const zig = builtins.get(names[i].text) orelse continue;
        try writer.print("    pub const {s} = {s};\n", .{ names[i].text, zig });
    }
}

fn writeClass(
    allocator: Allocator,
    writer: *std.Io.Writer,
    header: []const Token,
    following: []const Token,
) !void {
    var cursor: Cursor = .{ .tokens = header[1..] };
    const name = try cursor.take(.name);
    try cursor.expect("(");
    const base_name = try cursor.take(.name);
    const subscript = if (cursor.accept("[")) try cursor.take(.name) else null;
    if (subscript != null) try cursor.expect("]");
    try cursor.expect(")");
    try cursor.expect(":");
    try cursor.end();

    var attributes: std.EnumMap(Attribute, []const u8) = .{};
    var fields: std.ArrayList(u8) = .empty;
    var body = following;
    while (nextStatement(&body)) |statement| {
        if (!statement[0].indented) break;
        try parseBodyStatement(allocator, statement, &attributes, &fields);
    }
    if (fields.items.len > 0) {
        const text = try std.fmt.allocPrint(allocator, "struct {{ {s} }}", .{fields.items});
        attributes.put(.fields, text);
    }

    try writer.print("    pub const {f} = ", .{std.zig.fmtId(name)});
    const function, const arguments = bases.get(base_name) orelse {
        if (subscript != null or attributes.count() != 0) return error.UnsupportedSubclass;
        return writer.print("{f};\n", .{std.zig.fmtId(base_name)});
    };
    if (subscript) |element| {
        const text = try std.fmt.allocPrint(allocator, "{f}", .{std.zig.fmtId(element)});
        const declared = attributes.fetchPut(.element, text) orelse text;
        if (!std.mem.eql(u8, declared, text)) return error.ElementTypeMismatch;
    }
    try writer.print("{s}(", .{function});
    for (arguments, 0..) |argument, i| {
        const text = attributes.get(argument) orelse return error.InvalidClassAttributes;
        try writer.print("{s}{s}", .{ if (i == 0) "" else ", ", text });
    }
    if (attributes.count() != arguments.len) return error.InvalidClassAttributes;
    try writer.writeAll(");\n");
}

fn parseBodyStatement(
    allocator: Allocator,
    tokens: []const Token,
    attributes: *std.EnumMap(Attribute, []const u8),
    fields: *std.ArrayList(u8),
) !void {
    if (tokens.len == 1 and tokens[0].kind == .string) return;
    const name = tokens[0].text;
    if (tokens[0].kind != .name or name[0] == '_') return error.UnsupportedClassBody;

    var cursor: Cursor = .{ .tokens = tokens[1..] };
    if (cursor.accept(":")) {
        if (!cursor.accept("ClassVar")) {
            const type_name = try cursor.take(.name);
            if (cursor.tokens.len != 0) return error.UnsupportedClassBody;
            return fields.print(allocator, "{s}{f}: {f}", .{
                if (fields.items.len == 0) "" else ", ",
                std.zig.fmtId(name),
                std.zig.fmtId(type_name),
            });
        }
        try cursor.expect("[");
        _ = try cursor.take(.name);
        try cursor.expect("]");
    }
    if (!cursor.accept("=")) return error.UnsupportedClassBody;

    if (std.mem.eql(u8, name, "LENGTH")) {
        attributes.put(.length, try evalInt(allocator, &cursor));
    } else if (std.mem.eql(u8, name, "LIMIT")) {
        attributes.put(.limit, try evalInt(allocator, &cursor));
    } else if (std.mem.eql(u8, name, "ELEMENT_TYPE")) {
        const element = std.zig.fmtId(try cursor.take(.name));
        attributes.put(.element, try std.fmt.allocPrint(allocator, "{f}", .{element}));
    } else if (std.mem.eql(u8, name, "ACTIVE_FIELDS")) {
        attributes.put(.active_fields, try evalActiveFields(allocator, &cursor));
    } else if (std.mem.eql(u8, name, "OPTIONS")) {
        attributes.put(.options, try evalOptions(allocator, &cursor));
    } else {
        return error.UnsupportedClassBody;
    }
    try cursor.end();
}

fn evalInt(allocator: Allocator, cursor: *Cursor) ![]const u8 {
    var value = try cursor.int(u64);
    while (cursor.accept("*")) {
        value = std.math.mul(u64, value, try cursor.int(u64)) catch return error.InvalidNumber;
    }
    return std.fmt.allocPrint(allocator, "{d}", .{value});
}

fn evalActiveFields(allocator: Allocator, cursor: *Cursor) ![]const u8 {
    var bits: std.ArrayList(u8) = .empty;
    var count: usize = 0;
    try cursor.expect("(");
    while (!cursor.accept(")")) {
        const splat = cursor.accept("*");
        if (splat) {
            try cursor.expect("(");
            try cursor.expect("[");
        }
        const bit = try cursor.int(u1);
        var repeat: usize = 1;
        if (splat) {
            try cursor.expect("]");
            try cursor.expect("*");
            repeat = try cursor.int(usize);
            try cursor.expect(")");
        }
        if (repeat > max_active_fields - count) return error.ActiveFieldsTooWide;
        for (count..count + repeat) |i| {
            try bits.print(allocator, "{s}{d}", .{ if (i == 0) "" else ", ", bit });
        }
        count += repeat;
        if (!cursor.accept(",")) {
            try cursor.expect(")");
            break;
        }
    }
    return std.fmt.allocPrint(allocator, "&.{{ {s} }}", .{bits.items});
}

fn evalOptions(allocator: Allocator, cursor: *Cursor) ![]const u8 {
    var options: std.ArrayList(u8) = .empty;
    try cursor.expect("{");
    while (!cursor.accept("}")) {
        const selector = try cursor.int(u8);
        try cursor.expect(":");
        try options.print(allocator, "{s}.{{ {d}, {f} }}", .{
            if (options.items.len == 0) "" else ", ",
            selector,
            std.zig.fmtId(try cursor.take(.name)),
        });
        if (!cursor.accept(",")) {
            try cursor.expect("}");
            break;
        }
    }
    return std.fmt.allocPrint(allocator, ".{{ {s} }}", .{options.items});
}

const Cursor = struct {
    tokens: []const Token,

    fn end(cursor: Cursor) !void {
        if (cursor.tokens.len != 0) return error.UnsupportedSyntax;
    }

    fn accept(cursor: *Cursor, text: []const u8) bool {
        if (cursor.tokens.len == 0 or !cursor.tokens[0].is(text)) return false;
        cursor.tokens = cursor.tokens[1..];
        return true;
    }

    fn expect(cursor: *Cursor, text: []const u8) !void {
        if (!cursor.accept(text)) return error.UnsupportedSyntax;
    }

    fn take(cursor: *Cursor, kind: TokenKind) ![]const u8 {
        if (cursor.tokens.len == 0 or cursor.tokens[0].kind != kind) return error.UnsupportedSyntax;
        defer cursor.tokens = cursor.tokens[1..];
        return cursor.tokens[0].text;
    }

    fn int(cursor: *Cursor, comptime T: type) !T {
        return std.fmt.parseInt(T, try cursor.take(.number), 0) catch error.InvalidNumber;
    }
};

const TokenKind = enum { name, number, string, punctuation };

const Token = struct {
    kind: TokenKind,
    text: []const u8,
    line: usize,
    line_start: bool,
    indented: bool,

    fn is(token: Token, expected: []const u8) bool {
        return std.mem.eql(u8, token.text, expected);
    }
};

fn nextStatement(tokens: *[]const Token) ?[]const Token {
    if (tokens.len == 0) return null;
    var end: usize = 1;
    while (end < tokens.len and !tokens.*[end].line_start) end += 1;
    defer tokens.* = tokens.*[end..];
    return tokens.*[0..end];
}

fn tokenize(allocator: Allocator, source: []const u8, diagnostic: *Diagnostic) ![]const Token {
    var tokens: std.ArrayList(Token) = .empty;
    var depth: usize = 0;
    var line: usize = 1;
    var line_start = true;
    var i: usize = 0;
    errdefer diagnostic.line = line;

    while (i < source.len) {
        const start = i;
        const c = source[i];
        i += 1;
        var kind: TokenKind = .punctuation;
        switch (c) {
            ' ', '\t' => continue,
            '\n' => {
                line += 1;
                line_start = depth == 0;
                continue;
            },
            '#' => {
                i = std.mem.findScalarPos(u8, source, i, '\n') orelse source.len;
                continue;
            },
            '"', '\'' => {
                i = try stringEnd(source, start);
                kind = .string;
            },
            '0'...'9', 'A'...'Z', '_', 'a'...'z' => {
                while (i < source.len) : (i += 1) {
                    if (!std.ascii.isAlphanumeric(source[i]) and source[i] != '_') break;
                }
                kind = if (std.ascii.isDigit(c)) .number else .name;
            },
            '(', '[', '{' => depth += 1,
            ')', ']', '}' => depth = std.math.sub(usize, depth, 1) catch
                return error.UnbalancedBrackets,
            else => if (!std.ascii.isPrint(c)) return error.UnsupportedCharacter,
        }
        try tokens.append(allocator, .{
            .kind = kind,
            .text = source[start..i],
            .line = line,
            .line_start = line_start,
            // Only spaces and tabs can sit between a line's newline and its first token.
            .indented = line_start and start > 0 and source[start - 1] != '\n',
        });
        line += std.mem.countScalar(u8, source[start..i], '\n');
        line_start = false;
    }
    if (depth != 0) return error.UnbalancedBrackets;
    return tokens.items;
}

fn stringEnd(source: []const u8, start: usize) !usize {
    const quote = source[start];
    const triple = std.mem.startsWith(u8, source[start..], &.{ quote, quote, quote });
    const delimiter = source[start..][0..if (triple) 3 else 1];
    var i = start + delimiter.len;
    while (i < source.len) : (i += 1) {
        if (source[i] == '\\') {
            i += 1;
        } else if (source[i] == '\n' and !triple) {
            return error.UnterminatedString;
        } else if (std.mem.startsWith(u8, source[i..], delimiter)) {
            return i + delimiter.len;
        }
    }
    return error.UnterminatedString;
}

test {
    _ = @import("filler_schema_test.zig");
}
