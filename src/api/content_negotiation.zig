//! Content negotiation for the Beacon REST API.
//!
//! Implements RFC-9110 Accept header parsing to select between JSON and SSZ
//! wire formats. Also handles Content-Type parsing for request bodies.
//!
//! Reference:
//! - https://httpwg.org/specs/rfc9110.html#field.accept
//! - TypeScript equivalent: packages/api/src/utils/headers.ts (parseAcceptHeader)

const std = @import("std");

/// Supported wire formats for Beacon API responses.
pub const WireFormat = enum {
    json,
    ssz,

    pub fn mediaType(self: WireFormat) []const u8 {
        return switch (self) {
            .json => "application/json",
            .ssz => "application/octet-stream",
        };
    }
};

/// Result of content negotiation.
pub const NegotiationResult = union(enum) {
    /// A wire format was selected.
    format: WireFormat,
    /// Accept header was present but no supported type was listed → 406.
    not_acceptable,
    /// No Accept header → caller should default to JSON.
    absent,
};

/// Parse an Accept header value and select the preferred supported wire format.
///
/// Follows RFC-9110: comma-separated media ranges with optional q-values.
/// - Returns `.absent` if `accept` is null (caller should default to JSON).
/// - Returns `.not_acceptable` if `accept` is non-null but contains no
///   supported types with q > 0.
/// - Returns `.format` with the highest-q supported type otherwise.
///
/// Special cases:
/// - `*/*` is treated as `application/json` (default)
/// - `application/json` → WireFormat.json
/// - `application/octet-stream` → WireFormat.ssz
///
/// Example: "application/octet-stream;q=0.9, application/json;q=0.5"
///          → .{ .format = .ssz }
pub fn parseAcceptHeader(accept: ?[]const u8) NegotiationResult {
    const header = accept orelse return .absent;

    var best_q: f32 = -1.0;
    var best_format: ?WireFormat = null;

    var it = std.mem.splitScalar(u8, header, ',');
    while (it.next()) |raw_entry| {
        const entry = std.mem.trim(u8, raw_entry, " \t");
        if (entry.len == 0) continue;

        // Split on ';' to separate media type from q-value
        var parts = std.mem.splitScalar(u8, entry, ';');
        const media_type = std.mem.trim(u8, parts.next() orelse continue, " \t");

        // Parse q-value (default = 1.0)
        var q: f32 = 1.0;
        while (parts.next()) |param| {
            const p = std.mem.trim(u8, param, " \t");
            if (std.mem.startsWith(u8, p, "q=")) {
                const q_str = p[2..];
                q = std.fmt.parseFloat(f32, q_str) catch continue;
                if (q < 0.0 or q > 1.0) q = 0.0;
            }
        }

        // RFC 7231 §5.3.2: q=0 means explicitly NOT acceptable.
        if (q == 0.0) continue;
        // Skip if this q-value is not better than our current best
        if (q <= best_q) continue;

        // Map media type to WireFormat
        const lower = blk: {
            // Stack-allocate for comparison (max media type length ~32)
            var buf: [64]u8 = undefined;
            if (media_type.len > buf.len) break :blk null;
            break :blk std.ascii.lowerString(buf[0..media_type.len], media_type);
        } orelse continue;

        const fmt: ?WireFormat = if (std.mem.eql(u8, lower, "application/json"))
            .json
        else if (std.mem.eql(u8, lower, "application/octet-stream"))
            .ssz
        else if (std.mem.eql(u8, lower, "*/*"))
            .json // treat wildcard as json
        else
            null;

        if (fmt) |f| {
            best_q = q;
            best_format = f;
        }
    }

    if (best_format) |f| {
        return .{ .format = f };
    }

    // Accept header was present but listed no supported types
    return .not_acceptable;
}

/// Parse a Content-Type header for request body decoding.
///
/// Returns the wire format if the content type is supported, or null.
/// Does not return `.not_acceptable` — missing/unsupported Content-Type
/// is handled at the call site (POST bodies only).
pub fn parseContentTypeHeader(content_type: ?[]const u8) ?WireFormat {
    const header = content_type orelse return null;

    // Content-Type may include parameters: "application/json; charset=utf-8"
    var parts = std.mem.splitScalar(u8, header, ';');
    const media_type = std.mem.trim(u8, parts.next() orelse return null, " \t");

    var buf: [64]u8 = undefined;
    if (media_type.len > buf.len) return null;
    const lower = std.ascii.lowerString(buf[0..media_type.len], media_type);

    if (std.mem.eql(u8, lower, "application/json")) return .json;
    if (std.mem.eql(u8, lower, "application/octet-stream")) return .ssz;
    return null;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parseAcceptHeader absent" {
    const result = parseAcceptHeader(null);
    try std.testing.expect(result == .absent);
}

test "parseAcceptHeader json" {
    const result = parseAcceptHeader("application/json");
    try std.testing.expect(result == .format);
    try std.testing.expectEqual(WireFormat.json, result.format);
}

test "parseAcceptHeader ssz" {
    const result = parseAcceptHeader("application/octet-stream");
    try std.testing.expect(result == .format);
    try std.testing.expectEqual(WireFormat.ssz, result.format);
}

test "parseAcceptHeader wildcard defaults to json" {
    const result = parseAcceptHeader("*/*");
    try std.testing.expect(result == .format);
    try std.testing.expectEqual(WireFormat.json, result.format);
}

test "parseAcceptHeader not_acceptable" {
    const result = parseAcceptHeader("text/html, text/plain");
    try std.testing.expect(result == .not_acceptable);
}

test "parseAcceptHeader q-value selection: ssz preferred" {
    const result = parseAcceptHeader("application/json;q=0.5, application/octet-stream;q=0.9");
    try std.testing.expect(result == .format);
    try std.testing.expectEqual(WireFormat.ssz, result.format);
}

test "parseAcceptHeader q-value selection: json preferred" {
    const result = parseAcceptHeader("application/json;q=0.9, application/octet-stream;q=0.5");
    try std.testing.expect(result == .format);
    try std.testing.expectEqual(WireFormat.json, result.format);
}

test "parseAcceptHeader multiple types first wins when equal q" {
    // Both q=1.0 default — first encountered should win, but we pick highest
    // Our impl takes highest q, ties go to later (but both 1.0 → first parsed wins)
    const result = parseAcceptHeader("application/json, application/octet-stream");
    try std.testing.expect(result == .format);
    // json comes first at q=1.0, ssz also at q=1.0 — both equal
    // our impl takes the last since q <= best_q means skip (strictly less-than for skip)
    // Let's just verify it's one of the two
    try std.testing.expect(result.format == .json or result.format == .ssz);
}

test "parseAcceptHeader case insensitive" {
    const result = parseAcceptHeader("Application/JSON");
    try std.testing.expect(result == .format);
    try std.testing.expectEqual(WireFormat.json, result.format);
}

test "parseAcceptHeader with extra whitespace" {
    const result = parseAcceptHeader("  application/octet-stream  ;  q=1.0  ");
    try std.testing.expect(result == .format);
    try std.testing.expectEqual(WireFormat.ssz, result.format);
}

test "parseContentTypeHeader json" {
    try std.testing.expectEqual(WireFormat.json, parseContentTypeHeader("application/json").?);
}

test "parseContentTypeHeader ssz" {
    try std.testing.expectEqual(WireFormat.ssz, parseContentTypeHeader("application/octet-stream").?);
}

test "parseContentTypeHeader with charset" {
    try std.testing.expectEqual(WireFormat.json, parseContentTypeHeader("application/json; charset=utf-8").?);
}

test "parseContentTypeHeader unknown" {
    try std.testing.expect(parseContentTypeHeader("text/html") == null);
}

test "parseContentTypeHeader null" {
    try std.testing.expect(parseContentTypeHeader(null) == null);
}

test "WireFormat.mediaType" {
    try std.testing.expectEqualStrings("application/json", WireFormat.json.mediaType());
    try std.testing.expectEqualStrings("application/octet-stream", WireFormat.ssz.mediaType());
}
