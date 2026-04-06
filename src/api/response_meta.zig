//! Response metadata for Beacon REST API responses.
//!
//! The Beacon API spec requires certain metadata to be emitted as HTTP headers
//! alongside (or instead of) JSON body fields. This module provides:
//! - `ResponseMeta` — the metadata a handler populates
//! - `MetaHeader` — standard header name constants
//! - `Fork` — fork name enum matching the Beacon API spec
//! - `writeHeaders` — serializes metadata to a header list
//!
//! TypeScript equivalent: packages/api/src/utils/metadata.ts
//!
//! Standard headers:
//! - `Eth-Consensus-Version`        — fork name (phase0, altair, ...)
//! - `Eth-Execution-Optimistic`     — "true" / "false"
//! - `Eth-Consensus-Finalized`      — "true" / "false"
//! - `Eth-Consensus-Dependent-Root` — 0x-prefixed hex root
//! - `Eth-Execution-Payload-Source` — "engine" / "builder"
//! - `Eth-Execution-Payload-Value`  — execution payload value in wei
//! - `Eth-Consensus-Block-Value`    — consensus proposer reward in wei
//! - `Access-Control-Expose-Headers` — comma list of exposed custom headers

const std = @import("std");
const api_types = @import("types.zig");

/// Standard Beacon API metadata header names.
pub const MetaHeader = struct {
    pub const version = "Eth-Consensus-Version";
    pub const consensus_block_value = "Eth-Consensus-Block-Value";
    pub const execution_payload_blinded = "Eth-Execution-Payload-Blinded";
    pub const execution_payload_source = "Eth-Execution-Payload-Source";
    pub const execution_payload_value = "Eth-Execution-Payload-Value";
    pub const execution_optimistic = "Eth-Execution-Optimistic";
    pub const finalized = "Eth-Consensus-Finalized";
    pub const dependent_root = "Eth-Consensus-Dependent-Root";
    pub const expose_headers = "Access-Control-Expose-Headers";
};

/// Ethereum consensus fork names, in order.
pub const Fork = enum {
    phase0,
    altair,
    bellatrix,
    capella,
    deneb,
    electra,
    fulu,
    gloas,

    pub fn toString(self: Fork) []const u8 {
        return switch (self) {
            .phase0 => "phase0",
            .altair => "altair",
            .bellatrix => "bellatrix",
            .capella => "capella",
            .deneb => "deneb",
            .electra => "electra",
            .fulu => "fulu",
            .gloas => "gloas",
        };
    }

    pub fn fromString(s: []const u8) ?Fork {
        const fields = @typeInfo(Fork).@"enum".fields;
        inline for (fields) |field| {
            if (std.mem.eql(u8, s, field.name)) {
                return @enumFromInt(field.value);
            }
        }
        return null;
    }
};

/// Metadata attached to a Beacon API response.
///
/// Handlers populate this struct with whatever metadata is applicable.
/// The HTTP server layer calls `writeHeaders()` to emit them as response headers.
pub const ResponseMeta = struct {
    /// Fork version of the response data (blocks, states).
    version: ?Fork = null,
    /// True if the response contains a blinded execution payload.
    execution_payload_blinded: ?bool = null,
    /// Whether the execution payload came from the engine or builder flow.
    execution_payload_source: ?api_types.ExecutionPayloadSource = null,
    /// Execution payload value in wei.
    execution_payload_value: ?u256 = null,
    /// Consensus proposer reward for the block in wei.
    consensus_block_value: ?u256 = null,
    /// True if the data references an unverified execution payload.
    execution_optimistic: ?bool = null,
    /// True if the data references finalized chain history.
    finalized: ?bool = null,
    /// Block root that this response is dependent on (for duties endpoints).
    dependent_root: ?[32]u8 = null,

    /// The set of custom headers that will be emitted (for Access-Control-Expose-Headers).
    ///
    /// Returns a comma-separated list of exposed header names.
    /// The caller provides a buffer for the output string.
    pub fn exposeHeadersList(self: ResponseMeta, buf: []u8) []const u8 {
        var pos: usize = 0;
        var first = true;

        const appendStr = struct {
            fn f(b: []u8, p: *usize, s: []const u8) void {
                const end = @min(p.* + s.len, b.len);
                @memcpy(b[p.*..end], s[0 .. end - p.*]);
                p.* = end;
            }
        }.f;

        if (self.version != null) {
            if (!first) appendStr(buf, &pos, ",");
            appendStr(buf, &pos, MetaHeader.version);
            first = false;
        }
        if (self.execution_payload_blinded != null) {
            if (!first) appendStr(buf, &pos, ",");
            appendStr(buf, &pos, MetaHeader.execution_payload_blinded);
            first = false;
        }
        if (self.execution_payload_source != null) {
            if (!first) appendStr(buf, &pos, ",");
            appendStr(buf, &pos, MetaHeader.execution_payload_source);
            first = false;
        }
        if (self.execution_payload_value != null) {
            if (!first) appendStr(buf, &pos, ",");
            appendStr(buf, &pos, MetaHeader.execution_payload_value);
            first = false;
        }
        if (self.consensus_block_value != null) {
            if (!first) appendStr(buf, &pos, ",");
            appendStr(buf, &pos, MetaHeader.consensus_block_value);
            first = false;
        }
        if (self.execution_optimistic != null) {
            if (!first) appendStr(buf, &pos, ",");
            appendStr(buf, &pos, MetaHeader.execution_optimistic);
            first = false;
        }
        if (self.finalized != null) {
            if (!first) appendStr(buf, &pos, ",");
            appendStr(buf, &pos, MetaHeader.finalized);
            first = false;
        }
        if (self.dependent_root != null) {
            if (!first) appendStr(buf, &pos, ",");
            appendStr(buf, &pos, MetaHeader.dependent_root);
            first = false;
        }

        return buf[0..pos];
    }

    /// Returns true if there are any metadata headers to emit.
    pub fn hasHeaders(self: ResponseMeta) bool {
        return self.version != null or
            self.execution_payload_blinded != null or
            self.execution_payload_source != null or
            self.execution_payload_value != null or
            self.consensus_block_value != null or
            self.execution_optimistic != null or
            self.finalized != null or
            self.dependent_root != null;
    }
};

/// A single HTTP header (name + value as slices).
pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// Result of writing metadata headers.
///
/// Contains up to 9 headers (version, execution_payload_blinded,
/// execution_payload_source, execution_payload_value, consensus_block_value,
/// execution_optimistic, finalized, dependent_root, expose_headers) plus their
/// value strings in fixed buffers.
/// The struct is stack-allocated — no heap allocation needed.
pub const MetaHeaders = struct {
    /// The header entries (name/value pairs).
    headers: [9]Header = undefined,
    /// Number of valid entries in `headers`.
    count: usize = 0,

    // Backing buffers for formatted values.
    version_buf: [16]u8 = undefined,
    execution_payload_value_buf: [80]u8 = undefined,
    consensus_block_value_buf: [80]u8 = undefined,
    dep_root_buf: [66]u8 = undefined, // "0x" + 64 hex chars
    expose_buf: [256]u8 = undefined,

    pub fn slice(self: *const MetaHeaders) []const Header {
        return self.headers[0..self.count];
    }
};

/// Serialize `ResponseMeta` into a `MetaHeaders` struct.
///
/// Takes an out-param pointer so that the slice values inside `MetaHeaders`
/// remain valid — they point into the struct's own backing buffers, which
/// live in the caller's stack frame.
///
/// Usage:
///   var hdrs: MetaHeaders = undefined;
///   buildHeaders(meta, &hdrs);
///   for (hdrs.slice()) |h| { ... }
pub fn buildHeaders(meta: ResponseMeta, result: *MetaHeaders) void {
    result.count = 0;

    if (meta.version) |fork| {
        const v = fork.toString();
        const out = result.version_buf[0..v.len];
        @memcpy(out, v);
        result.headers[result.count] = .{ .name = MetaHeader.version, .value = out };
        result.count += 1;
    }

    if (meta.execution_payload_blinded) |blinded| {
        result.headers[result.count] = .{
            .name = MetaHeader.execution_payload_blinded,
            .value = if (blinded) "true" else "false",
        };
        result.count += 1;
    }

    if (meta.execution_payload_source) |source| {
        result.headers[result.count] = .{
            .name = MetaHeader.execution_payload_source,
            .value = source.headerValue(),
        };
        result.count += 1;
    }

    if (meta.execution_payload_value) |value| {
        const out = std.fmt.bufPrint(result.execution_payload_value_buf[0..], "{d}", .{value}) catch unreachable;
        result.headers[result.count] = .{
            .name = MetaHeader.execution_payload_value,
            .value = out,
        };
        result.count += 1;
    }

    if (meta.consensus_block_value) |value| {
        const out = std.fmt.bufPrint(result.consensus_block_value_buf[0..], "{d}", .{value}) catch unreachable;
        result.headers[result.count] = .{
            .name = MetaHeader.consensus_block_value,
            .value = out,
        };
        result.count += 1;
    }

    if (meta.execution_optimistic) |opt| {
        result.headers[result.count] = .{
            .name = MetaHeader.execution_optimistic,
            .value = if (opt) "true" else "false",
        };
        result.count += 1;
    }

    if (meta.finalized) |fin| {
        result.headers[result.count] = .{
            .name = MetaHeader.finalized,
            .value = if (fin) "true" else "false",
        };
        result.count += 1;
    }

    if (meta.dependent_root) |root| {
        result.dep_root_buf[0] = '0';
        result.dep_root_buf[1] = 'x';
        const hex = std.fmt.bytesToHex(&root, .lower);
        @memcpy(result.dep_root_buf[2..66], &hex);
        result.headers[result.count] = .{ .name = MetaHeader.dependent_root, .value = result.dep_root_buf[0..66] };
        result.count += 1;
    }

    // Build expose-headers list last (so we can include all emitted headers)
    if (result.count > 0) {
        const expose = meta.exposeHeadersList(&result.expose_buf);
        if (expose.len > 0) {
            result.headers[result.count] = .{
                .name = MetaHeader.expose_headers,
                .value = expose,
            };
            result.count += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "Fork.toString roundtrip" {
    const fields = @typeInfo(Fork).@"enum".fields;
    inline for (fields) |field| {
        const fork: Fork = @enumFromInt(field.value);
        try std.testing.expectEqualStrings(field.name, fork.toString());
    }
}

test "Fork.fromString known" {
    try std.testing.expectEqual(Fork.phase0, Fork.fromString("phase0").?);
    try std.testing.expectEqual(Fork.deneb, Fork.fromString("deneb").?);
    try std.testing.expectEqual(Fork.electra, Fork.fromString("electra").?);
}

test "Fork.fromString unknown" {
    try std.testing.expect(Fork.fromString("unknown_fork") == null);
}

test "ResponseMeta empty" {
    const meta = ResponseMeta{};
    try std.testing.expect(!meta.hasHeaders());
}

test "ResponseMeta with version" {
    const meta = ResponseMeta{ .version = .deneb };
    try std.testing.expect(meta.hasHeaders());
}

test "buildHeaders version only" {
    const meta = ResponseMeta{ .version = .capella };
    var hdrs: MetaHeaders = undefined;
    buildHeaders(meta, &hdrs);
    const s = hdrs.slice();

    // Should have version + expose_headers
    try std.testing.expectEqual(@as(usize, 2), s.len);
    try std.testing.expectEqualStrings("Eth-Consensus-Version", s[0].name);
    try std.testing.expectEqualStrings("capella", s[0].value);
    try std.testing.expectEqualStrings("Access-Control-Expose-Headers", s[1].name);
    try std.testing.expect(std.mem.indexOf(u8, s[1].value, "Eth-Consensus-Version") != null);
}

test "buildHeaders execution_optimistic" {
    const meta = ResponseMeta{ .execution_optimistic = true };
    var hdrs: MetaHeaders = undefined;
    buildHeaders(meta, &hdrs);
    const s = hdrs.slice();

    try std.testing.expectEqual(@as(usize, 2), s.len);
    try std.testing.expectEqualStrings("Eth-Execution-Optimistic", s[0].name);
    try std.testing.expectEqualStrings("true", s[0].value);
}

test "buildHeaders execution_payload_blinded" {
    const meta = ResponseMeta{ .execution_payload_blinded = true };
    var hdrs: MetaHeaders = undefined;
    buildHeaders(meta, &hdrs);
    const s = hdrs.slice();

    try std.testing.expectEqual(@as(usize, 2), s.len);
    try std.testing.expectEqualStrings("Eth-Execution-Payload-Blinded", s[0].name);
    try std.testing.expectEqualStrings("true", s[0].value);
}

test "buildHeaders execution_payload_source" {
    const meta = ResponseMeta{ .execution_payload_source = .builder };
    var hdrs: MetaHeaders = undefined;
    buildHeaders(meta, &hdrs);
    const s = hdrs.slice();

    try std.testing.expectEqual(@as(usize, 2), s.len);
    try std.testing.expectEqualStrings("Eth-Execution-Payload-Source", s[0].name);
    try std.testing.expectEqualStrings("builder", s[0].value);
}

test "buildHeaders execution_payload_value" {
    const meta = ResponseMeta{ .execution_payload_value = 123456789 };
    var hdrs: MetaHeaders = undefined;
    buildHeaders(meta, &hdrs);
    const s = hdrs.slice();

    try std.testing.expectEqual(@as(usize, 2), s.len);
    try std.testing.expectEqualStrings("Eth-Execution-Payload-Value", s[0].name);
    try std.testing.expectEqualStrings("123456789", s[0].value);
}

test "buildHeaders consensus_block_value" {
    const meta = ResponseMeta{ .consensus_block_value = 42000000000 };
    var hdrs: MetaHeaders = undefined;
    buildHeaders(meta, &hdrs);
    const s = hdrs.slice();

    try std.testing.expectEqual(@as(usize, 2), s.len);
    try std.testing.expectEqualStrings("Eth-Consensus-Block-Value", s[0].name);
    try std.testing.expectEqualStrings("42000000000", s[0].value);
}

test "buildHeaders finalized false" {
    const meta = ResponseMeta{ .finalized = false };
    var hdrs: MetaHeaders = undefined;
    buildHeaders(meta, &hdrs);
    const s = hdrs.slice();

    try std.testing.expectEqualStrings("Eth-Consensus-Finalized", s[0].name);
    try std.testing.expectEqualStrings("false", s[0].value);
}

test "buildHeaders full metadata" {
    const meta = ResponseMeta{
        .version = .deneb,
        .execution_optimistic = false,
        .finalized = true,
    };
    var hdrs: MetaHeaders = undefined;
    buildHeaders(meta, &hdrs);
    const s = hdrs.slice();

    // version + exec_opt + finalized + expose = 4
    try std.testing.expectEqual(@as(usize, 4), s.len);
}

test "buildHeaders dependent_root" {
    const root = [_]u8{0xab} ** 32;
    const meta = ResponseMeta{ .dependent_root = root };
    var hdrs: MetaHeaders = undefined;
    buildHeaders(meta, &hdrs);
    const s = hdrs.slice();

    try std.testing.expectEqualStrings("Eth-Consensus-Dependent-Root", s[0].name);
    try std.testing.expect(std.mem.startsWith(u8, s[0].value, "0x"));
    try std.testing.expectEqual(@as(usize, 66), s[0].value.len);
}

test "buildHeaders empty = no headers" {
    const meta = ResponseMeta{};
    var hdrs: MetaHeaders = undefined;
    buildHeaders(meta, &hdrs);
    try std.testing.expectEqual(@as(usize, 0), hdrs.slice().len);
}
