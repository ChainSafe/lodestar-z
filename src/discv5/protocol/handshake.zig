//! Pure wire-format and validation helpers for the discv5 handshake.
//!
//! These functions are stateless: they take explicit inputs and return values
//! or errors, with no reference to the protocol instance. That keeps the
//! `handleWhoareyou`/`handleHandshake` handlers as thin orchestration and makes
//! the fiddly byte-layout and ENR-validation logic unit-testable on its own.

const std = @import("std");
const enr_mod = @import("../enr.zig");

const Io = std.Io;
const Address = Io.net.IpAddress;
const NodeId = enr_mod.NodeId;

/// id-signature size in handshake authdata (fixed for identity scheme "v4").
pub const sig_size: u8 = 64;
/// Ephemeral compressed-pubkey size in handshake authdata.
pub const eph_key_size: u8 = 33;
/// authdata-head = src-id (32) || sig-size (1) || eph-key-size (1).
const authdata_head_size: usize = 34;

pub const Error = error{
    ShortAuthdata,
    TruncatedAuthdata,
    BadAuthdataSizes,
    InvalidEnr,
    EnrMissingPubkey,
    EnrNodeIdMismatch,
    EnrEndpointMismatch,
    BufferTooSmall,
};

/// Parsed view over a received HANDSHAKE packet's authdata. `id_sig` and
/// `eph_pubkey` borrow from the caller's `authdata` buffer.
pub const Authdata = struct {
    src_id: NodeId,
    id_sig: *const [sig_size]u8,
    eph_pubkey: *const [eph_key_size]u8,
    maybe_enr: ?[]const u8,
};

/// Validate the authdata structure and slice out its fields:
///   authdata = src-id (32) || sig-size (1) || eph-key-size (1)
///              || id-signature (64) || eph-pubkey (33) || [record]
pub fn parseAuthdata(authdata: []const u8) Error!Authdata {
    if (authdata.len < authdata_head_size) return Error.ShortAuthdata;

    const declared_sig = authdata[32];
    const declared_eph = authdata[33];
    if (authdata.len < authdata_head_size + @as(usize, declared_sig) + @as(usize, declared_eph))
        return Error.TruncatedAuthdata;
    if (declared_sig != sig_size or declared_eph != eph_key_size) return Error.BadAuthdataSizes;

    const sig_end = authdata_head_size + @as(usize, sig_size);
    const eph_end = sig_end + @as(usize, eph_key_size);
    return .{
        .src_id = authdata[0..32].*,
        .id_sig = authdata[authdata_head_size..][0..sig_size],
        .eph_pubkey = authdata[sig_end..][0..eph_key_size],
        .maybe_enr = if (authdata.len > eph_end) authdata[eph_end..] else null,
    };
}

/// Assemble HANDSHAKE authdata into `out`, returning the populated prefix.
/// `enr_bytes` may be empty to omit the optional record.
pub fn buildAuthdata(
    out: []u8,
    local_node_id: NodeId,
    id_sig: *const [sig_size]u8,
    eph_pubkey: *const [eph_key_size]u8,
    enr_bytes: []const u8,
) Error![]u8 {
    const sig_end = authdata_head_size + @as(usize, sig_size);
    const eph_end = sig_end + @as(usize, eph_key_size);
    const total = eph_end + enr_bytes.len;
    if (total > out.len) return Error.BufferTooSmall;

    out[0..32].* = local_node_id;
    out[32] = sig_size;
    out[33] = eph_key_size;
    @memcpy(out[authdata_head_size..sig_end], id_sig);
    @memcpy(out[sig_end..eph_end], eph_pubkey);
    if (enr_bytes.len > 0) @memcpy(out[eph_end..total], enr_bytes);
    return out[0..total];
}

/// Decode `enr_bytes`, confirm it carries a secp256k1 pubkey whose derived
/// node-id equals `src_id`, and return that compressed pubkey.
pub fn pubkeyFromEnr(enr_bytes: []const u8, src_id: NodeId) Error![eph_key_size]u8 {
    const parsed = enr_mod.decode(enr_bytes) catch return Error.InvalidEnr;
    const pk = parsed.pubkey orelse return Error.EnrMissingPubkey;
    if (!std.mem.eql(u8, &enr_mod.nodeIdFromCompressedPubkey(&pk), &src_id))
        return Error.EnrNodeIdMismatch;
    return pk;
}

/// Decode `enr_bytes` and confirm its advertised endpoint matches `observed`,
/// unless `allow_unverified` is set (an ENR with no endpoint always passes).
pub fn verifyEnrEndpoint(enr_bytes: []const u8, src_id: NodeId, observed: Address, allow_unverified: bool) Error!void {
    const parsed = enr_mod.decode(enr_bytes) catch return Error.InvalidEnr;
    if (!endpointMatches(&parsed, &src_id, observed) and !allow_unverified)
        return Error.EnrEndpointMismatch;
}

/// True when `parsed`'s node-id equals `expected_node_id` and either it
/// advertises no endpoint or an advertised endpoint matches `observed_addr`.
fn endpointMatches(parsed: *const enr_mod.Enr, expected_node_id: *const NodeId, observed_addr: Address) bool {
    const node_id = parsed.nodeId() orelse return false;
    if (!std.mem.eql(u8, &node_id, expected_node_id)) return false;

    var has_endpoint = false;
    if (parsed.ip) |ip| {
        if (parsed.udp) |port| {
            has_endpoint = true;
            switch (observed_addr) {
                .ip4 => |ip4| {
                    if (std.mem.eql(u8, &ip, &ip4.bytes) and port == ip4.port) return true;
                },
                .ip6 => {},
            }
        }
    }
    if (parsed.ip6) |ip6| {
        if (parsed.udp6) |port| {
            has_endpoint = true;
            switch (observed_addr) {
                .ip4 => {},
                .ip6 => |addr_ip6| {
                    if (std.mem.eql(u8, &ip6, &addr_ip6.bytes) and port == addr_ip6.port) return true;
                },
            }
        }
    }

    return !has_endpoint;
}

test "parseAuthdata round-trips a built authdata header" {
    const node_id = [_]u8{0xAB} ** 32;
    var sig = [_]u8{0} ** sig_size;
    sig[0] = 0x11;
    var eph = [_]u8{0} ** eph_key_size;
    eph[0] = 0x22;

    var buf: [256]u8 = undefined;
    const built = try buildAuthdata(&buf, node_id, &sig, &eph, &[_]u8{});
    const parsed = try parseAuthdata(built);

    try std.testing.expectEqualSlices(u8, &node_id, &parsed.src_id);
    try std.testing.expectEqualSlices(u8, &sig, parsed.id_sig);
    try std.testing.expectEqualSlices(u8, &eph, parsed.eph_pubkey);
    try std.testing.expect(parsed.maybe_enr == null);
}

test "parseAuthdata carries the optional trailing ENR" {
    const node_id = [_]u8{0x01} ** 32;
    const sig = [_]u8{0} ** sig_size;
    const eph = [_]u8{0} ** eph_key_size;
    const enr = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };

    var buf: [256]u8 = undefined;
    const built = try buildAuthdata(&buf, node_id, &sig, &eph, &enr);
    const parsed = try parseAuthdata(built);
    try std.testing.expectEqualSlices(u8, &enr, parsed.maybe_enr.?);
}

test "parseAuthdata rejects short and truncated authdata" {
    try std.testing.expectError(Error.ShortAuthdata, parseAuthdata(&[_]u8{ 0x00, 0x01 }));

    var head = [_]u8{0} ** authdata_head_size;
    head[32] = sig_size;
    head[33] = eph_key_size;
    try std.testing.expectError(Error.TruncatedAuthdata, parseAuthdata(&head));
}

test "parseAuthdata rejects non-v4 sizes" {
    // Long enough to pass the truncation check (which runs first) so the
    // wrong-sizes check is what trips.
    var buf = [_]u8{0} ** (authdata_head_size + 65 + eph_key_size);
    buf[32] = 65; // wrong sig size
    buf[33] = eph_key_size;
    try std.testing.expectError(Error.BadAuthdataSizes, parseAuthdata(&buf));
}
