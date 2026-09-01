const std = @import("std");
const crypto = @import("crypto.zig");
const types = @import("../types.zig");
const constants = @import("../wire/constants.zig");
const rlp = @import("../wire/rlp.zig");

const Keccak256 = std.crypto.hash.sha3.Keccak256;
const field_pairs_max: usize = constants.enr_size_max / 2;

pub const Error = rlp.Error || crypto.Error || error{
    InvalidRecord,
    TooManyFields,
    UnsupportedScheme,
};

pub const Record = struct {
    bytes: [constants.enr_size_max]u8,
    length: u16,
    sequence: u64,
    public_key: [33]u8,
    node_id: types.NodeId,
    ip4: ?[4]u8,
    ip6: ?[16]u8,
    udp: ?u16,
    udp6: ?u16,

    pub fn create(
        key_pair: *const crypto.KeyPair,
        sequence: u64,
        endpoint_value: types.Address,
    ) Error!Record {
        if (!validEndpoint(endpoint_value)) return Error.InvalidRecord;
        const public_key = crypto.compressedPublicKey(key_pair);

        var content_buffer: [constants.enr_size_max]u8 = undefined;
        var content_writer = rlp.Writer.init(&content_buffer);
        const content = try content_writer.beginList();
        try writeFields(&content_writer, sequence, endpoint_value, &public_key);
        content_writer.finishList(content);
        var digest: [32]u8 = undefined;
        Keccak256.hash(content_writer.bytes(), &digest, .{});
        const signature = try crypto.sign(&digest, key_pair);

        var record_buffer: [constants.enr_size_max]u8 = undefined;
        var record_writer = rlp.Writer.init(&record_buffer);
        const record = try record_writer.beginList();
        try record_writer.writeBytes(&signature);
        try writeFields(&record_writer, sequence, endpoint_value, &public_key);
        record_writer.finishList(record);
        return Record.init(record_writer.bytes());
    }

    pub fn init(data: []const u8) Error!Record {
        if (data.len > constants.enr_size_max) return Error.InvalidRecord;
        const parsed = try parse(data);
        var record = Record{
            .bytes = [_]u8{0} ** constants.enr_size_max,
            .length = @intCast(data.len),
            .sequence = parsed.sequence,
            .public_key = parsed.public_key,
            .node_id = try nodeIdFromPublicKey(&parsed.public_key),
            .ip4 = parsed.ip4,
            .ip6 = parsed.ip6,
            .udp = parsed.udp,
            .udp6 = parsed.udp6,
        };
        @memcpy(record.bytes[0..data.len], data);
        return record;
    }

    pub fn initText(text: []const u8) Error!Record {
        if (!std.mem.startsWith(u8, text, "enr:")) return Error.InvalidRecord;
        const encoded = text[4..];
        const decoded_size = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(encoded) catch
            return Error.InvalidRecord;
        if (decoded_size > constants.enr_size_max) return Error.InvalidRecord;
        var decoded: [constants.enr_size_max]u8 = undefined;
        std.base64.url_safe_no_pad.Decoder.decode(decoded[0..decoded_size], encoded) catch
            return Error.InvalidRecord;
        return Record.init(decoded[0..decoded_size]);
    }

    pub fn slice(self: *const Record) []const u8 {
        std.debug.assert(self.length <= self.bytes.len);
        return self.bytes[0..self.length];
    }

    pub fn endpoint(self: *const Record) ?types.Address {
        if (self.ip4) |ip| if (self.udp) |port| {
            return .{ .ip4 = .{ .octets = ip, .port = port } };
        };
        if (self.ip6) |ip| if (self.udp6 orelse self.udp) |port| {
            return .{ .ip6 = .{ .octets = ip, .port = port } };
        };
        return null;
    }
};

fn writeFields(
    writer: *rlp.Writer,
    sequence: u64,
    endpoint_value: types.Address,
    public_key: *const [33]u8,
) rlp.Error!void {
    try writer.writeUint(sequence);
    try writer.writeBytes("id");
    try writer.writeBytes("v4");
    switch (endpoint_value) {
        .ip4 => |address| {
            try writer.writeBytes("ip");
            try writer.writeBytes(&address.octets);
        },
        .ip6 => |address| {
            try writer.writeBytes("ip6");
            try writer.writeBytes(&address.octets);
        },
    }
    try writer.writeBytes("secp256k1");
    try writer.writeBytes(public_key);
    switch (endpoint_value) {
        .ip4 => |address| {
            try writer.writeBytes("udp");
            try writer.writeUint(address.port);
        },
        .ip6 => |address| {
            try writer.writeBytes("udp6");
            try writer.writeUint(address.port);
        },
    }
}

fn validEndpoint(endpoint_value: types.Address) bool {
    return switch (endpoint_value) {
        .ip4 => |address| address.port != 0 and !allZero(&address.octets),
        .ip6 => |address| address.port != 0 and !allZero(&address.octets),
    };
}

fn allZero(bytes: []const u8) bool {
    for (bytes) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

const Parsed = struct {
    sequence: u64,
    public_key: [33]u8,
    ip4: ?[4]u8 = null,
    ip6: ?[16]u8 = null,
    udp: ?u16 = null,
    udp6: ?u16 = null,
};

fn parse(data: []const u8) Error!Parsed {
    var outer = rlp.Reader.init(data);
    var list = outer.readList() catch return Error.InvalidRecord;
    if (!outer.atEnd()) return Error.InvalidRecord;
    const signature_bytes = list.readBytes() catch return Error.InvalidRecord;
    if (signature_bytes.len != 64) return Error.InvalidRecord;
    const signed_payload = list.data[list.position..];
    const sequence = list.readUint() catch return Error.InvalidRecord;
    var parsed = Parsed{ .sequence = sequence, .public_key = undefined };
    var saw_public_key = false;
    var saw_v4 = false;
    var previous_key: ?[]const u8 = null;

    var fields: usize = 0;
    while (!list.atEnd() and fields < field_pairs_max) : (fields += 1) {
        const key = list.readBytes() catch return Error.InvalidRecord;
        const value = list.readBytes() catch return Error.InvalidRecord;
        if (previous_key) |previous| {
            if (std.mem.order(u8, previous, key) != .lt) return Error.InvalidRecord;
        }
        previous_key = key;
        try parseField(&parsed, key, value, &saw_public_key, &saw_v4);
    }
    if (!list.atEnd()) return Error.TooManyFields;
    if (!saw_v4) return Error.UnsupportedScheme;
    if (!saw_public_key) return Error.InvalidRecord;

    var digest: [32]u8 = undefined;
    hashSignedPayload(signed_payload, &digest);
    const signature = signature_bytes[0..64].*;
    try crypto.verify(&digest, &signature, &parsed.public_key);
    return parsed;
}

fn parseField(
    parsed: *Parsed,
    key: []const u8,
    value: []const u8,
    saw_public_key: *bool,
    saw_v4: *bool,
) Error!void {
    if (std.mem.eql(u8, key, "id")) {
        if (!std.mem.eql(u8, value, "v4")) return Error.UnsupportedScheme;
        saw_v4.* = true;
    } else if (std.mem.eql(u8, key, "secp256k1")) {
        if (value.len != 33) return Error.InvalidRecord;
        parsed.public_key = value[0..33].*;
        saw_public_key.* = true;
    } else if (std.mem.eql(u8, key, "ip")) {
        if (value.len != 4) return Error.InvalidRecord;
        parsed.ip4 = value[0..4].*;
    } else if (std.mem.eql(u8, key, "ip6")) {
        if (value.len != 16) return Error.InvalidRecord;
        parsed.ip6 = value[0..16].*;
    } else if (std.mem.eql(u8, key, "udp")) {
        parsed.udp = try parsePort(value);
    } else if (std.mem.eql(u8, key, "udp6")) {
        parsed.udp6 = try parsePort(value);
    }
}

fn parsePort(bytes: []const u8) Error!u16 {
    if (bytes.len > 2) return Error.InvalidRecord;
    if (bytes.len > 0 and bytes[0] == 0) return Error.InvalidRecord;
    var value: u16 = 0;
    for (bytes) |byte| value = (value << 8) | byte;
    return value;
}

pub fn nodeIdFromPublicKey(public_key: *const [33]u8) Error!types.NodeId {
    const uncompressed = try crypto.uncompressedPublicKey(public_key);
    var node_id: types.NodeId = undefined;
    Keccak256.hash(uncompressed[1..], &node_id, .{});
    return node_id;
}

fn hashSignedPayload(payload: []const u8, digest: *[32]u8) void {
    std.debug.assert(payload.len <= constants.enr_size_max);
    var prefix: [3]u8 = undefined;
    const prefix_length = listPrefix(&prefix, payload.len);
    var hasher = Keccak256.init(.{});
    hasher.update(prefix[0..prefix_length]);
    hasher.update(payload);
    hasher.final(digest);
}

fn listPrefix(out: *[3]u8, payload_length: usize) usize {
    if (payload_length <= 55) {
        out[0] = 0xc0 + @as(u8, @intCast(payload_length));
        return 1;
    }
    if (payload_length <= std.math.maxInt(u8)) {
        out[0] = 0xf8;
        out[1] = @intCast(payload_length);
        return 2;
    }
    std.debug.assert(payload_length <= constants.enr_size_max);
    out[0] = 0xf9;
    std.mem.writeInt(u16, out[1..3], @intCast(payload_length), .big);
    return 3;
}

comptime {
    std.debug.assert(field_pairs_max == 150);
    std.debug.assert(@sizeOf(Record) <= 448);
}
