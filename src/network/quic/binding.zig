const std = @import("std");
const constants = @import("../constants.zig");
const types = @import("../types.zig");

pub const c = @import("quiche_zig:quiche");

pub const Error = error{
    Done,
    BufferTooShort,
    UnknownVersion,
    InvalidFrame,
    InvalidPacket,
    InvalidState,
    InvalidStreamState,
    InvalidTransportParam,
    CryptoFail,
    TlsFail,
    FlowControl,
    StreamLimit,
    StreamStopped,
    StreamReset,
    FinalSize,
    CongestionControl,
    IdLimit,
    OutOfIdentifiers,
    KeyUpdate,
    CryptoBufferExceeded,
    InvalidAckRange,
    OptimisticAckDetected,
    InvalidDcidInitialization,
    Unknown,
};

pub fn check(rc: anytype) Error!usize {
    const value: isize = @intCast(rc);
    if (value >= 0) return @intCast(value);
    return switch (value) {
        c.QUICHE_ERR_DONE => error.Done,
        c.QUICHE_ERR_BUFFER_TOO_SHORT => error.BufferTooShort,
        c.QUICHE_ERR_UNKNOWN_VERSION => error.UnknownVersion,
        c.QUICHE_ERR_INVALID_FRAME => error.InvalidFrame,
        c.QUICHE_ERR_INVALID_PACKET => error.InvalidPacket,
        c.QUICHE_ERR_INVALID_STATE => error.InvalidState,
        c.QUICHE_ERR_INVALID_STREAM_STATE => error.InvalidStreamState,
        c.QUICHE_ERR_INVALID_TRANSPORT_PARAM => error.InvalidTransportParam,
        c.QUICHE_ERR_CRYPTO_FAIL => error.CryptoFail,
        c.QUICHE_ERR_TLS_FAIL => error.TlsFail,
        c.QUICHE_ERR_FLOW_CONTROL => error.FlowControl,
        c.QUICHE_ERR_STREAM_LIMIT => error.StreamLimit,
        c.QUICHE_ERR_STREAM_STOPPED => error.StreamStopped,
        c.QUICHE_ERR_STREAM_RESET => error.StreamReset,
        c.QUICHE_ERR_FINAL_SIZE => error.FinalSize,
        c.QUICHE_ERR_CONGESTION_CONTROL => error.CongestionControl,
        c.QUICHE_ERR_ID_LIMIT => error.IdLimit,
        c.QUICHE_ERR_OUT_OF_IDENTIFIERS => error.OutOfIdentifiers,
        c.QUICHE_ERR_KEY_UPDATE => error.KeyUpdate,
        c.QUICHE_ERR_CRYPTO_BUFFER_EXCEEDED => error.CryptoBufferExceeded,
        c.QUICHE_ERR_INVALID_ACK_RANGE => error.InvalidAckRange,
        c.QUICHE_ERR_OPTIMISTIC_ACK_DETECTED => error.OptimisticAckDetected,
        c.QUICHE_ERR_INVALID_DCID_INITIALIZATION => error.InvalidDcidInitialization,
        else => error.Unknown,
    };
}

pub fn versionSupported(version: u32) bool {
    return c.quiche_version_is_supported(version);
}

pub const Config = struct {
    ptr: *c.quiche_config,

    pub fn init(idle_timeout_ms: u64) Error!Config {
        const ptr = c.quiche_config_new(c.QUICHE_PROTOCOL_VERSION) orelse return error.Unknown;
        c.quiche_config_verify_peer(ptr, true);
        c.quiche_config_set_max_idle_timeout(ptr, idle_timeout_ms);
        c.quiche_config_set_max_recv_udp_payload_size(ptr, constants.recv_udp_payload_max);
        c.quiche_config_set_initial_max_data(ptr, constants.connection_window);
        c.quiche_config_set_initial_max_stream_data_bidi_local(ptr, constants.stream_window);
        c.quiche_config_set_initial_max_stream_data_bidi_remote(ptr, constants.stream_window);
        c.quiche_config_set_initial_max_stream_data_uni(ptr, 0);
        c.quiche_config_set_initial_max_streams_bidi(ptr, constants.peer_streams_bidi);
        c.quiche_config_set_initial_max_streams_uni(ptr, 0);
        c.quiche_config_set_max_connection_window(ptr, constants.connection_window);
        c.quiche_config_set_max_stream_window(ptr, constants.stream_window);
        c.quiche_config_set_active_connection_id_limit(ptr, 2);
        c.quiche_config_set_disable_active_migration(ptr, true);
        return .{ .ptr = ptr };
    }

    pub fn deinit(self: *Config) void {
        c.quiche_config_free(self.ptr);
        self.* = undefined;
    }
};

pub const SockAddr = struct {
    storage: Storage,
    len: std.posix.socklen_t,

    const Storage = extern union {
        any: std.posix.sockaddr,
        in: std.posix.sockaddr.in,
        in6: std.posix.sockaddr.in6,
    };

    pub fn fromAddress(address: types.Address) SockAddr {
        return switch (address) {
            .ip4 => |ip| .{
                .storage = .{ .in = .{
                    .port = std.mem.nativeToBig(u16, ip.port),
                    .addr = @bitCast(ip.octets),
                } },
                .len = @sizeOf(std.posix.sockaddr.in),
            },
            .ip6 => |ip| .{
                .storage = .{ .in6 = .{
                    .port = std.mem.nativeToBig(u16, ip.port),
                    .flowinfo = 0,
                    .addr = ip.octets,
                    .scope_id = ip.interface,
                } },
                .len = @sizeOf(std.posix.sockaddr.in6),
            },
        };
    }

    pub fn any(self: *const SockAddr) *const std.posix.sockaddr {
        return &self.storage.any;
    }
};

pub const Cid = struct {
    bytes: [constants.cid_length_max]u8 = undefined,
    len: u8 = 0,

    pub fn fromSlice(bytes: []const u8) Cid {
        std.debug.assert(bytes.len <= constants.cid_length_max);
        var cid = Cid{ .len = @intCast(bytes.len) };
        @memcpy(cid.bytes[0..bytes.len], bytes);
        return cid;
    }

    pub fn slice(self: *const Cid) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn eql(self: *const Cid, other: *const Cid) bool {
        return std.mem.eql(u8, self.slice(), other.slice());
    }
};

pub const PacketType = enum(u8) {
    initial = 1,
    retry = 2,
    handshake = 3,
    zero_rtt = 4,
    short = 5,
    version_negotiation = 6,
    _,
};

pub const HeaderInfo = struct {
    version: u32,
    packet_type: PacketType,
    scid: Cid,
    dcid: Cid,
    token_len: usize,
};

const token_length_max = 256;

pub fn headerInfo(datagram: []const u8) Error!HeaderInfo {
    var version: u32 = 0;
    var packet_type: u8 = 0;
    var scid: [constants.cid_length_max]u8 = undefined;
    var scid_len: usize = scid.len;
    var dcid: [constants.cid_length_max]u8 = undefined;
    var dcid_len: usize = dcid.len;
    var token: [token_length_max]u8 = undefined;
    var token_len: usize = token.len;
    _ = try check(c.quiche_header_info(
        datagram.ptr,
        datagram.len,
        constants.local_cid_length,
        &version,
        &packet_type,
        &scid,
        &scid_len,
        &dcid,
        &dcid_len,
        &token,
        &token_len,
    ));
    return .{
        .version = version,
        .packet_type = @enumFromInt(packet_type),
        .scid = Cid.fromSlice(scid[0..scid_len]),
        .dcid = Cid.fromSlice(dcid[0..dcid_len]),
        .token_len = token_len,
    };
}
