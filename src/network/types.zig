const address = @import("wire/address.zig");

pub const Address = address.Address;

pub const Direction = enum { inbound, outbound };
pub const ShutdownDirection = enum { read, write };

pub const Now = struct {
    mono_ms: u64,
    unix_s: i64,
};

pub const CloseReason = union(enum) {
    host,
    idle_timeout,
    handshake_timeout,
    peer_id_mismatch,
    tls_failed,
    peer_closed: struct { app: bool, code: u64 },
    transport_error: u64,
};

pub const PendingClose = struct { reason: CloseReason, code: u64 };

pub const Read = struct {
    len: usize,
    fin: bool,
    reset_code: ?u64 = null,
};

pub const app_error_normal: u64 = 0;
pub const app_error_peer_id_mismatch: u64 = 1;
pub const app_error_handshake_timeout: u64 = 2;
pub const app_error_stream_table_full: u64 = 3;

pub const crypto_error_first: u64 = 0x100;
pub const crypto_error_last: u64 = 0x1ff;

pub fn reasonFromLocalError(is_app: bool, code: u64) CloseReason {
    if (!is_app and code >= crypto_error_first and code <= crypto_error_last) return .tls_failed;
    return .{ .transport_error = code };
}
