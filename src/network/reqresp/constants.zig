const std = @import("std");

pub const MAX_PAYLOAD_SIZE: usize = 10 * 1024 * 1024;
pub const MAX_CONCURRENT_REQUESTS: u8 = 2;

pub const outbound_max_default: u16 = 64;
pub const inbound_max_default: u16 = 64;
pub const slots_ceiling: u16 = 1_024;
pub const inbound_per_peer_max_default: u8 = 8;
pub const progress_timeout_ms_default: u64 = 10_000;

pub const frame_uncompressed_max: usize = 65_536;
pub const varint_length_max: usize = 10;
pub const context_bytes_length: usize = 4;

pub const result_success: u8 = 0;
pub const result_invalid_request: u8 = 1;
pub const result_server_error: u8 = 2;
pub const result_resource_unavailable: u8 = 3;
pub const result_reserved_max: u8 = 127;

pub const app_error_timeout: u64 = 16;
pub const app_error_invalid_response: u64 = 17;
pub const app_error_over_limit: u64 = 18;

pub fn maxEncodedLength(uncompressed: usize) usize {
    std.debug.assert(uncompressed <= MAX_PAYLOAD_SIZE);
    return 32 + uncompressed + uncompressed / 6;
}

comptime {
    std.debug.assert(outbound_max_default <= slots_ceiling);
    std.debug.assert(inbound_max_default <= slots_ceiling);
    std.debug.assert(inbound_per_peer_max_default >= MAX_CONCURRENT_REQUESTS);
    std.debug.assert(result_resource_unavailable < result_reserved_max);
    std.debug.assert(app_error_timeout > 4);
}
