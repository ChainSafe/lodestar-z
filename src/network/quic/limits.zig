const std = @import("std");
const constants = @import("../constants.zig");

pub const connections_max_default: u16 = 128;
pub const connections_max_ceiling: u16 = 1_024;
pub const handshaking_max: u16 = 32;
pub const handshaking_per_source_max: u16 = 4;
pub const dialing_max: u16 = 16;
pub const peer_streams_bidi: u64 = 64;
pub const streams_per_connection: u16 = 128;
pub const idle_timeout_ms: u64 = 10_000;
pub const keep_alive_ms: u64 = 5_000;
pub const handshake_timeout_ms: u64 = 5_000;
pub const recv_udp_payload_max: u64 = 1_452;
pub const send_udp_payload_max: u64 = 1_200;
pub const amplification_factor_max: usize = 3;
pub const initial_congestion_window_packets: usize = 10;
pub const ack_delay_exponent: u64 = 3;
pub const ack_delay_max_ms: u64 = 25;
pub const client_initial_min: usize = 1_200;
pub const receive_budget_bytes: u64 = 512 * 1_024 * 1_024;
pub const connection_window_min: u64 = 1 * 1_024 * 1_024;
pub const connection_window_max: u64 = 16 * 1_024 * 1_024;
pub const send_burst_max: u32 = 256;
pub const local_cid_length: usize = 16;
pub const cid_length_max: usize = 20;
pub const path_events_per_call_max: u8 = 8;

comptime {
    std.debug.assert(local_cid_length <= cid_length_max);
    std.debug.assert(client_initial_min <= recv_udp_payload_max);
    std.debug.assert(client_initial_min <= send_udp_payload_max);
    std.debug.assert(send_udp_payload_max <= recv_udp_payload_max);
    std.debug.assert(recv_udp_payload_max <= constants.datagram_size_max);
    std.debug.assert(connection_window_min <= connection_window_max);
    std.debug.assert(handshaking_max <= connections_max_default);
    std.debug.assert(dialing_max <= connections_max_default - handshaking_max);
    std.debug.assert(send_burst_max % constants.send_batch_max == 0);
    std.debug.assert(connections_max_default <= connections_max_ceiling);
    std.debug.assert(streams_per_connection == 2 * peer_streams_bidi);
    std.debug.assert(receive_budget_bytes / connections_max_default >= connection_window_min);
    std.debug.assert(receive_budget_bytes / connections_max_default <= connection_window_max);
}
