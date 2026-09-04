const std = @import("std");

/// Maximum uncompressed gossip payload, shared with the req/resp domain.
pub const MAX_PAYLOAD_SIZE: usize = 10 * 1024 * 1024;

/// Snappy's worst-case compressed length for a payload of `n` bytes.
pub fn maxCompressedLen(n: usize) usize {
    return 32 + n + n / 6;
}

/// `GOSSIP_MAX_SIZE`: the bound on a whole encoded RPC frame, per the consensus
/// p2p-interface `max_message_size()`.
pub const GOSSIP_MAX_SIZE: usize = @max(maxCompressedLen(MAX_PAYLOAD_SIZE) + 1024, 1024 * 1024);

/// 4-byte message-id domains that isolate valid from invalid snappy payloads.
pub const MESSAGE_DOMAIN_VALID_SNAPPY = [4]u8{ 0x01, 0x00, 0x00, 0x00 };
pub const MESSAGE_DOMAIN_INVALID_SNAPPY = [4]u8{ 0x00, 0x00, 0x00, 0x00 };
pub const message_id_length: usize = 20;

/// Mesh degree parameters (Ethereum overrides of the gossipsub defaults).
pub const mesh_d: u8 = 8;
pub const mesh_d_low: u8 = 6;
pub const mesh_d_high: u8 = 12;
pub const mesh_d_lazy: u8 = 6;
pub const mesh_d_out: u8 = 2;
pub const mesh_d_score: u8 = 4;

/// Timers, in milliseconds unless noted.
pub const heartbeat_interval_ms: u64 = 700;
pub const fanout_ttl_ms: u64 = 60_000;
pub const prune_backoff_ms: u64 = 60_000;
pub const unsubscribe_backoff_ms: u64 = 10_000;
pub const backoff_slack_heartbeats: u64 = 2;
pub const iwant_followup_ms: u64 = 3_000;
pub const opportunistic_graft_ms: u64 = 60_000;
pub const opportunistic_graft_peers: u8 = 2;
/// The seen-cache holds message ids for two epochs; the host supplies the slot
/// duration so the window tracks the active preset.
pub const seen_ttl_epochs: u64 = 2;

/// Message-cache windows: full messages retained for `mcache_len` heartbeats,
/// gossiped about for `mcache_gossip` of them.
pub const mcache_len: usize = 6;
pub const mcache_gossip: usize = 3;

/// Only announce IDONTWANT for messages at least this large, so small topics
/// (attestations) are not burdened; blocks and data columns clear it.
pub const idontwant_size_threshold: usize = 16 * 1024;

/// Per-RPC and per-heartbeat element caps beyond `GOSSIP_MAX_SIZE`.
pub const max_subscriptions_per_rpc: usize = 200;
pub const max_publish_per_rpc: usize = 4_096;
pub const max_control_per_rpc: usize = 4_096;
pub const max_ihave_per_heartbeat: usize = 10;
pub const max_ihave_ids_per_heartbeat: usize = 5_000;
pub const max_iwant_ids_per_rpc: usize = 5_000;
pub const max_idontwant_per_heartbeat: usize = 10;
pub const gossip_retransmission: u8 = 3;

pub fn seenTtlMs(slots_per_epoch: u64, seconds_per_slot: u64) u64 {
    return seconds_per_slot * 1000 * slots_per_epoch * seen_ttl_epochs;
}

comptime {
    std.debug.assert(mesh_d_low <= mesh_d);
    std.debug.assert(mesh_d <= mesh_d_high);
    std.debug.assert(mesh_d_out <= mesh_d_low);
    std.debug.assert(mesh_d_score <= mesh_d);
    std.debug.assert(mcache_gossip <= mcache_len);
    std.debug.assert(GOSSIP_MAX_SIZE >= 1024 * 1024);
    std.debug.assert(message_id_length == 20);
}
