const constants = @import("constants.zig");
const topic_mod = @import("topic.zig");
const score_mod = @import("score.zig");
const storage = @import("message_store.zig");

pub const Options = struct {
    message_id_policy: topic_mod.MessageIdPolicy = .{},
    heartbeat_interval_ms: u64 = constants.heartbeat_interval_ms,
    seen_capacity: usize = 65_536,
    mcache_capacity: usize = 8_192,
    mcache_arena_bytes: usize = 64 * 1024 * 1024,
    validation_capacity: usize = 1024,
    validation_timeout_ms: u64 = 30_000,
    validation_tombstone_ms: u64 = 30_000,
    /// Absolute receive-frame residence and local-pressure wait limit.
    pressure_timeout_ms: u64 = 30_000,
    /// Absolute per-frame residence from queue admission through transmission.
    tx_timeout_ms: u64 = 30_000,
    control_bytes: usize = 28 * 1024,
    critical_bytes: usize = 4 * 1024,
    tx_peer_bytes: usize = 16 * 1024 * 1024,
    peers_per_pump: usize = 32,
    topics_per_pump: usize = 4,
    items_per_peer: usize = 32,
    items_per_pump: usize = 128,
    input_per_peer: usize = 128 * 1024,
    input_per_pump: usize = 1024 * 1024,
    output_per_peer: usize = 128 * 1024,
    output_per_pump: usize = 1024 * 1024,
    fields_per_peer: usize = 32_768,
    fields_per_pump: usize = 131_072,
    work_per_pump: usize = 8 * 1024 * 1024,
    calls_per_peer: usize = 64,
    calls_per_pump: usize = 256,
    /// Decompressed bytes surfaced in one pump; the host consumes them before
    /// the next pump. Full means new messages wait, applying backpressure.
    decompressed_arena_bytes: usize = 16 * 1024 * 1024,
    /// Ordinary per-peer compressed-copy/decode/hash byte credits; one legal oversized item may use the shared allowance.
    decompress_per_peer_bytes: usize = 4 * 1024 * 1024,
    /// Byte-progress timeout for partial receive frames and active transmit frames.
    large_frame_timeout_ms: u64 = 10_000,
    body_buffer_bytes: usize = constants.body_buffer_len,
    /// A pool of large body buffers claimed while receiving a frame that does
    /// not fit the per-peer buffer (blocks and data columns).
    large_message_bytes: usize = constants.GOSSIP_MAX_SIZE,
    large_pool_count: usize = 2,
    seen_ttl_ms: u64 = constants.seenTtlMs(32, 12),
    score_params: score_mod.Params = .{},
    opportunistic_graft_interval_ms: u64 = constants.opportunistic_graft_ms,
    /// Seed for the mesh-pruning randomness that keeps an oversubscribed mesh
    /// eclipse-resistant. A host should pass an unpredictable per-node value.
    random_seed: u64 = 0x9e3779b97f4a7c15,
};

pub fn validate(o: *const Options) error{InvalidLimits}!void {
    const compressed = constants.maxCompressedLen(constants.MAX_PAYLOAD_SIZE);
    try range(o.validation_capacity, 1, 8192);
    try range(o.seen_capacity, 1, 1_048_576);
    try range(o.mcache_capacity, 1, 65536);
    try range(o.mcache_arena_bytes, compressed + storage.page_bytes, 1024 * 1024 * 1024);
    try range(o.decompressed_arena_bytes, constants.MAX_PAYLOAD_SIZE + topic_mod.topic_max_len, 1024 * 1024 * 1024);
    try range(o.large_message_bytes, constants.GOSSIP_MAX_SIZE, 2 * constants.GOSSIP_MAX_SIZE);
    try range(o.large_pool_count, 1, 16);
    try range(o.body_buffer_bytes, 1, constants.GOSSIP_MAX_SIZE);
    try range(o.control_bytes, 1, 65536);
    try range(o.critical_bytes, 32 + topic_mod.topic_max_len, 65536);
    try range(o.tx_peer_bytes, compressed, 1024 * 1024 * 1024);
    try range(o.topics_per_pump, 1, constants.topics_cap);
    try range(o.peers_per_pump, 1, constants.peers_cap);
    try range(o.items_per_peer, 1, 4096);
    try range(o.items_per_pump, 1, 16384);
    try range(o.fields_per_peer, 16_385, 1_048_576);
    try range(o.fields_per_pump, 16_385, 4_194_304);
    try range(o.calls_per_peer, 1, 4096);
    try range(o.calls_per_pump, 1, 65536);
    const byte_credits = [_]usize{ o.input_per_peer, o.input_per_pump, o.output_per_peer, o.output_per_pump, o.work_per_pump, o.decompress_per_peer_bytes };
    for (byte_credits) |bytes| try range(bytes, 1, 128 * 1024 * 1024);
    const timers = [_]u64{ o.heartbeat_interval_ms, o.validation_timeout_ms, o.validation_tombstone_ms, o.pressure_timeout_ms, o.tx_timeout_ms, o.large_frame_timeout_ms, o.seen_ttl_ms, o.opportunistic_graft_interval_ms };
    for (timers) |timer| if (timer == 0 or timer > 86_400_000) return error.InvalidLimits;
}

fn range(value: usize, min: usize, max: usize) error{InvalidLimits}!void {
    if (value < min or value > max) return error.InvalidLimits;
}
