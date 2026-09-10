const constants = @import("constants.zig");
const storage = @import("message_store.zig");
const delivery = @import("delivery.zig");
const validation = @import("validation.zig");
const policy = @import("topic_policy.zig");
const Options = @import("options.zig").Options;

pub const Plan = struct {
    retained_bytes: usize,
    page_count: usize,
    message_entries: usize,
    validation_capacity: usize,
    duplicate_attributions_per_validation: usize,
    data_descriptors_per_peer: usize,
    data_descriptors_total: usize,
    data_descriptors_reserved_per_peer: usize,
    legal_atomic_work_bytes: usize,
    page_bytes: usize,
    rounding_per_message_max: usize,
    frame_bytes: usize,
    event_bytes: usize,
    compression_bytes: usize,
    peer_buffer_bytes: usize,
    metadata_bytes: usize,
    total_bytes: usize,
};

/// Derives physical storage from configured concurrency. Per-peer byte limits
/// charge logical obligations; they do not multiply the shared payload budget.
pub const Layout = struct {
    sessions: u16,
    retained: u16,
    history: usize,
    seen: usize,
    validations: usize,
    payload_entries: usize,
    payload_bytes: usize,
    deliveries: usize,
    receive_frames: usize,
    receive_frame_bytes: usize,
    session_buffer_bytes: usize,
    output_bytes: usize,
    namespace_bytes: usize,

    pub fn init(options: *const Options) Layout {
        var namespace_bytes: usize = 0;
        if (options.topic_policy) |boundaries| {
            var topics: usize = 0;
            for (boundaries) |boundary| for (boundary.rules) |rule| {
                topics += rule.count;
            };
            namespace_bytes = boundaries.len * (@sizeOf(policy.Boundary) + @sizeOf([policy.kind_count]u16)) +
                options.connected_capacity * ((topics + 63) / 64) * @sizeOf(u64);
        }
        return .{
            .sessions = options.connected_capacity,
            .retained = options.retained_capacity,
            .history = options.mcache_capacity,
            .seen = options.seen_capacity,
            .validations = options.validation_capacity,
            .payload_entries = options.mcache_capacity + options.validation_capacity,
            .payload_bytes = options.mcache_arena_bytes / storage.page_bytes * storage.page_bytes,
            .deliveries = delivery.Pool.capacity(options.connected_capacity, options.validation_capacity),
            .receive_frames = options.large_pool_count,
            .receive_frame_bytes = options.large_message_bytes,
            .session_buffer_bytes = @import("peer_io.zig").PeerIo.bufferBytes(options),
            .output_bytes = options.decompressed_arena_bytes,
            .namespace_bytes = namespace_bytes,
        };
    }

    pub fn plan(self: *const Layout) Plan {
        const peers = @import("peer_book.zig");
        const scores = @import("score.zig");
        const metadata = @sizeOf(@import("gossipsub.zig").Gossipsub) +
            @sizeOf(@import("sessions.zig").Sessions) + @sizeOf(@import("overlay.zig").Overlay) +
            @as(usize, self.sessions) * @sizeOf(@import("peer_session.zig").Session) +
            @as(usize, self.retained) * (@sizeOf(peers.Row) + constants.topics_cap * (@sizeOf(peers.Backoff) + @sizeOf(scores.TopicCounters)) + 2 * @sizeOf(f64)) +
            @import("messages.zig").Messages.metadataBytes(self) + delivery.Pool.memoryBytes(self.deliveries) +
            @import("recovery.zig").Recovery.memoryBytes() + @import("receive_pool.zig").ReceivePool.metadataBytes(self.receive_frames) + self.namespace_bytes;
        const frames = self.receive_frames * self.receive_frame_bytes;
        const buffers = self.sessions * self.session_buffer_bytes;
        return .{
            .retained_bytes = self.payload_bytes,
            .page_count = self.payload_bytes / storage.page_bytes,
            .message_entries = self.payload_entries,
            .validation_capacity = self.validations,
            .duplicate_attributions_per_validation = validation.duplicates_max,
            .data_descriptors_per_peer = delivery.per_peer_limit,
            .data_descriptors_total = self.deliveries,
            .data_descriptors_reserved_per_peer = delivery.per_peer_reserve,
            .legal_atomic_work_bytes = 2 * constants.maxCompressedLen(constants.MAX_PAYLOAD_SIZE) + 2 * constants.MAX_PAYLOAD_SIZE,
            .page_bytes = storage.page_bytes,
            .rounding_per_message_max = storage.page_bytes - 1,
            .frame_bytes = frames,
            .event_bytes = self.output_bytes,
            .compression_bytes = constants.GOSSIP_MAX_SIZE,
            .peer_buffer_bytes = buffers,
            .metadata_bytes = metadata,
            .total_bytes = metadata + self.payload_bytes + frames + self.output_bytes + constants.GOSSIP_MAX_SIZE + buffers,
        };
    }
};
