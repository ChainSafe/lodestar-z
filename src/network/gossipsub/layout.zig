const constants = @import("constants.zig");
const storage = @import("message_store.zig");
const delivery = @import("delivery.zig");
const policy = @import("topic_policy.zig");
const Options = @import("options.zig").Options;

pub const Plan = struct {
    retained_bytes: usize,
    page_count: usize,
    message_entries: usize,
    validation_capacity: usize,
    data_descriptors_per_peer: usize,
    data_descriptors_reserved_per_peer: usize,
    page_bytes: usize,
    frame_bytes: usize,
    compression_bytes: usize,
    peer_buffer_bytes: usize,
    metadata_bytes: usize,
    total_bytes: usize,
};

/// Derives physical storage from configured concurrency. Per-peer byte limits
/// charge logical obligations; they do not multiply the shared payload budget.
pub const Layout = struct {
    sessions: u16,
    connection_slots: u16,
    retained: u16,
    history: usize,
    seen: usize,
    validations: usize,
    fingerprints: usize,
    payload_entries: usize,
    payload_bytes: usize,
    deliveries: usize,
    receive_arena_bytes: usize,
    session_buffer_bytes: usize,
    namespace_bytes: usize,

    pub fn init(options: *const Options) Layout {
        return .{
            .sessions = options.connected_capacity,
            .connection_slots = options.connection_slots,
            .retained = options.retained_capacity,
            .history = historyCapacity(options),
            .seen = options.seen_capacity,
            .validations = options.validation_capacity,
            .fingerprints = 4 * options.validation_capacity,
            .payload_entries = historyCapacity(options) + options.validation_capacity,
            .payload_bytes = options.mcache_arena_bytes / storage.page_bytes * storage.page_bytes,
            .deliveries = delivery.Pool.capacity(options.connected_capacity, options.validation_capacity),
            .receive_arena_bytes = options.receive_arena_bytes,
            .session_buffer_bytes = @import("peer_io.zig").PeerIo.bufferBytes(options),
            .namespace_bytes = if (options.topic_policy) |boundaries| policy.Namespace.backingBytes(boundaries, options.connected_capacity) else 0,
        };
    }

    /// The history must hold every message retained in its six windows, publications included,
    /// or it evicts messages peers can still request. With processor limits, their per-kind
    /// allowances bound what it can retain, so it covers their total, which validation capacity
    /// equals and which stays below the history's ceiling. A node on every attestation subnet can
    /// retain a whole slot of attestations within six windows.
    fn historyCapacity(options: *const Options) usize {
        return if (options.payload_limits != null) @max(options.mcache_capacity, options.validation_capacity) else options.mcache_capacity;
    }

    pub fn plan(self: *const Layout) Plan {
        const peers = @import("peer_book.zig");
        const metadata = @sizeOf(@import("gossipsub.zig").Gossipsub) +
            @sizeOf(@import("sessions.zig").Sessions) + @sizeOf(@import("overlay.zig").Overlay) +
            @import("sessions.zig").Sessions.metadataBytes(self) +
            peers.PeerBook.backingBytes(self.retained) +
            @import("messages.zig").Messages.metadataBytes(self) +
            @import("recovery.zig").Recovery.backingBytes() + self.namespace_bytes;
        const frames = self.receive_arena_bytes + constants.GOSSIP_MAX_SIZE;
        const buffers = self.sessions * self.session_buffer_bytes;
        return .{
            .retained_bytes = self.payload_bytes,
            .page_count = self.payload_bytes / storage.page_bytes,
            .message_entries = self.payload_entries,
            .validation_capacity = self.validations,
            .data_descriptors_per_peer = delivery.per_peer_limit,
            .data_descriptors_reserved_per_peer = delivery.per_peer_reserve,
            .page_bytes = storage.page_bytes,
            .frame_bytes = frames,
            .compression_bytes = constants.GOSSIP_MAX_SIZE,
            .peer_buffer_bytes = buffers,
            .metadata_bytes = metadata,
            .total_bytes = metadata + self.payload_bytes + frames + constants.GOSSIP_MAX_SIZE + buffers,
        };
    }
};
