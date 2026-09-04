const std = @import("std");
const connection = @import("connection.zig");
const constants = @import("../constants.zig");
const limits = @import("limits.zig");
const peer_id = @import("../wire/peer_id.zig");
const types = @import("../types.zig");

pub const Now = types.Now;
pub const Direction = types.Direction;
pub const ShutdownDirection = types.ShutdownDirection;
pub const CloseReason = types.CloseReason;
pub const Read = types.Read;
pub const Address = types.Address;
pub const Stats = connection.Stats;
pub const Sent = connection.Sent;

pub const Error = std.mem.Allocator.Error || error{InvalidLimits};

pub const StreamError = error{
    StaleHandle,
    UnknownStream,
    WouldBlock,
    StreamStopped,
    StreamLimit,
    StreamTableFull,
    NotEstablished,
    Transport,
};

pub const DialError = error{
    TableFull,
    DialLimit,
    OpenFailed,
};

pub const Handle = struct {
    index: u16,
    generation: u32,
};

pub const StreamHandle = struct {
    conn: Handle,
    id: u64,
    slot: u8,
};

pub const Event = union(enum) {
    connected: struct { conn: Handle, peer_id: peer_id.PeerId, direction: Direction },
    closed: struct {
        conn: Handle,
        peer_id: ?peer_id.PeerId,
        direction: Direction,
        reason: CloseReason,
    },
    stream_opened: StreamHandle,
    stream_closed: struct { stream: StreamHandle, reset_code: ?u64 },
    path_changed: struct { conn: Handle, peer: Address },
};

pub const Limits = struct {
    connections_max: u16 = limits.connections_max_default,
    handshaking_max: u16 = limits.handshaking_max,
    handshaking_per_source_max: u16 = limits.handshaking_per_source_max,
    dialing_max: u16 = limits.dialing_max,
    outbound_max: ?u16 = null,
    receive_budget_bytes: u64 = limits.receive_budget_bytes,
    idle_timeout_ms: u64 = limits.idle_timeout_ms,
    handshake_timeout_ms: u64 = limits.handshake_timeout_ms,
    keep_alive_ms: u64 = limits.keep_alive_ms,
    send_per_step_max: u16 = 256,
    receive_per_step_max: u16 = constants.receive_batch_max,
    work_per_step_max: u16 = 1024,
    keylog: bool = false,
    admit: ?*const fn (context: ?*anyopaque, from: *const Address) bool = null,
    admit_context: ?*anyopaque = null,
};

pub const Counters = struct {
    accepted: u64 = 0,
    dropped_unroutable: u64 = 0,
    dropped_short_initial: u64 = 0,
    dropped_full: u64 = 0,
    dropped_source_limit: u64 = 0,
    dropped_rejected: u64 = 0,
    dropped_no_entropy: u64 = 0,
    recv_errors: u64 = 0,
    send_errors: u64 = 0,
    stream_errors: u64 = 0,
    version_negotiations: u64 = 0,
    path_changes: u64 = 0,
};

pub const SendBatch = struct {
    buffers: [constants.send_batch_max][constants.datagram_size_max]u8 = undefined,
    sent: [constants.send_batch_max]Sent = undefined,
    owners: [constants.send_batch_max]Handle = undefined,
};

pub const ReceiveOutcome = union(enum) {
    accepted: Handle,
    version_negotiation: []u8,
    dropped,
};

pub const EntropyPool = struct {
    bytes: [limits.local_cid_length]u8 = undefined,
    fresh: bool = false,

    pub fn fill(self: *EntropyPool, bytes: [limits.local_cid_length]u8) void {
        self.bytes = bytes;
        self.fresh = true;
    }

    pub fn take(self: *EntropyPool) ?[limits.local_cid_length]u8 {
        if (!self.fresh) return null;
        self.fresh = false;
        return self.bytes;
    }
};

/// Flow-control windows and host-owned queues, excluding native QUIC/TLS overhead.
pub const MemoryPlan = struct {
    requested_receive_window_bytes: u64,
    receive_window_bytes: u64,
    connection_window_bytes: u64,
    stream_window_bytes: u64,
    scheduled_datagrams: u16,
    scheduled_payload_bytes: u64,
    scheduled_storage_bytes: u64,
    ready_batch_datagrams: u8 = constants.send_batch_max,
    ready_batch_storage_bytes: u64 = @sizeOf(SendBatch),
    udp_receive_storage_bytes: u64 = @sizeOf(@import("../udp.zig").Udp),
    native_pacing_supported: bool,
};
