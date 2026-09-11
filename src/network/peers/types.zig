pub const PeerId = @import("../wire/peer_id.zig").PeerId;
pub const Handle = @import("../quic/api.zig").Handle;
pub const Direction = @import("../types.zig").Direction;
pub const Address = @import("../types.zig").Address;
pub const ForkSeq = @import("config").ForkSeq;
pub const PeerRef = struct { index: u16, generation: u64 };
pub const Status = struct {
    fork_digest: [4]u8 = @splat(0),
    finalized_root: [32]u8 = @splat(0),
    finalized_epoch: u64 = 0,
    head_root: [32]u8 = @splat(0),
    head_slot: u64 = 0,
    earliest_available_slot: ?u64 = null,
};
pub const Metadata = struct {
    seq_number: u64 = 0,
    attnets: [8]u8 = @splat(0),
    syncnets: u8 = 0,
    custody_group_count: ?u64 = null,
};
pub const ForkContext = struct {
    fork: ForkSeq = .phase0,
    digest: [4]u8 = @splat(0),
    custody_groups: u16 = @min(128, @import("preset").NUMBER_OF_COLUMNS),
    minimum_sampling_groups: u16 = 0,

    pub fn validate(self: ForkContext) error{InvalidForkContext}!void {
        if (self.custody_groups == 0 or self.custody_groups > 128 or
            self.minimum_sampling_groups > self.custody_groups or
            @import("preset").NUMBER_OF_COLUMNS % self.custody_groups != 0)
            return error.InvalidForkContext;
    }
};
pub const LocalState = struct {
    status: Status = .{},
    metadata: Metadata = .{},
    fork: ForkContext = .{},
};
pub const PeerAction = enum { fatal, low_tolerance, mid_tolerance, high_tolerance };
pub const ReputationDecision = enum { none, disconnect, ban };
pub const DisconnectReason = enum {
    host,
    shutdown,
    transport_closed,
    duplicate,
    capacity,
    incompatible_fork,
    future_head,
    finalized_mismatch,
    missing_availability,
    invalid_status,
    invalid_metadata,
    remote_goodbye,
    health_timeout,
    reputation,
    banned,
    count_pruning,
    gossip_unavailable,
    health_error,
};
pub const Snapshot = struct {
    identify: ?@import("../identify/root.zig").Metadata = null,
    peer: PeerRef,
    identity: PeerId,
    connection: ?Handle,
    direction: Direction,
    endpoint: Address,
    relevant: bool,
    disconnect_reason: ?DisconnectReason = null,
    status: ?Status,
    metadata: ?Metadata,
    status_at_ms: u64,
    metadata_at_ms: u64,
    custody_groups: ?@import("custody.zig").Groups = null,
    sampling_groups: ?@import("custody.zig").Groups = null,
    connected_at_ms: u64,
    direct: bool,
    score: f64,
    score_at_ms: u64 = 0,
    ban_until_ms: u64,
    goodbye_until_ms: u64,
};
pub const Event = union(enum) {
    ready: Snapshot,
    updated: Snapshot,
    closed: struct {
        peer: PeerRef,
        identity: PeerId,
        connection: Handle,
        reason: DisconnectReason,
    },
};
pub const Admission = union(enum) {
    admitted: struct { peer: PeerRef, displaced: ?Handle = null, fresh: bool },
    duplicate,
    banned,
    cooldown,
    capacity,
};
pub const AdmissionOptions = struct { direction: Direction, endpoint: Address, now_ms: u64 };
pub const Options = struct {
    capacity: u16 = 512,
    outbound_reserve: u16 = 32,
    target_peers: u16 = 64,
    max_peers: u16 = 96,
    min_outbound: u16 = 16,
    engine_capacity: u16 = 96,

    pub fn validate(self: Options) error{InvalidOptions}!void {
        if (self.capacity == 0 or self.capacity > 4096 or
            self.outbound_reserve >= self.capacity or self.max_peers == 0 or
            self.max_peers > self.capacity or self.max_peers > self.engine_capacity or
            self.max_peers > 256 or self.target_peers > self.max_peers or
            self.min_outbound > self.target_peers) return error.InvalidOptions;
    }
};
pub const MemoryPlan = struct {
    inline_bytes: usize,
    allocated_bytes: usize,
    rows: u16,
    notification_slots: u16,
};

pub const Coverage = struct {
    attnets: u64 = 0,
    syncnets: u4 = 0,
    groups: @import("custody.zig").Groups = .initEmpty(),
};
pub const Demand = struct {
    attnets: u64 = 0,
    syncnets: u4 = 0,
    group_targets: [128]u16 = @splat(0),
    attestation_target: u16 = 1,
    sync_target: u16 = 1,
    expires_at_slot: u64 = 0,

    pub fn wanted(self: *const Demand) Coverage {
        var result: Coverage = .{ .attnets = self.attnets, .syncnets = self.syncnets };
        for (self.group_targets, 0..) |target, index| if (target > 0) {
            result.groups.set(index);
        };
        return result;
    }

    pub fn validate(self: *const Demand, context: *const ForkContext, max_peers: u16) !void {
        try context.validate();
        if (max_peers == 0 or max_peers > 256 or self.attestation_target == 0 or
            self.sync_target == 0 or self.attestation_target > max_peers or
            self.sync_target > max_peers) return error.InvalidDemand;
        for (self.group_targets, 0..) |target, index| {
            if (target > max_peers or (index >= context.custody_groups and target != 0))
                return error.InvalidDemand;
        }
    }
};
