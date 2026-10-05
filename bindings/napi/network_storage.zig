const std = @import("std");
const n = @import("network");
const r = @import("network_runtime.zig");
const Runtime = r.Runtime;
const application_cfg = @import("network_application_config.zig");
const requests = @import("network_requests.zig");
const incoming = @import("network_incoming.zig");
const publications = @import("network_publications.zig");
const gossip = @import("network_gossip.zig");
const projection = @import("network_peer_projection.zig");
const network_metrics = @import("network_metrics.zig");

/// A remembered peers snapshot and the network it belongs to.
const RememberedPage = struct {
    genesis_root: [32]u8,
    records: [n.peers.remembered.capacity]n.peers.remembered.Record,
};

pub const Stores = struct {
    backing: std.mem.Allocator,
    intents: [2]application_cfg.Intent = undefined,
    snapshots: [2][]n.peers.types.Snapshot,
    gossip_diagnostics: [2]n.gossipsub.diagnostics.Page = undefined,
    direct: [2][256]n.PeerId = undefined,
    targets: [2][256]n.PeerId = undefined,
    remembered: [2]RememberedPage = undefined,
    pub fn create(backing: std.mem.Allocator, capacity: usize) !*Stores {
        return createForTopics(backing, capacity, n.gossipsub.constants.topics_cap);
    }
    pub fn createForTopics(backing: std.mem.Allocator, capacity: usize, topics: usize) !*Stores {
        const self = try backing.create(Stores);
        errdefer backing.destroy(self);
        self.* = .{ .backing = backing, .snapshots = undefined };
        self.snapshots[0] = try backing.alloc(n.peers.types.Snapshot, capacity);
        errdefer backing.free(self.snapshots[0]);
        self.snapshots[1] = try backing.alloc(n.peers.types.Snapshot, capacity);
        errdefer backing.free(self.snapshots[1]);
        self.gossip_diagnostics[0] = try n.gossipsub.diagnostics.Page.init(backing, topics);
        errdefer self.gossip_diagnostics[0].deinit(backing);
        self.gossip_diagnostics[1] = try n.gossipsub.diagnostics.Page.init(backing, topics);
        return self;
    }
    pub fn destroy(self: *Stores) void {
        for (&self.gossip_diagnostics) |*page| page.deinit(self.backing);
        for (self.snapshots) |snapshots| self.backing.free(snapshots);
        self.backing.destroy(self);
    }
    pub fn bytes(capacity: usize) usize {
        return bytesForTopics(capacity, n.gossipsub.constants.topics_cap);
    }
    pub fn bytesForTopics(capacity: usize, topics: usize) usize {
        return @sizeOf(Stores) + 2 * capacity * @sizeOf(n.peers.types.Snapshot) + 2 * n.gossipsub.diagnostics.Page.backingBytes(topics);
    }
};

/// The runtime owns each installed allocation, including on partial initialization failure.
pub fn initialize(runtime: *Runtime, app: *const application_cfg.Config) !void {
    const resolved = &runtime.heavy.?.resolved;
    runtime.peer_capacity = resolved.core.peers.capacity;
    runtime.max_peers = resolved.core.peers.max_peers;
    const limits = resolved.core.protocols.reqresp;
    const request_capacity: usize = limits.outbound_max - limits.outbound_control_reserved;
    const incoming_capacity: usize = limits.serving_max - limits.serving_control_reserved;
    const gossip_options = &resolved.core.protocols.gossipsub;
    const chain = &runtime.heavy.?.config.chain;
    const processor_options = try n.gossip_processor.GossipProcessor.Options.resolve(runtime.heavy.?.config.processor_limits, runtime.heavy.?.config.execution_limits, gossip_options.topic_policy.?, chain.forks[0..chain.boundary_count], gossip_options.random_seed.?);
    const gossip_backing = gossip.Table.backingBytes(&processor_options);
    const resident_topics = try n.gossipsub.topic_policy.validate(gossip_options.topic_policy.?);
    const metrics_capacity = n.metrics.textCapacity(chain.topics[0..chain.boundary_count]);
    const publication_capacity: usize = if (runtime.heavy.?.config.profile == .small) 32 else publications.capacity_max;
    const bridge = publication_capacity * @sizeOf(publications.Cell) + 2 * metrics_capacity + gossip_backing + incoming_capacity * @sizeOf(incoming.Cell) + request_capacity * @sizeOf(requests.Cell) + @sizeOf(Runtime) + @sizeOf(r.Owner) - @sizeOf(n.NetworkCore) + Stores.bytesForTopics(runtime.peer_capacity, resident_topics) + @sizeOf(projection.Lane);
    if (bridge > app.resources.bridgeBudgetBytes) return error.NetworkBridgeBudgetExceeded;
    runtime.metrics = try network_metrics.Export.init(metrics_capacity);
    runtime.requests = try requests.Table.init(r.allocator, request_capacity, &runtime.payload_budget);
    runtime.payload_budget.limit = app.resources.bridgeBudgetBytes - bridge;
    var response_max: usize = 0;
    var request_max: usize = 0;
    for (0..n.reqresp.Protocol.count) |i| {
        const protocol: n.reqresp.Protocol = @enumFromInt(i);
        if (protocol.isControl()) continue;
        response_max = @max(response_max, protocol.info().response_max);
        request_max = @max(request_max, protocol.info().request_max);
    }
    // Keep one serving response, two local RPCs, and two urgent publications independently admissible.
    try runtime.payload_budget.protect(response_max + 2 * request_max * incoming_capacity, 2 * (request_max + 2 * response_max), 2 * gossip.payload_max);
    runtime.publications = try publications.Table.init(r.allocator, publication_capacity, &runtime.payload_budget);
    runtime.incoming = try incoming.Table.init(r.allocator, incoming_capacity, &runtime.payload_budget);
    runtime.gossip = try gossip.Table.init(r.allocator, processor_options);
    runtime.stores = try Stores.createForTopics(r.allocator, runtime.peer_capacity, resident_topics);
    runtime.lane = try r.allocator.create(projection.Lane);
    runtime.lane.?.* = .{};
}

test {
    _ = @import("network_storage_test.zig");
}
