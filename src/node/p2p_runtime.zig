//! Node-owned P2P runtime orchestration.
//!
//! Keeps the beacon node's networking event loop, discovery/bootstrap,
//! gossip ingress, and sync transport plumbing out of `beacon_node.zig`.

const std = @import("std");
const log = @import("log");

const preset = @import("preset").preset;
const preset_root = @import("preset");
const config_mod = @import("config");
const BeaconConfig = config_mod.BeaconConfig;
const ForkSeq = config_mod.ForkSeq;
const state_transition = @import("state_transition");
const computeEpochAtSlot = state_transition.computeEpochAtSlot;
const types = @import("consensus_types");
const fork_types = @import("fork_types");
const chain_mod = @import("chain");
const kzg_mod = @import("kzg");
const networking = @import("networking");
const DiscoveryService = networking.DiscoveryService;
const PeerManager = networking.PeerManager;
const SubnetService = networking.SubnetService;
const SubnetId = networking.SubnetId;
const ReqRespContext = networking.ReqRespContext;
const ConnectionDirection = networking.ConnectionDirection;
const GoodbyeReason = networking.GoodbyeReason;
const PeerAction = networking.PeerAction;
const peer_scoring = networking.peer_scoring;
const StatusMessage = networking.messages.StatusMessage;
const StatusMessageV2 = networking.messages.StatusMessageV2;
const MetadataV2 = networking.messages.MetadataV2;
const MetadataV3 = networking.messages.MetadataV3;
const AttnetsBitfield = networking.peer_info.AttnetsBitfield;
const SyncnetsBitfield = networking.peer_info.SyncnetsBitfield;
const ATTESTATION_SUBNET_COUNT = networking.peer_info.ATTESTATION_SUBNET_COUNT;
const SYNC_COMMITTEE_SUBNET_COUNT = networking.peer_info.SYNC_COMMITTEE_SUBNET_COUNT;
const discv5 = @import("discv5");
const libp2p = @import("zig-libp2p");
const Multiaddr = @import("multiaddr").Multiaddr;
const sync_mod = @import("sync");
const SyncService = sync_mod.SyncService;
const BatchBlock = sync_mod.BatchBlock;

const GossipHandler = @import("gossip_handler.zig").GossipHandler;
const gossip_ingress_mod = @import("gossip_ingress.zig");
const reqresp_callbacks_mod = @import("reqresp_callbacks.zig");
const gossip_node_callbacks_mod = @import("gossip_node_callbacks.zig");
const SyncCallbackCtx = @import("sync_bridge.zig").SyncCallbackCtx;

const BlobSidecar = types.deneb.BlobSidecar;
const BlobIdentifier = types.deneb.BlobIdentifier;
const DataColumnSidecar = types.fulu.DataColumnSidecar;
const Libp2pPeerId = @TypeOf((@as(libp2p.security.Session1, undefined)).remote_id);
const Libp2pPublicKey = @TypeOf((@as(libp2p.security.Session1, undefined)).remote_public_key);

const BYTES_PER_BLOB = kzg_mod.BYTES_PER_BLOB;
const MAX_COLUMNS = preset_root.NUMBER_OF_COLUMNS;

const SyncBlockMeta = chain_mod.PlannedBlockIngress;

const PeerStatusResponse = struct {
    status: StatusMessage.Type,
    earliest_available_slot: ?u64 = null,
};

const PeerMetadataResponse = struct {
    metadata: MetadataV2.Type,
    custody_group_count: ?u64 = null,
};

const ReqRespMaintenanceProtocol = peer_scoring.ReqRespProtocol;

const SlotRange = struct {
    start_slot: u64,
    count: u64,
};

const DiscoveryPeerIdentity = struct {
    node_id: [32]u8,
    pubkey: [33]u8,
};

const BlobFetchState = struct {
    existing: ?[]const u8 = null,
    sidecars: []?[]const u8,
    new_sidecars: std.ArrayListUnmanaged([]const u8) = .empty,

    fn init(
        allocator: std.mem.Allocator,
        blob_count: usize,
        existing: ?[]const u8,
    ) !BlobFetchState {
        const sidecars = try allocator.alloc(?[]const u8, blob_count);
        @memset(sidecars, null);

        if (existing) |bytes| {
            var offset: usize = 0;
            var index: usize = 0;
            while (offset + preset_root.BLOBSIDECAR_FIXED_SIZE <= bytes.len and index < sidecars.len) : ({
                offset += preset_root.BLOBSIDECAR_FIXED_SIZE;
                index += 1;
            }) {
                sidecars[index] = bytes[offset..][0..preset_root.BLOBSIDECAR_FIXED_SIZE];
            }
        }

        return .{
            .existing = existing,
            .sidecars = sidecars,
        };
    }

    fn deinit(self: *BlobFetchState, allocator: std.mem.Allocator) void {
        if (self.existing) |bytes| allocator.free(bytes);
        for (self.new_sidecars.items) |bytes| allocator.free(bytes);
        self.new_sidecars.deinit(allocator);
        allocator.free(self.sidecars);
        self.* = undefined;
    }

    fn setFetched(self: *BlobFetchState, allocator: std.mem.Allocator, index: usize, bytes: []const u8) !void {
        self.sidecars[index] = bytes;
        try self.new_sidecars.append(allocator, bytes);
    }

    fn aggregate(self: *const BlobFetchState, allocator: std.mem.Allocator) ![]u8 {
        var total_len: usize = 0;
        for (self.sidecars) |maybe_sidecar| {
            const sidecar = maybe_sidecar orelse return error.MissingBlobSidecar;
            total_len += sidecar.len;
        }

        const out = try allocator.alloc(u8, total_len);
        var offset: usize = 0;
        for (self.sidecars) |maybe_sidecar| {
            const sidecar = maybe_sidecar.?;
            @memcpy(out[offset..][0..sidecar.len], sidecar);
            offset += sidecar.len;
        }
        return out;
    }
};

fn parseIp4(raw: []const u8) ?[4]u8 {
    const addr = std.Io.net.IpAddress.parseIp4(raw, 0) catch return null;
    return switch (addr) {
        .ip4 => |ip4| ip4.bytes,
        .ip6 => null,
    };
}

fn parseIp6(raw: []const u8) ?[16]u8 {
    const addr = std.Io.net.IpAddress.parseIp6(raw, 0) catch return null;
    return switch (addr) {
        .ip4 => null,
        .ip6 => |ip6| ip6.bytes,
    };
}

fn formatListenMultiaddr(buf: []u8, host: []const u8, port: u16) ![]const u8 {
    _ = std.Io.net.IpAddress.parseIp4(host, 0) catch {
        _ = std.Io.net.IpAddress.parseIp6(host, 0) catch return error.InvalidListenAddress;
        return std.fmt.bufPrint(buf, "/ip6/{s}/udp/{d}/quic-v1", .{ host, port });
    };
    return std.fmt.bufPrint(buf, "/ip4/{s}/udp/{d}/quic-v1", .{ host, port });
}

fn formatDiscv5DialMultiaddr(buf: []u8, addr: discv5.Address) ![]const u8 {
    return switch (addr) {
        .ip4 => |ip4| std.fmt.bufPrint(buf, "/ip4/{d}.{d}.{d}.{d}/udp/{d}/quic-v1", .{
            ip4.bytes[0], ip4.bytes[1], ip4.bytes[2], ip4.bytes[3], ip4.port,
        }),
        .ip6 => |ip6| std.fmt.bufPrint(buf, "/ip6/{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}/udp/{d}/quic-v1", .{
            ip6.bytes[0],  ip6.bytes[1],  ip6.bytes[2],  ip6.bytes[3],
            ip6.bytes[4],  ip6.bytes[5],  ip6.bytes[6],  ip6.bytes[7],
            ip6.bytes[8],  ip6.bytes[9],  ip6.bytes[10], ip6.bytes[11],
            ip6.bytes[12], ip6.bytes[13], ip6.bytes[14], ip6.bytes[15],
            ip6.port,
        }),
    };
}

fn discoveryIdentityKnown(identity: DiscoveryPeerIdentity) bool {
    return !std.mem.eql(u8, &identity.pubkey, &([_]u8{0} ** 33));
}

fn discoveryPeerIdMatches(
    allocator: std.mem.Allocator,
    peer_id_text: []const u8,
    pubkey: [33]u8,
) !bool {
    const peer_data = try allocator.dupe(u8, pubkey[0..]);
    defer allocator.free(peer_data);

    var public_key = Libp2pPublicKey{
        .type = .SECP256K1,
        .data = peer_data,
    };

    const expected_peer_id = try Libp2pPeerId.fromPublicKey(allocator, &public_key);
    const actual_peer_id = try Libp2pPeerId.fromString(allocator, peer_id_text);
    return expected_peer_id.eql(&actual_peer_id);
}

fn discoveryPeerIdTextFromPubkey(
    allocator: std.mem.Allocator,
    pubkey: [33]u8,
) ![]u8 {
    const peer_data = try allocator.dupe(u8, pubkey[0..]);
    defer allocator.free(peer_data);

    var public_key = Libp2pPublicKey{
        .type = .SECP256K1,
        .data = peer_data,
    };

    const peer_id = try Libp2pPeerId.fromPublicKey(allocator, &public_key);
    const peer_id_text = try allocator.alloc(u8, peer_id.toBase58Len());
    _ = try peer_id.toBase58(peer_id_text);
    return peer_id_text;
}

pub fn start(self: *BeaconNode, io: std.Io, listen_addr: []const u8, port: u16) !void {
    var ma_buf: [160]u8 = undefined;
    const ma_str = try formatListenMultiaddr(&ma_buf, listen_addr, port);
    const listen_multiaddr = try Multiaddr.fromString(self.allocator, ma_str);
    defer listen_multiaddr.deinit();

    const p2p_req_ctx = try self.allocator.create(reqresp_callbacks_mod.RequestContext);
    errdefer self.allocator.destroy(p2p_req_ctx);
    p2p_req_ctx.* = .{ .node = @ptrCast(self) };
    self.p2p_request_ctx = p2p_req_ctx;

    const req_resp_ctx = try self.allocator.create(ReqRespContext);
    errdefer self.allocator.destroy(req_resp_ctx);
    req_resp_ctx.* = reqresp_callbacks_mod.makeReqRespContext(p2p_req_ctx);
    self.p2p_req_resp_ctx = req_resp_ctx;

    const req_resp_server_policy = try self.allocator.create(networking.ReqRespServerPolicy);
    errdefer self.allocator.destroy(req_resp_server_policy);
    req_resp_server_policy.* = reqresp_callbacks_mod.makeReqRespServerPolicy(p2p_req_ctx);
    self.p2p_req_resp_policy = req_resp_server_policy;

    const req_resp_rate_limiter = try self.allocator.create(networking.RateLimiter);
    errdefer self.allocator.destroy(req_resp_rate_limiter);
    req_resp_rate_limiter.* = networking.RateLimiter.init(self.allocator);
    self.req_resp_rate_limiter = req_resp_rate_limiter;

    const head_slot = self.currentHeadSlot();
    const fork_digest = self.config.forkDigestAtSlot(head_slot, self.genesis_validators_root);

    var host_identity = self.node_identity.libp2pKeyPair();
    {
        const derived_peer_id = try host_identity.peerId(self.allocator);
        const base58_len = derived_peer_id.toBase58Len();
        const base58_buf = try self.allocator.alloc(u8, base58_len);
        defer self.allocator.free(base58_buf);
        const peer_id_text = try derived_peer_id.toBase58(base58_buf);
        if (!std.mem.eql(u8, peer_id_text, self.node_identity.peer_id)) {
            return error.PeerIdMismatch;
        }
    }

    self.p2p_service = try networking.p2p_service.P2pService.init(self.allocator, .{
        .fork_digest = fork_digest,
        .fork_seq = self.config.forkSeq(head_slot),
        .req_resp_context = req_resp_ctx,
        .req_resp_server_policy = req_resp_server_policy,
        .host_identity = host_identity,
        .identify_agent_version = self.identify_agent_version,
        .gossipsub_config = .{
            .mesh_degree = 8,
            .mesh_degree_lo = 6,
            .mesh_degree_hi = 12,
            .mesh_degree_lazy = 6,
            .heartbeat_interval_ms = 700,
            .signature_policy = .strict_no_sign,
            .publish_policy = .anonymous,
            .msg_id_fn = &networking.gossipMessageIdFn,
        },
    });
    defer deinitService(self, io);

    var svc = &self.p2p_service.?;
    try svc.start(io, listen_multiaddr);
    try initSubnetService(self);
    subscribeInitialSubnets(self, svc);

    initDiscoveryService(self) catch |err| {
        log.logger(.node).warn("Failed to initialize discovery service: {}", .{err});
    };
    initPeerManager(self) catch |err| {
        log.logger(.node).warn("Failed to initialize peer manager: {}", .{err});
    };

    initGossipHandler(self);
    initSyncPipeline(self) catch |err| {
        log.logger(.node).warn("Failed to initialize sync pipeline: {}", .{err});
    };

    bootstrapBootnodes(self, io, svc);
    runLoop(self, io, svc);
}

pub fn deinitService(self: *BeaconNode, io: std.Io) void {
    if (self.p2p_service) |*svc| {
        svc.deinit(io);
        self.p2p_service = null;
    }
}

pub fn deinitOwnedState(self: *BeaconNode) void {
    if (self.discovery_service) |ds| {
        ds.deinit();
        self.allocator.destroy(ds);
        self.discovery_service = null;
    }

    if (self.peer_manager) |pm| {
        pm.deinit();
        self.allocator.destroy(pm);
        self.peer_manager = null;
    }

    if (self.subnet_service) |svc| {
        svc.deinit();
        self.allocator.destroy(svc);
        self.subnet_service = null;
    }

    if (self.req_resp_rate_limiter) |limiter| {
        limiter.deinit();
        self.allocator.destroy(limiter);
        self.req_resp_rate_limiter = null;
    }
    if (self.p2p_req_resp_policy) |policy| {
        self.allocator.destroy(policy);
        self.p2p_req_resp_policy = null;
    }
    if (self.p2p_req_resp_ctx) |ctx| {
        self.allocator.destroy(ctx);
        self.p2p_req_resp_ctx = null;
    }
    if (self.p2p_request_ctx) |ctx| {
        self.allocator.destroy(ctx);
        self.p2p_request_ctx = null;
    }

    if (self.gossip_handler) |gh| {
        gh.deinit();
        self.gossip_handler = null;
    }

    if (self.sync_service_inst) |svc| {
        self.allocator.destroy(svc);
        self.sync_service_inst = null;
    }
    if (self.sync_callback_ctx) |ctx| {
        self.allocator.destroy(ctx);
        self.sync_callback_ctx = null;
    }
}

pub fn processSyncBatches(self: *BeaconNode, io: std.Io, svc: *networking.P2pService) void {
    const cb_ctx = self.sync_callback_ctx orelse return;
    if (self.sync_service_inst == null) return;

    while (cb_ctx.popPendingRequest()) |req| {
        const peer_id = req.peerId();
        std.log.info("Processing sync chain {d} batch {d}/gen {d}: slots {d}..{d} from peer {s}", .{
            req.chain_id,
            req.batch_id,
            req.generation,
            req.start_slot,
            req.start_slot + req.count - 1,
            peer_id,
        });

        if (self.peer_manager) |pm| {
            if (pm.getPeer(peer_id)) |peer| {
                if (peer.sync_info) |sync_info| {
                    if (sync_info.earliest_available_slot) |earliest_available_slot| {
                        if (req.start_slot < earliest_available_slot) {
                            std.log.warn("Batch {d}: peer {s} cannot serve requested range start_slot={d} earliest_available_slot={d}", .{
                                req.batch_id,
                                peer_id,
                                req.start_slot,
                                earliest_available_slot,
                            });
                            if (self.sync_service_inst) |sync_svc| {
                                sync_svc.onBatchError(req.chain_id, req.batch_id, req.generation, peer_id);
                            }
                            continue;
                        }
                    }
                }
            }
        }

        const blocks = fetchRawBlocksByRange(self, io, svc, peer_id, req.start_slot, req.count) catch |err| {
            reportReqRespFetchFailure(self, io, peer_id, .beacon_blocks_by_range, err);
            std.log.warn("Batch {d} fetch failed: {}", .{ req.batch_id, err });
            if (self.sync_service_inst) |sync_svc| {
                sync_svc.onBatchError(req.chain_id, req.batch_id, req.generation, peer_id);
            }
            continue;
        };
        defer {
            for (blocks) |blk| self.allocator.free(blk.block_bytes);
            self.allocator.free(blocks);
        }

        if (blocks.len == 0) {
            std.log.warn("Batch {d}: empty response from peer", .{req.batch_id});
            if (self.sync_service_inst) |sync_svc| {
                sync_svc.onBatchError(req.chain_id, req.batch_id, req.generation, peer_id);
            }
            continue;
        }

        ensureRangeSyncDataAvailability(self, io, svc, peer_id, blocks) catch |err| {
            std.log.warn("Batch {d}: DA prefetch failed: {}", .{ req.batch_id, err });
            if (self.sync_service_inst) |sync_svc| {
                sync_svc.onBatchError(req.chain_id, req.batch_id, req.generation, peer_id);
            }
            continue;
        };

        if (self.sync_service_inst) |sync_svc| {
            sync_svc.onBatchResponse(req.chain_id, req.batch_id, req.generation, blocks);
        }

        std.log.info("Batch {d}: delivered {d} blocks to sync pipeline", .{
            req.batch_id,
            blocks.len,
        });
    }
}

pub fn processSyncByRootRequests(self: *BeaconNode, io: std.Io, svc: *networking.P2pService) void {
    const cb_ctx = self.sync_callback_ctx orelse return;

    while (cb_ctx.popPendingByRootRequest()) |req| {
        const peer_id = req.peerId();
        const root = req.root;
        std.log.info("processSyncByRoot: fetching root {x:0>2}{x:0>2}{x:0>2}{x:0>2}... from peer {s}", .{
            root[0], root[1], root[2], root[3], peer_id,
        });

        const block_ssz = fetchBlockByRoot(self, io, svc, peer_id, root) catch |err| {
            reportReqRespFetchFailure(self, io, peer_id, .beacon_blocks_by_root, err);
            std.log.warn("processSyncByRoot: fetch failed for root {x:0>2}{x:0>2}{x:0>2}{x:0>2}...: {}", .{
                root[0], root[1], root[2], root[3], err,
            });
            self.unknown_block_sync.onFetchFailed(root);
            continue;
        };
        defer self.allocator.free(block_ssz);

        ensureByRootDataAvailability(self, io, svc, peer_id, block_ssz) catch |err| {
            std.log.warn("processSyncByRoot: DA prefetch failed for root {x:0>2}{x:0>2}{x:0>2}{x:0>2}...: {}", .{
                root[0], root[1], root[2], root[3], err,
            });
            self.unknown_block_sync.onFetchFailed(root);
            continue;
        };

        self.unknown_block_sync.onParentFetched(root, block_ssz) catch |err| {
            std.log.warn("processSyncByRoot: onParentFetched error: {}", .{err});
        };
    }
}

fn subscribeInitialSubnets(self: *BeaconNode, svc: *networking.P2pService) void {
    const gossip_topics = networking.gossip_topics;

    if (self.node_options.subscribe_all_subnets) {
        var attestation_subnet: u8 = 0;
        while (attestation_subnet < gossip_topics.MAX_ATTESTATION_SUBNET_ID) : (attestation_subnet += 1) {
            svc.subscribeSubnet(.beacon_attestation, attestation_subnet) catch |err| {
                std.log.warn("Failed to subscribe to attestation subnet {d}: {}", .{ attestation_subnet, err });
            };
        }
        std.log.info("Subscribed to all {d} attestation subnets", .{gossip_topics.MAX_ATTESTATION_SUBNET_ID});
    } else {
        std.log.info("Attestation subnet gossip subscriptions will follow validator subnet demand", .{});
    }

    const custody_req = self.config.chain.CUSTODY_REQUIREMENT;
    var data_column_subnet: u8 = 0;
    while (data_column_subnet < custody_req and data_column_subnet < gossip_topics.MAX_DATA_COLUMN_SIDECAR_SUBNET_ID) : (data_column_subnet += 1) {
        svc.subscribeSubnet(.data_column_sidecar, data_column_subnet) catch |err| {
            std.log.warn("Failed to subscribe to data column subnet {d}: {}", .{ data_column_subnet, err });
        };
    }
    std.log.info("Subscribed to {d} data column subnets (custody requirement)", .{custody_req});
}

fn initSubnetService(self: *BeaconNode) !void {
    const svc = try self.allocator.create(SubnetService);
    errdefer self.allocator.destroy(svc);
    svc.* = SubnetService.init(self.allocator, self.node_identity.node_id);
    if (self.clock) |clock| {
        if (clock.currentSlot(self.io)) |slot| {
            svc.onSlot(slot);
        }
    }
    self.subnet_service = svc;
}

fn closeOwnedQuicStream(io: std.Io, stream: *networking.QuicStream) void {
    stream.close(io);
    stream.deinit();
}

const OpenedReqRespRequest = struct {
    permit: networking.ReqRespRequestPermit,
    stream: networking.QuicStream,

    fn deinit(self: *OpenedReqRespRequest, io: std.Io) void {
        closeOwnedQuicStream(io, &self.stream);
        self.permit.deinit(io);
    }
};

fn openReqRespRequest(
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
    method: networking.rate_limiter.SelfRateLimitMethod,
    protocol_id: []const u8,
) !OpenedReqRespRequest {
    var permit = try svc.acquireReqRespRequestPermit(io, peer_id, method);
    errdefer permit.deinit(io);

    const stream = try svc.dialProtocol(io, peer_id, protocol_id);
    return .{
        .permit = permit,
        .stream = stream,
    };
}

fn bootstrapBootnodes(self: *BeaconNode, io: std.Io, svc: *networking.P2pService) void {
    if (self.bootstrap_peers.len == 0) return;

    std.log.info("Dialing {d} bootstrap peer(s)...", .{self.bootstrap_peers.len});
    for (self.bootstrap_peers) |enr_str| {
        dialBootnodeEnr(self, io, svc, enr_str) catch |err| {
            std.log.warn("Failed to dial bootnode: {}", .{err});
        };
    }
}

const active_p2p_tick_ns: u64 = std.time.ns_per_ms;
const idle_p2p_tick_ns: u64 = 25 * std.time.ns_per_ms;
const connectivity_maintenance_interval_ns: u64 = 100 * std.time.ns_per_ms;
const discovery_maintenance_interval_ns: u64 = 6 * std.time.ns_per_s;
const peer_maintenance_interval_ns: u64 = std.time.ns_per_s;
const peer_manager_heartbeat_interval_ns: u64 = networking.peer_manager.HEARTBEAT_INTERVAL_MS * std.time.ns_per_ms;
const max_discovery_dials_per_tick: u32 = 4;

fn runDiscoveryMaintenance(self: *BeaconNode) bool {
    if (self.discovery_service) |ds| {
        if (self.peer_manager) |pm| {
            const peer_count = pm.peerCount();
            ds.setConnectedPeers(peer_count);
            if (self.metrics) |metrics| metrics.peers_connected.set(@intCast(peer_count));
        }
        ds.discoverPeers();
        if (self.metrics) |metrics| {
            metrics.discovery_peers_known.set(@intCast(ds.knownPeerCount()));
        }
        return true;
    }
    return false;
}

fn runConnectivityMaintenance(self: *BeaconNode, io: std.Io, svc: *networking.P2pService) bool {
    var did_work = syncSubnetState(self, svc);

    if (self.discovery_service) |ds| {
        ds.poll();
        if (ds.takeLocalEnrChanged()) {
            refreshApiNodeIdentityFromDiscovery(self, ds) catch |err| {
                std.log.warn("Failed to refresh API node identity from discovery ENR: {}", .{err});
            };
            did_work = true;
        }
        did_work = dialDiscoveredPeers(self, io, svc, ds) or did_work;
    }

    return reconcilePeerConnections(self, io, svc) or did_work;
}

fn currentNetworkSlot(self: *BeaconNode, io: std.Io) ?u64 {
    if (self.clock) |clock| {
        if (clock.currentSlot(io)) |slot| return slot;
    }
    return self.currentHeadSlot();
}

fn getDesiredActiveAttestationSubnets(self: *BeaconNode, subnet_service: *SubnetService) ![]SubnetId {
    if (!self.node_options.subscribe_all_subnets) {
        return subnet_service.getActiveAttestationSubnets();
    }

    const subnets = try self.allocator.alloc(SubnetId, ATTESTATION_SUBNET_COUNT);
    for (subnets, 0..) |*subnet, i| subnet.* = @intCast(i);
    return subnets;
}

fn bitsetFromSubnets(comptime BitSet: type, subnets: []const SubnetId) BitSet {
    var bits = BitSet.initEmpty();
    for (subnets) |subnet| bits.set(subnet);
    return bits;
}

fn attnetsBytesFromSubnets(subnets: []const SubnetId) [8]u8 {
    var bytes = [_]u8{0} ** 8;
    for (subnets) |subnet| {
        bytes[subnet / 8] |= @as(u8, 1) << @intCast(subnet % 8);
    }
    return bytes;
}

fn syncnetsBytesFromSubnets(subnets: []const SubnetId) [1]u8 {
    var bytes = [_]u8{0} ** 1;
    for (subnets) |subnet| {
        bytes[subnet / 8] |= @as(u8, 1) << @intCast(subnet % 8);
    }
    return bytes;
}

fn syncGossipForkState(self: *BeaconNode, svc: *networking.P2pService) bool {
    const slot = currentNetworkSlot(self, self.io) orelse return false;
    const epoch = computeEpochAtSlot(slot);
    const active = self.config.activeGossipForksAtEpoch(epoch, self.genesis_validators_root);

    var active_forks: [config_mod.ForkSeq.count]networking.p2p_service.ActiveGossipFork = undefined;
    for (active.asSlice(), 0..) |fork, i| {
        active_forks[i] = .{
            .fork_digest = fork.digest,
            .fork_seq = fork.fork_seq,
        };
    }

    svc.setActiveGossipForks(active_forks[0..active.count]) catch |err| {
        std.log.warn("Failed to update active gossip fork boundaries: {}", .{err});
        return false;
    };
    svc.setPublishFork(
        self.config.forkDigestAtSlot(slot, self.genesis_validators_root),
        self.config.forkSeq(slot),
    );
    return true;
}

fn syncSubnetState(self: *BeaconNode, svc: *networking.P2pService) bool {
    const subnet_service = self.subnet_service orelse return false;
    const slot = currentNetworkSlot(self, self.io) orelse return false;
    var did_work = syncGossipForkState(self, svc);
    if (subnet_service.current_slot != slot) {
        subnet_service.onSlot(slot);
    }

    const active_attnets = getDesiredActiveAttestationSubnets(self, subnet_service) catch |err| {
        std.log.warn("Failed to collect active attestation subnet demand: {}", .{err});
        return false;
    };
    defer if (active_attnets.len > 0) self.allocator.free(active_attnets);

    const active_syncnets = subnet_service.getActiveSyncSubnets() catch |err| {
        std.log.warn("Failed to collect active sync subnet demand: {}", .{err});
        return false;
    };
    defer if (active_syncnets.len > 0) self.allocator.free(active_syncnets);

    var desired_gossip_attnets = if (self.node_options.subscribe_all_subnets)
        bitsetFromSubnets(networking.peer_info.AttnetsBitfield, active_attnets)
    else blk: {
        const gossip_attnets = subnet_service.getGossipAttestationSubnets() catch |err| {
            std.log.warn("Failed to collect gossip attestation subnets: {}", .{err});
            return false;
        };
        defer if (gossip_attnets.len > 0) self.allocator.free(gossip_attnets);
        break :blk bitsetFromSubnets(networking.peer_info.AttnetsBitfield, gossip_attnets);
    };
    const desired_gossip_syncnets = bitsetFromSubnets(networking.peer_info.SyncnetsBitfield, active_syncnets);

    var subnet: usize = 0;
    while (subnet < ATTESTATION_SUBNET_COUNT) : (subnet += 1) {
        const should_subscribe = desired_gossip_attnets.isSet(subnet);
        const is_subscribed = self.gossip_attestation_subscriptions.isSet(subnet);
        if (should_subscribe == is_subscribed) continue;

        if (should_subscribe) {
            svc.subscribeSubnet(.beacon_attestation, @intCast(subnet)) catch |err| {
                std.log.warn("Failed to subscribe attestation subnet {d}: {}", .{ subnet, err });
                continue;
            };
            self.gossip_attestation_subscriptions.set(subnet);
        } else {
            svc.unsubscribeSubnet(.beacon_attestation, @intCast(subnet)) catch |err| {
                std.log.warn("Failed to unsubscribe attestation subnet {d}: {}", .{ subnet, err });
                continue;
            };
            self.gossip_attestation_subscriptions.unset(subnet);
        }
        did_work = true;
    }

    subnet = 0;
    while (subnet < SYNC_COMMITTEE_SUBNET_COUNT) : (subnet += 1) {
        const should_subscribe = desired_gossip_syncnets.isSet(subnet);
        const is_subscribed = self.gossip_sync_subscriptions.isSet(subnet);
        if (should_subscribe == is_subscribed) continue;

        if (should_subscribe) {
            svc.subscribeSubnet(.sync_committee, @intCast(subnet)) catch |err| {
                std.log.warn("Failed to subscribe sync subnet {d}: {}", .{ subnet, err });
                continue;
            };
            self.gossip_sync_subscriptions.set(subnet);
        } else {
            svc.unsubscribeSubnet(.sync_committee, @intCast(subnet)) catch |err| {
                std.log.warn("Failed to unsubscribe sync subnet {d}: {}", .{ subnet, err });
                continue;
            };
            self.gossip_sync_subscriptions.unset(subnet);
        }
        did_work = true;
    }

    const metadata_attnets = subnet_service.getMetadataAttestationSubnets() catch |err| {
        std.log.warn("Failed to collect metadata attestation subnets: {}", .{err});
        return false;
    };
    defer if (metadata_attnets.len > 0) self.allocator.free(metadata_attnets);

    const attnets_bytes = attnetsBytesFromSubnets(metadata_attnets);
    const syncnets_bytes = syncnetsBytesFromSubnets(active_syncnets);
    if (!std.mem.eql(u8, &self.api_node_identity.metadata.attnets, &attnets_bytes) or
        !std.mem.eql(u8, &self.api_node_identity.metadata.syncnets, &syncnets_bytes))
    {
        self.api_node_identity.metadata.attnets = attnets_bytes;
        self.api_node_identity.metadata.syncnets = syncnets_bytes;
        self.api_node_identity.metadata.seq_number +%= 1;
        if (self.api_node_identity.metadata.seq_number == 0) {
            self.api_node_identity.metadata.seq_number = 1;
        }

        if (self.discovery_service) |ds| {
            ds.updateSubnets(attnets_bytes, syncnets_bytes) catch |err| {
                std.log.warn("Failed to update local ENR subnet bitfields: {}", .{err});
            };
            refreshApiNodeIdentityFromDiscovery(self, ds) catch |err| {
                std.log.warn("Failed to refresh API node identity after subnet update: {}", .{err});
            };
        }
        did_work = true;
    }

    return did_work;
}

fn runPeerManagerHeartbeat(self: *BeaconNode, io: std.Io, svc: *networking.P2pService) bool {
    const pm = self.peer_manager orelse return false;
    const now_ms = currentUnixTimeMs(io);

    if (self.subnet_service) |subnet_service| {
        var did_work = false;
        var housekeeping = pm.housekeeping(now_ms) catch |err| {
            std.log.warn("PeerManager housekeeping failed: {}", .{err});
            return false;
        };
        defer housekeeping.deinit(self.allocator);

        const active_attnets = getDesiredActiveAttestationSubnets(self, subnet_service) catch |err| {
            std.log.warn("Failed to read active attestation subnets for prioritization: {}", .{err});
            return false;
        };
        defer if (active_attnets.len > 0) self.allocator.free(active_attnets);

        const active_syncnets = subnet_service.getActiveSyncSubnets() catch |err| {
            std.log.warn("Failed to read active sync subnets for prioritization: {}", .{err});
            return false;
        };
        defer if (active_syncnets.len > 0) self.allocator.free(active_syncnets);

        var prioritization = pm.runPrioritization(active_attnets, active_syncnets) catch |err| {
            std.log.warn("PeerManager prioritization failed: {}", .{err});
            return false;
        };
        defer prioritization.deinit(self.allocator);

        if (self.discovery_service) |ds| {
            for (prioritization.subnets_needing_peers) |query| {
                ds.requestSubnetPeers(switch (query.kind) {
                    .attestation => .attestation,
                    .sync_committee => .sync_committee,
                }, @intCast(query.subnet_id), @max(query.peers_needed, 1));
                did_work = true;
            }
            for (prioritization.custody_columns_needing_peers) |query| {
                ds.requestCustodyColumnPeers(query.column_index, @max(query.peers_needed, 1));
                did_work = true;
            }
            if (prioritization.peers_to_discover > 0) {
                ds.requestMorePeers(prioritization.peers_to_discover);
                did_work = true;
            }
            ds.discoverPeers();
            did_work = true;
        }

        for (housekeeping.peers_to_disconnect) |peer_id| {
            sendGoodbyeAndDisconnect(self, io, svc, peer_id, heartbeatDisconnectReason(pm.getPeer(peer_id)));
            did_work = true;
        }
        for (prioritization.peers_to_disconnect) |disconnect| {
            if (containsPeerId(housekeeping.peers_to_disconnect, disconnect.peer_id)) continue;
            sendGoodbyeAndDisconnect(self, io, svc, disconnect.peer_id, heartbeatDisconnectReason(pm.getPeer(disconnect.peer_id)));
            did_work = true;
        }

        return did_work;
    }

    var did_work = false;
    svc.syncGossipsubScores(pm, now_ms) catch |err| {
        std.log.warn("Failed to mirror gossipsub scores into peer manager: {}", .{err});
    };
    if (self.req_resp_rate_limiter) |limiter| {
        limiter.pruneInactive(std.Io.Clock.awake.now(io).nanoseconds, networking.rate_limiter.INACTIVE_PEER_TIMEOUT_NS);
    }
    svc.pruneReqRespSelfLimiter(io);

    var actions = pm.heartbeat(now_ms) catch |err| {
        std.log.warn("PeerManager heartbeat failed: {}", .{err});
        return false;
    };
    defer actions.deinit(self.allocator);

    if (self.discovery_service) |ds| {
        for (actions.subnets_needing_peers) |subnet_id| {
            ds.requestSubnetPeers(.attestation, @intCast(subnet_id), 1);
            did_work = true;
        }
        if (actions.peers_to_discover > 0) {
            ds.requestMorePeers(actions.peers_to_discover);
            did_work = true;
        }
        ds.discoverPeers();
        did_work = true;
    }

    for (actions.peers_to_disconnect) |peer_id| {
        sendGoodbyeAndDisconnect(self, io, svc, peer_id, heartbeatDisconnectReason(pm.getPeer(peer_id)));
        did_work = true;
    }

    return did_work;
}

fn runPeerManagerMaintenance(self: *BeaconNode, io: std.Io, svc: *networking.P2pService) bool {
    const pm = self.peer_manager orelse return false;

    const now_ms = currentUnixTimeMs(io);
    var actions = pm.maintenance(now_ms, .{}) catch |err| {
        std.log.warn("PeerManager maintenance selection failed: {}", .{err});
        return false;
    };
    defer actions.deinit(self.allocator);

    var did_work = false;

    for (actions.peers_to_restatus) |peer_id| {
        const peer_status = sendStatus(self, io, svc, peer_id) catch |err| {
            handleReqRespMaintenanceFailure(self, io, svc, peer_id, .status, err);
            did_work = true;
            continue;
        };

        if (reqresp_callbacks_mod.handlePeerStatus(self, peer_id, peer_status.status, peer_status.earliest_available_slot)) |_| {
            sendGoodbyeAndDisconnect(self, io, svc, peer_id, .irrelevant_network);
            did_work = true;
            continue;
        }

        did_work = true;
    }

    for (actions.peers_to_ping) |peer_id| {
        const remote_seq = requestPeerPing(self, io, svc, peer_id) catch |err| {
            handleReqRespMaintenanceFailure(self, io, svc, peer_id, .ping, err);
            did_work = true;
            continue;
        };

        pm.markPingResponse(peer_id, currentUnixTimeMs(io));
        did_work = true;

        const peer = pm.getPeer(peer_id) orelse continue;
        if (remote_seq == peer.metadata_seq) continue;

        const metadata = requestPeerMetadata(self, io, svc, peer_id) catch |err| {
            handleReqRespMaintenanceFailure(self, io, svc, peer_id, .metadata, err);
            continue;
        };
        applyPeerMetadata(self, peer_id, metadata, currentUnixTimeMs(io));
    }

    return did_work;
}

fn runRealtimeP2pTick(self: *BeaconNode, io: std.Io, svc: *networking.P2pService) bool {
    var did_work = false;

    did_work = gossip_ingress_mod.processEvents(self, io, svc) > 0 or did_work;
    did_work = self.processPendingExecutionForkchoiceUpdates() or did_work;
    did_work = self.processPendingExecutionPayloadVerifications() or did_work;
    did_work = self.processPendingBlockStateWork() or did_work;
    did_work = self.processPendingGossipBlsBatch() or did_work;

    if (self.beacon_processor) |bp| {
        const dispatched = bp.tick(128);
        did_work = dispatched > 0 or did_work;
        if (dispatched > 0) {
            std.log.debug("Processor: dispatched {d} items ({d} queued)", .{
                dispatched,
                bp.totalQueued(),
            });
        }
        if (!did_work) {
            did_work = bp.totalQueued() > 0;
        }
    }

    if (self.sync_service_inst) |sync_svc| {
        sync_svc.tick() catch |err| {
            std.log.warn("SyncService.tick failed: {}", .{err});
        };
    }
    did_work = self.drivePendingSyncSegments() or did_work;

    maybeHandleForkTransition(self, svc);

    processSyncBatches(self, io, svc);
    processSyncByRootRequests(self, io, svc);
    updateSyncMetrics(self);
    maybePrepareProposerPayload(self, io);
    pruneSyncCommitteePools(self);
    advanceChainClock(self, io);

    return did_work;
}

fn runLoop(self: *BeaconNode, io: std.Io, svc: *networking.P2pService) void {
    std.log.info("Starting P2P runtime loop...", .{});
    const start_ns = std.Io.Timestamp.now(io, .awake).toNanoseconds();
    var next_connectivity_maintenance_ns = start_ns;
    var next_discovery_maintenance_ns = start_ns;
    var next_peer_maintenance_ns = start_ns;
    var next_peer_manager_heartbeat_ns = start_ns;
    while (!self.shutdown_requested.load(.acquire)) {
        const now_ns = std.Io.Timestamp.now(io, .awake).toNanoseconds();
        var did_work = false;

        if (now_ns >= next_connectivity_maintenance_ns) {
            did_work = runConnectivityMaintenance(self, io, svc) or did_work;
            next_connectivity_maintenance_ns = now_ns + connectivity_maintenance_interval_ns;
        }
        if (now_ns >= next_discovery_maintenance_ns) {
            did_work = runDiscoveryMaintenance(self) or did_work;
            next_discovery_maintenance_ns = now_ns + discovery_maintenance_interval_ns;
        }
        if (now_ns >= next_peer_maintenance_ns) {
            did_work = runPeerManagerMaintenance(self, io, svc) or did_work;
            next_peer_maintenance_ns = now_ns + peer_maintenance_interval_ns;
        }
        if (now_ns >= next_peer_manager_heartbeat_ns) {
            did_work = runPeerManagerHeartbeat(self, io, svc) or did_work;
            next_peer_manager_heartbeat_ns = now_ns + peer_manager_heartbeat_interval_ns;
        }

        did_work = runRealtimeP2pTick(self, io, svc) or did_work;

        const sleep_timeout: std.Io.Timeout = .{ .duration = .{
            .raw = std.Io.Duration.fromNanoseconds(@intCast(if (did_work) active_p2p_tick_ns else idle_p2p_tick_ns)),
            .clock = .awake,
        } };
        sleep_timeout.sleep(io) catch break;
    }
}

fn maybeHandleForkTransition(self: *BeaconNode, svc: *networking.P2pService) void {
    const head_slot = self.currentHeadSlot();
    const current_fork_seq = self.config.forkSeq(head_slot);
    const current_digest = self.config.forkDigestAtSlot(
        head_slot,
        self.genesis_validators_root,
    );
    if (std.mem.eql(u8, &current_digest, &self.last_active_fork_digest)) return;

    if (!std.mem.eql(u8, &self.last_active_fork_digest, &[4]u8{ 0, 0, 0, 0 })) {
        const last_digest_hex = std.fmt.bytesToHex(&self.last_active_fork_digest, .lower);
        const current_digest_hex = std.fmt.bytesToHex(&current_digest, .lower);
        std.log.info("Fork transition detected at slot {d}: {s} -> {s}", .{
            head_slot,
            &last_digest_hex,
            &current_digest_hex,
        });
        _ = syncGossipForkState(self, svc);
        if (self.gossip_handler) |gh| {
            gh.updateForkSeq(current_fork_seq);
        }
    }
    self.last_active_fork_digest = current_digest;
}

fn updateSyncMetrics(self: *BeaconNode) void {
    if (self.metrics) |metrics| {
        if (self.sync_service_inst) |sync_svc| {
            const status = sync_svc.getSyncStatus();
            metrics.sync_status.set(if (sync_svc.isSynced()) @as(u64, 0) else @as(u64, 1));
            metrics.sync_distance.set(status.sync_distance);
        }
    }
}

fn pruneSyncCommitteePools(self: *BeaconNode) void {
    const head_slot = self.currentHeadSlot();
    self.chainService().pruneSyncCommitteePools(head_slot);
}

fn advanceChainClock(self: *BeaconNode, io: std.Io) void {
    const clock = self.clock orelse return;
    const current_slot = clock.currentSlot(io) orelse return;

    if (self.last_slot_tick) |last_slot| {
        if (current_slot <= last_slot) return;
    }

    self.chainService().onSlot(current_slot);
    self.last_slot_tick = current_slot;

    self.queueCurrentOptimisticHeadRevalidation();
}

fn dialBootnodeEnr(self: *BeaconNode, io: std.Io, svc: *networking.P2pService, enr_str: []const u8) !void {
    var s: []const u8 = enr_str;
    if (std.mem.startsWith(u8, s, "enr:")) s = s[4..];

    const decoded_len = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(s) catch |err| {
        std.log.err("ENR base64 calcSize failed: {} for input[0..@min(s.len,20)]={s}", .{ err, s[0..@min(s.len, 20)] });
        return error.InvalidEnr;
    };
    const raw = try self.allocator.alloc(u8, decoded_len);
    defer self.allocator.free(raw);
    std.base64.url_safe_no_pad.Decoder.decode(raw, s) catch |err| {
        std.log.err("ENR base64 decode failed: {}", .{err});
        return error.InvalidEnr;
    };

    var enr = try discv5.enr.decode(self.allocator, raw);
    defer enr.deinit();

    const dial_addr = preferredBootnodeDialAddress(self, &enr) orelse return error.NoDialableAddressInEnr;

    var ma_buf: [160]u8 = undefined;
    const ma_str = try formatDiscv5DialMultiaddr(&ma_buf, dial_addr);

    std.log.info("Dialing bootnode at {s}", .{ma_str});

    const peer_addr = try Multiaddr.fromString(self.allocator, ma_str);
    defer peer_addr.deinit();

    const peer_id = svc.dial(io, peer_addr) catch |err| {
        std.log.warn("Bootnode dial failed: {}", .{err});
        return err;
    };
    std.log.info("Connected to bootnode, peer_id: {s}", .{peer_id});
    _ = registerConnectedPeer(
        self,
        io,
        svc,
        peer_id,
        .outbound,
        if (enr.pubkey) |pubkey|
            .{ .node_id = discv5.enr.nodeIdFromCompressedPubkey(&pubkey), .pubkey = pubkey }
        else
            null,
    );
}

fn initDiscoveryService(self: *BeaconNode) !void {
    const fork_digest = self.config.forkDigestAtSlot(
        self.currentHeadSlot(),
        self.genesis_validators_root,
    );

    const ds = try self.allocator.create(DiscoveryService);
    errdefer self.allocator.destroy(ds);
    // QUIC transport binds p2p_port on UDP, so discv5 must use a separate port
    // to avoid AddressInUse. Default to p2p_port + 1 when not explicitly set.
    const disc_port = self.node_options.discovery_port orelse self.node_options.p2p_port + 1;
    const disc_port6 = self.node_options.discovery_port6 orelse if (self.node_options.p2p_port6) |p6| p6 + 1 else null;
    const local_ip = if (self.node_options.p2p_host) |host|
        parseIp4(host) orelse return error.InvalidListenAddress
    else
        null;
    const local_ip6 = if (self.node_options.p2p_host6) |host|
        parseIp6(host) orelse return error.InvalidListenAddress
    else
        null;
    const enr_ip = if (self.node_options.enr_ip) |raw|
        parseIp4(raw) orelse return error.InvalidEnrAddress
    else
        null;
    const enr_ip6 = if (self.node_options.enr_ip6) |raw|
        parseIp6(raw) orelse return error.InvalidEnrAddress
    else
        null;

    ds.* = try DiscoveryService.init(self.io, self.allocator, .{
        .listen_port = disc_port,
        .listen_port6 = disc_port6,
        .secret_key = self.node_identity.secret_key,
        .local_ip = local_ip,
        .local_ip6 = local_ip6,
        .enr_ip = enr_ip,
        .enr_ip6 = enr_ip6,
        .enr_udp = self.node_options.enr_udp,
        .enr_udp6 = self.node_options.enr_udp6,
        .p2p_port = self.node_options.p2p_port,
        .p2p_port6 = self.node_options.p2p_port6,
        .custody_group_count = @intCast(self.chain_runtime.custody_columns.len),
        .default_custody_group_count = self.config.chain.CUSTODY_REQUIREMENT,
        .fork_digest = fork_digest,
        .target_peers = self.node_options.target_peers,
        .bootnodes = self.discovery_bootnodes,
    });

    ds.seedBootnodes();
    self.discovery_service = ds;
    try refreshApiNodeIdentityFromDiscovery(self, ds);

    std.log.info("Discovery service initialized (known_peers={d})", .{ds.knownPeerCount()});
}

fn refreshApiNodeIdentityFromDiscovery(self: *BeaconNode, ds: *DiscoveryService) !void {
    const raw_enr = ds.service.localEnr() orelse return;
    self.api_node_identity.metadata.seq_number = ds.service.localEnrSeq();
    const enr_buf = ds.buildLocalEnrString() catch |err| switch (err) {
        error.NoLocalEnr => return,
        else => return err,
    };
    errdefer self.allocator.free(enr_buf);

    if (self.api_node_identity.enr.len > 0) {
        self.allocator.free(self.api_node_identity.enr);
    }
    self.api_node_identity.enr = enr_buf;

    var parsed = try discv5.enr.decode(self.allocator, raw_enr);
    defer parsed.deinit();
    self.api_node_identity.metadata.attnets = parsed.attnets orelse [_]u8{0} ** 8;
    self.api_node_identity.metadata.syncnets = parsed.syncnets orelse [_]u8{0} ** 1;

    try refreshApiDiscoveryAddressesFromEnr(self, raw_enr);
}

fn refreshApiDiscoveryAddressesFromEnr(self: *BeaconNode, raw_enr: []const u8) !void {
    var parsed = try discv5.enr.decode(self.allocator, raw_enr);
    defer parsed.deinit();

    var addresses: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (addresses.items) |address| self.allocator.free(address);
        addresses.deinit(self.allocator);
    }

    if (parsed.ip) |ip4| {
        if (parsed.udp) |port| {
            try addresses.append(self.allocator, try std.fmt.allocPrint(
                self.allocator,
                "/ip4/{d}.{d}.{d}.{d}/udp/{d}/p2p/{s}",
                .{ ip4[0], ip4[1], ip4[2], ip4[3], port, self.api_node_identity.peer_id },
            ));
        }
    }
    if (parsed.ip6) |ip6| {
        if (parsed.udp6) |port| {
            try addresses.append(self.allocator, try std.fmt.allocPrint(
                self.allocator,
                "/ip6/{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}/udp/{d}/p2p/{s}",
                .{
                    ip6[0],  ip6[1],                         ip6[2],  ip6[3],
                    ip6[4],  ip6[5],                         ip6[6],  ip6[7],
                    ip6[8],  ip6[9],                         ip6[10], ip6[11],
                    ip6[12], ip6[13],                        ip6[14], ip6[15],
                    port,    self.api_node_identity.peer_id,
                },
            ));
        }
    }

    for (self.api_node_identity.discovery_addresses) |address| self.allocator.free(address);
    if (self.api_node_identity.discovery_addresses.len > 0) {
        self.allocator.free(self.api_node_identity.discovery_addresses);
    }
    self.api_node_identity.discovery_addresses = try addresses.toOwnedSlice(self.allocator);
}

fn preferredBootnodeDialAddress(self: *BeaconNode, enr: *const discv5.enr.Enr) ?discv5.Address {
    const addr_ip4 = if (enr.ip) |ip4|
        if (enr.quic) |port|
            discv5.Address{ .ip4 = .{ .bytes = ip4, .port = port } }
        else
            null
    else
        null;
    const addr_ip6 = if (enr.ip6) |ip6|
        if (enr.quic6) |port|
            discv5.Address{ .ip6 = .{ .bytes = ip6, .port = port } }
        else
            null
    else
        null;

    const wants_ip6 = self.node_options.p2p_host == null and self.node_options.p2p_host6 != null;
    if (wants_ip6) return addr_ip6 orelse addr_ip4;
    if (self.node_options.p2p_host != null and self.node_options.p2p_host6 == null) return addr_ip4 orelse addr_ip6;
    return addr_ip4 orelse addr_ip6;
}

fn preferredDiscoveredDialAddress(self: *BeaconNode, peer: *const networking.DiscoveredPeer) ?discv5.Address {
    const wants_ip6 = self.node_options.p2p_host == null and self.node_options.p2p_host6 != null;
    if (wants_ip6) return peer.addr_ip6 orelse peer.addr_ip4;
    if (self.node_options.p2p_host != null and self.node_options.p2p_host6 == null) return peer.addr_ip4 orelse peer.addr_ip6;
    return peer.addr_ip4 orelse peer.addr_ip6;
}

fn discoveryDialBudget(self: *BeaconNode) u32 {
    const pm = self.peer_manager orelse return max_discovery_dials_per_tick;
    const occupied_peers = pm.peerCount() + pm.dialingPeerCount();
    if (occupied_peers >= pm.config.max_peers) return 0;
    return @min(max_discovery_dials_per_tick, pm.config.max_peers - occupied_peers);
}

fn dialDiscoveredPeers(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    ds: *DiscoveryService,
) bool {
    const dial_budget = discoveryDialBudget(self);
    if (dial_budget == 0) return false;

    const discovered_peers = ds.takeDiscoveredPeers(dial_budget);
    defer if (discovered_peers.len > 0) self.allocator.free(discovered_peers);

    var did_work = false;
    const pm = self.peer_manager;
    const now_ms = currentUnixTimeMs(io);
    for (discovered_peers) |peer| {
        if (!peer.has_quic) continue;
        const dial_addr = preferredDiscoveredDialAddress(self, &peer) orelse continue;

        var predicted_peer_id: ?[]u8 = null;
        defer if (predicted_peer_id) |peer_id| self.allocator.free(peer_id);

        if (discoveryIdentityKnown(.{ .node_id = peer.node_id, .pubkey = peer.pubkey })) {
            predicted_peer_id = discoveryPeerIdTextFromPubkey(self.allocator, peer.pubkey) catch |err| {
                std.log.warn("Failed to derive peer ID from discovered ENR: {}", .{err});
                continue;
            };

            const peer_id = predicted_peer_id.?;
            if (svc.isPeerConnected(peer_id)) continue;

            if (pm) |peer_manager| {
                if (peer_manager.getPeer(peer_id)) |existing| {
                    switch (existing.connection_state) {
                        .banned, .dialing, .connected, .disconnecting => continue,
                        .disconnected => {},
                    }
                }
            }
        }

        var ma_buf: [160]u8 = undefined;
        const ma_str = formatDiscv5DialMultiaddr(&ma_buf, dial_addr) catch continue;
        const peer_addr = Multiaddr.fromString(self.allocator, ma_str) catch continue;
        defer peer_addr.deinit();

        if (pm) |peer_manager| {
            if (predicted_peer_id) |known_peer_id| {
                peer_manager.onDialing(known_peer_id, now_ms) catch |err| {
                    std.log.warn("Failed to mark discovered peer {s} as dialing: {}", .{ known_peer_id, err });
                    continue;
                };
            }
        }

        const peer_id = svc.dial(io, peer_addr) catch |err| {
            if (pm) |peer_manager| {
                if (predicted_peer_id) |known_peer_id| {
                    notePeerDisconnected(self, peer_manager, known_peer_id, now_ms);
                }
            }
            std.log.debug("Discovered peer dial failed: {}", .{err});
            continue;
        };

        if (pm) |peer_manager| {
            if (predicted_peer_id) |known_peer_id| {
                if (!std.mem.eql(u8, known_peer_id, peer_id)) {
                    notePeerDisconnected(self, peer_manager, known_peer_id, now_ms);
                }
            }
        }

        std.log.info("Connected to discovered peer {s} via {s}", .{ peer_id, ma_str });
        did_work = registerConnectedPeer(
            self,
            io,
            svc,
            peer_id,
            .outbound,
            .{ .node_id = peer.node_id, .pubkey = peer.pubkey },
        ) or did_work;
    }

    return did_work;
}

fn reconcilePeerConnections(self: *BeaconNode, io: std.Io, svc: *networking.P2pService) bool {
    const pm = self.peer_manager orelse return false;

    const connected_peer_ids = svc.snapshotConnectedPeerIds(self.allocator) catch |err| {
        std.log.warn("Failed to snapshot connected peers: {}", .{err});
        return false;
    };
    defer freeOwnedPeerIds(self.allocator, connected_peer_ids);

    var did_work = false;
    for (connected_peer_ids) |peer_id| {
        const maybe_peer = pm.getPeer(peer_id);
        if (maybe_peer) |peer| {
            switch (peer.connection_state) {
                .banned => {
                    sendGoodbyeAndDisconnect(self, io, svc, peer_id, .banned);
                    did_work = true;
                    continue;
                },
                .disconnecting => continue,
                .connected => {
                    if (peer.relevance == .irrelevant) {
                        sendGoodbyeAndDisconnect(self, io, svc, peer_id, .irrelevant_network);
                        did_work = true;
                        continue;
                    }
                    did_work = maybeRecordPeerIdentity(self, svc, peer_id) or did_work;
                    continue;
                },
                .dialing => {},
                .disconnected => {
                    if (peer.relevance == .irrelevant) {
                        sendGoodbyeAndDisconnect(self, io, svc, peer_id, .irrelevant_network);
                        did_work = true;
                        continue;
                    }
                },
            }
        }

        const direction = if (maybe_peer) |peer|
            peer.direction orelse .inbound
        else
            .inbound;
        did_work = registerConnectedPeer(self, io, svc, peer_id, direction, null) or did_work;
    }

    const managed_peer_ids = pm.getConnectedPeerIds() catch |err| {
        std.log.warn("Failed to snapshot peer-manager peers: {}", .{err});
        return did_work;
    };
    defer freeOwnedPeerIds(self.allocator, managed_peer_ids);

    const now_ms = currentUnixTimeMs(io);
    for (managed_peer_ids) |peer_id| {
        if (containsPeerId(connected_peer_ids, peer_id)) continue;
        notePeerDisconnected(self, pm, peer_id, now_ms);
        if (self.metrics) |metrics| metrics.peer_disconnected_total.incr();
        did_work = true;
    }

    return did_work;
}

fn registerConnectedPeer(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
    direction: ConnectionDirection,
    discovery_identity: ?DiscoveryPeerIdentity,
) bool {
    const pm = self.peer_manager orelse return maybeRecordPeerIdentity(self, svc, peer_id);
    const now_ms = currentUnixTimeMs(io);
    const existing = pm.getPeer(peer_id);
    const was_connected = if (existing) |peer| peer.isConnected() else false;

    if (discovery_identity) |identity| {
        if (discoveryIdentityKnown(identity)) {
            const matches = discoveryPeerIdMatches(self.allocator, peer_id, identity.pubkey) catch true;
            if (!matches) {
                std.log.warn("Discovered ENR identity did not match connected peer {s}; dropping connection", .{peer_id});
                _ = svc.disconnectPeer(io, peer_id);
                return true;
            }
        }
    }

    if (existing) |peer| {
        if (peer.connection_state == .banned) {
            sendGoodbyeAndDisconnect(self, io, svc, peer_id, .banned);
            return true;
        }
        if (peer.connection_state == .disconnecting) {
            return false;
        }
    }

    const connect_direction = if (existing) |peer| peer.direction orelse direction else direction;
    const connected = pm.onPeerConnected(peer_id, connect_direction, now_ms) catch |err| {
        std.log.warn("Failed to register connected peer {s}: {}", .{ peer_id, err });
        return false;
    };
    if (connected == null) {
        sendGoodbyeAndDisconnect(self, io, svc, peer_id, .banned);
        return true;
    }

    if (discovery_identity) |identity| {
        pm.updatePeerDiscoveryNodeId(peer_id, identity.node_id) catch |err| {
            std.log.warn("Failed to record discovery node ID for peer {s}: {}", .{ peer_id, err });
        };
    }

    var did_work = !was_connected;
    if (!was_connected) {
        if (self.metrics) |metrics| metrics.peer_connected_total.incr();
        did_work = completePeerHandshake(self, io, svc, peer_id) or did_work;
    }

    did_work = maybeRecordPeerIdentity(self, svc, peer_id) or did_work;
    return did_work;
}

fn completePeerHandshake(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
) bool {
    const peer_status = sendStatus(self, io, svc, peer_id) catch |err| {
        handleReqRespMaintenanceFailure(self, io, svc, peer_id, .status, err);
        return true;
    };

    if (reqresp_callbacks_mod.handlePeerStatus(self, peer_id, peer_status.status, peer_status.earliest_available_slot)) |_| {
        sendGoodbyeAndDisconnect(self, io, svc, peer_id, .irrelevant_network);
        return true;
    }

    const metadata = requestPeerMetadata(self, io, svc, peer_id) catch |err| {
        handleReqRespMaintenanceFailure(self, io, svc, peer_id, .metadata, err);
        return true;
    };
    applyPeerMetadata(self, peer_id, metadata, currentUnixTimeMs(io));

    svc.openGossipsubStream(io, peer_id) catch |err| {
        std.log.warn("Failed to open outbound gossipsub stream to {s}: {}", .{ peer_id, err });
    };
    return true;
}

fn maybeRecordPeerIdentity(
    self: *BeaconNode,
    svc: *networking.P2pService,
    peer_id: []const u8,
) bool {
    const pm = self.peer_manager orelse return false;
    const peer = pm.getPeer(peer_id) orelse return false;
    if (peer.agent_version != null) return false;

    const identify_result = svc.identifyResult(peer_id) orelse return false;
    pm.updateAgentVersion(peer_id, identify_result.agentVersion()) catch |err| {
        std.log.warn("Failed to record identify result for peer {s}: {}", .{ peer_id, err });
        return false;
    };
    return true;
}

fn applyPeerMetadata(self: *BeaconNode, peer_id: []const u8, metadata: PeerMetadataResponse, now_ms: u64) void {
    const pm = self.peer_manager orelse return;
    pm.updatePeerMetadata(
        peer_id,
        metadata.metadata.seq_number,
        attnetsFromMetadata(metadata.metadata.attnets.data),
        syncnetsFromMetadata(metadata.metadata.syncnets.data),
        metadata.custody_group_count,
    ) catch |err| {
        std.log.warn("Failed to update metadata for peer {s}: {}", .{ peer_id, err });
        return;
    };
    pm.notePeerSeen(peer_id, now_ms);
}

fn sendGoodbyeAndDisconnect(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
    reason: GoodbyeReason,
) void {
    if (self.peer_manager) |pm| pm.onPeerDisconnecting(peer_id);
    sendGoodbye(self, io, svc, peer_id, reason) catch |err| {
        std.log.debug("Goodbye send failed for peer {s}: {}", .{ peer_id, err });
    };
    _ = svc.disconnectPeer(io, peer_id);
}

fn heartbeatDisconnectReason(maybe_peer: ?*const networking.PeerInfo) GoodbyeReason {
    const peer = maybe_peer orelse return .too_many_peers;
    return switch (peer.scoreState()) {
        .healthy => .too_many_peers,
        .disconnected, .banned => .score_too_low,
    };
}

fn notePeerDisconnected(_: *BeaconNode, pm: *PeerManager, peer_id: []const u8, now_ms: u64) void {
    pm.onPeerDisconnected(peer_id, now_ms);
}

fn containsPeerId(peer_ids: []const []const u8, needle: []const u8) bool {
    for (peer_ids) |peer_id| {
        if (std.mem.eql(u8, peer_id, needle)) return true;
    }
    return false;
}

fn freeOwnedPeerIds(allocator: std.mem.Allocator, peer_ids: []const []const u8) void {
    for (peer_ids) |peer_id| allocator.free(peer_id);
    allocator.free(peer_ids);
}

fn initPeerManager(self: *BeaconNode) !void {
    const pm = try self.allocator.create(PeerManager);
    errdefer self.allocator.destroy(pm);
    pm.* = PeerManager.init(self.allocator, .{
        .target_peers = self.node_options.target_peers,
        .target_group_peers = self.node_options.target_group_peers,
        .local_custody_columns = self.chain_runtime.custody_columns,
    });
    self.peer_manager = pm;
    std.log.info("Peer manager initialized (target_peers={d} target_group_peers={d})", .{
        pm.config.target_peers,
        pm.config.target_group_peers,
    });
}

fn initSyncPipeline(self: *BeaconNode) !void {
    const cb_ctx = try self.allocator.create(SyncCallbackCtx);
    cb_ctx.* = .{ .node = self };
    self.sync_callback_ctx = cb_ctx;

    const sync_svc = try self.allocator.create(SyncService);
    sync_svc.* = SyncService.init(
        self.allocator,
        cb_ctx.syncServiceCallbacks(),
        self.currentHeadSlot(),
        self.getHead().finalized_epoch,
    );
    sync_svc.is_single_node = self.node_options.sync_is_single_node;
    if (sync_svc.is_single_node) {
        // Trigger mode recalculation so the service starts in .synced mode.
        sync_svc.onHeadUpdate(self.currentHeadSlot());
    }
    self.sync_service_inst = sync_svc;

    std.log.info("Sync pipeline initialized (head_slot={d})", .{self.currentHeadSlot()});
}

fn ensureRangeSyncDataAvailability(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
    blocks: []const BatchBlock,
) !void {
    const metas = try buildSyncBlockMetas(self, blocks);
    defer deinitSyncBlockMetas(self, metas);

    fetchBlobSidecarsByRangeForMetas(self, io, svc, peer_id, metas) catch |err| {
        reportReqRespFetchFailure(self, io, peer_id, .blob_sidecars_by_range, err);
        return err;
    };
    fetchDataColumnsByRangeForMetas(self, io, svc, peer_id, metas) catch |err| {
        reportReqRespFetchFailure(self, io, peer_id, .data_column_sidecars_by_range, err);
        return err;
    };
}

fn ensureByRootDataAvailability(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
    block_bytes: []const u8,
) !void {
    var meta = try buildSyncBlockMeta(self, block_bytes, null);
    defer deinitSyncBlockMeta(self, &meta);

    switch (meta.block_data_plan) {
        .none => return,
        .blobs => |missing| {
            if (missing.len == 0) return;
            fetchBlobSidecarsByRootForMeta(self, io, svc, peer_id, meta, missing) catch |err| {
                reportReqRespFetchFailure(self, io, peer_id, .blob_sidecars_by_root, err);
                return err;
            };
        },
        .columns => |missing| {
            if (missing.len == 0) return;
            fetchDataColumnsByRootForMeta(self, io, svc, peer_id, meta) catch |err| {
                reportReqRespFetchFailure(self, io, peer_id, .data_column_sidecars_by_root, err);
                return err;
            };
        },
    }
}

fn buildSyncBlockMetas(self: *BeaconNode, blocks: []const BatchBlock) ![]SyncBlockMeta {
    const metas = try self.allocator.alloc(SyncBlockMeta, blocks.len);
    errdefer self.allocator.free(metas);

    var built: usize = 0;
    errdefer {
        for (metas[0..built]) |*meta| {
            deinitSyncBlockMeta(self, meta);
        }
    }

    for (blocks, 0..) |block, i| {
        metas[i] = try buildSyncBlockMeta(self, block.block_bytes, block.slot);
        built = i + 1;
    }

    return metas;
}

fn buildSyncBlockMeta(
    self: *BeaconNode,
    block_bytes: []const u8,
    slot_hint: ?u64,
) !SyncBlockMeta {
    return self.chainService().planRawBlockIngress(block_bytes, slot_hint);
}

fn deinitSyncBlockMetas(self: *BeaconNode, metas: []SyncBlockMeta) void {
    for (metas) |*meta| deinitSyncBlockMeta(self, meta);
    self.allocator.free(metas);
}

fn deinitSyncBlockMeta(self: *BeaconNode, meta: *SyncBlockMeta) void {
    meta.deinit(self.allocator);
}

fn fetchBlobSidecarsByRangeForMetas(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
    metas: []const SyncBlockMeta,
) !void {
    var start_slot: u64 = std.math.maxInt(u64);
    var end_slot: u64 = 0;
    var have_pending = false;

    var states = try self.allocator.alloc(?BlobFetchState, metas.len);
    defer {
        for (states) |*maybe_state| {
            if (maybe_state.*) |*state| state.deinit(self.allocator);
        }
        self.allocator.free(states);
    }
    @memset(states, null);

    for (metas, 0..) |meta, i| {
        if (!needsBlobFetch(meta)) continue;
        have_pending = true;
        start_slot = @min(start_slot, meta.slot);
        end_slot = @max(end_slot, meta.slot);

        const blob_commitments = try meta.any_signed.beaconBlock().beaconBlockBody().blobKzgCommitments();
        const existing = try self.chainQuery().blobSidecarsByRoot(meta.block_root);
        states[i] = try BlobFetchState.init(self.allocator, blob_commitments.items.len, existing);
    }

    if (!have_pending) return;

    const protocol_id = "/eth2/beacon_chain/req/blob_sidecars_by_range/1/ssz_snappy";
    const req_resp_encoding = networking.req_resp_encoding;

    var outbound = try openReqRespRequest(io, svc, peer_id, .blob_sidecars_by_range, protocol_id);
    defer outbound.deinit(io);

    const request = networking.messages.BlobSidecarsByRangeRequest.Type{
        .start_slot = start_slot,
        .count = end_slot - start_slot + 1,
    };
    var req_ssz: [networking.messages.BlobSidecarsByRangeRequest.fixed_size]u8 = undefined;
    _ = networking.messages.BlobSidecarsByRangeRequest.serializeIntoBytes(&request, &req_ssz);
    try req_resp_encoding.writeRequestToStream(self.allocator, io, &outbound.stream, &req_ssz);
    outbound.stream.closeWrite(io);

    var reader = req_resp_encoding.ResponseChunkStreamReader{
        .allocator = self.allocator,
        .has_context_bytes = true,
    };
    defer reader.deinit();

    while (try reader.next(io, &outbound.stream)) |decoded| {
        if (decoded.result != .success) {
            self.allocator.free(decoded.ssz_bytes);
            return responseCodeError(decoded.result);
        }
        errdefer self.allocator.free(decoded.ssz_bytes);

        var sidecar: BlobSidecar.Type = undefined;
        BlobSidecar.deserializeFromBytes(decoded.ssz_bytes, &sidecar) catch return error.MalformedBlobSidecar;

        const slot = sidecar.signed_block_header.message.slot;
        const context_bytes = decoded.context_bytes orelse return error.MissingContextBytes;
        const expected_digest = self.config.forkDigestAtSlot(slot, self.genesis_validators_root);
        if (!std.mem.eql(u8, &context_bytes, &expected_digest)) return error.ForkDigestMismatch;

        var block_root: [32]u8 = undefined;
        try types.phase0.BeaconBlockHeader.hashTreeRoot(&sidecar.signed_block_header.message, &block_root);

        const meta_index = findMetaIndexByRoot(metas, block_root) orelse return error.UnexpectedBlobSidecar;
        const meta = metas[meta_index];
        if (!needsBlobFetch(meta)) {
            self.allocator.free(decoded.ssz_bytes);
            continue;
        }

        const blob_commitments = try meta.any_signed.beaconBlock().beaconBlockBody().blobKzgCommitments();
        if (slot != meta.slot) return error.UnexpectedBlobSlot;
        if (sidecar.index >= blob_commitments.items.len) return error.InvalidBlobIndex;
        if (!std.mem.eql(u8, &blob_commitments.items[sidecar.index], &sidecar.kzg_commitment)) {
            return error.KzgCommitmentMismatch;
        }

        const blob_ptr: *const [BYTES_PER_BLOB]u8 = @ptrCast(&sidecar.blob);
        try self.chainService().verifyBlobSidecar(.{
            .blob = blob_ptr,
            .commitment = sidecar.kzg_commitment,
            .proof = sidecar.kzg_proof,
        });

        var state = &states[meta_index].?;
        if (state.sidecars[sidecar.index] != null) {
            self.allocator.free(decoded.ssz_bytes);
            continue;
        }
        try state.setFetched(self.allocator, sidecar.index, decoded.ssz_bytes);
    }

    for (metas, 0..) |meta, i| {
        if (!needsBlobFetch(meta)) continue;
        var state = &states[i].?;
        const aggregate = try state.aggregate(self.allocator);
        defer self.allocator.free(aggregate);

        const blob_indices = try self.allocator.alloc(u64, state.sidecars.len);
        defer self.allocator.free(blob_indices);
        for (blob_indices, 0..) |*blob_index, blob_i| blob_index.* = @intCast(blob_i);

        if (try self.chainService().ingestBlobSidecars(meta.block_root, meta.slot, aggregate, blob_indices)) |ready| {
            var owned_ready = ready;
            owned_ready.deinit(self.allocator);
        }

        if (self.chainService().dataAvailabilityStatusForBlock(meta.block_root, meta.any_signed) == .pending) {
            return error.MissingBlobSidecar;
        }
    }
}

fn fetchBlobSidecarsByRootForMeta(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
    meta: SyncBlockMeta,
    missing: []const u64,
) !void {
    if (missing.len == 0) return;

    const blob_commitments = try meta.any_signed.beaconBlock().beaconBlockBody().blobKzgCommitments();
    const existing = try self.chainQuery().blobSidecarsByRoot(meta.block_root);
    var state = try BlobFetchState.init(self.allocator, blob_commitments.items.len, existing);
    defer state.deinit(self.allocator);

    const protocol_id = "/eth2/beacon_chain/req/blob_sidecars_by_root/1/ssz_snappy";
    const req_resp_encoding = networking.req_resp_encoding;

    var request = networking.messages.BlobSidecarsByRootRequest.Type.empty;
    defer networking.messages.BlobSidecarsByRootRequest.deinit(self.allocator, &request);
    for (missing) |blob_index| {
        try request.append(self.allocator, .{
            .block_root = meta.block_root,
            .index = blob_index,
        });
    }

    var outbound = try openReqRespRequest(io, svc, peer_id, .blob_sidecars_by_root, protocol_id);
    defer outbound.deinit(io);

    const request_bytes = try self.allocator.alloc(u8, networking.messages.BlobSidecarsByRootRequest.serializedSize(&request));
    defer self.allocator.free(request_bytes);
    _ = networking.messages.BlobSidecarsByRootRequest.serializeIntoBytes(&request, request_bytes);
    try req_resp_encoding.writeRequestToStream(self.allocator, io, &outbound.stream, request_bytes);
    outbound.stream.closeWrite(io);

    var reader = req_resp_encoding.ResponseChunkStreamReader{
        .allocator = self.allocator,
        .has_context_bytes = true,
    };
    defer reader.deinit();

    while (try reader.next(io, &outbound.stream)) |decoded| {
        if (decoded.result != .success) {
            self.allocator.free(decoded.ssz_bytes);
            return responseCodeError(decoded.result);
        }
        errdefer self.allocator.free(decoded.ssz_bytes);

        var sidecar: BlobSidecar.Type = undefined;
        BlobSidecar.deserializeFromBytes(decoded.ssz_bytes, &sidecar) catch return error.MalformedBlobSidecar;

        const context_bytes = decoded.context_bytes orelse return error.MissingContextBytes;
        const expected_digest = self.config.forkDigestAtSlot(sidecar.signed_block_header.message.slot, self.genesis_validators_root);
        if (!std.mem.eql(u8, &context_bytes, &expected_digest)) return error.ForkDigestMismatch;

        var block_root: [32]u8 = undefined;
        try types.phase0.BeaconBlockHeader.hashTreeRoot(&sidecar.signed_block_header.message, &block_root);
        if (!std.mem.eql(u8, &block_root, &meta.block_root)) return error.UnexpectedBlobSidecar;
        if (sidecar.signed_block_header.message.slot != meta.slot) return error.UnexpectedBlobSlot;
        if (sidecar.index >= blob_commitments.items.len) return error.InvalidBlobIndex;
        if (!std.mem.eql(u8, &blob_commitments.items[sidecar.index], &sidecar.kzg_commitment)) {
            return error.KzgCommitmentMismatch;
        }

        const blob_ptr: *const [BYTES_PER_BLOB]u8 = @ptrCast(&sidecar.blob);
        try self.chainService().verifyBlobSidecar(.{
            .blob = blob_ptr,
            .commitment = sidecar.kzg_commitment,
            .proof = sidecar.kzg_proof,
        });

        if (state.sidecars[sidecar.index] != null) {
            self.allocator.free(decoded.ssz_bytes);
            continue;
        }
        try state.setFetched(self.allocator, sidecar.index, decoded.ssz_bytes);
    }

    const aggregate = try state.aggregate(self.allocator);
    defer self.allocator.free(aggregate);

    const blob_indices = try self.allocator.alloc(u64, state.sidecars.len);
    defer self.allocator.free(blob_indices);
    for (blob_indices, 0..) |*blob_index, i| blob_index.* = @intCast(i);

    if (try self.chainService().ingestBlobSidecars(meta.block_root, meta.slot, aggregate, blob_indices)) |ready| {
        var owned_ready = ready;
        owned_ready.deinit(self.allocator);
    }

    if (self.chainService().dataAvailabilityStatusForBlock(meta.block_root, meta.any_signed) == .pending) {
        return error.MissingBlobSidecar;
    }
}

fn fetchDataColumnsByRangeForMetas(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    preferred_peer_id: []const u8,
    metas: []const SyncBlockMeta,
) !void {
    var attempted_peers = std.ArrayListUnmanaged([]const u8).empty;
    defer {
        for (attempted_peers.items) |peer_id| self.allocator.free(peer_id);
        attempted_peers.deinit(self.allocator);
    }

    var last_err: ?anyerror = null;

    while (true) {
        const missing_before = try countMissingDataColumnsForMetas(self, metas);
        if (missing_before == 0) return;

        var request = (try buildDataColumnRangeRequest(self, metas)) orelse return;
        defer networking.messages.DataColumnSidecarsByRangeRequest.deinit(self.allocator, &request);

        const end_slot = request.start_slot +| (request.count -| 1);
        const selected_peer = try selectDataColumnFetchPeer(
            self,
            request.columns.items,
            request.start_slot,
            end_slot,
            preferred_peer_id,
            attempted_peers.items,
        ) orelse break;
        errdefer self.allocator.free(selected_peer);
        try attempted_peers.append(self.allocator, selected_peer);

        fetchDataColumnsByRangeOnce(self, io, svc, selected_peer, metas, &request) catch |err| {
            std.log.warn("Data column by-range fetch failed from peer {s}: {}", .{ selected_peer, err });
            last_err = err;
            continue;
        };

        const missing_after = try countMissingDataColumnsForMetas(self, metas);
        if (missing_after == 0) return;
        if (missing_after >= missing_before) continue;
    }

    return last_err orelse error.MissingDataColumnSidecar;
}

fn fetchDataColumnsByRangeOnce(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
    metas: []const SyncBlockMeta,
    request: *const networking.messages.DataColumnSidecarsByRangeRequest.Type,
) !void {
    const protocol_id = "/eth2/beacon_chain/req/data_column_sidecars_by_range/1/ssz_snappy";
    const req_resp_encoding = networking.req_resp_encoding;

    var outbound = try openReqRespRequest(io, svc, peer_id, .data_column_sidecars_by_range, protocol_id);
    defer outbound.deinit(io);

    const request_bytes = try self.allocator.alloc(u8, networking.messages.DataColumnSidecarsByRangeRequest.serializedSize(request));
    defer self.allocator.free(request_bytes);
    _ = networking.messages.DataColumnSidecarsByRangeRequest.serializeIntoBytes(request, request_bytes);
    try req_resp_encoding.writeRequestToStream(self.allocator, io, &outbound.stream, request_bytes);
    outbound.stream.closeWrite(io);

    var seen_columns = try self.allocator.alloc(std.StaticBitSet(MAX_COLUMNS), metas.len);
    defer self.allocator.free(seen_columns);
    for (seen_columns) |*bits| bits.* = std.StaticBitSet(MAX_COLUMNS).initEmpty();

    var reader = req_resp_encoding.ResponseChunkStreamReader{
        .allocator = self.allocator,
        .has_context_bytes = true,
    };
    defer reader.deinit();

    while (try reader.next(io, &outbound.stream)) |decoded| {
        if (decoded.result != .success) {
            self.allocator.free(decoded.ssz_bytes);
            return responseCodeError(decoded.result);
        }
        defer self.allocator.free(decoded.ssz_bytes);

        var sidecar = DataColumnSidecar.default_value;
        DataColumnSidecar.deserializeFromBytes(self.allocator, decoded.ssz_bytes, &sidecar) catch return error.MalformedDataColumnSidecar;
        defer DataColumnSidecar.deinit(self.allocator, &sidecar);

        const slot = sidecar.signed_block_header.message.slot;
        const context_bytes = decoded.context_bytes orelse return error.MissingContextBytes;
        const expected_digest = self.config.forkDigestAtSlot(slot, self.genesis_validators_root);
        if (!std.mem.eql(u8, &context_bytes, &expected_digest)) return error.ForkDigestMismatch;

        var block_root: [32]u8 = undefined;
        try types.phase0.BeaconBlockHeader.hashTreeRoot(&sidecar.signed_block_header.message, &block_root);

        const meta_index = findMetaIndexByRoot(metas, block_root) orelse return error.UnexpectedDataColumnSidecar;
        const meta = metas[meta_index];
        if (!needsColumnFetch(meta)) continue;

        const blob_commitments = try meta.any_signed.beaconBlock().beaconBlockBody().blobKzgCommitments();
        if (slot != meta.slot) return error.UnexpectedColumnSlot;
        if (sidecar.index >= MAX_COLUMNS) return error.InvalidColumnIndex;
        if (seen_columns[meta_index].isSet(@intCast(sidecar.index))) continue;
        seen_columns[meta_index].set(@intCast(sidecar.index));

        if (sidecar.kzg_commitments.items.len != blob_commitments.items.len) return error.KzgCommitmentLengthMismatch;
        if (sidecar.column.items.len != blob_commitments.items.len) return error.ColumnLengthMismatch;
        if (sidecar.kzg_proofs.items.len != blob_commitments.items.len) return error.ColumnProofLengthMismatch;

        for (blob_commitments.items, sidecar.kzg_commitments.items) |expected_commitment, actual_commitment| {
            if (!std.mem.eql(u8, &expected_commitment, &actual_commitment)) {
                return error.KzgCommitmentMismatch;
            }
        }

        try self.chainService().verifyDataColumnSidecar(
            self.allocator,
            sidecar.index,
            sidecar.kzg_commitments.items,
            sidecar.column.items,
            sidecar.kzg_proofs.items,
        );

        if (try self.chainService().ingestDataColumnSidecar(block_root, sidecar.index, slot, decoded.ssz_bytes)) |ready| {
            var owned_ready = ready;
            owned_ready.deinit(self.allocator);
        }
    }
}

fn fetchDataColumnsByRootForMeta(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    preferred_peer_id: []const u8,
    meta: SyncBlockMeta,
) !void {
    var attempted_peers = std.ArrayListUnmanaged([]const u8).empty;
    defer {
        for (attempted_peers.items) |peer_id| self.allocator.free(peer_id);
        attempted_peers.deinit(self.allocator);
    }

    var last_err: ?anyerror = null;

    while (true) {
        const missing = try self.chainService().missingDataColumns(self.allocator, meta.block_root);
        defer self.allocator.free(missing);
        if (missing.len == 0) return;

        const selected_peer = try selectDataColumnFetchPeer(
            self,
            missing,
            meta.slot,
            meta.slot,
            preferred_peer_id,
            attempted_peers.items,
        ) orelse break;
        errdefer self.allocator.free(selected_peer);
        try attempted_peers.append(self.allocator, selected_peer);

        fetchDataColumnsByRootOnce(self, io, svc, selected_peer, meta, missing) catch |err| {
            std.log.warn("Data column by-root fetch failed from peer {s}: {}", .{ selected_peer, err });
            last_err = err;
            continue;
        };

        if (self.chainService().dataAvailabilityStatusForBlock(meta.block_root, meta.any_signed) != .pending) {
            return;
        }
    }

    return last_err orelse error.MissingDataColumnSidecar;
}

fn fetchDataColumnsByRootOnce(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
    meta: SyncBlockMeta,
    missing: []const u64,
) !void {
    var request_bytes = try self.allocator.alloc(u8, missing.len * networking.messages.DataColumnIdentifier.fixed_size);
    defer self.allocator.free(request_bytes);
    for (missing, 0..) |column_index, i| {
        const identifier = networking.messages.DataColumnIdentifier.Type{
            .block_root = meta.block_root,
            .index = column_index,
        };
        _ = networking.messages.DataColumnIdentifier.serializeIntoBytes(
            &identifier,
            request_bytes[i * networking.messages.DataColumnIdentifier.fixed_size ..][0..networking.messages.DataColumnIdentifier.fixed_size],
        );
    }

    const protocol_id = "/eth2/beacon_chain/req/data_column_sidecars_by_root/1/ssz_snappy";
    const req_resp_encoding = networking.req_resp_encoding;

    var outbound = try openReqRespRequest(io, svc, peer_id, .data_column_sidecars_by_root, protocol_id);
    defer outbound.deinit(io);

    try req_resp_encoding.writeRequestToStream(self.allocator, io, &outbound.stream, request_bytes);
    outbound.stream.closeWrite(io);

    var seen_columns = std.StaticBitSet(MAX_COLUMNS).initEmpty();
    var reader = req_resp_encoding.ResponseChunkStreamReader{
        .allocator = self.allocator,
        .has_context_bytes = true,
    };
    defer reader.deinit();

    const blob_commitments = try meta.any_signed.beaconBlock().beaconBlockBody().blobKzgCommitments();

    while (try reader.next(io, &outbound.stream)) |decoded| {
        if (decoded.result != .success) {
            self.allocator.free(decoded.ssz_bytes);
            return responseCodeError(decoded.result);
        }
        defer self.allocator.free(decoded.ssz_bytes);

        var sidecar = DataColumnSidecar.default_value;
        DataColumnSidecar.deserializeFromBytes(self.allocator, decoded.ssz_bytes, &sidecar) catch return error.MalformedDataColumnSidecar;
        defer DataColumnSidecar.deinit(self.allocator, &sidecar);

        const context_bytes = decoded.context_bytes orelse return error.MissingContextBytes;
        const expected_digest = self.config.forkDigestAtSlot(sidecar.signed_block_header.message.slot, self.genesis_validators_root);
        if (!std.mem.eql(u8, &context_bytes, &expected_digest)) return error.ForkDigestMismatch;

        var block_root: [32]u8 = undefined;
        try types.phase0.BeaconBlockHeader.hashTreeRoot(&sidecar.signed_block_header.message, &block_root);
        if (!std.mem.eql(u8, &block_root, &meta.block_root)) return error.UnexpectedDataColumnSidecar;
        if (sidecar.signed_block_header.message.slot != meta.slot) return error.UnexpectedColumnSlot;
        if (sidecar.index >= MAX_COLUMNS) return error.InvalidColumnIndex;
        if (seen_columns.isSet(@intCast(sidecar.index))) continue;
        seen_columns.set(@intCast(sidecar.index));

        if (sidecar.kzg_commitments.items.len != blob_commitments.items.len) return error.KzgCommitmentLengthMismatch;
        if (sidecar.column.items.len != blob_commitments.items.len) return error.ColumnLengthMismatch;
        if (sidecar.kzg_proofs.items.len != blob_commitments.items.len) return error.ColumnProofLengthMismatch;

        for (blob_commitments.items, sidecar.kzg_commitments.items) |expected_commitment, actual_commitment| {
            if (!std.mem.eql(u8, &expected_commitment, &actual_commitment)) {
                return error.KzgCommitmentMismatch;
            }
        }

        try self.chainService().verifyDataColumnSidecar(
            self.allocator,
            sidecar.index,
            sidecar.kzg_commitments.items,
            sidecar.column.items,
            sidecar.kzg_proofs.items,
        );

        if (try self.chainService().ingestDataColumnSidecar(block_root, sidecar.index, sidecar.signed_block_header.message.slot, decoded.ssz_bytes)) |ready| {
            var owned_ready = ready;
            owned_ready.deinit(self.allocator);
        }
    }
}

fn buildDataColumnRangeRequest(
    self: *BeaconNode,
    metas: []const SyncBlockMeta,
) !?networking.messages.DataColumnSidecarsByRangeRequest.Type {
    var requested_columns = std.StaticBitSet(MAX_COLUMNS).initEmpty();
    var start_slot: u64 = std.math.maxInt(u64);
    var end_slot: u64 = 0;
    var have_pending = false;

    for (metas) |meta| {
        if (!needsColumnFetch(meta)) continue;
        const missing = try self.chainService().missingDataColumns(self.allocator, meta.block_root);
        defer self.allocator.free(missing);
        if (missing.len == 0) continue;

        have_pending = true;
        start_slot = @min(start_slot, meta.slot);
        end_slot = @max(end_slot, meta.slot);
        for (missing) |column_index| {
            if (column_index < MAX_COLUMNS) requested_columns.set(@intCast(column_index));
        }
    }

    if (!have_pending) return null;

    var request: networking.messages.DataColumnSidecarsByRangeRequest.Type = .{
        .start_slot = start_slot,
        .count = end_slot - start_slot + 1,
        .columns = .empty,
    };
    errdefer networking.messages.DataColumnSidecarsByRangeRequest.deinit(self.allocator, &request);

    for (0..MAX_COLUMNS) |column_index| {
        if (requested_columns.isSet(column_index)) {
            try request.columns.append(self.allocator, @intCast(column_index));
        }
    }
    if (request.columns.items.len == 0) return null;
    return request;
}

fn countMissingDataColumnsForMetas(self: *BeaconNode, metas: []const SyncBlockMeta) !usize {
    var count: usize = 0;
    for (metas) |meta| {
        if (!needsColumnFetch(meta)) continue;
        count += try countMissingDataColumnsForMeta(self, meta);
    }
    return count;
}

fn countMissingDataColumnsForMeta(self: *BeaconNode, meta: SyncBlockMeta) !usize {
    const missing = try self.chainService().missingDataColumns(self.allocator, meta.block_root);
    defer self.allocator.free(missing);
    return missing.len;
}

fn selectDataColumnFetchPeer(
    self: *BeaconNode,
    missing_columns: []const u64,
    start_slot: u64,
    end_slot: u64,
    preferred_peer_id: []const u8,
    excluded_peer_ids: []const []const u8,
) !?[]const u8 {
    if (self.peer_manager) |pm| {
        return try pm.selectDataColumnPeer(
            missing_columns,
            start_slot,
            end_slot,
            preferred_peer_id,
            excluded_peer_ids,
        );
    }

    if (containsPeerId(excluded_peer_ids, preferred_peer_id)) return null;
    return try self.allocator.dupe(u8, preferred_peer_id);
}

fn needsBlobFetch(meta: SyncBlockMeta) bool {
    return switch (meta.block_data_plan) {
        .blobs => true,
        else => false,
    };
}

fn needsColumnFetch(meta: SyncBlockMeta) bool {
    return switch (meta.block_data_plan) {
        .columns => true,
        else => false,
    };
}

fn requiredColumnIndices(meta: SyncBlockMeta) []const u64 {
    return switch (meta.block_data_plan) {
        .columns => |indices| indices,
        else => &[_]u64{},
    };
}

fn findMetaIndexByRoot(metas: []const SyncBlockMeta, root: [32]u8) ?usize {
    for (metas, 0..) |meta, i| {
        if (std.mem.eql(u8, &meta.block_root, &root)) return i;
    }
    return null;
}

fn readSignedBeaconBlockSlot(bytes: []const u8) ?u64 {
    if (bytes.len < 4) return null;
    const msg_offset = std.mem.readInt(u32, bytes[0..4], .little);
    if (bytes.len < @as(usize, msg_offset) + 8) return null;
    return std.mem.readInt(u64, bytes[msg_offset..][0..8], .little);
}

fn responseCodeError(code: networking.ResponseCode) anyerror {
    return switch (code) {
        .success => unreachable,
        .invalid_request => error.InvalidRequestResponse,
        .server_error => error.ServerErrorResponse,
        .resource_unavailable => error.ResourceUnavailableResponse,
    };
}

fn fetchBlockByRoot(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
    root: [32]u8,
) ![]const u8 {
    const protocol_id = "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy";
    const req_resp_encoding = networking.req_resp_encoding;

    var outbound = try openReqRespRequest(io, svc, peer_id, .beacon_blocks_by_root, protocol_id);
    defer outbound.deinit(io);

    try req_resp_encoding.writeRequestToStream(self.allocator, io, &outbound.stream, &root);
    outbound.stream.closeWrite(io);

    var reader = req_resp_encoding.ResponseChunkStreamReader{
        .allocator = self.allocator,
        .has_context_bytes = true,
    };
    defer reader.deinit();

    const decoded = (try reader.next(io, &outbound.stream)) orelse return error.NoBlockReturned;
    if (decoded.result != .success) {
        self.allocator.free(decoded.ssz_bytes);
        return responseCodeError(decoded.result);
    }

    return decoded.ssz_bytes;
}

fn fetchRawBlocksByRange(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
    start_slot: u64,
    count: u64,
) ![]BatchBlock {
    const protocol_id = "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy";
    const req_resp_encoding = networking.req_resp_encoding;

    var outbound = try openReqRespRequest(io, svc, peer_id, .beacon_blocks_by_range, protocol_id);
    defer outbound.deinit(io);

    const request = networking.messages.BeaconBlocksByRangeRequest.Type{
        .start_slot = start_slot,
        .count = count,
    };
    var req_ssz: [networking.messages.BeaconBlocksByRangeRequest.fixed_size]u8 = undefined;
    _ = networking.messages.BeaconBlocksByRangeRequest.serializeIntoBytes(&request, &req_ssz);
    try req_resp_encoding.writeRequestToStream(self.allocator, io, &outbound.stream, &req_ssz);
    outbound.stream.closeWrite(io);

    var result: std.ArrayListUnmanaged(BatchBlock) = .empty;
    errdefer {
        for (result.items) |blk| self.allocator.free(blk.block_bytes);
        result.deinit(self.allocator);
    }

    var reader = req_resp_encoding.ResponseChunkStreamReader{
        .allocator = self.allocator,
        .has_context_bytes = true,
    };
    defer reader.deinit();
    var blocks_received: u64 = 0;
    var previous_slot: ?u64 = null;

    while (blocks_received < count) {
        const decoded = (try reader.next(io, &outbound.stream)) orelse break;
        if (decoded.result != .success) {
            self.allocator.free(decoded.ssz_bytes);
            return responseCodeError(decoded.result);
        }

        const slot = validateFetchedBlockRangeChunk(self, start_slot, count, previous_slot, decoded.context_bytes, decoded.ssz_bytes) catch |err| {
            self.allocator.free(decoded.ssz_bytes);
            return err;
        };
        previous_slot = slot;

        try result.append(self.allocator, .{
            .slot = slot,
            .block_bytes = decoded.ssz_bytes,
        });
        blocks_received += 1;
    }

    return result.toOwnedSlice(self.allocator);
}

fn validateFetchedBlockRangeChunk(
    self: *const BeaconNode,
    start_slot: u64,
    count: u64,
    previous_slot: ?u64,
    context_bytes: ?[4]u8,
    ssz_bytes: []const u8,
) !u64 {
    const slot = readSignedBeaconBlockSlot(ssz_bytes) orelse return error.MalformedBlockBytes;
    if (slot < start_slot) return error.BlockOutsideRequestedRange;
    if (slot - start_slot >= count) return error.BlockOutsideRequestedRange;
    if (previous_slot) |prev| {
        if (slot <= prev) return error.UnsortedBlockRangeResponse;
    }

    const chunk_context = context_bytes orelse return error.MissingContextBytes;
    const expected_digest = self.config.forkDigestAtSlot(slot, self.genesis_validators_root);
    if (!std.mem.eql(u8, &chunk_context, &expected_digest)) return error.ForkDigestMismatch;

    return slot;
}

fn sendStatus(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
) !PeerStatusResponse {
    const current_fork_seq = self.config.forkSeq(self.currentHeadSlot());
    const use_status_v2 = current_fork_seq.gte(.fulu);
    const status_protocol_id = if (use_status_v2)
        "/eth2/beacon_chain/req/status/2/ssz_snappy"
    else
        "/eth2/beacon_chain/req/status/1/ssz_snappy";
    const req_resp_encoding = networking.req_resp_encoding;

    var outbound = try openReqRespRequest(io, svc, peer_id, .status, status_protocol_id);
    defer outbound.deinit(io);

    const our_status = self.getStatus();
    std.log.info("Sending Status: fork_digest={x:0>2}{x:0>2}{x:0>2}{x:0>2} head_slot={d} finalized_epoch={d}", .{
        our_status.fork_digest[0],
        our_status.fork_digest[1],
        our_status.fork_digest[2],
        our_status.fork_digest[3],
        our_status.head_slot,
        our_status.finalized_epoch,
    });

    if (use_status_v2) {
        const our_status_v2: StatusMessageV2.Type = .{
            .fork_digest = our_status.fork_digest,
            .finalized_root = our_status.finalized_root,
            .finalized_epoch = our_status.finalized_epoch,
            .head_root = our_status.head_root,
            .head_slot = our_status.head_slot,
            .earliest_available_slot = self.earliest_available_slot,
        };
        var status_ssz: [StatusMessageV2.fixed_size]u8 = undefined;
        _ = StatusMessageV2.serializeIntoBytes(&our_status_v2, &status_ssz);
        try req_resp_encoding.writeRequestToStream(self.allocator, io, &outbound.stream, &status_ssz);
    } else {
        var status_ssz: [StatusMessage.fixed_size]u8 = undefined;
        _ = StatusMessage.serializeIntoBytes(&our_status, &status_ssz);
        try req_resp_encoding.writeRequestToStream(self.allocator, io, &outbound.stream, &status_ssz);
    }
    outbound.stream.closeWrite(io);

    var reader = req_resp_encoding.ResponseChunkStreamReader{
        .allocator = self.allocator,
        .has_context_bytes = false,
    };
    defer reader.deinit();

    const decoded = (try reader.next(io, &outbound.stream)) orelse {
        std.log.warn("Status: peer sent empty response", .{});
        return error.EmptyResponse;
    };
    defer self.allocator.free(decoded.ssz_bytes);

    if (decoded.result != .success) {
        std.log.warn("Status response: error code {}", .{decoded.result});
        return responseCodeError(decoded.result);
    }

    if (use_status_v2) {
        var peer_status_v2: StatusMessageV2.Type = undefined;
        StatusMessageV2.deserializeFromBytes(decoded.ssz_bytes, &peer_status_v2) catch |err| {
            std.log.warn("StatusV2 SSZ deserialize error: {}", .{err});
            return err;
        };

        std.log.info("Peer StatusV2: fork_digest={x:0>2}{x:0>2}{x:0>2}{x:0>2} head_slot={d} finalized_epoch={d} earliest_available_slot={d}", .{
            peer_status_v2.fork_digest[0],
            peer_status_v2.fork_digest[1],
            peer_status_v2.fork_digest[2],
            peer_status_v2.fork_digest[3],
            peer_status_v2.head_slot,
            peer_status_v2.finalized_epoch,
            peer_status_v2.earliest_available_slot,
        });

        return .{
            .status = .{
                .fork_digest = peer_status_v2.fork_digest,
                .finalized_root = peer_status_v2.finalized_root,
                .finalized_epoch = peer_status_v2.finalized_epoch,
                .head_root = peer_status_v2.head_root,
                .head_slot = peer_status_v2.head_slot,
            },
            .earliest_available_slot = peer_status_v2.earliest_available_slot,
        };
    }

    var peer_status: StatusMessage.Type = undefined;
    StatusMessage.deserializeFromBytes(decoded.ssz_bytes, &peer_status) catch |err| {
        std.log.warn("Status SSZ deserialize error: {}", .{err});
        return err;
    };

    std.log.info("Peer Status: fork_digest={x:0>2}{x:0>2}{x:0>2}{x:0>2} head_slot={d} finalized_epoch={d} finalized_root={x:0>2}{x:0>2}{x:0>2}{x:0>2}...", .{
        peer_status.fork_digest[0],
        peer_status.fork_digest[1],
        peer_status.fork_digest[2],
        peer_status.fork_digest[3],
        peer_status.head_slot,
        peer_status.finalized_epoch,
        peer_status.finalized_root[0],
        peer_status.finalized_root[1],
        peer_status.finalized_root[2],
        peer_status.finalized_root[3],
    });

    return .{ .status = peer_status };
}

fn requestPeerPing(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
) !networking.messages.Ping.Type {
    const ping_protocol_id = "/eth2/beacon_chain/req/ping/1/ssz_snappy";
    const req_resp_encoding = networking.req_resp_encoding;

    var outbound = try openReqRespRequest(io, svc, peer_id, .ping, ping_protocol_id);
    defer outbound.deinit(io);

    var ping_ssz: [networking.messages.Ping.fixed_size]u8 = undefined;
    const local_seq: networking.messages.Ping.Type = self.api_node_identity.metadata.seq_number;
    _ = networking.messages.Ping.serializeIntoBytes(&local_seq, &ping_ssz);

    try req_resp_encoding.writeRequestToStream(self.allocator, io, &outbound.stream, &ping_ssz);
    outbound.stream.closeWrite(io);

    var reader = req_resp_encoding.ResponseChunkStreamReader{
        .allocator = self.allocator,
        .has_context_bytes = false,
    };
    defer reader.deinit();

    const decoded = (try reader.next(io, &outbound.stream)) orelse return error.EmptyResponse;
    defer self.allocator.free(decoded.ssz_bytes);

    if (decoded.result != .success) return responseCodeError(decoded.result);

    var remote_seq: networking.messages.Ping.Type = undefined;
    try networking.messages.Ping.deserializeFromBytes(decoded.ssz_bytes, &remote_seq);
    return remote_seq;
}

fn requestPeerMetadata(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
) !PeerMetadataResponse {
    const current_fork_seq = self.config.forkSeq(self.currentHeadSlot());
    const use_metadata_v3 = current_fork_seq.gte(.fulu);
    const metadata_protocol_id = if (use_metadata_v3)
        "/eth2/beacon_chain/req/metadata/3/ssz_snappy"
    else
        "/eth2/beacon_chain/req/metadata/2/ssz_snappy";
    const req_resp_encoding = networking.req_resp_encoding;

    var outbound = try openReqRespRequest(io, svc, peer_id, .metadata, metadata_protocol_id);
    defer outbound.deinit(io);

    try req_resp_encoding.writeRequestToStream(self.allocator, io, &outbound.stream, &.{});
    outbound.stream.closeWrite(io);

    var reader = req_resp_encoding.ResponseChunkStreamReader{
        .allocator = self.allocator,
        .has_context_bytes = false,
    };
    defer reader.deinit();

    const decoded = (try reader.next(io, &outbound.stream)) orelse return error.EmptyResponse;
    defer self.allocator.free(decoded.ssz_bytes);

    if (decoded.result != .success) return responseCodeError(decoded.result);

    if (use_metadata_v3) {
        var metadata_v3: MetadataV3.Type = undefined;
        try MetadataV3.deserializeFromBytes(decoded.ssz_bytes, &metadata_v3);
        return .{
            .metadata = .{
                .seq_number = metadata_v3.seq_number,
                .attnets = metadata_v3.attnets,
                .syncnets = metadata_v3.syncnets,
            },
            .custody_group_count = metadata_v3.custody_group_count,
        };
    }

    var metadata: MetadataV2.Type = undefined;
    try MetadataV2.deserializeFromBytes(decoded.ssz_bytes, &metadata);
    return .{ .metadata = metadata };
}

fn reportReqRespFetchFailure(
    self: *BeaconNode,
    io: std.Io,
    peer_id: []const u8,
    protocol: ReqRespMaintenanceProtocol,
    err: anyerror,
) void {
    const pm = self.peer_manager orelse return;
    const action = peer_scoring.reqRespFailureAction(protocol, err) orelse return;
    _ = pm.reportPeer(peer_id, action, .rpc, currentUnixTimeMs(io));
}

fn handleReqRespMaintenanceFailure(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
    protocol: ReqRespMaintenanceProtocol,
    err: anyerror,
) void {
    std.log.warn("Peer maintenance {s} failed for {s}: {}", .{ @tagName(protocol), peer_id, err });

    if (err == error.RequestSelfRateLimited) {
        std.log.debug("Local req/resp self rate limit hit for maintenance {s} to {s}", .{ @tagName(protocol), peer_id });
        return;
    }

    const pm = self.peer_manager orelse {
        _ = svc.disconnectPeer(io, peer_id);
        return;
    };

    const now_ms = currentUnixTimeMs(io);
    const action = reqRespMaintenanceFailureAction(protocol, err) orelse {
        _ = svc.disconnectPeer(io, peer_id);
        return;
    };
    const score_state = pm.reportPeer(peer_id, action, .rpc, now_ms);

    var reason: GoodbyeReason = .fault_error;
    if (score_state) |state| {
        switch (state) {
            .healthy => {},
            .disconnected => reason = .score_too_low,
            .banned => {
                pm.banPeer(peer_id, .medium, now_ms) catch |ban_err| {
                    std.log.warn("Failed to ban peer {s} after req/resp failure: {}", .{ peer_id, ban_err });
                };
                reason = .banned;
            },
        }
    }

    sendGoodbyeAndDisconnect(self, io, svc, peer_id, reason);
}

fn reqRespMaintenanceFailureAction(protocol: ReqRespMaintenanceProtocol, err: anyerror) ?PeerAction {
    return peer_scoring.reqRespFailureAction(protocol, err);
}

fn sendGoodbye(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
    reason: GoodbyeReason,
) !void {
    const goodbye_protocol_id = "/eth2/beacon_chain/req/goodbye/1/ssz_snappy";
    const req_resp_encoding = networking.req_resp_encoding;

    var outbound = try openReqRespRequest(io, svc, peer_id, .goodbye, goodbye_protocol_id);
    defer outbound.deinit(io);

    var goodbye_ssz: [networking.messages.GoodbyeReason.fixed_size]u8 = undefined;
    const reason_code: networking.messages.GoodbyeReason.Type = @intFromEnum(reason);
    _ = networking.messages.GoodbyeReason.serializeIntoBytes(&reason_code, &goodbye_ssz);

    try req_resp_encoding.writeRequestToStream(self.allocator, io, &outbound.stream, &goodbye_ssz);
    outbound.stream.closeWrite(io);
}

fn attnetsFromMetadata(bytes: [8]u8) AttnetsBitfield {
    var attnets = AttnetsBitfield.initEmpty();
    var subnet: u32 = 0;
    while (subnet < ATTESTATION_SUBNET_COUNT) : (subnet += 1) {
        if ((bytes[subnet / 8] & (@as(u8, 1) << @intCast(subnet % 8))) != 0) {
            attnets.set(subnet);
        }
    }
    return attnets;
}

fn syncnetsFromMetadata(bytes: [1]u8) SyncnetsBitfield {
    var syncnets = SyncnetsBitfield.initEmpty();
    var subnet: u32 = 0;
    while (subnet < SYNC_COMMITTEE_SUBNET_COUNT) : (subnet += 1) {
        if ((bytes[subnet / 8] & (@as(u8, 1) << @intCast(subnet % 8))) != 0) {
            syncnets.set(subnet);
        }
    }
    return syncnets;
}

fn initGossipHandler(self: *BeaconNode) void {
    if (self.gossip_handler != null) return;

    const callbacks = gossip_node_callbacks_mod;
    self.gossip_handler = GossipHandler.create(
        self.allocator,
        @ptrCast(self),
        &callbacks.importBlockFromGossip,
        &callbacks.getForkSeqForSlot,
        &callbacks.getProposerIndex,
        &callbacks.isKnownBlockRoot,
        &callbacks.getValidatorCount,
        &callbacks.resolveAttestation,
        &callbacks.resolveAggregate,
        &callbacks.isValidSyncCommitteeSubnet,
    ) catch |err| {
        std.log.warn("Failed to create GossipHandler: {}", .{err});
        return;
    };

    if (self.gossip_handler) |gh| {
        gh.importResolvedAttestationFn = &callbacks.importResolvedAttestation;
        gh.importResolvedAggregateFn = &callbacks.importResolvedAggregate;
        gh.importVoluntaryExitFn = &callbacks.importVoluntaryExit;
        gh.importProposerSlashingFn = &callbacks.importProposerSlashing;
        gh.importAttesterSlashingFn = &callbacks.importAttesterSlashing;
        gh.importBlsChangeFn = &callbacks.importBlsChange;
        gh.importBlobSidecarFn = &callbacks.importBlobSidecar;
        gh.importDataColumnSidecarFn = &callbacks.importDataColumnSidecar;

        gh.verifyBlockSignatureFn = &callbacks.verifyBlockSignature;
        gh.verifyVoluntaryExitSignatureFn = &callbacks.verifyVoluntaryExitSignature;
        gh.verifyProposerSlashingSignatureFn = &callbacks.verifyProposerSlashingSignature;
        gh.verifyAttesterSlashingSignatureFn = &callbacks.verifyAttesterSlashingSignature;
        gh.verifyBlsChangeSignatureFn = &callbacks.verifyBlsChangeSignature;
        gh.verifyAttestationSignatureFn = &callbacks.verifyAttestationSignature;
        gh.verifyAggregateSignatureFn = &callbacks.verifyResolvedAggregateSignature;
        gh.verifySyncCommitteeSignatureFn = &callbacks.verifySyncCommitteeSignature;

        gh.importSyncContributionFn = &callbacks.importSyncContribution;
        gh.importSyncCommitteeMessageFn = &callbacks.importSyncCommitteeMessage;

        gh.metrics = self.metrics;
        gh.beacon_processor = self.beacon_processor;
    }
}

fn currentUnixTimeMs(io: std.Io) u64 {
    const ms = std.Io.Timestamp.now(io, .real).toMilliseconds();
    return if (ms < 0) 0 else @intCast(ms);
}

fn maybePrepareProposerPayload(self: *BeaconNode, io: std.Io) void {
    const clock = self.clock orelse return;
    if (!self.hasExecutionEngine()) return;

    const current_slot = clock.currentSlot(io) orelse return;
    const next_slot = current_slot + 1;
    const head_root = self.currentHeadRoot();

    const head_state = self.headState() orelse return;
    _ = head_state.epoch_cache.getBeaconProposer(next_slot) catch return;

    const fee_recipient = self.chainQuery().proposerFeeRecipientForSlot(
        next_slot,
        self.node_options.suggested_fee_recipient,
    ) orelse return;
    self.refreshBuilderStatus(current_slot);
    if (self.execution_runtime.cachedPayloadFor(next_slot, head_root)) {
        return;
    }

    const timestamp = clock.slotStartSeconds(next_slot);
    const next_epoch = next_slot / preset.SLOTS_PER_EPOCH;
    const randao_index = next_epoch % preset.EPOCHS_PER_HISTORICAL_VECTOR;
    const prev_randao: [32]u8 = blk: {
        var mixes = head_state.state.randaoMixes() catch break :blk [_]u8{0} ** 32;
        const mix_ptr = mixes.getFieldRoot(randao_index) catch break :blk [_]u8{0} ** 32;
        break :blk mix_ptr.*;
    };

    self.preparePayload(
        next_slot,
        timestamp,
        prev_randao,
        fee_recipient,
        &.{},
        head_root,
    ) catch |err| {
        std.log.warn("W7: preparePayload failed for slot {d}: {}", .{ next_slot, err });
    };
}

const beacon_node_mod = @import("beacon_node.zig");
const BeaconNode = beacon_node_mod.BeaconNode;
