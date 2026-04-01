//! Node-owned P2P runtime orchestration.
//!
//! Keeps the beacon node's networking event loop, discovery/bootstrap,
//! gossip ingress, and sync transport plumbing out of `beacon_node.zig`.

const std = @import("std");
const log = @import("log");

const types = @import("consensus_types");
const preset = @import("preset").preset;
const fork_types = @import("fork_types");
const config_mod = @import("config");
const BeaconConfig = config_mod.BeaconConfig;
const state_transition = @import("state_transition");
const computeEpochAtSlot = state_transition.computeEpochAtSlot;
const networking = @import("networking");
const DiscoveryService = networking.DiscoveryService;
const PeerManager = networking.PeerManager;
const ReqRespContext = networking.ReqRespContext;
const discv5 = @import("discv5");
const ssl = @import("ssl");
const Multiaddr = @import("multiaddr").Multiaddr;
const sync_mod = @import("sync");
const SyncService = sync_mod.SyncService;
const BatchBlock = sync_mod.BatchBlock;

const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;
const GossipHandler = @import("gossip_handler.zig").GossipHandler;
const GossipIngressMetadata = @import("gossip_handler.zig").GossipIngressMetadata;
const reqresp_callbacks_mod = @import("reqresp_callbacks.zig");
const gossip_node_callbacks_mod = @import("gossip_node_callbacks.zig");
const SyncCallbackCtx = @import("sync_bridge.zig").SyncCallbackCtx;

pub fn start(self: *BeaconNode, io: std.Io, listen_addr: []const u8, port: u16) !void {
    var ma_buf: [64]u8 = undefined;
    const ma_str = try std.fmt.bufPrint(&ma_buf, "/ip4/{s}/udp/{d}/quic-v1", .{ listen_addr, port });
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

    const validator = try self.allocator.create(networking.p2p_service.PassthroughValidator);
    errdefer self.allocator.destroy(validator);
    validator.* = networking.p2p_service.PassthroughValidator.init(self.allocator);
    validator.fixupPointers();
    self.p2p_validator = validator;

    const fork_digest = self.config.forkDigestAtSlot(
        self.head_tracker.head_slot,
        self.genesis_validators_root,
    );

    std.log.warn(
        "libp2p transport still generates a separate TLS host key; local ENR/peer-id are prepared from the Ethereum network key but not yet consumed by zig-libp2p",
        .{},
    );

    const pctx = ssl.EVP_PKEY_CTX_new_id(ssl.EVP_PKEY_ED25519, null) orelse return error.KeyGenFailed;
    defer ssl.EVP_PKEY_CTX_free(pctx);
    if (ssl.EVP_PKEY_keygen_init(pctx) <= 0) return error.KeyGenFailed;
    var host_key: ?*ssl.EVP_PKEY = null;
    if (ssl.EVP_PKEY_keygen(pctx, &host_key) <= 0) return error.KeyGenFailed;

    self.p2p_service = try networking.p2p_service.P2pService.init(self.allocator, .{
        .fork_digest = fork_digest,
        .fork_seq = self.config.forkSeq(self.head_tracker.head_slot),
        .req_resp_context = req_resp_ctx,
        .validator = &validator.ctx,
        .host_key = host_key,
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

    if (self.p2p_validator) |validator| {
        validator.deinit();
        self.allocator.destroy(validator);
        self.p2p_validator = null;
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

        const blocks = fetchRawBlocksByRange(self, io, svc, peer_id, req.start_slot, req.count) catch |err| {
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
            std.log.warn("processSyncByRoot: fetch failed for root {x:0>2}{x:0>2}{x:0>2}{x:0>2}...: {}", .{
                root[0], root[1], root[2], root[3], err,
            });
            self.unknown_block_sync.onFetchFailed(root);
            continue;
        };
        defer self.allocator.free(block_ssz);

        self.unknown_block_sync.onParentFetched(root, block_ssz) catch |err| {
            std.log.warn("processSyncByRoot: onParentFetched error: {}", .{err});
        };
    }
}

pub fn updateApiSyncStatus(self: *BeaconNode) void {
    if (self.sync_service_inst) |svc| {
        const status = svc.getSyncStatus();
        self.api_sync_status.head_slot = status.head_slot;
        self.api_sync_status.sync_distance = status.sync_distance;
        self.api_sync_status.is_syncing = status.state == .syncing_finalized or status.state == .syncing_head;
        self.api_sync_status.is_optimistic = status.is_optimistic;
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
        std.log.info("Attestation subnet auto-subscribe disabled; duty-driven subnet management not yet wired", .{});
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

fn closeOwnedQuicStream(io: std.Io, stream: *networking.QuicStream) void {
    stream.close(io);
    stream.deinit();
}

fn bootstrapBootnodes(self: *BeaconNode, io: std.Io, svc: *networking.P2pService) void {
    if (self.bootnodes.len == 0) return;

    std.log.info("Dialing {d} bootnode(s)...", .{self.bootnodes.len});
    for (self.bootnodes) |enr_str| {
        dialBootnodeEnr(self, io, svc, enr_str) catch |err| {
            std.log.warn("Failed to dial bootnode: {}", .{err});
        };
    }
}

fn runLoop(self: *BeaconNode, io: std.Io, svc: *networking.P2pService) void {
    std.log.info("Starting P2P maintenance loop...", .{});
    while (!self.shutdown_requested.load(.acquire)) {
        const slot_sleep: std.Io.Timeout = .{ .duration = .{
            .raw = std.Io.Duration.fromNanoseconds(@as(i96, 6) * std.time.ns_per_s),
            .clock = .awake,
        } };
        slot_sleep.sleep(io) catch break;

        if (self.discovery_service) |ds| {
            if (self.peer_manager) |pm| {
                const peer_count = pm.peerCount();
                ds.setConnectedPeers(peer_count);
                if (self.metrics) |metrics| metrics.peers_connected.set(@intCast(peer_count));
            }
            ds.discoverPeers();
        }

        if (self.p2p_service) |p2p| {
            processGossipEvents(self, io, p2p);
        }

        if (self.beacon_processor) |bp| {
            const dispatched = bp.tick(128);
            if (dispatched > 0) {
                std.log.debug("Processor: dispatched {d} items ({d} queued)", .{
                    dispatched,
                    bp.totalQueued(),
                });
            }
        }

        if (self.sync_service_inst) |sync_svc| {
            sync_svc.tick() catch |err| {
                std.log.warn("SyncService.tick failed: {}", .{err});
            };
        }

        maybeHandleForkTransition(self, svc);

        processSyncBatches(self, io, svc);
        processSyncByRootRequests(self, io, svc);
        updateApiSyncStatus(self);
        updateSyncMetrics(self);
        maybePrepareProposerPayload(self, io);
        pruneSyncCommitteePools(self);
        advanceForkChoiceClock(self, io);
    }
}

fn maybeHandleForkTransition(self: *BeaconNode, svc: *networking.P2pService) void {
    const head_slot = self.head_tracker.head_slot;
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
        svc.onForkTransition(current_digest, self.config.forkSeq(head_slot)) catch |err| {
            std.log.warn("onForkTransition failed: {}", .{err});
            return;
        };
        subscribeInitialSubnets(self, svc);
        if (self.gossip_handler) |gh| {
            gh.updateForkSeq(self.config.forkSeq(head_slot));
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
    const head_slot = self.head_tracker.head_slot;
    if (self.sync_contribution_pool) |pool| pool.prune(head_slot);
    if (self.sync_committee_message_pool) |pool| pool.prune(head_slot);
}

fn advanceForkChoiceClock(self: *BeaconNode, io: std.Io) void {
    if (self.clock) |clock| {
        if (clock.currentSlot(io)) |current_slot| {
            if (self.chain.fork_choice) |fc| {
                fc.updateTime(self.allocator, current_slot) catch |err| {
                    std.log.warn("fork choice updateTime failed: {}", .{err});
                };
            }
        }
    }
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

    const ip = enr.ip orelse return error.NoIpInEnr;
    const quic_port = enr.quic orelse enr.udp orelse return error.NoPortInEnr;

    var ma_buf: [64]u8 = undefined;
    const ma_str = try std.fmt.bufPrint(&ma_buf, "/ip4/{d}.{d}.{d}.{d}/udp/{d}/quic-v1", .{
        ip[0], ip[1], ip[2], ip[3], quic_port,
    });

    std.log.info("Dialing bootnode at {s}", .{ma_str});

    const peer_addr = try Multiaddr.fromString(self.allocator, ma_str);
    defer peer_addr.deinit();

    const peer_id = svc.dial(io, peer_addr) catch |err| {
        std.log.warn("Bootnode dial failed: {}", .{err});
        return err;
    };
    std.log.info("Connected to bootnode, peer_id: {s}", .{peer_id});

    const delay: std.Io.Timeout = .{ .duration = .{
        .raw = std.Io.Duration.fromMilliseconds(500),
        .clock = .awake,
    } };
    delay.sleep(io) catch {};

    if (enr.eth2_fork_digest) |fork_digest| {
        std.log.info("Peer ENR fork_digest: {x:0>2}{x:0>2}{x:0>2}{x:0>2}", .{
            fork_digest[0], fork_digest[1], fork_digest[2], fork_digest[3],
        });
    }

    const peer_status = sendStatus(self, io, svc, peer_id) catch |err| {
        std.log.warn("Status exchange failed: {}", .{err});
        return;
    };

    if (self.sync_service_inst) |sync_svc| {
        sync_svc.onPeerStatus(peer_id, peer_status) catch |err| {
            std.log.warn("SyncService.onPeerStatus failed: {}", .{err});
        };
    }
    self.unknown_chain_sync.onPeerConnected(peer_id, peer_status.head_root) catch {};

    processSyncBatches(self, io, svc);

    const GossipsubHandler = @import("zig-libp2p").gossipsub.Handler;
    svc.newStream(io, peer_id, GossipsubHandler, null) catch |err| {
        std.log.warn("Failed to open outbound gossipsub stream: {}", .{err});
    };
    std.log.info("Opened outbound gossipsub stream to peer", .{});
}

fn parseIp4(s: []const u8) ?[4]u8 {
    var result: [4]u8 = undefined;
    var octet_idx: usize = 0;
    var segment_start: usize = 0;
    for (s, 0..) |c, i| {
        if (c == '.') {
            if (octet_idx >= 3) return null;
            result[octet_idx] = std.fmt.parseInt(u8, s[segment_start..i], 10) catch return null;
            octet_idx += 1;
            segment_start = i + 1;
        }
    }
    if (octet_idx != 3) return null;
    result[3] = std.fmt.parseInt(u8, s[segment_start..], 10) catch return null;
    return result;
}

fn initDiscoveryService(self: *BeaconNode) !void {
    const fork_digest = self.config.forkDigestAtSlot(
        self.head_tracker.head_slot,
        self.genesis_validators_root,
    );

    const ds = try self.allocator.create(DiscoveryService);
    errdefer self.allocator.destroy(ds);
    const disc_port = self.node_options.discovery_port orelse self.node_options.p2p_port;
    const local_ip = parseIp4(self.node_options.p2p_host) orelse [4]u8{ 0, 0, 0, 0 };

    ds.* = try DiscoveryService.init(self.io, self.allocator, .{
        .listen_port = disc_port,
        .secret_key = self.node_identity.secret_key,
        .local_ip = local_ip,
        .p2p_port = self.node_options.p2p_port,
        .fork_digest = fork_digest,
        .target_peers = self.node_options.target_peers,
        .cli_bootnodes = self.bootnodes,
    });

    ds.seedBootnodes();
    self.discovery_service = ds;
    try refreshApiNodeIdentityFromDiscovery(self, ds);

    std.log.info("Discovery service initialized (known_peers={d})", .{ds.knownPeerCount()});
}

fn refreshApiNodeIdentityFromDiscovery(self: *BeaconNode, ds: *DiscoveryService) !void {
    self.api_node_identity.metadata.seq_number = ds.enr_seq;

    const raw_enr = ds.local_enr orelse return;
    const encoded_len = std.base64.url_safe_no_pad.Encoder.calcSize(raw_enr.len);
    const enr_buf = try self.allocator.alloc(u8, 4 + encoded_len);
    errdefer self.allocator.free(enr_buf);

    @memcpy(enr_buf[0..4], "enr:");
    _ = std.base64.url_safe_no_pad.Encoder.encode(enr_buf[4..], raw_enr);

    if (self.api_node_identity.enr.len > 0) {
        self.allocator.free(self.api_node_identity.enr);
    }
    self.api_node_identity.enr = enr_buf;
}

fn initPeerManager(self: *BeaconNode) !void {
    const pm = try self.allocator.create(PeerManager);
    errdefer self.allocator.destroy(pm);
    pm.* = PeerManager.init(self.allocator, .{
        .target_peers = self.node_options.target_peers,
    });
    self.peer_manager = pm;
    std.log.info("Peer manager initialized (target_peers={d})", .{pm.config.target_peers});
}

fn initSyncPipeline(self: *BeaconNode) !void {
    const cb_ctx = try self.allocator.create(SyncCallbackCtx);
    cb_ctx.* = .{ .node = self };
    self.sync_callback_ctx = cb_ctx;

    const sync_svc = try self.allocator.create(SyncService);
    sync_svc.* = SyncService.init(
        self.allocator,
        cb_ctx.syncServiceCallbacks(),
        self.head_tracker.head_slot,
        0,
    );
    self.sync_service_inst = sync_svc;

    std.log.info("Sync pipeline initialized (head_slot={d})", .{self.head_tracker.head_slot});
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

    var stream = try svc.dialProtocol(io, peer_id, protocol_id);
    defer closeOwnedQuicStream(io, &stream);

    try req_resp_encoding.writeRequestToStream(self.allocator, io, &stream, &root);
    stream.closeWrite(io);

    var reader = req_resp_encoding.ResponseChunkStreamReader{
        .allocator = self.allocator,
        .has_context_bytes = true,
    };
    defer reader.deinit();

    const decoded = (try reader.next(io, &stream)) orelse return error.NoBlockReturned;
    if (decoded.result != .success) {
        self.allocator.free(decoded.ssz_bytes);
        return error.ErrorResponse;
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

    var stream = try svc.dialProtocol(io, peer_id, protocol_id);
    defer closeOwnedQuicStream(io, &stream);

    const request = networking.messages.BeaconBlocksByRangeRequest.Type{
        .start_slot = start_slot,
        .count = count,
    };
    var req_ssz: [networking.messages.BeaconBlocksByRangeRequest.fixed_size]u8 = undefined;
    _ = networking.messages.BeaconBlocksByRangeRequest.serializeIntoBytes(&request, &req_ssz);
    try req_resp_encoding.writeRequestToStream(self.allocator, io, &stream, &req_ssz);
    stream.closeWrite(io);

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

    while (blocks_received < count) {
        const decoded = (try reader.next(io, &stream)) orelse break;
        if (decoded.result != .success) {
            self.allocator.free(decoded.ssz_bytes);
            break;
        }

        const slot = if (decoded.ssz_bytes.len >= 108)
            std.mem.readInt(u64, decoded.ssz_bytes[100..108], .little)
        else
            start_slot + blocks_received;

        try result.append(self.allocator, .{
            .slot = slot,
            .block_bytes = decoded.ssz_bytes,
        });
        blocks_received += 1;
    }

    return result.toOwnedSlice(self.allocator);
}

fn sendStatus(
    self: *BeaconNode,
    io: std.Io,
    svc: *networking.P2pService,
    peer_id: []const u8,
) !networking.messages.StatusMessage.Type {
    const status_protocol_id = "/eth2/beacon_chain/req/status/1/ssz_snappy";
    const req_resp_encoding = networking.req_resp_encoding;

    var stream = try svc.dialProtocol(io, peer_id, status_protocol_id);
    defer closeOwnedQuicStream(io, &stream);

    var status_ssz: [networking.messages.StatusMessage.fixed_size]u8 = undefined;
    const our_status = self.getStatus();
    _ = networking.messages.StatusMessage.serializeIntoBytes(&our_status, &status_ssz);
    std.log.info("Sending Status: fork_digest={x:0>2}{x:0>2}{x:0>2}{x:0>2} head_slot={d} finalized_epoch={d}", .{
        our_status.fork_digest[0],
        our_status.fork_digest[1],
        our_status.fork_digest[2],
        our_status.fork_digest[3],
        our_status.head_slot,
        our_status.finalized_epoch,
    });

    try req_resp_encoding.writeRequestToStream(self.allocator, io, &stream, &status_ssz);
    stream.closeWrite(io);

    var reader = req_resp_encoding.ResponseChunkStreamReader{
        .allocator = self.allocator,
        .has_context_bytes = false,
    };
    defer reader.deinit();

    const decoded = (try reader.next(io, &stream)) orelse {
        std.log.warn("Status: peer sent empty response", .{});
        return error.EmptyResponse;
    };
    defer self.allocator.free(decoded.ssz_bytes);

    if (decoded.result != .success) {
        std.log.warn("Status response: error code {}", .{decoded.result});
        return error.StatusRejected;
    }

    var peer_status: networking.messages.StatusMessage.Type = undefined;
    networking.messages.StatusMessage.deserializeFromBytes(decoded.ssz_bytes, &peer_status) catch |err| {
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

    return peer_status;
}

fn initGossipHandler(self: *BeaconNode) void {
    if (self.gossip_handler != null) return;

    const callbacks = gossip_node_callbacks_mod;
    self.gossip_handler = GossipHandler.create(
        self.allocator,
        @ptrCast(self),
        &callbacks.importBlockFromGossip,
        &callbacks.getProposerIndex,
        &callbacks.isKnownBlockRoot,
        &callbacks.getValidatorCount,
    ) catch |err| {
        std.log.warn("Failed to create GossipHandler: {}", .{err});
        return;
    };

    if (self.gossip_handler) |gh| {
        gh.importAttestationFn = &callbacks.importAttestation;
        gh.importVoluntaryExitFn = &callbacks.importVoluntaryExit;
        gh.importProposerSlashingFn = &callbacks.importProposerSlashing;
        gh.importAttesterSlashingFn = &callbacks.importAttesterSlashing;
        gh.importBlsChangeFn = &callbacks.importBlsChange;

        gh.verifyBlockSignatureFn = &callbacks.verifyBlockSignature;
        gh.verifyVoluntaryExitSignatureFn = &callbacks.verifyVoluntaryExitSignature;
        gh.verifyProposerSlashingSignatureFn = &callbacks.verifyProposerSlashingSignature;
        gh.verifyAttesterSlashingSignatureFn = &callbacks.verifyAttesterSlashingSignature;
        gh.verifyBlsChangeSignatureFn = &callbacks.verifyBlsChangeSignature;
        gh.verifyAttestationSignatureFn = &callbacks.verifyAttestationSignature;
        gh.verifyAggregateSignatureFn = &callbacks.verifyAggregateSignature;
        gh.verifySyncCommitteeSignatureFn = &callbacks.verifySyncCommitteeSignature;

        gh.importSyncContributionFn = &callbacks.importSyncContribution;
        gh.importSyncCommitteeMessageFn = &callbacks.importSyncCommitteeMessage;

        gh.metrics = self.metrics;
        gh.beacon_processor = self.beacon_processor;
    }
}

fn processGossipEvents(self: *BeaconNode, io: std.Io, p2p: anytype) void {
    const events = p2p.gossipsub.drainEvents() catch &.{};
    defer self.allocator.free(events);
    processGossipEventsFromSlice(self, io, events);
}

fn processGossipEventsFromSlice(self: *BeaconNode, io: std.Io, events: anytype) void {
    const gossip_topics = networking.gossip_topics;
    const gossip_decoding = networking.gossip_decoding;

    for (events) |event| {
        switch (event) {
            .message => |msg| {
                const metadata = GossipIngressMetadata{
                    .peer_id = hashOpaqueGossipBytes(0x70656572, msg.from),
                    .message_id = networking.computeGossipMessageId(self.allocator, msg.data) catch std.mem.zeroes(networking.GossipMessageId),
                    .seen_timestamp_ns = currentUnixTimeNs(io),
                };

                const parsed = gossip_topics.parseTopic(msg.topic) orelse continue;
                switch (parsed.topic_type) {
                    .beacon_block => handleGossipBlock(self, gossip_decoding, msg.data, metadata),
                    .data_column_sidecar => handleGossipDataColumn(self, gossip_decoding, msg.data, parsed.subnet_id),
                    else => {
                        if (self.gossip_handler) |gh| {
                            const slot = self.head_tracker.head_slot;
                            gh.updateClock(slot, computeEpochAtSlot(slot), self.head_tracker.finalized_epoch * preset.SLOTS_PER_EPOCH);
                            gh.onGossipMessageWithSubnetAndMetadata(parsed.topic_type, parsed.subnet_id, msg.data, metadata) catch |err| {
                                switch (err) {
                                    error.ValidationIgnored => {},
                                    error.ValidationRejected => {
                                        std.log.debug("Gossip {s} rejected", .{parsed.topic_type.topicName()});
                                    },
                                    error.DecodeFailed => {
                                        std.log.debug("Gossip {s} decode failed", .{parsed.topic_type.topicName()});
                                    },
                                    else => {
                                        std.log.warn("Gossip {s} error: {}", .{ parsed.topic_type.topicName(), err });
                                    },
                                }
                            };
                        }
                    },
                }
            },
            else => {},
        }
    }
}

fn handleGossipBlock(
    self: *BeaconNode,
    gossip_decoding: anytype,
    data: []const u8,
    metadata: GossipIngressMetadata,
) void {
    const ssz_bytes = gossip_decoding.decompressGossipPayload(
        self.allocator,
        data,
        gossip_decoding.MAX_GOSSIP_SIZE_BEACON_BLOCK,
    ) catch {
        std.log.warn("Gossip: failed to decompress block", .{});
        return;
    };

    const fork_seq = self.config.forkSeq(self.head_tracker.head_slot);
    const any_signed = AnySignedBeaconBlock.deserialize(
        self.allocator,
        .full,
        fork_seq,
        ssz_bytes,
    ) catch |err| {
        self.allocator.free(ssz_bytes);
        std.log.warn("Gossip block deserialize: {}", .{err});
        return;
    };

    if (self.beacon_processor) |bp| {
        self.allocator.free(ssz_bytes);
        bp.ingest(.{ .gossip_block = .{
            .peer_id = metadata.peer_id,
            .message_id = metadata.message_id,
            .block = any_signed,
            .seen_timestamp_ns = metadata.seen_timestamp_ns,
        } });
        return;
    }

    defer self.allocator.free(ssz_bytes);
    defer any_signed.deinit(self.allocator);

    const result = self.importBlock(any_signed, .gossip) catch |err| {
        if (err == error.UnknownParentBlock) {
            self.queueOrphanBlock(any_signed, ssz_bytes);
        } else if (err != error.BlockAlreadyKnown and err != error.BlockAlreadyFinalized) {
            std.log.warn("Gossip block import: {}", .{err});
        }
        return;
    };
    self.processPendingChildren(result.block_root);
    std.log.info("GOSSIP BLOCK IMPORTED slot={d} root={x:0>2}{x:0>2}{x:0>2}{x:0>2}...", .{
        result.slot,
        result.block_root[0],
        result.block_root[1],
        result.block_root[2],
        result.block_root[3],
    });
}

fn handleGossipDataColumn(
    self: *BeaconNode,
    gossip_decoding_mod: anytype,
    data: []const u8,
    subnet_id: ?u8,
) void {
    _ = subnet_id;
    const ssz_bytes = gossip_decoding_mod.decompressGossipPayload(
        self.allocator,
        data,
        gossip_decoding_mod.MAX_GOSSIP_SIZE_DEFAULT,
    ) catch {
        std.log.warn("Gossip: failed to decompress data column sidecar", .{});
        return;
    };
    defer self.allocator.free(ssz_bytes);

    var sidecar = types.fulu.DataColumnSidecar.default_value;
    types.fulu.DataColumnSidecar.deserializeFromBytes(self.allocator, ssz_bytes, &sidecar) catch |err| {
        std.log.warn("Gossip: failed to decode data column sidecar: {}", .{err});
        return;
    };
    defer types.fulu.DataColumnSidecar.deinit(self.allocator, &sidecar);

    const column_index = sidecar.index;
    var block_root: [32]u8 = undefined;
    types.phase0.BeaconBlockHeader.hashTreeRoot(&sidecar.signed_block_header.message, &block_root) catch |err| {
        std.log.warn("Gossip: failed to hash data column block header: {}", .{err});
        return;
    };

    self.importDataColumnSidecar(block_root, column_index, ssz_bytes) catch |err| {
        std.log.warn("Gossip data column import error: {}", .{err});
    };
}

fn currentUnixTimeNs(io: std.Io) i64 {
    const ns = std.Io.Timestamp.now(io, .real).toNanoseconds();
    return if (ns > std.math.maxInt(i64))
        std.math.maxInt(i64)
    else if (ns < std.math.minInt(i64))
        std.math.minInt(i64)
    else
        @intCast(ns);
}

fn hashOpaqueGossipBytes(seed: u64, maybe_bytes: ?[]const u8) u64 {
    const bytes = maybe_bytes orelse return 0;
    return std.hash.Wyhash.hash(seed, bytes);
}

fn maybePrepareProposerPayload(self: *BeaconNode, io: std.Io) void {
    const clock = self.clock orelse return;
    _ = self.engine_api orelse return;

    const current_slot = clock.currentSlot(io) orelse return;
    const next_slot = current_slot + 1;

    const head_state_root = self.head_tracker.head_state_root;
    const head_state = self.block_state_cache.get(head_state_root) orelse return;
    _ = head_state.epoch_cache.getBeaconProposer(next_slot) catch return;

    const fee_recipient = self.node_options.suggested_fee_recipient orelse return;
    if (self.cached_payload_id != null) return;

    const timestamp = clock.slotStartSeconds(next_slot);
    const next_epoch = next_slot / preset.SLOTS_PER_EPOCH;
    const randao_index = next_epoch % preset.EPOCHS_PER_HISTORICAL_VECTOR;
    const prev_randao: [32]u8 = blk: {
        var mixes = head_state.state.randaoMixes() catch break :blk [_]u8{0} ** 32;
        const mix_ptr = mixes.getFieldRoot(randao_index) catch break :blk [_]u8{0} ** 32;
        break :blk mix_ptr.*;
    };

    self.preparePayload(
        timestamp,
        prev_randao,
        fee_recipient,
        &.{},
        self.head_tracker.head_root,
    ) catch |err| {
        std.log.warn("W7: preparePayload failed for slot {d}: {}", .{ next_slot, err });
    };
}

const beacon_node_mod = @import("beacon_node.zig");
const BeaconNode = beacon_node_mod.BeaconNode;
