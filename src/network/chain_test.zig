const std = @import("std");
const config = @import("config");
const preset = @import("preset");
const constants = @import("constants");
const chain = @import("chain.zig");
const topics = @import("gossipsub/topic_policy.zig");
const rr = @import("reqresp/ReqResp.zig");

fn fixture() config.ChainConfig {
    var result = if (preset.active_preset == .minimal) config.minimal.chain_config else config.mainnet.chain_config;
    result.ALTAIR_FORK_EPOCH = 0;
    result.BELLATRIX_FORK_EPOCH = 0;
    result.CAPELLA_FORK_EPOCH = 0;
    result.DENEB_FORK_EPOCH = 0;
    result.ELECTRA_FORK_EPOCH = 2;
    result.FULU_FORK_EPOCH = 3;
    result.GLOAS_FORK_EPOCH = constants.FAR_FUTURE_EPOCH;
    result.BLOB_SCHEDULE = &.{ .{ .EPOCH = 3, .MAX_BLOBS_PER_BLOCK = 33 }, .{ .EPOCH = 8, .MAX_BLOBS_PER_BLOCK = 40 } };
    return result;
}

test "network chain resolves same epoch forks BPO contexts and clock identity" {
    var cfg = config.BeaconConfig.init(fixture(), @splat(1));
    const plan = try chain.Plan.init(&cfg, false);
    try std.testing.expectEqual(@as(u8, 4), plan.boundary_count);
    try std.testing.expectEqual(@as(?[4]u8, null), plan.phase0_digest);
    const local: @import("peers/types.zig").LocalState = .{ .metadata = .{ .custody_group_count = 8 }, .status = .{ .head_slot = 1, .earliest_available_slot = 0 } };
    const genesis = try plan.update(local, null, 0);
    try std.testing.expectEqual(.deneb, genesis.local.fork.fork);
    try std.testing.expectEqual(@as(u64, 2), genesis.schedule.next_epoch);
    const fulu = try plan.update(local, null, 3 * preset.preset.SLOTS_PER_EPOCH);
    try std.testing.expectEqual(.fulu, fulu.local.fork.fork);
    try std.testing.expectEqual(cfg.chain.CUSTODY_REQUIREMENT, fulu.local.fork.custody_requirement);
    try std.testing.expectEqual(@as(u16, 0), genesis.local.fork.custody_requirement);
    try std.testing.expectEqual(@as(u64, 1), fulu.local.status.head_slot);
    try std.testing.expectEqual(config.fork_digest.computeForkDigest(&cfg, 3), fulu.local.status.fork_digest);
    try std.testing.expectEqual(cfg.chain.FULU_FORK_VERSION, fulu.schedule.next_version);
    try std.testing.expectEqual(@as(u64, 8), fulu.schedule.next_epoch);
    try std.testing.expectEqual(config.fork_digest.computeForkDigest(&cfg, 8), fulu.schedule.next_digest);
    try std.testing.expect(fulu.capabilities.request.contains(.{ .reqresp = .light_client_bootstrap_v1 }));
    try std.testing.expect(!fulu.capabilities.receive.contains(.{ .reqresp = .light_client_bootstrap_v1 }));
    const bpo = try plan.update(local, null, 8 * preset.preset.SLOTS_PER_EPOCH);
    try std.testing.expectEqual(.fulu, bpo.local.fork.fork);
    try std.testing.expect(!std.mem.eql(u8, &fulu.local.fork.digest, &bpo.local.fork.digest));
    try std.testing.expectEqual(fulu.local.fork.digest, plan.forks[2].digest);
    try std.testing.expectEqual(bpo.local.fork.digest, plan.forks[3].digest);
    try std.testing.expectEqual(.deneb, plan.topics[0].fork.?);
    try std.testing.expectEqual(@as(u64, 0), plan.topics[0].epoch);
    try std.testing.expectEqual(.fulu, plan.topics[2].fork.?);
    try std.testing.expectEqual(@as(u64, 3), plan.topics[2].epoch);
    try std.testing.expectEqual(.fulu, plan.topics[3].fork.?);
    try std.testing.expectEqual(@as(u64, 8), plan.topics[3].epoch);
    try std.testing.expectEqual(constants.FAR_FUTURE_EPOCH, bpo.schedule.next_epoch);
    try std.testing.expectEqualDeep(bpo, try plan.update(local, null, 11 * preset.preset.SLOTS_PER_EPOCH));
    cfg = config.BeaconConfig.init(fixture(), @splat(2));
    try std.testing.expectEqualDeep(fulu, try plan.update(local, null, 3 * preset.preset.SLOTS_PER_EPOCH));
}

test "network chain rejects every scheduled unsupported fork at startup" {
    for ([_]u64{ 0, 3, 8, constants.FAR_FUTURE_EPOCH - 1 }) |epoch| {
        var input = fixture();
        input.ELECTRA_FORK_EPOCH = 0;
        input.FULU_FORK_EPOCH = 0;
        input.GLOAS_FORK_EPOCH = epoch;
        const cfg = config.BeaconConfig.init(input, @splat(0));
        try std.testing.expectError(error.UnsupportedNetworkFork, chain.Plan.init(&cfg, false));
    }
}

test "network chain derives fixed request storage and historical blob limits independently of BPO" {
    const cfg = config.BeaconConfig.init(fixture(), @splat(0));
    const plan = try chain.Plan.init(&cfg, true);
    try std.testing.expectEqual(@as(usize, 768 * 40), plan.policy.requestBounds(.blob_sidecars_by_root_v1, .deneb).request_max);
    try std.testing.expectEqual(@as(usize, 1152 * 40), plan.policy.requestBounds(.blob_sidecars_by_root_v1, .fulu).request_max);
    const maximum = 128 * (40 + 8 * preset.NUMBER_OF_COLUMNS);
    try std.testing.expectEqual(@as(usize, maximum), plan.policy.requestMax());
    const policy = plan.requestPolicy();
    var requests = try rr.init(std.testing.allocator, .{ .forks = plan.forks[0..plan.boundary_count], .admission = try rr.Options.Admission.defaults(&policy, 8, 2, 6), .inbound_max = 8, .inbound_control_reserved = 2, .inbound_per_peer_max = 8 });
    defer requests.deinit();
    const bytes = requests.memoryPlan().total_bytes;
    for ([_]config.ForkSeq{ .deneb, .electra, .fulu }) |fork| {
        requests.setRequestFork(fork);
        try std.testing.expectEqual(bytes, requests.memoryPlan().total_bytes);
    }
    var range = [_]u8{0} ** 16;
    std.mem.writeInt(u64, range[0..8], 3 * preset.preset.SLOTS_PER_EPOCH, .little);
    std.mem.writeInt(u64, range[8..16], 128, .little);
    try std.testing.expectEqual(@as(u32, 0), (try plan.policy.inspect(.blob_sidecars_by_range_v1, &range, .fulu)).chunks_max);
    const fulu_topics = plan.topics[2].rules;
    try std.testing.expectEqual(@as(u16, 0), fulu_topics[@intFromEnum(topics.Kind.blob_sidecar)].count);
    try std.testing.expectEqual(@as(u16, 128), fulu_topics[@intFromEnum(topics.Kind.data_column_sidecar)].count);
}

test "network chain validates schedule and chain namespace before owner allocation" {
    var input = fixture();
    input.ELECTRA_FORK_EPOCH = 4;
    var cfg = config.BeaconConfig.init(input, @splat(0));
    try std.testing.expectError(error.InvalidNetworkChain, chain.Plan.init(&cfg, false));
    input = fixture();
    input.BLOB_SCHEDULE = &.{ .{ .EPOCH = 5, .MAX_BLOBS_PER_BLOCK = 40 }, .{ .EPOCH = 3, .MAX_BLOBS_PER_BLOCK = 33 } };
    cfg = config.BeaconConfig.init(input, @splat(0));
    try std.testing.expectError(error.InvalidNetworkChain, chain.Plan.init(&cfg, false));
    input = fixture();
    input.DATA_COLUMN_SIDECAR_SUBNET_COUNT = 129;
    cfg = config.BeaconConfig.init(input, @splat(0));
    try std.testing.expectError(error.InvalidTopicPolicy, chain.Plan.init(&cfg, false));
}

test "network chain honors configured wire limits and requires complete metadata before unscheduled Fulu" {
    var input = fixture();
    input.FULU_FORK_EPOCH = @import("constants").FAR_FUTURE_EPOCH;
    input.GLOAS_FORK_EPOCH = @import("constants").FAR_FUTURE_EPOCH;
    input.BLOB_SCHEDULE = &.{};
    input.MAX_REQUEST_BLOCKS = 16;
    input.MAX_REQUEST_BLOCKS_DENEB = 8;
    input.MAX_REQUEST_BLOB_SIDECARS = 2;
    input.MAX_REQUEST_BLOB_SIDECARS_ELECTRA = 3;
    input.MAX_PAYLOAD_SIZE = 1024 * 1024;
    const cfg = config.BeaconConfig.init(input, @splat(0));
    const plan = try chain.Plan.init(&cfg, false);
    try std.testing.expectError(error.MissingCustodyAdvertisement, plan.update(.{}, null, 0));
    const update = try plan.update(.{ .metadata = .{ .custody_group_count = 1 } }, null, 0);
    try std.testing.expect(update.capabilities.receive.contains(.{ .reqresp = .metadata_v3 }));
    const wire = @import("control_wire.zig");
    var encoded: [25]u8 = undefined;
    try std.testing.expectEqual(encoded.len, try wire.encodeMetadata(.metadata_v3, &update.local.metadata, update.local.fork, &encoded));
    try std.testing.expectEqualDeep(update.local.metadata, try wire.decodeMetadata(.metadata_v3, &encoded, update.local.fork));
    const policy = plan.requestPolicy();
    var requests = try rr.init(std.testing.allocator, .{ .forks = plan.forks[0..plan.boundary_count], .admission = try rr.Options.Admission.defaults(&policy, 8, 2, 64) });
    defer requests.deinit();
    try std.testing.expectEqual(@as(usize, 1024 * 1024), (try requests.responseBounds(.blocks_by_root_v2, .deneb)).max);
    requests.setRequestFork(.deneb);
    try std.testing.expectEqual(@as(usize, 80), requests.requestBounds(.blob_sidecars_by_root_v1).request_max);
    requests.setRequestFork(.electra);
    try std.testing.expectEqual(@as(usize, 120), requests.requestBounds(.blob_sidecars_by_root_v1).request_max);
    input.MAX_REQUEST_BLOCKS_DENEB = 128;
    input.MAX_PAYLOAD_SIZE = @import("consensus_types").deneb.BlobSidecar.fixed_size;
    const small_cfg = config.BeaconConfig.init(input, @splat(0));
    const small = try chain.Plan.init(&small_cfg, false);
    try std.testing.expectEqual(@as(usize, input.MAX_PAYLOAD_SIZE), small.policy.requestMax());
    try std.testing.expectEqual(@as(usize, input.MAX_PAYLOAD_SIZE), small.policy.requestBounds(.data_column_sidecars_by_root_v1, .fulu).request_max);
}

fn fuluSchedule() config.ChainConfig {
    var input = fixture();
    input.ELECTRA_FORK_EPOCH = 0;
    input.FULU_FORK_EPOCH = 0;
    input.BLOB_SCHEDULE = &.{ .{ .EPOCH = 10, .MAX_BLOBS_PER_BLOCK = 33 }, .{ .EPOCH = 11, .MAX_BLOBS_PER_BLOCK = 40 } };
    return input;
}

test "network chain rejects dense supported BPO demand before the future overlap" {
    for ([_]bool{ false, true }) |light_clients| {
        const cfg = config.BeaconConfig.init(fuluSchedule(), @splat(0));
        try std.testing.expectError(error.UnsupportedTopicOverlap, chain.Plan.init(&cfg, light_clients));
    }
    var input = fixture();
    input.BLOB_SCHEDULE = &.{ .{ .EPOCH = 3, .MAX_BLOBS_PER_BLOCK = 33 }, .{ .EPOCH = 5, .MAX_BLOBS_PER_BLOCK = 40 } };
    const cfg = config.BeaconConfig.init(input, @splat(0));
    try std.testing.expectError(error.UnsupportedTopicOverlap, chain.Plan.init(&cfg, true));
}

test "network chain scheduled topic demand accepts exact capacity and rejects one extra" {
    for ([_]bool{ false, true }) |light_clients| {
        var input = fuluSchedule();
        input.ELECTRA_FORK_EPOCH = 10;
        input.FULU_FORK_EPOCH = 10;
        input.BLOB_SIDECAR_SUBNET_COUNT = if (light_clients) 25 else 31;
        var cfg = config.BeaconConfig.init(input, @splat(0));
        const plan = try chain.Plan.init(&cfg, light_clients);
        try std.testing.expectEqual(@as(u8, 3), plan.boundary_count);
        var demand: usize = 0;
        for (plan.topics[0..plan.boundary_count]) |boundary| for (boundary.rules, 0..) |rule, k| {
            const kind: topics.Kind = @enumFromInt(k);
            if (!light_clients and (kind == .light_client_finality_update or kind == .light_client_optimistic_update)) continue;
            demand += rule.count;
        };
        try std.testing.expectEqual(@as(usize, 512), demand);
        input.BLOB_SIDECAR_SUBNET_COUNT += 1;
        cfg = config.BeaconConfig.init(input, @splat(0));
        try std.testing.expectError(error.UnsupportedTopicOverlap, chain.Plan.init(&cfg, light_clients));
    }
}

test "network chain live demand permits replacements at the same removal epoch" {
    var input = fuluSchedule();
    input.BLOB_SCHEDULE = &.{ .{ .EPOCH = 10, .MAX_BLOBS_PER_BLOCK = 33 }, .{ .EPOCH = 13, .MAX_BLOBS_PER_BLOCK = 40 } };
    var cfg = config.BeaconConfig.init(input, @splat(0));
    try std.testing.expectError(error.UnsupportedTopicOverlap, chain.Plan.init(&cfg, true));
    input.BLOB_SCHEDULE = &.{ .{ .EPOCH = 10, .MAX_BLOBS_PER_BLOCK = 33 }, .{ .EPOCH = 14, .MAX_BLOBS_PER_BLOCK = 40 } };
    cfg = config.BeaconConfig.init(input, @splat(0));
    _ = try chain.Plan.init(&cfg, true);
}

test "network chain uses configured topic demand and imposes no lifetime namespace cap" {
    var input = fuluSchedule();
    input.DATA_COLUMN_SIDECAR_SUBNET_COUNT = 93;
    var cfg = config.BeaconConfig.init(input, @splat(0));
    _ = try chain.Plan.init(&cfg, true);
    input.DATA_COLUMN_SIDECAR_SUBNET_COUNT = 94;
    cfg = config.BeaconConfig.init(input, @splat(0));
    try std.testing.expectError(error.UnsupportedTopicOverlap, chain.Plan.init(&cfg, true));
    _ = try chain.Plan.init(&cfg, false);
    input = fuluSchedule();
    input.BLOB_SCHEDULE = &.{ .{ .EPOCH = 10, .MAX_BLOBS_PER_BLOCK = 33 }, .{ .EPOCH = 110, .MAX_BLOBS_PER_BLOCK = 40 }, .{ .EPOCH = 210, .MAX_BLOBS_PER_BLOCK = 48 } };
    cfg = config.BeaconConfig.init(input, @splat(0));
    const plan = try chain.Plan.init(&cfg, true);
    try std.testing.expectEqual(@as(u16, 820), try topics.validate(plan.topics[0..plan.boundary_count]));
    input.BLOB_SCHEDULE = &.{.{ .EPOCH = 0, .MAX_BLOBS_PER_BLOCK = 33 }};
    cfg = config.BeaconConfig.init(input, @splat(0));
    try std.testing.expectEqual(@as(u8, 1), (try chain.Plan.init(&cfg, true)).boundary_count);
}

const gossip = @import("gossipsub/root.zig");

fn initScheduledGossip(plan: *const chain.Plan) !gossip.Gossipsub {
    return gossip.Gossipsub.init(std.testing.allocator, .{
        .random_seed = 1,
        .connected_capacity = 2,
        .retained_capacity = 4,
        .retained_outbound_reserve = 1,
        .seen_capacity = 16,
        .mcache_capacity = 16,
        .validation_capacity = 8,
        .topic_policy = plan.topics[0..plan.boundary_count],
    });
}

fn applyScheduled(g: *gossip.Gossipsub, plan: *const chain.Plan, epoch: u64) !usize {
    var desired: [chain.boundary_max]gossip.local_intent.Boundary = undefined;
    var count: usize = 0;
    for (plan.topics[0..plan.boundary_count], 0..) |boundary, i| {
        if (epoch < boundary.epoch -| 2 or (i + 1 < plan.boundary_count and epoch >= plan.boundaries[i + 1].epoch +| 2)) continue;
        desired[count] = .{ .digest = boundary.digest };
        for (boundary.rules, 0..) |rule, k| {
            const kind: topics.Kind = @enumFromInt(k);
            if (!plan.serve_light_clients and (kind == .light_client_finality_update or kind == .light_client_optimistic_update)) continue;
            desired[count].lengths[k] = @intCast((rule.count + 7) / 8);
            for (0..rule.count) |subnet| desired[count].mask(kind)[subnet / 8] |= @as(u8, 1) << @intCast(subnet % 8);
        }
        count += 1;
    }
    var workspace = try gossip.local_intent.Workspace.init(std.testing.allocator, g.overlay.rows.len);
    defer workspace.deinit(std.testing.allocator);
    const slot = epoch * preset.preset.SLOTS_PER_EPOCH;
    if (try g.prepareSubscriptions(desired[0..count], &workspace, .{ .mono_ms = slot * 12_000, .unix_s = 0 }, slot)) g.commitSubscriptions(&workspace);
    return workspace.len;
}

test "network chain exact capacity schedule advances into the supported three digest overlap" {
    for ([_]bool{ false, true }) |light_clients| {
        var input = fuluSchedule();
        input.ELECTRA_FORK_EPOCH = 10;
        input.FULU_FORK_EPOCH = 10;
        input.BLOB_SIDECAR_SUBNET_COUNT = if (light_clients) 25 else 31;
        const cfg = config.BeaconConfig.init(input, @splat(0));
        const plan = try chain.Plan.init(&cfg, light_clients);
        var g = try initScheduledGossip(&plan);
        defer g.deinit();
        try std.testing.expectEqual(@as(usize, if (light_clients) 102 else 106), try applyScheduled(&g, &plan, 0));
        try std.testing.expectEqual(@as(usize, if (light_clients) 307 else 309), try applyScheduled(&g, &plan, 8));
        try std.testing.expectEqual(@as(usize, 512), try applyScheduled(&g, &plan, 9));
    }
}

test "network chain namespace capacity preserves retired scores and backoffs across transitions" {
    for ([_]u64{ 14, 16 }) |incoming_epoch| {
        for ([_]bool{ false, true }) |delayed| {
            var input = fuluSchedule();
            input.BLOB_SCHEDULE = &.{ .{ .EPOCH = 10, .MAX_BLOBS_PER_BLOCK = 33 }, .{ .EPOCH = incoming_epoch, .MAX_BLOBS_PER_BLOCK = 40 } };
            const cfg = config.BeaconConfig.init(input, @splat(0));
            const plan = try chain.Plan.init(&cfg, true);
            var g = try initScheduledGossip(&plan);
            defer g.deinit();
            try std.testing.expectEqual(@as(usize, 615), g.overlay.rows.len);
            try std.testing.expectEqual(@as(usize, 410), try applyScheduled(&g, &plan, 8));
            const peer = @import("gossipsub/test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
            const logical = g.sessions.rows[peer.index].logical;
            var generations: [205]u64 = undefined;
            for (g.overlay.rows[0..205], 0..) |row, i| {
                generations[i] = row.generation;
                g.peers.scores.invalid(logical.index, @intCast(i));
                g.peers.addBackoff(logical, @intCast(i), row.generation, 1_000_000_000, 60_000);
            }
            if (!delayed) try std.testing.expectEqual(@as(usize, if (incoming_epoch == 14) 410 else 205), try applyScheduled(&g, &plan, 12));
            try std.testing.expectEqual(@as(usize, 410), try applyScheduled(&g, &plan, incoming_epoch - 2));
            for (g.overlay.rows[0..205], 0..) |row, i| {
                try std.testing.expect(row.active and !row.subscribed);
                try std.testing.expectEqual(generations[i], row.generation);
                try std.testing.expectEqual(@as(f64, 1), g.peers.scores.topics[@as(usize, logical.index) * g.overlay.rows.len + i].invalid);
                try std.testing.expect(g.peers.backedOff(logical, @intCast(i), generations[i], 1_000_000_001));
            }
            var live: usize = 0;
            for (g.overlay.rows) |row| {
                try std.testing.expect(row.active);
                live += @intFromBool(row.subscribed);
            }
            try std.testing.expectEqual(@as(usize, 410), live);
        }
    }
}
