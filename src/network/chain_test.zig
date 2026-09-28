const std = @import("std");
const config = @import("config");
const preset = @import("preset");
const constants = @import("constants");
const chain = @import("chain.zig");
const topics = @import("gossipsub/topic_policy.zig");
const rr = @import("reqresp/reqresp.zig");

fn fixture() config.ChainConfig {
    var result = if (preset.active_preset == .minimal) config.minimal.chain_config else config.mainnet.chain_config;
    result.ALTAIR_FORK_EPOCH = 0;
    result.BELLATRIX_FORK_EPOCH = 0;
    result.CAPELLA_FORK_EPOCH = 0;
    result.DENEB_FORK_EPOCH = 0;
    result.ELECTRA_FORK_EPOCH = 2;
    result.FULU_FORK_EPOCH = 3;
    result.GLOAS_FORK_EPOCH = constants.FAR_FUTURE_EPOCH;
    result.BLOB_SCHEDULE = &.{ .{ .EPOCH = 3, .MAX_BLOBS_PER_BLOCK = 33 }, .{ .EPOCH = 5, .MAX_BLOBS_PER_BLOCK = 40 } };
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
    try std.testing.expectEqual(@as(u64, 5), fulu.schedule.next_epoch);
    try std.testing.expectEqual(config.fork_digest.computeForkDigest(&cfg, 5), fulu.schedule.next_digest);
    try std.testing.expect(fulu.capabilities.request.contains(.{ .reqresp = .light_client_bootstrap_v1 }));
    try std.testing.expect(!fulu.capabilities.receive.contains(.{ .reqresp = .light_client_bootstrap_v1 }));
    const bpo = try plan.update(local, null, 5 * preset.preset.SLOTS_PER_EPOCH);
    try std.testing.expectEqual(.fulu, bpo.local.fork.fork);
    try std.testing.expect(!std.mem.eql(u8, &fulu.local.fork.digest, &bpo.local.fork.digest));
    try std.testing.expectEqual(fulu.local.fork.digest, plan.forks[2].digest);
    try std.testing.expectEqual(bpo.local.fork.digest, plan.forks[3].digest);
    try std.testing.expectEqual(.deneb, plan.topics[0].fork.?);
    try std.testing.expectEqual(@as(u64, 0), plan.topics[0].epoch);
    try std.testing.expectEqual(.fulu, plan.topics[2].fork.?);
    try std.testing.expectEqual(@as(u64, 3), plan.topics[2].epoch);
    try std.testing.expectEqual(.fulu, plan.topics[3].fork.?);
    try std.testing.expectEqual(@as(u64, 5), plan.topics[3].epoch);
    try std.testing.expectEqual(constants.FAR_FUTURE_EPOCH, bpo.schedule.next_epoch);
    try std.testing.expectEqualDeep(bpo, try plan.update(local, null, 8 * preset.preset.SLOTS_PER_EPOCH));
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
    var requests = try rr.ReqResp.init(std.testing.allocator, .{ .forks = plan.forks[0..plan.boundary_count], .admission = try rr.AdmissionOptions.defaults(&policy, 8, 2, 6), .inbound_max = 8, .inbound_control_reserved = 2, .inbound_per_peer_max = 8 });
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
    var requests = try rr.ReqResp.init(std.testing.allocator, .{ .forks = plan.forks[0..plan.boundary_count], .admission = try rr.AdmissionOptions.defaults(&policy, 8, 2, 64) });
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
