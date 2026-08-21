const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("consensus_types");
const BeaconState = @import("fork_types").BeaconState;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const BeaconConfig = @import("config").BeaconConfig;
const isValidIndexedPayloadAttestation = @import("./is_valid_indexed_payload_attestation.zig").isValidIndexedPayloadAttestation;

pub fn processPayloadAttestation(
    allocator: Allocator,
    io: std.Io,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: *BeaconState(.gloas),
    payload_attestation: *const types.gloas.PayloadAttestation.Type,
) !void {
    const data = &payload_attestation.data;

    var latest_block_header = try state.latestBlockHeader();
    const parent_root = try latest_block_header.getFieldRoot("parent_root");
    if (!std.mem.eql(u8, &data.beacon_block_root, parent_root)) {
        return error.PayloadAttestationWrongBlock;
    }

    if (data.slot + 1 != try state.slot()) {
        return error.PayloadAttestationNotFromPreviousSlot;
    }

    var indexed_payload_attestation = try epoch_cache.getIndexedPayloadAttestation(allocator, state, data.slot, payload_attestation);
    defer indexed_payload_attestation.attesting_indices.deinit(allocator);

    if (!(try isValidIndexedPayloadAttestation(allocator, io, config, epoch_cache, &indexed_payload_attestation, true))) {
        return error.InvalidPayloadAttestation;
    }
}

const Node = @import("persistent_merkle_tree").Node;
const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
const DoubleFreeDetectAllocator = @import("testing_allocators").DoubleFreeDetectAllocator;

test "Gloas payload attestation - OOM does not double-free indexed data" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 500_000 });
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.initGloas(allocator, &pool, 256);
    defer test_state.deinit();
    const state = test_state.cached_state.state.castToFork(.gloas);

    var latest_block_header = try state.latestBlockHeader();
    var payload_attestation = types.gloas.PayloadAttestation.default_value;
    payload_attestation.data.slot = (try state.slot()) - 1;
    payload_attestation.data.beacon_block_root = (try latest_block_header.getFieldRoot("parent_root")).*;
    try payload_attestation.aggregation_bits.set(0, true);

    var saw_oom = false;
    var saw_terminal_result = false;
    var fail_at: usize = 0;
    while (fail_at < 64) : (fail_at += 1) {
        var oom = DoubleFreeDetectAllocator.init(std.testing.allocator, fail_at);
        defer oom.deinit();

        processPayloadAttestation(
            oom.allocator(),
            std.testing.io,
            test_state.cached_state.config,
            test_state.cached_state.epoch_cache,
            state,
            &payload_attestation,
        ) catch |err| switch (err) {
            error.OutOfMemory => {
                saw_oom = true;
                try std.testing.expect(!oom.double_free);
                continue;
            },
            else => {
                try std.testing.expect(!oom.double_free);
                saw_terminal_result = true;
                break;
            },
        };

        try std.testing.expect(!oom.double_free);
        saw_terminal_result = true;
        break;
    }

    try std.testing.expect(saw_oom);
    try std.testing.expect(saw_terminal_result);
}
