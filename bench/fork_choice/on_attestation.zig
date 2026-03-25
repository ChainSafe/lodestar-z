//! Benchmark for fork-choice `onAttestation` operation.
//!
//! Measures how fast the fork choice can process indexed attestations.
//! Ported from the Lodestar TS `onAttestation.test.ts` benchmark.
//!
//! Setup: 600K validators, 64-block linear chain, 0 equivocated.
//!   - Unaggregated: 3 committees x 135 validators = 405 single-validator attestations.
//!   - Aggregated: 64 committees x 11 aggregators x 135 validators = 704 aggregated attestations.
//!   - Total: 1109 attestations per iteration.

const std = @import("std");
const zbench = @import("zbench");
const fork_choice = @import("fork_choice");
const consensus_types = @import("consensus_types");
const fork_types = @import("fork_types");

const ForkChoice = fork_choice.ForkChoiceStruct;
const AnyIndexedAttestation = fork_types.AnyIndexedAttestation;
const Phase0IndexedAttestation = consensus_types.phase0.IndexedAttestation.Type;

const util = @import("util.zig");

const ZERO_HASH = @import("constants").ZERO_HASH;

// ── Constants matching the TS benchmark ──

const UNAGG_COMMITTEES: u32 = 3;
const VALIDATORS_PER_COMMITTEE: u32 = 135;
const AGG_COMMITTEES: u32 = 64;
const AGGREGATORS_PER_COMMITTEE: u32 = 11;

const UNAGG_COUNT: u32 = UNAGG_COMMITTEES * VALIDATORS_PER_COMMITTEE; // 405
const AGG_COUNT: u32 = AGG_COMMITTEES * AGGREGATORS_PER_COMMITTEE; // 704
const TOTAL_ATT_COUNT: u32 = UNAGG_COUNT + AGG_COUNT; // 1109

/// Benchmark struct for onAttestation.
///
/// Pre-builds all 1109 attestations during setup so the benchmark loop
/// measures only `onAttestation` processing time.
const OnAttestationBench = struct {
    fc: *ForkChoice,
    phase0_atts: []Phase0IndexedAttestation,
    any_atts: []AnyIndexedAttestation,
    att_data_root: [32]u8,

    pub fn run(self: OnAttestationBench, allocator: std.mem.Allocator) void {
        for (self.any_atts) |*att| {
            self.fc.onAttestation(allocator, att, self.att_data_root, false) catch unreachable;
        }
    }
};

/// Build the OnAttestationBench instance.
///
/// 1. Initialize a ForkChoice with 600K validators and 64 blocks.
/// 2. Compute head via updateAndGetHead.
/// 3. Advance current_slot to 64 so attestations at slot 63 are past-slot.
/// 4. Pre-build 405 unaggregated + 704 aggregated attestations.
fn setupBench(allocator: std.mem.Allocator) !OnAttestationBench {
    const fc = try util.initializeForkChoice(allocator, .{
        .initial_block_count = 64,
        .initial_validator_count = 600_000,
        .initial_equivocated_count = 0,
    });

    // Compute head so fc.head is populated.
    _ = fc.updateAndGetHead(allocator, .{ .get_canonical_head = {} }) catch unreachable;

    // Advance store time so attestations at slot 63 are past-slot (immediate apply).
    fc.fcStore.current_slot = 64;

    // Head block root is the target for all attestations.
    const head_root = fc.head.block_root;

    // Attestation parameters:
    //   att_slot = 63 (past slot relative to current_slot = 64)
    //   target_epoch = floor(63 / 32) = 1
    //   target_root = head block root
    //   beacon_block_root = head block root
    const att_slot: u64 = 63;
    const target_epoch: u64 = 1; // floor(63 / SLOTS_PER_EPOCH=32)

    // A fixed attestation data root for the cache.
    const att_data_root: [32]u8 = [_]u8{0xAA} ** 32;

    // Allocate attestation storage.
    const phase0_atts = try allocator.alloc(Phase0IndexedAttestation, TOTAL_ATT_COUNT);
    const any_atts = try allocator.alloc(AnyIndexedAttestation, TOTAL_ATT_COUNT);

    var att_idx: u32 = 0;

    // ── Unaggregated attestations: 3 committees x 135 validators ──
    // Each attestation has exactly one attesting index.
    for (0..UNAGG_COMMITTEES) |c| {
        for (0..VALIDATORS_PER_COMMITTEE) |v| {
            const vi: u64 = @as(u64, c) * VALIDATORS_PER_COMMITTEE + @as(u64, v);

            phase0_atts[att_idx] = .{
                .attesting_indices = .{},
                .data = .{
                    .slot = att_slot,
                    .index = 0,
                    .beacon_block_root = head_root,
                    .source = .{ .epoch = 0, .root = ZERO_HASH },
                    .target = .{ .epoch = target_epoch, .root = head_root },
                },
                .signature = [_]u8{0} ** 96,
            };
            try phase0_atts[att_idx].attesting_indices.append(allocator, vi);
            any_atts[att_idx] = .{ .phase0 = &phase0_atts[att_idx] };
            att_idx += 1;
        }
    }

    // ── Aggregated attestations: 64 committees x 11 aggregators x 135 validators ──
    // Each attestation has 135 attesting indices.
    for (0..AGG_COMMITTEES) |c| {
        for (0..AGGREGATORS_PER_COMMITTEE) |a| {
            const start_index: u64 = @as(u64, c) * VALIDATORS_PER_COMMITTEE * AGGREGATORS_PER_COMMITTEE +
                @as(u64, a) * VALIDATORS_PER_COMMITTEE;

            phase0_atts[att_idx] = .{
                .attesting_indices = .{},
                .data = .{
                    .slot = att_slot,
                    .index = 0,
                    .beacon_block_root = head_root,
                    .source = .{ .epoch = 0, .root = ZERO_HASH },
                    .target = .{ .epoch = target_epoch, .root = head_root },
                },
                .signature = [_]u8{0} ** 96,
            };
            for (0..VALIDATORS_PER_COMMITTEE) |v| {
                try phase0_atts[att_idx].attesting_indices.append(allocator, start_index + @as(u64, v));
            }
            any_atts[att_idx] = .{ .phase0 = &phase0_atts[att_idx] };
            att_idx += 1;
        }
    }

    std.debug.assert(att_idx == TOTAL_ATT_COUNT);

    return .{
        .fc = fc,
        .phase0_atts = phase0_atts,
        .any_atts = any_atts,
        .att_data_root = att_data_root,
    };
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const stdout = std.io.getStdOut().writer();

    var bench = zbench.Benchmark.init(allocator, .{});
    defer bench.deinit();

    const b = try setupBench(allocator);
    try bench.addParam("onAttestation 1109 attestations (vc=600000 bc=64)", &b, .{});

    try bench.run(stdout);
}
