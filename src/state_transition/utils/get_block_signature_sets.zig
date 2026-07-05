const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const AnySignedBeaconBlock = @import("fork_types").AnySignedBeaconBlock;
const SingleSignatureSet = @import("./signature_sets.zig").SingleSignatureSet;
const AggregatedSignatureSet = @import("./signature_sets.zig").AggregatedSignatureSet;

const proposer_sig = @import("../signature_sets/proposer.zig");
const randao_sig = @import("../signature_sets/randao.zig");
const proposer_slashings_sig = @import("../signature_sets/proposer_slashings.zig");
const voluntary_exits_sig = @import("../signature_sets/voluntary_exits.zig");
const bls_to_exec_sig = @import("../signature_sets/bls_to_execution_change.zig");
const attester_slashings_sig = @import("../signature_sets/attester_slashings.zig");
const indexed_attestation_sig = @import("../signature_sets/indexed_attestation.zig");
const process_sync = @import("../block/process_sync_committee.zig");

pub const GetBlockSignatureSetsOpts = struct {
    skip_proposer_signature: bool = false,
};

pub const BlockSignatureSets = struct {
    single: std.ArrayList(SingleSignatureSet),
    aggregated: std.ArrayList(AggregatedSignatureSet),

    pub const empty: BlockSignatureSets = .{
        .single = .empty,
        .aggregated = .empty,
    };

    pub fn deinit(self: *BlockSignatureSets, allocator: Allocator) void {
        for (self.aggregated.items) |set| {
            allocator.free(set.pubkeys);
        }
        self.aggregated.deinit(allocator);
        self.single.deinit(allocator);
    }
};

/// Assembles every BLS signature set that must be verified for `signed_block`
/// to be considered valid. Fork-dispatched via the accessors on `AnyBeaconBlock`.
/// The caller owns the returned sets — invoke `out.deinit(allocator)`.
pub fn getBlockSignatureSets(
    allocator: Allocator,
    cached_state: *const CachedBeaconState,
    signed_block: AnySignedBeaconBlock,
    opts: GetBlockSignatureSetsOpts,
    out: *BlockSignatureSets,
) !void {
    const config = cached_state.config;
    const epoch_cache = cached_state.epoch_cache;
    const block = signed_block.beaconBlock();
    const body = block.beaconBlockBody();
    const fork_seq = signed_block.forkSeq();

    std.debug.assert(out.single.items.len == 0);
    std.debug.assert(out.aggregated.items.len == 0);

    if (!opts.skip_proposer_signature) {
        const set = try proposer_sig.getBlockProposerSignatureSet(allocator, config, epoch_cache, signed_block);
        try out.single.append(allocator, set);
    }

    const randao_reveal = body.randaoReveal();
    const set_randao = try randao_sig.randaoRevealSignatureSet(
        config,
        epoch_cache,
        randao_reveal,
        block.slot(),
        block.proposerIndex(),
    );
    try out.single.append(allocator, set_randao);

    const proposer_slashings = body.proposerSlashings();
    for (proposer_slashings) |*proposer_slashing| {
        const sets = try proposer_slashings_sig.getProposerSlashingSignatureSets(config, epoch_cache, proposer_slashing);
        try out.single.append(allocator, sets[0]);
        try out.single.append(allocator, sets[1]);
    }

    const attester_slashings_any = body.attesterSlashings();
    try attester_slashings_sig.attesterSlashingsSignatureSets(
        allocator,
        config,
        epoch_cache,
        attester_slashings_any.items(),
        &out.aggregated,
    );

    try indexed_attestation_sig.attestationsSignatureSets(allocator, cached_state, &signed_block, &out.aggregated);

    const voluntary_exits = body.voluntaryExits();
    for (voluntary_exits) |*signed_voluntary_exit| {
        const set = try voluntary_exits_sig.getVoluntaryExitSignatureSet(config, epoch_cache, signed_voluntary_exit);
        try out.single.append(allocator, set);
    }

    if (fork_seq.gte(.altair)) {
        const sync_aggregate = try body.syncAggregate();
        const parent_root = block.parentRoot();
        if (try process_sync.getSyncCommitteeSignatureSet(
            allocator,
            config,
            epoch_cache,
            sync_aggregate,
            block.slot(),
            parent_root,
            null,
        )) |sync_set| {
            try out.aggregated.append(allocator, sync_set);
        }
    }

    if (fork_seq.gte(.capella)) {
        const bls_to_execution_changes = try body.blsToExecutionChanges();
        for (bls_to_execution_changes) |*signed_change| {
            const set = try bls_to_exec_sig.getBlsToExecutionChangeSignatureSet(config, signed_change);
            try out.single.append(allocator, set);
        }
    }
}
