const std = @import("std");
const Allocator = std.mem.Allocator;
const expect = std.testing.expect;
const preset = @import("preset").preset;
const ForkSeq = @import("config").ForkSeq;
const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;
const createSingleProof = @import("persistent_merkle_tree").proof.createSingleProof;
const SingleProof = @import("persistent_merkle_tree").proof.SingleProof;
const isBasicType = @import("ssz").isBasicType;
const isFixedType = @import("ssz").isFixedType;
const BaseTreeView = @import("ssz").BaseTreeView;
const CloneOpts = @import("ssz").BaseTreeView.CloneOpts;
const ct = @import("consensus_types");
const ExecutionPayloadHeader = @import("./execution_payload.zig").ExecutionPayloadHeader;
const constants = @import("constants");

/// wrapper for all BeaconState types across forks so that we don't have to do switch/case for all methods
pub const BeaconState = union(ForkSeq) {
    phase0: ct.phase0.BeaconState.TreeView,
    altair: ct.altair.BeaconState.TreeView,
    bellatrix: ct.bellatrix.BeaconState.TreeView,
    capella: ct.capella.BeaconState.TreeView,
    deneb: ct.deneb.BeaconState.TreeView,
    electra: ct.electra.BeaconState.TreeView,
    fulu: ct.fulu.BeaconState.TreeView,

    pub fn fromValue(allocator: Allocator, pool: *Node.Pool, comptime fork_seq: ForkSeq, value: anytype) !BeaconState {
        return switch (fork_seq) {
            .phase0 => .{
                .phase0 = try ct.phase0.BeaconState.TreeView.fromValue(allocator, pool, value),
            },
            .altair => .{
                .altair = try ct.altair.BeaconState.TreeView.fromValue(allocator, pool, value),
            },
            .bellatrix => .{
                .bellatrix = try ct.bellatrix.BeaconState.TreeView.fromValue(allocator, pool, value),
            },
            .capella => .{
                .capella = try ct.capella.BeaconState.TreeView.fromValue(allocator, pool, value),
            },
            .deneb => .{
                .deneb = try ct.deneb.BeaconState.TreeView.fromValue(allocator, pool, value),
            },
            .electra => .{
                .electra = try ct.electra.BeaconState.TreeView.fromValue(allocator, pool, value),
            },
            .fulu => .{
                .fulu = try ct.fulu.BeaconState.TreeView.fromValue(allocator, pool, value),
            },
        };
    }

    pub fn deserialize(allocator: Allocator, pool: *Node.Pool, fork_seq: ForkSeq, bytes: []const u8) !BeaconState {
        return switch (fork_seq) {
            .phase0 => .{
                .phase0 = try ct.phase0.BeaconState.TreeView.deserialize(allocator, pool, bytes),
            },
            .altair => .{
                .altair = try ct.altair.BeaconState.TreeView.deserialize(allocator, pool, bytes),
            },
            .bellatrix => .{
                .bellatrix = try ct.bellatrix.BeaconState.TreeView.deserialize(allocator, pool, bytes),
            },
            .capella => .{
                .capella = try ct.capella.BeaconState.TreeView.deserialize(allocator, pool, bytes),
            },
            .deneb => .{
                .deneb = try ct.deneb.BeaconState.TreeView.deserialize(allocator, pool, bytes),
            },
            .electra => .{
                .electra = try ct.electra.BeaconState.TreeView.deserialize(allocator, pool, bytes),
            },
            .fulu => .{
                .fulu = try ct.fulu.BeaconState.TreeView.deserialize(allocator, pool, bytes),
            },
        };
    }

    pub fn serialize(self: BeaconState, allocator: Allocator) ![]u8 {
        var s = self;
        switch (s) {
            .phase0 => |*state| {
                const out = try allocator.alloc(u8, try state.serializedSize());
                errdefer allocator.free(out);
                _ = try state.serializeIntoBytes(out);
                return out;
            },
            .altair => |*state| {
                const out = try allocator.alloc(u8, try state.serializedSize());
                errdefer allocator.free(out);
                _ = try state.serializeIntoBytes(out);
                return out;
            },
            .bellatrix => |*state| {
                const out = try allocator.alloc(u8, try state.serializedSize());
                errdefer allocator.free(out);
                _ = try state.serializeIntoBytes(out);
                return out;
            },
            .capella => |*state| {
                const out = try allocator.alloc(u8, try state.serializedSize());
                errdefer allocator.free(out);
                _ = try state.serializeIntoBytes(out);
                return out;
            },
            .deneb => |*state| {
                const out = try allocator.alloc(u8, try state.serializedSize());
                errdefer allocator.free(out);
                _ = try state.serializeIntoBytes(out);
                return out;
            },
            .electra => |*state| {
                const out = try allocator.alloc(u8, try state.serializedSize());
                errdefer allocator.free(out);
                _ = try state.serializeIntoBytes(out);
                return out;
            },
            .fulu => |*state| {
                const out = try allocator.alloc(u8, try state.serializedSize());
                errdefer allocator.free(out);
                _ = try state.serializeIntoBytes(out);
                return out;
            },
        }
    }

    pub fn format(
        self: BeaconState,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        return switch (self) {
            inline else => {
                try writer.print("{s} (at slot {})", .{ @tagName(self), self.slot() });
            },
        };
    }

    pub fn baseView(self: *BeaconState) BaseTreeView {
        return switch (self.*) {
            inline else => |*state| state.base_view,
        };
    }

    pub fn clone(self: *BeaconState, opts: CloneOpts) !BeaconState {
        return switch (self.*) {
            .phase0 => |*state| .{ .phase0 = try state.clone(opts) },
            .altair => |*state| .{ .altair = try state.clone(opts) },
            .bellatrix => |*state| .{ .bellatrix = try state.clone(opts) },
            .capella => |*state| .{ .capella = try state.clone(opts) },
            .deneb => |*state| .{ .deneb = try state.clone(opts) },
            .electra => |*state| .{ .electra = try state.clone(opts) },
            .fulu => |*state| .{ .fulu = try state.clone(opts) },
        };
    }

    pub fn commit(self: *BeaconState) !void {
        switch (self.*) {
            inline else => |*state| try state.commit(),
        }
    }

    /// Get a Merkle proof for the finalized root in the beacon state.
    pub fn getFinalizedRootProof(self: *BeaconState, allocator: Allocator) !SingleProof {
        try self.commit();
        const gindex_value: u64 = switch (self.*) {
            .electra, .fulu => constants.FINALIZED_ROOT_GINDEX_ELECTRA,
            else => constants.FINALIZED_ROOT_GINDEX,
        };
        const gindex: Gindex = @enumFromInt(gindex_value);
        return switch (self.*) {
            inline else => |*state| try createSingleProof(
                allocator,
                state.base_view.pool,
                state.base_view.data.root,
                gindex,
            ),
        };
    }

    pub fn hashTreeRoot(self: *BeaconState) !*const [32]u8 {
        return switch (self.*) {
            inline else => |*state| try state.hashTreeRoot(),
        };
    }

    pub fn deinit(self: *BeaconState) void {
        switch (self.*) {
            inline else => |*state| state.deinit(),
        }
    }

    pub fn forkSeq(self: *BeaconState) ForkSeq {
        return (self.*);
    }

    pub fn genesisTime(self: *BeaconState) !u64 {
        return switch (self.*) {
            inline else => |*state| try state.get("genesis_time"),
        };
    }

    pub fn genesisValidatorsRoot(self: *BeaconState) !*const [32]u8 {
        return switch (self.*) {
            inline else => |*state| try state.getRoot("genesis_validators_root"),
        };
    }

    pub fn slot(self: *BeaconState) !u64 {
        return switch (self.*) {
            inline else => |*state| try state.get("slot"),
        };
    }

    pub fn setSlot(self: *BeaconState, s: u64) !void {
        switch (self.*) {
            inline else => |*state| try state.set("slot", s),
        }
    }

    pub fn fork(self: *BeaconState) !ct.phase0.Fork.TreeView {
        return switch (self.*) {
            inline else => |*state| try state.get("fork"),
        };
    }

    pub fn forkCurrentVersion(self: *BeaconState) ![4]u8 {
        var f = switch (self.*) {
            inline else => |*state| try state.getReadonly("fork"),
        };
        const current_version_root = try f.getRoot("current_version");
        var version: [4]u8 = undefined;
        @memcpy(&version, current_version_root[0..4]);
        return version;
    }

    pub fn setFork(self: *BeaconState, f: *const ct.phase0.Fork.Type) !void {
        switch (self.*) {
            inline else => |*state| try state.setValue("fork", f),
        }
    }

    pub fn latestBlockHeader(self: *BeaconState) !ct.phase0.BeaconBlockHeader.TreeView {
        return switch (self.*) {
            inline else => |*state| try state.get("latest_block_header"),
        };
    }

    pub fn setLatestBlockHeader(self: *BeaconState, header: *const ct.phase0.BeaconBlockHeader.Type) !void {
        switch (self.*) {
            inline else => |*state| try state.setValue("latest_block_header", header),
        }
    }

    pub fn blockRoots(self: *BeaconState) !ct.phase0.HistoricalBlockRoots.TreeView {
        return switch (self.*) {
            inline else => |*state| try state.get("block_roots"),
        };
    }

    pub fn blockRootsRoot(self: *BeaconState) !*const [32]u8 {
        return switch (self.*) {
            inline else => |*state| try state.getRoot("block_roots"),
        };
    }

    pub fn stateRoots(self: *BeaconState) !ct.phase0.HistoricalStateRoots.TreeView {
        return switch (self.*) {
            inline else => |*state| try state.get("state_roots"),
        };
    }

    pub fn stateRootsRoot(self: *BeaconState) !*const [32]u8 {
        return switch (self.*) {
            inline else => |*state| try state.getRoot("state_roots"),
        };
    }

    pub fn historicalRoots(self: *BeaconState) !ct.phase0.HistoricalRoots.TreeView {
        return switch (self.*) {
            inline else => |*state| try state.get("historical_roots"),
        };
    }

    pub fn eth1Data(self: *BeaconState) !ct.phase0.Eth1Data.TreeView {
        return switch (self.*) {
            inline else => |*state| try state.get("eth1_data"),
        };
    }

    pub fn setEth1Data(self: *BeaconState, eth1_data: *const ct.phase0.Eth1Data.Type) !void {
        switch (self.*) {
            inline else => |*state| try state.setValue("eth1_data", eth1_data),
        }
    }

    pub fn eth1DataVotes(self: *BeaconState) !ct.phase0.Eth1DataVotes.TreeView {
        return switch (self.*) {
            inline else => |*state| try state.get("eth1_data_votes"),
        };
    }

    pub fn setEth1DataVotes(self: *BeaconState, eth1_data_votes: ct.phase0.Eth1DataVotes.TreeView) !void {
        switch (self.*) {
            inline else => |*state| try state.set("eth1_data_votes", eth1_data_votes),
        }
    }

    pub fn appendEth1DataVote(self: *BeaconState, eth1_data: *const ct.phase0.Eth1Data.Type) !void {
        var votes = try self.eth1DataVotes();
        try votes.pushValue(eth1_data);
    }

    pub fn resetEth1DataVotes(self: *BeaconState) !void {
        switch (self.*) {
            inline else => |*state| try state.setValue("eth1_data_votes", &ct.phase0.Eth1DataVotes.default_value),
        }
    }

    pub fn eth1DepositIndex(self: *BeaconState) !u64 {
        return switch (self.*) {
            inline else => |*state| try state.get("eth1_deposit_index"),
        };
    }

    pub fn setEth1DepositIndex(self: *BeaconState, index: u64) !void {
        return switch (self.*) {
            inline else => |*state| try state.set("eth1_deposit_index", index),
        };
    }

    pub fn incrementEth1DepositIndex(self: *BeaconState) !void {
        try self.setEth1DepositIndex(try self.eth1DepositIndex() + 1);
    }

    pub fn validators(self: *BeaconState) !ct.phase0.Validators.TreeView {
        return switch (self.*) {
            inline else => |*state| try state.get("validators"),
        };
    }

    pub fn validatorsCount(self: *BeaconState) !usize {
        return switch (self.*) {
            inline else => |*state| {
                var validators_view = try state.getReadonly("validators");
                return validators_view.length();
            },
        };
    }

    /// Returns a read-only slice of validators.
    /// This is read-only in the sense that modifications will not be reflected back to the state.
    /// Caller owns the returned slice and must free it with the same allocator.
    pub fn validatorsSlice(self: *BeaconState, allocator: Allocator) ![]ct.phase0.Validator.Type {
        return switch (self.*) {
            inline else => |*state| {
                var validators_view = try state.getReadonly("validators");
                return validators_view.getAllReadonlyValues(allocator);
            },
        };
    }

    pub fn balances(self: *BeaconState) !ct.phase0.Balances.TreeView {
        return switch (self.*) {
            inline else => |*state| try state.get("balances"),
        };
    }

    /// Returns a read-only slice of balances.
    /// This is read-only in the sense that modifications will not be reflected back to the state.
    /// Caller owns the returned slice and must free it with the same allocator.
    pub fn balancesSlice(self: *BeaconState, allocator: Allocator) ![]u64 {
        return switch (self.*) {
            inline else => |*state| {
                var balances_view = try state.get("balances");
                try balances_view.commit();
                return balances_view.getAll(allocator);
            },
        };
    }

    pub fn setBalances(self: *BeaconState, b: *const ct.phase0.Balances.Type) !void {
        return switch (self.*) {
            inline else => |*state| try state.setValue("balances", b),
        };
    }

    pub fn randaoMixes(self: *BeaconState) !ct.phase0.RandaoMixes.TreeView {
        return switch (self.*) {
            inline else => |*state| try state.get("randao_mixes"),
        };
    }

    pub fn setRandaoMix(self: *BeaconState, epoch: u64, randao_mix: *const ct.primitive.Bytes32.Type) !void {
        var mixes = try self.randaoMixes();
        try mixes.setValue(epoch % preset.EPOCHS_PER_HISTORICAL_VECTOR, randao_mix);
    }

    pub fn slashings(self: *BeaconState) !ct.phase0.Slashings.TreeView {
        return switch (self.*) {
            inline else => |*state| try state.get("slashings"),
        };
    }

    pub fn previousEpochPendingAttestations(self: *BeaconState) !ct.phase0.EpochAttestations.TreeView {
        return switch (self.*) {
            .phase0 => |*state| try state.get("previous_epoch_attestations"),
            else => error.InvalidAtFork,
        };
    }

    pub fn currentEpochPendingAttestations(self: *BeaconState) !ct.phase0.EpochAttestations.TreeView {
        return switch (self.*) {
            .phase0 => |*state| try state.get("current_epoch_attestations"),
            else => error.InvalidAtFork,
        };
    }

    pub fn rotateEpochPendingAttestations(self: *BeaconState) !void {
        return switch (self.*) {
            .phase0 => |*state| {
                const current_root = try state.getRootNode("current_epoch_attestations");
                try state.setRootNode("previous_epoch_attestations", current_root);
                try state.setValue("current_epoch_attestations", &ct.phase0.EpochAttestations.default_value);
            },
            else => error.InvalidAtFork,
        };
    }

    pub fn previousEpochParticipation(self: *BeaconState) !ct.altair.EpochParticipation.TreeView {
        return switch (self.*) {
            .phase0 => error.InvalidAtFork,
            inline else => |*state| try state.get("previous_epoch_participation"),
        };
    }

    pub fn setPreviousEpochParticipation(self: *BeaconState, participations: *const ct.altair.EpochParticipation.Type) !void {
        return switch (self.*) {
            .phase0 => error.InvalidAtFork,
            inline else => |*state| try state.setValue("previous_epoch_participation", participations),
        };
    }

    pub fn currentEpochParticipation(self: *BeaconState) !ct.altair.EpochParticipation.TreeView {
        return switch (self.*) {
            .phase0 => error.InvalidAtFork,
            inline else => |*state| try state.get("current_epoch_participation"),
        };
    }

    pub fn setCurrentEpochParticipation(self: *BeaconState, participations: *const ct.altair.EpochParticipation.Type) !void {
        return switch (self.*) {
            .phase0 => error.InvalidAtFork,
            inline else => |*state| try state.setValue("current_epoch_participation", participations),
        };
    }

    pub fn rotateEpochParticipation(self: *BeaconState) !void {
        return switch (self.*) {
            .phase0 => error.InvalidAtFork,
            inline else => |*state| {
                var current_epoch_participation = try state.get("current_epoch_participation");
                try current_epoch_participation.commit();
                const length = try current_epoch_participation.length();
                try state.set(
                    "previous_epoch_participation",
                    // cannot set without cloning because the original is owned by the tree
                    // we need to clone it to create an owned tree
                    try current_epoch_participation.clone(.{ .transfer_cache = true }),
                );

                // Reset current_epoch_participation by rebuilding a zeroed SSZ List of the same length.
                const new_current_root = try ct.altair.EpochParticipation.tree.zeros(
                    state.base_view.pool,
                    length,
                );
                errdefer state.base_view.pool.unref(new_current_root);
                try state.setRootNode("current_epoch_participation", new_current_root);
            },
        };
    }

    pub fn justificationBits(self: *BeaconState) !ct.phase0.JustificationBits.TreeView {
        return switch (self.*) {
            inline else => |*state| try state.get("justification_bits"),
        };
    }

    pub fn setJustificationBits(self: *BeaconState, bits: *const ct.phase0.JustificationBits.Type) !void {
        return switch (self.*) {
            inline else => |*state| try state.setValue("justification_bits", bits),
        };
    }

    pub fn previousJustifiedCheckpoint(self: *BeaconState, out: *ct.phase0.Checkpoint.Type) !void {
        return switch (self.*) {
            inline else => |*state| try state.getValue(undefined, "previous_justified_checkpoint", out),
        };
    }

    pub fn setPreviousJustifiedCheckpoint(self: *BeaconState, checkpoint: *const ct.phase0.Checkpoint.Type) !void {
        return switch (self.*) {
            inline else => |*state| try state.setValue("previous_justified_checkpoint", checkpoint),
        };
    }

    pub fn currentJustifiedCheckpoint(self: *BeaconState, out: *ct.phase0.Checkpoint.Type) !void {
        return switch (self.*) {
            inline else => |*state| try state.getValue(undefined, "current_justified_checkpoint", out),
        };
    }

    pub fn setCurrentJustifiedCheckpoint(self: *BeaconState, checkpoint: *const ct.phase0.Checkpoint.Type) !void {
        return switch (self.*) {
            inline else => |*state| try state.setValue("current_justified_checkpoint", checkpoint),
        };
    }

    pub fn finalizedCheckpoint(self: *BeaconState, out: *ct.phase0.Checkpoint.Type) !void {
        return switch (self.*) {
            inline else => |*state| try state.getValue(undefined, "finalized_checkpoint", out),
        };
    }

    pub fn setFinalizedCheckpoint(self: *BeaconState, checkpoint: *const ct.phase0.Checkpoint.Type) !void {
        return switch (self.*) {
            inline else => |*state| try state.setValue("finalized_checkpoint", checkpoint),
        };
    }

    pub fn finalizedEpoch(self: *BeaconState) !u64 {
        return switch (self.*) {
            inline else => |*state| {
                var checkpoint_view = try state.getReadonly("finalized_checkpoint");
                return try checkpoint_view.get("epoch");
            },
        };
    }

    pub fn inactivityScores(self: *BeaconState) !ct.altair.InactivityScores.TreeView {
        return switch (self.*) {
            .phase0 => error.InvalidAtFork,
            inline else => |*state| try state.get("inactivity_scores"),
        };
    }

    pub fn currentSyncCommittee(self: *BeaconState) !ct.altair.SyncCommittee.TreeView {
        return switch (self.*) {
            .phase0 => error.InvalidAtFork,
            inline else => |*state| try state.get("current_sync_committee"),
        };
    }

    pub fn setCurrentSyncCommittee(self: *BeaconState, sync_committee: *const ct.altair.SyncCommittee.Type) !void {
        return switch (self.*) {
            .phase0 => error.InvalidAtFork,
            inline else => |*state| try state.setValue("current_sync_committee", sync_committee),
        };
    }

    pub fn nextSyncCommittee(self: *BeaconState) !ct.altair.SyncCommittee.TreeView {
        return switch (self.*) {
            .phase0 => error.InvalidAtFork,
            inline else => |*state| try state.get("next_sync_committee"),
        };
    }

    pub fn setNextSyncCommittee(self: *BeaconState, sync_committee: *const ct.altair.SyncCommittee.Type) !void {
        return switch (self.*) {
            .phase0 => error.InvalidAtFork,
            inline else => |*state| try state.setValue("next_sync_committee", sync_committee),
        };
    }

    pub fn rotateSyncCommittees(self: *BeaconState, next_sync_committee: *const ct.altair.SyncCommittee.Type) !void {
        return switch (self.*) {
            .phase0 => error.InvalidAtFork,
            inline else => |*state| {
                const next_sync_committee_root = try state.getRootNode("next_sync_committee");
                try state.setRootNode("current_sync_committee", next_sync_committee_root);
                try state.setValue("next_sync_committee", next_sync_committee);
            },
        };
    }

    pub fn latestExecutionPayloadHeader(self: *BeaconState, allocator: Allocator, out: *ExecutionPayloadHeader) !void {
        return switch (self.*) {
            .phase0, .altair => error.InvalidAtFork,
            .bellatrix => |*state| {
                out.* = .{ .bellatrix = undefined };
                try state.getValue(allocator, "latest_execution_payload_header", &out.bellatrix);
            },
            .capella => |*state| {
                out.* = .{ .capella = undefined };
                try state.getValue(allocator, "latest_execution_payload_header", &out.capella);
            },
            .deneb => |*state| {
                out.* = .{ .deneb = undefined };
                try state.getValue(allocator, "latest_execution_payload_header", &out.deneb);
            },
            .electra => |*state| {
                out.* = .{ .electra = undefined };
                try state.getValue(allocator, "latest_execution_payload_header", &out.electra);
            },
            .fulu => |*state| {
                out.* = .{ .fulu = undefined };
                try state.getValue(allocator, "latest_execution_payload_header", &out.fulu);
            },
        };
    }

    pub fn latestExecutionPayloadHeaderBlockHash(self: *BeaconState) !*const [32]u8 {
        return switch (self.*) {
            .phase0, .altair => error.InvalidAtFork,
            inline else => |*state| {
                var header = try state.get("latest_execution_payload_header");
                return try header.getRoot("block_hash");
            },
        };
    }

    pub fn setLatestExecutionPayloadHeader(self: *BeaconState, header: *const ExecutionPayloadHeader) !void {
        switch (self.*) {
            .bellatrix => |*state| try state.setValue("latest_execution_payload_header", &header.bellatrix),
            .capella => |*state| try state.setValue("latest_execution_payload_header", &header.capella),
            .deneb => |*state| try state.setValue("latest_execution_payload_header", &header.deneb),
            .electra => |*state| try state.setValue("latest_execution_payload_header", &header.electra),
            .fulu => |*state| try state.setValue("latest_execution_payload_header", &header.fulu),
            else => return error.InvalidAtFork,
        }
    }

    pub fn nextWithdrawalIndex(self: *BeaconState) !u64 {
        return switch (self.*) {
            .phase0, .altair, .bellatrix => error.InvalidAtFork,
            inline else => |*state| try state.get("next_withdrawal_index"),
        };
    }

    pub fn setNextWithdrawalIndex(self: *BeaconState, next_withdrawal_index: u64) !void {
        return switch (self.*) {
            .phase0, .altair, .bellatrix => error.InvalidAtFork,
            inline else => |*state| try state.set("next_withdrawal_index", next_withdrawal_index),
        };
    }

    pub fn nextWithdrawalValidatorIndex(self: *BeaconState) !u64 {
        return switch (self.*) {
            .phase0, .altair, .bellatrix => error.InvalidAtFork,
            inline else => |*state| try state.get("next_withdrawal_validator_index"),
        };
    }

    pub fn setNextWithdrawalValidatorIndex(self: *BeaconState, next_withdrawal_validator_index: u64) !void {
        return switch (self.*) {
            .phase0, .altair, .bellatrix => error.InvalidAtFork,
            inline else => |*state| try state.set("next_withdrawal_validator_index", next_withdrawal_validator_index),
        };
    }

    pub fn historicalSummaries(self: *BeaconState) !ct.capella.HistoricalSummaries.TreeView {
        return switch (self.*) {
            .phase0, .altair, .bellatrix => error.InvalidAtFork,
            inline else => |*state| try state.get("historical_summaries"),
        };
    }

    pub fn depositRequestsStartIndex(self: *BeaconState) !u64 {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |*state| try state.get("deposit_requests_start_index"),
        };
    }

    pub fn setDepositRequestsStartIndex(self: *BeaconState, index: u64) !void {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |*state| try state.set("deposit_requests_start_index", index),
        };
    }

    pub fn depositBalanceToConsume(self: *BeaconState) !u64 {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |*state| try state.get("deposit_balance_to_consume"),
        };
    }

    pub fn setDepositBalanceToConsume(self: *BeaconState, balance: u64) !void {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |*state| try state.set("deposit_balance_to_consume", balance),
        };
    }

    pub fn exitBalanceToConsume(self: *BeaconState) !u64 {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |*state| try state.get("exit_balance_to_consume"),
        };
    }

    pub fn setExitBalanceToConsume(self: *BeaconState, balance: u64) !void {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |*state| try state.set("exit_balance_to_consume", balance),
        };
    }

    pub fn earliestExitEpoch(self: *BeaconState) !u64 {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |*state| try state.get("earliest_exit_epoch"),
        };
    }

    pub fn setEarliestExitEpoch(self: *BeaconState, epoch: u64) !void {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |*state| try state.set("earliest_exit_epoch", epoch),
        };
    }

    pub fn consolidationBalanceToConsume(self: *BeaconState) !u64 {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |*state| try state.get("consolidation_balance_to_consume"),
        };
    }

    pub fn setConsolidationBalanceToConsume(self: *BeaconState, balance: u64) !void {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |*state| try state.set("consolidation_balance_to_consume", balance),
        };
    }

    pub fn earliestConsolidationEpoch(self: *BeaconState) !u64 {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |*state| try state.get("earliest_consolidation_epoch"),
        };
    }

    pub fn setEarliestConsolidationEpoch(self: *BeaconState, epoch: u64) !void {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |*state| try state.set("earliest_consolidation_epoch", epoch),
        };
    }

    pub fn pendingDeposits(self: *BeaconState) !ct.electra.PendingDeposits.TreeView {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |*state| try state.get("pending_deposits"),
        };
    }

    pub fn setPendingDeposits(self: *BeaconState, deposits: ct.electra.PendingDeposits.TreeView) !void {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |*state| try state.set("pending_deposits", deposits),
        };
    }

    pub fn pendingPartialWithdrawals(self: *BeaconState) !ct.electra.PendingPartialWithdrawals.TreeView {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |*state| try state.get("pending_partial_withdrawals"),
        };
    }

    pub fn setPendingPartialWithdrawals(self: *BeaconState, pending_partial_withdrawals: ct.electra.PendingPartialWithdrawals.TreeView) !void {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |*state| try state.set("pending_partial_withdrawals", pending_partial_withdrawals),
        };
    }

    pub fn pendingConsolidations(self: *BeaconState) !ct.electra.PendingConsolidations.TreeView {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |*state| try state.get("pending_consolidations"),
        };
    }

    pub fn setPendingConsolidations(self: *BeaconState, consolidations: ct.electra.PendingConsolidations.TreeView) !void {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |*state| try state.set("pending_consolidations", consolidations),
        };
    }

    /// Get proposer_lookahead
    pub fn proposerLookahead(self: *BeaconState) !ct.fulu.ProposerLookahead.TreeView {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb, .electra => error.InvalidAtFork,
            inline else => |*state| try state.get("proposer_lookahead"),
        };
    }

    /// Returns a read-only slice of proposer_lookahead values.
    /// Caller owns the returned slice and must free it with the same allocator.
    pub fn proposerLookaheadSlice(self: *BeaconState, allocator: Allocator) !*[ct.fulu.ProposerLookahead.length]u64 {
        var lookahead_view = try self.proposerLookahead();
        return @ptrCast(try lookahead_view.getAll(allocator));
    }

    pub fn setProposerLookahead(self: *BeaconState, proposer_lookahead: *const [ct.fulu.ProposerLookahead.length]u64) !void {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb, .electra => error.InvalidAtFork,
            inline else => |*state| try state.setValue("proposer_lookahead", proposer_lookahead),
        };
    }

    /// Copies fields of `BeaconState` from type `F` to type `T`, provided they have the same field name.
    /// The cache of original state is cleared after the copy is complete.
    fn populateFields(
        comptime F: type,
        comptime T: type,
        allocator: Allocator,
        pool: *Node.Pool,
        state: F.TreeView,
    ) !T.TreeView {
        // first ensure that the source state is committed
        var committed_state = state;
        try committed_state.commit();

        var upgraded = try T.TreeView.fromValue(allocator, pool, &T.default_value);
        errdefer upgraded.deinit();

        inline for (F.fields) |f| {
            if (comptime T.hasField(f.name)) {
                if (T.getFieldType(f.name) != f.type) {
                    // BeaconState of prev_fork and cur_fork has the same field name but different types
                    // for example latest_execution_payload_header changed from Bellatrix to Capella
                    // In this case we just skip copying this field and leave it to caller to set properly
                    continue;
                }

                if (comptime isBasicType(f.type)) {
                    // For basic fields, get() returns a copy, so we can directly set it.
                    try upgraded.set(f.name, try committed_state.get(f.name));
                } else {
                    // For composite fields, get() returns a borrowed TreeView backed by committed_state caches.
                    // Clone it to create an owned view, then transfer ownership to upgraded.
                    var field_view = try committed_state.get(f.name);
                    var owned_field_view = try field_view.clone(.{ .transfer_cache = true });
                    errdefer owned_field_view.deinit();
                    try upgraded.set(f.name, owned_field_view);
                }
            }
        }

        try upgraded.commit();

        return upgraded;
    }

    /// Upgrade `self` from a certain fork to the next.
    /// Allocates a new `state` of the next fork, clones all fields of the current `state` to it and assigns `self` to it.
    /// Caller must make sure an upgrade is needed by checking BeaconConfig then free upgraded state.
    /// Caller needs to deinit the old state
    pub fn upgradeUnsafe(self: *BeaconState) !BeaconState {
        return switch (self.*) {
            .phase0 => |state| .{
                .altair = try populateFields(
                    ct.phase0.BeaconState,
                    ct.altair.BeaconState,
                    state.base_view.allocator,
                    state.base_view.pool,
                    state,
                ),
            },
            .altair => |state| .{
                .bellatrix = try populateFields(
                    ct.altair.BeaconState,
                    ct.bellatrix.BeaconState,
                    state.base_view.allocator,
                    state.base_view.pool,
                    state,
                ),
            },
            .bellatrix => |state| .{
                .capella = try populateFields(
                    ct.bellatrix.BeaconState,
                    ct.capella.BeaconState,
                    state.base_view.allocator,
                    state.base_view.pool,
                    state,
                ),
            },
            .capella => |state| .{
                .deneb = try populateFields(
                    ct.capella.BeaconState,
                    ct.deneb.BeaconState,
                    state.base_view.allocator,
                    state.base_view.pool,
                    state,
                ),
            },
            .deneb => |state| .{
                .electra = try populateFields(
                    ct.deneb.BeaconState,
                    ct.electra.BeaconState,
                    state.base_view.allocator,
                    state.base_view.pool,
                    state,
                ),
            },
            .electra => |state| .{
                .fulu = try populateFields(
                    ct.electra.BeaconState,
                    ct.fulu.BeaconState,
                    state.base_view.allocator,
                    state.base_view.pool,
                    state,
                ),
            },
            .fulu => error.InvalidAtFork,
        };
    }
};

test "electra - sanity" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var beacon_state = try BeaconState.fromValue(allocator, &pool, .electra, &ct.electra.BeaconState.default_value);
    defer beacon_state.deinit();

    try beacon_state.setSlot(12345);

    try std.testing.expect((try beacon_state.genesisTime()) == 0);
    try std.testing.expectEqualSlices(u8, &[_]u8{0} ** 32, (try beacon_state.genesisValidatorsRoot())[0..]);
    try std.testing.expect((try beacon_state.slot()) == 12345);
    try beacon_state.setSlot(2025);
    try std.testing.expect((try beacon_state.slot()) == 2025);

    const out: *const [32]u8 = try beacon_state.hashTreeRoot();
    try expect(!std.mem.eql(u8, (&[_]u8{0} ** 32)[0..], out.*[0..]));

    // TODO: more tests
}

test "clone - sanity" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var beacon_state = try BeaconState.fromValue(allocator, &pool, .electra, &ct.electra.BeaconState.default_value);
    defer beacon_state.deinit();

    try beacon_state.setSlot(12345);
    try beacon_state.commit();

    // test the clone() and deinit() works fine without memory leak
    var cloned_state = try beacon_state.clone(.{});
    defer cloned_state.deinit();

    try expect((try cloned_state.slot()) == 12345);
}

test "clone - cases" {
    const allocator = std.testing.allocator;

    const TestCase = struct {
        name: []const u8,
        slot_set: u64,
        commit_before_clone: bool,
        expected_slot: u64,
    };

    const test_Case = [_]TestCase{
        .{ .name = "commit before clone", .slot_set = 12345, .commit_before_clone = true, .expected_slot = 12345 },
        .{ .name = "no commit before clone", .slot_set = 12345, .commit_before_clone = false, .expected_slot = 0 },
    };

    inline for (test_Case) |tc| {
        var pool = try Node.Pool.init(allocator, 500_000);
        defer pool.deinit();

        var beacon_state = try BeaconState.fromValue(allocator, &pool, .electra, &ct.electra.BeaconState.default_value);
        defer beacon_state.deinit();

        try beacon_state.setSlot(tc.slot_set);
        try expect((try beacon_state.slot()) == tc.slot_set);

        if (tc.commit_before_clone) {
            try beacon_state.commit();
        }

        var cloned_state = try beacon_state.clone(.{});
        defer cloned_state.deinit();

        const got = try cloned_state.slot();
        if (got != tc.expected_slot) {
            std.debug.print("clone case '{s}' failed: got slot {}, expected {}\n", .{ tc.name, got, tc.expected_slot });
            return error.TestExpectedEqual;
        }
    }
}

test "upgrade state - sanity" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var phase0_state = try BeaconState.fromValue(allocator, &pool, .phase0, &ct.phase0.BeaconState.default_value);
    defer phase0_state.deinit();

    var altair_state = try phase0_state.upgradeUnsafe();
    defer altair_state.deinit();
    try expect(altair_state.forkSeq() == .altair);

    var bellatrix_state = try altair_state.upgradeUnsafe();
    defer bellatrix_state.deinit();
    try expect(bellatrix_state.forkSeq() == .bellatrix);

    var capella_state = try bellatrix_state.upgradeUnsafe();
    defer capella_state.deinit();
    try expect(capella_state.forkSeq() == .capella);

    var deneb_state = try capella_state.upgradeUnsafe();
    defer deneb_state.deinit();
    try expect(deneb_state.forkSeq() == .deneb);

    var electra_state = try deneb_state.upgradeUnsafe();
    defer electra_state.deinit();
    try expect(electra_state.forkSeq() == .electra);

    var fulu_state = try electra_state.upgradeUnsafe();
    defer fulu_state.deinit();
    try expect(fulu_state.forkSeq() == .fulu);
}
