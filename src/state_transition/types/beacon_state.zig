const std = @import("std");
const Allocator = std.mem.Allocator;
const expect = std.testing.expect;
const preset = @import("preset").preset;
const ForkSeq = @import("config").ForkSeq;
const Node = @import("persistent_merkle_tree").Node;
const isFixedType = @import("ssz").isFixedType;
const CloneOpts = @import("ssz").tree_view.BaseTreeView.CloneOpts;
const ct = @import("consensus_types");
const ExecutionPayloadHeader = @import("./execution_payload.zig").ExecutionPayloadHeader;

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
        };
    }

    pub fn serialize(self: BeaconState, allocator: Allocator) ![]u8 {
        switch (self) {
            .phase0 => |state| {
                const out = try allocator.alloc(u8, try state.serializedSize());
                errdefer allocator.free(out);
                _ = state.serializeIntoBytes(out);
                return out;
            },
            .altair => |state| {
                const out = try allocator.alloc(u8, state.serializedSize());
                errdefer allocator.free(out);
                _ = state.serializeIntoBytes(out);
                return out;
            },
            .bellatrix => |state| {
                const out = try allocator.alloc(u8, state.serializedSize());
                errdefer allocator.free(out);
                _ = state.serializeIntoBytes(out);
                return out;
            },
            .capella => |state| {
                const out = try allocator.alloc(u8, state.serializedSize());
                errdefer allocator.free(out);
                _ = state.serializeIntoBytes(out);
                return out;
            },
            .deneb => |state| {
                const out = try allocator.alloc(u8, state.serializedSize());
                errdefer allocator.free(out);
                _ = state.serializeIntoBytes(out);
                return out;
            },
            .electra => |state| {
                const out = try allocator.alloc(u8, state.serializedSize());
                errdefer allocator.free(out);
                _ = state.serializeIntoBytes(out);
                return out;
            },
            .fulu => |state| {
                const out = try allocator.alloc(u8, state.serializedSize());
                errdefer allocator.free(out);
                _ = state.serializeIntoBytes(out);
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

    pub fn clone(self: *const BeaconState, opts: CloneOpts) !BeaconState {
        return switch (self.*) {
            .phase0 => |state| .{ .phase0 = try state.clone(opts) },
            .altair => |state| .{ .altair = try state.clone(opts) },
            .bellatrix => |state| .{ .bellatrix = try state.clone(opts) },
            .capella => |state| .{ .capella = try state.clone(opts) },
            .deneb => |state| .{ .deneb = try state.clone(opts) },
            .electra => |state| .{ .electra = try state.clone(opts) },
            .fulu => |state| .{ .fulu = try state.clone(opts) },
        };
    }

    pub fn commit(self: *const BeaconState) !void {
        switch (self.*) {
            inline else => |*state| try @constCast(state).commit(),
        }
    }

    pub fn hashTreeRoot(self: *const BeaconState) !*const [32]u8 {
        return switch (self.*) {
            inline else => |*state| {
                try state.commit();
                return state.base_view.root.getRoot(state.base_view.pool);
            },
        };
    }

    pub fn deinit(self: *BeaconState) void {
        switch (self.*) {
            inline else => |*state| state.deinit(),
        }
    }

    pub fn forkSeq(self: *const BeaconState) ForkSeq {
        return (self.*);
    }

    pub fn genesisTime(self: *const BeaconState) !u64 {
        return switch (self.*) {
            inline else => |state| try state.get("genesis_time"),
        };
    }

    pub fn genesisValidatorsRoot(self: *const BeaconState) !*const [32]u8 {
        return switch (self.*) {
            inline else => |state| try state.getRoot("genesis_validators_root"),
        };
    }

    pub fn slot(self: *const BeaconState) !u64 {
        return switch (self.*) {
            inline else => |state| try state.get("slot"),
        };
    }

    pub fn setSlot(self: *BeaconState, s: u64) !void {
        switch (self.*) {
            inline else => |*state| try state.set("slot", s),
        }
    }

    pub fn fork(self: *const BeaconState) !ct.phase0.Fork.TreeView {
        return switch (self.*) {
            inline else => |state| try state.get("fork"),
        };
    }

    pub fn setFork(self: *BeaconState, f: *const ct.phase0.Fork.Value) !void {
        switch (self.*) {
            inline else => |*state| try state.setValue("fork", f),
        }
    }

    pub fn latestBlockHeader(self: *const BeaconState) !ct.phase0.BeaconBlockHeader.TreeView {
        return switch (self.*) {
            inline else => |state| try state.get("latest_block_header"),
        };
    }

    pub fn setLatestBlockHeader(self: *BeaconState, header: *const ct.phase0.BeaconBlockHeader.Type) !void {
        switch (self.*) {
            inline else => |*state| try state.setValue("latest_block_header", header),
        }
    }

    pub fn blockRoots(self: *const BeaconState) !ct.phase0.HistoricalBlockRoots.TreeView {
        return switch (self.*) {
            inline else => |state| try state.get("block_roots"),
        };
    }

    pub fn stateRoots(self: *const BeaconState) !ct.phase0.HistoricalStateRoots.TreeView {
        return switch (self.*) {
            inline else => |state| try state.get("state_roots"),
        };
    }

    pub fn historicalRoots(self: *const BeaconState) !ct.phase0.HistoricalRoots.TreeView {
        return switch (self.*) {
            inline else => |state| try state.get("historical_roots"),
        };
    }

    pub fn eth1Data(self: *const BeaconState) !ct.phase0.Eth1Data.TreeView {
        return switch (self.*) {
            inline else => |state| try state.get("eth1_data"),
        };
    }

    pub fn setEth1Data(self: *BeaconState, eth1_data: *const ct.phase0.Eth1Data.Type) !void {
        switch (self.*) {
            inline else => |*state| try state.setValue("eth1_data", eth1_data),
        }
    }

    pub fn eth1DataVotes(self: *const BeaconState) !ct.phase0.Eth1DataVotes.TreeView {
        return switch (self.*) {
            inline else => |state| try state.get("eth1_data_votes"),
        };
    }

    pub fn appendEth1DataVote(self: *BeaconState, eth1_data: *const ct.phase0.Eth1Data.Type) !void {
        var votes = try self.eth1DataVotes();
        const VotesView = @TypeOf(votes);
        const ElemST = VotesView.SszType.Element;

        const child_root = try ElemST.tree.fromValue(votes.base_view.pool, eth1_data);
        errdefer votes.base_view.pool.unref(child_root);
        const child_view = try ElemST.TreeView.init(
            votes.base_view.allocator,
            votes.base_view.pool,
            child_root,
        );

        try votes.push(child_view);
    }

    pub fn eth1DepositIndex(self: *const BeaconState) !u64 {
        return switch (self.*) {
            inline else => |state| try state.get("eth1_deposit_index"),
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

    pub fn validators(self: *const BeaconState) !ct.phase0.Validators.TreeView {
        return switch (self.*) {
            inline else => |state| try state.get("validators"),
        };
    }

    // Returns a read-only slice of validators.
    // Caller owns the returned slice and must free it with the same allocator.
    pub fn validatorsSlice(self: *const BeaconState, allocator: Allocator) ![]const ct.phase0.Validator.Type {
        return switch (self.*) {
            inline else => |state| {
                var validators_view = try state.get("validators");
                return validators_view.getAllReadonlyValues(allocator);
            },
        };
    }

    pub fn balances(self: *const BeaconState) !ct.phase0.Balances.TreeView {
        return switch (self.*) {
            inline else => |state| try state.get("balances"),
        };
    }

    pub fn randaoMixes(self: *const BeaconState) !ct.phase0.RandaoMixes.TreeView {
        return switch (self.*) {
            inline else => |state| try state.get("randao_mixes"),
        };
    }

    pub fn setRandaoMix(self: *BeaconState, epoch: u64, randao_mix: *const ct.primitive.Bytes32.Type) !void {
        var mixes = try self.randaoMixes();
        const MixesView = @TypeOf(mixes);
        const ElemST = MixesView.SszType.Element;

        const child_root = try ElemST.tree.fromValue(mixes.base_view.pool, randao_mix);
        errdefer mixes.base_view.pool.unref(child_root);
        const child_view = try ElemST.TreeView.init(
            mixes.base_view.allocator,
            mixes.base_view.pool,
            child_root,
        );

        try mixes.set(epoch % preset.EPOCHS_PER_HISTORICAL_VECTOR, child_view);
    }

    pub fn slashings(self: *const BeaconState) !ct.phase0.Slashings.TreeView {
        return switch (self.*) {
            inline else => |state| try state.get("slashings"),
        };
    }

    pub fn previousEpochPendingAttestations(self: *const BeaconState) !ct.phase0.EpochAttestations.TreeView {
        return switch (self.*) {
            .phase0 => |state| try state.get("previous_epoch_attestations"),
            else => error.InvalidAtFork,
        };
    }

    pub fn currentEpochPendingAttestations(self: *const BeaconState) !ct.phase0.EpochAttestations.TreeView {
        return switch (self.*) {
            .phase0 => |state| try state.get("current_epoch_attestations"),
            else => error.InvalidAtFork,
        };
    }

    pub fn rotateEpochPendingAttestations(self: *BeaconState) !void {
        return switch (self.*) {
            .phase0 => |*state| {
                const current_epoch_attestations = try state.get("current_epoch_attestations");
                try state.set("previous_epoch_attestations", current_epoch_attestations);
                try state.setValue("current_epoch_attestations", &ct.phase0.EpochAttestations.default_value);
            },
            else => error.InvalidAtFork,
        };
    }

    pub fn previousEpochParticipation(self: *const BeaconState) !ct.altair.EpochParticipation.TreeView {
        return switch (self.*) {
            .phase0 => error.InvalidAtFork,
            inline else => |state| try state.get("previous_epoch_participation"),
        };
    }

    pub fn setPreviousEpochParticipation(self: *BeaconState, participations: *const ct.altair.EpochParticipation.Type) !void {
        return switch (self.*) {
            .phase0 => error.InvalidAtFork,
            inline else => |*state| try state.setValue("previous_epoch_participation", participations),
        };
    }

    pub fn currentEpochParticipation(self: *const BeaconState) !ct.altair.EpochParticipation.TreeView {
        return switch (self.*) {
            .phase0 => error.InvalidAtFork,
            inline else => |state| try state.get("current_epoch_participation"),
        };
    }

    pub fn rotateEpochParticipation(self: *BeaconState) !void {
        return switch (self.*) {
            .phase0 => error.InvalidAtFork,
            inline else => |*state| {
                const current_epoch_participation = try state.get("current_epoch_participation");
                try state.set("previous_epoch_participation", current_epoch_participation);
                try state.setValue("current_epoch_participation", &ct.altair.EpochParticipation.default_value);
            },
        };
    }

    pub fn justificationBits(self: *const BeaconState) !ct.phase0.JustificationBits.TreeView {
        return switch (self.*) {
            inline else => |state| try state.get("justification_bits"),
        };
    }

    pub fn previousJustifiedCheckpoint(self: *const BeaconState) !ct.phase0.Checkpoint.TreeView {
        return switch (self.*) {
            inline else => |state| try state.get("previous_justified_checkpoint"),
        };
    }

    pub fn currentJustifiedCheckpoint(self: *const BeaconState) !ct.phase0.Checkpoint.TreeView {
        return switch (self.*) {
            inline else => |state| try state.get("current_justified_checkpoint"),
        };
    }

    pub fn finalizedCheckpoint(self: *const BeaconState) !ct.phase0.Checkpoint.TreeView {
        return switch (self.*) {
            inline else => |state| try state.get("finalized_checkpoint"),
        };
    }

    pub fn inactivityScores(self: *const BeaconState) !ct.altair.InactivityScores.TreeView {
        return switch (self.*) {
            .phase0 => error.InvalidAtFork,
            inline else => |state| try state.get("inactivity_scores"),
        };
    }

    pub fn currentSyncCommittee(self: *const BeaconState) !ct.altair.SyncCommittee.TreeView {
        return switch (self.*) {
            .phase0 => error.InvalidAtFork,
            inline else => |state| try state.get("current_sync_committee"),
        };
    }

    pub fn setCurrentSyncCommittee(self: *BeaconState, sync_committee: *const ct.altair.SyncCommittee.Type) !void {
        return switch (self.*) {
            .phase0 => error.InvalidAtFork,
            inline else => |*state| try state.setValue("current_sync_committee", sync_committee),
        };
    }

    pub fn nextSyncCommittee(self: *const BeaconState) !ct.altair.SyncCommittee.TreeView {
        return switch (self.*) {
            .phase0 => error.InvalidAtFork,
            inline else => |state| try state.get("next_sync_committee"),
        };
    }

    pub fn setNextSyncCommittee(self: *BeaconState, sync_committee: *const ct.altair.SyncCommittee.Type) !void {
        return switch (self.*) {
            .phase0 => error.InvalidAtFork,
            inline else => |*state| try state.setValue("next_sync_committee", sync_committee),
        };
    }

    pub fn latestExecutionPayloadHeader(self: *const BeaconState, allocator: Allocator) !ExecutionPayloadHeader {
        return switch (self.*) {
            .phase0, .altair => error.InvalidAtFork,
            .bellatrix => |state| .{
                .bellatrix = (try state.get("latest_execution_payload_header")).toValue(allocator),
            },
            .capella => |state| .{
                .capella = (try state.get("latest_execution_payload_header")).toValue(allocator),
            },
            .deneb => |state| .{
                .deneb = (try state.get("latest_execution_payload_header")).toValue(allocator),
            },
            .electra => |state| .{
                .deneb = (try state.get("latest_execution_payload_header")).toValue(allocator),
            },
            .fulu => |state| .{
                .deneb = (try state.get("latest_execution_payload_header")).toValue(allocator),
            },
        };
    }

    pub fn latestExecutionPayloadHeaderBlockHash(self: *const BeaconState) !*const [32]u8 {
        return switch (self.*) {
            .phase0, .altair => error.InvalidAtFork,
            inline else => |state| {
                const header = try state.get("latest_execution_payload_header");
                return try header.getRoot("block_hash");
            },
        };
    }

    // `header` ownership is transferred to BeaconState and will be deinit when state is deinit
    // caller must guarantee that `header` is properly initialized and allocated/cloned with `allocator` and no longer used after this call
    pub fn setLatestExecutionPayloadHeader(self: *BeaconState, header: ExecutionPayloadHeader) !void {
        switch (self.*) {
            .bellatrix => |*state| try state.setValue("latest_execution_payload_header", header.bellatrix),
            .capella => |*state| try state.setValue("latest_execution_payload_header", header.capella),
            .deneb => |*state| try state.setValue("latest_execution_payload_header", header.deneb),
            .electra => |*state| try state.setValue("latest_execution_payload_header", header.deneb),
            .fulu => |*state| try state.setValue("latest_execution_payload_header", header.deneb),
            else => return error.InvalidAtFork,
        }
    }

    pub fn nextWithdrawalIndex(self: *const BeaconState) !u64 {
        return switch (self.*) {
            .phase0, .altair, .bellatrix => error.InvalidAtFork,
            inline else => |state| try state.get("next_withdrawal_index"),
        };
    }

    pub fn setNextWithdrawalIndex(self: *BeaconState, next_withdrawal_index: u64) !void {
        return switch (self.*) {
            .phase0, .altair, .bellatrix => error.InvalidAtFork,
            inline else => |*state| try state.set("next_withdrawal_index", next_withdrawal_index),
        };
    }

    pub fn nextWithdrawalValidatorIndex(self: *const BeaconState) !u64 {
        return switch (self.*) {
            .phase0, .altair, .bellatrix => error.InvalidAtFork,
            inline else => |state| try state.get("next_withdrawal_validator_index"),
        };
    }

    pub fn setNextWithdrawalValidatorIndex(self: *BeaconState, next_withdrawal_validator_index: u64) !void {
        return switch (self.*) {
            .phase0, .altair, .bellatrix => error.InvalidAtFork,
            inline else => |*state| try state.set("next_withdrawal_validator_index", next_withdrawal_validator_index),
        };
    }

    pub fn historicalSummaries(self: *const BeaconState) !ct.capella.HistoricalSummaries.TreeView {
        return switch (self.*) {
            .phase0, .altair, .bellatrix => error.InvalidAtFork,
            inline else => |state| try state.get("historical_summaries"),
        };
    }

    pub fn depositRequestsStartIndex(self: *const BeaconState) !u64 {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |state| try state.get("deposit_requests_start_index"),
        };
    }

    pub fn setDepositRequestsStartIndex(self: *BeaconState, index: u64) !void {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |*state| try state.set("deposit_requests_start_index", index),
        };
    }

    pub fn depositBalanceToConsume(self: *const BeaconState) !u64 {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |state| try state.get("deposit_balance_to_consume"),
        };
    }

    pub fn setDepositBalanceToConsume(self: *BeaconState, balance: u64) !void {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |*state| try state.set("deposit_balance_to_consume", balance),
        };
    }

    pub fn exitBalanceToConsume(self: *const BeaconState) !u64 {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |state| try state.get("exit_balance_to_consume"),
        };
    }

    pub fn setExitBalanceToConsume(self: *BeaconState, balance: u64) !void {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |*state| try state.set("exit_balance_to_consume", balance),
        };
    }

    pub fn earliestExitEpoch(self: *const BeaconState) !u64 {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |state| try state.get("earliest_exit_epoch"),
        };
    }

    pub fn setEarliestExitEpoch(self: *BeaconState, epoch: u64) !void {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |*state| try state.set("earliest_exit_epoch", epoch),
        };
    }

    pub fn consolidationBalanceToConsume(self: *const BeaconState) !u64 {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |state| try state.get("consolidation_balance_to_consume"),
        };
    }

    pub fn setConsolidationBalanceToConsume(self: *BeaconState, balance: u64) !void {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |*state| try state.set("consolidation_balance_to_consume", balance),
        };
    }

    pub fn earliestConsolidationEpoch(self: *const BeaconState) !u64 {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |state| try state.get("earliest_consolidation_epoch"),
        };
    }

    pub fn setEarliestConsolidationEpoch(self: *BeaconState, epoch: u64) !void {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |*state| try state.set("earliest_consolidation_epoch", epoch),
        };
    }

    pub fn pendingDeposits(self: *const BeaconState) !ct.electra.PendingDeposits.TreeView {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |state| try state.get("pending_deposits"),
        };
    }

    pub fn pendingPartialWithdrawals(self: *const BeaconState) !ct.electra.PendingPartialWithdrawals.TreeView {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |state| try state.get("pending_partial_withdrawals"),
        };
    }

    pub fn pendingConsolidations(self: *const BeaconState) !ct.electra.PendingConsolidations.TreeView {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => error.InvalidAtFork,
            inline else => |state| try state.get("pending_consolidations"),
        };
    }

    /// Get proposer_lookahead
    pub fn proposerLookahead(self: *const BeaconState) !ct.fulu.ProposerLookahead.TreeView {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb, .electra => error.InvalidAtFork,
            inline else => |state| try state.get("proposer_lookahead"),
        };
    }

    pub fn setProposerLookahead(self: *BeaconState, proposer_lookahead: *const ct.fulu.ProposerLookahead.Type) !void {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb, .electra => error.InvalidAtFork,
            inline else => |*state| try state.setValue("proposer_lookahead", proposer_lookahead),
        };
    }

    /// Copies fields of `BeaconState` from type `F` to type `T`, provided they have the same field name.
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
            const field_name: []const u8 = comptime f.name[0..f.name.len];
            if (@hasField(T.Fields, field_name)) {
                if (comptime isFixedType(f.type)) {
                    try upgraded.set(field_name, try committed_state.get(field_name));
                } else {
                    if (@field(T.Fields, field_name) != f.type) {
                        // BeaconState of prev_fork and cur_fork has the same field name but different types
                        // for example latest_execution_payload_header changed from Bellatrix to Capella
                        // In this case we just skip copying this field and leave it to caller to set properly
                    } else {
                        const source_node = try committed_state.getRootNode(field_name);
                        try upgraded.setRootNode(field_name, source_node);
                    }
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
    pub fn upgradeUnsafe(self: *const BeaconState) !BeaconState {
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

    const beacon_state = try BeaconState.fromValue(allocator, &pool, .electra, &ct.electra.BeaconState.default_value);
    defer beacon_state.deinit();

    try beacon_state.setSlot(12345);

    try std.testing.expect(beacon_state.genesisTime() == 0);
    try std.testing.expectEqualSlices(u8, &[_]u8{0} ** 32, &beacon_state.genesisValidatorsRoot());
    try std.testing.expect(beacon_state.slot() == 12345);
    try beacon_state.setSlot(2025);
    try std.testing.expect(beacon_state.slot() == 2025);

    const out: *const [32]u8 = try beacon_state.hashTreeRoot();
    try expect(!std.mem.eql(u8, &[_]u8{0} ** 32, &out));

    // TODO: more tests
}

test "clone - sanity" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    const beacon_state = try BeaconState.fromValue(allocator, &pool, .electra, &ct.electra.BeaconState.default_value);
    defer beacon_state.deinit();

    try beacon_state.setSlot(12345);

    // test the clone() and deinit() works fine without memory leak
    const cloned_state = try beacon_state.clone(.{});
    defer cloned_state.deinit();

    try expect(cloned_state.slot() == 12345);
}

test "upgrade state - sanity" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    const phase0_state = try BeaconState.fromValue(allocator, &pool, .phase0, &ct.phase0.BeaconState.default_value);
    defer phase0_state.deinit();

    const altair_state = try phase0_state.upgradeUnsafe();
    defer altair_state.deinit();
    try expect(altair_state.forkSeq() == .altair);

    const bellatrix_state = try altair_state.upgradeUnsafe();
    defer bellatrix_state.deinit();
    try expect(bellatrix_state.forkSeq() == .bellatrix);

    const capella_state = try bellatrix_state.upgradeUnsafe();
    defer capella_state.deinit();
    try expect(capella_state.forkSeq() == .capella);

    const deneb_state = try capella_state.upgradeUnsafe();
    defer deneb_state.deinit();
    try expect(deneb_state.forkSeq() == .deneb);

    const electra_state = try deneb_state.upgradeUnsafe();
    defer electra_state.deinit();
    try expect(electra_state.forkSeq() == .electra);

    const fulu_state = try electra_state.upgradeUnsafe();
    defer fulu_state.deinit();
    try expect(fulu_state.forkSeq() == .fulu);
}
