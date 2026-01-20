const std = @import("std");
const preset = @import("preset").preset;
const ForkSeq = @import("config").ForkSeq;
const Node = @import("persistent_merkle_tree").Node;
const isBasicType = @import("ssz").isBasicType;

const ForkTypes = @import("./fork_types.zig").ForkTypes;

pub fn ForkBeaconState(comptime f: ForkSeq) type {
    return struct {
        const Self = @This();

        inner: ForkTypes(f).BeaconState.TreeView,

        pub const fork_seq = f;

        pub fn baseView(self: *Self) @import("ssz").BaseTreeView {
            return self.inner.base_view;
        }

        pub fn clone(self: *Self, opts: @import("ssz").BaseTreeView.CloneOpts) !Self {
            return .{ .inner = try self.inner.clone(opts) };
        }

        pub fn commit(self: *Self) !void {
            try self.inner.commit();
        }

        pub fn hashTreeRoot(self: *Self) !*const [32]u8 {
            return try self.inner.hashTreeRoot();
        }

        pub fn deinit(self: *Self) void {
            self.inner.deinit();
        }

        pub fn genesisTime(self: *Self) !u64 {
            return self.inner.get("genesis_time");
        }

        pub fn genesisValidatorsRoot(self: *Self) !*const [32]u8 {
            return try self.inner.getRoot("genesis_validators_root");
        }

        pub fn slot(self: *Self) !u64 {
            return self.inner.get("slot");
        }

        pub fn setSlot(self: *Self, s: u64) !void {
            try self.inner.set("slot", s);
        }

        pub fn fork(self: *Self) !ForkTypes(f).Fork.TreeView {
            return try self.inner.get("fork");
        }

        pub fn forkCurrentVersion(self: *Self) ![4]u8 {
            var fork_view = try self.inner.getReadonly("fork");
            const current_version_root = try fork_view.getRoot("current_version");
            var version: [4]u8 = undefined;
            @memcpy(&version, current_version_root[0..4]);
            return version;
        }

        pub fn setFork(self: *Self, new_fork: *const ForkTypes(f).Fork.Type) !void {
            try self.inner.setValue("fork", new_fork);
        }

        pub fn latestBlockHeader(self: *Self) !ForkTypes(f).BeaconBlockHeader.TreeView {
            return try self.inner.get("latest_block_header");
        }

        pub fn setLatestBlockHeader(self: *Self, header: *const ForkTypes(f).BeaconBlockHeader.Type) !void {
            try self.inner.setValue("latest_block_header", header);
        }

        pub fn blockRoots(self: *Self) !ForkTypes(f).HistoricalBlockRoots.TreeView {
            return try self.inner.get("block_roots");
        }

        pub fn blockRootsRoot(self: *Self) !*const [32]u8 {
            return try self.inner.getRoot("block_roots");
        }

        pub fn stateRoots(self: *Self) !ForkTypes(f).HistoricalStateRoots.TreeView {
            return try self.inner.get("state_roots");
        }

        pub fn stateRootsRoot(self: *Self) !*const [32]u8 {
            return try self.inner.getRoot("state_roots");
        }

        pub fn historicalRoots(self: *Self) !ForkTypes(f).HistoricalRoots.TreeView {
            return try self.inner.get("historical_roots");
        }

        pub fn eth1Data(self: *Self) !ForkTypes(f).Eth1Data.TreeView {
            return try self.inner.get("eth1_data");
        }

        pub fn setEth1Data(self: *Self, eth1_data: *const ForkTypes(f).Eth1Data.Type) !void {
            try self.inner.setValue("eth1_data", eth1_data);
        }

        pub fn eth1DataVotes(self: *Self) !ForkTypes(f).Eth1DataVotes.TreeView {
            return try self.inner.get("eth1_data_votes");
        }

        pub fn setEth1DataVotes(self: *Self, eth1_data_votes: ForkTypes(f).Eth1DataVotes.TreeView) !void {
            try self.inner.set("eth1_data_votes", eth1_data_votes);
        }

        pub fn appendEth1DataVote(self: *Self, eth1_data: *const ForkTypes(f).Eth1Data.Type) !void {
            var votes = try self.eth1DataVotes();
            try votes.pushValue(eth1_data);
        }

        pub fn resetEth1DataVotes(self: *Self) !void {
            try self.inner.setValue("eth1_data_votes", &ForkTypes(f).Eth1DataVotes.default_value);
        }

        pub fn eth1DepositIndex(self: *Self) !u64 {
            return try self.inner.get("eth1_deposit_index");
        }

        pub fn setEth1DepositIndex(self: *Self, index: u64) !void {
            try self.inner.set("eth1_deposit_index", index);
        }

        pub fn incrementEth1DepositIndex(self: *Self) !void {
            try self.setEth1DepositIndex(try self.eth1DepositIndex() + 1);
        }

        pub fn validators(self: *Self) !ForkTypes(f).Validators.TreeView {
            return try self.inner.get("validators");
        }

        pub fn validatorsCount(self: *Self) !usize {
            var validators_view = try self.inner.getReadonly("validators");
            return validators_view.length();
        }

        pub fn validatorsSlice(self: *Self, allocator: std.mem.Allocator) ![]ForkTypes(f).Validator.Type {
            var validators_view = try self.inner.getReadonly("validators");
            return validators_view.getAllReadonlyValues(allocator);
        }

        pub fn balances(self: *Self) !ForkTypes(f).Balances.TreeView {
            return try self.inner.get("balances");
        }

        pub fn balancesSlice(self: *Self, allocator: std.mem.Allocator) ![]u64 {
            var balances_view = try self.inner.get("balances");
            try balances_view.commit();
            return balances_view.getAll(allocator);
        }

        pub fn setBalances(self: *Self, b: *const ForkTypes(f).Balances.Type) !void {
            try self.inner.setValue("balances", b);
        }

        pub fn randaoMixes(self: *Self) !ForkTypes(f).RandaoMixes.TreeView {
            return try self.inner.get("randao_mixes");
        }

        pub fn setRandaoMix(self: *Self, epoch: u64, randao_mix: *const ForkTypes(f).Bytes32.Type) !void {
            var mixes = try self.randaoMixes();
            try mixes.setValue(epoch % preset.EPOCHS_PER_HISTORICAL_VECTOR, randao_mix);
        }

        pub fn slashings(self: *Self) !ForkTypes(f).Slashings.TreeView {
            return try self.inner.get("slashings");
        }

        pub fn previousEpochPendingAttestations(self: *Self) !ForkTypes(.phase0).EpochAttestations.TreeView {
            if (comptime f != .phase0) return error.InvalidAtFork;
            return try self.inner.get("previous_epoch_attestations");
        }

        pub fn currentEpochPendingAttestations(self: *Self) !ForkTypes(.phase0).EpochAttestations.TreeView {
            if (comptime f != .phase0) return error.InvalidAtFork;
            return try self.inner.get("current_epoch_attestations");
        }

        pub fn rotateEpochPendingAttestations(self: *Self) !void {
            if (comptime f != .phase0) return error.InvalidAtFork;
            const current_root = try self.inner.getRootNode("current_epoch_attestations");
            try self.inner.setRootNode("previous_epoch_attestations", current_root);
            try self.inner.setValue("current_epoch_attestations", &ForkTypes(.phase0).EpochAttestations.default_value);
        }

        pub fn previousEpochParticipation(self: *Self) !ForkTypes(.altair).EpochParticipation.TreeView {
            if (comptime f == .phase0) return error.InvalidAtFork;
            return try self.inner.get("previous_epoch_participation");
        }

        pub fn setPreviousEpochParticipation(self: *Self, participations: *const ForkTypes(.altair).EpochParticipation.Type) !void {
            if (comptime f == .phase0) return error.InvalidAtFork;
            try self.inner.setValue("previous_epoch_participation", participations);
        }

        pub fn currentEpochParticipation(self: *Self) !ForkTypes(.altair).EpochParticipation.TreeView {
            if (comptime f == .phase0) return error.InvalidAtFork;
            return try self.inner.get("current_epoch_participation");
        }

        pub fn setCurrentEpochParticipation(self: *Self, participations: *const ForkTypes(.altair).EpochParticipation.Type) !void {
            if (comptime f == .phase0) return error.InvalidAtFork;
            try self.inner.setValue("current_epoch_participation", participations);
        }

        pub fn rotateEpochParticipation(self: *Self) !void {
            if (comptime f == .phase0) return error.InvalidAtFork;

            var current_epoch_participation = try self.inner.get("current_epoch_participation");
            try current_epoch_participation.commit();
            const length = try current_epoch_participation.length();
            try self.inner.set(
                "previous_epoch_participation",
                try current_epoch_participation.clone(.{ .transfer_cache = true }),
            );

            const new_current_root = try ForkTypes(.altair).EpochParticipation.tree.zeros(
                self.inner.base_view.pool,
                length,
            );
            errdefer self.inner.base_view.pool.unref(new_current_root);
            try self.inner.setRootNode("current_epoch_participation", new_current_root);
        }

        pub fn justificationBits(self: *Self) !ForkTypes(f).JustificationBits.TreeView {
            return try self.inner.get("justification_bits");
        }

        pub fn setJustificationBits(self: *Self, bits: *const ForkTypes(f).JustificationBits.Type) !void {
            try self.inner.setValue("justification_bits", bits);
        }

        pub fn previousJustifiedCheckpoint(self: *Self, out: *ForkTypes(f).Checkpoint.Type) !void {
            try self.inner.getValue(undefined, "previous_justified_checkpoint", out);
        }

        pub fn setPreviousJustifiedCheckpoint(self: *Self, checkpoint: *const ForkTypes(f).Checkpoint.Type) !void {
            try self.inner.setValue("previous_justified_checkpoint", checkpoint);
        }

        pub fn currentJustifiedCheckpoint(self: *Self, out: *ForkTypes(f).Checkpoint.Type) !void {
            try self.inner.getValue(undefined, "current_justified_checkpoint", out);
        }

        pub fn setCurrentJustifiedCheckpoint(self: *Self, checkpoint: *const ForkTypes(f).Checkpoint.Type) !void {
            try self.inner.setValue("current_justified_checkpoint", checkpoint);
        }

        pub fn finalizedCheckpoint(self: *Self, out: *ForkTypes(f).Checkpoint.Type) !void {
            try self.inner.getValue(undefined, "finalized_checkpoint", out);
        }

        pub fn setFinalizedCheckpoint(self: *Self, checkpoint: *const ForkTypes(f).Checkpoint.Type) !void {
            try self.inner.setValue("finalized_checkpoint", checkpoint);
        }

        pub fn finalizedEpoch(self: *Self) !u64 {
            var checkpoint_view = try self.inner.getReadonly("finalized_checkpoint");
            return try checkpoint_view.get("epoch");
        }

        pub fn inactivityScores(self: *Self) !ForkTypes(.altair).InactivityScores.TreeView {
            if (comptime f == .phase0) return error.InvalidAtFork;
            return try self.inner.get("inactivity_scores");
        }

        pub fn currentSyncCommittee(self: *Self) !ForkTypes(.altair).SyncCommittee.TreeView {
            if (comptime f == .phase0) return error.InvalidAtFork;
            return try self.inner.get("current_sync_committee");
        }

        pub fn setCurrentSyncCommittee(self: *Self, sync_committee: *const ForkTypes(.altair).SyncCommittee.Type) !void {
            if (comptime f == .phase0) return error.InvalidAtFork;
            try self.inner.setValue("current_sync_committee", sync_committee);
        }

        pub fn nextSyncCommittee(self: *Self) !ForkTypes(.altair).SyncCommittee.TreeView {
            if (comptime f == .phase0) return error.InvalidAtFork;
            return try self.inner.get("next_sync_committee");
        }

        pub fn setNextSyncCommittee(self: *Self, sync_committee: *const ForkTypes(.altair).SyncCommittee.Type) !void {
            if (comptime f == .phase0) return error.InvalidAtFork;
            try self.inner.setValue("next_sync_committee", sync_committee);
        }

        pub fn rotateSyncCommittees(self: *Self, next_sync_committee: *const ForkTypes(.altair).SyncCommittee.Type) !void {
            if (comptime f == .phase0) return error.InvalidAtFork;
            const next_sync_committee_root = try self.inner.getRootNode("next_sync_committee");
            try self.inner.setRootNode("current_sync_committee", next_sync_committee_root);
            try self.inner.setValue("next_sync_committee", next_sync_committee);
        }

        pub fn latestExecutionPayloadHeader(self: *Self, allocator: std.mem.Allocator, out: *ForkTypes(f).ExecutionPayloadHeader) !void {
            if (comptime (f.lt(.bellatrix))) return error.InvalidAtFork;
            try self.inner.getValue(allocator, "latest_execution_payload_header", &out);
        }

        pub fn latestExecutionPayloadHeaderBlockHash(self: *Self) !*const [32]u8 {
            if (comptime (f.lt(.bellatrix))) return error.InvalidAtFork;
            var header = try self.inner.get("latest_execution_payload_header");
            return try header.getRoot("block_hash");
        }

        pub fn setLatestExecutionPayloadHeader(self: *Self, header: *const ForkTypes(f).ExecutionPayloadHeader) !void {
            if (comptime (f.lt(.bellatrix))) return error.InvalidAtFork;
            try self.inner.setValue("latest_execution_payload_header", &header);
        }

        pub fn nextWithdrawalIndex(self: *Self) !u64 {
            if (comptime (f == .phase0 or f == .altair or f == .bellatrix)) return error.InvalidAtFork;
            return try self.inner.get("next_withdrawal_index");
        }

        pub fn setNextWithdrawalIndex(self: *Self, next_withdrawal_index: u64) !void {
            if (comptime (f == .phase0 or f == .altair or f == .bellatrix)) return error.InvalidAtFork;
            try self.inner.set("next_withdrawal_index", next_withdrawal_index);
        }

        pub fn nextWithdrawalValidatorIndex(self: *Self) !u64 {
            if (comptime (f == .phase0 or f == .altair or f == .bellatrix)) return error.InvalidAtFork;
            return try self.inner.get("next_withdrawal_validator_index");
        }

        pub fn setNextWithdrawalValidatorIndex(self: *Self, next_withdrawal_validator_index: u64) !void {
            if (comptime (f == .phase0 or f == .altair or f == .bellatrix)) return error.InvalidAtFork;
            try self.inner.set("next_withdrawal_validator_index", next_withdrawal_validator_index);
        }

        pub fn historicalSummaries(self: *Self) !ForkTypes(.capella).HistoricalSummaries.TreeView {
            if (comptime (f == .phase0 or f == .altair or f == .bellatrix)) return error.InvalidAtFork;
            return try self.inner.get("historical_summaries");
        }

        pub fn depositRequestsStartIndex(self: *Self) !u64 {
            if (comptime (f == .phase0 or f == .altair or f == .bellatrix or f == .capella or f == .deneb)) return error.InvalidAtFork;
            return try self.inner.get("deposit_requests_start_index");
        }

        pub fn setDepositRequestsStartIndex(self: *Self, index: u64) !void {
            if (comptime (f == .phase0 or f == .altair or f == .bellatrix or f == .capella or f == .deneb)) return error.InvalidAtFork;
            try self.inner.set("deposit_requests_start_index", index);
        }

        pub fn depositBalanceToConsume(self: *Self) !u64 {
            if (comptime (f == .phase0 or f == .altair or f == .bellatrix or f == .capella or f == .deneb)) return error.InvalidAtFork;
            return try self.inner.get("deposit_balance_to_consume");
        }

        pub fn setDepositBalanceToConsume(self: *Self, balance: u64) !void {
            if (comptime (f == .phase0 or f == .altair or f == .bellatrix or f == .capella or f == .deneb)) return error.InvalidAtFork;
            try self.inner.set("deposit_balance_to_consume", balance);
        }

        pub fn exitBalanceToConsume(self: *Self) !u64 {
            if (comptime (f == .phase0 or f == .altair or f == .bellatrix or f == .capella or f == .deneb)) return error.InvalidAtFork;
            return try self.inner.get("exit_balance_to_consume");
        }

        pub fn setExitBalanceToConsume(self: *Self, balance: u64) !void {
            if (comptime (f == .phase0 or f == .altair or f == .bellatrix or f == .capella or f == .deneb)) return error.InvalidAtFork;
            try self.inner.set("exit_balance_to_consume", balance);
        }

        pub fn earliestExitEpoch(self: *Self) !u64 {
            if (comptime (f == .phase0 or f == .altair or f == .bellatrix or f == .capella or f == .deneb)) return error.InvalidAtFork;
            return try self.inner.get("earliest_exit_epoch");
        }

        pub fn setEarliestExitEpoch(self: *Self, epoch: u64) !void {
            if (comptime (f == .phase0 or f == .altair or f == .bellatrix or f == .capella or f == .deneb)) return error.InvalidAtFork;
            try self.inner.set("earliest_exit_epoch", epoch);
        }

        pub fn consolidationBalanceToConsume(self: *Self) !u64 {
            if (comptime (f == .phase0 or f == .altair or f == .bellatrix or f == .capella or f == .deneb)) return error.InvalidAtFork;
            return try self.inner.get("consolidation_balance_to_consume");
        }

        pub fn setConsolidationBalanceToConsume(self: *Self, balance: u64) !void {
            if (comptime (f == .phase0 or f == .altair or f == .bellatrix or f == .capella or f == .deneb)) return error.InvalidAtFork;
            try self.inner.set("consolidation_balance_to_consume", balance);
        }

        pub fn earliestConsolidationEpoch(self: *Self) !u64 {
            if (comptime (f == .phase0 or f == .altair or f == .bellatrix or f == .capella or f == .deneb)) return error.InvalidAtFork;
            return try self.inner.get("earliest_consolidation_epoch");
        }

        pub fn setEarliestConsolidationEpoch(self: *Self, epoch: u64) !void {
            if (comptime (f == .phase0 or f == .altair or f == .bellatrix or f == .capella or f == .deneb)) return error.InvalidAtFork;
            try self.inner.set("earliest_consolidation_epoch", epoch);
        }

        pub fn pendingDeposits(self: *Self) !ForkTypes(.electra).PendingDeposits.TreeView {
            if (comptime (f == .phase0 or f == .altair or f == .bellatrix or f == .capella or f == .deneb)) return error.InvalidAtFork;
            return try self.inner.get("pending_deposits");
        }

        pub fn setPendingDeposits(self: *Self, deposits: ForkTypes(.electra).PendingDeposits.TreeView) !void {
            if (comptime (f == .phase0 or f == .altair or f == .bellatrix or f == .capella or f == .deneb)) return error.InvalidAtFork;
            try self.inner.set("pending_deposits", deposits);
        }

        pub fn pendingPartialWithdrawals(self: *Self) !ForkTypes(.electra).PendingPartialWithdrawals.TreeView {
            if (comptime (f == .phase0 or f == .altair or f == .bellatrix or f == .capella or f == .deneb)) return error.InvalidAtFork;
            return try self.inner.get("pending_partial_withdrawals");
        }

        pub fn setPendingPartialWithdrawals(self: *Self, pending_partial_withdrawals: ForkTypes(.electra).PendingPartialWithdrawals.TreeView) !void {
            if (comptime (f == .phase0 or f == .altair or f == .bellatrix or f == .capella or f == .deneb)) return error.InvalidAtFork;
            try self.inner.set("pending_partial_withdrawals", pending_partial_withdrawals);
        }

        pub fn pendingConsolidations(self: *Self) !ForkTypes(.electra).PendingConsolidations.TreeView {
            if (comptime (f == .phase0 or f == .altair or f == .bellatrix or f == .capella or f == .deneb)) return error.InvalidAtFork;
            return try self.inner.get("pending_consolidations");
        }

        pub fn setPendingConsolidations(self: *Self, consolidations: ForkTypes(.electra).PendingConsolidations.TreeView) !void {
            if (comptime (f == .phase0 or f == .altair or f == .bellatrix or f == .capella or f == .deneb)) return error.InvalidAtFork;
            try self.inner.set("pending_consolidations", consolidations);
        }

        pub fn proposerLookahead(self: *Self) !ForkTypes(.fulu).ProposerLookahead.TreeView {
            if (comptime (f == .phase0 or f == .altair or f == .bellatrix or f == .capella or f == .deneb or f == .electra)) return error.InvalidAtFork;
            return try self.inner.get("proposer_lookahead");
        }

        pub fn proposerLookaheadSlice(self: *Self, allocator: std.mem.Allocator) !*[ForkTypes(.fulu).ProposerLookahead.length]u64 {
            var lookahead_view = try self.proposerLookahead();
            return @ptrCast(try lookahead_view.getAll(allocator));
        }

        pub fn setProposerLookahead(self: *Self, proposer_lookahead: *const [ForkTypes(.fulu).ProposerLookahead.length]u64) !void {
            if (comptime (f == .phase0 or f == .altair or f == .bellatrix or f == .capella or f == .deneb or f == .electra)) return error.InvalidAtFork;
            try self.inner.setValue("proposer_lookahead", proposer_lookahead);
        }

        fn populateFields(
            comptime F: type,
            comptime T: type,
            allocator: std.mem.Allocator,
            pool: *Node.Pool,
            state: F.TreeView,
        ) !T.TreeView {
            var committed_state = state;
            try committed_state.commit();

            var upgraded = try T.TreeView.fromValue(allocator, pool, &T.default_value);
            errdefer upgraded.deinit();

            inline for (F.fields) |fld| {
                if (comptime T.hasField(fld.name)) {
                    if (T.getFieldType(fld.name) != fld.type) continue;

                    if (comptime isBasicType(fld.type)) {
                        try upgraded.set(fld.name, try committed_state.get(fld.name));
                    } else {
                        var field_view = try committed_state.get(fld.name);
                        var owned_field_view = try field_view.clone(.{ .transfer_cache = true });
                        errdefer owned_field_view.deinit();
                        try upgraded.set(fld.name, owned_field_view);
                    }
                }
            }

            try upgraded.commit();
            return upgraded;
        }

        pub fn upgradeUnsafe(self: *Self) !ForkBeaconState(switch (f) {
            .phase0 => .altair,
            .altair => .bellatrix,
            .bellatrix => .capella,
            .capella => .deneb,
            .deneb => .electra,
            .electra => .fulu,
            .fulu => error.InvalidAtFork,
        }) {
            const cur = self.inner;
            const allocator = cur.base_view.allocator;
            const pool = cur.base_view.pool;

            return switch (comptime f) {
                .phase0 => .{ .inner = try populateFields(ForkTypes(.phase0).BeaconState, ForkTypes(.altair).BeaconState, allocator, pool, cur) },
                .altair => .{ .inner = try populateFields(ForkTypes(.altair).BeaconState, ForkTypes(.bellatrix).BeaconState, allocator, pool, cur) },
                .bellatrix => .{ .inner = try populateFields(ForkTypes(.bellatrix).BeaconState, ForkTypes(.capella).BeaconState, allocator, pool, cur) },
                .capella => .{ .inner = try populateFields(ForkTypes(.capella).BeaconState, ForkTypes(.deneb).BeaconState, allocator, pool, cur) },
                .deneb => .{ .inner = try populateFields(ForkTypes(.deneb).BeaconState, ForkTypes(.electra).BeaconState, allocator, pool, cur) },
                .electra => .{ .inner = try populateFields(ForkTypes(.electra).BeaconState, ForkTypes(.fulu).BeaconState, allocator, pool, cur) },
                .fulu => return error.InvalidAtFork,
            };
        }
    };
}
