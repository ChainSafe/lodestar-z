const std = @import("std");
const panic = std.debug.panic;
const Allocator = std.mem.Allocator;
const expect = std.testing.expect;
const ct = @import("consensus_types");
const preset = @import("preset").preset;
const BeaconStatePhase0 = ct.phase0.BeaconState.Type;
const BeaconStateAltair = ct.altair.BeaconState.Type;
const BeaconStateBellatrix = ct.bellatrix.BeaconState.Type;
const BeaconStateCapella = ct.capella.BeaconState.Type;
const BeaconStateDeneb = ct.deneb.BeaconState.Type;
const BeaconStateElectra = ct.electra.BeaconState.Type;
const ExecutionPayloadHeader = @import("./execution_payload.zig").ExecutionPayloadHeader;
const Root = ct.primitive.Root.Type;
const Fork = ct.phase0.Fork.Type;
const BeaconBlockHeader = ct.phase0.BeaconBlockHeader.Type;
const Eth1Data = ct.phase0.Eth1Data.Type;
const Eth1DataVotes = ct.phase0.Eth1DataVotes.Type;
const Validator = ct.phase0.Validator.Type;
const Validators = ct.phase0.Validators.Type;
const PendingAttestation = ct.phase0.PendingAttestation.Type;
const JustificationBits = ct.phase0.JustificationBits.Type;
const Checkpoint = ct.phase0.Checkpoint.Type;
const SyncCommittee = ct.altair.SyncCommittee.Type;
const HistoricalSummary = ct.capella.HistoricalSummary.Type;
const PendingDeposit = ct.electra.PendingDeposit.Type;
const PendingPartialWithdrawal = ct.electra.PendingPartialWithdrawal.Type;
const PendingConsolidation = ct.electra.PendingConsolidation.Type;
const Bytes32 = ct.primitive.Bytes32.Type;
const Gwei = ct.primitive.Gwei.Type;
const Epoch = ct.primitive.Epoch.Type;
const ForkSeq = @import("config").ForkSeq;

/// wrapper for all BeaconState types across forks so that we don't have to do switch/case for all methods
/// right now this works with regular types
/// TODO: migrate this to TreeView and implement the same set of methods here because TreeView objects does not have a great Devex APIs
pub const BeaconStateAllForks = union(enum) {
    phase0: *BeaconStatePhase0,
    altair: *BeaconStateAltair,
    bellatrix: *BeaconStateBellatrix,
    capella: *BeaconStateCapella,
    deneb: *BeaconStateDeneb,
    electra: *BeaconStateElectra,

    pub fn init(f: ForkSeq, state_any: anytype) !@This() {
        var state: @This() = undefined;

        switch (f) {
            .phase0 => {
                const T = ct.phase0.BeaconState;
                const src: *T.Type = @ptrCast(@alignCast(state_any));
                state = .{ .phase0 = src };
            },
            .altair => {
                const T = ct.altair.BeaconState;
                const src: *T.Type = @ptrCast(@alignCast(state_any));
                state = .{ .altair = src };
            },
            .bellatrix => {
                const T = ct.bellatrix.BeaconState;
                const src: *T.Type = @ptrCast(@alignCast(state_any));
                state = .{ .bellatrix = src };
            },
            .capella => {
                const T = ct.capella.BeaconState;
                const src: *T.Type = @ptrCast(@alignCast(state_any));
                state = .{ .capella = src };
            },
            .deneb => {
                const T = ct.deneb.BeaconState;
                const src: *T.Type = @ptrCast(@alignCast(state_any));
                state = .{ .deneb = src };
            },
            .electra => {
                const T = ct.electra.BeaconState;
                const src: *T.Type = @ptrCast(@alignCast(state_any));
                state = .{ .electra = src };
            },
        }

        return state;
    }

    pub fn format(
        self: BeaconStateAllForks,
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

    pub fn clone(self: *const BeaconStateAllForks, allocator: std.mem.Allocator) !*BeaconStateAllForks {
        const out = try allocator.create(BeaconStateAllForks);
        errdefer allocator.destroy(out);
        switch (self.*) {
            .phase0 => |state| {
                const cloned_state = try allocator.create(BeaconStatePhase0);
                errdefer allocator.destroy(cloned_state);
                out.* = .{ .phase0 = cloned_state };
                try ct.phase0.BeaconState.clone(allocator, state, cloned_state);
            },
            .altair => |state| {
                const cloned_state = try allocator.create(BeaconStateAltair);
                errdefer allocator.destroy(cloned_state);
                out.* = .{ .altair = cloned_state };
                try ct.altair.BeaconState.clone(allocator, state, cloned_state);
            },
            .bellatrix => |state| {
                const cloned_state = try allocator.create(BeaconStateBellatrix);
                errdefer allocator.destroy(cloned_state);
                out.* = .{ .bellatrix = cloned_state };
                try ct.bellatrix.BeaconState.clone(allocator, state, cloned_state);
            },
            .capella => |state| {
                const cloned_state = try allocator.create(BeaconStateCapella);
                errdefer allocator.destroy(cloned_state);
                out.* = .{ .capella = cloned_state };
                try ct.capella.BeaconState.clone(allocator, state, cloned_state);
            },
            .deneb => |state| {
                const cloned_state = try allocator.create(BeaconStateDeneb);
                errdefer allocator.destroy(cloned_state);
                out.* = .{ .deneb = cloned_state };
                try ct.deneb.BeaconState.clone(allocator, state, cloned_state);
            },
            .electra => |state| {
                const cloned_state = try allocator.create(BeaconStateElectra);
                errdefer allocator.destroy(cloned_state);
                out.* = .{ .electra = cloned_state };
                try ct.electra.BeaconState.clone(allocator, state, cloned_state);
            },
        }

        return out;
    }

    pub fn hashTreeRoot(self: *const BeaconStateAllForks, allocator: std.mem.Allocator, out: *[32]u8) !void {
        return switch (self.*) {
            .phase0 => |state| try ct.phase0.BeaconState.hashTreeRoot(allocator, state, out),
            .altair => |state| try ct.altair.BeaconState.hashTreeRoot(allocator, state, out),
            .bellatrix => |state| try ct.bellatrix.BeaconState.hashTreeRoot(allocator, state, out),
            .capella => |state| try ct.capella.BeaconState.hashTreeRoot(allocator, state, out),
            .deneb => |state| try ct.deneb.BeaconState.hashTreeRoot(allocator, state, out),
            .electra => |state| try ct.electra.BeaconState.hashTreeRoot(allocator, state, out),
        };
    }

    pub fn deinit(self: *BeaconStateAllForks, allocator: Allocator) void {
        switch (self.*) {
            .phase0 => |state| {
                ct.phase0.BeaconState.deinit(allocator, state);
                allocator.destroy(state);
            },
            .altair => |state| {
                ct.altair.BeaconState.deinit(allocator, state);
                allocator.destroy(state);
            },
            .capella => |state| {
                ct.capella.BeaconState.deinit(allocator, state);
                allocator.destroy(state);
            },
            .bellatrix => |state| {
                ct.bellatrix.BeaconState.deinit(allocator, state);
                allocator.destroy(state);
            },
            .deneb => |state| {
                ct.deneb.BeaconState.deinit(allocator, state);
                allocator.destroy(state);
            },
            .electra => |state| {
                ct.electra.BeaconState.deinit(allocator, state);
                allocator.destroy(state);
            },
        }
    }

    pub fn forkSeq(self: *const BeaconStateAllForks) ForkSeq {
        return switch (self.*) {
            .phase0 => .phase0,
            .altair => .altair,
            .bellatrix => .bellatrix,
            .capella => .capella,
            .deneb => .deneb,
            .electra => .electra,
        };
    }

    pub fn isPhase0(self: *const BeaconStateAllForks) bool {
        return switch (self.*) {
            .phase0 => true,
            else => false,
        };
    }

    pub fn isAltair(self: *const BeaconStateAllForks) bool {
        return switch (self.*) {
            .altair => true,
            else => false,
        };
    }

    pub fn isPreAltair(self: *const BeaconStateAllForks) bool {
        return switch (self.*) {
            .phase0 => true,
            else => false,
        };
    }

    pub fn isPostAltair(self: *const BeaconStateAllForks) bool {
        return switch (self.*) {
            .phase0 => false,
            else => true,
        };
    }

    pub fn isBellatrix(self: *const BeaconStateAllForks) bool {
        return switch (self.*) {
            .bellatrix => true,
            else => false,
        };
    }

    pub fn isPreBellatrix(self: *const BeaconStateAllForks) bool {
        return switch (self.*) {
            inline .phase0, .altair => false,
            else => true,
        };
    }

    pub fn isPostBellatrix(self: *const BeaconStateAllForks) bool {
        return switch (self.*) {
            inline .phase0, .altair => false,
            else => true,
        };
    }

    pub fn isCapella(self: *const BeaconStateAllForks) bool {
        return switch (self.*) {
            .capella => true,
            else => false,
        };
    }

    pub fn isPreCapella(self: *const BeaconStateAllForks) bool {
        return switch (self.*) {
            inline .phase0, .altair, .bellatrix => true,
            else => false,
        };
    }

    pub fn isPostCapella(self: *const BeaconStateAllForks) bool {
        return switch (self.*) {
            inline .phase0, .altair, .bellatrix => false,
            else => true,
        };
    }

    pub fn isDeneb(self: *const BeaconStateAllForks) bool {
        return switch (self.*) {
            .deneb => true,
            else => false,
        };
    }

    pub fn isPreDeneb(self: *const BeaconStateAllForks) bool {
        return switch (self.*) {
            inline .phase0, .altair, .bellatrix, .capella => true,
            else => false,
        };
    }

    pub fn isPostDeneb(self: *const BeaconStateAllForks) bool {
        return switch (self.*) {
            inline .phase0, .altair, .bellatrix, .capella => false,
            else => true,
        };
    }

    pub fn isElectra(self: *const BeaconStateAllForks) bool {
        return switch (self.*) {
            .electra => true,
            else => false,
        };
    }

    pub fn isPreElectra(self: *const BeaconStateAllForks) bool {
        return switch (self.*) {
            .phase0, .altair, .bellatrix, .capella, .deneb => true,
            else => false,
        };
    }

    pub fn isPostElectra(self: *const BeaconStateAllForks) bool {
        return switch (self.*) {
            inline .phase0, .altair, .bellatrix, .capella, .deneb => false,
            else => true,
        };
    }

    pub fn genesisTime(self: *const BeaconStateAllForks) u64 {
        return switch (self.*) {
            inline else => |state| state.genesis_time,
        };
    }

    pub fn genesisValidatorsRoot(self: *const BeaconStateAllForks) Root {
        return switch (self.*) {
            inline else => |state| state.genesis_validators_root,
        };
    }

    pub fn slot(self: *const BeaconStateAllForks) u64 {
        return switch (self.*) {
            inline else => |state| state.slot,
        };
    }

    pub fn slotPtr(self: *const BeaconStateAllForks) *u64 {
        return switch (self.*) {
            inline else => |state| &state.slot,
        };
    }

    pub fn fork(self: *const BeaconStateAllForks) Fork {
        return switch (self.*) {
            inline else => |state| state.fork,
        };
    }

    pub fn latestBlockHeader(self: *const BeaconStateAllForks) *BeaconBlockHeader {
        return switch (self.*) {
            inline else => |state| &state.latest_block_header,
        };
    }

    pub fn blockRoots(self: *const BeaconStateAllForks) *[preset.SLOTS_PER_HISTORICAL_ROOT]Root {
        return switch (self.*) {
            inline else => |state| &state.block_roots,
        };
    }

    pub fn stateRoots(self: *const BeaconStateAllForks) *[preset.SLOTS_PER_HISTORICAL_ROOT]Root {
        return switch (self.*) {
            inline else => |state| &state.state_roots,
        };
    }

    pub fn historicalRoots(self: *BeaconStateAllForks) *std.ArrayListUnmanaged(Root) {
        return switch (self.*) {
            inline else => |state| &state.historical_roots,
        };
    }

    pub fn eth1Data(self: *const BeaconStateAllForks) *Eth1Data {
        return switch (self.*) {
            inline else => |state| &state.eth1_data,
        };
    }

    pub fn eth1DataVotes(self: *const BeaconStateAllForks) *Eth1DataVotes {
        return switch (self.*) {
            inline else => |state| &state.eth1_data_votes,
        };
    }

    pub fn eth1DepositIndex(self: *const BeaconStateAllForks) u64 {
        return switch (self.*) {
            inline else => |state| state.eth1_deposit_index,
        };
    }

    pub fn eth1DepositIndexPtr(self: *const BeaconStateAllForks) *u64 {
        return switch (self.*) {
            inline else => |state| &state.eth1_deposit_index,
        };
    }

    pub fn increaseEth1DepositIndex(self: *BeaconStateAllForks) void {
        switch (self.*) {
            inline else => |state| state.eth1_deposit_index += 1,
        }
    }

    // TODO: change to []Validator
    pub fn validators(self: *const BeaconStateAllForks) *Validators {
        return switch (self.*) {
            inline else => |state| &state.validators,
        };
    }

    pub fn balances(self: *const BeaconStateAllForks) *std.ArrayListUnmanaged(u64) {
        return switch (self.*) {
            inline else => |state| &state.balances,
        };
    }

    pub fn randaoMixes(self: *const BeaconStateAllForks) []Bytes32 {
        return switch (self.*) {
            inline else => |state| &state.randao_mixes,
        };
    }

    pub fn slashings(self: *const BeaconStateAllForks) []u64 {
        return switch (self.*) {
            inline else => |state| &state.slashings,
        };
    }

    pub fn previousEpochPendingAttestations(self: *const BeaconStateAllForks) *std.ArrayListUnmanaged(PendingAttestation) {
        return switch (self.*) {
            .phase0 => |state| &state.previous_epoch_attestations,
            else => @panic("current_epoch_pending_attestations is not available post phase0"),
        };
    }

    pub fn currentEpochPendingAttestations(self: *const BeaconStateAllForks) *std.ArrayListUnmanaged(PendingAttestation) {
        return switch (self.*) {
            .phase0 => |state| &state.current_epoch_attestations,
            else => @panic("current_epoch_pending_attestations is not available post phase0"),
        };
    }

    pub fn rotateEpochPendingAttestations(self: *BeaconStateAllForks) void {
        switch (self.*) {
            .phase0 => |state| {
                state.previous_epoch_attestations.clearRetainingCapacity();
                state.previous_epoch_attestations = state.current_epoch_attestations;
                state.current_epoch_attestations = ct.phase0.EpochAttestations.default_value;
            },
            else => @panic("shift_epoch_pending_attestations is not available post phase0"),
        }
    }

    pub fn previousEpochParticipations(self: *const BeaconStateAllForks) *std.ArrayListUnmanaged(u8) {
        return switch (self.*) {
            .phase0 => @panic("previous_epoch_participation is not available in phase0"),
            inline .altair, .bellatrix, .capella, .deneb, .electra => |state| &state.previous_epoch_participation,
        };
    }

    pub fn currentEpochParticipations(self: *const BeaconStateAllForks) *std.ArrayListUnmanaged(u8) {
        return switch (self.*) {
            .phase0 => @panic("current_epoch_participation is not available in phase0"),
            inline else => |state| &state.current_epoch_participation,
        };
    }

    pub fn rotateEpochParticipations(self: *BeaconStateAllForks, allocator: Allocator) !void {
        switch (self.*) {
            .phase0 => @panic("rotate_epoch_participations is not available in phase0"),
            inline else => |state| {
                state.previous_epoch_participation.clearRetainingCapacity();
                try state.previous_epoch_participation.appendSlice(allocator, state.current_epoch_participation.items);
                @memset(state.current_epoch_participation.items, 0);
            },
        }
    }

    pub fn justificationBits(self: *const BeaconStateAllForks) *JustificationBits {
        return switch (self.*) {
            inline else => |state| &state.justification_bits,
        };
    }

    pub fn previousJustifiedCheckpoint(self: *const BeaconStateAllForks) *Checkpoint {
        return switch (self.*) {
            inline else => |state| &state.previous_justified_checkpoint,
        };
    }

    pub fn currentJustifiedCheckpoint(self: *const BeaconStateAllForks) *Checkpoint {
        return switch (self.*) {
            inline else => |state| &state.current_justified_checkpoint,
        };
    }

    pub fn finalizedCheckpoint(self: *const BeaconStateAllForks) *Checkpoint {
        return switch (self.*) {
            inline else => |state| &state.finalized_checkpoint,
        };
    }

    pub fn inactivityScores(self: *const BeaconStateAllForks) *std.ArrayListUnmanaged(u64) {
        return switch (self.*) {
            .phase0 => @panic("inactivity_scores is not available in phase0"),
            inline else => |state| &state.inactivity_scores,
        };
    }

    pub fn currentSyncCommittee(self: *const BeaconStateAllForks) *SyncCommittee {
        return switch (self.*) {
            .phase0 => @panic("current_sync_committee is not available in phase0"),
            inline else => |state| &state.current_sync_committee,
        };
    }

    pub fn nextSyncCommittee(self: *const BeaconStateAllForks) *SyncCommittee {
        return switch (self.*) {
            .phase0 => @panic("next_sync_committee is not available in phase0"),
            inline else => |state| &state.next_sync_committee,
        };
    }

    pub fn setNextSyncCommittee(self: *BeaconStateAllForks, sync_committee: *const SyncCommittee) void {
        switch (self.*) {
            .phase0 => @panic("next_sync_committee is not available in phase0"),
            inline else => |state| state.next_sync_committee = sync_committee.*,
        }
    }

    pub fn latestExecutionPayloadHeader(self: *const BeaconStateAllForks) ExecutionPayloadHeader {
        return switch (self.*) {
            .bellatrix => |state| .{ .bellatrix = &state.latest_execution_payload_header },
            .capella => |state| .{ .capella = &state.latest_execution_payload_header },
            .deneb => |state| .{ .deneb = &state.latest_execution_payload_header },
            .electra => |state| .{ .electra = &state.latest_execution_payload_header },
            else => panic("latest_execution_payload_header is not available in {}", .{self}),
        };
    }

    pub fn setLatestExecutionPayloadHeader(self: *BeaconStateAllForks, header: *const ExecutionPayloadHeader) void {
        switch (self.*) {
            .bellatrix => |state| state.latest_execution_payload_header = header.*.bellatrix.*,
            .capella => |state| state.latest_execution_payload_header = header.*.capella.*,
            .deneb => |state| state.latest_execution_payload_header = header.*.deneb.*,
            .electra => |state| state.latest_execution_payload_header = header.*.electra.*,
            else => panic("latest_execution_payload_header is not available in {}", .{self}),
        }
    }

    pub fn nextWithdrawalIndex(self: *const BeaconStateAllForks) *u64 {
        return switch (self.*) {
            inline .phase0, .altair, .bellatrix => panic("next_withdrawal_index is not available in {}", .{self}),
            inline else => |state| &state.next_withdrawal_index,
        };
    }

    pub fn nextWithdrawalValidatorIndex(self: *const BeaconStateAllForks) *u64 {
        return switch (self.*) {
            inline .phase0, .altair, .bellatrix => panic("next_withdrawal_validator_index is not available in {}", .{self}),
            inline else => |state| &state.next_withdrawal_validator_index,
        };
    }

    pub fn historicalSummaries(self: *const BeaconStateAllForks) *std.ArrayListUnmanaged(HistoricalSummary) {
        return switch (self.*) {
            inline .phase0, .altair, .bellatrix => panic("historical_summaries is not available in {}", .{self}),
            inline else => |state| &state.historical_summaries,
        };
    }

    pub fn depositRequestsStartIndex(self: *const BeaconStateAllForks) *u64 {
        return switch (self.*) {
            inline .phase0, .altair, .bellatrix, .capella, .deneb => panic("deposit_requests_start_index is not available in {}", .{self}),
            inline else => |state| &state.deposit_requests_start_index,
        };
    }

    pub fn depositBalanceToConsume(self: *const BeaconStateAllForks) *Gwei {
        return switch (self.*) {
            inline .phase0, .altair, .bellatrix, .capella, .deneb => panic("deposit_balance_to_consume is not available in {}", .{self}),
            inline else => |state| &state.deposit_balance_to_consume,
        };
    }

    pub fn exitBalanceToConsume(self: *const BeaconStateAllForks) *Gwei {
        return switch (self.*) {
            inline .phase0, .altair, .bellatrix, .capella, .deneb => panic("exit_balance_to_consume is not available in {}", .{self}),
            inline else => |state| &state.exit_balance_to_consume,
        };
    }

    pub fn earliestExitEpoch(self: *const BeaconStateAllForks) *Epoch {
        return switch (self.*) {
            inline .phase0, .altair, .bellatrix, .capella, .deneb => panic("earliest_exit_epoch is not available in {}", .{self}),
            inline else => |state| &state.earliest_exit_epoch,
        };
    }

    pub fn consolidationBalanceToConsume(self: *const BeaconStateAllForks) *Gwei {
        return switch (self.*) {
            inline .phase0, .altair, .bellatrix, .capella, .deneb => panic("consolidation_balance_to_consume is not available in {}", .{self}),
            inline else => |state| &state.consolidation_balance_to_consume,
        };
    }

    pub fn earliestConsolidationEpoch(self: *const BeaconStateAllForks) *Epoch {
        return switch (self.*) {
            inline .phase0, .altair, .bellatrix, .capella, .deneb => panic("earliest_consolidation_epoch is not available in {}", .{self}),
            inline else => |state| &state.earliest_consolidation_epoch,
        };
    }

    pub fn pendingDeposits(self: *const BeaconStateAllForks) *std.ArrayListUnmanaged(PendingDeposit) {
        return switch (self.*) {
            .electra => |state| &state.pending_deposits,
            else => panic("pending_deposits is not available in {}", .{self}),
        };
    }

    pub fn pendingPartialWithdrawals(self: *const BeaconStateAllForks) *std.ArrayListUnmanaged(PendingPartialWithdrawal) {
        return switch (self.*) {
            .electra => |state| &state.pending_partial_withdrawals,
            else => panic("pending_partial_withdrawals is not available in {}", .{self}),
        };
    }

    pub fn pendingConsolidations(self: *const BeaconStateAllForks) *std.ArrayListUnmanaged(PendingConsolidation) {
        return switch (self.*) {
            .electra => |state| &state.pending_consolidations,
            else => panic("pending_consolidations is not available in {}", .{self}),
        };
    }

    /// Copies ct fields of `BeaconState` from type `F` to type `T`, provided they have the same field name.
    fn populateFields(
        comptime F: type,
        comptime T: type,
        allocator: Allocator,
        state: *F.Type,
    ) !*T.Type {
        var upgraded = try allocator.create(T.Type);
        upgraded.* = T.default_value;
        inline for (@typeInfo(F).@"struct".fields) |f| {
            if (@hasField(T.Type, f.name)) {
                f.type.clone(allocator, &@field(state, f.name), &@field(upgraded, f.name));
            }
        }

        return upgraded;
    }

    /// Upgrade `self` from a certain fork to the next.
    ///
    /// Allocates a new `state` of the next fork, clones all fields of the current `state` to it and assigns `self` to it.
    /// Destroys the old `state`.
    ///
    /// Caller must make sure an upgrade is needed by checking BeaconConfig then free upgraded state.
    pub fn upgradeUnsafe(self: *BeaconStateAllForks, allocator: std.mem.Allocator) !*BeaconStateAllForks {
        switch (self.*) {
            .phase0 => |state| {
                self.* = .{
                    .altair = try populateFields(
                        ct.phase0.BeaconState,
                        ct.altair.BeaconState,
                        allocator,
                        state,
                    ),
                };
                allocator.destroy(state);
                return self;
            },
            .altair => |state| {
                self.* = .{
                    .bellatrix = try populateFields(
                        ct.altair.BeaconState,
                        ct.bellatrix.BeaconState,
                        allocator,
                        state,
                    ),
                };
                allocator.destroy(state);
                return self;
            },
            .bellatrix => |state| {
                self.* = .{
                    .capella = try populateFields(
                        ct.bellatrix.BeaconState,
                        ct.capella.BeaconState,
                        allocator,
                        state,
                    ),
                };
                allocator.destroy(state);
                return self;
            },
            .capella => |state| {
                self.* = .{
                    .deneb = try populateFields(
                        ct.capella.BeaconState,
                        ct.deneb.BeaconState,
                        allocator,
                        state,
                    ),
                };
                allocator.destroy(state);
                return self;
            },
            .deneb => |state| {
                self.* = .{
                    .electra = try populateFields(
                        ct.deneb.BeaconState,
                        ct.electra.BeaconState,
                        allocator,
                        state,
                    ),
                };
                allocator.destroy(state);
                return self;
            },
            .electra => |_| {
                @panic("upgrade state from electra to fulu unimplemented");
            },
        }
    }
};

test "electra - sanity" {
    const allocator = std.testing.allocator;
    var electra_state = ct.electra.BeaconState.default_value;
    electra_state.slot = 12345;
    var beacon_state = BeaconStateAllForks{
        .electra = &electra_state,
    };

    try std.testing.expect(beacon_state.genesisTime() == 0);
    try std.testing.expectEqualSlices(u8, &[_]u8{0} ** 32, &beacon_state.genesisValidatorsRoot());
    try std.testing.expect(beacon_state.slot() == 12345);
    const slot = beacon_state.slotPtr();
    slot.* = 2025;
    try std.testing.expect(beacon_state.slot() == 2025);

    var out: [32]u8 = undefined;
    try beacon_state.hashTreeRoot(allocator, &out);
    try expect(!std.mem.eql(u8, &[_]u8{0} ** 32, &out));

    // TODO: more tests
}

test "clone - sanity" {
    const allocator = std.testing.allocator;
    var electra_state = ct.electra.BeaconState.default_value;
    electra_state.slot = 12345;
    var beacon_state = BeaconStateAllForks{
        .electra = &electra_state,
    };

    // test the clone() and deinit() works fine without memory leak
    const cloned_state = try beacon_state.clone(allocator);
    try expect(cloned_state.slot() == 12345);
    defer {
        cloned_state.deinit(allocator);
        allocator.destroy(cloned_state);
    }
}

test "upgrade state - sanity" {
    const allocator = std.testing.allocator;
    const phase0_state = try allocator.create(ct.phase0.BeaconState.Type);
    phase0_state.* = ct.phase0.BeaconState.default_value;

    var phase0 = BeaconStateAllForks{ .phase0 = phase0_state };
    var altair = try phase0.upgradeUnsafe(allocator);
    const bellatrix = try altair.upgradeUnsafe(allocator);
    const capella = try bellatrix.upgradeUnsafe(allocator);
    var deneb = try capella.upgradeUnsafe(allocator);
    defer deneb.deinit(allocator);
}
