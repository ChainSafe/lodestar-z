//! Chain read/query surface.
//!
//! Adapters such as req/resp, gossip, and API should prefer this boundary over
//! reaching into raw chain internals.

const std = @import("std");
const consensus_types = @import("consensus_types");
const preset = @import("preset").preset;
const state_transition = @import("state_transition");
const networking = @import("networking");
const fork_types = @import("fork_types");
const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;
const AnyAttestation = fork_types.AnyAttestation;
const AnyAttesterSlashing = fork_types.AnyAttesterSlashing;
const fork_choice_mod = @import("fork_choice");

const Chain = @import("chain.zig").Chain;
const chain_types = @import("types.zig");
const chain_effects = @import("effects.zig");

const CachedBeaconState = state_transition.CachedBeaconState;
const Slot = consensus_types.primitive.Slot.Type;
const Epoch = consensus_types.primitive.Epoch.Type;
const Root = [32]u8;
const Phase0Attestation = consensus_types.phase0.Attestation.Type;
const SyncCommitteeContribution = consensus_types.altair.SyncCommitteeContribution.Type;
const SignedVoluntaryExit = consensus_types.phase0.SignedVoluntaryExit.Type;
const ProposerSlashing = consensus_types.phase0.ProposerSlashing.Type;
const SignedBLSToExecutionChange = consensus_types.capella.SignedBLSToExecutionChange.Type;
const ProtoBlock = fork_choice_mod.ProtoBlock;
const ProtoNode = fork_choice_mod.ProtoNode;

pub const Query = struct {
    chain: *Chain,

    pub fn init(chain: *Chain) Query {
        return .{ .chain = chain };
    }

    pub fn head(self: Query) chain_types.HeadInfo {
        return self.chain.getHead();
    }

    pub fn syncStatus(self: Query) chain_types.SyncStatus {
        return self.chain.getSyncStatus();
    }

    pub fn currentSlot(self: Query) Slot {
        return self.chain.currentSlot();
    }

    pub fn validatorSeenAtEpoch(self: Query, validator_index: u64, epoch: Epoch) bool {
        return self.chain.validatorSeenAtEpoch(validator_index, epoch);
    }

    pub fn blockExecutionOptimistic(self: Query, block_root: Root) bool {
        return self.chain.blockExecutionOptimistic(block_root);
    }

    pub fn blockExecutionOptimisticAtSlot(self: Query, slot: Slot) !bool {
        const head_info = self.head();
        if (slot == head_info.slot) return self.chain.currentHeadExecutionOptimistic();

        const block_root = try self.canonicalBlockRootAtSlot(slot) orelse return false;
        return self.blockExecutionOptimistic(block_root);
    }

    pub fn executionForkchoiceState(self: Query, head_root: Root) ?chain_types.ForkchoiceUpdateState {
        return self.chain.executionForkchoiceState(head_root);
    }

    pub fn slotsPresent(self: Query, window_start: Slot) u32 {
        return self.chain.slotsPresent(window_start);
    }

    pub fn status(self: Query) networking.messages.StatusMessage.Type {
        return self.chain.getStatus();
    }

    pub fn currentSnapshot(self: Query) chain_effects.ChainSnapshot {
        return .{
            .head = self.head(),
            .justified = self.justifiedCheckpoint(),
            .finalized = self.finalizedCheckpoint(),
            .status = self.status(),
        };
    }

    pub fn justifiedCheckpoint(self: Query) chain_effects.CheckpointSnapshot {
        const cp = self.chain.forkChoice().getJustifiedCheckpoint();
        return .{
            .epoch = cp.epoch,
            .slot = checkpointSlot(cp.epoch),
            .root = cp.root,
        };
    }

    pub fn finalizedCheckpoint(self: Query) chain_effects.CheckpointSnapshot {
        const cp = self.chain.forkChoice().getFinalizedCheckpoint();
        return .{
            .epoch = cp.epoch,
            .slot = checkpointSlot(cp.epoch),
            .root = cp.root,
        };
    }

    pub fn forkChoiceHeads(self: Query, allocator: std.mem.Allocator) ![]ProtoBlock {
        return self.chain.forkChoice().getHeads(allocator);
    }

    pub fn forkChoiceNodes(self: Query) []const ProtoNode {
        return self.chain.forkChoice().getAllNodes();
    }

    pub fn blockRootAtSlot(self: Query, slot: Slot) !?Root {
        return self.chain.canonicalHotBlockRootAtSlot(slot);
    }

    pub fn canonicalBlockRootAtSlot(self: Query, slot: Slot) !?Root {
        if (try self.blockRootAtSlot(slot)) |root| return root;
        return self.chain.db.getFinalizedBlockRootBySlot(slot);
    }

    pub fn finalizedBlockRootByParentRoot(self: Query, parent_root: Root) !?Root {
        const child = try self.chain.db.getArchivedCanonicalChild(parent_root) orelse return null;
        return child.root;
    }

    pub fn stateArchiveAtSlot(self: Query, slot: Slot) !?[]const u8 {
        return self.chain.db.getStateArchive(slot);
    }

    pub fn latestStateArchiveSlot(self: Query) !?Slot {
        return self.chain.db.getLatestStateArchiveSlot();
    }

    pub fn stateArchiveByRoot(self: Query, root: Root) !?[]const u8 {
        return self.chain.db.getStateArchiveByRoot(root);
    }

    /// Returns raw SSZ state bytes for the given slot.
    ///
    /// Search order:
    /// 1. Head/cached state serialized on demand.
    /// 2. Archived state bytes from DB.
    /// 3. Historical state lookup/regeneration serialized on demand.
    ///
    /// Caller owns the returned bytes.
    pub fn stateBytesBySlot(self: Query, slot: Slot) !?[]const u8 {
        const head_info = self.head();
        if (slot == head_info.slot) {
            if (self.headState()) |state| {
                const bytes = try state.state.serialize(self.chain.allocator);
                return bytes;
            }
        }

        if (try self.chain.db.getStateArchive(slot)) |state_bytes| return state_bytes;

        if (try self.stateBySlot(slot)) |state| {
            const bytes = try state.state.serialize(self.chain.allocator);
            return bytes;
        }

        return null;
    }

    /// Returns raw SSZ state bytes for the given state root.
    ///
    /// Search order:
    /// 1. Archived state bytes from DB.
    /// 2. Cached/regenerated state serialized on demand.
    ///
    /// Caller owns the returned bytes.
    pub fn stateBytesByRoot(self: Query, state_root: Root) !?[]const u8 {
        if (try self.chain.db.getStateArchiveByRoot(state_root)) |state_bytes| return state_bytes;

        if (try self.stateByRoot(state_root)) |state| {
            const bytes = try state.state.serialize(self.chain.allocator);
            return bytes;
        }

        return null;
    }

    pub fn blockBytesByRoot(self: Query, root: Root) !?[]const u8 {
        if (try self.chain.db.getBlock(root)) |block_bytes| return block_bytes;
        return self.chain.db.getBlockArchiveByRoot(root);
    }

    pub fn blockBytesAtSlot(self: Query, slot: Slot) !?[]const u8 {
        const root = try self.canonicalBlockRootAtSlot(slot) orelse return null;
        return self.blockBytesByRoot(root);
    }

    pub fn blobSidecarsByRoot(self: Query, root: Root) !?[]const u8 {
        if (try self.chain.db.getBlobSidecars(root)) |bytes| return bytes;
        return self.chain.db.getBlobSidecarsArchiveByRoot(root);
    }

    pub fn blobSidecarsAtSlot(self: Query, slot: Slot) !?[]const u8 {
        const root = try self.canonicalBlockRootAtSlot(slot) orelse return null;
        return self.blobSidecarsByRoot(root);
    }

    pub fn dataColumnByRoot(self: Query, root: Root, column_index: u64) !?[]const u8 {
        if (try self.chain.db.getDataColumn(root, column_index)) |bytes| return bytes;
        return self.chain.db.getDataColumnArchiveByRoot(root, column_index);
    }

    pub fn dataColumnAtSlot(self: Query, slot: Slot, column_index: u64) !?[]const u8 {
        const root = try self.canonicalBlockRootAtSlot(slot) orelse return null;
        return self.dataColumnByRoot(root, column_index);
    }

    pub fn headState(self: Query) ?*CachedBeaconState {
        const head_state_root = self.chain.headStateRoot();
        return self.chain.block_state_cache.get(head_state_root);
    }

    pub fn stateRootByBlockRoot(self: Query, block_root: Root) !?Root {
        if (self.chain.block_to_state.get(block_root)) |state_root| return state_root;

        const block_bytes = try self.blockBytesByRoot(block_root) orelse return null;
        defer self.chain.allocator.free(block_bytes);
        return self.deserializeSignedBlockStateRoot(block_bytes);
    }

    pub fn stateByRoot(self: Query, state_root: Root) !?*CachedBeaconState {
        if (self.chain.block_state_cache.get(state_root)) |state| return state;

        return self.chain.queued_regen.getStateByRoot(state_root, .api);
    }

    pub fn stateExecutionOptimisticByRoot(self: Query, state_root: Root) bool {
        const head_info = self.head();
        if (std.mem.eql(u8, &head_info.state_root, &state_root)) {
            return self.chain.currentHeadExecutionOptimistic();
        }

        var it = self.chain.block_to_state.iterator();
        while (it.next()) |entry| {
            if (std.mem.eql(u8, entry.value_ptr, &state_root)) {
                return self.blockExecutionOptimistic(entry.key_ptr.*);
            }
        }

        return false;
    }

    pub fn stateExecutionOptimisticAtSlot(self: Query, slot: Slot) !bool {
        const head_info = self.head();
        if (slot == head_info.slot) return self.chain.currentHeadExecutionOptimistic();

        const block_root = try self.canonicalBlockRootAtSlot(slot) orelse return false;
        return self.blockExecutionOptimistic(block_root);
    }

    pub fn stateByBlockRoot(self: Query, block_root: Root) !?*CachedBeaconState {
        const state_root = try self.stateRootByBlockRoot(block_root) orelse return null;
        return self.stateByRoot(state_root);
    }

    pub fn stateRootBySlot(self: Query, slot: Slot) !?Root {
        const head_info = self.head();
        if (slot == head_info.slot) return head_info.state_root;

        if (try self.canonicalBlockRootAtSlot(slot)) |block_root| {
            return self.stateRootByBlockRoot(block_root);
        }

        if (try self.stateBySlot(slot)) |state| {
            return (try state.state.hashTreeRoot()).*;
        }

        return null;
    }

    pub fn stateBySlot(self: Query, slot: Slot) !?*CachedBeaconState {
        const head_info = self.head();
        if (slot == head_info.slot) return self.headState();

        if (try self.canonicalBlockRootAtSlot(slot)) |block_root| {
            if (try self.stateByBlockRoot(block_root)) |state| return state;
        }

        return self.chain.state_regen.getStateBySlot(slot);
    }

    pub fn getProposerIndex(self: Query, slot: Slot) ?u32 {
        const cached = self.headState() orelse return null;
        const proposer = cached.getBeaconProposer(slot) catch return null;
        return @intCast(proposer);
    }

    pub fn proposerFeeRecipientForSlot(
        self: Query,
        slot: Slot,
        default_fee_recipient: ?[20]u8,
    ) ?[20]u8 {
        const cached = self.headState() orelse return default_fee_recipient;
        const proposer_index = cached.getBeaconProposer(slot) catch return default_fee_recipient;
        return self.chain.beacon_proposer_cache.getOrDefault(proposer_index, default_fee_recipient);
    }

    pub fn getValidatorCount(self: Query) u32 {
        const cached = self.headState() orelse return 0;
        return @intCast(cached.epoch_cache.index_to_pubkey.items.len);
    }

    pub fn aggregateAttestation(self: Query, slot: Slot, data_root: Root) !?Phase0Attestation {
        const attestation = self.chain.op_pool.agg_attestation_pool.getAggregate(slot, data_root) orelse return null;

        var cloned = attestation;
        const src = attestation.aggregation_bits.data.items;
        var new_data = try std.ArrayListUnmanaged(u8).initCapacity(self.chain.allocator, src.len);
        new_data.appendSliceAssumeCapacity(src);
        cloned.aggregation_bits.data = new_data;
        return cloned;
    }

    pub fn syncCommitteeContribution(
        self: Query,
        subcommittee_index: u64,
        slot: Slot,
        block_root: Root,
    ) ?SyncCommitteeContribution {
        const pool = self.chain.sync_committee_message_pool orelse return null;
        return pool.getContribution(subcommittee_index, slot, block_root);
    }

    pub fn opPoolCounts(self: Query) [5]usize {
        return .{
            self.chain.op_pool.attestation_pool.groupCount(),
            self.chain.op_pool.voluntary_exit_pool.size(),
            self.chain.op_pool.proposer_slashing_pool.size(),
            self.chain.op_pool.attester_slashing_pool.size(),
            self.chain.op_pool.bls_change_pool.size(),
        };
    }

    pub fn attestations(
        self: Query,
        allocator: std.mem.Allocator,
        slot_filter: ?u64,
        committee_index_filter: ?u64,
    ) ![]Phase0Attestation {
        return self.chain.op_pool.attestation_pool.getAll(allocator, slot_filter, committee_index_filter);
    }

    pub fn attestationsV2(
        self: Query,
        allocator: std.mem.Allocator,
        slot_filter: ?u64,
        committee_index_filter: ?u64,
    ) ![]AnyAttestation {
        return self.chain.op_pool.attestation_pool.getAllAny(allocator, slot_filter, committee_index_filter);
    }

    pub fn voluntaryExits(
        self: Query,
        allocator: std.mem.Allocator,
    ) ![]SignedVoluntaryExit {
        return self.chain.op_pool.voluntary_exit_pool.getAll(allocator);
    }

    pub fn proposerSlashings(
        self: Query,
        allocator: std.mem.Allocator,
    ) ![]ProposerSlashing {
        return self.chain.op_pool.proposer_slashing_pool.getAll(allocator);
    }

    pub fn attesterSlashings(
        self: Query,
        allocator: std.mem.Allocator,
    ) ![]AnyAttesterSlashing {
        return self.chain.op_pool.attester_slashing_pool.getAll(allocator);
    }

    pub fn blsToExecutionChanges(
        self: Query,
        allocator: std.mem.Allocator,
    ) ![]SignedBLSToExecutionChange {
        return self.chain.op_pool.bls_change_pool.getAll(allocator);
    }

    pub fn isKnownBlockRoot(self: Query, root: Root) bool {
        return self.chain.hasCanonicalBlock(root);
    }

    fn checkpointSlot(epoch: Epoch) Slot {
        return epoch * preset.SLOTS_PER_EPOCH;
    }

    fn readSignedBlockSlotFromSsz(block_bytes: []const u8) ?Slot {
        if (block_bytes.len < 108) return null;
        return std.mem.readInt(u64, block_bytes[100..108], .little);
    }

    fn deserializeSignedBlockStateRoot(self: Query, block_bytes: []const u8) !?Root {
        const slot = readSignedBlockSlotFromSsz(block_bytes) orelse return null;
        const fork_seq = self.chain.config.forkSeq(slot);
        const any_signed = try AnySignedBeaconBlock.deserialize(
            self.chain.allocator,
            .full,
            fork_seq,
            block_bytes,
        );
        defer any_signed.deinit(self.chain.allocator);
        return any_signed.beaconBlock().stateRoot().*;
    }
};
