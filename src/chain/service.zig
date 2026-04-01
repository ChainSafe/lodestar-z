//! Chain write/service surface.
//!
//! This is the typed ingress for state-changing operations. Runtime adapters
//! should call into this surface rather than reaching through the chain to
//! mutate pools, caches, and storage directly.

const consensus_types = @import("consensus_types");
const fork_types = @import("fork_types");

const Chain = @import("chain.zig").Chain;
const chain_types = @import("types.zig");
const chain_effects = @import("effects.zig");
const Query = @import("query.zig").Query;

const Root = [32]u8;
const Slot = consensus_types.primitive.Slot.Type;
const ValidatorIndex = consensus_types.primitive.ValidatorIndex.Type;
const SignedVoluntaryExit = consensus_types.phase0.SignedVoluntaryExit.Type;
const ProposerSlashing = consensus_types.phase0.ProposerSlashing.Type;
const AttesterSlashing = consensus_types.phase0.AttesterSlashing.Type;
const SignedBLSToExecutionChange = consensus_types.capella.SignedBLSToExecutionChange.Type;
const SyncCommitteeContribution = consensus_types.altair.SyncCommitteeContribution.Type;
const BLSSignature = consensus_types.primitive.BLSSignature.Type;

pub const Service = struct {
    chain: *Chain,

    pub fn init(chain: *Chain) Service {
        return .{ .chain = chain };
    }

    pub fn query(self: Service) Query {
        return Query.init(self.chain);
    }

    pub fn importBlock(
        self: Service,
        any_signed: fork_types.AnySignedBeaconBlock,
        source: chain_types.BlockSource,
    ) !chain_effects.ImportOutcome {
        const result = try self.chain.importBlock(any_signed, source);
        const snapshot = self.query().currentSnapshot();

        return .{
            .result = result,
            .snapshot = snapshot,
            .effects = .{
                .notify_forkchoice_update_root = snapshot.head.root,
                .archive_state = if (result.epoch_transition)
                    .{
                        .slot = result.slot,
                        .state_root = result.state_root,
                    }
                else
                    null,
                .finalized_checkpoint = if (result.epoch_transition)
                    snapshot.finalized
                else
                    null,
            },
        };
    }

    pub fn importAttestation(
        self: Service,
        attestation_slot: u64,
        committee_index: u64,
        beacon_block_root: Root,
        target_root: Root,
        target_epoch: u64,
        validator_index: ValidatorIndex,
        attestation: fork_types.AnyAttestation,
    ) !void {
        try self.chain.importAttestation(
            attestation_slot,
            committee_index,
            beacon_block_root,
            target_root,
            target_epoch,
            validator_index,
            attestation,
        );
    }

    pub fn importVoluntaryExit(self: Service, exit: SignedVoluntaryExit) !void {
        try self.chain.op_pool.voluntary_exit_pool.add(exit);
    }

    pub fn importProposerSlashing(self: Service, slashing: ProposerSlashing) !void {
        try self.chain.op_pool.proposer_slashing_pool.add(slashing);
    }

    pub fn importAttesterSlashing(self: Service, slashing: AttesterSlashing) !void {
        try self.chain.op_pool.attester_slashing_pool.add(slashing);
    }

    pub fn importBlsChange(self: Service, change: SignedBLSToExecutionChange) !void {
        try self.chain.op_pool.bls_change_pool.add(change);
    }

    pub fn importSyncContribution(
        self: Service,
        contribution: *const SyncCommitteeContribution,
    ) !void {
        const pool = self.chain.sync_contribution_pool orelse return;
        try pool.add(contribution);
    }

    pub fn importSyncCommitteeMessage(
        self: Service,
        subnet: u64,
        slot: Slot,
        beacon_block_root: Root,
        index_in_subcommittee: u64,
        signature: BLSSignature,
    ) !void {
        const pool = self.chain.sync_committee_message_pool orelse return;
        try pool.add(subnet, slot, beacon_block_root, index_in_subcommittee, signature);
    }

    pub fn importBlobSidecar(self: Service, root: Root, data: []const u8) !void {
        try self.chain.importBlobSidecar(root, data);
    }

    pub fn importDataColumnSidecar(
        self: Service,
        root: Root,
        column_index: u64,
        data: []const u8,
    ) !void {
        try self.chain.db.putDataColumn(root, column_index, data);
    }

    pub fn archiveState(self: Service, slot: Slot, state_root: Root) !void {
        try self.chain.archiveState(slot, state_root);
    }
};
