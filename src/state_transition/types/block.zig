pub const SignedBlock = union(enum) {
    regular: SignedBeaconBlock,
    blinded: SignedBlindedBeaconBlock,

    pub fn message(self: *const SignedBlock) Block {
        return switch (self.*) {
            .regular => |b| .{ .regular = b.beaconBlock() },
            .blinded => |b| .{ .blinded = b.beaconBlock() },
        };
    }

    pub fn signature(self: *const SignedBlock) types.primitive.BLSSignature.Type {
        return switch (self.*) {
            inline .regular, .blinded => |b| b.signature(),
        };
    }
};

pub const Block = union(enum) {
    regular: BeaconBlock,
    blinded: BlindedBeaconBlock,

    pub fn beaconBlockBody(self: *const Block) Body {
        return switch (self.*) {
            .regular => |b| .{ .regular = b.beaconBlockBody() },
            .blinded => |b| .{ .blinded = b.beaconBlockBody() },
        };
    }

    pub fn parentRoot(self: *const Block) [32]u8 {
        return switch (self.*) {
            .regular => |b| b.parentRoot(),
            .blinded => |b| b.parentRoot(),
        };
    }

    pub fn slot(self: *const Block) Slot {
        return switch (self.*) {
            .regular => |b| b.slot(),
            .blinded => |b| b.slot(),
        };
    }

    pub fn hashTreeRoot(self: *const Block, allocator: std.mem.Allocator, out: *[32]u8) !void {
        return switch (self.*) {
            .regular => |b| b.hashTreeRoot(allocator, out),
            .blinded => |b| b.hashTreeRoot(allocator, out),
        };
    }

    pub fn proposerIndex(self: *const Block) u64 {
        return switch (self.*) {
            .regular => |b| b.proposerIndex(),
            .blinded => |b| b.proposerIndex(),
        };
    }
};

pub const Body = union(enum) {
    regular: BeaconBlockBody,
    blinded: BlindedBeaconBlockBody,

    pub fn hashTreeRoot(self: *const Body, allocator: std.mem.Allocator, out: *Root) !void {
        return switch (self.*) {
            inline .regular, .blinded => |b| b.hashTreeRoot(allocator, out),
        };
    }

    pub fn blobKzgCommitmentsLen(self: *const Body) usize {
        return switch (self.*) {
            inline .regular, .blinded => |b| b.blobKzgCommitments().items.len,
        };
    }

    pub fn eth1Data(self: *const Body) *const types.phase0.Eth1Data.Type {
        return switch (self.*) {
            inline .regular, .blinded => |b| b.eth1Data(),
        };
    }

    pub fn randaoReveal(self: *const Body) types.primitive.BLSSignature.Type {
        return switch (self.*) {
            inline .regular, .blinded => |b| b.randaoReveal(),
        };
    }

    pub fn deposits(self: *const Body) []Deposit {
        return switch (self.*) {
            inline .regular, .blinded => |b| b.deposits(),
        };
    }
    pub fn depositRequests(self: *const Body) []DepositRequest {
        return switch (self.*) {
            inline .regular, .blinded => |b| b.depositRequests(),
        };
    }
    pub fn withdrawalRequests(self: *const Body) []WithdrawalRequest {
        return switch (self.*) {
            inline .regular, .blinded => |b| b.withdrawalRequests(),
        };
    }
    pub fn consolidationRequests(self: *const Body) []ConsolidationRequest {
        return switch (self.*) {
            inline .regular, .blinded => |b| b.consolidationRequests(),
        };
    }

    pub fn syncAggregate(self: *const Body) *const types.altair.SyncAggregate.Type {
        return switch (self.*) {
            inline .regular, .blinded => |b| b.syncAggregate(),
        };
    }

    pub fn attesterSlashings(self: *const Body) AttesterSlashings {
        return switch (self.*) {
            inline .regular, .blinded => |b| b.attesterSlashings(),
        };
    }

    pub fn attestations(self: *const Body) Attestations {
        return switch (self.*) {
            inline .regular, .blinded => |b| b.attestations(),
        };
    }

    pub fn voluntaryExits(self: *const Body) []SignedVoluntaryExit {
        return switch (self.*) {
            inline .regular, .blinded => |b| b.voluntaryExits(),
        };
    }

    pub fn proposerSlashings(self: *const Body) []ProposerSlashing {
        return switch (self.*) {
            inline .regular, .blinded => |b| b.proposerSlashings(),
        };
    }

    pub fn blsToExecutionChanges(self: *const Body) []SignedBLSToExecutionChange {
        return switch (self.*) {
            inline .regular, .blinded => |b| b.blsToExecutionChanges(),
        };
    }
};

const std = @import("std");
const types = @import("consensus_types");

const Root = types.primitive.Root.Type;
const Deposit = types.phase0.Deposit.Type;
const DepositRequest = types.electra.DepositRequest.Type;
const WithdrawalRequest = types.electra.WithdrawalRequest.Type;
const ConsolidationRequest = types.electra.ConsolidationRequest.Type;

const Attestations = @import("attestation.zig").Attestations;
const AttesterSlashings = @import("attester_slashing.zig").AttesterSlashings;
const ProposerSlashing = types.phase0.ProposerSlashing.Type;
const SignedVoluntaryExit = types.phase0.SignedVoluntaryExit.Type;
const Slot = types.primitive.Slot.Type;
const SignedBLSToExecutionChange = types.capella.SignedBLSToExecutionChange.Type;

const BeaconBlock = @import("beacon_block.zig").BeaconBlock;
const SignedBeaconBlock = @import("beacon_block.zig").SignedBeaconBlock;
const SignedBlindedBeaconBlock = @import("beacon_block.zig").SignedBlindedBeaconBlock;
const BlindedBeaconBlock = @import("beacon_block.zig").BlindedBeaconBlock;
const BlindedBeaconBlockBody = @import("beacon_block.zig").BlindedBeaconBlockBody;
const BeaconBlockBody = @import("beacon_block.zig").BeaconBlockBody;
