pub const Block = union(enum) {
    regular: BeaconBlock,
    blinded: BlindedBeaconBlock,
};

pub const SignedBlock = union(enum) {
    regular: *const SignedBeaconBlock,
    blinded: *const SignedBlindedBeaconBlock,

    pub const Body = union(enum) {
        regular: BeaconBlockBody,
        blinded: BlindedBeaconBlockBody,

        pub fn blobKzgCommitmentsLen(self: *const Body) usize {
            return switch (self.*) {
                inline .regular, .blinded => |b| b.blobKzgCommitments().items.len,
            };
        }

        pub fn eth1Data(self: *const Body) *const ssz.phase0.Eth1Data.Type {
            return switch (self.*) {
                inline .regular, .blinded => |b| b.eth1Data(),
            };
        }

        pub fn randaoReveal(self: *const Body) ssz.primitive.BLSSignature.Type {
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

        pub fn syncAggregate(self: *const Body) *const ssz.altair.SyncAggregate.Type {
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

        pub fn hashTreeRoot(self: *const Body, allocator: std.mem.Allocator, out: *Root) !void {
            return switch (self.*) {
                inline .regular, .blinded => |b| b.hashTreeRoot(allocator, out),
            };
        }
    };

    pub fn message(self: *const SignedBlock) Block {
        return switch (self.*) {
            .regular => |b| .{ .regular = b.beaconBlock() },
            .blinded => |b| .{ .blinded = b.beaconBlock() },
        };
    }
    pub fn beaconBlockBody(self: *const SignedBlock) Body {
        return switch (self.*) {
            .regular => |b| .{ .regular = b.beaconBlock().beaconBlockBody() },
            .blinded => |b| .{ .blinded = b.beaconBlock().beaconBlockBody() },
        };
    }

    pub fn parentRoot(self: *const SignedBlock) [32]u8 {
        return switch (self.*) {
            .regular => |b| b.beaconBlock().parentRoot(),
            .blinded => |b| b.beaconBlock().parentRoot(),
        };
    }

    pub fn slot(self: *const SignedBlock) Slot {
        return switch (self.*) {
            .regular => |b| b.beaconBlock().slot(),
            .blinded => |b| b.beaconBlock().slot(),
        };
    }

    pub fn hashTreeRoot(self: *const SignedBlock, allocator: std.mem.Allocator, out: *[32]u8) !void {
        return switch (self.*) {
            .regular => |b| b.beaconBlock().hashTreeRoot(allocator, out),
            .blinded => |b| b.beaconBlock().hashTreeRoot(allocator, out),
        };
    }

    pub fn proposerIndex(self: *const SignedBlock) u64 {
        return switch (self.*) {
            .regular => |b| b.beaconBlock().proposerIndex(),
            .blinded => |b| b.beaconBlock().proposerIndex(),
        };
    }

    pub fn signature(self: *const SignedBlock) ssz.primitive.BLSSignature.Type {
        return switch (self.*) {
            inline .regular, .blinded => |b| b.signature(),
        };
    }
};

const std = @import("std");
const ssz = @import("consensus_types");
const preset = @import("preset").preset;
const ZERO_HASH = @import("constants").ZERO_HASH;

const Root = ssz.primitive.Root.Type;
const Deposit = ssz.phase0.Deposit.Type;
const DepositRequest = ssz.electra.DepositRequest.Type;
const WithdrawalRequest = ssz.electra.WithdrawalRequest.Type;
const ConsolidationRequest = ssz.electra.ConsolidationRequest.Type;

const Attestation = @import("attestation.zig").Attestation;
const Attestations = @import("attestation.zig").Attestations;
const AttesterSlashings = @import("attester_slashing.zig").AttesterSlashings;
const ProposerSlashing = ssz.phase0.ProposerSlashing.Type;
const SignedVoluntaryExit = ssz.phase0.SignedVoluntaryExit.Type;
const Slot = ssz.primitive.Slot.Type;
const SignedBLSToExecutionChange = ssz.capella.SignedBLSToExecutionChange.Type;

const BeaconBlock = @import("beacon_block.zig").BeaconBlock;
const SignedBeaconBlock = @import("beacon_block.zig").SignedBeaconBlock;
const SignedBlindedBeaconBlock = @import("beacon_block.zig").SignedBlindedBeaconBlock;
const BlindedBeaconBlock = @import("beacon_block.zig").BlindedBeaconBlock;
const BlindedBeaconBlockBody = @import("beacon_block.zig").BlindedBeaconBlockBody;
const BeaconBlockBody = @import("beacon_block.zig").BeaconBlockBody;
