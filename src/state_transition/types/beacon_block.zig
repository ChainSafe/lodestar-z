const std = @import("std");

const panic = std.debug.panic;
const Allocator = std.mem.Allocator;
const expect = std.testing.expect;
const ct = @import("consensus_types");
const Slot = ct.primitive.Slot.Type;
const Deposit = ct.phase0.Deposit.Type;
const SignedVoluntaryExit = ct.phase0.SignedVoluntaryExit.Type;
const ValidatorIndex = ct.primitive.ValidatorIndex.Type;
const SignedBLSToExecutionChange = ct.capella.SignedBLSToExecutionChange.Type;
const DepositRequest = ct.electra.DepositRequest.Type;
const WithdrawalRequest = ct.electra.WithdrawalRequest.Type;
const ConsolidationRequest = ct.electra.ConsolidationRequest.Type;
const Root = ct.primitive.Root.Type;
const ProposerSlashing = ct.phase0.ProposerSlashing.Type;
const ProposerSlashings = ct.phase0.ProposerSlashings.Type;
const ExecutionPayload = @import("./execution_payload.zig").ExecutionPayload;
const ExecutionPayloadHeader = @import("./execution_payload.zig").ExecutionPayloadHeader;
const Attestations = @import("./attestation.zig").Attestations;
const AttesterSlashings = @import("./attester_slashing.zig").AttesterSlashings;
const AttesterSlashing = @import("./attester_slashing.zig").AttesterSlashing;

pub const SignedBeaconBlock = union(enum) {
    phase0: *const ct.phase0.SignedBeaconBlock.Type,
    altair: *const ct.altair.SignedBeaconBlock.Type,
    bellatrix: *const ct.bellatrix.SignedBeaconBlock.Type,
    capella: *const ct.capella.SignedBeaconBlock.Type,
    deneb: *const ct.deneb.SignedBeaconBlock.Type,
    electra: *const ct.electra.SignedBeaconBlock.Type,

    pub fn beaconBlock(self: *const SignedBeaconBlock) BeaconBlock {
        return switch (self.*) {
            .phase0 => |block| .{ .phase0 = &block.message },
            .altair => |block| .{ .altair = &block.message },
            .bellatrix => |block| .{ .bellatrix = &block.message },
            .capella => |block| .{ .capella = &block.message },
            .deneb => |block| .{ .deneb = &block.message },
            .electra => |block| .{ .electra = &block.message },
        };
    }

    pub fn signature(self: *const SignedBeaconBlock) ct.primitive.BLSSignature.Type {
        return switch (self.*) {
            inline .phase0, .altair, .bellatrix, .capella, .deneb, .electra => |block| block.signature,
        };
    }
};

pub const SignedBlindedBeaconBlock = union(enum) {
    capella: *const ct.capella.SignedBlindedBeaconBlock.Type,
    deneb: *const ct.deneb.SignedBlindedBeaconBlock.Type,
    electra: *const ct.electra.SignedBlindedBeaconBlock.Type,

    pub fn beaconBlock(self: *const SignedBlindedBeaconBlock) BlindedBeaconBlock {
        return switch (self.*) {
            .capella => |block| .{ .capella = &block.message },
            .deneb => |block| .{ .deneb = &block.message },
            .electra => |block| .{ .electra = &block.message },
        };
    }

    pub fn signature(self: *const SignedBlindedBeaconBlock) ct.primitive.BLSSignature.Type {
        return switch (self.*) {
            inline .capella, .deneb, .electra => |block| block.signature,
        };
    }
};

pub const BeaconBlock = union(enum) {
    phase0: *const ct.phase0.BeaconBlock.Type,
    altair: *const ct.altair.BeaconBlock.Type,
    bellatrix: *const ct.bellatrix.BeaconBlock.Type,
    capella: *const ct.capella.BeaconBlock.Type,
    deneb: *const ct.deneb.BeaconBlock.Type,
    electra: *const ct.electra.BeaconBlock.Type,

    pub fn hashTreeRoot(self: *const BeaconBlock, allocator: std.mem.Allocator, out: *[32]u8) !void {
        switch (self.*) {
            .phase0 => |block| try ct.phase0.BeaconBlock.hashTreeRoot(allocator, block, out),
            .altair => |block| try ct.altair.BeaconBlock.hashTreeRoot(allocator, block, out),
            .bellatrix => |block| try ct.bellatrix.BeaconBlock.hashTreeRoot(allocator, block, out),
            .capella => |block| try ct.capella.BeaconBlock.hashTreeRoot(allocator, block, out),
            .deneb => |block| try ct.deneb.BeaconBlock.hashTreeRoot(allocator, block, out),
            .electra => |block| try ct.electra.BeaconBlock.hashTreeRoot(allocator, block, out),
        }
    }
    pub fn format(
        self: BeaconBlock,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        return switch (self) {
            inline .phase0, .altair, .bellatrix, .capella, .deneb, .electra => {
                try writer.print("{s} (at slot {})", .{ @tagName(self), self.slot() });
            },
        };
    }

    pub fn slot(self: *const BeaconBlock) Slot {
        return switch (self.*) {
            inline .phase0, .altair, .bellatrix, .capella, .deneb, .electra => |block| block.slot,
        };
    }

    pub fn proposerIndex(self: *const BeaconBlock) ValidatorIndex {
        return switch (self.*) {
            inline .phase0, .altair, .bellatrix, .capella, .deneb, .electra => |block| block.proposer_index,
        };
    }

    pub fn parentRoot(self: *const BeaconBlock) Root {
        return switch (self.*) {
            inline .phase0, .altair, .bellatrix, .capella, .deneb, .electra => |block| block.parent_root,
        };
    }

    pub fn stateRoot(self: *const BeaconBlock) Root {
        return switch (self.*) {
            inline .phase0, .altair, .bellatrix, .capella, .deneb, .electra => |block| block.state_root,
        };
    }

    pub fn beaconBlockBody(self: *const BeaconBlock) BeaconBlockBody {
        return switch (self.*) {
            .phase0 => |block| .{ .phase0 = &block.body },
            .altair => |block| .{ .altair = &block.body },
            .bellatrix => |block| .{ .bellatrix = &block.body },
            .capella => |block| .{ .capella = &block.body },
            .deneb => |block| .{ .deneb = &block.body },
            .electra => |block| .{ .electra = &block.body },
        };
    }
};

pub const BlindedBeaconBlock = union(enum) {
    capella: *const ct.capella.BlindedBeaconBlock.Type,
    deneb: *const ct.deneb.BlindedBeaconBlock.Type,
    electra: *const ct.electra.BlindedBeaconBlock.Type,

    const Self = @This();

    pub fn beaconBlockBody(self: *const Self) BlindedBeaconBlockBody {
        return switch (self.*) {
            .capella => |block| .{ .capella = &block.body },
            .deneb => |block| .{ .deneb = &block.body },
            .electra => |block| .{ .electra = &block.body },
        };
    }

    pub fn hashTreeRoot(self: *const Self, allocator: std.mem.Allocator, out: *[32]u8) !void {
        switch (self.*) {
            .capella => |block| try ct.capella.BlindedBeaconBlock.hashTreeRoot(allocator, block, out),
            .deneb => |block| try ct.deneb.BlindedBeaconBlock.hashTreeRoot(allocator, block, out),
            .electra => |block| try ct.electra.BlindedBeaconBlock.hashTreeRoot(allocator, block, out),
        }
    }

    pub fn slot(self: *const Self) Slot {
        return switch (self.*) {
            inline .capella, .deneb, .electra => |block| block.slot,
        };
    }

    pub fn proposerIndex(self: *const Self) ValidatorIndex {
        return switch (self.*) {
            inline .capella, .deneb, .electra => |block| block.proposer_index,
        };
    }

    pub fn parentRoot(self: *const Self) Root {
        return switch (self.*) {
            inline .capella, .deneb, .electra => |block| block.parent_root,
        };
    }

    pub fn stateRoot(self: *const Self) Root {
        return switch (self.*) {
            inline .capella, .deneb, .electra => |block| block.state_root,
        };
    }
};

pub const BeaconBlockBody = union(enum) {
    phase0: *const ct.phase0.BeaconBlockBody.Type,
    altair: *const ct.altair.BeaconBlockBody.Type,
    bellatrix: *const ct.bellatrix.BeaconBlockBody.Type,
    capella: *const ct.capella.BeaconBlockBody.Type,
    deneb: *const ct.deneb.BeaconBlockBody.Type,
    electra: *const ct.electra.BeaconBlockBody.Type,

    pub fn format(
        self: BeaconBlockBody,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        return switch (self) {
            inline .phase0, .altair, .bellatrix, .capella, .deneb, .electra => try writer.print("{s}", .{@tagName(self)}),
        };
    }

    pub fn hashTreeRoot(self: *const BeaconBlockBody, allocator: std.mem.Allocator, out: *[32]u8) !void {
        return switch (self.*) {
            .phase0 => |body| try ct.phase0.BeaconBlockBody.hashTreeRoot(allocator, body, out),
            .altair => |body| try ct.altair.BeaconBlockBody.hashTreeRoot(allocator, body, out),
            .bellatrix => |body| try ct.bellatrix.BeaconBlockBody.hashTreeRoot(allocator, body, out),
            .capella => |body| try ct.capella.BeaconBlockBody.hashTreeRoot(allocator, body, out),
            .deneb => |body| try ct.deneb.BeaconBlockBody.hashTreeRoot(allocator, body, out),
            .electra => |body| try ct.electra.BeaconBlockBody.hashTreeRoot(allocator, body, out),
        };
    }

    pub fn isExecutionType(self: *const BeaconBlockBody) bool {
        return switch (self.*) {
            .phase0 => false,
            .altair => false,
            else => true,
        };
    }

    // phase0 fields
    pub fn randaoReveal(self: *const BeaconBlockBody) ct.primitive.BLSSignature.Type {
        return switch (self.*) {
            inline .phase0, .altair, .bellatrix, .capella, .deneb, .electra => |body| body.randao_reveal,
        };
    }

    pub fn eth1Data(self: *const BeaconBlockBody) *const ct.phase0.Eth1Data.Type {
        return switch (self.*) {
            inline .phase0, .altair, .bellatrix, .capella, .deneb, .electra => |body| &body.eth1_data,
        };
    }

    pub fn graffiti(self: *const BeaconBlockBody) ct.primitive.Bytes32.Type {
        return switch (self.*) {
            inline .phase0, .altair, .bellatrix, .capella, .deneb, .electra => |body| body.graffiti,
        };
    }

    pub fn proposerSlashings(self: *const BeaconBlockBody) []ProposerSlashing {
        return switch (self.*) {
            inline .phase0, .altair, .bellatrix, .capella, .deneb, .electra => |body| body.proposer_slashings.items,
        };
    }

    pub fn attesterSlashings(self: *const BeaconBlockBody) AttesterSlashings {
        return switch (self.*) {
            .electra => |body| .{ .electra = body.attester_slashings },
            inline .phase0, .altair, .bellatrix, .capella, .deneb => |body| .{ .phase0 = body.attester_slashings },
        };
    }

    pub fn attestations(self: *const BeaconBlockBody) Attestations {
        return switch (self.*) {
            inline .phase0, .altair, .bellatrix, .capella, .deneb => |body| .{ .phase0 = &body.attestations },
            .electra => |body| .{ .electra = &body.attestations },
        };
    }

    pub fn deposits(self: *const BeaconBlockBody) []Deposit {
        return switch (self.*) {
            inline .phase0, .altair, .bellatrix, .capella, .deneb, .electra => |body| body.deposits.items,
        };
    }

    pub fn voluntaryExits(self: *const BeaconBlockBody) []SignedVoluntaryExit {
        return switch (self.*) {
            inline .phase0, .altair, .bellatrix, .capella, .deneb, .electra => |body| body.voluntary_exits.items,
        };
    }

    // altair fields
    pub fn syncAggregate(self: *const BeaconBlockBody) *const ct.altair.SyncAggregate.Type {
        return switch (self.*) {
            inline .altair, .bellatrix, .capella, .deneb, .electra => |body| &body.sync_aggregate,
            else => @panic("SyncAggregate is not available in phase0"),
        };
    }

    // bellatrix fields
    pub fn executionPayload(self: *const BeaconBlockBody) ExecutionPayload {
        return switch (self.*) {
            .bellatrix => |body| .{ .bellatrix = &body.execution_payload },
            .capella => |body| .{ .capella = &body.execution_payload },
            .deneb => |body| .{ .deneb = &body.execution_payload },
            .electra => |body| .{ .electra = &body.execution_payload },
            else => panic("ExecutionPayload is not available in {}", .{self}),
        };
    }

    // capella fields
    pub fn blsToExecutionChanges(self: *const BeaconBlockBody) []SignedBLSToExecutionChange {
        return switch (self.*) {
            .capella => |body| body.bls_to_execution_changes.items,
            .deneb => |body| body.bls_to_execution_changes.items,
            .electra => |body| body.bls_to_execution_changes.items,
            else => panic("BlsToExecutionChanges is not available in {}", .{self}),
        };
    }

    // deneb fields
    pub fn blobKzgCommitments(self: *const BeaconBlockBody) *const ct.deneb.BlobKzgCommitments.Type {
        return switch (self.*) {
            .deneb => |body| &body.blob_kzg_commitments,
            .electra => |body| &body.blob_kzg_commitments,
            else => panic("BlobKzgCommitments is not available in {}", .{self}),
        };
    }

    // electra fields
    pub fn executionRequests(self: *const BeaconBlockBody) *const ct.electra.ExecutionRequests.Type {
        return switch (self.*) {
            .electra => |body| &body.execution_requests,
            else => panic("ExecutionRequests is not available in {}", .{self}),
        };
    }

    pub fn depositRequests(self: *const BeaconBlockBody) []DepositRequest {
        return switch (self.*) {
            .electra => |body| body.execution_requests.deposits.items,
            else => panic("DepositRequests is not available in {}", .{self}),
        };
    }

    pub fn withdrawalRequests(self: *const BeaconBlockBody) []WithdrawalRequest {
        return switch (self.*) {
            .electra => |body| body.execution_requests.withdrawals.items,
            else => panic("WithdrawalRequests is not available in {}", .{self}),
        };
    }

    pub fn consolidationRequests(self: *const BeaconBlockBody) []ConsolidationRequest {
        return switch (self.*) {
            .electra => |body| body.execution_requests.consolidations.items,
            else => panic("ConsolidationRequests is not available in {}", .{self}),
        };
    }
};

pub const BlindedBeaconBlockBody = union(enum) {
    capella: *const ct.capella.BlindedBeaconBlockBody.Type,
    deneb: *const ct.deneb.BlindedBeaconBlockBody.Type,
    electra: *const ct.electra.BlindedBeaconBlockBody.Type,

    pub fn hashTreeRoot(self: *const BlindedBeaconBlockBody, allocator: std.mem.Allocator, out: *[32]u8) !void {
        return switch (self.*) {
            .capella => |body| try ct.capella.BlindedBeaconBlockBody.hashTreeRoot(allocator, body, out),
            .deneb => |body| try ct.deneb.BlindedBeaconBlockBody.hashTreeRoot(allocator, body, out),
            .electra => |body| try ct.electra.BlindedBeaconBlockBody.hashTreeRoot(allocator, body, out),
        };
    }

    // phase0 fields
    pub fn randaoReveal(self: *const BlindedBeaconBlockBody) ct.primitive.BLSSignature.Type {
        return switch (self.*) {
            inline .capella, .deneb, .electra => |body| body.randao_reveal,
        };
    }

    pub fn eth1Data(self: *const BlindedBeaconBlockBody) *const ct.phase0.Eth1Data.Type {
        return switch (self.*) {
            inline .capella, .deneb, .electra => |body| &body.eth1_data,
        };
    }

    pub fn graffiti(self: *const BlindedBeaconBlockBody) ct.primitive.Bytes32.Type {
        return switch (self.*) {
            inline .capella, .deneb, .electra => |body| body.graffiti,
        };
    }

    pub fn proposerSlashings(self: *const BlindedBeaconBlockBody) []ProposerSlashing {
        return switch (self.*) {
            inline .capella, .deneb, .electra => |body| body.proposer_slashings.items,
        };
    }

    pub fn attesterSlashings(self: *const BlindedBeaconBlockBody) AttesterSlashings {
        return switch (self.*) {
            .electra => |body| .{ .electra = body.attester_slashings },
            inline .capella, .deneb => |body| .{ .phase0 = body.attester_slashings },
        };
    }

    pub fn attestations(self: *const BlindedBeaconBlockBody) Attestations {
        return switch (self.*) {
            inline .capella, .deneb => |body| .{ .phase0 = &body.attestations },
            .electra => |body| .{ .electra = &body.attestations },
        };
    }

    pub fn deposits(self: *const BlindedBeaconBlockBody) []Deposit {
        return switch (self.*) {
            inline .capella, .deneb, .electra => |body| body.deposits.items,
        };
    }

    pub fn voluntaryExits(self: *const BlindedBeaconBlockBody) []SignedVoluntaryExit {
        return switch (self.*) {
            inline .capella, .deneb, .electra => |body| body.voluntary_exits.items,
        };
    }

    // altair fields
    pub fn syncAggregate(self: *const BlindedBeaconBlockBody) *const ct.altair.SyncAggregate.Type {
        return switch (self.*) {
            inline .capella, .deneb, .electra => |body| &body.sync_aggregate,
        };
    }

    // bellatrix fields
    pub fn executionPayloadHeader(self: *const BlindedBeaconBlockBody) ExecutionPayloadHeader {
        return switch (self.*) {
            .capella => |body| .{ .capella = &body.execution_payload_header },
            .deneb => |body| .{ .deneb = &body.execution_payload_header },
            .electra => |body| .{ .electra = &body.execution_payload_header },
        };
    }

    // capella fields
    pub fn blsToExecutionChanges(self: *const BlindedBeaconBlockBody) []SignedBLSToExecutionChange {
        return switch (self.*) {
            .capella => |body| body.bls_to_execution_changes.items,
            .deneb => |body| body.bls_to_execution_changes.items,
            .electra => |body| body.bls_to_execution_changes.items,
        };
    }

    // deneb fields
    pub fn blobKzgCommitments(self: *const BlindedBeaconBlockBody) *const ct.deneb.BlobKzgCommitments.Type {
        return switch (self.*) {
            .capella => @panic("BlobKzgCommitments is not available in capella"),
            .deneb => |body| &body.blob_kzg_commitments,
            .electra => |body| &body.blob_kzg_commitments,
        };
    }

    // electra fields
    pub fn executionRequests(self: *const BlindedBeaconBlockBody) *const ct.electra.ExecutionRequests.Type {
        return switch (self.*) {
            .capella => @panic("ExecutionRequests is not available in capella"),
            .deneb => @panic("ExecutionRequests is not available in deneb"),
            .electra => |body| &body.execution_requests,
        };
    }

    pub fn depositRequests(self: *const BlindedBeaconBlockBody) []DepositRequest {
        return switch (self.*) {
            .capella => @panic("DepositRequests is not available in capella"),
            .deneb => @panic("DepositRequests is not available in deneb"),
            .electra => |body| body.execution_requests.deposits.items,
        };
    }

    pub fn withdrawalRequests(self: *const BlindedBeaconBlockBody) []WithdrawalRequest {
        return switch (self.*) {
            .capella => @panic("WithdrawalRequests is not available in capella"),
            .deneb => @panic("WithdrawalRequests is not available in deneb"),
            .electra => |body| body.execution_requests.withdrawals.items,
        };
    }

    pub fn consolidationRequests(self: *const BlindedBeaconBlockBody) []ConsolidationRequest {
        return switch (self.*) {
            .capella => @panic("ConsolidationRequests is not available in capella"),
            .deneb => @panic("ConsolidationRequests is not available in deneb"),
            .electra => |body| body.execution_requests.consolidations.items,
        };
    }
};

fn testBlockSanity(Block: type) !void {
    const allocator = std.testing.allocator;

    const is_blinded = Block == BlindedBeaconBlock;
    const ssz_block = if (is_blinded) ct.electra.BlindedBeaconBlock else ct.electra.BeaconBlock;
    var electra_block = ssz_block.default_value;

    electra_block.slot = 12345;
    electra_block.proposer_index = 1;
    electra_block.body.randao_reveal = [_]u8{1} ** 96;
    var attestations = try std.ArrayListUnmanaged(ct.electra.Attestation.Type).initCapacity(std.testing.allocator, 10);
    defer attestations.deinit(allocator);
    var attestation0 = ct.electra.Attestation.default_value;
    attestation0.data.slot = 12345;
    try attestations.append(allocator, attestation0);
    electra_block.body.attestations = attestations;
    try expect(electra_block.body.attestations.items[0].data.slot == 12345);

    const beacon_block = Block{ .electra = &electra_block };

    try expect(beacon_block.slot() == 12345);
    try expect(beacon_block.proposerIndex() == 1);
    try std.testing.expectEqualSlices(u8, &[_]u8{0} ** 32, &beacon_block.parentRoot());
    try std.testing.expectEqualSlices(u8, &[_]u8{0} ** 32, &beacon_block.stateRoot());

    var out: [32]u8 = undefined;
    // all phases
    try beacon_block.hashTreeRoot(allocator, &out);
    try expect(!std.mem.eql(u8, &[_]u8{0} ** 32, &out));
    const block_body = beacon_block.beaconBlockBody();
    out = [_]u8{0} ** 32;
    try block_body.hashTreeRoot(allocator, &out);
    try expect(!std.mem.eql(u8, &[_]u8{0} ** 32, &out));

    try std.testing.expectEqualSlices(u8, &[_]u8{1} ** 96, &block_body.randaoReveal());
    const eth1_data = block_body.eth1Data();
    try expect(eth1_data.deposit_count == 0);
    try std.testing.expectEqualSlices(u8, &[_]u8{0} ** 32, &block_body.graffiti());
    try expect(block_body.proposerSlashings().len == 0);
    try expect(block_body.attesterSlashings().length() == 0);
    try expect(block_body.attestations().length() == 1);
    try expect(block_body.attestations().items().electra[0].data.slot == 12345);
    try expect(block_body.deposits().len == 0);
    try expect(block_body.voluntaryExits().len == 0);

    // altair
    const sync_aggregate = block_body.syncAggregate();
    try std.testing.expectEqualSlices(u8, &[_]u8{0} ** 96, &sync_aggregate.sync_committee_signature);

    if (is_blinded) {
        // Blinded blocks do not have the execution payload in plain
        try std.testing.expectEqualSlices(u8, &[_]u8{0} ** 32, &block_body.executionPayloadHeader().electra.parent_hash);
        // another way to access the parent_hash
        try std.testing.expectEqualSlices(u8, &[_]u8{0} ** 32, &block_body.executionPayloadHeader().getParentHash());
    } else {
        try std.testing.expectEqualSlices(u8, &[_]u8{0} ** 32, &block_body.executionPayload().electra.parent_hash);
        // another way to access the parent_hash
        try std.testing.expectEqualSlices(u8, &[_]u8{0} ** 32, &block_body.executionPayload().getParentHash());
    }

    // capella
    try expect(block_body.blsToExecutionChanges().len == 0);

    // deneb
    try expect(block_body.blobKzgCommitments().items.len == 0);

    // electra
    const execution_request = block_body.executionRequests();
    try expect(execution_request.deposits.items.len == 0);
    try expect(execution_request.withdrawals.items.len == 0);
    try expect(execution_request.consolidations.items.len == 0);
}

test "electra - sanity" {
    try testBlockSanity(BeaconBlock);
    try testBlockSanity(BlindedBeaconBlock);
}
