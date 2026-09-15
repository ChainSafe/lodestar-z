//! Tests for `any_beacon_block.zig`.

const std = @import("std");
const AnySignedBeaconBlock = @import("any_beacon_block.zig").AnySignedBeaconBlock;
const expect = std.testing.expect;
const ct = @import("consensus_types");
const AnyBeaconBlock = @import("any_beacon_block.zig").AnyBeaconBlock;

fn testBlockSanity(Block: type) !void {
    const allocator = std.testing.allocator;

    const ssz_block = ct.electra.BeaconBlock;
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

    const beacon_block = Block{ .full_electra = &electra_block };

    try expect(beacon_block.slot() == 12345);
    try expect(beacon_block.proposerIndex() == 1);
    try std.testing.expectEqualSlices(u8, &[_]u8{0} ** 32, beacon_block.parentRoot());
    try std.testing.expectEqualSlices(u8, &[_]u8{0} ** 32, beacon_block.stateRoot());

    var out: [32]u8 = undefined;
    // all phases
    try beacon_block.hashTreeRoot(allocator, &out);
    try expect(!std.mem.eql(u8, &[_]u8{0} ** 32, &out));
    const block_body = beacon_block.beaconBlockBody();
    try expect(block_body.forkSeq() == .electra);
    out = [_]u8{0} ** 32;
    try block_body.hashTreeRoot(allocator, &out);
    try expect(!std.mem.eql(u8, &[_]u8{0} ** 32, &out));

    try std.testing.expectEqualSlices(u8, &[_]u8{1} ** 96, block_body.randaoReveal());
    const eth1_data = block_body.eth1Data();
    try expect(eth1_data.deposit_count == 0);
    try std.testing.expectEqualSlices(u8, &[_]u8{0} ** 32, block_body.graffiti());
    try expect(block_body.proposerSlashings().len == 0);
    try expect(block_body.attesterSlashings().length() == 0);
    try expect(block_body.attestations().length() == 1);
    try expect(block_body.attestations().items().electra[0].data.slot == 12345);
    try expect(block_body.deposits().len == 0);
    try expect(block_body.voluntaryExits().len == 0);

    // altair
    const sync_aggregate = try block_body.syncAggregate();
    try std.testing.expectEqualSlices(u8, &[_]u8{0} ** 96, &sync_aggregate.sync_committee_signature);

    try std.testing.expectEqualSlices(u8, &[_]u8{0} ** 32, (try block_body.executionPayload()).parentHash());

    // capella
    try expect((try block_body.blsToExecutionChanges()).len == 0);

    // deneb
    try expect((try block_body.blobKzgCommitments()).items.len == 0);

    // electra
    const execution_request = try block_body.executionRequests();
    try expect(execution_request.deposits.items.len == 0);
    try expect(execution_request.withdrawals.items.len == 0);
    try expect(execution_request.consolidations.items.len == 0);
}

test "electra - sanity" {
    try testBlockSanity(AnyBeaconBlock);
}

test "memory_safety: AnySignedBeaconBlock deserialize should deinit partial block on OOM" {
    const allocator = std.testing.allocator;
    const SignedBeaconBlock = ct.phase0.SignedBeaconBlock;

    var block = SignedBeaconBlock.default_value;
    defer SignedBeaconBlock.deinit(allocator, &block);

    try block.message.body.proposer_slashings.append(
        allocator,
        ct.phase0.ProposerSlashing.default_value,
    );
    try block.message.body.voluntary_exits.append(
        allocator,
        ct.phase0.SignedVoluntaryExit.default_value,
    );

    const bytes = try allocator.alloc(u8, SignedBeaconBlock.serializedSize(&block));
    defer allocator.free(bytes);
    _ = SignedBeaconBlock.serializeIntoBytes(&block, bytes);

    var saw_operation_oom = false;
    try std.testing.checkAllAllocationFailures(allocator, struct {
        fn run(failing_allocator: std.mem.Allocator, serialized: []const u8, saw_oom: *bool) !void {
            errdefer |err| {
                saw_oom.* = err == error.OutOfMemory;
            }
            var decoded = try AnySignedBeaconBlock.deserialize(failing_allocator, .full, .phase0, serialized);
            defer decoded.deinit(failing_allocator);
        }
    }.run, .{ bytes, &saw_operation_oom });
    try std.testing.expect(saw_operation_oom);
}
