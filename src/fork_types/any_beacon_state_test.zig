//! Tests for `any_beacon_state.zig`.

const std = @import("std");
const expect = std.testing.expect;
const Node = @import("persistent_merkle_tree").Node;
const ct = @import("consensus_types");
const BeaconState = @import("./beacon_state.zig").BeaconState;
const AnyBeaconState = @import("any_beacon_state.zig").AnyBeaconState;

test "electra - sanity" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 500_000 });
    defer pool.deinit();

    var beacon_state = try AnyBeaconState.fromValue(allocator, &pool, .electra, &ct.electra.BeaconState.default_value);
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
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 500_000 });
    defer pool.deinit();

    var beacon_state = try AnyBeaconState.fromValue(allocator, &pool, .electra, &ct.electra.BeaconState.default_value);
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
        var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 500_000 });
        defer pool.deinit();

        var beacon_state = try AnyBeaconState.fromValue(allocator, &pool, .electra, &ct.electra.BeaconState.default_value);
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
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 500_000 });
    defer pool.deinit();

    var phase0_state = try AnyBeaconState.fromValue(allocator, &pool, .phase0, &ct.phase0.BeaconState.default_value);
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

    var gloas_state = try fulu_state.upgradeUnsafe();
    defer gloas_state.deinit();
    try expect(gloas_state.forkSeq() == .gloas);
}

test "single proof: validators[0].withdrawal_credentials" {
    const allocator = std.testing.allocator;
    const ssz = @import("ssz");
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 500_000 });
    defer pool.deinit();

    var beacon_state = try AnyBeaconState.fromValue(
        allocator,
        &pool,
        .electra,
        &ct.electra.BeaconState.default_value,
    );
    defer beacon_state.deinit();

    // Bootstrap one validator so `validators[0]` exists.
    var validators_view = try beacon_state.validators();
    const validator_value = ct.electra.Validator.Type{
        .pubkey = [_]u8{1} ** 48,
        .withdrawal_credentials = [_]u8{0xab} ** 32,
        .effective_balance = 32_000_000_000,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = std.math.maxInt(u64),
        .withdrawable_epoch = std.math.maxInt(u64),
    };
    try validators_view.pushValue(&validator_value);
    try beacon_state.commit();

    const gindex = ssz.getPathGindex(ct.electra.BeaconState, "validators.0.withdrawal_credentials");
    var proof = try beacon_state.getSingleProof(allocator, @intFromEnum(gindex));
    defer proof.deinit(allocator);

    // The proof should be non-empty and the leaf should match the value
    // we set above. (We do not yet verify witness chain correctness — just
    // that proof generation does not error out with InvalidNode.)
    try std.testing.expect(proof.witnesses.len > 0);
    try std.testing.expectEqualSlices(u8, &[_]u8{0xab} ** 32, &proof.leaf);
}

test "single proof: balances[0]" {
    const allocator = std.testing.allocator;
    const ssz = @import("ssz");
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 500_000 });
    defer pool.deinit();

    var beacon_state = try AnyBeaconState.fromValue(
        allocator,
        &pool,
        .electra,
        &ct.electra.BeaconState.default_value,
    );
    defer beacon_state.deinit();

    var balances_view = try beacon_state.balances();
    try balances_view.push(31_000_000_000);
    try beacon_state.commit();

    const gindex = ssz.getPathGindex(ct.electra.BeaconState, "balances.0");
    var proof = try beacon_state.getSingleProof(allocator, @intFromEnum(gindex));
    defer proof.deinit(allocator);

    try std.testing.expect(proof.witnesses.len > 0);
    // balances[0] is a packed u64; only the low 8 bytes of the leaf carry
    // the value (LE-encoded), the rest of the chunk is zero-padded.
    var expected_leaf: [32]u8 = [_]u8{0} ** 32;
    std.mem.writeInt(u64, expected_leaf[0..8], 31_000_000_000, .little);
    try std.testing.expectEqualSlices(u8, &expected_leaf, &proof.leaf);
}
