const std = @import("std");
const testing = std.testing;
const Node = @import("persistent_merkle_tree").Node;
const types = @import("consensus_types");

const Validator = types.phase0.Validator;
const Validators = types.phase0.Validators;
const ValidatorFlatCache = @import("validator_flat_cache.zig").ValidatorFlatCache;

fn expectInSync(cache: *ValidatorFlatCache, view: *Validators.TreeView) !void {
    try view.commit();
    const depth = view.iteratorReadonly(0).depth_iterator.base_gindex.pathLen();
    const list_len = try view.length();
    try cache.sync(view.getRoot(), depth, list_len);
    try testing.expectEqual(@as(usize, 0), try cache.countMismatches(view.getRoot(), depth, list_len));
}


fn testValidator(i: usize) Validator.Type {
    var v: Validator.Type = Validator.default_value;
    v.pubkey[0] = @intCast(i & 0xff);
    v.withdrawal_credentials[0] = if (i % 3 == 0) 2 else 1;
    v.effective_balance = 32_000_000_000;
    v.slashed = i % 7 == 0;
    v.activation_eligibility_epoch = i;
    v.activation_epoch = i + 1;
    v.exit_epoch = std.math.maxInt(u64);
    v.withdrawable_epoch = std.math.maxInt(u64);
    return v;
}



test "ValidatorFlatCache follows writes, appends, truncation and forks" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 4096 });
    defer pool.deinit();

    var list: Validators.Type = .empty;
    defer list.deinit(allocator);
    for (0..100) |i| try list.append(allocator, testValidator(i));

    const root = try Validators.tree.fromValue(&pool, &list);
    var view = try Validators.TreeView.init(allocator, &pool, root);
    defer view.deinit();

    var cache = ValidatorFlatCache.init(allocator, &pool);
    defer cache.deinit();

    try expectInSync(&cache, view);
    try testing.expectEqual(@as(usize, 100), cache.last_patched);

    // Nothing changed: nothing patched.
    try expectInSync(&cache, view);
    try testing.expectEqual(@as(usize, 0), cache.last_patched);

    // Field writes patch only the touched validators.
    var fork = try view.clone(.{ .transfer_cache = false });
    defer fork.deinit();
    for ([_]usize{ 3, 64, 99 }) |i| {
        var v = try view.get(i);
        try v.set("exit_epoch", 1234 + i);
        try v.set("slashed", true);
    }
    try expectInSync(&cache, view);
    try testing.expectEqual(@as(usize, 3), cache.last_patched);

    // Appends, including across a power-of-two boundary.
    for (100..140) |i| {
        const v = testValidator(i);
        try view.pushValue(&v);
    }
    try expectInSync(&cache, view);
    try testing.expectEqual(@as(usize, 40), cache.last_patched);

    // A state on another branch: the diff runs both ways.
    {
        var v = try fork.get(10);
        try v.set("withdrawable_epoch", 77);
    }
    try expectInSync(&cache, fork);
    try expectInSync(&cache, view);

    // Truncation.
    var sliced = try view.sliceTo(49);
    defer sliced.deinit();
    try expectInSync(&cache, sliced);
    try testing.expectEqual(@as(usize, 50), cache.len());
    try expectInSync(&cache, view);
}

