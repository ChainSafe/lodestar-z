//! Tests for `store.zig`: one honest node walked by hand through two slots.

const std = @import("std");
const testing = std.testing;
const limits = @import("limits.zig");
const types = @import("types.zig");
const block_tree = @import("block_tree.zig");
const Schedule = @import("schedule.zig").Schedule;
const Store = @import("store.zig").Store;

const GoldfishVote = types.GoldfishVote;

fn threeOfFour() Schedule {
    var schedule = Schedule.blank(4);
    for (0..limits.max_slots) |s| {
        schedule.proposer[s] = 0;
        schedule.committee[s][0] = true;
        schedule.committee[s][1] = true;
        schedule.committee[s][2] = true;
    }
    return schedule;
}

test "slot 1 proposal on genesis, votes, confirmation at t_1 + 6" {
    const schedule = threeOfFour();
    const store = try testing.allocator.create(Store);
    defer testing.allocator.destroy(store);
    store.init(&schedule, .goldfish);

    store.setTime(4);
    const block = store.proposeBlock(0);
    try testing.expect(std.mem.eql(u8, &block.parent, &types.genesis_root));
    try testing.expect(store.onBlock(&block));
    try testing.expect(!store.onBlock(&block));
    const b1 = store.tree.find(&block.root).?;

    store.setTime(5);
    try testing.expectEqual(b1, store.voteHead());
    for ([_]u32{ 0, 1, 2 }) |v| {
        const vote: GoldfishVote = .{ .val_index = v, .slot = 1, .head = block.root };
        try testing.expect(store.onGoldfishVote(&vote));
    }
    const outsider: GoldfishVote = .{ .val_index = 3, .slot = 1, .head = block.root };
    try testing.expect(!store.onGoldfishVote(&outsider));

    store.setTime(6);
    store.updateConfirmation(0);
    try testing.expectEqual(block_tree.genesis_index, store.getConfirmed());

    store.setTime(10);
    store.updateConfirmation(1);
    try testing.expectEqual(b1, store.getConfirmed());
    try testing.expectEqual(block_tree.genesis_index, store.getStable());
}

test "expired votes are refused, future votes too" {
    const schedule = threeOfFour();
    const store = try testing.allocator.create(Store);
    defer testing.allocator.destroy(store);
    store.init(&schedule, .goldfish);

    store.setTime(4);
    const b1 = store.proposeBlock(0);
    try testing.expect(store.onBlock(&b1));
    store.setTime(5);
    const early: GoldfishVote = .{ .val_index = 0, .slot = 1, .head = b1.root };
    try testing.expect(store.onGoldfishVote(&early));

    store.setTime(7);
    const after_freeze: GoldfishVote = .{ .val_index = 1, .slot = 1, .head = b1.root };
    try testing.expect(store.onGoldfishVote(&after_freeze));

    store.setTime(8);
    const b2 = store.proposeBlock(0);
    try testing.expectEqual(@as(u32, 2), b2.votes.count);
    try testing.expect(store.onBlock(&b2));

    store.setTime(12);
    const stale: GoldfishVote = .{ .val_index = 2, .slot = 1, .head = b1.root };
    try testing.expect(!store.onGoldfishVote(&stale));
    const future: GoldfishVote = .{ .val_index = 2, .slot = 4, .head = b1.root };
    try testing.expect(!store.onGoldfishVote(&future));
}

test "the LMD-GHOST control keeps old votes" {
    const schedule = threeOfFour();
    const store = try testing.allocator.create(Store);
    defer testing.allocator.destroy(store);
    store.init(&schedule, .lmd_ghost);

    store.setTime(4);
    const b1 = store.proposeBlock(0);
    try testing.expect(store.onBlock(&b1));
    store.setTime(12);
    const stale: GoldfishVote = .{ .val_index = 2, .slot = 1, .head = b1.root };
    try testing.expect(store.onGoldfishVote(&stale));
}

test "a block with a non-committee vote is rejected whole" {
    const schedule = threeOfFour();
    const store = try testing.allocator.create(Store);
    defer testing.allocator.destroy(store);
    store.init(&schedule, .goldfish);

    store.setTime(4);
    const b1 = store.proposeBlock(0);
    try testing.expect(store.onBlock(&b1));
    store.setTime(8);
    var b2: types.Block = .{ .slot = 2, .parent = b1.root, .proposer = 0 };
    b2.votes.push(.{ .val_index = 3, .slot = 1, .head = b1.root });
    b2.seal();
    try testing.expect(!store.onBlock(&b2));
    var wrong_proposer: types.Block = .{ .slot = 2, .parent = b1.root, .proposer = 1 };
    wrong_proposer.seal();
    try testing.expect(!store.onBlock(&wrong_proposer));
}
