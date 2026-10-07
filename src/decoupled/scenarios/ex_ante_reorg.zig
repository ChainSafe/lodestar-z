//! The ex-ante reorg of the ethresear.ch post. The adversary holds a
//! committee majority in `m` consecutive slots, builds a private chain there
//! and withholds its blocks and votes, then releases everything one slot
//! after the honest chain has resumed.
//!
//! Under Goldfish, only the latest slot's votes count, and that slot has an
//! honest majority: the honest head stands. Under the LMD-GHOST control, the
//! released majorities of `m` old slots outweigh the honest votes and the
//! private chain wins.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const BoundedArray = @import("bounded_array").BoundedArray;
const limits = @import("../limits.zig");
const types = @import("../types.zig");
const Schedule = @import("../schedule.zig").Schedule;
const store_mod = @import("../store.zig");
const Store = store_mod.Store;
const event = @import("../sim/event.zig");
const Runner = @import("../sim/runner.zig").Runner;
const state_hash = @import("../sim/state_hash.zig");

const Block = types.Block;
const GoldfishVote = types.GoldfishVote;
const Slot = types.Slot;
const Time = types.Time;

const validator_count: u32 = 64;
const committee_size: u32 = 8;
const adversaries_per_slot: u32 = 7;
const min_attack_slots: u32 = 3;
const max_attack_slots: u32 = 5;
const earliest_attack_slot: Slot = 2;
const latest_attack_slot: Slot = 3;

comptime {
    assert(validator_count <= limits.max_validators);
    assert(committee_size <= limits.max_committee);
    assert(adversaries_per_slot < committee_size);
    // Committees rotate through the validator set in `cycle` slots. The
    // classification slot `k + m + 2` must come before the first attack
    // committee repeats at `k + cycle`.
    const cycle = validator_count / committee_size;
    assert(max_attack_slots + 2 < cycle);
    assert(latest_attack_slot + max_attack_slots + 2 < limits.max_slots);
}

pub const Params = struct {
    seed: u64,
    rule: store_mod.ForkChoiceRule,
};

pub const Outcome = enum { honest, private, mixed };

pub const Result = struct {
    outcome: Outcome,
    digest: types.Root,
    first_attack_slot: Slot,
    attack_slots: Slot,
};

fn buildSchedule(schedule: *Schedule, rand: std.Random, k: Slot, m: Slot) void {
    schedule.* = Schedule.blank(validator_count);
    for (0..limits.max_slots) |s| {
        const base: u32 = @intCast((s * committee_size) % validator_count);
        for (0..committee_size) |j| schedule.committee[s][(base + j) % validator_count] = true;
        schedule.proposer[s] = base;
    }
    var s = k;
    while (s < k + m) : (s += 1) {
        var members: [committee_size]u32 = undefined;
        const base: u32 = (s * committee_size) % validator_count;
        for (0..committee_size) |j| members[j] = (base + @as(u32, @intCast(j))) % validator_count;
        rand.shuffle(u32, &members);
        for (members[0..adversaries_per_slot]) |v| schedule.honest[v] = false;
        schedule.proposer[s] = members[0];
        assert(!schedule.honestMajority(s));
    }
    for (0..k + m + 3) |slot| {
        const in_attack = slot >= k and slot < k + m;
        if (in_attack) continue;
        assert(schedule.honestMajority(@intCast(slot)));
        assert(schedule.isHonest(schedule.proposer[slot]));
    }
}

const Scenario = struct {
    adv: *Store,
    schedule: *const Schedule,
    k: Slot,
    m: Slot,
    private_blocks: BoundedArray(Block, max_attack_slots) = .{},
    withheld: BoundedArray(GoldfishVote, max_attack_slots * committee_size) = .{},
    first_private: ?types.Root = null,
    outcome: ?Outcome = null,

    pub fn onEmission(self: *Scenario, runner: anytype, payload: *const event.Payload, t: Time) void {
        _ = runner;
        self.adv.setTime(t);
        switch (payload.*) {
            .block => |*block| _ = self.adv.onBlock(block),
            .vote => |*vote| _ = self.adv.onGoldfishVote(vote),
        }
    }

    pub fn onTime(self: *Scenario, runner: anytype, t: Time) void {
        self.adv.setTime(t);
        const s = types.slotOf(t);
        const offset = t - types.slotStart(s);
        const attacking = s >= self.k and s < self.k + self.m;
        if (attacking and offset == 0) self.buildPrivateBlock(s);
        if (attacking and offset == 1) self.castWithheldVotes(s);
        if (s == self.k + self.m + 1 and offset == 0) self.release(runner, t);
        if (s == self.k + self.m + 2 and offset == 1) self.classify(runner);
    }

    fn buildPrivateBlock(self: *Scenario, s: Slot) void {
        assert(!self.schedule.isHonest(self.schedule.proposer[s]));
        const block = self.adv.proposeBlock(self.schedule.proposer[s]);
        const accepted = self.adv.onBlock(&block);
        assert(accepted);
        if (self.first_private == null) self.first_private = block.root;
        self.private_blocks.push(block);
    }

    fn castWithheldVotes(self: *Scenario, s: Slot) void {
        const head = self.adv.voteHead();
        const root = self.adv.tree.block(head).root;
        assert(std.mem.eql(u8, &root, &self.private_blocks.buffer[self.private_blocks.count - 1].root));
        for (0..validator_count) |v| {
            const val_index: u32 = @intCast(v);
            if (self.schedule.isHonest(val_index)) continue;
            if (!self.schedule.inCommittee(s, val_index)) continue;
            const vote: GoldfishVote = .{ .val_index = val_index, .slot = s, .head = root };
            const accepted = self.adv.onGoldfishVote(&vote);
            assert(accepted);
            self.withheld.push(vote);
        }
    }

    fn release(self: *Scenario, runner: anytype, t: Time) void {
        assert(self.private_blocks.count == self.m);
        assert(self.withheld.count == self.m * adversaries_per_slot);
        for (0..runner.node_count) |n| {
            const node: u32 = @intCast(n);
            for (self.private_blocks.constSlice()) |*block| {
                runner.scheduler.push(t + 1, .before_tick, node, &.{ .block = block.* });
            }
            for (self.withheld.constSlice()) |*vote| {
                runner.scheduler.push(t + 1, .before_tick, node, &.{ .vote = vote.* });
            }
        }
    }

    fn classify(self: *Scenario, runner: anytype) void {
        const first = self.first_private.?;
        var honest_heads: u32 = 0;
        var private_heads: u32 = 0;
        for (runner.nodes[0..runner.node_count]) |*node| {
            const store = node.store;
            const private_root = store.tree.find(&first) orelse {
                honest_heads += 1;
                continue;
            };
            if (store.tree.isAncestorOrSelf(private_root, node.last_head)) {
                private_heads += 1;
            } else {
                honest_heads += 1;
            }
        }
        assert(honest_heads + private_heads == runner.node_count);
        if (private_heads == 0) {
            self.outcome = .honest;
        } else if (honest_heads == 0) {
            self.outcome = .private;
        } else {
            self.outcome = .mixed;
        }
    }
};

pub fn run(allocator: Allocator, params: Params) !Result {
    var prng = std.Random.Xoshiro256.init(params.seed);
    const rand = prng.random();
    const k = rand.intRangeAtMost(Slot, earliest_attack_slot, latest_attack_slot);
    const m = rand.intRangeAtMost(Slot, min_attack_slots, max_attack_slots);

    const schedule = try allocator.create(Schedule);
    defer allocator.destroy(schedule);
    buildSchedule(schedule, rand, k, m);

    const adv = try allocator.create(Store);
    defer allocator.destroy(adv);
    adv.init(schedule, params.rule);

    var scenario: Scenario = .{ .adv = adv, .schedule = schedule, .k = k, .m = m };
    const runner = try Runner(Scenario).init(allocator, schedule, params.rule, &scenario);
    defer runner.deinit();
    try runner.runUntil(types.slotStart(k + m + 2) + 1);

    var digest = types.genesis_root;
    for (runner.nodes[0..runner.node_count]) |*node| {
        state_hash.combine(&digest, &state_hash.storeDigest(node.store));
    }
    assert(scenario.outcome != null);
    return .{
        .outcome = scenario.outcome.?,
        .digest = digest,
        .first_attack_slot = k,
        .attack_slots = m,
    };
}

test {
    _ = @import("ex_ante_reorg_test.zig");
}
