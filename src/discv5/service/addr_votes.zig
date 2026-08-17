const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Address = Io.net.IpAddress;

pub const MAX_ADDR_VOTES: usize = 200;

const SourceKey = struct {
    family: Address.Family,
    bytes: [16]u8,

    fn fromAddress(addr: Address) SourceKey {
        return switch (addr) {
            .ip4 => |ip4| blk: {
                var bytes = [_]u8{0} ** 16;
                @memcpy(bytes[0..4], &ip4.bytes);
                break :blk .{ .family = .ip4, .bytes = bytes };
            },
            .ip6 => |ip6| .{ .family = .ip6, .bytes = ip6.bytes },
        };
    }
};

const VoteKey = struct {
    family: Address.Family,
    bytes: [16]u8,
    port: u16,

    fn fromAddress(addr: Address) VoteKey {
        return switch (addr) {
            .ip4 => |ip4| blk: {
                var bytes = [_]u8{0} ** 16;
                @memcpy(bytes[0..4], &ip4.bytes);
                break :blk .{ .family = .ip4, .bytes = bytes, .port = ip4.port };
            },
            .ip6 => |ip6| .{ .family = .ip6, .bytes = ip6.bytes, .port = ip6.port },
        };
    }
};

const VoterRecord = struct {
    vote_key: VoteKey,
};

const VoteOrderEntry = struct {
    source: SourceKey,
    vote_key: VoteKey,
};

pub const AddrVotes = struct {
    allocator: Allocator,
    threshold: usize,
    voters: std.AutoHashMap(SourceKey, VoterRecord),
    tallies: std.AutoHashMap(VoteKey, usize),
    order: std.ArrayListUnmanaged(VoteOrderEntry) = .empty,

    pub fn init(allocator: Allocator, threshold: usize) AddrVotes {
        return .{
            .allocator = allocator,
            .threshold = threshold,
            .voters = std.AutoHashMap(SourceKey, VoterRecord).init(allocator),
            .tallies = std.AutoHashMap(VoteKey, usize).init(allocator),
        };
    }

    pub fn deinit(self: *AddrVotes) void {
        self.voters.deinit();
        self.tallies.deinit();
        self.order.deinit(self.allocator);
    }

    pub fn clear(self: *AddrVotes) void {
        self.voters.clearRetainingCapacity();
        self.tallies.clearRetainingCapacity();
        self.order.clearRetainingCapacity();
    }

    /// Record one external-address vote per source IP. Node IDs are cheap to
    /// generate, so counting them independently would let one remote host meet
    /// the ENR-update threshold with local sybils.
    pub fn addVote(self: *AddrVotes, source_addr: Address, observed_addr: Address) !bool {
        const source = SourceKey.fromAddress(source_addr);
        const vote_key = VoteKey.fromAddress(observed_addr);
        const previous = self.voters.get(source);

        if (previous) |record| {
            if (std.meta.eql(record.vote_key, vote_key)) return false;
        }

        const tally = (self.tallies.get(vote_key) orelse 0) + 1;
        if (tally >= self.threshold) {
            self.clear();
            return true;
        }

        try self.tallies.ensureUnusedCapacity(1);
        try self.voters.ensureUnusedCapacity(1);
        if (previous == null) try self.order.ensureUnusedCapacity(self.allocator, 1);

        if (previous) |record| self.decrementTally(record.vote_key);
        self.tallies.putAssumeCapacity(vote_key, tally);
        self.voters.putAssumeCapacity(source, .{ .vote_key = vote_key });

        if (previous == null) {
            self.order.appendAssumeCapacity(.{ .source = source, .vote_key = vote_key });
        } else {
            for (self.order.items) |*entry| {
                if (!std.meta.eql(entry.source, source)) continue;
                entry.vote_key = vote_key;
                break;
            } else unreachable;
        }

        self.evictOverflow();
        return false;
    }

    pub fn currentVoteCount(self: *const AddrVotes) usize {
        return self.voters.count();
    }

    fn decrementTally(self: *AddrVotes, vote_key: VoteKey) void {
        const tally = self.tallies.getPtr(vote_key) orelse return;
        std.debug.assert(tally.* > 0);
        if (tally.* == 1) {
            _ = self.tallies.remove(vote_key);
        } else {
            tally.* -= 1;
        }
    }

    fn evictOverflow(self: *AddrVotes) void {
        while (self.voters.count() > MAX_ADDR_VOTES and self.order.items.len > 0) {
            const evicted = self.order.orderedRemove(0);
            const current = self.voters.get(evicted.source) orelse continue;
            if (!std.meta.eql(current.vote_key, evicted.vote_key)) continue;
            _ = self.voters.remove(evicted.source);
            self.decrementTally(evicted.vote_key);
        }
    }
};

fn testIp4(last: u8, port: u16) Address {
    return .{ .ip4 = .{ .bytes = .{ 127, 0, 0, last }, .port = port } };
}

test "address votes replace a source IP's previous tally" {
    var votes = AddrVotes.init(std.testing.allocator, 3);
    defer votes.deinit();

    const address_a = testIp4(10, 9000);
    const address_b = testIp4(11, 9000);

    try std.testing.expect(!try votes.addVote(testIp4(1, 1001), address_a));
    try std.testing.expect(!try votes.addVote(testIp4(2, 1002), address_a));
    try std.testing.expect(!try votes.addVote(testIp4(1, 2001), address_b));
    try std.testing.expect(!try votes.addVote(testIp4(3, 1003), address_a));
    try std.testing.expect(try votes.addVote(testIp4(4, 1004), address_a));
}

test "address votes count one vote per source IP despite port changes" {
    var votes = AddrVotes.init(std.testing.allocator, 2);
    defer votes.deinit();

    const observed = testIp4(10, 9000);
    try std.testing.expect(!try votes.addVote(testIp4(1, 1001), observed));
    try std.testing.expect(!try votes.addVote(testIp4(1, 2002), observed));
    try std.testing.expectEqual(@as(usize, 1), votes.currentVoteCount());
    try std.testing.expect(try votes.addVote(testIp4(2, 1002), observed));
}

test "address vote replacement keeps ordering storage bounded" {
    var votes = AddrVotes.init(std.testing.allocator, 10);
    defer votes.deinit();

    const source = testIp4(1, 1001);
    for (0..500) |index| {
        const address: Address = .{
            .ip4 = .{
                .bytes = .{ 127, 0, 0, @intCast(index % 255) },
                .port = @intCast(1 + index),
            },
        };
        try std.testing.expect(!try votes.addVote(source, address));
    }

    try std.testing.expectEqual(@as(usize, 1), votes.currentVoteCount());
    try std.testing.expectEqual(@as(usize, 1), votes.order.items.len);
}
