const std = @import("std");
const ForkSeq = @import("config").ForkSeq;
const forkSeqByForkName = @import("config").forkSeqByForkName;
const state_transition = @import("state_transition");
const upgradeStateToAltair = state_transition.upgradeStateToAltair;
const upgradeStateToBellatrix = state_transition.upgradeStateToBellatrix;
const upgradeStateToCapella = state_transition.upgradeStateToCapella;
const upgradeStateToDeneb = state_transition.upgradeStateToDeneb;
const upgradeStateToElectra = state_transition.upgradeStateToElectra;
const upgradeStateToFulu = state_transition.upgradeStateToFulu;
const TestCachedBeaconStateAllForks = state_transition.test_utils.TestCachedBeaconStateAllForks;
const BeaconStateAllForks = state_transition.BeaconStateAllForks;
const test_case = @import("../test_case.zig");
const TestCaseUtils = test_case.TestCaseUtils;
const expectEqualBeaconStates = test_case.expectEqualBeaconStates;

pub const Handler = enum {
    fork,

    pub fn suiteName(self: Handler) []const u8 {
        return @tagName(self) ++ "/pyspec_tests";
    }
};

const Allocator = std.mem.Allocator;

pub fn TestCase(comptime target_fork: ForkSeq) type {
    comptime {
        switch (target_fork) {
            .altair, .bellatrix, .capella, .deneb, .electra, .fulu => {},
            else => @compileError("fork tests are not defined for " ++ @tagName(target_fork)),
        }
    }

    const pre_fork = comptime previousFork(target_fork);
    const pre_tc_utils = TestCaseUtils(pre_fork);
    const post_tc_utils = TestCaseUtils(target_fork);

    return struct {
        pre: TestCachedBeaconStateAllForks,
        post: ?BeaconStateAllForks,

        const Self = @This();

        pub fn execute(allocator: Allocator, dir: std.fs.Dir) !void {
            var tc = try Self.init(allocator, dir);
            defer {
                tc.deinit();
                state_transition.deinitStateTransition();
            }

            try tc.runTest();
        }

        fn init(allocator: Allocator, dir: std.fs.Dir) !Self {
            const meta_fork = try loadTargetFork(allocator, dir);
            if (meta_fork != target_fork) return error.InvalidMetaFile;

            var pre_state = try pre_tc_utils.loadPreState(allocator, dir);
            errdefer pre_state.deinit();

            const post_state = try post_tc_utils.loadPostState(allocator, dir);

            return .{
                .pre = pre_state,
                .post = post_state,
            };
        }

        fn deinit(self: *Self) void {
            self.pre.deinit();
            if (self.post) |*post_state| {
                post_state.deinit(self.pre.allocator);
            }
        }

        fn runTest(self: *Self) !void {
            if (self.post) |expected| {
                try self.upgrade();
                try expectEqualBeaconStates(expected, self.pre.cached_state.state.*);
            } else {
                self.upgrade() catch |err| {
                    if (err == error.SkipZigTest) {
                        return err;
                    }
                    return;
                };
                return error.ExpectedError;
            }
        }

        fn upgrade(self: *Self) !void {
            const cached_state = self.pre.cached_state;
            switch (target_fork) {
                .altair => try upgradeStateToAltair(self.pre.allocator, cached_state),
                .bellatrix => try upgradeStateToBellatrix(self.pre.allocator, cached_state),
                .capella => try upgradeStateToCapella(self.pre.allocator, cached_state),
                .deneb => try upgradeStateToDeneb(self.pre.allocator, cached_state),
                .electra => try upgradeStateToElectra(self.pre.allocator, cached_state),
                .fulu => try upgradeStateToFulu(self.pre.allocator, cached_state),
                else => unreachable,
            }
        }
    };
}

fn loadTargetFork(allocator: Allocator, dir: std.fs.Dir) !ForkSeq {
    var meta_file = try dir.openFile("meta.yaml", .{});
    defer meta_file.close();
    const contents = try meta_file.readToEndAlloc(allocator, 256);
    defer allocator.free(contents);

    const key = "fork: ";
    if (std.mem.indexOf(u8, contents, key)) |start| {
        const after_key = contents[start + key.len ..];
        const end = std.mem.indexOf(u8, after_key, "}") orelse return error.InvalidMetaFile;
        const fork_slice = after_key[0..end];
        if (fork_slice.len == 0) return error.InvalidMetaFile;
        return forkSeqByForkName(fork_slice);
    }

    return error.InvalidMetaFile;
}

fn previousFork(target: ForkSeq) ForkSeq {
    return switch (target) {
        .altair => .phase0,
        .bellatrix => .altair,
        .capella => .bellatrix,
        .deneb => .capella,
        .electra => .deneb,
        .fulu => .electra,
        else => @compileError("Unsupported fork transition for " ++ @tagName(target)),
    };
}
