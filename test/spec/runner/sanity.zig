const std = @import("std");
const ssz = @import("consensus_types");
const ForkSeq = @import("config").ForkSeq;
const Preset = @import("preset").Preset;
const state_transition = @import("state_transition");
const TestCachedBeaconStateAllForks = state_transition.test_utils.TestCachedBeaconStateAllForks;
const BeaconStateAllForks = state_transition.BeaconStateAllForks;
const CachedBeaconStateAllForks = state_transition.CachedBeaconStateAllForks;
const test_case = @import("../test_case.zig");
const loadSszValue = test_case.loadSszSnappyValue;
const expectEqualBeaconStates = test_case.expectEqualBeaconStates;
const TestCaseUtils = test_case.TestCaseUtils;
const loadBlsSetting = test_case.loadBlsSetting;
const BlsSetting = test_case.BlsSetting;

/// https://github.com/ethereum/consensus-specs/blob/master/tests/formats/sanity/README.md
pub const Handler = enum {
    /// https://github.com/ethereum/consensus-specs/blob/master/tests/formats/sanity/blocks.md
    blocks,
    /// https://github.com/ethereum/consensus-specs/blob/master/tests/formats/sanity/slots.md
    slots,

    pub fn suiteName(self: Handler) []const u8 {
        return @tagName(self) ++ "/pyspec_tests";
    }
};

pub fn SlotsTestCase(comptime fork: ForkSeq) type {
    const tc_utils = TestCaseUtils(fork);

    return struct {
        pre: TestCachedBeaconStateAllForks,
        post: BeaconStateAllForks,
        slots: u64,

        const Self = @This();

        pub fn execute(allocator: std.mem.Allocator, dir: std.fs.Dir) !void {
            var tc = try Self.init(allocator, dir);
            defer {
                tc.deinit();
                state_transition.deinitStateTransition();
            }

            try tc.runTest();
        }

        pub fn init(allocator: std.mem.Allocator, dir: std.fs.Dir) !Self {
            var tc = Self{
                .pre = undefined,
                .post = undefined,
                .slots = 0,
            };

            // load pre state
            tc.pre = try tc_utils.loadPreState(allocator, dir);
            errdefer tc.pre.deinit();

            // load post state
            tc.post = try tc_utils.loadPostState(allocator, dir) orelse
                return error.PostStateNotFound;

            // load slots
            var slots_file = try dir.openFile("slots.yaml", .{});
            defer slots_file.close();
            const slots_content = try slots_file.readToEndAlloc(allocator, 1024);
            defer allocator.free(slots_content);
            // Parse YAML for slots (simplified; assume single value)
            tc.slots = std.fmt.parseInt(u64, std.mem.trim(u8, slots_content, "... \n"), 10) catch 0;

            return tc;
        }

        pub fn deinit(self: *Self) void {
            self.pre.deinit();
            self.post.deinit(self.pre.allocator);
        }

        pub fn process(self: *Self) !void {
            try state_transition.state_transition.processSlotsWithTransientCache(
                self.pre.allocator,
                self.pre.cached_state,
                self.pre.cached_state.state.slot() + self.slots,
                undefined,
            );
        }

        pub fn runTest(self: *Self) !void {
            try self.process();
            try expectEqualBeaconStates(self.post, self.pre.cached_state.state.*);
        }
    };
}

pub fn BlocksTestCase(comptime fork: ForkSeq) type {
    const ForkTypes = @field(ssz, fork.name());
    const tc_utils = TestCaseUtils(fork);
    const SignedBeaconBlock = @field(ForkTypes, "SignedBeaconBlock");

    return struct {
        pre: TestCachedBeaconStateAllForks,
        // a null post state means the test is expected to fail
        post: ?BeaconStateAllForks,
        blocks: []SignedBeaconBlock.Type,
        bls_setting: BlsSetting,

        const Self = @This();

        pub fn execute(allocator: std.mem.Allocator, dir: std.fs.Dir) !void {
            var tc = try Self.init(allocator, dir);
            defer {
                tc.deinit();
                state_transition.deinitStateTransition();
            }

            try tc.runTest();
        }

        pub fn init(allocator: std.mem.Allocator, dir: std.fs.Dir) !Self {
            var tc = Self{
                .pre = undefined,
                .post = undefined,
                .blocks = undefined,
                .bls_setting = loadBlsSetting(allocator, dir),
            };

            // load pre state
            tc.pre = try tc_utils.loadPreState(allocator, dir);
            errdefer tc.pre.deinit();

            // load post state
            tc.post = try tc_utils.loadPostState(allocator, dir);

            // Load meta.yaml for blocks_count
            var meta_file = try dir.openFile("meta.yaml", .{});
            defer meta_file.close();
            const meta_content = try meta_file.readToEndAlloc(allocator, 1024);
            defer allocator.free(meta_content);
            // Parse YAML for blocks_count (simplified; assume "blocks_count: N")
            const blocks_count_str = std.mem.trim(u8, meta_content, " \n{}");
            const blocks_count = if (std.mem.indexOf(u8, blocks_count_str, "blocks_count: ")) |start| blk: {
                const num_start = start + "blocks_count: ".len;
                const num_str = blocks_count_str[num_start..];
                const end = std.mem.indexOf(u8, num_str, ",") orelse num_str.len;
                break :blk std.fmt.parseInt(usize, std.mem.trim(u8, num_str[0..end], " "), 10) catch 1;
            } else 1;

            // load blocks
            tc.blocks = try allocator.alloc(SignedBeaconBlock.Type, blocks_count);
            errdefer {
                for (tc.blocks) |*block| {
                    SignedBeaconBlock.deinit(allocator, block);
                }
                allocator.free(tc.blocks);
            }
            for (tc.blocks, 0..) |*block, i| {
                block.* = SignedBeaconBlock.default_value;
                const block_filename = try std.fmt.allocPrint(allocator, "blocks_{d}.ssz_snappy", .{i});
                defer allocator.free(block_filename);
                try loadSszValue(SignedBeaconBlock, allocator, dir, block_filename, block);
            }

            return tc;
        }

        pub fn deinit(self: *Self) void {
            for (self.blocks) |*block| {
                if (comptime @hasDecl(SignedBeaconBlock, "deinit")) {
                    SignedBeaconBlock.deinit(self.pre.allocator, block);
                }
            }
            self.pre.allocator.free(self.blocks);
            self.pre.deinit();
            if (self.post) |*post| {
                post.deinit(self.pre.allocator);
            }
        }

        pub fn process(self: *Self) !*CachedBeaconStateAllForks {
            const verify = self.bls_setting.verify();
            var post_state: *CachedBeaconStateAllForks = self.pre.cached_state;
            for (self.blocks, 0..) |*block, i| {
                const signed_block = @unionInit(state_transition.SignedBeaconBlock, @tagName(fork), block);
                {
                    // if error, clean pre_state of stateTransition() function
                    errdefer {
                        if (i > 0) {
                            post_state.deinit();
                            self.pre.allocator.destroy(post_state);
                        }
                    }
                    const new_post_state = try state_transition.state_transition.stateTransition(self.pre.allocator, post_state, .{
                        .regular = signed_block,
                    }, .{
                        .verify_signatures = verify,
                        .verify_proposer = verify,
                    });

                    // don't deinit the initial pre state, we do it in deinit()
                    const to_destroy = post_state;
                    post_state = new_post_state;

                    // clean post_state of stateTransition() function
                    if (i > 0) {
                        to_destroy.deinit();
                        self.pre.allocator.destroy(to_destroy);
                    }
                }
            }

            return post_state;
        }

        pub fn runTest(self: *Self) !void {
            if (self.post) |post| {
                const actual = try self.process();
                defer {
                    actual.deinit();
                    self.pre.allocator.destroy(actual);
                }
                try expectEqualBeaconStates(post, actual.state.*);
            } else {
                _ = self.process() catch |err| {
                    if (err == error.SkipZigTest) {
                        return err;
                    }
                    return;
                };
                return error.ExpectedError;
            }
        }
    };
}
