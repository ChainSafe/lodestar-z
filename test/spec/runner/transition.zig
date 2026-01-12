const std = @import("std");
const Node = @import("persistent_merkle_tree").Node;
const ssz = @import("consensus_types");
const ForkSeq = @import("config").ForkSeq;
const Preset = @import("preset").Preset;
const state_transition = @import("state_transition");
const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;
const SignedBeaconBlock = state_transition.SignedBeaconBlock;
const BeaconState = state_transition.BeaconState;
const CachedBeaconState = state_transition.CachedBeaconState;
const test_case = @import("../test_case.zig");
const loadSszValue = test_case.loadSszSnappyValue;
const expectEqualBeaconStates = test_case.expectEqualBeaconStates;
const TestCaseUtils = test_case.TestCaseUtils;
const loadSignedBeaconBlock = test_case.loadSignedBeaconBlock;

pub fn Transition(comptime fork: ForkSeq) type {
    const tc_utils = TestCaseUtils(fork);

    return struct {
        pre: TestCachedBeaconState,
        post: ?*BeaconState,
        blocks: []SignedBeaconBlock,

        const Self = @This();

        pub fn execute(allocator: std.mem.Allocator, dir: std.fs.Dir) !void {
            var tc = try Self.init(allocator, dir);
            defer {
                tc.deinit();
                state_transition.deinitStateTransition();
            }
            try tc.runTest();
        }

        pub fn init(allocator: std.mem.Allocator, pool: *Node.Pool, dir: std.fs.Dir) !Self {
            var tc = Self{
                .pre = undefined,
                .post = undefined,
                .blocks = undefined,
            };

            // Load meta.yaml for blocks_count
            var meta_file = try dir.openFile("meta.yaml", .{});
            defer meta_file.close();
            const meta_content = try meta_file.readToEndAlloc(allocator, 1024);
            defer allocator.free(meta_content);
            const meta_content_one_line = std.mem.trim(u8, meta_content, " \n");
            // sample content of meta.yaml: {post_fork: electra, fork_epoch: 2, blocks_count: 96, fork_block: 62}
            // Parse YAML for fork_epoch (simplified; assume "fork_epoch: N")
            const fork_epoch = if (std.mem.indexOf(u8, meta_content_one_line, "fork_epoch: ")) |start| blk: {
                const str = meta_content_one_line[start + "fork_epoch: ".len ..];
                if (std.mem.indexOf(u8, str, ",")) |end| {
                    const num_str = str[0..end];
                    break :blk std.fmt.parseInt(usize, std.mem.trim(u8, num_str, " "), 10) catch 1;
                } else unreachable;
            } else unreachable;

            // block_count could be ended with "," or "}"
            // for example: {post_fork: altair, fork_epoch: 6, blocks_count: 2}
            const blocks_count = if (std.mem.indexOf(u8, meta_content_one_line, "blocks_count: ")) |start| blk: {
                const str = meta_content_one_line[start + "blocks_count: ".len ..];
                const end = std.mem.indexOf(u8, str, ",") orelse std.mem.indexOf(u8, str, "}") orelse unreachable;
                const num_str = str[0..end];
                break :blk std.fmt.parseInt(usize, std.mem.trim(u8, num_str, " "), 10) catch 1;
            } else unreachable;

            // fork_block is optional
            const fork_block_idx = if (std.mem.indexOf(u8, meta_content_one_line, "fork_block: ")) |start| blk: {
                const str = meta_content_one_line[start + "fork_block: ".len ..];
                if (std.mem.indexOf(u8, str, "}")) |end| {
                    const num_str = str[0..end];
                    break :blk std.fmt.parseInt(u64, std.mem.trim(u8, num_str, " "), 10) catch 0;
                } else unreachable;
            } else null;

            // load blocks
            tc.blocks = try allocator.alloc(SignedBeaconBlock, blocks_count);
            errdefer {
                for (tc.blocks) |block| {
                    test_case.deinitSignedBeaconBlock(block, allocator);
                }
                allocator.free(tc.blocks);
            }
            for (0..blocks_count) |i| {
                // The fork_block is the index in the test data of the last block of the initial fork.
                const fork_block = if (fork_block_idx == null or i > fork_block_idx.?) fork else tc_utils.getForkPre();

                const block_filename = try std.fmt.allocPrint(allocator, "blocks_{d}.ssz_snappy", .{i});
                defer allocator.free(block_filename);
                tc.blocks[i] = try loadSignedBeaconBlock(allocator, fork_block, dir, block_filename);
            }

            // load pre state
            tc.pre = try tc_utils.loadPreStatePreFork(allocator, pool, dir, fork_epoch);
            errdefer tc.pre.deinit();

            // load post state
            tc.post = try tc_utils.loadPostState(allocator, pool, dir);

            return tc;
        }

        pub fn deinit(self: *Self) void {
            for (self.blocks) |block| {
                test_case.deinitSignedBeaconBlock(block, self.pre.allocator);
            }
            self.pre.allocator.free(self.blocks);
            self.pre.deinit();
            if (self.post) |*post| {
                post.deinit(self.pre.allocator);
                self.pre.allocator.destroy(post);
            }
        }

        pub fn process(self: *Self) !*CachedBeaconState {
            var post_state: *CachedBeaconState = self.pre.cached_state;
            for (self.blocks, 0..) |beacon_block, i| {
                // if error, clean pre_state of stateTransition() function
                errdefer {
                    if (i > 0) {
                        post_state.deinit();
                        self.pre.allocator.destroy(post_state);
                    }
                }
                const new_post_state = try state_transition.state_transition.stateTransition(
                    self.pre.allocator,
                    post_state,
                    .{
                        .regular = beacon_block,
                    },
                    .{
                        .verify_state_root = true,
                        .verify_proposer = true,
                        .verify_signatures = true,
                    },
                );

                // don't deinit the initial pre state, we do it in deinit()
                const to_destroy = post_state;
                post_state = new_post_state;

                // clean post_state of stateTransition() function
                if (i > 0) {
                    to_destroy.deinit();
                    self.pre.allocator.destroy(to_destroy);
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
                try expectEqualBeaconStates(post, actual.state);
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
