const std = @import("std");
const ssz = @import("consensus_types");
const ForkSeq = @import("config").ForkSeq;
const Preset = @import("preset").Preset;
const state_transition = @import("state_transition");
const TestCachedBeaconStateAllForks = state_transition.test_utils.TestCachedBeaconStateAllForks;
const SignedBeaconBlock = state_transition.SignedBeaconBlock;
const BeaconStateAllForks = state_transition.BeaconStateAllForks;
const CachedBeaconStateAllForks = state_transition.CachedBeaconStateAllForks;
const test_case = @import("../test_case.zig");
const loadSszValue = test_case.loadSszSnappyValue;
const expectEqualBeaconStates = test_case.expectEqualBeaconStates;
const expectEqualBlindedBeaconStates = test_case.expectEqualBlindedBeaconStates;
const TestCaseUtils = test_case.TestCaseUtils;
const loadSignedBeaconBlock = test_case.loadSignedBeaconBlock;
const beaconBlockToBlinded = test_case.beaconBlockToBlinded;
const loadBlsSetting = test_case.loadBlsSetting;
const BlsSetting = test_case.BlsSetting;

pub fn Transition(comptime fork: ForkSeq) type {
    const tc_utils = TestCaseUtils(fork);

    return struct {
        pre: TestCachedBeaconStateAllForks,
        post: ?BeaconStateAllForks,
        blocks: []SignedBeaconBlock,
        bls_setting: BlsSetting,
        dir: std.fs.Dir,

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
                .dir = dir,
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
            tc.pre = try tc_utils.loadPreStatePreFork(allocator, dir, fork_epoch);
            errdefer tc.pre.deinit();

            // load post state
            tc.post = try tc_utils.loadPostState(allocator, dir);

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
            }
        }

        pub fn process(self: *Self) !*CachedBeaconStateAllForks {
            var post_state: *CachedBeaconStateAllForks = self.pre.cached_state;
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
                        .verify_proposer = false,
                        .verify_signatures = false,
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

        pub fn processBlinded(self: *Self, pre_state: *CachedBeaconStateAllForks) !*CachedBeaconStateAllForks {
            var post_state: *CachedBeaconStateAllForks = pre_state;

            // Note: runTest() already ensures all blocks are Capella+ and no fork transitions
            for (self.blocks, 0..) |beacon_block, i| {
                switch (beacon_block) {
                    .capella => |b| {
                        var regular_body_root: [32]u8 = undefined;
                        try ssz.capella.BeaconBlockBody.hashTreeRoot(self.pre.allocator, &b.message.body, &regular_body_root);

                        const blinded_block = ssz.capella.SignedBlindedBeaconBlock.Type{
                            .message = try beaconBlockToBlinded(.capella).convert(self.pre.allocator, &b.message),
                            .signature = b.signature,
                        };
                        defer ssz.capella.ExecutionPayloadHeader.getFieldType("extra_data").deinit(self.pre.allocator, @constCast(&blinded_block.message.body.execution_payload_header.extra_data));

                        post_state = try self.processBlindedBlock(post_state, .{ .capella = &blinded_block }, i, regular_body_root);
                    },
                    .deneb => |b| {
                        var regular_body_root: [32]u8 = undefined;
                        try ssz.deneb.BeaconBlockBody.hashTreeRoot(self.pre.allocator, &b.message.body, &regular_body_root);

                        const blinded_block = ssz.deneb.SignedBlindedBeaconBlock.Type{
                            .message = try beaconBlockToBlinded(.deneb).convert(self.pre.allocator, &b.message),
                            .signature = b.signature,
                        };
                        defer ssz.deneb.ExecutionPayloadHeader.getFieldType("extra_data").deinit(self.pre.allocator, @constCast(&blinded_block.message.body.execution_payload_header.extra_data));

                        post_state = try self.processBlindedBlock(post_state, .{ .deneb = &blinded_block }, i, regular_body_root);
                    },
                    .electra => |b| {
                        var regular_body_root: [32]u8 = undefined;
                        try ssz.electra.BeaconBlockBody.hashTreeRoot(self.pre.allocator, &b.message.body, &regular_body_root);

                        const blinded_block = ssz.electra.SignedBlindedBeaconBlock.Type{
                            .message = try beaconBlockToBlinded(.electra).convert(self.pre.allocator, &b.message),
                            .signature = b.signature,
                        };
                        defer {
                            ssz.electra.BeaconBlockBody.getFieldType("execution_requests").deinit(self.pre.allocator, @constCast(&blinded_block.message.body.execution_requests));
                            ssz.electra.ExecutionPayloadHeader.getFieldType("extra_data").deinit(self.pre.allocator, @constCast(&blinded_block.message.body.execution_payload_header.extra_data));
                        }

                        post_state = try self.processBlindedBlock(post_state, .{ .electra = &blinded_block }, i, regular_body_root);
                    },
                    else => return error.UnsupportedForkForBlindedBlocks,
                }
            }

            return post_state;
        }

        fn processBlindedBlock(
            self: *Self,
            post_state: *CachedBeaconStateAllForks,
            blinded_block: state_transition.SignedBlindedBeaconBlock,
            block_index: usize,
            regular_body_root: [32]u8,
        ) !*CachedBeaconStateAllForks {
            errdefer {
                if (block_index > 0) {
                    post_state.deinit();
                    self.pre.allocator.destroy(post_state);
                }
            }

            const new_post_state = try state_transition.state_transition.stateTransition(
                self.pre.allocator,
                post_state,
                .{ .blinded = blinded_block },
                .{
                    .verify_state_root = true,
                    .verify_proposer = false,
                    .verify_signatures = false,
                },
            );

            const to_destroy = post_state;
            const result = new_post_state;

            // Restore regular body_root for multi-block support
            result.state.latestBlockHeader().body_root = regular_body_root;

            if (block_index > 0) {
                to_destroy.deinit();
                self.pre.allocator.destroy(to_destroy);
            }

            return result;
        }

        pub fn runTest(self: *Self) !void {
            if (self.post) |post| {
                // Test regular blocks
                const actual = try self.process();
                defer {
                    actual.deinit();
                    self.pre.allocator.destroy(actual);
                }
                try expectEqualBeaconStates(post, actual.state.*);

                // Test blinded blocks for Capella+ (if BLS verification is not required)
                if (comptime fork.gte(.capella) and fork.lte(.electra)) {
                    if (!self.bls_setting.verify()) {
                        const pre_state_fork = self.pre.cached_state.state.forkSeq();

                        // Check if blocks cross fork boundaries
                        // Skip blinded testing for cross-fork scenarios (e.g., Deneb state → Electra blocks)
                        var has_fork_transition = false;
                        for (self.blocks) |block| {
                            const block_fork_tag = std.meta.activeTag(block);
                            const block_fork: ForkSeq = @enumFromInt(@intFromEnum(block_fork_tag));
                            if (block_fork != pre_state_fork) {
                                has_fork_transition = true;
                                break;
                            }
                        }

                        // Only test same-fork scenarios with Capella+
                        if (!has_fork_transition and pre_state_fork.gte(.capella)) {
                            var blinded_pre = try tc_utils.loadPreStatePreFork(self.pre.allocator, self.dir, @intCast(self.pre.cached_state.state.fork().epoch));
                            defer blinded_pre.deinit();

                            const blinded_actual = try self.processBlinded(blinded_pre.cached_state);
                            defer {
                                blinded_actual.deinit();
                                self.pre.allocator.destroy(blinded_actual);
                            }
                            try expectEqualBlindedBeaconStates(post, blinded_actual.state.*);
                        }
                    }
                }
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
