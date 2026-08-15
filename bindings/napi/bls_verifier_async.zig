const std = @import("std");
const builtin = @import("builtin");
const zapi = @import("zapi:zapi");
const js = zapi.js;
const napi = zapi.napi;
const bls = @import("bls");

const blst_bindings = @import("./blst.zig");
const common = @import("./bls_verifier_common.zig");
const pubkeys = @import("./pubkeys.zig");

const max_verify_sets = common.max_verify_sets;
const max_same_message_sets = common.max_same_message_sets;
const max_indices_per_set = common.max_indices_per_set;
const SignatureSetBatch = common.SignatureSetBatch;
const SameMessageSignatureSetBatch = common.SameMessageSignatureSetBatch;
const SetType = common.SetType;
const CommonSet = common.CommonSet;
const IndexedSet = common.IndexedSet;
const AggregateSet = common.AggregateSet;
const SingleSet = common.SingleSet;
const SameMessageSet = common.SameMessageSet;
const uint32 = common.uint32;

var gpa: std.heap.DebugAllocator(.{}) = .init;
const allocator = if (builtin.mode == .Debug) gpa.allocator() else std.heap.c_allocator;

const signature_size = bls.Signature.COMPRESS_SIZE;
const public_key_size = bls.PublicKey.COMPRESS_SIZE;
const max_async_envs = 64;

const OwnedBytes = struct {
    bytes: [signature_size]u8 = undefined,
    has_valid_length: bool,

    fn fromSlice(bytes_slice: []const u8) OwnedBytes {
        var owned = OwnedBytes{ .has_valid_length = bytes_slice.len == signature_size };
        if (owned.has_valid_length) @memcpy(&owned.bytes, bytes_slice);
        return owned;
    }

    fn slice(self: *const OwnedBytes) []const u8 {
        return if (self.has_valid_length) &self.bytes else &.{};
    }
};

const OwnedPublicKeyBytes = struct {
    bytes: [public_key_size]u8 = undefined,
    has_valid_length: bool,

    fn fromSlice(bytes_slice: []const u8) OwnedPublicKeyBytes {
        var owned = OwnedPublicKeyBytes{ .has_valid_length = bytes_slice.len == public_key_size };
        if (owned.has_valid_length) @memcpy(&owned.bytes, bytes_slice);
        return owned;
    }

    fn slice(self: *const OwnedPublicKeyBytes) []const u8 {
        return if (self.has_valid_length) &self.bytes else &.{};
    }
};

const OwnedPublicKey = union(enum) {
    indexed: u32,
    aggregate: []u32,
    single: OwnedPublicKeyBytes,
};

const OwnedSignatureSet = struct {
    public_key: OwnedPublicKey,
    message: [32]u8,
    signature: OwnedBytes,

    fn deinit(self: *OwnedSignatureSet) void {
        switch (self.public_key) {
            .aggregate => |indices| allocator.free(indices),
            else => {},
        }
    }
};

const OwnedSameMessageSet = struct {
    index: u32,
    signature: OwnedBytes,
};

const GeneralJob = struct {
    sets: []OwnedSignatureSet,
    result: bool = false,
};

const SameMessageJob = struct {
    sets: []OwnedSameMessageSet,
    message: [32]u8,
    results: []bool,
};

const JobData = union(enum) {
    general: GeneralJob,
    same_message: SameMessageJob,
};

const CompletionPort = struct {
    env: napi.c.napi_env,
    io: std.Io,
    tsfn: napi.c.napi_threadsafe_function,
    mutex: std.Io.Mutex = .init,
    native_refs: std.atomic.Value(usize) = std.atomic.Value(usize).init(1),
    active_jobs: usize = 0,
    referenced: bool = false,
    closing: bool = false,

    fn create(env: napi.Env) !*CompletionPort {
        const self = try allocator.create(CompletionPort);
        self.* = .{
            .env = env.env,
            .io = js.io(),
            .tsfn = undefined,
        };

        const name = env.createStringUtf8("blsVerifierCompletion") catch |err| {
            allocator.destroy(self);
            return err;
        };
        napi.status.check(napi.c.napi_create_threadsafe_function(
            env.env,
            null,
            null,
            name.value,
            bls.ThreadPool.MAX_ASYNC_ROOTS,
            1,
            self,
            completionPortFinalize,
            self,
            completeAsyncJob,
            &self.tsfn,
        )) catch |err| {
            allocator.destroy(self);
            return err;
        };
        errdefer napi.status.check(napi.c.napi_release_threadsafe_function(
            self.tsfn,
            napi.c.napi_tsfn_abort,
        )) catch {};

        try napi.status.check(napi.c.napi_unref_threadsafe_function(env.env, self.tsfn));
        try env.addEnvCleanupHook(CompletionPort, self, cleanupEnv);
        return self;
    }

    fn cleanupEnv(self: *CompletionPort) void {
        async_state.deinitPort(self);
    }

    fn beginJob(self: *CompletionPort, env: napi.Env) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        if (self.closing) return error.CompletionPortClosing;
        if (self.active_jobs >= bls.ThreadPool.MAX_ASYNC_ROOTS) return error.AsyncQueueFull;

        if (!self.referenced) {
            try napi.status.check(napi.c.napi_ref_threadsafe_function(env.env, self.tsfn));
            self.referenced = true;
        }
        errdefer if (self.active_jobs == 0 and self.referenced) {
            napi.status.check(napi.c.napi_unref_threadsafe_function(env.env, self.tsfn)) catch {};
            self.referenced = false;
        };

        _ = self.native_refs.fetchAdd(1, .monotonic);
        self.active_jobs += 1;
    }

    fn cancelJobOnLoop(self: *CompletionPort, env: napi.Env) void {
        self.finishJobOnLoop(env);
        self.releaseNative();
    }

    fn finishJobOnLoop(self: *CompletionPort, env: napi.Env) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        std.debug.assert(self.active_jobs > 0);
        self.active_jobs -= 1;
        if (self.active_jobs == 0 and self.referenced and !self.closing) {
            napi.status.check(napi.c.napi_unref_threadsafe_function(env.env, self.tsfn)) catch {};
            self.referenced = false;
        }
    }

    fn finishJobWithoutJs(self: *CompletionPort) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        std.debug.assert(self.active_jobs > 0);
        self.active_jobs -= 1;
    }

    fn send(self: *CompletionPort, job: *AsyncVerifyJob) ?napi.c.napi_status {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        if (self.closing) return null;
        return napi.c.napi_call_threadsafe_function(
            self.tsfn,
            job,
            napi.c.napi_tsfn_nonblocking,
        );
    }

    fn close(self: *CompletionPort) void {
        self.mutex.lockUncancelable(self.io);
        std.debug.assert(!self.closing);
        self.closing = true;
        self.referenced = false;
        self.mutex.unlock(self.io);

        napi.status.check(napi.c.napi_release_threadsafe_function(
            self.tsfn,
            napi.c.napi_tsfn_abort,
        )) catch {};
    }

    fn releaseNative(self: *CompletionPort) void {
        if (self.native_refs.fetchSub(1, .acq_rel) == 1) allocator.destroy(self);
    }
};

const AsyncState = struct {
    mutex: std.Io.Mutex = .init,
    ports: [max_async_envs]?*CompletionPort = .{null} ** max_async_envs,

    fn getOrCreatePort(self: *AsyncState, env: napi.Env) !*CompletionPort {
        const io = js.io();
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        var free_slot: ?usize = null;
        for (&self.ports, 0..) |port, i| {
            if (port) |existing| {
                if (existing.env == env.env) return existing;
            } else if (free_slot == null) {
                free_slot = i;
            }
        }

        const slot = free_slot orelse return error.TooManyNapiEnvironments;
        const port = try CompletionPort.create(env);
        self.ports[slot] = port;
        return port;
    }

    fn deinitPort(self: *AsyncState, port: *CompletionPort) void {
        const io = port.io;
        self.mutex.lockUncancelable(io);
        for (&self.ports) |*entry| {
            if (entry.* == port) {
                entry.* = null;
                break;
            }
        }
        self.mutex.unlock(io);

        port.close();
    }
};

var async_state: AsyncState = .{};

const AsyncVerifyJob = struct {
    work: bls.ThreadPool.WorkItem = .{
        .exec_fn = execute,
        .finish_fn = finish,
    },
    io: std.Io,
    pool: *bls.ThreadPool,
    port: *CompletionPort,
    deferred: napi.Deferred,
    data: JobData,
    err: ?anyerror = null,

    fn execute(work: *bls.ThreadPool.WorkItem) void {
        const self: *AsyncVerifyJob = @fieldParentPtr("work", work);
        switch (self.data) {
            .general => |*general| self.executeGeneral(general) catch |err| {
                self.err = err;
            },
            .same_message => |*same_message| self.executeSameMessage(same_message) catch |err| {
                self.err = err;
            },
        }
    }

    fn executeGeneral(self: *AsyncVerifyJob, general: *GeneralJob) !void {
        if (general.sets.len == 0) {
            general.result = false;
            return;
        }

        var batch: SignatureSetBatch = .{};
        for (general.sets) |*set| {
            const public_key: bls.PublicKey = switch (set.public_key) {
                .indexed => |index| blk: {
                    if (!pubkeys.state.initialized) return error.PubkeyIndexNotInitialized;
                    break :blk pubkeys.state.cache.getPubkey(self.io, index) orelse
                        return error.PubkeyIndexNotFound;
                },
                .aggregate => |indices| blk: {
                    if (!pubkeys.state.initialized) return error.PubkeyIndexNotInitialized;
                    break :blk pubkeys.state.cache.aggregateIndices(self.io, u32, indices) catch |err| switch (err) {
                        error.InvalidIndex => return error.PubkeyIndexNotFound,
                        error.InvalidLength => return error.EmptyIndices,
                    };
                },
                .single => |*bytes| bls.PublicKey.keyValidate(bytes.slice()) catch {
                    general.result = false;
                    return;
                },
            };

            if (!batch.append(&public_key, &set.message, set.signature.slice())) {
                general.result = false;
                return;
            }
        }

        general.result = try batch.verify(self.io, self.pool);
    }

    fn executeSameMessage(self: *AsyncVerifyJob, same_message: *SameMessageJob) !void {
        if (same_message.sets.len == 0) return;
        if (!pubkeys.state.initialized) return error.PubkeyIndexNotInitialized;

        var batch: SameMessageSignatureSetBatch = .{};
        for (same_message.sets) |*set| {
            const public_key = pubkeys.state.cache.getPubkey(self.io, set.index) orelse
                return error.PubkeyIndexNotFound;
            batch.append(&public_key, set.signature.slice());
        }

        try batch.verify(self.io, self.pool, &same_message.message, same_message.results);
    }

    fn finish(work: *bls.ThreadPool.WorkItem) void {
        const self: *AsyncVerifyJob = @fieldParentPtr("work", work);
        const port = self.port;

        // Serialize calls with close(). Once close marks the port, no pool
        // worker may touch the TSFN handle again.
        const call_status = port.send(self) orelse {
            port.finishJobWithoutJs();
            self.destroy();
            port.releaseNative();
            return;
        };

        if (call_status != napi.c.napi_ok) {
            port.finishJobWithoutJs();
            self.destroy();
            port.releaseNative();
            return;
        }
    }

    fn complete(self: *AsyncVerifyJob, env: napi.Env) void {
        defer self.destroy();
        self.settle(env) catch {
            rejectWithError(env, self.deferred, "blsVerifier", "InternalError") catch {};
        };
    }

    fn settle(self: *AsyncVerifyJob, env: napi.Env) !void {
        if (self.err) |err| {
            return rejectWithError(env, self.deferred, "blsVerifier", @errorName(err));
        }

        switch (self.data) {
            .general => |general| try self.deferred.resolve(try env.getBoolean(general.result)),
            .same_message => |same_message| {
                const results = try env.createArrayWithLength(same_message.results.len);
                for (same_message.results, 0..) |result, i| {
                    try results.setElement(@intCast(i), try env.getBoolean(result));
                }
                try self.deferred.resolve(results);
            },
        }
    }

    fn destroy(self: *AsyncVerifyJob) void {
        switch (self.data) {
            .general => |general| {
                for (general.sets) |*set| set.deinit();
                allocator.free(general.sets);
            },
            .same_message => |same_message| {
                allocator.free(same_message.sets);
                allocator.free(same_message.results);
            },
        }
        allocator.destroy(self);
    }
};

fn completionPortFinalize(
    _: napi.c.napi_env,
    raw_data: ?*anyopaque,
    _: ?*anyopaque,
) callconv(.c) void {
    const port: *CompletionPort = @ptrCast(@alignCast(raw_data orelse return));
    port.releaseNative();
}

fn completeAsyncJob(
    raw_env: napi.c.napi_env,
    _: napi.c.napi_value,
    raw_context: ?*anyopaque,
    raw_data: ?*anyopaque,
) callconv(.c) void {
    const port: *CompletionPort = @ptrCast(@alignCast(raw_context orelse return));
    const job: *AsyncVerifyJob = @ptrCast(@alignCast(raw_data orelse return));

    if (raw_env == null) {
        port.finishJobWithoutJs();
        job.destroy();
        port.releaseNative();
        return;
    }

    const env = napi.Env{ .env = raw_env };
    port.finishJobOnLoop(env);
    job.complete(env);
    port.releaseNative();
}

fn snapshotGeneralSets(sets: js.Array) ![]OwnedSignatureSet {
    const count = try sets.length();
    if (count > max_verify_sets) return error.TooManySets;

    const owned = try allocator.alloc(OwnedSignatureSet, count);
    var initialized: usize = 0;
    errdefer {
        for (owned[0..initialized]) |*set| set.deinit();
        allocator.free(owned);
    }

    for (0..count) |i| {
        const value = try sets.get(@intCast(i));
        const set = try (try value.asObject(CommonSet)).get();
        const set_type: SetType = switch (try uint32(set.type)) {
            @intFromEnum(SetType.indexed) => .indexed,
            @intFromEnum(SetType.aggregate) => .aggregate,
            @intFromEnum(SetType.single) => .single,
            else => return error.InvalidSetType,
        };

        const message = try set.message.toSlice();
        if (message.len != 32) return error.InvalidMessageLength;
        const signature = try set.signature.toSlice();

        const public_key: OwnedPublicKey = switch (set_type) {
            .indexed => blk: {
                const indexed = try (try value.asObject(IndexedSet)).get();
                break :blk .{ .indexed = try uint32(indexed.index) };
            },
            .aggregate => blk: {
                const aggregate = try (try value.asObject(AggregateSet)).get();
                const indices = try aggregate.indices.toSlice();
                if (indices.len == 0) return error.EmptyIndices;
                if (indices.len > max_indices_per_set) return error.TooManyIndices;

                const indices_copy = try allocator.dupe(u32, indices);
                break :blk .{ .aggregate = indices_copy };
            },
            .single => blk: {
                const single = try (try value.asObject(SingleSet)).get();
                break :blk .{ .single = OwnedPublicKeyBytes.fromSlice(try single.pubkey.toSlice()) };
            },
        };

        owned[i] = .{
            .public_key = public_key,
            .message = message[0..32].*,
            .signature = OwnedBytes.fromSlice(signature),
        };
        initialized += 1;
    }

    return owned;
}

fn snapshotSameMessageSets(sets: js.Array) ![]OwnedSameMessageSet {
    const count = try sets.length();
    if (count > max_same_message_sets) return error.TooManySets;

    const owned = try allocator.alloc(OwnedSameMessageSet, count);
    errdefer allocator.free(owned);

    for (0..count) |i| {
        const value = try sets.get(@intCast(i));
        const set = try (try value.asObject(SameMessageSet)).get();
        owned[i] = .{
            .index = try uint32(set.index),
            .signature = OwnedBytes.fromSlice(try set.signature.toSlice()),
        };
    }
    return owned;
}

fn queueAsyncJob(job: *AsyncVerifyJob, critical: ?js.Boolean) !js.Value {
    const env = js.env();
    const undefined_value = try env.getUndefined();
    errdefer job.destroy();

    job.deferred = try env.createPromise();
    errdefer job.deferred.resolve(undefined_value) catch {};

    try job.port.beginJob(env);
    errdefer job.port.cancelJobOnLoop(env);

    try job.pool.submitRoot(
        job.io,
        &job.work,
        if (critical) |value| if (try value.toBool()) .critical else .normal else .normal,
    );
    return .{ .val = job.deferred.getPromise() };
}

/// Verify indexed, aggregate, and raw-pubkey signature sets without blocking
/// the JavaScript event loop. Input bytes are snapshotted before returning.
pub fn verifySignatureSets(sets: js.Array, critical: ?js.Boolean) !js.Value {
    const pool = blst_bindings.state.thread_pool orelse return error.ThreadPoolNotInitialized;
    const owned_sets = try snapshotGeneralSets(sets);
    var owns_sets = true;
    errdefer if (owns_sets) {
        for (owned_sets) |*set| set.deinit();
        allocator.free(owned_sets);
    };

    const port = try async_state.getOrCreatePort(js.env());
    const job = try allocator.create(AsyncVerifyJob);
    job.* = .{
        .io = js.io(),
        .pool = pool,
        .port = port,
        .deferred = undefined,
        .data = .{ .general = .{ .sets = owned_sets } },
    };
    owns_sets = false;
    return queueAsyncJob(job, critical);
}

/// Verify indexed signatures sharing one message without blocking the
/// JavaScript event loop. Result ordering matches input ordering.
pub fn verifySignatureSetsSameMessage(
    sets: js.Array,
    message: js.Uint8Array,
    critical: ?js.Boolean,
) !js.Value {
    const pool = blst_bindings.state.thread_pool orelse return error.ThreadPoolNotInitialized;
    const message_slice = try message.toSlice();
    if (message_slice.len != 32) return error.InvalidMessageLength;

    const owned_sets = try snapshotSameMessageSets(sets);
    var owns_sets = true;
    errdefer if (owns_sets) allocator.free(owned_sets);
    const results = try allocator.alloc(bool, owned_sets.len);
    var owns_results = true;
    errdefer if (owns_results) allocator.free(results);

    const port = try async_state.getOrCreatePort(js.env());
    const job = try allocator.create(AsyncVerifyJob);
    job.* = .{
        .io = js.io(),
        .pool = pool,
        .port = port,
        .deferred = undefined,
        .data = .{ .same_message = .{
            .sets = owned_sets,
            .message = message_slice[0..32].*,
            .results = results,
        } },
    };
    owns_sets = false;
    owns_results = false;
    return queueAsyncJob(job, critical);
}

fn rejectWithError(env: napi.Env, deferred: napi.Deferred, where: []const u8, code: []const u8) !void {
    var msg_buf: [256]u8 = undefined;
    const msg = std.fmt.bufPrint(&msg_buf, "{s}: {s}", .{ where, code }) catch code;

    const code_value = try env.createStringUtf8(code);
    const message_value = try env.createStringUtf8(msg);
    const error_value = try env.createError(code_value, message_value);
    try deferred.reject(error_value);
}
