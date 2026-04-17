//! StateWorkService — bounded worker for expensive state-transition compute.
//!
//! The main thread remains the single owner of chain state and import side
//! effects. This service only executes the expensive STFN step and returns an
//! owned completion object for the main thread to commit later.

const std = @import("std");
const Allocator = std.mem.Allocator;
const BlsThreadPool = @import("bls").ThreadPool;
const regen_mod = @import("regen/root.zig");
const StateGraphGate = regen_mod.StateGraphGate;
const StateRegen = regen_mod.StateRegen;

const blocks = @import("blocks/root.zig");
const PlannedBlockImport = blocks.pipeline.PlannedBlockImport;
const StateTransitionJob = blocks.pipeline.StateTransitionJob;
const PreparedBlockImport = blocks.pipeline.PreparedBlockImport;
const BlockImportError = blocks.BlockImportError;

pub const DEFAULT_MAX_PENDING_BLOCK_IMPORTS: u16 = 32;

pub const MetricsSnapshot = struct {
    pending_jobs: u64 = 0,
    completed_jobs: u64 = 0,
    active_jobs: u64 = 0,
    submitted_total: u64 = 0,
    rejected_total: u64 = 0,
    success_total: u64 = 0,
    failure_total: u64 = 0,
    execution_time_ns_total: u64 = 0,
    last_execution_time_ns: u64 = 0,
};

pub const CompletedBlockImport = union(enum) {
    success: PreparedBlockImport,
    failure: struct {
        planned: PlannedBlockImport,
        err: BlockImportError,
    },

    pub fn deinit(self: *CompletedBlockImport, allocator: Allocator) void {
        switch (self.*) {
            .success => |*prepared| prepared.deinit(allocator),
            .failure => |*failure| failure.planned.deinit(allocator),
        }
        self.* = undefined;
    }
};

pub const StateWorkService = struct {
    allocator: Allocator,
    io: std.Io,
    state_regen: *StateRegen,
    state_graph_gate: *StateGraphGate,
    block_bls_thread_pool: ?*BlsThreadPool,
    max_pending_block_imports: usize,

    mutex: std.Io.Mutex = .init,
    cond: std.Io.Condition = .init,
    pending_block_imports: std.ArrayListUnmanaged(StateTransitionJob) = .empty,
    completed_block_imports: std.ArrayListUnmanaged(CompletedBlockImport) = .empty,
    active_block_imports: usize = 0,
    submitted_total: u64 = 0,
    rejected_total: u64 = 0,
    success_total: u64 = 0,
    failure_total: u64 = 0,
    execution_time_ns_total: u64 = 0,
    last_execution_time_ns: u64 = 0,
    shutdown_requested: bool = false,
    thread: ?std.Thread = null,

    pub const WaitResult = enum {
        completed,
        idle,
        shutdown,
    };

    pub fn init(
        allocator: Allocator,
        io: std.Io,
        state_regen: *StateRegen,
        state_graph_gate: *StateGraphGate,
        block_bls_thread_pool: ?*BlsThreadPool,
        max_pending_block_imports: u16,
    ) !*StateWorkService {
        const service = try allocator.create(StateWorkService);
        errdefer allocator.destroy(service);

        service.* = .{
            .allocator = allocator,
            .io = io,
            .state_regen = state_regen,
            .state_graph_gate = state_graph_gate,
            .block_bls_thread_pool = block_bls_thread_pool,
            .max_pending_block_imports = max_pending_block_imports,
        };

        service.thread = try std.Thread.spawn(.{}, workerMain, .{service});
        return service;
    }

    pub fn deinit(self: *StateWorkService) void {
        self.mutex.lockUncancelable(self.io);
        self.shutdown_requested = true;
        self.cond.signal(self.io);
        self.mutex.unlock(self.io);

        if (self.thread) |thread| {
            thread.join();
        }

        for (self.pending_block_imports.items) |*job| {
            job.deinit(self.allocator, self.state_regen);
        }
        self.pending_block_imports.deinit(self.allocator);

        for (self.completed_block_imports.items) |*completed| {
            completed.deinit(self.allocator);
        }
        self.completed_block_imports.deinit(self.allocator);

        self.allocator.destroy(self);
    }

    pub fn canAcceptBlockImport(self: *StateWorkService) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.pending_block_imports.items.len +
            self.completed_block_imports.items.len +
            self.active_block_imports < self.max_pending_block_imports;
    }

    pub fn submitBlockImport(self: *StateWorkService, job: StateTransitionJob) !bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        if (self.shutdown_requested) {
            self.rejected_total += 1;
            return false;
        }
        if (self.pending_block_imports.items.len +
            self.completed_block_imports.items.len +
            self.active_block_imports >= self.max_pending_block_imports)
        {
            self.rejected_total += 1;
            return false;
        }

        try self.pending_block_imports.append(self.allocator, job);
        self.submitted_total += 1;
        self.cond.signal(self.io);
        return true;
    }

    pub fn popCompletedBlockImport(self: *StateWorkService) ?CompletedBlockImport {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        if (self.completed_block_imports.items.len == 0) return null;
        return self.completed_block_imports.orderedRemove(0);
    }

    pub fn waitForCompletion(self: *StateWorkService) WaitResult {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        while (!self.shutdown_requested and
            self.completed_block_imports.items.len == 0 and
            (self.pending_block_imports.items.len > 0 or self.active_block_imports > 0))
        {
            self.cond.waitUncancelable(self.io, &self.mutex);
        }

        if (self.completed_block_imports.items.len > 0) return .completed;
        if (self.shutdown_requested) return .shutdown;
        return .idle;
    }

    pub fn metricsSnapshot(self: *const StateWorkService) MetricsSnapshot {
        const mutable_self: *StateWorkService = @constCast(self);
        mutable_self.mutex.lockUncancelable(mutable_self.io);
        defer mutable_self.mutex.unlock(mutable_self.io);

        return .{
            .pending_jobs = @intCast(self.pending_block_imports.items.len),
            .completed_jobs = @intCast(self.completed_block_imports.items.len),
            .active_jobs = @intCast(self.active_block_imports),
            .submitted_total = self.submitted_total,
            .rejected_total = self.rejected_total,
            .success_total = self.success_total,
            .failure_total = self.failure_total,
            .execution_time_ns_total = self.execution_time_ns_total,
            .last_execution_time_ns = self.last_execution_time_ns,
        };
    }

    fn workerMain(self: *StateWorkService) void {
        while (true) {
            self.mutex.lockUncancelable(self.io);
            while (!self.shutdown_requested and self.pending_block_imports.items.len == 0) {
                self.cond.waitUncancelable(self.io, &self.mutex);
            }

            if (self.shutdown_requested and self.pending_block_imports.items.len == 0) {
                self.mutex.unlock(self.io);
                return;
            }

            var job = self.pending_block_imports.orderedRemove(0);
            self.active_block_imports += 1;
            self.mutex.unlock(self.io);

            const started_at_ns = std.Io.Timestamp.now(self.io, .awake).toNanoseconds();
            const completed: CompletedBlockImport = blk: {
                const prepared = blocks.pipeline.executeStateTransitionJob(
                    self.allocator,
                    self.io,
                    self.state_regen,
                    self.state_graph_gate,
                    self.block_bls_thread_pool,
                    &job,
                ) catch |err| {
                    break :blk .{ .failure = .{
                        .planned = job.releasePlanned(),
                        .err = err,
                    } };
                };
                break :blk .{ .success = prepared };
            };
            const elapsed_ns: u64 = @intCast(std.Io.Timestamp.now(self.io, .awake).toNanoseconds() - started_at_ns);

            self.mutex.lockUncancelable(self.io);
            switch (completed) {
                .success => self.success_total += 1,
                .failure => self.failure_total += 1,
            }
            self.execution_time_ns_total += elapsed_ns;
            self.last_execution_time_ns = elapsed_ns;
            self.completed_block_imports.append(self.allocator, completed) catch {
                var owned_completed = completed;
                self.active_block_imports -= 1;
                self.mutex.unlock(self.io);
                owned_completed.deinit(self.allocator);
                @panic("OOM queueing completed block state work");
            };
            self.active_block_imports -= 1;
            self.cond.signal(self.io);
            self.mutex.unlock(self.io);
        }
    }
};
