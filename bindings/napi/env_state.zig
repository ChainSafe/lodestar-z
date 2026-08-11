const std = @import("std");
const napi = @import("zapi:zapi").napi;
const peer_manager = @import("peer_manager");

const allocator = std.heap.page_allocator;

pub const PeerManagerState = struct {
    manager: ?peer_manager.PeerManager = null,

    pub fn init(
        self: *PeerManagerState,
        config: peer_manager.Config,
        clock_fn: *const fn () i64,
    ) !void {
        if (self.manager != null) return error.AlreadyInitialized;
        self.manager = try peer_manager.PeerManager.init(
            allocator,
            config,
            clock_fn,
        );
    }

    pub fn deinit(self: *PeerManagerState) void {
        if (self.manager) |*manager| {
            manager.deinit();
            self.manager = null;
        }
    }

    pub fn get(self: *PeerManagerState) !*peer_manager.PeerManager {
        if (self.manager) |*manager| return manager;
        return error.PeerManagerNotInitialized;
    }
};

pub const EnvState = struct {
    peer_manager: PeerManagerState = .{},

    fn deinit(self: *EnvState) void {
        self.peer_manager.deinit();
    }
};

fn finalizeEnvState(_: napi.Env, state: *EnvState, _: ?*anyopaque) void {
    state.deinit();
    allocator.destroy(state);
}

/// Claims the addon's single N-API instance-data slot for the current
/// environment. All future environment-local binding state belongs in
/// `EnvState` rather than installing another instance-data pointer.
pub fn install(env: napi.Env) !void {
    if (try env.getInstanceData(EnvState) != null) {
        return error.EnvironmentStateAlreadyInstalled;
    }

    const state = try allocator.create(EnvState);
    errdefer allocator.destroy(state);
    state.* = .{};

    try env.setInstanceData(EnvState, state, finalizeEnvState, null);
}

pub fn get(env: napi.Env) !*EnvState {
    return try env.getInstanceData(EnvState) orelse
        error.EnvironmentStateNotInstalled;
}
