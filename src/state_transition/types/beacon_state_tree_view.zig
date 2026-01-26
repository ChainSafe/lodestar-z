const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("consensus_types");
const ForkSeq = @import("config").ForkSeq;
const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;

const Slot = types.primitive.Slot.Type;

// BeaconState field indices are stable across forks.
// - phase0: validators index = 11
// - altair+: inactivity_scores index = 21
pub const BEACON_STATE_VALIDATORS_FIELD_INDEX: usize = 11;
pub const BEACON_STATE_INACTIVITY_SCORES_FIELD_INDEX: usize = 21;

// TODO: use BeaconStateAllForks directly once it changed to use TreeView
pub const BeaconStateTreeViewAllForks = union(enum) {
    phase0: types.phase0.BeaconState.TreeView,
    altair: types.altair.BeaconState.TreeView,
    bellatrix: types.bellatrix.BeaconState.TreeView,
    capella: types.capella.BeaconState.TreeView,
    deneb: types.deneb.BeaconState.TreeView,
    electra: types.electra.BeaconState.TreeView,
    fulu: types.fulu.BeaconState.TreeView,

    pub fn deinit(self: *@This()) void {
        switch (self.*) {
            inline else => |*v| v.deinit(),
        }
    }

    pub fn commit(self: *@This()) !void {
        switch (self.*) {
            inline else => |*v| try v.commit(),
        }
    }

    pub fn pool(self: *const @This()) *Node.Pool {
        return switch (self.*) {
            inline else => |v| v.base_view.pool,
        };
    }

    pub fn allocator(self: *const @This()) Allocator {
        return switch (self.*) {
            inline else => |v| v.base_view.allocator,
        };
    }

    pub fn forkSeq(self: *const @This()) ForkSeq {
        return switch (self.*) {
            .phase0 => .phase0,
            .altair => .altair,
            .bellatrix => .bellatrix,
            .capella => .capella,
            .deneb => .deneb,
            .electra => .electra,
            .fulu => .fulu,
        };
    }

    pub fn fromTreeView(comptime fork: ForkSeq, view: anytype) @This() {
        return switch (fork) {
            .phase0 => .{ .phase0 = view },
            .altair => .{ .altair = view },
            .bellatrix => .{ .bellatrix = view },
            .capella => .{ .capella = view },
            .deneb => .{ .deneb = view },
            .electra => .{ .electra = view },
            .fulu => .{ .fulu = view },
        };
    }

    pub fn slot(self: *@This()) !Slot {
        return switch (self.*) {
            inline else => |*v| try v.get("slot"),
        };
    }

    pub fn validators(self: *@This()) !types.phase0.Validators.TreeView {
        const root = try self.validatorsNodeId();
        // NOTE(ownership): Returns an *owned* view (caller must deinit).
        // Borrowed child views built by copying cached TreeViewData can be unsafe (UAF/leaks) once
        // they perform cached operations (e.g. length/get/clone with cache transfer).
        // TODO(ssz/tree_view): Fix child-view semantics so borrowed views are safe.
        return try types.phase0.Validators.TreeView.init(self.allocator(), self.pool(), root);
    }

    pub fn inactivityScores(self: *@This()) !types.altair.InactivityScores.TreeView {
        const root = try self.inactivityScoresNodeId();
        // NOTE(ownership): Returns an *owned* view (caller must deinit).
        // Borrowed child views built by copying cached TreeViewData can be unsafe (UAF/leaks) once
        // they perform cached operations (e.g. length/get/clone with cache transfer).
        // TODO(ssz/tree_view): Fix child-view semantics so borrowed views are safe.
        return try types.altair.InactivityScores.TreeView.init(self.allocator(), self.pool(), root);
    }

    pub fn setValidators(self: *@This(), validators_view: types.phase0.Validators.TreeView) !void {
        switch (self.*) {
            inline else => |*v| try v.set("validators", validators_view),
        }
    }

    pub fn setInactivityScores(self: *@This(), scores_view: types.altair.InactivityScores.TreeView) !void {
        switch (self.*) {
            .phase0 => return error.NoInactivityScores,
            inline else => |*v| try v.set("inactivity_scores", scores_view),
        }
    }

    fn validatorsNodeId(self: *@This()) !Node.Id {
        return switch (self.*) {
            .phase0 => |*v| try v.base_view.getChildNode(Gindex.fromDepth(types.phase0.BeaconState.chunk_depth, BEACON_STATE_VALIDATORS_FIELD_INDEX)),
            .altair => |*v| try v.base_view.getChildNode(Gindex.fromDepth(types.altair.BeaconState.chunk_depth, BEACON_STATE_VALIDATORS_FIELD_INDEX)),
            .bellatrix => |*v| try v.base_view.getChildNode(Gindex.fromDepth(types.bellatrix.BeaconState.chunk_depth, BEACON_STATE_VALIDATORS_FIELD_INDEX)),
            .capella => |*v| try v.base_view.getChildNode(Gindex.fromDepth(types.capella.BeaconState.chunk_depth, BEACON_STATE_VALIDATORS_FIELD_INDEX)),
            .deneb => |*v| try v.base_view.getChildNode(Gindex.fromDepth(types.deneb.BeaconState.chunk_depth, BEACON_STATE_VALIDATORS_FIELD_INDEX)),
            .electra => |*v| try v.base_view.getChildNode(Gindex.fromDepth(types.electra.BeaconState.chunk_depth, BEACON_STATE_VALIDATORS_FIELD_INDEX)),
            .fulu => |*v| try v.base_view.getChildNode(Gindex.fromDepth(types.fulu.BeaconState.chunk_depth, BEACON_STATE_VALIDATORS_FIELD_INDEX)),
        };
    }

    fn inactivityScoresNodeId(self: *@This()) !Node.Id {
        return switch (self.*) {
            .phase0 => error.NoInactivityScores,
            .altair => |*v| try v.base_view.getChildNode(Gindex.fromDepth(types.altair.BeaconState.chunk_depth, BEACON_STATE_INACTIVITY_SCORES_FIELD_INDEX)),
            .bellatrix => |*v| try v.base_view.getChildNode(Gindex.fromDepth(types.bellatrix.BeaconState.chunk_depth, BEACON_STATE_INACTIVITY_SCORES_FIELD_INDEX)),
            .capella => |*v| try v.base_view.getChildNode(Gindex.fromDepth(types.capella.BeaconState.chunk_depth, BEACON_STATE_INACTIVITY_SCORES_FIELD_INDEX)),
            .deneb => |*v| try v.base_view.getChildNode(Gindex.fromDepth(types.deneb.BeaconState.chunk_depth, BEACON_STATE_INACTIVITY_SCORES_FIELD_INDEX)),
            .electra => |*v| try v.base_view.getChildNode(Gindex.fromDepth(types.electra.BeaconState.chunk_depth, BEACON_STATE_INACTIVITY_SCORES_FIELD_INDEX)),
            .fulu => |*v| try v.base_view.getChildNode(Gindex.fromDepth(types.fulu.BeaconState.chunk_depth, BEACON_STATE_INACTIVITY_SCORES_FIELD_INDEX)),
        };
    }
};
