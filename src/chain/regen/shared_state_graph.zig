const BeaconConfig = @import("config").BeaconConfig;
const Node = @import("persistent_merkle_tree").Node;
const state_transition = @import("state_transition");
const CachedBeaconState = state_transition.CachedBeaconState;
const SharedValidatorPubkeys = state_transition.SharedValidatorPubkeys;
const StateDisposer = @import("state_disposer.zig").StateDisposer;
const StateGraphGate = @import("state_graph_gate.zig").StateGraphGate;
const StateTransitionMetrics = state_transition.metrics.StateTransitionMetrics;

/// Runtime-owned immutable/shared state graph borrowed by all published states.
///
/// This is the application singleton that backs state deserialization,
/// publication ownership checks, deferred disposal, and the coarse mutation
/// lease used by STFN/regen.
pub const SharedStateGraph = struct {
    config: *const BeaconConfig,
    pool: *Node.Pool,
    validator_pubkeys: *SharedValidatorPubkeys,
    state_disposer: *StateDisposer,
    gate: *StateGraphGate,
    state_transition_metrics: *StateTransitionMetrics,

    pub fn acquireMutationLease(self: *SharedStateGraph) StateGraphGate.Lease {
        return self.gate.acquire();
    }

    pub fn verifyPublishedStateOwnership(
        self: *const SharedStateGraph,
        state: *CachedBeaconState,
    ) !void {
        if (state.config != self.config) return error.PublishedStateConfigMismatch;

        const pool = switch (state.state.*) {
            inline else => |fork_state| fork_state.pool,
        };
        if (pool != self.pool) return error.PublishedStatePoolMismatch;

        if (!self.validator_pubkeys.ownsStateCaches(
            state.epoch_cache.pubkey_to_index,
            state.epoch_cache.index_to_pubkey,
        )) {
            return error.PublishedStatePubkeyCacheMismatch;
        }
    }
};
