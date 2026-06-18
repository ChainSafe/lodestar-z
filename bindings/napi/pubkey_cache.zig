//! Per-state-tree pubkey cache ownership for the napi bindings.
//!
//! This is intentionally NOT registered as a JS namespace in `root.zig`: the
//! zapi DSL turns every `pub fn` of an exported module into a JS function, and
//! these handles are not JS values. They are consumed only by `BeaconStateView`.
//!
//! Replaces the process-global `pubkeys.state` for state-attached caches: each
//! root state (`BeaconStateView.createFromBytes`) mints its own `PubkeyCacheRc`,
//! shared with its regen (`loadState`) and transition (`stateTransition`)
//! descendants via refcount. This mirrors the TS `EpochCache`, where the pubkey
//! registry is a constructor input shared across cloned states rather than a
//! hidden global — so independent states (e.g. spec-test fixtures loaded in the
//! same process) never see each other's pubkey→index entries.
const std = @import("std");
const PubkeyIndexMap = @import("state_transition").PubkeyIndexMap;
const Index2PubkeyCache = @import("state_transition").Index2PubkeyCache;
const RefCount = @import("state_transition").RefCount;

/// Matches the allocator the previous global cache used.
const allocator = std.heap.page_allocator;

/// Owned bundle of the two pubkey caches for one state tree.
pub const PubkeyMaps = struct {
    pubkey2index: PubkeyIndexMap,
    index2pubkey: Index2PubkeyCache,

    /// 1-arg form so `RefCount` dispatches here on the last unref().
    pub fn deinit(self: *PubkeyMaps) void {
        self.pubkey2index.deinit();
        self.index2pubkey.deinit(allocator);
    }
};

pub const PubkeyCacheRc = RefCount(PubkeyMaps);

/// Allocate a fresh, empty pubkey cache owned by one state tree (ref_count = 1).
/// The epoch cache populates it from the state's validators on first build via
/// `syncPubkeys`. Caller owns the returned handle and must `unref()` it.
pub fn create() !*PubkeyCacheRc {
    return PubkeyCacheRc.init(allocator, .{
        .pubkey2index = PubkeyIndexMap.init(allocator),
        .index2pubkey = Index2PubkeyCache.empty,
    });
}
