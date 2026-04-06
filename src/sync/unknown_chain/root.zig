//! Unknown chain sync: backwards header chain sync for unknown blocks.
//!
//! When blocks, attestations, or peer status messages reference roots
//! not in our fork choice, this module tracks them and builds header
//! chains backwards until they link to our known chain.
//!
//! Components:
//! - `backwards_chain` — BackwardsChain state machine (unknown_head → unknown_ancestor → linked)
//! - `unknown_chain_sync` — Coordinator managing multiple BackwardsChain instances

const std = @import("std");

pub const backwards_chain = @import("backwards_chain.zig");
pub const unknown_chain_sync = @import("unknown_chain_sync.zig");

// Re-export key types.
pub const BackwardsChain = backwards_chain.BackwardsChain;
pub const MinimalHeader = backwards_chain.MinimalHeader;
pub const PeerSet = backwards_chain.PeerSet;
pub const ChainState = backwards_chain.State;

pub const UnknownChainSync = unknown_chain_sync.UnknownChainSync;
pub const Callbacks = unknown_chain_sync.Callbacks;
pub const ForkChoiceQuery = unknown_chain_sync.ForkChoiceQuery;

test {
    std.testing.refAllDecls(@This());
}

test {
    _ = @import("unknown_chain_sync_test.zig");
}
