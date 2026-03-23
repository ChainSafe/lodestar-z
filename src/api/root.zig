//! Beacon REST API module.
//!
//! Implements the Ethereum Beacon API (https://ethereum.github.io/beacon-APIs/)
//! as pure handler functions with a shared ApiContext. The handlers are
//! transport-agnostic — they take typed parameters and return typed responses.
//! An HTTP server layer can be wired on top to dispatch requests.
//!
//! ## Module structure
//!
//! - `types.zig`    — Request/response types, identifiers (BlockId, StateId, etc.)
//! - `context.zig`  — ApiContext struct with dependencies for all handlers
//! - `routes.zig`   — Route table mapping URL patterns to operation IDs
//! - `response.zig` — JSON/SSZ response encoding
//! - `handlers/`    — Pure handler functions grouped by namespace:
//!   - `node.zig`   — `/eth/v1/node/*`  (identity, version, sync, health, peers)
//!   - `beacon.zig` — `/eth/v{1,2}/beacon/*` (genesis, blocks, headers, state queries)
//!   - `config.zig` — `/eth/v1/config/*` (spec, fork schedule)

const std = @import("std");
const testing = std.testing;

pub const types = @import("types.zig");
pub const context = @import("context.zig");
pub const routes = @import("routes.zig");
pub const response = @import("response.zig");
pub const handlers = @import("handlers/root.zig");
pub const test_helpers = @import("test_helpers.zig");

// Re-export key types for convenience.
pub const ApiContext = context.ApiContext;
pub const BlockId = types.BlockId;
pub const StateId = types.StateId;
pub const ValidatorId = types.ValidatorId;
pub const ContentType = types.ContentType;
pub const ApiResponse = types.ApiResponse;

// Re-export route matching.
pub const findRoute = routes.findRoute;
pub const HttpMethod = routes.HttpMethod;

test {
    testing.refAllDecls(types);
    testing.refAllDecls(context);
    testing.refAllDecls(routes);
    testing.refAllDecls(response);
    testing.refAllDecls(handlers);
    _ = test_helpers;
}
