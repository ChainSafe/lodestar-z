//! Beacon REST API module.
//!
//! Implements the Ethereum Beacon API (https://ethereum.github.io/beacon-APIs/)
//! as pure handler functions with a shared ApiContext. The handlers are
//! transport-agnostic — they take typed parameters and return typed responses.
//! An HTTP server layer (`http_server.zig`) dispatches requests over TCP.
//!
//! ## Module structure
//!
//! - `types.zig`        — Request/response types, identifiers (BlockId, StateId, etc.)
//! - `context.zig`      — ApiContext struct with dependencies for all handlers
//! - `routes.zig`       — Route table mapping URL patterns to operation IDs
//! - `response.zig`     — JSON/SSZ response encoding
//! - `http_server.zig`  — HTTP/1.1 server using std.http.Server + std.Io.net
//! - `handlers/`        — Pure handler functions grouped by namespace:
//!   - `node.zig`       — `/eth/v1/node/*`  (identity, version, sync, health, peers)
//!   - `beacon.zig`     — `/eth/v{1,2}/beacon/*` (genesis, blocks, headers, state queries)
//!   - `config.zig`     — `/eth/v1/config/*` (spec, fork schedule)

const std = @import("std");
const testing = std.testing;

pub const types = @import("types.zig");
pub const context = @import("context.zig");
pub const routes = @import("routes.zig");
pub const response = @import("response.zig");
pub const handlers = @import("handlers/root.zig");
pub const http_server = @import("http_server.zig");
pub const test_helpers = @import("test_helpers.zig");
pub const event_bus = @import("event_bus.zig");

// Re-export key types for convenience.
pub const ApiContext = context.ApiContext;
pub const BlockId = types.BlockId;
pub const StateId = types.StateId;
pub const ValidatorId = types.ValidatorId;
pub const ContentType = types.ContentType;
pub const ApiResponse = types.ApiResponse;
pub const HttpServer = http_server.HttpServer;
pub const EventBus = event_bus.EventBus;
pub const Event = event_bus.Event;

// Re-export route matching.
pub const findRoute = routes.findRoute;
pub const HttpMethod = routes.HttpMethod;

test {
    testing.refAllDecls(types);
    testing.refAllDecls(context);
    testing.refAllDecls(routes);
    testing.refAllDecls(response);
    testing.refAllDecls(handlers);
    testing.refAllDecls(http_server);
    _ = test_helpers;
}
