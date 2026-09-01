pub const calls = @import("calls.zig");
pub const engine = @import("engine.zig");
pub const identity = @import("identity/root.zig");
pub const lookup = @import("lookup.zig");
pub const protocol = @import("protocol.zig");
pub const routing = @import("routing.zig");
pub const runtime = @import("runtime.zig");
pub const session = @import("session.zig");
pub const types = @import("types.zig");
pub const wire = @import("wire/root.zig");

test {
    _ = calls;
    _ = engine;
    _ = identity;
    _ = lookup;
    _ = protocol;
    _ = routing;
    _ = runtime;
    _ = session;
    _ = types;
    _ = wire;
    _ = @import("calls_test.zig");
    _ = @import("engine_test.zig");
    _ = @import("lookup_test.zig");
    _ = @import("routing_test.zig");
    _ = @import("runtime_test.zig");
    _ = @import("session_test.zig");
    _ = @import("standard_response_test.zig");
    _ = @import("types_test.zig");
}
