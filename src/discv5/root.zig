//! DiscV5 node discovery.
//!
//! Layers, lowest first: `types`, `wire`, `identity`; `SessionStore`, `CallTable`, `RoutingTable`,
//! `ResponsePlan`, `Udp`; `Channel`; `Engine`; `Lookup`; `Driver` and `lookup_driver`. Each file
//! imports only layers below it. See docs/architecture/discv5.md.

pub const CallTable = @import("CallTable.zig");
pub const Channel = @import("Channel.zig");
pub const Driver = @import("Driver.zig");
pub const Engine = @import("Engine.zig");
pub const Lookup = @import("Lookup.zig");
pub const ResponsePlan = @import("ResponsePlan.zig");
pub const RoutingTable = @import("RoutingTable.zig");
pub const SessionStore = @import("SessionStore.zig");
pub const Udp = @import("Udp.zig");
pub const identity = @import("identity/root.zig");
pub const lookup_driver = @import("lookup_driver.zig");
pub const types = @import("types.zig");
pub const wire = @import("wire/root.zig");

test {
    _ = CallTable;
    _ = Channel;
    _ = Driver;
    _ = Engine;
    _ = Lookup;
    _ = ResponsePlan;
    _ = RoutingTable;
    _ = SessionStore;
    _ = Udp;
    _ = identity;
    _ = lookup_driver;
    _ = types;
    _ = wire;
    _ = @import("call_table_test.zig");
    _ = @import("channel_test.zig");
    _ = @import("driver_test.zig");
    _ = @import("engine_test.zig");
    _ = @import("lookup_test.zig");
    _ = @import("response_plan_test.zig");
    _ = @import("routing_table_test.zig");
    _ = @import("session_store_test.zig");
    _ = @import("types_test.zig");
    _ = @import("udp_test.zig");
}
