//! DiscV5 node discovery.
//!
//! The lowest layer is `types`, followed by `wire` and `identity`. Above them sit `SessionStore`,
//! `CallTable`, `RoutingTable`, `ResponsePlan`, and `Udp`, which depend on nothing but those
//! three. `Channel` builds on the session store, `Engine` on the channel and the tables, `Lookup`
//! on the engine, and `Driver` and `lookup_driver` on everything beneath them. Each file imports
//! only layers below it. The design is described in docs/architecture/discv5.md.

pub const CallTable = @import("CallTable.zig");
pub const Channel = @import("Channel.zig");
pub const Driver = @import("Driver.zig");
pub const Engine = @import("Engine.zig");
pub const Lookup = @import("Lookup.zig");
pub const Maintenance = @import("Maintenance.zig");
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
    _ = Maintenance;
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
    _ = @import("engine_schedule_test.zig");
    _ = @import("lookup_test.zig");
    _ = @import("response_plan_test.zig");
    _ = @import("routing_table_test.zig");
    _ = @import("session_store_test.zig");
    _ = @import("session_schedule_test.zig");
    _ = @import("lookup_driver_test.zig");
    _ = @import("maintenance_test.zig");
    _ = @import("types_test.zig");
    _ = @import("udp_test.zig");
}
