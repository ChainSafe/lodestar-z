//! DiscV5 node discovery.
//!
//! Engine owns protocol state with explicit time and entropy. Transport owns its Engine,
//! shared UDP sockets and bounded packet I/O. Lookup and Maintenance own discovery policy.

pub const CallTable = @import("CallTable.zig");
pub const admission = @import("admission.zig");
pub const Channel = @import("Channel.zig");
pub const sockets = @import("udp");
pub const Transport = @import("Transport.zig");
pub const Engine = @import("Engine.zig");
pub const Lookup = @import("Lookup.zig");
pub const Maintenance = @import("Maintenance.zig");
pub const ResponsePlan = @import("ResponsePlan.zig");
pub const RoutingTable = @import("RoutingTable.zig");
pub const SessionStore = @import("SessionStore.zig");
pub const identity = @import("identity/root.zig");
pub const lookup_io = @import("lookup_io.zig");
pub const lookup_batch = @import("lookup_batch.zig");
pub const types = @import("types.zig");
pub const wire = @import("wire/root.zig");

test {
    _ = admission;
    _ = CallTable;
    _ = Channel;
    _ = Transport;
    _ = Engine;
    _ = Lookup;
    _ = Maintenance;
    _ = ResponsePlan;
    _ = RoutingTable;
    _ = SessionStore;
    _ = identity;
    _ = lookup_batch;
    _ = types;
    _ = wire;
    _ = @import("call_table_test.zig");
    _ = @import("channel_test.zig");
    _ = @import("transport_test.zig");
    _ = @import("engine_test.zig");
    _ = @import("engine_schedule_test.zig");
    _ = @import("lookup_test.zig");
    _ = @import("response_plan_test.zig");
    _ = @import("routing_table_test.zig");
    _ = @import("session_store_test.zig");
    _ = @import("session_schedule_test.zig");
    _ = @import("lookup_batch_test.zig");
    _ = @import("maintenance_test.zig");
    _ = @import("types_test.zig");
    _ = @import("udp_test.zig");
}
