pub const metrics = @import("metrics.zig");
pub const identify = @import("identify/root.zig");
pub const capabilities = @import("capabilities.zig");
pub const core = @import("core.zig");
pub const Core = core.Core;
pub const network_core = @import("network_core.zig");
pub const NetworkCore = network_core.NetworkCore;
pub const peers = @import("peers/root.zig");
pub const constants = @import("constants.zig");
pub const types = @import("types.zig");
pub const wire = @import("wire/root.zig");
pub const quic = @import("quic/root.zig");
pub const tls = @import("tls/root.zig");
pub const udp = @import("udp.zig");
pub const driver = @import("driver.zig");
pub const transport = @import("transport.zig");
pub const negotiate = @import("negotiate.zig");
pub const router = @import("router.zig");
pub const service = @import("service.zig");
pub const Router = router.Router;
pub const Service = service.Service;
pub const stream_io = @import("stream_io.zig");
pub const reqresp = @import("reqresp/root.zig");
pub const gossipsub = @import("gossipsub/root.zig");

pub const Transport = transport.Transport;
pub const Negotiator = negotiate.Negotiator;
pub const Engine = quic.engine.Engine;
pub const Driver = driver.Driver;
pub const Udp = udp.Udp;
pub const Handle = quic.engine.Handle;
pub const StreamHandle = quic.engine.StreamHandle;
pub const Event = quic.engine.Event;
pub const Limits = quic.engine.Limits;
pub const StepOptions = driver.StepOptions;
pub const StepResult = driver.StepResult;
pub const CloseReason = types.CloseReason;
pub const Now = types.Now;
pub const Address = types.Address;
pub const PeerId = wire.peer_id.PeerId;
pub const Multiaddr = wire.multiaddr.Multiaddr;
pub const KeyPair = wire.keys.KeyPair;

test {
    _ = peers;
    _ = constants;
    _ = types;
    _ = wire;
    _ = quic;
    _ = tls;
    _ = udp;
    _ = driver;
    _ = transport;
    _ = negotiate;
    _ = stream_io;
    _ = reqresp;
    _ = gossipsub;
    _ = @import("types_test.zig");
    _ = @import("udp_test.zig");
    _ = @import("wait_test.zig");
    _ = @import("driver_test.zig");
    _ = @import("transport_test.zig");
    _ = @import("negotiate_test.zig");
    _ = @import("router_test.zig");
}
test {
    _ = @import("core_test.zig");
}
test {
    _ = @import("core_control_test.zig");
    _ = @import("network_core_test.zig");
}

test {
    _ = @import("reservations.zig");
}

pub const configuration = @import("configuration.zig");
test {
    _ = configuration;
}

test {
    _ = @import("capabilities_test.zig");
}

test {
    _ = identify;
    _ = metrics;
    _ = @import("metrics_histogram.zig");
    _ = @import("metrics_score.zig");
    _ = @import("reqresp/metrics.zig");
}
