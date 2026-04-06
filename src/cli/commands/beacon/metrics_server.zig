const shared_metrics = @import("app_metrics");
const node_mod = @import("node");

pub const default_address = "127.0.0.1";
pub const default_port: u16 = 8008;

pub const Config = shared_metrics.Config;
pub const Runtime = shared_metrics.Runtime(node_mod.MetricsServer, node_mod.MetricsSurface, "beacon");
