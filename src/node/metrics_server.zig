//! Prometheus HTTP server for beacon-node metrics.

const shared_metrics = @import("app_metrics");
const MetricsSurface = @import("metrics.zig").MetricsSurface;

pub const MetricsServer = shared_metrics.Server(MetricsSurface, "beacon");
