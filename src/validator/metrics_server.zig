//! Prometheus HTTP server for validator metrics.

const shared_metrics = @import("app_metrics");
const ValidatorMetrics = @import("metrics.zig").ValidatorMetrics;

pub const MetricsServer = shared_metrics.Server(ValidatorMetrics, "validator");
