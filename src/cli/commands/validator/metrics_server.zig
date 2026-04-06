const shared_metrics = @import("app_metrics");
const validator_mod = @import("validator");

pub const default_address = "127.0.0.1";
pub const default_port: u16 = 5064;

pub const Config = shared_metrics.Config;
pub const Runtime = shared_metrics.Runtime(validator_mod.MetricsServer, validator_mod.ValidatorMetrics, "validator");
