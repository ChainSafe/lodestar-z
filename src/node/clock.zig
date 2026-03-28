//! Wall clock slot ticker for production beacon node use.
//!
//! Re-exports the canonical SlotClock from config/clock.zig.
//! The underlying implementation uses `std.Io` for deterministic testability
//! while also working with real wall-clock time in production.

const config_mod = @import("config");

/// Re-exported canonical SlotClock from config/clock.zig.
pub const SlotClock = config_mod.SlotClock;
