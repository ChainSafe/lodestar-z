//! Zig beacon clock – slot/epoch timing for Ethereum consensus.
//!
//! Public surface:
//!   `slot_math` – pure arithmetic, comptime-compatible
//!   `Clock`     – event-driven beacon clock with listeners and waiters
//! Internally `Clock` layers on `SlotClock`, a stateful slot clock reading
//! wall-clock time via `std.Io`.

pub const config = @import("config.zig");
pub const slot_math = @import("slot_math.zig");
pub const Clock = @import("Clock.zig");

pub const ClockConfig = config.ClockConfig;
pub const Slot = slot_math.Slot;
pub const Epoch = slot_math.Epoch;

pub const ListenerId = Clock.ListenerId;
pub const Error = Clock.Error;

test {
    _ = config;
    _ = slot_math;
    // Clock's transitive import compiles SlotClock but does not run its tests.
    _ = @import("SlotClock.zig");
    _ = Clock;
}
