//! Zig beacon clock – slot/epoch timing for Ethereum consensus.
//!
//! Three-layer architecture:
//!   Layer 0 (`slot_math`)   – pure arithmetic, comptime-compatible
//!   Layer 1 (`SlotClock`)   – stateful clock with time source
//!   Layer 2 (`EventClock`)  – async event loop with listeners and waiters

pub const slot_math = @import("slot_math.zig");
pub const time_source = @import("time_source.zig");
pub const SlotClock = @import("SlotClock.zig");
pub const EventClock = @import("EventClock.zig");

pub const Config = SlotClock.Config;
pub const Slot = SlotClock.Slot;
pub const Epoch = SlotClock.Epoch;

pub const ListenerId = EventClock.ListenerId;
pub const Error = EventClock.Error;

test {
    _ = slot_math;
    _ = SlotClock;
    _ = EventClock;
}
