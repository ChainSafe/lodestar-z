//! The binding's one process-fatal path, for a bridge contract failure that no promise or host callback can report
//! reliably. It terminates at once: it calls no host code and attempts no shutdown. Every other failure is an ordinary
//! throw or rejection, a retired operation, a local shutdown or a failed close.
//!
//! Each site, with the invariant it guards, its caller and its lifetime:
//! - `settlement`: valid, preallocated handles settle while JavaScript can run. Legacy settlement from a notification
//!   or an exchange (network.zig), for a failure other than a stopped environment. Goes with legacy settlement.
//! - `exchange_build`: an exchange that applied its actions and selected a delivery builds the result it promised.
//!   `network_exchange.run`, for a build failure classified as a contract failure. Kept.
//! - `exchange_finish`: a committed delivery reaches JavaScript intact. `network_exchange.run`, for a finish failure
//!   classified as a contract failure. Kept.
//! - `generated_batch`: the actions and demand the pump generates satisfy the exchange's input contract. The pump,
//!   through the runtime's `fail`, when an exchange refuses them with a coded error. Kept.
//! - `failed_turns`: the only completion path does not stay unusable. The pump, through the runtime's `fail`, on its
//!   third consecutive failed turn, during shutdown too. Kept.
//! - `completion_contract`: every completion names the current generation of a record the completion owner installed,
//!   of the kind it expects, and the close result leaves no promised completion missing. The completion owner
//!   (network-tickets.js), through the runtime's `fail`; a completion for an older generation is obsolete and ignored.
//!   Kept.
const std = @import("std");
const napi = @import("zapi:zapi").napi;

pub const Site = enum { settlement, exchange_build, exchange_finish, generated_batch, failed_turns, completion_contract };

/// A longer detail is cut to this many bytes.
pub const detail_max = 64;

pub const name_max = blk: {
    var max: usize = 0;
    for (std.meta.fieldNames(Site)) |name| max = @max(max, name.len);
    break :blk max;
};

/// Prints `native network bridge <site>: <detail>` through Node's fatal error handler, which aborts.
pub fn terminate(env: napi.Env, site: Site, detail: []const u8) noreturn {
    var buffer: [message_max]u8 = undefined;
    env.fatalError("native network bridge", message(&buffer, site, detail));
}

const message_max = name_max + ": ".len + detail_max;

fn message(buffer: *[message_max]u8, site: Site, detail: []const u8) []const u8 {
    return std.fmt.bufPrint(buffer, "{s}: {s}", .{ @tagName(site), detail[0..@min(detail.len, detail_max)] }) catch unreachable;
}

test "a message names its site and keeps at most detail_max bytes of detail" {
    var buffer: [message_max]u8 = undefined;
    try std.testing.expectEqualStrings("settlement: GenericFailure", message(&buffer, .settlement, "GenericFailure"));
    const long: [detail_max + 1]u8 = @splat('x');
    try std.testing.expectEqualStrings("exchange_finish: " ++ long[0..detail_max], message(&buffer, .exchange_finish, &long));
}
