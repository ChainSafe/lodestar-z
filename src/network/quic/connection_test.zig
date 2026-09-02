const std = @import("std");
const connection = @import("connection.zig");

test "local crypto errors report tls_failed" {
    try std.testing.expectEqual(connection.CloseReason.tls_failed, connection.reasonFromLocalError(false, 0x174));
    try std.testing.expectEqual(connection.CloseReason.tls_failed, connection.reasonFromLocalError(false, connection.crypto_error_first));
    try std.testing.expectEqual(connection.CloseReason.tls_failed, connection.reasonFromLocalError(false, connection.crypto_error_last));

    const transport = connection.reasonFromLocalError(false, 0x0a);
    try std.testing.expectEqual(@as(u64, 0x0a), transport.transport_error);
    const outside = connection.reasonFromLocalError(false, 0x200);
    try std.testing.expectEqual(@as(u64, 0x200), outside.transport_error);
    const application = connection.reasonFromLocalError(true, 0x174);
    try std.testing.expectEqual(@as(u64, 0x174), application.transport_error);
}
