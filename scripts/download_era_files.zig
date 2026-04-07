const std = @import("std");
const download_era_options = @import("download_era_options");

pub fn main() !void {
    const io = std.Options.debug_io;
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    for (download_era_options.era_files) |era_file| {
        try download_era_file(allocator, io, download_era_options.era_base_url, era_file, download_era_options.era_out_dir);
    }
}

fn download_era_file(
    allocator: std.mem.Allocator,
    io: std.Io,
    base_url: []const u8,
    era_file: []const u8,
    out_dir: []const u8,
) !void {
    try std.Io.Dir.cwd().createDirPath(io, out_dir);

    const out_path = try std.fs.path.join(allocator, &[_][]const u8{ out_dir, era_file });
    defer allocator.free(out_path);

    if (std.Io.Dir.cwd().openFile(io, out_path, .{})) |f| {
        std.log.info("{s} already downloaded", .{era_file});
        f.close(io);
        return;
    } else |_| {}

    std.log.info("Downloading {s} from {s}", .{ era_file, base_url });

    const url = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ base_url, era_file });
    defer allocator.free(url);

    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();

    var response_writer: std.Io.Writer.Allocating = .init(allocator);
    defer response_writer.deinit();

    const result = try client.fetch(.{
        .location = .{ .url = url },
        .response_writer = &response_writer.writer,
    });

    if (result.status.class() != .success) {
        std.log.err("Failed to download {s}: HTTP {d}", .{ era_file, @intFromEnum(result.status) });
        return error.DownloadFailed;
    }

    const body = response_writer.written();
    std.log.info("Writing {s}: {d} bytes", .{ out_path, body.len });

    const file = try std.Io.Dir.cwd().createFile(io, out_path, .{});
    defer file.close(io);

    var write_buf: [8192]u8 = undefined;
    var fw = file.writer(io, &write_buf);
    try fw.interface.writeAll(body);
    try fw.end();
}
