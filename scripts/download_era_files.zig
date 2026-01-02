const std = @import("std");
const download_era_options = @import("download_era_options");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    for (download_era_options.era_files) |era_file| {
        try download_era_file(
            allocator,
            download_era_options.era_base_url,
            era_file,
            download_era_options.era_out_dir,
        );
    }
}

fn download_era_file(
    allocator: std.mem.Allocator,
    base_url: []const u8,
    era_file: []const u8,
    out_dir: []const u8,
) !void {
    // Ensure the output directory exists before creating the file
    try std.fs.cwd().makePath(out_dir);

    // If the file already exists, return early
    const out_path = try std.fs.path.join(allocator, &[_][]const u8{ out_dir, era_file });
    defer allocator.free(out_path);

    if (std.fs.cwd().openFile(out_path, .{})) |f| {
        std.log.info("{s} already downloaded", .{
            era_file,
        });
        f.close();
        return;
    } else |_| {}

    std.log.info("Downloading {s} from {s}", .{
        era_file,
        base_url,
    });

    const url = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ base_url, era_file });
    defer allocator.free(url);

    var client: std.http.Client = .{ .allocator = allocator };
    defer client.deinit();

    // Prepare the request
    const uri = try std.Uri.parse(url);
    var server_header_buffer: [16 * 1024]u8 = undefined;
    var req = try client.open(.GET, uri, .{
        .server_header_buffer = &server_header_buffer,
    });
    defer req.deinit();

    // Send the request and await initial response
    try req.send();
    try req.wait();

    // Handle non-200 response
    if (req.response.status.class() != .success) {
        std.log.err("Failed to download {s}: {s}", .{
            era_file,
            req.response.status.phrase() orelse "Unknown error",
        });
        return error.DownloadFailed;
    }

    // Stream the response to a file
    std.log.info("Writing {s}", .{
        out_path,
    });

    const file = try std.fs.cwd().createFile(out_path, .{});
    defer file.close();

    var buf = try allocator.alloc(u8, 16 * 1024);
    defer allocator.free(buf);
    var reader = req.reader();
    var bytes_count: usize = 0;
    while (true) {
        const read_bytes = try reader.readAll(buf);
        try file.writeAll(buf[0..read_bytes]);
        bytes_count += read_bytes;
        if (read_bytes != buf.len) {
            break;
        }
    }

    std.log.info("Written {s}: {d} bytes", .{
        era_file,
        bytes_count,
    });
}
