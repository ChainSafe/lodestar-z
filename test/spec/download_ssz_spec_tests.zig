const std = @import("std");
const options = @import("spec_test_options");

pub fn main(init: std.process.Init) !void {
    try download(std.heap.page_allocator, init.io);
}

/// SSZ generic fixtures have their own release lifecycle.
/// Authenticate the small archive before extraction and publish only a completed
/// directory, so interrupted downloads cannot become an empty passing test suite.
pub fn download(allocator: std.mem.Allocator, io: std.Io) !void {
    const version = options.ssz_spec_test_version;
    const expected_hash = options.ssz_spec_test_sha256;
    var hash: [32]u8 = undefined;
    if (expected_hash.len != 64) return error.InvalidArchiveDigest;
    _ = try std.fmt.hexToBytes(&hash, expected_hash);
    const base_path = try std.fs.path.join(allocator, &.{ options.spec_test_out_dir, "ssz" });
    defer allocator.free(base_path);
    var base = try std.Io.Dir.cwd().createDirPathOpen(io, base_path, .{});
    defer base.close(io);
    const marker = try std.fmt.allocPrint(allocator, "{s}/archive.sha256", .{version});
    defer allocator.free(marker);
    const existing = base.readFileAlloc(io, marker, allocator, .limited(65)) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    if (existing) |bytes| {
        defer allocator.free(bytes);
        if (!std.mem.eql(u8, bytes, expected_hash)) return error.ArchiveDigestMismatch;
        std.log.info("SSZ fixtures {s} already extracted (archive digest matches)", .{version});
        return;
    }

    const url = try std.fmt.allocPrint(allocator, "{s}/releases/download/{s}/ssz-test-vectors-{s}.tar.gz", .{ options.ssz_spec_test_url, version, version });
    defer allocator.free(url);
    std.log.info("downloading SSZ fixtures {s}", .{url});
    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();
    var req = try client.request(.GET, try std.Uri.parse(url), .{});
    defer req.deinit();
    try req.sendBodiless();
    var redirect_buffer: [8 * 1024]u8 = undefined;
    var response = try req.receiveHead(&redirect_buffer);
    if (response.head.status != .ok) return error.FixtureDownloadFailed;
    const body = try response.reader(&.{}).allocRemaining(allocator, .limited(16 * 1024 * 1024));
    defer allocator.free(body);
    var actual_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(body, &actual_hash, .{});
    if (!std.mem.eql(u8, &hash, &actual_hash)) return error.ArchiveDigestMismatch;

    const staging_name = try std.fmt.allocPrint(allocator, "{s}.extracting", .{version});
    defer allocator.free(staging_name);
    try base.deleteTree(io, staging_name);
    var staging = try base.createDirPathOpen(io, staging_name, .{});
    defer staging.close(io);
    errdefer base.deleteTree(io, staging_name) catch {};
    var reader: std.Io.Reader = .fixed(body);
    var decompress_buf: [std.compress.flate.max_window_len]u8 = undefined;
    var decompressor = std.compress.flate.Decompress.init(&reader, .gzip, &decompress_buf);
    try std.tar.pipeToFileSystem(io, staging, &decompressor.reader, .{});
    var fixtures = try staging.openDir(io, "fixtures/ssz/ssz", .{});
    fixtures.close(io);
    const digest_file = try staging.createFile(io, "archive.sha256", .{});
    defer digest_file.close(io);
    try digest_file.writeStreamingAll(io, expected_hash);
    try base.rename(staging_name, base, version, io);
    std.log.info("SSZ fixtures {s} extracted, SHA-256 {s}", .{ version, expected_hash });
}
