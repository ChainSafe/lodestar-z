const std = @import("std");
const options = @import("spec_test_options");

pub fn main(init: std.process.Init) !void {
    try download(std.heap.page_allocator, init.io);
}

/// Generous bound on each archive download.
const max_archive_bytes = 1024 * 1024;

/// SSZ generic fixtures ship from ethereum/ssz-specs, separately from the consensus spec tests.
pub fn download(gpa: std.mem.Allocator, io: std.Io) !void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const allocator = arena.allocator();

    const version = options.ssz_spec_test_version;
    const base_path = try std.fs.path.join(allocator, &.{ options.spec_test_out_dir, "ssz" });
    var base = try std.Io.Dir.cwd().createDirPathOpen(io, base_path, .{});
    defer base.close(io);

    try fetch(allocator, io, base, .{
        .name = version,
        .url = try std.fmt.allocPrint(
            allocator,
            "{s}/releases/download/{s}/ssz-test-vectors-{s}.tar.gz",
            .{ options.ssz_spec_test_url, version, version },
        ),
        .sha256 = options.ssz_spec_test_sha256,
        .strip_components = 0,
        .required_path = "fixtures/ssz/ssz",
    });
    try fetch(allocator, io, base, .{
        .name = try std.fmt.allocPrint(allocator, "{s}-source", .{version}),
        .url = try std.fmt.allocPrint(
            allocator,
            "{s}/archive/refs/tags/{s}.tar.gz",
            .{ options.ssz_spec_test_url, version },
        ),
        .sha256 = options.ssz_spec_source_sha256,
        .strip_components = 1,
        .required_path = "tests/fillers/ssz",
    });
}

const Archive = struct {
    name: []const u8,
    url: []const u8,
    sha256: []const u8,
    strip_components: u32,
    required_path: []const u8,
};

/// The archive is verified before extraction, and only a complete directory is published, so an
/// interrupted download cannot become an empty passing suite.
fn fetch(allocator: std.mem.Allocator, io: std.Io, base: std.Io.Dir, archive: Archive) !void {
    var expected: [32]u8 = undefined;
    if (archive.sha256.len != 64) return error.InvalidArchiveDigest;
    _ = try std.fmt.hexToBytes(&expected, archive.sha256);

    const marker = try std.fmt.allocPrint(allocator, "{s}/archive.sha256", .{archive.name});
    const existing = base.readFileAlloc(io, marker, allocator, .limited(65)) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    if (existing) |digest| {
        if (!std.mem.eql(u8, digest, archive.sha256)) return error.ArchiveDigestMismatch;
        std.log.info("{s} already extracted", .{archive.name});
        return;
    }

    std.log.info("downloading {s}", .{archive.url});
    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();
    var req = try client.request(.GET, try std.Uri.parse(archive.url), .{});
    defer req.deinit();
    try req.sendBodiless();
    var redirect_buffer: [8 * 1024]u8 = undefined;
    var response = try req.receiveHead(&redirect_buffer);
    if (response.head.status != .ok) return error.FixtureDownloadFailed;
    const body = try response.reader(&.{}).allocRemaining(allocator, .limited(max_archive_bytes));

    var actual: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(body, &actual, .{});
    if (!std.mem.eql(u8, &expected, &actual)) return error.ArchiveDigestMismatch;

    const staging_name = try std.fmt.allocPrint(allocator, "{s}.extracting", .{archive.name});
    try base.deleteTree(io, staging_name);
    var staging = try base.createDirPathOpen(io, staging_name, .{});
    defer staging.close(io);
    errdefer base.deleteTree(io, staging_name) catch {};

    var reader: std.Io.Reader = .fixed(body);
    var decompress_buf: [std.compress.flate.max_window_len]u8 = undefined;
    var decompressor = std.compress.flate.Decompress.init(&reader, .gzip, &decompress_buf);
    try std.tar.pipeToFileSystem(io, staging, &decompressor.reader, .{
        .strip_components = archive.strip_components,
    });
    var required = try staging.openDir(io, archive.required_path, .{});
    required.close(io);

    const digest_file = try staging.createFile(io, "archive.sha256", .{});
    defer digest_file.close(io);
    try digest_file.writeStreamingAll(io, archive.sha256);
    try base.rename(staging_name, base, archive.name, io);
    std.log.info("{s} extracted", .{archive.name});
}
