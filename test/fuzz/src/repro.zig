const std = @import("std");
const fuzz_options = @import("fuzz_options");
const fuzz_target = @import("fuzz_target");

const directory_entry_count_max: u32 = 100_000;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return error.ExpectedOneFileOrDirectory;

    fuzz_target.zig_fuzz_init();

    const cwd = std.Io.Dir.cwd();
    const stat = try cwd.statFile(io, args[1], .{});
    switch (stat.kind) {
        .file => try replayFile(cwd, io, allocator, args[1]),
        .directory => try replayDirectory(cwd, io, allocator, args[1]),
        else => return error.ExpectedOneFileOrDirectory,
    }
}

fn replayDirectory(
    cwd: std.Io.Dir,
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
) !void {
    var directory = try cwd.openDir(io, path, .{ .iterate = true });
    defer directory.close(io);

    var entry_count: u32 = 0;
    var iterator = directory.iterate();
    while (try iterator.next(io)) |entry| {
        entry_count += 1;
        if (entry_count > directory_entry_count_max) return error.TooManyDirectoryEntries;
        if (entry.kind != .file) continue;
        try replayFile(directory, io, allocator, entry.name);
    }
}

fn replayFile(
    directory: std.Io.Dir,
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
) !void {
    const read_limit = @as(usize, fuzz_options.max_input_len) + 1;
    const input = try directory.readFileAlloc(
        io,
        path,
        allocator,
        .limited(read_limit),
    );
    defer allocator.free(input);

    if (input.len > @as(usize, fuzz_options.max_input_len)) return error.InputTooLong;
    fuzz_target.zig_fuzz_test(input.ptr, input.len);
}
