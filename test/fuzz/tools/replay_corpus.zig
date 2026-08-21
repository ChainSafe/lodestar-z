// Native corpus replay driver.
//
// Links against a single fuzz harness (zig_fuzz_init / zig_fuzz_test) and
// feeds it every regular file in the directories passed as arguments.
// Directories that don't exist are skipped, so callers can always pass both
// the -cmin and -initial corpus directories.
//
// Unlike the AFL++-instrumented binaries this needs no afl-cc, runs on any
// host, and can be built in Debug so every corpus input executes with full
// safety checks. A crashing input aborts the process, which makes the
// `zig build replay` step a deterministic regression gate for the committed
// corpus.

const std = @import("std");
const Dir = std.Io.Dir;

extern fn zig_fuzz_init() callconv(.c) void;
extern fn zig_fuzz_test(buf: [*]const u8, len: usize) callconv(.c) void;

/// Largest corpus input we accept; AFL++ default max input is far below this.
const max_input_len = 16 * 1024 * 1024;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    const read_buf = try allocator.alloc(u8, max_input_len);
    defer allocator.free(read_buf);

    zig_fuzz_init();

    var total: u32 = 0;
    var dirs: u32 = 0;

    var args = std.process.Args.Iterator.init(init.minimal.args);
    defer args.deinit();
    _ = args.skip(); // program name

    const cwd = Dir.cwd();
    while (args.next()) |dir_path| {
        var dir = cwd.openDir(io, dir_path, .{ .iterate = true }) catch {
            continue;
        };
        defer dir.close(io);
        dirs += 1;

        var iter = dir.iterate();
        while (try iter.next(io)) |entry| {
            if (entry.kind != .file) continue;
            if (entry.name[0] == '.') continue;

            const data = dir.readFile(io, entry.name, read_buf) catch |err| {
                std.debug.print(
                    "replay: cannot read {s}/{s}: {}\n",
                    .{ dir_path, entry.name, err },
                );
                return err;
            };
            zig_fuzz_test(data.ptr, data.len);
            total += 1;
        }
    }

    std.debug.print(
        "replay: {} inputs replayed from {} director{s}\n",
        .{ total, dirs, if (dirs == 1) "y" else "ies" },
    );
}
