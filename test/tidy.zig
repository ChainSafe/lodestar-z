//! Repo-wide lint rules that `zig fmt` cannot express.
//!
//! Run with `zig build test:tidy`.
//!
//! These rules guard test discovery. Zig only collects tests from files reached
//! through an analyzed `test` block, so a test file that nothing imports
//! compiles cleanly, runs nothing, and still reports success. That failure is
//! invisible in CI, which makes it worth a lint rather than a code review.
//!
//! Every rule reports all of its violations before failing, so one run shows the
//! full list instead of only the first item.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;

/// Upper bounds. The lint walks a source tree of known size, and these keep a
/// runaway walk or a pathological file from turning a lint into an OOM.
const max_source_files = 2048;
const max_file_bytes: std.Io.Limit = .limited(8 << 20);

/// A module may keep tests inline up to these limits. Past either one the tests
/// belong in a sibling `<module>_test.zig`. Documented in AGENTS.md.
const max_inline_test_lines = 100;
const max_inline_test_count = 8;

/// Files that deliberately keep their tests inline. Their tests exercise private
/// declarations that a sibling `_test.zig` cannot reach, and widening those
/// declarations to `pub` purely to relocate a test is not a trade worth making.
///
/// `tidy: inline test allowlist is current` fails when an entry stops needing
/// the exemption, so this list cannot quietly rot into a blanket exclusion.
const inline_test_allowlist = [_][]const u8{
    // Private methods on a public struct: destroyState.
    "src/beacon_node/chain/state_cache/block_state_cache.zig",
    // Private cgroup v1/v2 parsers: parseCpuV1, parseCpuMaxV2, translate.
    "src/cpu_count.zig",
    // Private methods on ForkChoice: updateHead, addLatestMessage, getProposerHead.
    "src/fork_choice/fork_choice.zig",
    // Private method on ProtoArray: init.
    "src/fork_choice/proto_array.zig",
    // Private helper: compatibleUnionOptionsAreCompatible.
    "src/ssz/type/compatible_union.zig",
    // Private diff internals: findModifiedValidators, loadValidators.
    "src/state_transition/load_state.zig",
    // Private helper: ComputeShuffledIndex.
    "src/state_transition/utils/committee_indices.zig",
};

/// Test files that cover a whole module rather than one sibling module. These
/// are wired from the package `root.zig` instead of from a paired file.
const module_wide_test_files = [_][]const u8{
    "memory_safety_test.zig",
};

const Source = struct {
    /// Repo-relative, always `/`-separated.
    path: []const u8,
    /// Directory portion of `path`, without a trailing separator.
    dir: []const u8,
    basename: []const u8,
    text: []const u8,
};

/// Collects every violation so a single run reports the complete list.
const Report = struct {
    arena: Allocator,
    lines: std.ArrayList([]const u8) = .empty,

    fn add(self: *Report, comptime fmt: []const u8, args: anytype) !void {
        const line = try std.fmt.allocPrint(self.arena, fmt, args);
        try self.lines.append(self.arena, line);
    }

    fn finish(self: *Report, rule: []const u8, fix: []const u8) !void {
        if (self.lines.items.len == 0) return;
        std.debug.print("\n{s}: {d} violation(s)\n", .{ rule, self.lines.items.len });
        for (self.lines.items) |line| std.debug.print("  {s}\n", .{line});
        std.debug.print("  fix: {s}\n\n", .{fix});
        return error.TidyViolation;
    }
};

/// Loads every `.zig` file under `src/`, plus the repo files the rules inspect.
///
/// Fails loudly when the working directory is not the repo root. A lint that
/// silently finds no files to check is the exact failure these rules exist to
/// prevent.
fn loadSources(arena: Allocator, io: std.Io) ![]Source {
    const cwd: std.Io.Dir = .cwd();
    _ = cwd.statFile(io, "build.zig.zon", .{}) catch |err| switch (err) {
        error.FileNotFound => {
            std.debug.print(
                "tidy must run from the repository root (no build.zig.zon in the " ++
                    "working directory). Use `zig build test:tidy`.\n",
                .{},
            );
            return error.NotRepoRoot;
        },
        else => return err,
    };

    var src_dir = try cwd.openDir(io, "src", .{ .iterate = true });
    defer src_dir.close(io);

    var sources: std.ArrayList(Source) = .empty;
    var walker = try src_dir.walk(arena);
    defer walker.deinit();

    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.basename, ".zig")) continue;

        std.debug.assert(sources.items.len < max_source_files);
        const path = try std.fmt.allocPrint(arena, "src/{s}", .{entry.path});
        std.mem.replaceScalar(u8, path, std.fs.path.sep, '/');

        const text = try cwd.readFileAlloc(io, path, arena, max_file_bytes);
        const dir = std.fs.path.dirnamePosix(path) orelse "";
        try sources.append(arena, .{
            .path = path,
            .dir = dir,
            .basename = std.fs.path.basenamePosix(path),
            .text = text,
        });
    }

    // A source tree this size never legitimately reads as empty.
    std.debug.assert(sources.items.len > 0);
    return sources.items;
}

fn readRepoFile(arena: Allocator, io: std.Io, path: []const u8) ![]const u8 {
    const cwd: std.Io.Dir = .cwd();
    return cwd.readFileAlloc(io, path, arena, max_file_bytes);
}

fn isTestFile(basename: []const u8) bool {
    return std.mem.endsWith(u8, basename, "_test.zig");
}

fn isModuleWide(basename: []const u8) bool {
    for (module_wide_test_files) |name| {
        if (std.mem.eql(u8, basename, name)) return true;
    }
    return false;
}

fn inAllowlist(path: []const u8) bool {
    for (inline_test_allowlist) |allowed| {
        if (std.mem.eql(u8, path, allowed)) return true;
    }
    return false;
}

fn find(sources: []const Source, path: []const u8) ?*const Source {
    for (sources) |*source| {
        if (std.mem.eql(u8, source.path, path)) return source;
    }
    return null;
}

/// True when `text` declares at least one top-level `test` block.
fn hasTestBlock(text: []const u8) bool {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (startsTestBlock(line)) return true;
    }
    return false;
}

/// A `test` block declaration only ever starts at column zero, which keeps this
/// from matching the word `test` inside a comment, string, or nested scope.
fn startsTestBlock(line: []const u8) bool {
    if (!std.mem.startsWith(u8, line, "test")) return false;
    if (line.len == 4) return true;
    return line[4] == ' ' or line[4] == '{';
}

const InlineTests = struct { lines: usize, count: usize };

/// Measures the top-level `test` blocks in `text` by brace depth.
fn measureInlineTests(text: []const u8) InlineTests {
    var result: InlineTests = .{ .lines = 0, .count = 0 };
    var depth: isize = 0;
    var inside = false;

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (!inside) {
            if (!startsTestBlock(line)) continue;
            inside = true;
            result.count += 1;
            result.lines += 1;
            depth = braceDelta(line);
            if (depth <= 0) inside = false;
            continue;
        }
        result.lines += 1;
        depth += braceDelta(line);
        if (depth <= 0) inside = false;
    }
    return result;
}

fn braceDelta(line: []const u8) isize {
    var delta: isize = 0;
    for (line) |c| {
        if (c == '{') delta += 1;
        if (c == '}') delta -= 1;
    }
    return delta;
}

/// True when `text` contains `@import("...basename")`, with or without a
/// leading `./` or directory prefix.
fn importsBasename(text: []const u8, basename: []const u8) bool {
    var rest = text;
    while (std.mem.indexOf(u8, rest, "@import(\"")) |at| {
        rest = rest[at + "@import(\"".len ..];
        const end = std.mem.indexOfScalar(u8, rest, '"') orelse return false;
        const arg = rest[0..end];
        if (std.mem.eql(u8, std.fs.path.basenamePosix(arg), basename)) return true;
        rest = rest[end..];
    }
    return false;
}

/// The module a `<stem>_test.zig` file pairs with, as a sibling file name.
/// Accepts the snake_case form and the TitleCase form, since a file that is
/// itself a type keeps its TitleCase name (`Node.zig` pairs `node_test.zig`).
fn pairedModule(arena: Allocator, stem: []const u8, which: enum { snake, title }) ![]const u8 {
    if (which == .snake) return std.fmt.allocPrint(arena, "{s}.zig", .{stem});

    var out: std.ArrayList(u8) = .empty;
    var parts = std.mem.splitScalar(u8, stem, '_');
    while (parts.next()) |part| {
        if (part.len == 0) continue;
        try out.append(arena, std.ascii.toUpper(part[0]));
        try out.appendSlice(arena, part[1..]);
    }
    try out.appendSlice(arena, ".zig");
    return out.items;
}

test "tidy: every _test.zig is imported by something" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const sources = try loadSources(arena, testing.io);
    var report: Report = .{ .arena = arena };

    for (sources) |source| {
        if (!isTestFile(source.basename)) continue;
        var imported = false;
        for (sources) |other| {
            if (std.mem.eql(u8, other.path, source.path)) continue;
            if (importsBasename(other.text, source.basename)) {
                imported = true;
                break;
            }
        }
        if (!imported) try report.add("{s} is imported by no other file", .{source.path});
    }

    try report.finish(
        "tidy: orphan test file",
        "add `test { _ = @import(\"<name>_test.zig\"); }` to the module it covers; " ++
            "an unimported test file compiles but runs nothing",
    );
}

test "tidy: every _test.zig pairs with a module" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const sources = try loadSources(arena, testing.io);
    var report: Report = .{ .arena = arena };

    for (sources) |source| {
        if (!isTestFile(source.basename)) continue;
        if (isModuleWide(source.basename)) continue;

        const stem = source.basename[0 .. source.basename.len - "_test.zig".len];
        const snake = try pairedModule(arena, stem, .snake);
        const title = try pairedModule(arena, stem, .title);

        const snake_path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ source.dir, snake });
        const title_path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ source.dir, title });

        if (find(sources, snake_path) == null and find(sources, title_path) == null) {
            try report.add(
                "{s} has no sibling module ({s} or {s})",
                .{ source.path, snake, title },
            );
        }
    }

    try report.finish(
        "tidy: unpaired test file",
        "name a test file after the module it covers, or add it to " ++
            "module_wide_test_files if it covers the whole module",
    );
}

test "tidy: every _test.zig is wired from the module it covers" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const sources = try loadSources(arena, testing.io);
    var report: Report = .{ .arena = arena };

    for (sources) |source| {
        if (!isTestFile(source.basename)) continue;

        if (isModuleWide(source.basename)) {
            // Module-wide files belong to the package, so the package root wires them.
            const root_path = try std.fmt.allocPrint(arena, "{s}/root.zig", .{source.dir});
            const root = find(sources, root_path) orelse {
                try report.add("{s} has no {s} to wire it", .{ source.path, root_path });
                continue;
            };
            if (!importsBasename(root.text, source.basename)) {
                try report.add("{s} is not imported by {s}", .{ source.path, root_path });
            }
            continue;
        }

        const stem = source.basename[0 .. source.basename.len - "_test.zig".len];
        const snake = try pairedModule(arena, stem, .snake);
        const title = try pairedModule(arena, stem, .title);
        const snake_path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ source.dir, snake });
        const title_path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ source.dir, title });

        const pair = find(sources, snake_path) orelse find(sources, title_path) orelse continue;
        if (!importsBasename(pair.text, source.basename)) {
            try report.add("{s} is not imported by {s}", .{ source.path, pair.path });
        }
    }

    try report.finish(
        "tidy: test file wired elsewhere",
        "wire the import from the module under test, not from a package root, " ++
            "so the pairing survives moving or deleting the module",
    );
}

test "tidy: a root.zig whose siblings have tests declares a test block" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const sources = try loadSources(arena, testing.io);
    var report: Report = .{ .arena = arena };

    for (sources) |root| {
        if (!std.mem.eql(u8, root.basename, "root.zig")) continue;
        if (hasTestBlock(root.text)) continue;

        for (sources) |sibling| {
            if (!std.mem.eql(u8, sibling.dir, root.dir)) continue;
            if (std.mem.eql(u8, sibling.path, root.path)) continue;
            if (!hasTestBlock(sibling.text)) continue;

            try report.add(
                "{s} has no test block, but {s} has tests",
                .{ root.path, sibling.path },
            );
            break;
        }
    }

    try report.finish(
        "tidy: unreachable tests",
        "add `test { _ = @import(\"<file>.zig\"); }` to the root; re-exporting a " ++
            "file with `pub const` does not pull in its tests",
    );
}

test "tidy: every declared test module runs in CI" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const zon = try readRepoFile(arena, testing.io, "build.zig.zon");
    const ci = try readRepoFile(arena, testing.io, ".github/workflows/CI.yml");
    var report: Report = .{ .arena = arena };

    const tests_marker = ".tests = .{";
    const tests_at = std.mem.indexOf(u8, zon, tests_marker) orelse return error.NoTestsBlock;
    const rest = zon[tests_at + tests_marker.len ..];

    // Entries sit one level inside `.tests`, so track depth and read names at depth 0.
    var depth: isize = 0;
    var lines = std.mem.splitScalar(u8, rest, '\n');
    var count: usize = 0;
    while (lines.next()) |line| {
        if (depth == 0) {
            const trimmed = std.mem.trim(u8, line, " \t");
            if (std.mem.startsWith(u8, trimmed, ".") and
                std.mem.indexOf(u8, trimmed, "= .{") != null)
            {
                const name_end = std.mem.indexOfScalar(u8, trimmed[1..], ' ') orelse continue;
                const name = trimmed[1 .. 1 + name_end];
                count += 1;

                const needle = try std.fmt.allocPrint(arena, "zig build test:{s}", .{name});
                if (std.mem.indexOf(u8, ci, needle) == null) {
                    try report.add("module `{s}` has no `{s}` step in CI.yml", .{ name, needle });
                }
            }
        }
        depth += braceDelta(line);
        if (depth < 0) break; // closed `.tests`
    }

    std.debug.assert(count > 0);
    try report.finish(
        "tidy: module not covered by CI",
        "add a `zig build test:<module>` step to .github/workflows/CI.yml, " ++
            "otherwise the module's tests never run on a pull request",
    );
}

test "tidy: bulky inline tests live in a sibling _test.zig" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const sources = try loadSources(arena, testing.io);
    var report: Report = .{ .arena = arena };

    for (sources) |source| {
        if (isTestFile(source.basename)) continue;
        if (inAllowlist(source.path)) continue;

        const inline_tests = measureInlineTests(source.text);
        if (inline_tests.lines > max_inline_test_lines or
            inline_tests.count > max_inline_test_count)
        {
            try report.add(
                "{s} keeps {d} test lines in {d} tests inline (limit {d} lines / {d} tests)",
                .{
                    source.path,
                    inline_tests.lines,
                    inline_tests.count,
                    max_inline_test_lines,
                    max_inline_test_count,
                },
            );
        }
    }

    try report.finish(
        "tidy: bulky inline tests",
        "move them to a sibling `<module>_test.zig` and wire it with " ++
            "`test { _ = @import(\"<module>_test.zig\"); }`",
    );
}

test "tidy: inline test allowlist is current" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const sources = try loadSources(arena, testing.io);
    var report: Report = .{ .arena = arena };

    for (inline_test_allowlist) |allowed| {
        const source = find(sources, allowed) orelse {
            try report.add("{s} is allowlisted but does not exist", .{allowed});
            continue;
        };
        const inline_tests = measureInlineTests(source.text);
        if (inline_tests.lines <= max_inline_test_lines and
            inline_tests.count <= max_inline_test_count)
        {
            try report.add(
                "{s} is allowlisted but no longer exceeds the limit ({d} lines, {d} tests)",
                .{ allowed, inline_tests.lines, inline_tests.count },
            );
        }
    }

    try report.finish(
        "tidy: stale allowlist entry",
        "remove the entry from inline_test_allowlist; an exemption that outlives " ++
            "its reason turns the allowlist into a blanket exclusion",
    );
}
