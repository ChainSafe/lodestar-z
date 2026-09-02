//! Repo-wide lint rules that `zig fmt` cannot express.
//!
//! Run with `zig build test:tidy`.
//!
//! These rules guard test discovery. Zig only collects tests from files reached
//! through an analyzed `test` block, so a test file that nothing imports
//! compiles cleanly, runs nothing, and still reports success. That failure is
//! invisible in CI, which makes it worth a lint rather than a code review.
//!
//! Rules read the parsed AST rather than raw lines, so a brace or the word
//! `test` inside a comment or string literal cannot skew them. Every rule
//! reports all of its violations before failing, so one run shows the full list
//! instead of only the first item. Each rule also has a test below that feeds it
//! synthetic source and asserts the exact diagnostics, so a rule that stops
//! catching anything fails here rather than going quiet.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Ast = std.zig.Ast;
const assert = std.debug.assert;

/// Upper bounds. The lint walks a source tree of known size, and these keep a
/// runaway walk or a pathological file from turning a lint into an OOM.
const max_tracked_files = 4096;
const max_file_bytes: std.Io.Limit = .limited(8 << 20);
const max_git_output_bytes = 4 << 20;

/// A module may keep tests inline up to these limits. Past either one the tests
/// belong in a sibling `<module>_test.zig`. Documented in AGENTS.md.
const max_inline_test_lines = 100;
const max_inline_test_count = 8;

/// Files that deliberately keep their tests inline. Their tests exercise private
/// declarations that a sibling `_test.zig` cannot reach, and widening those
/// declarations to `pub` purely to relocate a test is not a trade worth making.
///
/// `stale allowlist entry` fails when an entry stops needing the exemption, so
/// this list cannot quietly rot into a blanket exclusion.
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

/// Files that nothing imports on purpose. Entry points reached by the build
/// system rather than by an `@import`, so the dead-file rule cannot see them.
const unimported_file_allowlist = [_][]const u8{
    // Narrow roots for running one subtree's tests without compiling the rest.
    "src/state_transition/block_test_root.zig",
    "src/state_transition/utils_test_root.zig",
};

/// Confirmed dead code, listed only so this lint stays green until the removal
/// lands. Delete the file and its entry together; do not grow this list.
const dead_file_removal_pending = [_][]const u8{
    // Unfinished scratch from `cdd7a832 feat: refactor (#21)`. Nothing references
    // `Serialized`, and its test block still has debug prints and a stray `s.foo`.
    "src/ssz/type/serialized.zig",
    // Orphaned by `2515713d feat: use high level zapi dsl (#320)`, which replaced
    // manual property descriptors with the zapi DSL.
    "bindings/napi/napi_property_descriptor.zig",
};

/// Rule scoping.
///
/// Wiring and discovery rules run repo-wide, because a test that never runs is
/// a defect anywhere. The other two are narrower on purpose:
///
///   - Dead-file detection covers shipped code only. Elsewhere, entry points are
///     declared programmatically (`test/fuzz/build.zig` builds its target paths
///     with `fmt`) or reached from generated sources, and neither is visible to
///     static analysis.
///   - The inline test limit is about keeping implementation files readable, so
///     it does not apply to trees that are themselves tests.
const dead_file_scope = [_][]const u8{ "src/", "bindings/" };
const inline_test_scope = [_][]const u8{"src/"};

// -------------------------------------------------------------------------
// Diagnostics
// -------------------------------------------------------------------------

/// Accumulates diagnostics so a run reports every violation rather than the
/// first. Formats as `path:line: error: ...` so editors and CI can parse them.
const Errors = struct {
    gpa: Allocator,
    count: u32 = 0,
    /// Set by the rule tests below to assert exact output.
    captured: ?*std.ArrayList(u8) = null,

    fn emit(errors: *Errors, comptime fmt: []const u8, args: anytype) void {
        comptime assert(fmt[fmt.len - 1] == '\n');
        errors.count += 1;
        if (errors.captured) |captured| {
            const line = std.fmt.allocPrint(errors.gpa, fmt, args) catch @panic("OOM");
            defer errors.gpa.free(line);
            captured.appendSlice(errors.gpa, line) catch @panic("OOM");
        } else {
            std.debug.print(fmt, args);
        }
    }

    fn addParseError(errors: *Errors, path: []const u8, line: usize) void {
        errors.emit("{s}:{d}: error: cannot parse file\n", .{ path, line });
    }

    fn addOrphanTestFile(errors: *Errors, path: []const u8) void {
        errors.emit(
            "{s}: error: test file is imported by nothing, so its tests never run\n",
            .{path},
        );
    }

    fn addUnpairedTestFile(errors: *Errors, path: []const u8, expected: []const u8) void {
        errors.emit(
            "{s}: error: no sibling module to pair with, expected {s}\n",
            .{ path, expected },
        );
    }

    fn addTestFileWiredElsewhere(errors: *Errors, path: []const u8, expected: []const u8) void {
        errors.emit(
            "{s}: error: not imported by {s}, wire it from the module under test\n",
            .{ path, expected },
        );
    }

    fn addRootMissingTestBlock(errors: *Errors, path: []const u8, sibling: []const u8) void {
        errors.emit(
            "{s}: error: no test block, but {s} has tests that will not run\n",
            .{ path, sibling },
        );
    }

    fn addDeadFile(errors: *Errors, path: []const u8) void {
        errors.emit("{s}: error: file is imported by nothing\n", .{path});
    }

    fn addModuleNotInCi(errors: *Errors, module: []const u8) void {
        errors.emit(
            "build.zig.zon: error: module `{s}` has no `zig build test:{s}` step in CI\n",
            .{ module, module },
        );
    }

    fn addBulkyInlineTests(
        errors: *Errors,
        path: []const u8,
        line: usize,
        lines: usize,
        count: usize,
    ) void {
        errors.emit(
            "{s}:{d}: error: {d} test lines in {d} tests inline, limit is {d} lines / {d} tests\n",
            .{ path, line, lines, count, max_inline_test_lines, max_inline_test_count },
        );
    }

    fn addStaleAllowlistEntry(errors: *Errors, path: []const u8, reason: []const u8) void {
        errors.emit("{s}: error: allowlisted but {s}\n", .{ path, reason });
    }
};

// -------------------------------------------------------------------------
// Source model
// -------------------------------------------------------------------------

const InlineTests = struct {
    lines: usize = 0,
    count: usize = 0,
    /// One-based line of the first `test` declaration, for the diagnostic.
    first_line: usize = 0,
};

/// One analyzed file. Everything a rule needs is extracted during the single
/// load pass, so no rule re-reads or re-parses.
const File = struct {
    path: []const u8,
    dir: []const u8,
    basename: []const u8,
    /// `@import` targets, taken from the token stream, so a commented-out or
    /// stringified import is not mistaken for a real one.
    imports: []const []const u8,
    inline_tests: InlineTests,

    fn hasTestBlock(file: File) bool {
        return file.inline_tests.count > 0;
    }

    fn importsBasename(file: File, basename: []const u8) bool {
        for (file.imports) |import| {
            if (std.mem.eql(u8, std.fs.path.basenamePosix(import), basename)) return true;
        }
        return false;
    }
};

/// Parses one file and extracts everything the rules need.
fn analyze(gpa: Allocator, path: []const u8, text: [:0]const u8, errors: *Errors) !File {
    var tree = try Ast.parse(gpa, text, .zig);
    defer tree.deinit(gpa);

    if (tree.errors.len > 0) {
        const location = tree.tokenLocation(0, tree.errors[0].token);
        errors.addParseError(path, location.line + 1);
    }

    var imports: std.ArrayList([]const u8) = .empty;
    const token_tags = tree.tokens.items(.tag);
    for (token_tags, 0..) |tag, index| {
        if (tag != .builtin) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(@intCast(index)), "@import")) continue;
        if (index + 2 >= token_tags.len) continue;
        if (token_tags[index + 1] != .l_paren) continue;
        if (token_tags[index + 2] != .string_literal) continue;

        const literal = tree.tokenSlice(@intCast(index + 2));
        assert(literal.len >= 2);
        try imports.append(gpa, try gpa.dupe(u8, literal[1 .. literal.len - 1]));
    }

    var inline_tests: InlineTests = .{};
    for (tree.rootDecls()) |node| {
        if (tree.nodeTag(node) != .test_decl) continue;
        const line_first = tree.tokenLocation(0, tree.firstToken(node)).line + 1;
        const line_last = tree.tokenLocation(0, tree.lastToken(node)).line + 1;
        assert(line_last >= line_first);

        inline_tests.count += 1;
        inline_tests.lines += line_last - line_first + 1;
        if (inline_tests.first_line == 0) inline_tests.first_line = line_first;
    }

    return .{
        .path = path,
        .dir = std.fs.path.dirnamePosix(path) orelse "",
        .basename = std.fs.path.basenamePosix(path),
        .imports = imports.items,
        .inline_tests = inline_tests,
    };
}

/// Lists the repository's tracked `.zig` files.
///
/// Uses `git ls-files` rather than a directory walk so the lint sees exactly
/// what is committed: no build output, no vendored packages, no generated spec
/// tests, and no untracked scratch files.
fn listTrackedZigFiles(gpa: Allocator, io: std.Io) ![]const []const u8 {
    const result = std.process.run(gpa, io, .{
        .argv = &.{ "git", "ls-files", "-z", "--", "*.zig" },
    }) catch |err| {
        std.debug.print(
            "tidy could not run `git ls-files` ({s}). Run it from a git checkout " ++
                "with `zig build test:tidy`.\n",
            .{@errorName(err)},
        );
        return err;
    };
    defer gpa.free(result.stderr);
    defer gpa.free(result.stdout);

    if (result.term != .exited or result.term.exited != 0) return error.GitFailed;
    if (result.stdout.len > max_git_output_bytes) return error.GitOutputTooLarge;

    var paths: std.ArrayList([]const u8) = .empty;
    var entries = std.mem.splitScalar(u8, result.stdout, 0);
    while (entries.next()) |entry| {
        if (entry.len == 0) continue;
        assert(paths.items.len < max_tracked_files);
        try paths.append(gpa, try gpa.dupe(u8, entry));
    }

    // A git checkout of this repository always has Zig sources.
    if (paths.items.len == 0) return error.NoTrackedSources;
    return paths.items;
}

fn loadRepo(gpa: Allocator, io: std.Io, errors: *Errors) ![]const File {
    const paths = try listTrackedZigFiles(gpa, io);
    const cwd: std.Io.Dir = .cwd();

    var files: std.ArrayList(File) = .empty;
    for (paths) |path| {
        // A tracked file missing from the working tree is a normal intermediate
        // state, such as a `git rm` that is not committed yet. Skip it rather
        // than failing the lint with a file-system error.
        const text = cwd.readFileAllocOptions(
            io,
            path,
            gpa,
            max_file_bytes,
            .of(u8),
            0,
        ) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        try files.append(gpa, try analyze(gpa, path, text, errors));
    }
    return files.items;
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

fn isTestFile(basename: []const u8) bool {
    return std.mem.endsWith(u8, basename, "_test.zig");
}

fn isModuleWide(basename: []const u8) bool {
    for (module_wide_test_files) |name| {
        if (std.mem.eql(u8, basename, name)) return true;
    }
    return false;
}

fn inScope(scope: []const []const u8, path: []const u8) bool {
    for (scope) |prefix| {
        if (std.mem.startsWith(u8, path, prefix)) return true;
    }
    return false;
}

fn listContains(list: []const []const u8, path: []const u8) bool {
    for (list) |entry| {
        if (std.mem.eql(u8, entry, path)) return true;
    }
    return false;
}

fn findFile(files: []const File, path: []const u8) ?*const File {
    for (files) |*file| {
        if (std.mem.eql(u8, file.path, path)) return file;
    }
    return null;
}

/// The sibling module a `<stem>_test.zig` pairs with. Accepts the snake_case
/// name and the TitleCase name, since a file that is itself a type keeps its
/// TitleCase name: `Node.zig` pairs with `node_test.zig`.
fn pairedModule(
    gpa: Allocator,
    dir: []const u8,
    stem: []const u8,
    style: enum { snake, title },
) ![]const u8 {
    var name: std.ArrayList(u8) = .empty;
    if (dir.len > 0) {
        try name.appendSlice(gpa, dir);
        try name.append(gpa, '/');
    }
    switch (style) {
        .snake => try name.appendSlice(gpa, stem),
        .title => {
            var parts = std.mem.splitScalar(u8, stem, '_');
            while (parts.next()) |part| {
                if (part.len == 0) continue;
                try name.append(gpa, std.ascii.toUpper(part[0]));
                try name.appendSlice(gpa, part[1..]);
            }
        },
    }
    try name.appendSlice(gpa, ".zig");
    return name.items;
}

// -------------------------------------------------------------------------
// Rules
// -------------------------------------------------------------------------

/// Every `_test.zig` must be imported, must pair with a module of the same
/// name, and must be wired from that module rather than from a package root.
fn tidyTestFileWiring(gpa: Allocator, files: []const File, errors: *Errors) !void {
    for (files) |file| {
        if (!isTestFile(file.basename)) continue;

        var imported = false;
        for (files) |other| {
            if (std.mem.eql(u8, other.path, file.path)) continue;
            if (other.importsBasename(file.basename)) {
                imported = true;
                break;
            }
        }
        if (!imported) {
            errors.addOrphanTestFile(file.path);
            continue;
        }

        if (isModuleWide(file.basename)) {
            // Module-wide files belong to the package, so the package root wires them.
            const root_path = try pairedModule(gpa, file.dir, "root", .snake);
            const root = findFile(files, root_path) orelse {
                errors.addUnpairedTestFile(file.path, root_path);
                continue;
            };
            if (!root.importsBasename(file.basename)) {
                errors.addTestFileWiredElsewhere(file.path, root_path);
            }
            continue;
        }

        const stem = file.basename[0 .. file.basename.len - "_test.zig".len];
        const snake = try pairedModule(gpa, file.dir, stem, .snake);
        const title = try pairedModule(gpa, file.dir, stem, .title);

        const pair = findFile(files, snake) orelse findFile(files, title) orelse {
            errors.addUnpairedTestFile(file.path, snake);
            continue;
        };
        if (!pair.importsBasename(file.basename)) {
            errors.addTestFileWiredElsewhere(file.path, pair.path);
        }
    }
}

/// A `root.zig` whose siblings have tests must declare a `test` block. Without
/// one those tests are never collected, because re-exporting a file with
/// `pub const` does not pull in its tests.
fn tidyRootTestBlocks(files: []const File, errors: *Errors) void {
    for (files) |root| {
        if (!std.mem.eql(u8, root.basename, "root.zig")) continue;
        if (root.hasTestBlock()) continue;

        for (files) |sibling| {
            if (!std.mem.eql(u8, sibling.dir, root.dir)) continue;
            if (std.mem.eql(u8, sibling.path, root.path)) continue;
            if (!sibling.hasTestBlock()) continue;

            errors.addRootMissingTestBlock(root.path, sibling.path);
            break;
        }
    }
}

/// Zig's lazy compilation hides files that nothing imports: the compiler never
/// sees them, so it cannot report them as unused, and any tests they hold are
/// silently skipped.
fn tidyDeadFiles(
    files: []const File,
    roots: []const []const u8,
    scope: []const []const u8,
    errors: *Errors,
) void {
    for (files) |file| {
        if (!inScope(scope, file.path)) continue;
        if (listContains(&unimported_file_allowlist, file.path)) continue;
        if (listContains(&dead_file_removal_pending, file.path)) continue;
        if (listContains(roots, file.path)) continue;

        var imported = false;
        for (files) |other| {
            if (std.mem.eql(u8, other.path, file.path)) continue;
            if (other.importsBasename(file.basename)) {
                imported = true;
                break;
            }
        }
        if (!imported) errors.addDeadFile(file.path);
    }
}

/// No file keeps more tests inline than the limits allow.
fn tidyInlineTests(files: []const File, scope: []const []const u8, errors: *Errors) void {
    for (files) |file| {
        if (!inScope(scope, file.path)) continue;
        if (isTestFile(file.basename)) continue;
        if (listContains(&inline_test_allowlist, file.path)) continue;

        const inline_tests = file.inline_tests;
        if (inline_tests.lines > max_inline_test_lines or
            inline_tests.count > max_inline_test_count)
        {
            errors.addBulkyInlineTests(
                file.path,
                inline_tests.first_line,
                inline_tests.lines,
                inline_tests.count,
            );
        }
    }
}

/// An exemption that outlives its reason turns an allowlist into a blanket
/// exclusion, so every entry has to still need it.
fn tidyAllowlists(files: []const File, errors: *Errors) void {
    for (inline_test_allowlist) |allowed| {
        const file = findFile(files, allowed) orelse {
            errors.addStaleAllowlistEntry(allowed, "the file does not exist");
            continue;
        };
        if (file.inline_tests.lines <= max_inline_test_lines and
            file.inline_tests.count <= max_inline_test_count)
        {
            errors.addStaleAllowlistEntry(allowed, "it no longer exceeds the inline test limit");
        }
    }
    for (unimported_file_allowlist) |allowed| {
        if (findFile(files, allowed) == null) {
            errors.addStaleAllowlistEntry(allowed, "the file does not exist");
        }
    }
    for (dead_file_removal_pending) |allowed| {
        if (findFile(files, allowed) == null) {
            errors.addStaleAllowlistEntry(allowed, "the file is already gone, drop the entry");
        }
    }
}

/// Every module declared in `build.zig.zon` must have a CI step, otherwise its
/// tests never run on a pull request.
fn tidyCiCoverage(gpa: Allocator, zon: []const u8, ci: []const u8, errors: *Errors) !void {
    const modules = try declaredTestModules(gpa, zon);
    for (modules) |module| {
        const needle = try std.fmt.allocPrint(gpa, "zig build test:{s}", .{module});
        if (std.mem.indexOf(u8, ci, needle) == null) errors.addModuleNotInCi(module);
    }
}

/// Names declared one level inside `build.zig.zon`'s `.tests` block.
fn declaredTestModules(gpa: Allocator, zon: []const u8) ![]const []const u8 {
    const marker = ".tests = .{";
    const start = std.mem.indexOf(u8, zon, marker) orelse return error.NoTestsBlock;

    var modules: std.ArrayList([]const u8) = .empty;
    var depth: isize = 0;
    var lines = std.mem.splitScalar(u8, zon[start + marker.len ..], '\n');
    while (lines.next()) |line| {
        if (depth == 0) {
            const trimmed = std.mem.trim(u8, line, " \t");
            if (std.mem.startsWith(u8, trimmed, ".") and
                std.mem.indexOf(u8, trimmed, "= .{") != null)
            {
                if (std.mem.indexOfScalar(u8, trimmed[1..], ' ')) |end| {
                    try modules.append(gpa, trimmed[1 .. 1 + end]);
                }
            }
        }
        for (line) |c| {
            if (c == '{') depth += 1;
            if (c == '}') depth -= 1;
        }
        if (depth < 0) break; // closed `.tests`
    }
    return modules.items;
}

/// Root source files declared in `build.zig.zon`. The build reaches these
/// directly, so nothing needs to import them.
fn declaredRoots(gpa: Allocator, zon: []const u8) ![]const []const u8 {
    var roots: std.ArrayList([]const u8) = .empty;
    const marker = "root_source_file = \"";
    var rest = zon;
    while (std.mem.indexOf(u8, rest, marker)) |at| {
        rest = rest[at + marker.len ..];
        const end = std.mem.indexOfScalar(u8, rest, '"') orelse break;
        try roots.append(gpa, rest[0..end]);
        rest = rest[end..];
    }
    return roots.items;
}

// -------------------------------------------------------------------------
// Entry point
// -------------------------------------------------------------------------

test "tidy" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = testing.io;

    var errors: Errors = .{ .gpa = arena };

    const files = try loadRepo(arena, io, &errors);
    const cwd: std.Io.Dir = .cwd();
    const zon = try cwd.readFileAlloc(io, "build.zig.zon", arena, max_file_bytes);
    const ci = try cwd.readFileAlloc(io, ".github/workflows/CI.yml", arena, max_file_bytes);
    const roots = try declaredRoots(arena, zon);

    try tidyTestFileWiring(arena, files, &errors);
    tidyRootTestBlocks(files, &errors);
    tidyDeadFiles(files, roots, &dead_file_scope, &errors);
    tidyInlineTests(files, &inline_test_scope, &errors);
    tidyAllowlists(files, &errors);
    try tidyCiCoverage(arena, zon, ci, &errors);

    if (errors.count > 0) {
        std.debug.print(
            "\n{d} tidy violation(s). See AGENTS.md `Test file layout` for the rules.\n",
            .{errors.count},
        );
        return error.Untidy;
    }
}

// -------------------------------------------------------------------------
// Rule tests
//
// Each feeds a rule synthetic sources and asserts the exact diagnostics, so a
// rule that silently stops catching anything fails here.
// -------------------------------------------------------------------------

const SourceLiteral = struct { []const u8, [:0]const u8 };

/// Builds an in-memory file set so rules can run without touching the repo.
fn analyzeAll(gpa: Allocator, sources: []const SourceLiteral, errors: *Errors) ![]const File {
    var files: std.ArrayList(File) = .empty;
    for (sources) |source| {
        const path, const text = source;
        try files.append(gpa, try analyze(gpa, path, text, errors));
    }
    return files.items;
}

fn expectDiagnostics(actual: []const u8, expected: []const u8) !void {
    try testing.expectEqualStrings(expected, actual);
}

const Fixture = struct {
    arena_state: std.heap.ArenaAllocator,
    captured: std.ArrayList(u8) = .empty,
    errors: Errors = undefined,

    fn init() Fixture {
        return .{ .arena_state = .init(testing.allocator) };
    }

    fn arena(self: *Fixture) Allocator {
        return self.arena_state.allocator();
    }

    fn start(self: *Fixture) *Errors {
        self.errors = .{ .gpa = self.arena(), .captured = &self.captured };
        return &self.errors;
    }

    fn output(self: *Fixture) []const u8 {
        return self.captured.items;
    }

    fn deinit(self: *Fixture) void {
        self.captured.deinit(self.arena());
        self.arena_state.deinit();
    }
};

test "rule: inline test measurement ignores braces in comments and strings" {
    var fixture: Fixture = .init();
    defer fixture.deinit();
    const errors = fixture.start();

    // Line counting by brace depth reads the `{` in this comment as opening a
    // scope and swallows the second test. The AST does not.
    const file = try analyze(fixture.arena(), "demo.zig",
        \\test "one" {
        \\    // start object "{"
        \\    const x = 1;
        \\    _ = x;
        \\}
        \\
        \\test "two" {
        \\    const y = 2;
        \\    _ = y;
        \\}
        \\
    , errors);

    try testing.expectEqual(@as(usize, 2), file.inline_tests.count);
    // 5 lines for the first test, 4 for the second. Brace counting reports one
    // test of 11 lines here, having read the `{` in the comment as a scope.
    try testing.expectEqual(@as(usize, 9), file.inline_tests.lines);
    try testing.expectEqual(@as(usize, 1), file.inline_tests.first_line);
}

test "rule: import collection ignores commented-out imports" {
    var fixture: Fixture = .init();
    defer fixture.deinit();
    const errors = fixture.start();

    const file = try analyze(fixture.arena(), "demo.zig",
        \\const real = @import("real.zig");
        \\// const fake = @import("fake.zig");
        \\const text = "@import(\"quoted.zig\")";
        \\
    , errors);

    try testing.expect(file.importsBasename("real.zig"));
    try testing.expect(!file.importsBasename("fake.zig"));
    try testing.expect(!file.importsBasename("quoted.zig"));
}

test "rule: orphan test file" {
    var fixture: Fixture = .init();
    defer fixture.deinit();
    const errors = fixture.start();

    const files = try analyzeAll(fixture.arena(), &.{
        .{ "src/foo.zig", "pub const x = 1;\n" },
        .{ "src/foo_test.zig", "test \"t\" {}\n" },
    }, errors);
    try tidyTestFileWiring(fixture.arena(), files, errors);

    try expectDiagnostics(fixture.output(),
        \\src/foo_test.zig: error: test file is imported by nothing, so its tests never run
        \\
    );
}

test "rule: unpaired test file" {
    var fixture: Fixture = .init();
    defer fixture.deinit();
    const errors = fixture.start();

    const files = try analyzeAll(fixture.arena(), &.{
        .{ "src/root.zig", "test { _ = @import(\"ghost_test.zig\"); }\n" },
        .{ "src/ghost_test.zig", "test \"t\" {}\n" },
    }, errors);
    try tidyTestFileWiring(fixture.arena(), files, errors);

    try expectDiagnostics(fixture.output(),
        \\src/ghost_test.zig: error: no sibling module to pair with, expected src/ghost.zig
        \\
    );
}

test "rule: test file wired from a package root instead of its module" {
    var fixture: Fixture = .init();
    defer fixture.deinit();
    const errors = fixture.start();

    const files = try analyzeAll(fixture.arena(), &.{
        .{ "src/root.zig", "test { _ = @import(\"foo_test.zig\"); }\n" },
        .{ "src/foo.zig", "pub const x = 1;\n" },
        .{ "src/foo_test.zig", "test \"t\" {}\n" },
    }, errors);
    try tidyTestFileWiring(fixture.arena(), files, errors);

    try expectDiagnostics(fixture.output(),
        \\src/foo_test.zig: error: not imported by src/foo.zig, wire it from the module under test
        \\
    );
}

test "rule: TitleCase module pairs with a snake_case test file" {
    var fixture: Fixture = .init();
    defer fixture.deinit();
    const errors = fixture.start();

    const files = try analyzeAll(fixture.arena(), &.{
        .{ "src/Node.zig", "test { _ = @import(\"node_test.zig\"); }\n" },
        .{ "src/node_test.zig", "test \"t\" {}\n" },
    }, errors);
    try tidyTestFileWiring(fixture.arena(), files, errors);

    try expectDiagnostics(fixture.output(), "");
}

test "rule: root.zig without a test block hides sibling tests" {
    var fixture: Fixture = .init();
    defer fixture.deinit();
    const errors = fixture.start();

    // This is the era/root.zig bug: re-exporting a file does not collect its tests.
    const files = try analyzeAll(fixture.arena(), &.{
        .{ "src/era/root.zig", "pub const era = @import(\"era.zig\");\n" },
        .{ "src/era/era.zig", "test \"t\" {}\n" },
    }, errors);
    tidyRootTestBlocks(files, errors);

    try expectDiagnostics(fixture.output(),
        \\src/era/root.zig: error: no test block, but src/era/era.zig has tests that will not run
        \\
    );
}

test "rule: dead file" {
    var fixture: Fixture = .init();
    defer fixture.deinit();
    const errors = fixture.start();

    const files = try analyzeAll(fixture.arena(), &.{
        .{ "src/root.zig", "pub const used = @import(\"used.zig\");\n" },
        .{ "src/used.zig", "pub const x = 1;\n" },
        .{ "src/stray.zig", "pub const y = 2;\n" },
    }, errors);
    tidyDeadFiles(files, &.{"src/root.zig"}, &.{"src/"}, errors);

    try expectDiagnostics(fixture.output(),
        \\src/stray.zig: error: file is imported by nothing
        \\
    );
}

test "rule: bulky inline tests" {
    var fixture: Fixture = .init();
    defer fixture.deinit();
    const errors = fixture.start();

    var source: std.ArrayList(u8) = .empty;
    defer source.deinit(testing.allocator);
    try source.appendSlice(testing.allocator, "pub const x = 1;\n");
    for (0..max_inline_test_count + 1) |i| {
        const line = try std.fmt.allocPrint(testing.allocator, "test \"t{d}\" {{}}\n", .{i});
        defer testing.allocator.free(line);
        try source.appendSlice(testing.allocator, line);
    }
    const text = try source.toOwnedSliceSentinel(testing.allocator, 0);
    defer testing.allocator.free(text);

    const files = try analyzeAll(fixture.arena(), &.{.{ "src/bulky.zig", text }}, errors);
    tidyInlineTests(files, &.{"src/"}, errors);

    try expectDiagnostics(fixture.output(),
        \\src/bulky.zig:2: error: 9 test lines in 9 tests inline, limit is 100 lines / 8 tests
        \\
    );
}

test "rule: stale allowlist entry" {
    var fixture: Fixture = .init();
    defer fixture.deinit();
    const errors = fixture.start();

    // Every allowlisted path is missing from this file set, which is what a
    // deleted or renamed file looks like.
    const files = try analyzeAll(fixture.arena(), &.{
        .{ "src/unrelated.zig", "pub const x = 1;\n" },
    }, errors);
    tidyAllowlists(files, errors);

    try testing.expectEqual(
        inline_test_allowlist.len + unimported_file_allowlist.len +
            dead_file_removal_pending.len,
        errors.count,
    );
    try testing.expect(std.mem.indexOf(
        u8,
        fixture.output(),
        "src/cpu_count.zig: error: allowlisted but the file does not exist",
    ) != null);
}

test "rule: module declared but absent from CI" {
    var fixture: Fixture = .init();
    defer fixture.deinit();
    const errors = fixture.start();

    const zon =
        \\    .tests = .{
        \\        .covered = .{ .root_module = .covered },
        \\        .forgotten = .{ .root_module = .forgotten },
        \\    },
    ;
    const ci = "run: zig build test:covered\n";
    try tidyCiCoverage(fixture.arena(), zon, ci, errors);

    try expectDiagnostics(fixture.output(),
        \\build.zig.zon: error: module `forgotten` has no `zig build test:forgotten` step in CI
        \\
    );
}

test "rule: parse errors are reported, not silently skipped" {
    var fixture: Fixture = .init();
    defer fixture.deinit();
    const errors = fixture.start();

    _ = try analyze(fixture.arena(), "broken.zig", "pub fn oops( {\n", errors);
    try testing.expect(errors.count > 0);
    try testing.expect(std.mem.indexOf(u8, fixture.output(), "broken.zig:1: error:") != null);
}
