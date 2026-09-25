//! chainsafe/quiche-zig at 2e0b489, with `patches/send-capacity.patch` applied to the quiche crate
//! before it builds. The patch adds `quiche_conn_send_capacity`, a read-only accessor for the parts
//! of a stream's send capacity. Landing it in chainsafe/quiche-zig and pinning that retires this copy.
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const quiche_dep = b.dependency("quiche", .{});
    const quiche_src = patched(b, quiche_dep.path("."));

    const release = optimize != .Debug;
    const profile_dir = if (release) "release" else "debug";
    const rust_triple = rustTarget(b, target.result);

    const cargo = b.addSystemCommand(&.{
        "cargo",
        "build",
        // Without --quiet, cargo's "Compiling ..." progress messages go to stderr,
        // which Zig's Run step treats as diagnostic output and reports under a
        // misleading "failed command:" header (even though cargo exited cleanly).
        "--quiet",
        "--features",
        "ffi",
        "--target",
        rust_triple,
    });
    if (release) cargo.addArg("--release");
    cargo.addArg("--target-dir");
    cargo.setCwd(quiche_src);
    const cargo_target = cargo.addOutputDirectoryArg("target");

    const lib_subpath = b.fmt("{s}/{s}/libquiche.a", .{ rust_triple, profile_dir });
    const libquiche = cargo_target.path(b, lib_subpath);

    const translate = b.addTranslateC(.{
        .root_source_file = b.path("src/quiche.h"),
        .target = target,
        .optimize = optimize,
    });
    translate.addIncludePath(quiche_src.path(b, "include"));
    translate.addIncludePath(quiche_src.path(b, "deps/boringssl/src/include"));
    const quiche_mod = translate.addModule("quiche");
    // libquiche.a has no C++ stdlib usage, but Rust's std references the Itanium-ABI
    // unwinder (rust_eh_personality, _Unwind_*); link_libcpp pulls libunwind transitively.
    quiche_mod.link_libcpp = true;
    quiche_mod.addObjectFile(libquiche);
}

/// A copy of the quiche crate with the patch applied. The fetched package stays untouched.
fn patched(b: *std.Build, crate: std.Build.LazyPath) std.Build.LazyPath {
    const apply = b.addSystemCommand(&.{ "sh", "-c", "mkdir -p \"$1\" && cp -R \"$0\"/. \"$1\" && chmod -R u+w \"$1\" && patch -s -p1 -d \"$1\" < \"$2\"" });
    apply.addDirectoryArg(crate);
    const copy = apply.addOutputDirectoryArg("quiche");
    apply.addFileArg(b.path("patches/send-capacity.patch"));
    return copy;
}

fn rustTarget(b: *std.Build, t: std.Target) []const u8 {
    const arch = switch (t.cpu.arch) {
        .x86_64 => "x86_64",
        .aarch64 => "aarch64",
        .x86 => "i686",
        .arm => "arm",
        .riscv64 => "riscv64gc",
        else => std.debug.panic("no rust triple mapping for arch {s}", .{@tagName(t.cpu.arch)}),
    };
    return switch (t.os.tag) {
        .linux => if (t.abi.isMusl())
            b.fmt("{s}-unknown-linux-musl", .{arch})
        else
            b.fmt("{s}-unknown-linux-gnu", .{arch}),
        .macos => b.fmt("{s}-apple-darwin", .{arch}),
        .windows => if (t.abi == .gnu)
            b.fmt("{s}-pc-windows-gnu", .{arch})
        else
            b.fmt("{s}-pc-windows-msvc", .{arch}),
        else => std.debug.panic("no rust triple mapping for os {s}", .{@tagName(t.os.tag)}),
    };
}
