const std = @import("std");
const snappy = @import("snappy").raw;

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;

/// Selector byte mapping for each fuzz target.
/// First byte of corpus file selects which SSZ type to test.

// ssz_basic: Bool=0, Uint8=1, Uint16=2, Uint32=3,
//            Uint64=4, Uint128=5, Uint256=6
const uint_selectors = [_]struct { bits: []const u8, sel: u8 }{
    .{ .bits = "8", .sel = 0x01 },
    .{ .bits = "16", .sel = 0x02 },
    .{ .bits = "32", .sel = 0x03 },
    .{ .bits = "64", .sel = 0x04 },
    .{ .bits = "128", .sel = 0x05 },
    .{ .bits = "256", .sel = 0x06 },
};

// ssz_bitlist: BitList(8)=0, BitList(64)=1, BitList(2048)=2
const bitlist_selectors = [_]struct {
    limit: []const u8,
    sel: u8,
}{
    .{ .limit = "1", .sel = 0x00 },
    .{ .limit = "2", .sel = 0x00 },
    .{ .limit = "3", .sel = 0x00 },
    .{ .limit = "4", .sel = 0x00 },
    .{ .limit = "5", .sel = 0x00 },
    .{ .limit = "8", .sel = 0x00 },
    .{ .limit = "16", .sel = 0x01 },
    .{ .limit = "31", .sel = 0x01 },
    .{ .limit = "512", .sel = 0x02 },
    .{ .limit = "513", .sel = 0x02 },
};

// ssz_bitvector: BitVector(4)=0, BitVector(32)=1,
//               BitVector(64)=2
const bitvec_selectors = [_]struct {
    size: []const u8,
    sel: u8,
}{
    .{ .size = "1", .sel = 0x00 },
    .{ .size = "2", .sel = 0x00 },
    .{ .size = "3", .sel = 0x00 },
    .{ .size = "4", .sel = 0x00 },
    .{ .size = "31", .sel = 0x01 },
    .{ .size = "512", .sel = 0x03 },
};

// ssz_containers: consensus types
const container_selectors = [_]struct {
    name: []const u8,
    sel: u8,
}{
    .{ .name = "Fork", .sel = 0x00 },
    .{ .name = "Checkpoint", .sel = 0x01 },
    .{ .name = "AttestationData", .sel = 0x02 },
    .{ .name = "Eth1Data", .sel = 0x03 },
    .{ .name = "BeaconBlockHeader", .sel = 0x04 },
    .{ .name = "Validator", .sel = 0x05 },
    .{ .name = "Attestation", .sel = 0x06 },
    .{ .name = "IndexedAttestation", .sel = 0x07 },
};

/// 4 MiB buffer size — enough for any spec test vector.
const buf_len = 4 * 1024 * 1024;

const spec_version_file_path = "../../test/spec/version.txt";
const spec_version_file_size_max = 1024;
const spec_version_size_max = 64;
const spec_tests_root = "../../test/spec/spec_tests/";
const generic_spec_suffix = "/general/tests/general/phase0/ssz_generic";
const static_spec_suffix = "/minimal/tests/minimal/phase0/ssz_static";
const spec_path_size_max = spec_tests_root.len + spec_version_size_max + @max(
    generic_spec_suffix.len,
    static_spec_suffix.len,
);

fn readSpecVersion(cwd: Dir, io: std.Io, file_buf: []u8) ![]const u8 {
    std.debug.assert(file_buf.len == spec_version_file_size_max + 1);

    const contents = try cwd.readFile(io, spec_version_file_path, file_buf);
    if (contents.len > spec_version_file_size_max) {
        return error.SpecVersionFileTooLong;
    }

    var version: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, contents, '\n');
    for (0..contents.len + 1) |_| {
        const untrimmed_line = lines.next() orelse break;
        const line = std.mem.trim(u8, untrimmed_line, " \t\r");
        if (line.len == 0) continue;
        if (std.mem.startsWith(u8, line, "//")) continue;

        var tokens = std.mem.tokenizeAny(u8, line, " \t\r");
        const token = tokens.next() orelse unreachable;
        if (tokens.next() != null) return error.InvalidSpecVersionLine;
        if (token.len > spec_version_size_max) return error.SpecVersionTooLong;
        if (version != null) return error.MultipleSpecVersions;
        version = token;
    }

    return version orelse error.MissingSpecVersion;
}

/// Read a .ssz_snappy file, decompress it, and return
/// the raw SSZ bytes (slice into decompress_buf).
///
/// Uses separate buffers for compressed and decompressed
/// data to prevent aliasing during decompression.
fn readSnappy(
    dir: Dir,
    io: std.Io,
    path: []const u8,
    read_buf: []u8,
    decompress_buf: []u8,
) ![]const u8 {
    std.debug.assert(read_buf.len > 0);
    std.debug.assert(decompress_buf.len > 0);

    const compressed = dir.readFile(
        io,
        path,
        read_buf,
    ) catch {
        return error.ReadFailed;
    };
    const uncompressed_len = snappy.uncompressedLength(
        compressed,
    ) catch {
        return error.SnappyInvalid;
    };
    std.debug.assert(uncompressed_len <= decompress_buf.len);

    const len = snappy.uncompress(
        compressed,
        decompress_buf[0..uncompressed_len],
    ) catch {
        return error.SnappyDecompress;
    };
    std.debug.assert(len == uncompressed_len);
    return decompress_buf[0..len];
}

/// Write [selector_byte][ssz_data] to corpus directory.
fn writeCorpus(
    corpus_dir: Dir,
    io: std.Io,
    name: []const u8,
    selector: u8,
    ssz_data: []const u8,
) !void {
    const file = corpus_dir.createFile(io, name, .{}) catch {
        return error.CreateFailed;
    };
    defer file.close(io);

    var write_buf: [4096]u8 = undefined;
    var file_writer = file.writer(io, &write_buf);
    var writer = &file_writer.interface;
    try writer.writeByte(selector);
    try writer.writeAll(ssz_data);
    try file_writer.end();
}

fn writeNestedOpaqueProofSeed(corpus_dir: Dir, io: std.Io) !u32 {
    try writeCorpus(
        corpus_dir,
        io,
        "seed-01-gindex-2047",
        0x01,
        &.{ 0xff, 0x07 },
    );
    return 1;
}

fn writeOpaqueRoundtripSeeds(corpus_dir: Dir, io: std.Io) !u32 {
    try writeCorpus(corpus_dir, io, "selector-00-list-u64-zero", 0x00, &([_]u8{0} ** 8));
    try writeCorpus(corpus_dir, io, "selector-01-list-u32-zero", 0x01, &([_]u8{0} ** 4));
    try writeCorpus(corpus_dir, io, "selector-02-container-zero", 0x02, &([_]u8{0} ** 52));
    try writeCorpus(corpus_dir, io, "selector-03-vector-zero", 0x03, &([_]u8{0} ** 4152));
    return 4;
}

fn writeCorpusSeedPair(cwd: Dir, io: std.Io, options: struct {
    name: []const u8,
    initial_path: []const u8,
    cmin_path: []const u8,
    write_seeds: *const fn (Dir, std.Io) anyerror!u32,
}) !u32 {
    var initial_dir = try cwd.createDirPathOpen(io, options.initial_path, .{});
    defer initial_dir.close(io);

    var cmin_dir = try cwd.createDirPathOpen(io, options.cmin_path, .{});
    defer cmin_dir.close(io);

    const initial_count = try options.write_seeds(initial_dir, io);
    const cmin_count = try options.write_seeds(cmin_dir, io);
    std.debug.assert(initial_count == cmin_count);

    const count = initial_count + cmin_count;
    std.debug.print("  {s}: {} seeds\n", .{ options.name, count });
    return count;
}

fn extractBasic(
    spec_dir: Dir,
    corpus_dir: Dir,
    io: std.Io,
    read_buf: []u8,
    decompress_buf: []u8,
    name_buf: []u8,
) !u32 {
    var count: u32 = 0;

    // Boolean → selector 0x00.
    if (spec_dir.openDir(
        io,
        "boolean/valid",
        .{ .iterate = true },
    ) catch null) |dir_obj| {
        var dir = dir_obj;
        defer dir.close(io);

        var iter = dir.iterate();
        while (try iter.next(io)) |entry| {
            if (entry.kind != .directory) continue;
            if (entry.name[0] == '.') continue;
            const snappy_path = try std.fmt.bufPrint(
                name_buf,
                "{s}/serialized.ssz_snappy",
                .{entry.name},
            );
            const ssz = readSnappy(
                dir,
                io,
                snappy_path,
                read_buf,
                decompress_buf,
            ) catch continue;
            const out_name = try std.fmt.bufPrint(
                name_buf[snappy_path.len..],
                "spec-bool-{s}",
                .{entry.name},
            );
            try writeCorpus(
                corpus_dir,
                io,
                out_name,
                0x00,
                ssz,
            );
            count += 1;
        }
    }

    // Uints → selectors 0x01-0x06.
    if (spec_dir.openDir(
        io,
        "uints/valid",
        .{ .iterate = true },
    ) catch null) |dir_obj| {
        var dir = dir_obj;
        defer dir.close(io);

        var iter = dir.iterate();
        while (try iter.next(io)) |entry| {
            if (entry.kind != .directory) continue;
            if (entry.name[0] == '.') continue;

            // Parse "uint_<bits>_<variant>" to get bits
            const sel = findUintSelector(
                entry.name,
            ) orelse continue;

            const snappy_path = try std.fmt.bufPrint(
                name_buf,
                "{s}/serialized.ssz_snappy",
                .{entry.name},
            );
            const ssz = readSnappy(
                dir,
                io,
                snappy_path,
                read_buf,
                decompress_buf,
            ) catch continue;
            const out_name = try std.fmt.bufPrint(
                name_buf[snappy_path.len..],
                "spec-{s}",
                .{entry.name},
            );
            try writeCorpus(
                corpus_dir,
                io,
                out_name,
                sel,
                ssz,
            );
            count += 1;
        }
    }

    return count;
}

fn findUintSelector(name: []const u8) ?u8 {
    // name = "uint_<bits>_<variant>"
    if (!std.mem.startsWith(u8, name, "uint_")) {
        return null;
    }
    const rest = name["uint_".len..];
    // Find end of bits number
    const sep = std.mem.indexOfScalar(u8, rest, '_') orelse
        return null;
    const bits = rest[0..sep];
    for (uint_selectors) |entry| {
        if (std.mem.eql(u8, bits, entry.bits)) {
            return entry.sel;
        }
    }
    return null;
}

fn extractBitlist(
    spec_dir: Dir,
    corpus_dir: Dir,
    io: std.Io,
    read_buf: []u8,
    decompress_buf: []u8,
    name_buf: []u8,
) !u32 {
    var count: u32 = 0;

    const dir_result = spec_dir.openDir(
        io,
        "bitlist/valid",
        .{ .iterate = true },
    ) catch return 0;
    var dir = dir_result;
    defer dir.close(io);

    var iter = dir.iterate();
    while (try iter.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        if (entry.name[0] == '.') continue;

        // Parse "bitlist_<limit>_<variant>_<n>".
        const sel = findPrefixSelector(
            entry.name,
            "bitlist_",
            &bitlist_selectors,
        ) orelse continue;

        const snappy_path = try std.fmt.bufPrint(
            name_buf,
            "{s}/serialized.ssz_snappy",
            .{entry.name},
        );
        const ssz = readSnappy(
            dir,
            io,
            snappy_path,
            read_buf,
            decompress_buf,
        ) catch continue;
        const out_name = try std.fmt.bufPrint(
            name_buf[snappy_path.len..],
            "spec-{s}",
            .{entry.name},
        );
        try writeCorpus(corpus_dir, io, out_name, sel, ssz);
        count += 1;
    }

    return count;
}

fn extractBitvector(
    spec_dir: Dir,
    corpus_dir: Dir,
    io: std.Io,
    read_buf: []u8,
    decompress_buf: []u8,
    name_buf: []u8,
) !u32 {
    var count: u32 = 0;

    const dir_result = spec_dir.openDir(
        io,
        "bitvector/valid",
        .{ .iterate = true },
    ) catch return 0;
    var dir = dir_result;
    defer dir.close(io);

    var iter = dir.iterate();
    while (try iter.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        if (entry.name[0] == '.') continue;

        // Parse "bitvec_<size>_<variant>".
        const sel = findPrefixSelector(
            entry.name,
            "bitvec_",
            &bitvec_selectors,
        ) orelse continue;

        const snappy_path = try std.fmt.bufPrint(
            name_buf,
            "{s}/serialized.ssz_snappy",
            .{entry.name},
        );
        const ssz = readSnappy(
            dir,
            io,
            snappy_path,
            read_buf,
            decompress_buf,
        ) catch continue;
        const out_name = try std.fmt.bufPrint(
            name_buf[snappy_path.len..],
            "spec-{s}",
            .{entry.name},
        );
        try writeCorpus(corpus_dir, io, out_name, sel, ssz);
        count += 1;
    }

    return count;
}

fn extractContainers(
    static_dir: Dir,
    corpus_dir: Dir,
    io: std.Io,
    read_buf: []u8,
    decompress_buf: []u8,
    name_buf: []u8,
) !u32 {
    var count: u32 = 0;

    for (container_selectors) |cs| {
        const type_dir_result = static_dir.openDir(
            io,
            cs.name,
            .{ .iterate = true },
        ) catch continue;
        var type_dir = type_dir_result;
        defer type_dir.close(io);

        // Iterate categories: ssz_random, ssz_lengthy, etc.
        var cat_iter = type_dir.iterate();
        while (try cat_iter.next(io)) |cat| {
            if (cat.kind != .directory) continue;
            if (cat.name[0] == '.') continue;

            const cat_dir_result = type_dir.openDir(
                io,
                cat.name,
                .{ .iterate = true },
            ) catch continue;
            var cat_dir = cat_dir_result;
            defer cat_dir.close(io);

            // Iterate cases: case_0, case_1, etc.
            var case_iter = cat_dir.iterate();
            while (try case_iter.next(io)) |cas| {
                if (cas.kind != .directory) continue;
                if (cas.name[0] == '.') continue;

                const snappy_path = try std.fmt.bufPrint(
                    name_buf,
                    "{s}/serialized.ssz_snappy",
                    .{cas.name},
                );
                const ssz = readSnappy(
                    cat_dir,
                    io,
                    snappy_path,
                    read_buf,
                    decompress_buf,
                ) catch continue;
                const out_name = try std.fmt.bufPrint(
                    name_buf[snappy_path.len..],
                    "spec-{s}-{s}-{s}",
                    .{ cs.name, cat.name, cas.name },
                );
                try writeCorpus(
                    corpus_dir,
                    io,
                    out_name,
                    cs.sel,
                    ssz,
                );
                count += 1;
            }
        }
    }

    return count;
}

fn findPrefixSelector(
    name: []const u8,
    prefix: []const u8,
    selectors: anytype,
) ?u8 {
    if (!std.mem.startsWith(u8, name, prefix)) {
        return null;
    }
    const rest = name[prefix.len..];
    const sep = std.mem.indexOfScalar(u8, rest, '_') orelse
        return null;
    const key = rest[0..sep];
    for (selectors) |entry| {
        const field = if (@hasField(
            @TypeOf(entry),
            "limit",
        )) entry.limit else entry.size;
        if (std.mem.eql(u8, key, field)) {
            return entry.sel;
        }
    }
    return null;
}

pub fn main(init: std.process.Init) !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();
    const io = init.io;

    const read_buf = try allocator.alloc(u8, buf_len);
    defer allocator.free(read_buf);

    const decompress_buf = try allocator.alloc(u8, buf_len);
    defer allocator.free(decompress_buf);

    var name_buf: [4096]u8 = undefined;

    // Resolve paths relative to this tool's location.
    // Build system places the exe; we use CWD (test/fuzz/).
    const cwd = std.Io.Dir.cwd();

    // Spec test base paths.
    var version_file_buf: [spec_version_file_size_max + 1]u8 = undefined;
    const spec_version = readSpecVersion(cwd, io, &version_file_buf) catch |err| {
        std.debug.print(
            "Cannot read spec test version at {s}: {}\n" ++
                "Run: zig build run:download_spec_tests\n",
            .{ spec_version_file_path, err },
        );
        return err;
    };

    var generic_path_buf: [spec_path_size_max]u8 = undefined;
    const generic_path = std.fmt.bufPrint(
        &generic_path_buf,
        "{s}{s}{s}",
        .{ spec_tests_root, spec_version, generic_spec_suffix },
    ) catch return error.SpecTestPathTooLong;

    var static_path_buf: [spec_path_size_max]u8 = undefined;
    const static_path = std.fmt.bufPrint(
        &static_path_buf,
        "{s}{s}{s}",
        .{ spec_tests_root, spec_version, static_spec_suffix },
    ) catch return error.SpecTestPathTooLong;

    var generic_dir = cwd.openDir(
        io,
        generic_path,
        .{},
    ) catch |err| {
        std.debug.print(
            "Cannot open spec tests at {s}: {}\n" ++
                "Run: zig build run:download_spec_tests\n",
            .{ generic_path, err },
        );
        return err;
    };
    defer generic_dir.close(io);

    var static_dir = cwd.openDir(
        io,
        static_path,
        .{},
    ) catch |err| {
        std.debug.print(
            "Cannot open spec tests at {s}: {}\n" ++
                "Run: zig build run:download_spec_tests\n",
            .{ static_path, err },
        );
        return err;
    };
    defer static_dir.close(io);

    std.debug.print(
        "Extracting spec test vectors as corpus seeds...\n\n",
        .{},
    );

    var total: u32 = 0;

    total += try writeCorpusSeedPair(cwd, io, .{
        .name = "ssz_nested_opaque_proof",
        .initial_path = "corpus/ssz_nested_opaque_proof-initial",
        .cmin_path = "corpus/ssz_nested_opaque_proof-cmin",
        .write_seeds = writeNestedOpaqueProofSeed,
    });

    total += try writeCorpusSeedPair(cwd, io, .{
        .name = "ssz_opaque_roundtrip",
        .initial_path = "corpus/ssz_opaque_roundtrip-initial",
        .cmin_path = "corpus/ssz_opaque_roundtrip-cmin",
        .write_seeds = writeOpaqueRoundtripSeeds,
    });

    // ssz_basic
    {
        var dir = try cwd.openDir(
            io,
            "corpus/ssz_basic-initial",
            .{},
        );
        defer dir.close(io);

        const n = try extractBasic(
            generic_dir,
            dir,
            io,
            read_buf,
            decompress_buf,
            &name_buf,
        );
        std.debug.print("  ssz_basic: {} vectors\n", .{n});
        total += n;
    }

    // ssz_bitlist
    {
        var dir = try cwd.openDir(
            io,
            "corpus/ssz_bitlist-initial",
            .{},
        );
        defer dir.close(io);

        const n = try extractBitlist(
            generic_dir,
            dir,
            io,
            read_buf,
            decompress_buf,
            &name_buf,
        );
        std.debug.print(
            "  ssz_bitlist: {} vectors\n",
            .{n},
        );
        total += n;
    }

    // ssz_bitvector
    {
        var dir = try cwd.openDir(
            io,
            "corpus/ssz_bitvector-initial",
            .{},
        );
        defer dir.close(io);

        const n = try extractBitvector(
            generic_dir,
            dir,
            io,
            read_buf,
            decompress_buf,
            &name_buf,
        );
        std.debug.print(
            "  ssz_bitvector: {} vectors\n",
            .{n},
        );
        total += n;
    }

    // ssz_containers
    {
        var dir = try cwd.openDir(
            io,
            "corpus/ssz_containers-initial",
            .{},
        );
        defer dir.close(io);

        const n = try extractContainers(
            static_dir,
            dir,
            io,
            read_buf,
            decompress_buf,
            &name_buf,
        );
        std.debug.print(
            "  ssz_containers: {} vectors\n",
            .{n},
        );
        total += n;
    }

    std.debug.print(
        "\nTotal: {} corpus files generated\n",
        .{total},
    );
    std.debug.print(
        "\nNote: ssz_bytelist and ssz_lists have no" ++
            " matching spec vectors.\n" ++
            "Their hand-crafted seeds are retained.\n",
        .{},
    );
}
