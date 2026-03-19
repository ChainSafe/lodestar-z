# Zig 0.16 Upgrade Progress

## Status: IN PROGRESS — std.Io.Dir API migration remaining

## What's done
- Zig 0.16.0-dev.2915 installed at ~/zig-master
- All 5 ChainSafe deps upgraded and building (blst, hashtree, snappy, yaml, zapi)
- build.zig fixed for std.Io
- 2 commits on branch chore/zig-master-upgrade
- ~70 source files migrated for std.io → std.Io, @Type changes, fs API changes

## Current blocker
`std.Io.Dir` API changed — functions like `createFile`, `openFile` etc now require an explicit `io: Io` parameter as second argument.

Example error:
```
test/spec/ssz/write_generic_tests.zig:9:37: error: member function expected 3 argument(s), found 2
    const out = try std.Io.Dir.cwd().createFile("test/spec/ssz/generic_tests.zig", .{});
```

Fix pattern: `dir.createFile(path, flags)` → `dir.createFile(io, path, flags)` where `io` comes from `std.Io.defaultInstance()` or is threaded through from callers.

## Files likely still needing fixes
Any file that calls Dir methods: createFile, openFile, openDir, readFile, etc.
Run `zig build 2>&1 | head -20` to see current errors.

## How to get io parameter
```zig
const io = std.Io.defaultInstance();
// or for test contexts:
const io = std.testing.allocator; // check if there's a test io
```

## Build command
```bash
export PATH="$HOME/zig-master:$PATH"
cd ~/lodestar-z-zig-master
zig build 2>&1 | head -30
```
