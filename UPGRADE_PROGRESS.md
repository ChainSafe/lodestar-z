# Zig 0.16 Upgrade Progress

## Status: BUILD PASSES — Core tests passing

## Zig version
0.16.0-dev.2915+065c6e794 (installed at ~/zig-master)

## What's done
- **Build system**: Replaced zbuild-dependent build.zig with standard 1200-line std.Build code
- **Dependencies**: blst, hashtree, snappy, yaml upgraded (path deps)
- **Removed deps**: zbuild, zbench, metrics, httpz (not yet 0.16-compatible, skipped for now)
- **Skipped modules**: bench_*, metrics_stf, bindings (deps not ready)
- **4 commits on branch** chore/zig-master-upgrade

### Core API migrations completed
| Pattern | Old (0.14) | New (0.16) |
|---------|-----------|-----------|
| Hex formatting | `std.fmt.fmtSliceHexLower(slice)` | Direct `{x}` format on slice |
| JSON writer | `std.json.writeStream(w, .{})` | `std.json.Stringify{ .writer = &w }` |
| ArrayList writer | `arraylist.writer()` | `std.Io.Writer.Allocating` |
| File writer | `file.writer()` returns writer | `file.writer(io, &buf)` returns `File.Writer`, use `.interface` |
| Dir methods | `dir.openFile(path, flags)` | `dir.openFile(io, path, flags)` |
| Dir.Iterator | `iter.next()` | `iter.next(io)` |
| Dir.makeDir | `dir.makeDir(name)` | `dir.createDir(io, name, perms)` |
| Dir.close | `dir.close()` | `dir.close(io)` |
| File.close | `file.close()` | `file.close(io)` |
| HTTP Client | `.{ .allocator = alloc }` | `.{ .allocator = alloc, .io = io }` |
| HTTP open | `client.open(.GET, uri, .{})` | `client.fetch(.{ .location = .{ .url = url } })` |
| Thread.Mutex | `std.Thread.Mutex` | `std.atomic.Mutex` |
| Thread.Pool | `std.Thread.Pool` | Removed — use serial or `std.Io.Batch` |
| refAllDeclsRecursive | `testing.refAllDeclsRecursive` | `testing.refAllDecls` (recursive removed) |
| Optional comparison | `optional > 0` | `if (optional) \|v\| (v > 0)` |
| C pointers | `*T` auto-coerces to `[*c]T` | Must use `@ptrCast(&val)` |
| posix.getrandom | `std.posix.getrandom(buf)` | Removed — use timestamp or crypto |

## Tests passing
- ✅ test:constants
- ✅ test:preset
- ✅ test:hex
- ✅ test:hashing
- ✅ test:config
- ✅ test:consensus_types
- ✅ test:persistent_merkle_tree
- ✅ test:ssz

## Tests not yet working
- ❌ test:bls — Thread.ResetEvent removed, ThreadPool needs Io.Event migration
- ❌ test:state_transition — blocked on BLS + metrics dep
- ❌ test:era — not wired in build.zig yet
- ❌ test:fork_types — not wired in build.zig yet

## Still TODO
1. **BLS module**: ThreadPool needs `std.Io.Event` migration (replaces `Thread.ResetEvent`)
2. **Metrics dep**: Fork or upgrade `karlseguin/metrics.zig` for 0.16
3. **zbench dep**: Fork or upgrade for 0.16
4. **zapi/bindings**: Fork or upgrade for 0.16
5. **state_transition**: Wire up once BLS + metrics are fixed
6. **Wire era/fork_types tests** into build.zig
7. **Extract tar/gzip**: download_spec_tests.zig extraction needs 0.16 reader API

## Build command
```bash
export PATH="$HOME/zig-master:$PATH"
cd ~/lodestar-z-zig-master
zig build          # full build
zig build test:ssz # run specific test
```
