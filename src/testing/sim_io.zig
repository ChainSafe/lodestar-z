//! Deterministic I/O mock for simulation testing.
//!
//! Implements the `std.Io` vtable interface with fully deterministic time,
//! randomness, and sleep. Every source of non-determinism goes through the
//! seeded PRNG — same seed = identical execution.
//!
//! Design follows TigerBeetle's simulation testing approach adapted for
//! Zig 0.16's `std.Io` abstraction boundary.

const std = @import("std");
const Io = std.Io;

pub const SimIo = struct {
    /// Seeded PRNG for all randomness.
    prng: std.Random.DefaultPrng,

    /// Current simulated monotonic time (nanoseconds).
    monotonic_ns: u64 = 0,

    /// Current simulated realtime (nanoseconds since Unix epoch).
    /// Stored as i128 to match Io.Timestamp.nanoseconds (i96) range without loss.
    realtime_ns: i128 = 0,

    /// Clock drift/offset configuration (nanoseconds).
    /// Applied to realtime relative to monotonic.
    clock_offset_ns: i64 = 0,

    /// Total number of `sleep` calls observed (for test assertions).
    sleep_call_count: u64 = 0,

    /// If true, `sleep` advances simulated time by the requested duration.
    /// Otherwise sleep is a no-op (time only advances via explicit calls).
    auto_advance_on_sleep: bool = false,

    /// Create a `std.Io` that delegates to this SimIo.
    pub fn io(self: *SimIo) Io {
        return .{
            .userdata = self,
            .vtable = &vtable,
        };
    }

    // ── Time manipulation ────────────────────────────────────────────

    /// Advance both monotonic and realtime by `ns` nanoseconds.
    pub fn advanceTime(self: *SimIo, ns: u64) void {
        self.monotonic_ns += ns;
        self.realtime_ns += @as(i128, ns);
    }

    /// Set the monotonic clock to an exact value.
    /// Also adjusts realtime to maintain the current offset.
    pub fn setMonotonicTime(self: *SimIo, ns: u64) void {
        const delta: i128 = @as(i128, ns) - @as(i128, self.monotonic_ns);
        self.monotonic_ns = ns;
        self.realtime_ns += delta;
    }

    /// Set the realtime clock to an exact value (nanoseconds since epoch).
    pub fn setRealtimeNs(self: *SimIo, ns: i128) void {
        self.realtime_ns = ns;
    }

    /// Advance to the start of a specific slot.
    pub fn advanceToSlot(
        self: *SimIo,
        slot: u64,
        genesis_time_s: u64,
        seconds_per_slot: u64,
    ) void {
        const slot_start_ns: u64 = (genesis_time_s + slot * seconds_per_slot) * std.time.ns_per_s;

        // Only advance forward — assert we aren't going backwards.
        if (slot_start_ns > self.monotonic_ns) {
            const delta = slot_start_ns - self.monotonic_ns;
            self.advanceTime(delta);
        }
    }

    // ── VTable implementation ────────────────────────────────────────

    const vtable: Io.VTable = .{
        .crashHandler = crashHandler,

        // Concurrency — not supported in simulation.
        .async = asyncUnsupported,
        .concurrent = concurrentUnsupported,
        .await = awaitUnsupported,
        .cancel = cancelUnsupported,

        .groupAsync = groupAsyncUnsupported,
        .groupConcurrent = groupConcurrentUnsupported,
        .groupAwait = groupAwaitUnsupported,
        .groupCancel = groupCancelUnsupported,

        .recancel = recancelUnsupported,
        .swapCancelProtection = swapCancelProtectionStub,
        .checkCancel = checkCancelStub,

        .futexWait = futexWaitUnsupported,
        .futexWaitUncancelable = futexWaitUncancelableUnsupported,
        .futexWake = futexWakeUnsupported,

        .operate = operateUnsupported,
        .batchAwaitAsync = batchAwaitAsyncUnsupported,
        .batchAwaitConcurrent = batchAwaitConcurrentUnsupported,
        .batchCancel = batchCancelUnsupported,

        // Directory operations — unsupported.
        .dirCreateDir = dirUnsupported1,
        .dirCreateDirPath = dirUnsupported2,
        .dirCreateDirPathOpen = dirUnsupported3,
        .dirOpenDir = dirUnsupported4,
        .dirStat = dirUnsupported5,
        .dirStatFile = dirUnsupported6,
        .dirAccess = dirUnsupported7,
        .dirCreateFile = dirUnsupported8,
        .dirCreateFileAtomic = dirUnsupported9,
        .dirOpenFile = dirUnsupported10,
        .dirClose = dirUnsupported11,
        .dirRead = dirUnsupported12,
        .dirRealPath = dirUnsupported13,
        .dirRealPathFile = dirUnsupported14,
        .dirDeleteFile = dirUnsupported15,
        .dirDeleteDir = dirUnsupported16,
        .dirRename = dirUnsupported17,
        .dirRenamePreserve = dirUnsupported18,
        .dirSymLink = dirUnsupported19,
        .dirReadLink = dirUnsupported20,
        .dirSetOwner = dirUnsupported21,
        .dirSetFileOwner = dirUnsupported22,
        .dirSetPermissions = dirUnsupported23,
        .dirSetFilePermissions = dirUnsupported24,
        .dirSetTimestamps = dirUnsupported25,
        .dirHardLink = dirUnsupported26,

        // File operations — unsupported.
        .fileStat = fileUnsupported1,
        .fileLength = fileUnsupported2,
        .fileClose = fileUnsupported3,
        .fileWritePositional = fileUnsupported4,
        .fileWriteFileStreaming = fileUnsupported5,
        .fileWriteFilePositional = fileUnsupported6,
        .fileReadPositional = fileUnsupported7,
        .fileSeekBy = fileUnsupported8,
        .fileSeekTo = fileUnsupported9,
        .fileSync = fileUnsupported10,
        .fileIsTty = fileUnsupported11,
        .fileEnableAnsiEscapeCodes = fileUnsupported12,
        .fileSupportsAnsiEscapeCodes = fileUnsupported13,
        .fileSetLength = fileUnsupported14,
        .fileSetOwner = fileUnsupported15,
        .fileSetPermissions = fileUnsupported16,
        .fileSetTimestamps = fileUnsupported17,
        .fileLock = fileUnsupported18,
        .fileTryLock = fileUnsupported19,
        .fileUnlock = fileUnsupported20,
        .fileDowngradeLock = fileUnsupported21,
        .fileRealPath = fileUnsupported22,
        .fileHardLink = fileUnsupported23,

        // Memory map — unsupported.
        .fileMemoryMapCreate = memMapUnsupported1,
        .fileMemoryMapDestroy = memMapUnsupported2,
        .fileMemoryMapSetLength = memMapUnsupported3,
        .fileMemoryMapRead = memMapUnsupported4,
        .fileMemoryMapWrite = memMapUnsupported5,

        // Process — unsupported.
        .processExecutableOpen = processUnsupported1,
        .processExecutablePath = processUnsupported2,
        .lockStderr = processUnsupported3,
        .tryLockStderr = processUnsupported4,
        .unlockStderr = processUnsupported5,
        .processCurrentPath = processUnsupported6,
        .processSetCurrentDir = processUnsupported7,
        .processSetCurrentPath = processUnsupported8,
        .processReplace = processUnsupported9,
        .processReplacePath = processUnsupported10,
        .processSpawn = processUnsupported11,
        .processSpawnPath = processUnsupported12,
        .childWait = processUnsupported13,
        .childKill = processUnsupported14,

        .progressParentFile = progressUnsupported,

        // ── Implemented ──
        .now = nowFn,
        .clockResolution = clockResolutionFn,
        .sleep = sleepFn,

        .random = randomFn,
        .randomSecure = randomSecureFn,

        // Network — unsupported (use SimNetwork instead).
        .netListenIp = netUnsupported1,
        .netAccept = netUnsupported2,
        .netBindIp = netUnsupported3,
        .netConnectIp = netUnsupported4,
        .netListenUnix = netUnsupported5,
        .netConnectUnix = netUnsupported6,
        .netSocketCreatePair = netUnsupported7,
        .netSend = netUnsupported8,
        .netRead = netUnsupported9,
        .netWrite = netUnsupported10,
        .netWriteFile = netUnsupported11,
        .netClose = netUnsupported12,
        .netShutdown = netUnsupported13,
        .netInterfaceNameResolve = netUnsupported14,
        .netInterfaceName = netUnsupported15,
        .netLookup = netUnsupported16,
    };

    // ── Core VTable functions ────────────────────────────────────────

    fn nowFn(userdata: ?*anyopaque, clock: Io.Clock) Io.Timestamp {
        const self: *SimIo = @ptrCast(@alignCast(userdata));
        return switch (clock) {
            .real => .{ .nanoseconds = @intCast(self.realtime_ns + self.clock_offset_ns) },
            .awake, .boot => .{ .nanoseconds = @intCast(self.monotonic_ns) },
            // CPU clocks: return monotonic as a reasonable simulation.
            .cpu_process, .cpu_thread => .{ .nanoseconds = @intCast(self.monotonic_ns) },
        };
    }

    fn clockResolutionFn(_: ?*anyopaque, _: Io.Clock) Io.Clock.ResolutionError!Io.Duration {
        // Simulated clock has nanosecond resolution.
        return .{ .nanoseconds = 1 };
    }

    fn sleepFn(userdata: ?*anyopaque, timeout: Io.Timeout) Io.Cancelable!void {
        const self: *SimIo = @ptrCast(@alignCast(userdata));
        self.sleep_call_count += 1;

        if (self.auto_advance_on_sleep) {
            switch (timeout) {
                .none => {},
                .duration => |d| {
                    const ns: u64 = @intCast(@max(0, d.raw.nanoseconds));
                    self.advanceTime(ns);
                },
                .deadline => |dl| {
                    // Advance to deadline if it's in the future.
                    const deadline_ns: i96 = dl.raw.nanoseconds;
                    const current: i96 = switch (dl.clock) {
                        .real => @intCast(self.realtime_ns + self.clock_offset_ns),
                        .awake, .boot => @intCast(self.monotonic_ns),
                        .cpu_process, .cpu_thread => @intCast(self.monotonic_ns),
                    };
                    if (deadline_ns > current) {
                        const delta: u64 = @intCast(deadline_ns - current);
                        self.advanceTime(delta);
                    }
                },
            }
        }
    }

    fn randomFn(userdata: ?*anyopaque, buffer: []u8) void {
        const self: *SimIo = @ptrCast(@alignCast(userdata));
        self.prng.fill(buffer);
    }

    fn randomSecureFn(userdata: ?*anyopaque, buffer: []u8) Io.RandomSecureError!void {
        // In simulation, "secure" randomness uses the same deterministic PRNG.
        const self: *SimIo = @ptrCast(@alignCast(userdata));
        self.prng.fill(buffer);
    }

    fn crashHandler(_: ?*anyopaque) void {
        @panic("SimIo: crash handler invoked");
    }

    // ── Stubs for non-panicking unsupported operations ───────────────

    fn swapCancelProtectionStub(_: ?*anyopaque, _: Io.CancelProtection) Io.CancelProtection {
        return .unblocked;
    }

    fn checkCancelStub(_: ?*anyopaque) Io.Cancelable!void {}

    fn recancelUnsupported(_: ?*anyopaque) void {}

    // ── Unsupported operation stubs (panic on call) ──────────────────
    //
    // Each stub matches the signature required by the VTable field.
    // We use @panic to make it obvious during testing when simulation
    // code accidentally tries to use real I/O.

    fn asyncUnsupported(_: ?*anyopaque, _: []u8, _: std.mem.Alignment, _: []const u8, _: std.mem.Alignment, _: *const fn (*const anyopaque, *anyopaque) void) ?*Io.AnyFuture {
        @panic("SimIo: async not supported in simulation");
    }

    fn concurrentUnsupported(_: ?*anyopaque, _: usize, _: std.mem.Alignment, _: []const u8, _: std.mem.Alignment, _: *const fn (*const anyopaque, *anyopaque) void) Io.ConcurrentError!*Io.AnyFuture {
        @panic("SimIo: concurrent not supported in simulation");
    }

    fn awaitUnsupported(_: ?*anyopaque, _: *Io.AnyFuture, _: []u8, _: std.mem.Alignment) void {
        @panic("SimIo: await not supported in simulation");
    }

    fn cancelUnsupported(_: ?*anyopaque, _: *Io.AnyFuture, _: []u8, _: std.mem.Alignment) void {
        @panic("SimIo: cancel not supported in simulation");
    }

    fn groupAsyncUnsupported(_: ?*anyopaque, _: *Io.Group, _: []const u8, _: std.mem.Alignment, _: *const fn (*const anyopaque) void) void {
        @panic("SimIo: groupAsync not supported in simulation");
    }

    fn groupConcurrentUnsupported(_: ?*anyopaque, _: *Io.Group, _: []const u8, _: std.mem.Alignment, _: *const fn (*const anyopaque) void) Io.ConcurrentError!void {
        @panic("SimIo: groupConcurrent not supported in simulation");
    }

    fn groupAwaitUnsupported(_: ?*anyopaque, _: *Io.Group, _: *anyopaque) Io.Cancelable!void {
        @panic("SimIo: groupAwait not supported in simulation");
    }

    fn groupCancelUnsupported(_: ?*anyopaque, _: *Io.Group, _: *anyopaque) void {
        @panic("SimIo: groupCancel not supported in simulation");
    }

    fn futexWaitUnsupported(_: ?*anyopaque, _: *const u32, _: u32, _: Io.Timeout) Io.Cancelable!void {
        @panic("SimIo: futexWait not supported in simulation");
    }

    fn futexWaitUncancelableUnsupported(_: ?*anyopaque, _: *const u32, _: u32) void {
        @panic("SimIo: futexWaitUncancelable not supported in simulation");
    }

    fn futexWakeUnsupported(_: ?*anyopaque, _: *const u32, _: u32) void {
        @panic("SimIo: futexWake not supported in simulation");
    }

    fn operateUnsupported(_: ?*anyopaque, _: Io.Operation) Io.Cancelable!Io.Operation.Result {
        @panic("SimIo: operate not supported in simulation");
    }

    fn batchAwaitAsyncUnsupported(_: ?*anyopaque, _: *Io.Batch) Io.Cancelable!void {
        @panic("SimIo: batchAwaitAsync not supported in simulation");
    }

    fn batchAwaitConcurrentUnsupported(_: ?*anyopaque, _: *Io.Batch, _: Io.Timeout) Io.Batch.AwaitConcurrentError!void {
        @panic("SimIo: batchAwaitConcurrent not supported in simulation");
    }

    fn batchCancelUnsupported(_: ?*anyopaque, _: *Io.Batch) void {
        @panic("SimIo: batchCancel not supported in simulation");
    }

    // Directory stubs — each matches its VTable field signature.
    fn dirUnsupported1(_: ?*anyopaque, _: Io.Dir, _: []const u8, _: Io.Dir.Permissions) Io.Dir.CreateDirError!void {
        @panic("SimIo: directory operations not supported");
    }
    fn dirUnsupported2(_: ?*anyopaque, _: Io.Dir, _: []const u8, _: Io.Dir.Permissions) Io.Dir.CreateDirPathError!Io.Dir.CreatePathStatus {
        @panic("SimIo: directory operations not supported");
    }
    fn dirUnsupported3(_: ?*anyopaque, _: Io.Dir, _: []const u8, _: Io.Dir.Permissions, _: Io.Dir.OpenOptions) Io.Dir.CreateDirPathOpenError!Io.Dir {
        @panic("SimIo: directory operations not supported");
    }
    fn dirUnsupported4(_: ?*anyopaque, _: Io.Dir, _: []const u8, _: Io.Dir.OpenOptions) Io.Dir.OpenError!Io.Dir {
        @panic("SimIo: directory operations not supported");
    }
    fn dirUnsupported5(_: ?*anyopaque, _: Io.Dir) Io.Dir.StatError!Io.Dir.Stat {
        @panic("SimIo: directory operations not supported");
    }
    fn dirUnsupported6(_: ?*anyopaque, _: Io.Dir, _: []const u8, _: Io.Dir.StatFileOptions) Io.Dir.StatFileError!Io.File.Stat {
        @panic("SimIo: directory operations not supported");
    }
    fn dirUnsupported7(_: ?*anyopaque, _: Io.Dir, _: []const u8, _: Io.Dir.AccessOptions) Io.Dir.AccessError!void {
        @panic("SimIo: directory operations not supported");
    }
    fn dirUnsupported8(_: ?*anyopaque, _: Io.Dir, _: []const u8, _: Io.File.CreateFlags) Io.File.OpenError!Io.File {
        @panic("SimIo: directory operations not supported");
    }
    fn dirUnsupported9(_: ?*anyopaque, _: Io.Dir, _: []const u8, _: Io.Dir.CreateFileAtomicOptions) Io.Dir.CreateFileAtomicError!Io.File.Atomic {
        @panic("SimIo: directory operations not supported");
    }
    fn dirUnsupported10(_: ?*anyopaque, _: Io.Dir, _: []const u8, _: Io.File.OpenFlags) Io.File.OpenError!Io.File {
        @panic("SimIo: directory operations not supported");
    }
    fn dirUnsupported11(_: ?*anyopaque, _: []const Io.Dir) void {
        @panic("SimIo: directory operations not supported");
    }
    fn dirUnsupported12(_: ?*anyopaque, _: *Io.Dir.Reader, _: []Io.Dir.Entry) Io.Dir.Reader.Error!usize {
        @panic("SimIo: directory operations not supported");
    }
    fn dirUnsupported13(_: ?*anyopaque, _: Io.Dir, _: []u8) Io.Dir.RealPathError!usize {
        @panic("SimIo: directory operations not supported");
    }
    fn dirUnsupported14(_: ?*anyopaque, _: Io.Dir, _: []const u8, _: []u8) Io.Dir.RealPathFileError!usize {
        @panic("SimIo: directory operations not supported");
    }
    fn dirUnsupported15(_: ?*anyopaque, _: Io.Dir, _: []const u8) Io.Dir.DeleteFileError!void {
        @panic("SimIo: directory operations not supported");
    }
    fn dirUnsupported16(_: ?*anyopaque, _: Io.Dir, _: []const u8) Io.Dir.DeleteDirError!void {
        @panic("SimIo: directory operations not supported");
    }
    fn dirUnsupported17(_: ?*anyopaque, _: Io.Dir, _: []const u8, _: Io.Dir, _: []const u8) Io.Dir.RenameError!void {
        @panic("SimIo: directory operations not supported");
    }
    fn dirUnsupported18(_: ?*anyopaque, _: Io.Dir, _: []const u8, _: Io.Dir, _: []const u8) Io.Dir.RenamePreserveError!void {
        @panic("SimIo: directory operations not supported");
    }
    fn dirUnsupported19(_: ?*anyopaque, _: Io.Dir, _: []const u8, _: []const u8, _: Io.Dir.SymLinkFlags) Io.Dir.SymLinkError!void {
        @panic("SimIo: directory operations not supported");
    }
    fn dirUnsupported20(_: ?*anyopaque, _: Io.Dir, _: []const u8, _: []u8) Io.Dir.ReadLinkError!usize {
        @panic("SimIo: directory operations not supported");
    }
    fn dirUnsupported21(_: ?*anyopaque, _: Io.Dir, _: ?Io.File.Uid, _: ?Io.File.Gid) Io.Dir.SetOwnerError!void {
        @panic("SimIo: directory operations not supported");
    }
    fn dirUnsupported22(_: ?*anyopaque, _: Io.Dir, _: []const u8, _: ?Io.File.Uid, _: ?Io.File.Gid, _: Io.Dir.SetFileOwnerOptions) Io.Dir.SetFileOwnerError!void {
        @panic("SimIo: directory operations not supported");
    }
    fn dirUnsupported23(_: ?*anyopaque, _: Io.Dir, _: Io.Dir.Permissions) Io.Dir.SetPermissionsError!void {
        @panic("SimIo: directory operations not supported");
    }
    fn dirUnsupported24(_: ?*anyopaque, _: Io.Dir, _: []const u8, _: Io.File.Permissions, _: Io.Dir.SetFilePermissionsOptions) Io.Dir.SetFilePermissionsError!void {
        @panic("SimIo: directory operations not supported");
    }
    fn dirUnsupported25(_: ?*anyopaque, _: Io.Dir, _: []const u8, _: Io.Dir.SetTimestampsOptions) Io.Dir.SetTimestampsError!void {
        @panic("SimIo: directory operations not supported");
    }
    fn dirUnsupported26(_: ?*anyopaque, _: Io.Dir, _: []const u8, _: Io.Dir, _: []const u8, _: Io.Dir.HardLinkOptions) Io.Dir.HardLinkError!void {
        @panic("SimIo: directory operations not supported");
    }

    // File stubs
    fn fileUnsupported1(_: ?*anyopaque, _: Io.File) Io.File.StatError!Io.File.Stat {
        @panic("SimIo: file operations not supported");
    }
    fn fileUnsupported2(_: ?*anyopaque, _: Io.File) Io.File.LengthError!u64 {
        @panic("SimIo: file operations not supported");
    }
    fn fileUnsupported3(_: ?*anyopaque, _: []const Io.File) void {
        @panic("SimIo: file operations not supported");
    }
    fn fileUnsupported4(_: ?*anyopaque, _: Io.File, _: []const u8, _: []const []const u8, _: usize, _: u64) Io.File.WritePositionalError!usize {
        @panic("SimIo: file operations not supported");
    }
    fn fileUnsupported5(_: ?*anyopaque, _: Io.File, _: []const u8, _: *Io.File.Reader, _: Io.Limit) Io.File.Writer.WriteFileError!usize {
        @panic("SimIo: file operations not supported");
    }
    fn fileUnsupported6(_: ?*anyopaque, _: Io.File, _: []const u8, _: *Io.File.Reader, _: Io.Limit, _: u64) Io.File.WriteFilePositionalError!usize {
        @panic("SimIo: file operations not supported");
    }
    fn fileUnsupported7(_: ?*anyopaque, _: Io.File, _: []const []u8, _: u64) Io.File.ReadPositionalError!usize {
        @panic("SimIo: file operations not supported");
    }
    fn fileUnsupported8(_: ?*anyopaque, _: Io.File, _: i64) Io.File.SeekError!void {
        @panic("SimIo: file operations not supported");
    }
    fn fileUnsupported9(_: ?*anyopaque, _: Io.File, _: u64) Io.File.SeekError!void {
        @panic("SimIo: file operations not supported");
    }
    fn fileUnsupported10(_: ?*anyopaque, _: Io.File) Io.File.SyncError!void {
        @panic("SimIo: file operations not supported");
    }
    fn fileUnsupported11(_: ?*anyopaque, _: Io.File) Io.Cancelable!bool {
        @panic("SimIo: file operations not supported");
    }
    fn fileUnsupported12(_: ?*anyopaque, _: Io.File) Io.File.EnableAnsiEscapeCodesError!void {
        @panic("SimIo: file operations not supported");
    }
    fn fileUnsupported13(_: ?*anyopaque, _: Io.File) Io.Cancelable!bool {
        @panic("SimIo: file operations not supported");
    }
    fn fileUnsupported14(_: ?*anyopaque, _: Io.File, _: u64) Io.File.SetLengthError!void {
        @panic("SimIo: file operations not supported");
    }
    fn fileUnsupported15(_: ?*anyopaque, _: Io.File, _: ?Io.File.Uid, _: ?Io.File.Gid) Io.File.SetOwnerError!void {
        @panic("SimIo: file operations not supported");
    }
    fn fileUnsupported16(_: ?*anyopaque, _: Io.File, _: Io.File.Permissions) Io.File.SetPermissionsError!void {
        @panic("SimIo: file operations not supported");
    }
    fn fileUnsupported17(_: ?*anyopaque, _: Io.File, _: Io.File.SetTimestampsOptions) Io.File.SetTimestampsError!void {
        @panic("SimIo: file operations not supported");
    }
    fn fileUnsupported18(_: ?*anyopaque, _: Io.File, _: Io.File.Lock) Io.File.LockError!void {
        @panic("SimIo: file operations not supported");
    }
    fn fileUnsupported19(_: ?*anyopaque, _: Io.File, _: Io.File.Lock) Io.File.LockError!bool {
        @panic("SimIo: file operations not supported");
    }
    fn fileUnsupported20(_: ?*anyopaque, _: Io.File) void {
        @panic("SimIo: file operations not supported");
    }
    fn fileUnsupported21(_: ?*anyopaque, _: Io.File) Io.File.DowngradeLockError!void {
        @panic("SimIo: file operations not supported");
    }
    fn fileUnsupported22(_: ?*anyopaque, _: Io.File, _: []u8) Io.File.RealPathError!usize {
        @panic("SimIo: file operations not supported");
    }
    fn fileUnsupported23(_: ?*anyopaque, _: Io.File, _: Io.Dir, _: []const u8, _: Io.File.HardLinkOptions) Io.File.HardLinkError!void {
        @panic("SimIo: file operations not supported");
    }

    // Memory map stubs
    fn memMapUnsupported1(_: ?*anyopaque, _: Io.File, _: Io.File.MemoryMap.CreateOptions) Io.File.MemoryMap.CreateError!Io.File.MemoryMap {
        @panic("SimIo: memory map not supported");
    }
    fn memMapUnsupported2(_: ?*anyopaque, _: *Io.File.MemoryMap) void {
        @panic("SimIo: memory map not supported");
    }
    fn memMapUnsupported3(_: ?*anyopaque, _: *Io.File.MemoryMap, _: usize) Io.File.MemoryMap.SetLengthError!void {
        @panic("SimIo: memory map not supported");
    }
    fn memMapUnsupported4(_: ?*anyopaque, _: *Io.File.MemoryMap) Io.File.ReadPositionalError!void {
        @panic("SimIo: memory map not supported");
    }
    fn memMapUnsupported5(_: ?*anyopaque, _: *Io.File.MemoryMap) Io.File.WritePositionalError!void {
        @panic("SimIo: memory map not supported");
    }

    // Process stubs
    fn processUnsupported1(_: ?*anyopaque, _: Io.File.OpenFlags) std.process.OpenExecutableError!Io.File {
        @panic("SimIo: process operations not supported");
    }
    fn processUnsupported2(_: ?*anyopaque, _: []u8) std.process.ExecutablePathError!usize {
        @panic("SimIo: process operations not supported");
    }
    fn processUnsupported3(_: ?*anyopaque, _: ?Io.Terminal.Mode) Io.Cancelable!Io.LockedStderr {
        @panic("SimIo: process operations not supported");
    }
    fn processUnsupported4(_: ?*anyopaque, _: ?Io.Terminal.Mode) Io.Cancelable!?Io.LockedStderr {
        @panic("SimIo: process operations not supported");
    }
    fn processUnsupported5(_: ?*anyopaque) void {
        @panic("SimIo: process operations not supported");
    }
    fn processUnsupported6(_: ?*anyopaque, _: []u8) std.process.CurrentPathError!usize {
        @panic("SimIo: process operations not supported");
    }
    fn processUnsupported7(_: ?*anyopaque, _: Io.Dir) std.process.SetCurrentDirError!void {
        @panic("SimIo: process operations not supported");
    }
    fn processUnsupported8(_: ?*anyopaque, _: []const u8) std.process.SetCurrentPathError!void {
        @panic("SimIo: process operations not supported");
    }
    fn processUnsupported9(_: ?*anyopaque, _: std.process.ReplaceOptions) std.process.ReplaceError {
        @panic("SimIo: process operations not supported");
    }
    fn processUnsupported10(_: ?*anyopaque, _: Io.Dir, _: std.process.ReplaceOptions) std.process.ReplaceError {
        @panic("SimIo: process operations not supported");
    }
    fn processUnsupported11(_: ?*anyopaque, _: std.process.SpawnOptions) std.process.SpawnError!std.process.Child {
        @panic("SimIo: process operations not supported");
    }
    fn processUnsupported12(_: ?*anyopaque, _: Io.Dir, _: std.process.SpawnOptions) std.process.SpawnError!std.process.Child {
        @panic("SimIo: process operations not supported");
    }
    fn processUnsupported13(_: ?*anyopaque, _: *std.process.Child) std.process.Child.WaitError!std.process.Child.Term {
        @panic("SimIo: process operations not supported");
    }
    fn processUnsupported14(_: ?*anyopaque, _: *std.process.Child) void {
        @panic("SimIo: process operations not supported");
    }

    fn progressUnsupported(_: ?*anyopaque) std.Progress.ParentFileError!Io.File {
        @panic("SimIo: progress not supported");
    }

    // Network stubs
    fn netUnsupported1(_: ?*anyopaque, _: *const Io.net.IpAddress, _: Io.net.IpAddress.ListenOptions) Io.net.IpAddress.ListenError!Io.net.Socket {
        @panic("SimIo: use SimNetwork for networking");
    }
    fn netUnsupported2(_: ?*anyopaque, _: Io.net.Socket.Handle, _: Io.net.Server.AcceptOptions) Io.net.Server.AcceptError!Io.net.Socket {
        @panic("SimIo: use SimNetwork for networking");
    }
    fn netUnsupported3(_: ?*anyopaque, _: *const Io.net.IpAddress, _: Io.net.IpAddress.BindOptions) Io.net.IpAddress.BindError!Io.net.Socket {
        @panic("SimIo: use SimNetwork for networking");
    }
    fn netUnsupported4(_: ?*anyopaque, _: *const Io.net.IpAddress, _: Io.net.IpAddress.ConnectOptions) Io.net.IpAddress.ConnectError!Io.net.Socket {
        @panic("SimIo: use SimNetwork for networking");
    }
    fn netUnsupported5(_: ?*anyopaque, _: *const Io.net.UnixAddress, _: Io.net.UnixAddress.ListenOptions) Io.net.UnixAddress.ListenError!Io.net.Socket.Handle {
        @panic("SimIo: use SimNetwork for networking");
    }
    fn netUnsupported6(_: ?*anyopaque, _: *const Io.net.UnixAddress) Io.net.UnixAddress.ConnectError!Io.net.Socket.Handle {
        @panic("SimIo: use SimNetwork for networking");
    }
    fn netUnsupported7(_: ?*anyopaque, _: Io.net.Socket.CreatePairOptions) Io.net.Socket.CreatePairError![2]Io.net.Socket {
        @panic("SimIo: use SimNetwork for networking");
    }
    fn netUnsupported8(_: ?*anyopaque, _: Io.net.Socket.Handle, _: []Io.net.OutgoingMessage, _: Io.net.SendFlags) struct { ?Io.net.Socket.SendError, usize } {
        @panic("SimIo: use SimNetwork for networking");
    }
    fn netUnsupported9(_: ?*anyopaque, _: Io.net.Socket.Handle, _: [][]u8) Io.net.Stream.Reader.Error!usize {
        @panic("SimIo: use SimNetwork for networking");
    }
    fn netUnsupported10(_: ?*anyopaque, _: Io.net.Socket.Handle, _: []const u8, _: []const []const u8, _: usize) Io.net.Stream.Writer.Error!usize {
        @panic("SimIo: use SimNetwork for networking");
    }
    fn netUnsupported11(_: ?*anyopaque, _: Io.net.Socket.Handle, _: []const u8, _: *Io.File.Reader, _: Io.Limit) Io.net.Stream.Writer.WriteFileError!usize {
        @panic("SimIo: use SimNetwork for networking");
    }
    fn netUnsupported12(_: ?*anyopaque, _: []const Io.net.Socket.Handle) void {
        @panic("SimIo: use SimNetwork for networking");
    }
    fn netUnsupported13(_: ?*anyopaque, _: Io.net.Socket.Handle, _: Io.net.ShutdownHow) Io.net.ShutdownError!void {
        @panic("SimIo: use SimNetwork for networking");
    }
    fn netUnsupported14(_: ?*anyopaque, _: *const Io.net.Interface.Name) Io.net.Interface.Name.ResolveError!Io.net.Interface {
        @panic("SimIo: use SimNetwork for networking");
    }
    fn netUnsupported15(_: ?*anyopaque, _: Io.net.Interface) Io.net.Interface.NameError!Io.net.Interface.Name {
        @panic("SimIo: use SimNetwork for networking");
    }
    fn netUnsupported16(_: ?*anyopaque, _: Io.net.HostName, _: *Io.Queue(Io.net.HostName.LookupResult), _: Io.net.HostName.LookupOptions) Io.net.HostName.LookupError!void {
        @panic("SimIo: use SimNetwork for networking");
    }
};

// ── Tests ────────────────────────────────────────────────────────────

test "SimIo: deterministic time" {
    var sim: SimIo = .{
        .prng = std.Random.DefaultPrng.init(42),
        .realtime_ns = 1_700_000_000 * std.time.ns_per_s, // ~2023-11-14
    };
    const sio = sim.io();

    // Initial monotonic time is 0.
    const t0 = Io.Clock.real.now(sio);
    try std.testing.expectEqual(@as(i96, 1_700_000_000 * std.time.ns_per_s), t0.nanoseconds);

    // Advance time.
    sim.advanceTime(1_000_000_000); // 1 second
    const t1_mono = Io.Clock.awake.now(sio);
    try std.testing.expectEqual(@as(i96, 1_000_000_000), t1_mono.nanoseconds);

    const t1_real = Io.Clock.real.now(sio);
    try std.testing.expectEqual(@as(i96, 1_700_000_000 * std.time.ns_per_s + 1_000_000_000), t1_real.nanoseconds);
}

test "SimIo: same seed produces same random sequence" {
    var sim1: SimIo = .{ .prng = std.Random.DefaultPrng.init(12345) };
    var sim2: SimIo = .{ .prng = std.Random.DefaultPrng.init(12345) };

    const sio1 = sim1.io();
    const sio2 = sim2.io();

    var buf1: [32]u8 = undefined;
    var buf2: [32]u8 = undefined;

    sio1.random(&buf1);
    sio2.random(&buf2);

    try std.testing.expectEqualSlices(u8, &buf1, &buf2);
}

test "SimIo: different seeds produce different random sequences" {
    var sim1: SimIo = .{ .prng = std.Random.DefaultPrng.init(1) };
    var sim2: SimIo = .{ .prng = std.Random.DefaultPrng.init(2) };

    const sio1 = sim1.io();
    const sio2 = sim2.io();

    var buf1: [32]u8 = undefined;
    var buf2: [32]u8 = undefined;

    sio1.random(&buf1);
    sio2.random(&buf2);

    // Overwhelmingly likely to be different.
    try std.testing.expect(!std.mem.eql(u8, &buf1, &buf2));
}

test "SimIo: clock types" {
    var sim: SimIo = .{
        .prng = std.Random.DefaultPrng.init(0),
        .monotonic_ns = 5_000_000_000,
        .realtime_ns = 1_700_000_000 * @as(i128, std.time.ns_per_s),
    };
    const sio = sim.io();

    // Monotonic clocks return monotonic time.
    const awake = Io.Clock.awake.now(sio);
    const boot = Io.Clock.boot.now(sio);
    try std.testing.expectEqual(@as(i96, 5_000_000_000), awake.nanoseconds);
    try std.testing.expectEqual(@as(i96, 5_000_000_000), boot.nanoseconds);

    // Real clock returns realtime.
    const real = Io.Clock.real.now(sio);
    try std.testing.expectEqual(@as(i96, 1_700_000_000 * std.time.ns_per_s), real.nanoseconds);
}

test "SimIo: clock offset" {
    var sim: SimIo = .{
        .prng = std.Random.DefaultPrng.init(0),
        .realtime_ns = 1_000_000_000_000_000_000, // 1e18 ns
        .clock_offset_ns = 500_000_000, // +500ms offset
    };
    const sio = sim.io();

    const real = Io.Clock.real.now(sio);
    try std.testing.expectEqual(@as(i96, 1_000_000_000_000_000_000 + 500_000_000), real.nanoseconds);

    // Monotonic unaffected by offset.
    const mono = Io.Clock.awake.now(sio);
    try std.testing.expectEqual(@as(i96, 0), mono.nanoseconds);
}

test "SimIo: sleep counts and auto-advance" {
    var sim: SimIo = .{
        .prng = std.Random.DefaultPrng.init(0),
        .auto_advance_on_sleep = true,
    };
    const sio = sim.io();

    try std.testing.expectEqual(@as(u64, 0), sim.sleep_call_count);

    // Sleep with duration.
    sio.sleep(.{ .nanoseconds = @as(i96, 2 * std.time.ns_per_s) }, .awake) catch unreachable;

    try std.testing.expectEqual(@as(u64, 1), sim.sleep_call_count);
    try std.testing.expectEqual(@as(u64, 2 * std.time.ns_per_s), sim.monotonic_ns);
}

test "SimIo: clock resolution is nanosecond" {
    var sim: SimIo = .{ .prng = std.Random.DefaultPrng.init(0) };
    const sio = sim.io();

    const res = try Io.Clock.awake.resolution(sio);
    try std.testing.expectEqual(@as(i96, 1), res.nanoseconds);
}

test "SimIo: advanceToSlot" {
    const genesis_time: u64 = 1_606_824_023; // Mainnet genesis
    const seconds_per_slot: u64 = 12;

    var sim: SimIo = .{
        .prng = std.Random.DefaultPrng.init(0),
        .monotonic_ns = genesis_time * std.time.ns_per_s,
        .realtime_ns = @as(i128, genesis_time) * std.time.ns_per_s,
    };

    sim.advanceToSlot(1, genesis_time, seconds_per_slot);
    try std.testing.expectEqual((genesis_time + 12) * std.time.ns_per_s, sim.monotonic_ns);

    sim.advanceToSlot(10, genesis_time, seconds_per_slot);
    try std.testing.expectEqual((genesis_time + 120) * std.time.ns_per_s, sim.monotonic_ns);
}
