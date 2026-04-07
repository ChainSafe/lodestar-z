const std = @import("std");

const Io = std.Io;
const Allocator = std.mem.Allocator;

const c = @cImport({
    @cInclude("sys/statvfs.h");
    @cInclude("unistd.h");
});

const ValidatorClient = @import("validator.zig").ValidatorClient;
const ValidatorMetrics = @import("metrics.zig").ValidatorMetrics;
const time = @import("time.zig");

const log = std.log.scoped(.validator_monitoring);

pub const MonitoringOptions = struct {
    endpoint: []const u8,
    interval_ms: u64 = 60_000,
    initial_delay_ms: u64 = 30_000,
    request_timeout_ms: u64 = 10_000,
    collect_system_stats: bool = false,
};

const ValidatorRecord = struct {
    version: u32 = 1,
    timestamp: u64,
    process: []const u8 = "validator",
    cpu_process_seconds_total: f64,
    memory_process_bytes: u64,
    client_name: []const u8 = "lodestar-z",
    client_version: []const u8,
    client_build: u64 = 0,
    sync_eth2_fallback_configured: bool,
    sync_eth2_fallback_connected: bool,
    validator_total: u64,
    validator_active: u64,
};

const SystemRecord = struct {
    version: u32 = 1,
    timestamp: u64,
    process: []const u8 = "system",
    cpu_cores: u32,
    cpu_threads: u32,
    cpu_node_system_seconds_total: f64,
    cpu_node_user_seconds_total: f64,
    cpu_node_iowait_seconds_total: f64,
    cpu_node_idle_seconds_total: f64,
    memory_node_bytes_total: u64,
    memory_node_bytes_free: u64,
    memory_node_bytes_cached: u64,
    memory_node_bytes_buffers: u64,
    disk_node_bytes_total: u64,
    disk_node_bytes_free: u64,
};

const StaticSystemInfo = struct {
    cpu_cores: u32,
    cpu_threads: u32,
};

const CpuTimes = struct {
    total_seconds: f64,
    user_seconds: f64,
    iowait_seconds: f64,
    idle_seconds: f64,
};

const MemoryStats = struct {
    total_bytes: u64,
    free_bytes: u64,
    cached_bytes: u64,
    buffers_bytes: u64,
};

const DiskUsage = struct {
    total_bytes: u64,
    free_bytes: u64,
};

pub const MonitoringService = struct {
    allocator: Allocator,
    io: Io,
    client: *ValidatorClient,
    metrics: *ValidatorMetrics,
    options: MonitoringOptions,
    client_version: []const u8,
    endpoint: []u8,
    endpoint_uri: std.Uri,
    endpoint_host: []u8,
    shutdown_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    http_client: std.http.Client,
    system_info: ?StaticSystemInfo = null,

    const SendTaskResult = union(enum) {
        success,
        failure: anyerror,
        canceled,
    };

    const TimerResult = enum {
        fired,
        canceled,
    };

    const SendEvent = union(enum) {
        request: SendTaskResult,
        timeout: TimerResult,
    };

    pub fn init(
        allocator: Allocator,
        io: Io,
        client: *ValidatorClient,
        metrics: *ValidatorMetrics,
        options: MonitoringOptions,
        client_version: []const u8,
    ) !MonitoringService {
        if (options.endpoint.len == 0) return error.InvalidMonitoringEndpoint;
        if (options.interval_ms == 0) return error.InvalidMonitoringInterval;
        if (options.initial_delay_ms == 0) return error.InvalidMonitoringInitialDelay;
        if (options.request_timeout_ms == 0) return error.InvalidMonitoringRequestTimeout;

        const endpoint = try allocator.dupe(u8, options.endpoint);
        errdefer allocator.free(endpoint);

        const endpoint_uri = std.Uri.parse(endpoint) catch return error.InvalidMonitoringEndpoint;
        const scheme = endpoint_uri.scheme;
        if (scheme.len == 0) return error.InvalidMonitoringEndpoint;
        if (!std.mem.eql(u8, scheme, "https") and !std.mem.eql(u8, scheme, "http")) {
            return error.InvalidMonitoringEndpoint;
        }
        var endpoint_host_buf: [std.Io.net.HostName.max_len]u8 = undefined;
        const endpoint_host_name = endpoint_uri.getHost(&endpoint_host_buf) catch return error.InvalidMonitoringEndpoint;
        const endpoint_host = try allocator.dupe(u8, endpoint_host_name.bytes);
        errdefer allocator.free(endpoint_host);
        if (std.mem.eql(u8, scheme, "http")) {
            log.warn(
                "Insecure validator monitoring endpoint, use HTTPS in production host={s}",
                .{endpoint_host},
            );
        }

        const system_info = if (options.collect_system_stats)
            try collectStaticSystemInfo(io, allocator)
        else
            null;

        return .{
            .allocator = allocator,
            .io = io,
            .client = client,
            .metrics = metrics,
            .options = options,
            .client_version = client_version,
            .endpoint = endpoint,
            .endpoint_uri = endpoint_uri,
            .endpoint_host = endpoint_host,
            .http_client = .{
                .allocator = allocator,
                .io = io,
            },
            .system_info = system_info,
        };
    }

    pub fn deinit(self: *MonitoringService) void {
        self.http_client.deinit();
        self.allocator.free(self.endpoint_host);
        self.allocator.free(self.endpoint);
    }

    pub fn requestShutdown(self: *MonitoringService) void {
        self.shutdown_requested.store(true, .release);
    }

    pub fn run(self: *MonitoringService) !void {
        log.info("validator monitoring started remote={s} interval_ms={d}", .{
            self.endpoint_host,
            self.options.interval_ms,
        });

        try self.sleepInterruptibly(self.options.initial_delay_ms);
        while (!self.shutdown_requested.load(.acquire)) {
            self.sendOnce() catch |err| {
                log.warn("Failed to send validator monitoring stats to {s}: {s}", .{
                    self.endpoint_host,
                    @errorName(err),
                });
            };
            try self.sleepInterruptibly(self.options.interval_ms);
        }
    }

    fn sleepInterruptibly(self: *MonitoringService, duration_ms: u64) !void {
        var remaining_ns = duration_ms * std.time.ns_per_ms;
        const sleep_slice_ns = std.time.ns_per_s;
        while (remaining_ns > 0 and !self.shutdown_requested.load(.acquire)) {
            const sleep_ns = @min(remaining_ns, sleep_slice_ns);
            try self.io.sleep(.{ .nanoseconds = sleep_ns }, .real);
            remaining_ns -= sleep_ns;
        }
    }

    fn sendOnce(self: *MonitoringService) !void {
        const payload = try self.collectPayload();
        defer self.allocator.free(payload);

        const send_started_ns = time.awakeNanoseconds(self.io);
        var send_succeeded = false;
        defer {
            const elapsed_seconds = nsToSeconds(time.awakeNanoseconds(self.io) -| send_started_ns);
            self.metrics.observeMonitoringSend(elapsed_seconds, send_succeeded);
        }

        try self.sendPayloadWithTimeout(payload, self.options.request_timeout_ms);
        send_succeeded = true;
    }

    fn collectPayload(self: *MonitoringService) ![]u8 {
        const collect_started_ns = time.awakeNanoseconds(self.io);
        defer self.metrics.observeMonitoringCollect(nsToSeconds(time.awakeNanoseconds(self.io) -| collect_started_ns));

        const timestamp_ms = time.realMilliseconds(self.io);
        const counts = self.client.validatorCounts();
        const failover = self.client.api.failoverStatus();

        const validator_record: ValidatorRecord = .{
            .timestamp = timestamp_ms,
            .cpu_process_seconds_total = currentProcessCpuSeconds(),
            .memory_process_bytes = try currentProcessResidentBytes(self.io, self.allocator),
            .client_version = self.client_version,
            .sync_eth2_fallback_configured = failover.configured,
            .sync_eth2_fallback_connected = failover.connected,
            .validator_total = @intCast(counts.total),
            .validator_active = @intCast(counts.active),
        };

        var out: std.Io.Writer.Allocating = .init(self.allocator);
        errdefer out.deinit();
        var stream: std.json.Stringify = .{ .writer = &out.writer };

        try stream.beginArray();
        try stream.write(validator_record);
        if (self.options.collect_system_stats) {
            const system_record = try self.collectSystemRecord(timestamp_ms);
            try stream.write(system_record);
        }
        try stream.endArray();

        return out.toOwnedSlice();
    }

    fn collectSystemRecord(self: *MonitoringService, timestamp_ms: u64) !SystemRecord {
        const info = self.system_info orelse return error.SystemStatsUnavailable;
        const cpu = try currentSystemCpuTimes(self.io, self.allocator);
        const memory = try currentSystemMemory(self.io, self.allocator);
        const disk = try currentDiskUsage();

        return .{
            .timestamp = timestamp_ms,
            .cpu_cores = info.cpu_cores,
            .cpu_threads = info.cpu_threads,
            .cpu_node_system_seconds_total = cpu.total_seconds,
            .cpu_node_user_seconds_total = cpu.user_seconds,
            .cpu_node_iowait_seconds_total = cpu.iowait_seconds,
            .cpu_node_idle_seconds_total = cpu.idle_seconds,
            .memory_node_bytes_total = memory.total_bytes,
            .memory_node_bytes_free = memory.free_bytes,
            .memory_node_bytes_cached = memory.cached_bytes,
            .memory_node_bytes_buffers = memory.buffers_bytes,
            .disk_node_bytes_total = disk.total_bytes,
            .disk_node_bytes_free = disk.free_bytes,
        };
    }

    fn sendTaskResult(self: *MonitoringService, payload: []const u8) SendTaskResult {
        self.sendPayloadBlocking(payload) catch |err| switch (err) {
            error.Canceled => return .canceled,
            else => return .{ .failure = err },
        };
        return .success;
    }

    fn waitTimeout(io: Io, timeout: Io.Timeout) TimerResult {
        timeout.sleep(io) catch |err| switch (err) {
            error.Canceled => return .canceled,
        };
        return .fired;
    }

    fn sendPayloadWithTimeout(self: *MonitoringService, payload: []const u8, timeout_ms: u64) !void {
        var events_buf: [2]SendEvent = undefined;
        var select = std.Io.Select(SendEvent).init(self.io, &events_buf);

        try select.concurrent(.request, sendTaskResult, .{ self, payload });
        select.async(.timeout, waitTimeout, .{ self.io, timeoutFromMs(timeout_ms) });

        var timed_out = false;
        var result: ?SendTaskResult = null;

        while (true) {
            const event = try select.await();
            switch (event) {
                .request => |send_result| {
                    result = send_result;
                    break;
                },
                .timeout => |timeout_result| {
                    if (timeout_result == .fired) {
                        timed_out = true;
                        break;
                    }
                },
            }
        }

        while (select.cancel()) |_| {}

        if (timed_out) return error.Timeout;
        return switch (result orelse unreachable) {
            .success => {},
            .failure => |err| err,
            .canceled => error.Canceled,
        };
    }

    fn sendPayloadBlocking(self: *MonitoringService, payload: []const u8) !void {
        var req = try self.http_client.request(.POST, self.endpoint_uri, .{
            .keep_alive = true,
            .extra_headers = &.{
                .{ .name = "Accept", .value = "application/json" },
            },
            .headers = .{
                .content_type = .{ .override = "application/json" },
            },
        });
        defer req.deinit();

        req.transfer_encoding = .{ .content_length = payload.len };
        try req.sendBodyComplete(@constCast(payload));

        var redirect_buf: [1024]u8 = undefined;
        var response = try req.receiveHead(&redirect_buf);
        const status = @intFromEnum(response.head.status);

        var transfer_buf: [2048]u8 = undefined;
        const reader = response.reader(&transfer_buf);
        const response_body = reader.allocRemaining(self.allocator, Io.Limit.limited(64 * 1024)) catch |err| switch (err) {
            error.ReadFailed => return response.bodyErr() orelse error.ReadFailed,
            else => |e| return e,
        };
        defer self.allocator.free(response_body);

        if (status < 200 or status >= 300) {
            if (response_body.len > 0) {
                log.warn("validator monitoring endpoint returned HTTP {d}: {s}", .{ status, response_body });
            }
            return error.HttpError;
        }
    }
};

fn timeoutFromMs(timeout_ms: u64) std.Io.Timeout {
    return .{ .duration = .{
        .raw = .{ .nanoseconds = @as(i96, @intCast(timeout_ms * std.time.ns_per_ms)) },
        .clock = .real,
    } };
}

fn nsToSeconds(ns: u64) f64 {
    return @as(f64, @floatFromInt(ns)) / @as(f64, @floatFromInt(std.time.ns_per_s));
}

fn currentProcessCpuSeconds() f64 {
    const usage = std.posix.getrusage(std.posix.rusage.SELF);
    return timevalSeconds(usage.utime) + timevalSeconds(usage.stime);
}

fn currentProcessResidentBytes(io: Io, allocator: Allocator) !u64 {
    const contents = try readSmallFileAlloc(io, allocator, "/proc/self/statm", 1024);
    defer allocator.free(contents);

    var it = std.mem.tokenizeScalar(u8, contents, ' ');
    _ = it.next() orelse return error.InvalidProcStatm;
    const resident_pages_text = it.next() orelse return error.InvalidProcStatm;
    const resident_pages = try std.fmt.parseInt(u64, resident_pages_text, 10);
    return resident_pages * pageSize();
}

fn collectStaticSystemInfo(io: Io, allocator: Allocator) !StaticSystemInfo {
    const contents = try readSmallFileAlloc(io, allocator, "/proc/cpuinfo", 2 * 1024 * 1024);
    defer allocator.free(contents);

    var cpu_threads: u32 = 0;
    var unique_cores: std.AutoHashMapUnmanaged(u64, void) = .empty;
    defer unique_cores.deinit(allocator);

    var current_physical_id: ?u32 = null;
    var current_core_id: ?u32 = null;

    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0) {
            if (current_physical_id != null and current_core_id != null) {
                const key = (@as(u64, current_physical_id.?) << 32) | current_core_id.?;
                try unique_cores.put(allocator, key, {});
            }
            current_physical_id = null;
            current_core_id = null;
            continue;
        }

        const colon_index = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon_index], " \t");
        const value = std.mem.trim(u8, line[colon_index + 1 ..], " \t");

        if (std.mem.eql(u8, name, "processor")) {
            cpu_threads += 1;
        } else if (std.mem.eql(u8, name, "physical id")) {
            current_physical_id = std.fmt.parseInt(u32, value, 10) catch null;
        } else if (std.mem.eql(u8, name, "core id")) {
            current_core_id = std.fmt.parseInt(u32, value, 10) catch null;
        }
    }

    if (current_physical_id != null and current_core_id != null) {
        const key = (@as(u64, current_physical_id.?) << 32) | current_core_id.?;
        try unique_cores.put(allocator, key, {});
    }

    if (cpu_threads == 0) {
        cpu_threads = @intCast(std.Thread.getCpuCount() catch 0);
    }

    return .{
        .cpu_cores = if (unique_cores.count() > 0) @intCast(unique_cores.count()) else cpu_threads,
        .cpu_threads = cpu_threads,
    };
}

fn currentSystemCpuTimes(io: Io, allocator: Allocator) !CpuTimes {
    const contents = try readSmallFileAlloc(io, allocator, "/proc/stat", 16 * 1024);
    defer allocator.free(contents);

    var lines = std.mem.splitScalar(u8, contents, '\n');
    const first_line = lines.next() orelse return error.InvalidProcStat;
    if (!std.mem.startsWith(u8, first_line, "cpu ")) return error.InvalidProcStat;

    var fields = std.mem.tokenizeAny(u8, first_line[4..], " \t");
    const user = try parseProcStatField(fields.next());
    const nice = try parseProcStatField(fields.next());
    const system = try parseProcStatField(fields.next());
    const idle = try parseProcStatField(fields.next());
    const iowait = try parseProcStatField(fields.next());
    const irq = try parseProcStatField(fields.next());
    const softirq = try parseProcStatField(fields.next());
    const steal = parseProcStatField(fields.next()) catch 0;
    const guest = parseProcStatField(fields.next()) catch 0;
    const guest_nice = parseProcStatField(fields.next()) catch 0;

    const tick_hz = clockTicksPerSecond();
    const total_ticks = user + nice + system + idle + iowait + irq + softirq + steal + guest + guest_nice;

    return .{
        .total_seconds = @as(f64, @floatFromInt(total_ticks)) / @as(f64, @floatFromInt(tick_hz)),
        .user_seconds = @as(f64, @floatFromInt(user)) / @as(f64, @floatFromInt(tick_hz)),
        .iowait_seconds = @as(f64, @floatFromInt(iowait)) / @as(f64, @floatFromInt(tick_hz)),
        .idle_seconds = @as(f64, @floatFromInt(idle)) / @as(f64, @floatFromInt(tick_hz)),
    };
}

fn currentSystemMemory(io: Io, allocator: Allocator) !MemoryStats {
    const contents = try readSmallFileAlloc(io, allocator, "/proc/meminfo", 16 * 1024);
    defer allocator.free(contents);

    var total_bytes: u64 = 0;
    var free_bytes: u64 = 0;
    var cached_bytes: u64 = 0;
    var buffers_bytes: u64 = 0;

    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0) continue;
        const colon_index = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon_index], " \t");
        const rest = std.mem.trim(u8, line[colon_index + 1 ..], " \t");

        var fields = std.mem.tokenizeAny(u8, rest, " \t");
        const value_text = fields.next() orelse continue;
        const value = std.fmt.parseInt(u64, value_text, 10) catch continue;
        const bytes = value * 1024;

        if (std.mem.eql(u8, name, "MemTotal")) {
            total_bytes = bytes;
        } else if (std.mem.eql(u8, name, "MemFree")) {
            free_bytes = bytes;
        } else if (std.mem.eql(u8, name, "Cached")) {
            cached_bytes = bytes;
        } else if (std.mem.eql(u8, name, "Buffers")) {
            buffers_bytes = bytes;
        }
    }

    return .{
        .total_bytes = total_bytes,
        .free_bytes = free_bytes,
        .cached_bytes = cached_bytes,
        .buffers_bytes = buffers_bytes,
    };
}

fn currentDiskUsage() !DiskUsage {
    var stat: c.struct_statvfs = undefined;
    if (c.statvfs("/", &stat) != 0) return error.StatvfsFailed;
    const block_size = if (stat.f_frsize != 0) stat.f_frsize else stat.f_bsize;
    const total_bytes = @as(u64, @intCast(stat.f_blocks)) * @as(u64, @intCast(block_size));
    const free_bytes = @as(u64, @intCast(stat.f_bavail)) * @as(u64, @intCast(block_size));
    return .{
        .total_bytes = total_bytes,
        .free_bytes = free_bytes,
    };
}

fn readSmallFileAlloc(io: Io, allocator: Allocator, path: []const u8, max_bytes: usize) ![]u8 {
    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    const stat = try file.stat(io);
    const size = @min(stat.size, max_bytes);
    const buf = try allocator.alloc(u8, size);
    errdefer allocator.free(buf);
    const n = try file.readPositionalAll(io, buf, 0);
    return buf[0..@min(n, size)];
}

fn parseProcStatField(field: ?[]const u8) !u64 {
    const text = field orelse return error.InvalidProcStat;
    return std.fmt.parseInt(u64, text, 10);
}

fn pageSize() u64 {
    const raw = std.c.sysconf(@intFromEnum(std.c._SC.PAGESIZE));
    if (raw <= 0) return std.heap.page_size_min;
    return @intCast(raw);
}

fn clockTicksPerSecond() u64 {
    const raw = c.sysconf(c._SC_CLK_TCK);
    if (raw <= 0) return 100;
    return @intCast(raw);
}

fn timevalSeconds(tv: anytype) f64 {
    return @as(f64, @floatFromInt(tv.sec)) + (@as(f64, @floatFromInt(tv.usec)) / 1_000_000.0);
}

test "monitoring payload encodes validator and system records" {
    const validator_record: ValidatorRecord = .{
        .timestamp = 1,
        .cpu_process_seconds_total = 1.25,
        .memory_process_bytes = 1024,
        .client_version = "0.1.0",
        .sync_eth2_fallback_configured = true,
        .sync_eth2_fallback_connected = false,
        .validator_total = 4,
        .validator_active = 3,
    };
    const system_record: SystemRecord = .{
        .timestamp = 1,
        .cpu_cores = 4,
        .cpu_threads = 8,
        .cpu_node_system_seconds_total = 10,
        .cpu_node_user_seconds_total = 3,
        .cpu_node_iowait_seconds_total = 1,
        .cpu_node_idle_seconds_total = 6,
        .memory_node_bytes_total = 10,
        .memory_node_bytes_free = 5,
        .memory_node_bytes_cached = 2,
        .memory_node_bytes_buffers = 1,
        .disk_node_bytes_total = 100,
        .disk_node_bytes_free = 40,
    };

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var stream: std.json.Stringify = .{ .writer = &out.writer };
    try stream.beginArray();
    try stream.write(validator_record);
    try stream.write(system_record);
    try stream.endArray();

    const json = out.written();
    try std.testing.expect(std.mem.indexOf(u8, json, "\"process\":\"validator\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"validator_total\":4") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"process\":\"system\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"cpu_threads\":8") != null);
}
