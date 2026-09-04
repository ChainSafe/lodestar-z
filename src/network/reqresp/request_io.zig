const std = @import("std");
const engine_mod = @import("../quic/engine.zig");
const codec = @import("codec.zig");
const stream_io = @import("../stream_io.zig");

pub const RequestIO = struct {
    sink: []u8 = &.{},
    scratch: []u8 = &.{},
    read_buffer: []u8 = &.{},
    buffered_start: usize = 0,
    buffered_end: usize = 0,
    fin_seen: bool = false,
    decoder: codec.Decoder = undefined,
    decoding: bool = false,
    writer: codec.ChunkWriter = undefined,
    writing: bool = false,
    outbox: stream_io.Outbox = .{},

    pub const Flush = struct { done: bool, progressed: bool };

    pub fn flush(
        self: *RequestIO,
        engine: *engine_mod.Engine,
        stream: engine_mod.StreamHandle,
        fin: bool,
    ) !Flush {
        if (self.writing and self.outbox.idle()) {
            const piece = try self.writer.next(self.scratch);
            const last = self.writer.done();
            self.outbox.queue(piece, last and fin);
            if (last) self.writing = false;
        }
        const before = self.outbox.offset;
        const fin_before = self.outbox.fin;
        const flushed = try self.outbox.pump(engine, stream);
        const progressed = self.outbox.offset > before or (fin_before and !self.outbox.fin);
        const done = flushed and !self.writing;
        if (flushed) self.outbox = .{};
        return .{ .done = done, .progressed = progressed };
    }

    pub const Input = struct { bytes: []const u8, fin: bool, progressed: bool, reset: bool };

    pub fn read(
        self: *RequestIO,
        engine: *engine_mod.Engine,
        stream: engine_mod.StreamHandle,
    ) engine_mod.StreamError!Input {
        var progressed = false;
        var reset = false;
        if (self.buffered_start == self.buffered_end and !self.fin_seen) {
            const incoming = try engine.read(stream, self.read_buffer);
            self.buffered_start = 0;
            self.buffered_end = incoming.len;
            self.fin_seen = incoming.fin;
            progressed = incoming.len > 0 or incoming.fin;
            reset = incoming.reset_code != null;
        }
        return .{
            .bytes = self.read_buffer[self.buffered_start..self.buffered_end],
            .fin = self.fin_seen,
            .progressed = progressed,
            .reset = reset,
        };
    }

    pub fn feed(self: *RequestIO, bytes: []const u8) codec.Error!bool {
        const progress = try self.decoder.feed(bytes);
        std.debug.assert(progress.consumed <= self.buffered_end - self.buffered_start);
        self.buffered_start += progress.consumed;
        return progress.done;
    }

    pub fn clear(self: *RequestIO) void {
        self.buffered_start = 0;
        self.buffered_end = 0;
        self.decoding = false;
        self.writing = false;
        self.decoder = undefined;
        self.writer = undefined;
        self.outbox = .{};
    }
};
