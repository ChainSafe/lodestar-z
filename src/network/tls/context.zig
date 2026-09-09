const std = @import("std");
const cert = @import("cert.zig");
const constants = @import("../constants.zig");
const keys = @import("../wire/keys.zig");
const peer_id = @import("../wire/peer_id.zig");
const verify = @import("verify.zig");
const c = @import("../quic/binding.zig").c;

pub const Error = error{OpenSslFailed} || cert.Error;

pub const keylog_capacity: usize = 1_280;

pub const HandshakeState = struct {
    now_unix: i64 = 0,
    peer_id: ?peer_id.PeerId = null,
    failure: ?verify.Error = null,
    keylog: []u8 = &.{},
    keylog_len: u16 = 0,
    keylog_dropped: u16 = 0,

    pub fn appendKeylog(self: *HandshakeState, line: []const u8) bool {
        std.debug.assert(self.keylog.len <= keylog_capacity);
        std.debug.assert(self.keylog_len <= self.keylog.len);
        if (line.len + 1 > self.keylog.len - self.keylog_len) {
            self.keylog_dropped +|= 1;
            return false;
        }
        @memcpy(self.keylog[self.keylog_len..][0..line.len], line);
        self.keylog[self.keylog_len + line.len] = '\n';
        self.keylog_len += @intCast(line.len + 1);
        return true;
    }

    pub fn takeKeylog(self: *HandshakeState, out: []u8) usize {
        std.debug.assert(self.keylog_len <= self.keylog.len);
        std.debug.assert(out.len >= self.keylog.len);
        const length = self.keylog_len;
        @memcpy(out[0..length], self.keylog[0..length]);
        self.keylog_len = 0;
        return length;
    }
};

const alpn_protos = [_]u8{constants.alpn.len} ++ constants.alpn.*;

const HandshakeIndex = struct {
    value: std.atomic.Value(c_int) = .init(-1),
    mutex: std.Io.Mutex = .init,

    fn get(self: *HandshakeIndex) error{OpenSslFailed}!c_int {
        const ready = self.value.load(.acquire);
        if (ready >= 0) return ready;
        std.Io.Threaded.mutexLock(&self.mutex);
        defer std.Io.Threaded.mutexUnlock(&self.mutex);
        const initialized = self.value.load(.monotonic);
        if (initialized >= 0) return initialized;
        const index = c.SSL_get_ex_new_index(0, null, null, null, null);
        if (index < 0) return error.OpenSslFailed;
        self.value.store(index, .release);
        return index;
    }
};

var handshake_index: HandshakeIndex = .{};

pub const Context = struct {
    ssl_ctx: *c.SSL_CTX,
    certificate: cert.Certificate,
    local_peer_id: peer_id.PeerId,

    pub fn init(host: *const keys.KeyPair, now_unix: i64, serial: [8]u8) Error!Context {
        const host_key = host.publicKey();
        return initWith(&host_key, host, now_unix, serial);
    }

    pub fn initWith(
        host_key: *const keys.PublicKey,
        signer: *const keys.KeyPair,
        now_unix: i64,
        serial: [8]u8,
    ) Error!Context {
        _ = try handshake_index.get();

        var certificate = try cert.Certificate.createWith(host_key, signer, now_unix, serial);
        errdefer certificate.deinit();

        const ssl_ctx = c.SSL_CTX_new(c.TLS_method()) orelse return error.OpenSslFailed;
        errdefer c.SSL_CTX_free(ssl_ctx);

        if (c.SSL_CTX_set_min_proto_version(ssl_ctx, c.TLS1_3_VERSION) != 1) {
            return error.OpenSslFailed;
        }
        if (c.SSL_CTX_set_max_proto_version(ssl_ctx, c.TLS1_3_VERSION) != 1) {
            return error.OpenSslFailed;
        }
        if (c.SSL_CTX_use_certificate(ssl_ctx, certificate.x509) != 1) return error.OpenSslFailed;
        if (c.SSL_CTX_use_PrivateKey(ssl_ctx, certificate.key) != 1) return error.OpenSslFailed;
        _ = c.SSL_CTX_set_options(ssl_ctx, c.SSL_OP_NO_TICKET);
        if (c.SSL_CTX_set_alpn_protos(ssl_ctx, &alpn_protos, alpn_protos.len) != 0) {
            return error.OpenSslFailed;
        }
        c.SSL_CTX_set_alpn_select_cb(ssl_ctx, alpnSelect, null);
        c.SSL_CTX_set_keylog_callback(ssl_ctx, keylogCallback);
        c.SSL_CTX_set_custom_verify(
            ssl_ctx,
            c.SSL_VERIFY_PEER | c.SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
            verifyCallback,
        );

        return .{
            .ssl_ctx = ssl_ctx,
            .certificate = certificate,
            .local_peer_id = peer_id.PeerId.fromPublicKey(host_key),
        };
    }

    pub fn deinit(self: *Context) void {
        c.SSL_CTX_free(self.ssl_ctx);
        self.certificate.deinit();
        self.* = undefined;
    }

    pub fn newSsl(self: *const Context, state: *HandshakeState) Error!*c.SSL {
        const ssl = c.SSL_new(self.ssl_ctx) orelse return error.OpenSslFailed;
        errdefer c.SSL_free(ssl);
        if (c.SSL_set_ex_data(ssl, try handshake_index.get(), state) != 1) return error.OpenSslFailed;
        return ssl;
    }
};

pub fn handshakeState(ssl: *c.SSL) ?*HandshakeState {
    const index = handshake_index.value.load(.acquire);
    if (index < 0) return null;
    const raw = c.SSL_get_ex_data(ssl, index) orelse return null;
    return @ptrCast(@alignCast(raw));
}

fn verifyCallback(ssl: ?*c.SSL, out_alert: [*c]u8) callconv(.c) c.enum_ssl_verify_result_t {
    out_alert.* = c.SSL_AD_BAD_CERTIFICATE;
    const handle = ssl orelse return c.ssl_verify_invalid;
    const state = handshakeState(handle) orelse return c.ssl_verify_invalid;
    const chain = c.SSL_get0_peer_certificates(handle) orelse return c.ssl_verify_invalid;
    if (c.sk_CRYPTO_BUFFER_num(chain) != 1) return c.ssl_verify_invalid;
    const buffer = c.sk_CRYPTO_BUFFER_value(chain, 0) orelse return c.ssl_verify_invalid;
    const der = c.CRYPTO_BUFFER_data(buffer)[0..c.CRYPTO_BUFFER_len(buffer)];
    state.peer_id = verify.verifyDer(der, state.now_unix) catch |err| {
        state.failure = err;
        out_alert.* = switch (err) {
            error.CertificateExpired => c.SSL_AD_CERTIFICATE_EXPIRED,
            else => c.SSL_AD_BAD_CERTIFICATE,
        };
        return c.ssl_verify_invalid;
    };
    return c.ssl_verify_ok;
}

fn keylogCallback(ssl: ?*const c.SSL, line: [*c]const u8) callconv(.c) void {
    const handle = ssl orelse return;
    const state = handshakeState(@constCast(handle)) orelse return;
    _ = state.appendKeylog(std.mem.span(line));
}

fn alpnSelect(
    ssl: ?*c.SSL,
    out: [*c][*c]const u8,
    out_len: [*c]u8,
    in: [*c]const u8,
    in_len: c_uint,
    arg: ?*anyopaque,
) callconv(.c) c_int {
    _ = ssl;
    _ = arg;
    const result = c.SSL_select_next_proto(
        @ptrCast(out),
        out_len,
        in,
        in_len,
        &alpn_protos,
        alpn_protos.len,
    );
    if (result == c.OPENSSL_NPN_NEGOTIATED) return c.SSL_TLSEXT_ERR_OK;
    return c.SSL_TLSEXT_ERR_ALERT_FATAL;
}

test "context publishes one handshake index across concurrent initializers" {
    const Worker = struct {
        index: *HandshakeIndex,
        start: *std.Io.Event,
        result: c_int = -1,

        fn run(self: *@This()) void {
            self.start.waitUncancelable(std.testing.io);
            self.result = self.index.get() catch return;
        }
    };
    var index: HandshakeIndex = .{};
    var start: std.Io.Event = .unset;
    var workers: [8]Worker = undefined;
    var threads: [workers.len]std.Thread = undefined;
    var started: usize = 0;
    defer {
        start.set(std.testing.io);
        for (threads[0..started]) |thread| thread.join();
    }
    for (&workers, &threads) |*worker, *thread| {
        worker.* = .{ .index = &index, .start = &start };
        thread.* = try std.Thread.spawn(.{}, Worker.run, .{worker});
        started += 1;
    }
    start.set(std.testing.io);
    for (threads) |thread| thread.join();
    started = 0;
    const published = try index.get();
    try std.testing.expect(published >= 0);
    for (workers) |worker| try std.testing.expectEqual(published, worker.result);
}
