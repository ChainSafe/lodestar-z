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
    keylog: [keylog_capacity]u8 = undefined,
    keylog_len: u16 = 0,
    keylog_dropped: u16 = 0,

    pub fn takeKeylog(self: *HandshakeState, out: []u8) usize {
        std.debug.assert(self.keylog_len <= keylog_capacity);
        std.debug.assert(out.len >= keylog_capacity);
        const length = self.keylog_len;
        @memcpy(out[0..length], self.keylog[0..length]);
        self.keylog_len = 0;
        return length;
    }
};

const alpn_protos = [_]u8{constants.alpn.len} ++ constants.alpn.*;

var ex_data_index: c_int = -1;

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
        if (ex_data_index < 0) {
            ex_data_index = c.SSL_get_ex_new_index(0, null, null, null, null);
            if (ex_data_index < 0) return error.OpenSslFailed;
        }

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
        if (c.SSL_set_ex_data(ssl, ex_data_index, state) != 1) return error.OpenSslFailed;
        return ssl;
    }
};

pub fn handshakeState(ssl: *c.SSL) ?*HandshakeState {
    const raw = c.SSL_get_ex_data(ssl, ex_data_index) orelse return null;
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
    const text = std.mem.span(line);
    std.debug.assert(state.keylog_len <= keylog_capacity);
    if (text.len + 1 > keylog_capacity - state.keylog_len) {
        state.keylog_dropped +|= 1;
        return;
    }
    @memcpy(state.keylog[state.keylog_len..][0..text.len], text);
    state.keylog[state.keylog_len + text.len] = '\n';
    state.keylog_len += @intCast(text.len + 1);
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
