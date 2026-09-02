const std = @import("std");

const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
const scalar = std.crypto.ecc.Secp256k1.scalar;

pub const secret_key_length = 32;
pub const public_key_length = 33;
pub const protobuf_length = 37;
pub const signature_der_length_max = Ecdsa.Signature.der_encoded_length_max;

pub const half_order = [_]u8{
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
};

const protobuf_prefix = [_]u8{ 0x08, 0x02, 0x12, 0x21 };

pub const Error = error{
    InvalidSecretKey,
    InvalidPublicKey,
    InvalidProtobuf,
    InvalidSignature,
    SignatureVerificationFailed,
};

pub const PublicKey = struct {
    bytes: [public_key_length]u8,

    pub fn fromBytes(bytes: *const [public_key_length]u8) Error!PublicKey {
        _ = Ecdsa.PublicKey.fromSec1(bytes) catch return error.InvalidPublicKey;
        return .{ .bytes = bytes.* };
    }

    pub fn encodeProtobuf(self: *const PublicKey) [protobuf_length]u8 {
        return protobuf_prefix ++ self.bytes;
    }

    pub fn decodeProtobuf(bytes: []const u8) Error!PublicKey {
        if (bytes.len != protobuf_length) return error.InvalidProtobuf;
        if (!std.mem.eql(u8, bytes[0..protobuf_prefix.len], &protobuf_prefix)) {
            return error.InvalidProtobuf;
        }
        return fromBytes(bytes[protobuf_prefix.len..][0..public_key_length]);
    }

    pub fn verify(
        self: *const PublicKey,
        message: []const u8,
        signature_der: []const u8,
    ) Error!void {
        const signature = Ecdsa.Signature.fromDer(signature_der) catch
            return error.InvalidSignature;
        const key = Ecdsa.PublicKey.fromSec1(&self.bytes) catch return error.InvalidPublicKey;
        signature.verify(message, key) catch return error.SignatureVerificationFailed;
    }
};

pub const KeyPair = struct {
    inner: Ecdsa.KeyPair,

    pub fn fromSecretKey(secret: *const [secret_key_length]u8) Error!KeyPair {
        const secret_key = Ecdsa.SecretKey.fromBytes(secret.*) catch return error.InvalidSecretKey;
        const inner = Ecdsa.KeyPair.fromSecretKey(secret_key) catch return error.InvalidSecretKey;
        return .{ .inner = inner };
    }

    pub fn generate(io: std.Io) KeyPair {
        return .{ .inner = Ecdsa.KeyPair.generate(io) };
    }

    pub fn publicKey(self: *const KeyPair) PublicKey {
        return .{ .bytes = self.inner.public_key.toCompressedSec1() };
    }

    pub fn sign(
        self: *const KeyPair,
        message: []const u8,
        out: *[signature_der_length_max]u8,
    ) Error![]u8 {
        const signature = self.inner.sign(message, null) catch return error.InvalidSecretKey;
        return normalizeLowS(signature).toDer(out);
    }
};

fn normalizeLowS(signature: Ecdsa.Signature) Ecdsa.Signature {
    if (std.mem.order(u8, &signature.s, &half_order) != .gt) return signature;
    const negated = scalar.neg(signature.s, .big) catch unreachable;
    return .{ .r = signature.r, .s = negated };
}
