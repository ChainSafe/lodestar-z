//! Unified signature set abstraction for BLS batch verification.
//!
//! Two variants:
//! - `single`: one pubkey + message + signature (proposer, randao, voluntary exit, etc.)
//! - `aggregate`: multiple pubkeys aggregated + message + signature (attestations, sync committee)
//!
//! All fields are stored as already-parsed BLS types (not raw bytes) for zero-copy
//! integration with the batch verifier. Pubkeys come from the epoch cache (already
//! decompressed and validated), so no re-validation is needed at verification time.

const std = @import("std");
const bls = @import("root.zig");
const PublicKey = bls.PublicKey;
const Signature = bls.Signature;
const BlstError = bls.BlstError;

pub const SignatureSet = struct {
    /// The signing root (hash of the signed message with domain separation).
    signing_root: [32]u8,

    /// The BLS signature (compressed, 96 bytes). Decompressed at verification time.
    signature: [96]u8,

    /// For single sets: the already-decompressed pubkey.
    /// For aggregate sets: null (use `pubkeys` slice instead).
    pubkey: ?PublicKey = null,

    /// For aggregate sets: slice of already-decompressed pubkeys to aggregate.
    /// For single sets: null.
    /// Owned by the caller — the batch verifier does NOT free this.
    pubkeys: ?[]const PublicKey = null,

    /// Create a single-pubkey signature set.
    pub fn initSingle(pubkey: PublicKey, signing_root: [32]u8, signature: [96]u8) SignatureSet {
        return .{
            .signing_root = signing_root,
            .signature = signature,
            .pubkey = pubkey,
        };
    }

    /// Create an aggregate-pubkey signature set.
    /// The `pubkeys` slice must outlive this SignatureSet (or the batch verify call).
    pub fn initAggregate(pubkeys: []const PublicKey, signing_root: [32]u8, signature: [96]u8) SignatureSet {
        return .{
            .signing_root = signing_root,
            .signature = signature,
            .pubkeys = pubkeys,
        };
    }

    /// Returns true if this is a single-pubkey set.
    pub fn isSingle(self: *const SignatureSet) bool {
        return self.pubkey != null;
    }

    /// Resolve to a single PublicKey for use in batch verification.
    /// For single sets, returns the pubkey directly.
    /// For aggregate sets, aggregates all pubkeys into one.
    pub fn resolvePublicKey(self: *const SignatureSet) BlstError!PublicKey {
        if (self.pubkey) |pk| return pk;
        if (self.pubkeys) |pks| {
            if (pks.len == 0) return BlstError.AggrTypeMismatch;
            if (pks.len == 1) return pks[0];
            const agg = try bls.AggregatePublicKey.aggregate(pks, false);
            return agg.toPublicKey();
        }
        return BlstError.AggrTypeMismatch;
    }

    /// Decompress the signature bytes into a Signature.
    pub fn decompressSignature(self: *const SignatureSet) BlstError!Signature {
        return Signature.uncompress(&self.signature);
    }
};

/// A signature set wrapper that can own aggregate-pubkey buffers when the
/// caller needs a stable lifetime across queued verification work.
pub const OwnedSignatureSet = struct {
    set: SignatureSet,
    owned_pubkeys: ?[]const PublicKey = null,
    allocator: ?std.mem.Allocator = null,

    pub fn initSingle(pubkey: PublicKey, signing_root: [32]u8, signature: [96]u8) OwnedSignatureSet {
        return .{
            .set = SignatureSet.initSingle(pubkey, signing_root, signature),
        };
    }

    pub fn initOwnedAggregate(
        allocator: std.mem.Allocator,
        pubkeys: []const PublicKey,
        signing_root: [32]u8,
        signature: [96]u8,
    ) OwnedSignatureSet {
        return .{
            .set = SignatureSet.initAggregate(pubkeys, signing_root, signature),
            .owned_pubkeys = pubkeys,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *OwnedSignatureSet) void {
        if (self.owned_pubkeys) |pubkeys| {
            self.allocator.?.free(pubkeys);
        }
        self.* = undefined;
    }
};
