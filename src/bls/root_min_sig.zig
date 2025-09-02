const min_sig_sig_variant = @import("./root_c_abi_min_sig.zig");
pub const PublicKey = min_sig_sig_variant.PublicKey;
pub const AggregatePublicKey = min_sig_sig_variant.AggregatePublicKey;
pub const Signature = min_sig_sig_variant.Signature;
pub const AggregateSignature = min_sig_sig_variant.AggregateSignature;
pub const SecretKey = min_sig_sig_variant.SecretKey;
pub const aggregateWithRandomness = min_sig_sig_variant.aggregateWithRandomness;
