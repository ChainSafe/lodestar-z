const std = @import("std");
const Mutex = std.Thread.Mutex;
const AtomicOrder = std.builtin.AtomicOrder;
const Allocator = std.mem.Allocator;
const testing = std.testing;
const Xoshiro256 = std.Random.Xoshiro256;
const P = @import("./pairing.zig").Pairing;
const PairingError = @import("./pairing.zig").PairingError;
const spawnTask = @import("./thread_pool.zig").spawnTask;
const spawnTaskWg = @import("./thread_pool.zig").spawnTaskWg;
const waitAndWork = @import("./thread_pool.zig").waitAndWork;
const initializeThreadPool = @import("./thread_pool.zig").initializeThreadPool;
const deinitializeThreadPool = @import("./thread_pool.zig").deinitializeThreadPool;
const createMemoryPool = @import("./memory_pool.zig").createMemoryPool;
const BLST_FAILED_PAIRING = @import("./util.zig").BLST_FAILED_PAIRING;

const c = @cImport({
    @cInclude("blst.h");
});

const util = @import("util.zig");
const BLST_ERROR = util.BLST_ERROR;
const toBlstError = util.toBlstError;

/// specific constant used in aggregateWithRandomness() to avoid heap allocation
pub const MAX_SIGNATURE_SETS = 128;

/// ideally I want to have this struct inside test but it does not work
const Context = struct {
    fn callback(verification_res: c_uint) callconv(.C) void {
        if (Context.mutex) |_mutex| {
            _mutex.lock();
            Context.verify_result = verification_res;
            defer _mutex.unlock();
            if (Context.cond) |_cond| {
                _cond.signal();
            }
        }
    }

    var mutex: ?*Mutex = null;
    var cond: ?*std.Thread.Condition = null;
    var verify_result: ?c_uint = null;
};

/// generic implementation for both min_pk and min_sig
/// this is equivalent to Rust binding in blst/bindings/rust/src/lib.rs
pub fn createSigVariant(
    // Zig specific default functions
    default_pubkey_fn: anytype,
    default_agg_pubkey_fn: anytype,
    default_sig_fn: anytype,
    default_agg_sig_fn: anytype,
    comptime pk_type: type,
    comptime pk_aff_type: type,
    comptime sig_type: type,
    comptime sig_aff_type: type,
    sk_to_pk_fn: anytype,
    hash_or_encode: bool,
    hash_or_encode_to_fn: anytype,
    sign_fn: anytype,
    pk_eq_fn: anytype,
    sig_eq_fn: anytype,
    // 2 new zig specific eq functions
    agg_pk_eq_fn: anytype,
    agg_sig_eq_fn: anytype,
    verify_fn: anytype,
    pk_in_group_fn: anytype,
    pk_to_aff_fn: anytype,
    pk_from_aff_fn: anytype,
    pk_ser_fn: anytype,
    pk_comp_fn: anytype,
    pk_deser_fn: anytype,
    pk_uncomp_fn: anytype,
    pk_comp_size: usize,
    pk_ser_size: usize,
    sig_in_group_fn: anytype,
    sig_to_aff_fn: anytype,
    sig_from_aff_fn: anytype,
    sig_ser_fn: anytype,
    sig_comp_fn: anytype,
    sig_deser_fn: anytype,
    sig_uncomp_fn: anytype,
    sig_comp_size: usize,
    sig_ser_size: usize,
    pk_add_or_dbl_fn: anytype,
    pk_add_or_dbl_aff_fn: anytype,
    sig_add_or_dbl_fn: anytype,
    sig_add_or_dbl_aff_fn: anytype,
    pk_is_inf_fn: anytype,
    sig_is_inf_fn: anytype,
    sig_aggr_in_group_fn: anytype,
    // Zig specific multi_points
    pk_add_fn: anytype,
    pk_multi_scalar_mult_fn: anytype,
    pk_scratch_size_of_fn: anytype,
    pk_mult_fn: anytype,
    pk_generator_fn: anytype,
    pk_to_affines_fn: anytype,
    sig_add_fn: anytype,
    sig_multi_scalar_mult_fn: anytype,
    sig_scratch_size_of_fn: anytype,
    sig_mult_fn: anytype,
    sig_generator_fn: anytype,
    sig_to_affines_fn: anytype,
) type {
    const MemoryPool = createMemoryPool(MAX_SIGNATURE_SETS, pk_scratch_size_of_fn, sig_scratch_size_of_fn, P.sizeOf);

    const Pairing = struct {
        p: P,
        pool: *MemoryPool,
        buffer: []u8,
        mutex: Mutex,
        pub fn new(pool: *MemoryPool, hoe: bool, dst: []const u8) PairingError!@This() {
            const buffer = try pool.getPairingBuffer();
            const p = try P.new(&buffer[0], buffer.len, hoe, &dst[0], dst.len);
            return .{
                .p = p,
                .pool = pool,
                .buffer = buffer,
                .mutex = Mutex{},
            };
        }

        pub fn deinit(self: *@This()) !void {
            try self.pool.returnPairingBuffer(self.buffer);
        }

        pub fn sizeOf() usize {
            return P.sizeOf();
        }

        pub fn aggregate(self: *@This(), pk: *const pk_aff_type, pk_validate: bool, sig: ?*const sig_aff_type, sig_groupcheck: bool, msg: []const u8, aug: ?[]u8) BLST_ERROR!void {
            if (msg.len == 0) {
                return BLST_ERROR.BAD_ENCODING;
            }

            if (pk_comp_size == 48) {
                // min_pk
                return self.p.aggregateG1(pk, pk_validate, sig, sig_groupcheck, &msg[0], msg.len, aug);
            } else {
                // min_sig
                return self.p.aggregateG2(pk, pk_validate, sig, sig_groupcheck, &msg[0], msg.len, aug);
            }
        }

        pub fn mulAndAggregate(self: *@This(), pk: *const pk_aff_type, pk_validate: bool, sig: *const sig_aff_type, sig_groupcheck: bool, scalar: [*c]const u8, nbits: usize, msg: []const u8, aug: ?[]u8) BLST_ERROR!void {
            if (msg.len == 0) {
                return BLST_ERROR.BAD_ENCODING;
            }

            if (pk_comp_size == 48) {
                // min_pk
                return self.p.mulAndAggregateG1(pk, pk_validate, sig, sig_groupcheck, scalar, nbits, &msg[0], msg.len, aug);
            } else {
                // min_sig
                return self.p.mulAndAggregateG2(pk, pk_validate, sig, sig_groupcheck, scalar, nbits, &msg[0], msg.len, aug);
            }
        }

        pub fn commit(self: *@This()) void {
            self.p.commit();
        }

        pub fn aggregated(gtsig: *c.blst_fp12, sig: *const sig_aff_type) void {
            if (pk_comp_size == 48) {
                // min_pk
                P.aggregatedG1(gtsig, sig);
            } else {
                // min_sig
                P.aggregatedG2(gtsig, sig);
            }
        }

        pub fn merge(self: *@This(), other: *const @This()) !void {
            self.mutex.lock();
            defer self.mutex.unlock();
            try self.p.merge(&other.p);
        }

        pub fn finalVerify(self: *@This(), gtsig: ?*const c.blst_fp12) bool {
            return self.p.finalVerify(gtsig);
        }

        // add more methods here if needed
    };

    // TODO: implement Clone, Copy, Equal
    // each function has 2 version: 1 for Zig and 1 for C-ABI
    const PublicKey = struct {
        point: pk_aff_type,

        pub fn default() @This() {
            return .{
                .point = default_pubkey_fn(),
            };
        }

        pub fn defaultPublicKey() pk_aff_type {
            return default_pubkey_fn();
        }

        // Core operations

        // key_validate
        pub fn validate(self: *const @This()) BLST_ERROR!void {
            const res = validatePublicKey(&self.point);
            if (toBlstError(res)) |err| {
                return err;
            }
        }

        pub fn validatePublicKey(point: *const pk_aff_type) c_uint {
            if (pk_is_inf_fn(point)) {
                return c.BLST_PK_IS_INFINITY;
            }

            if (pk_in_group_fn(point) == false) {
                return c.BLST_POINT_NOT_IN_GROUP;
            }

            return c.BLST_SUCCESS;
        }

        pub fn keyValidate(key: []const u8) BLST_ERROR!void {
            const res = publicKeyBytesValidate(key);
            if (toBlstError(res)) |err| {
                return err;
            }
        }

        pub fn publicKeyBytesValidate(key: []const u8) c_uint {
            var point = default().point;
            const res = publicKeyFromBytes(&point, key);
            if (res != c.BLST_SUCCESS) {
                return res;
            }
            return validatePublicKey(&point);
        }

        pub fn fromAggregate(comptime AggregatePublicKey: type, agg_pk: *const AggregatePublicKey) @This() {
            var pk_aff = @This().default();
            publicKeyFromAggregate(&pk_aff.point, &agg_pk.point);
            return pk_aff;
        }

        pub fn publicKeyFromAggregate(out: *pk_aff_type, agg_pk: *const pk_type) void {
            return pk_to_aff_fn(out, agg_pk);
        }

        // Serdes

        pub fn compress(self: *const @This()) [pk_comp_size]u8 {
            var pk_comp = [_]u8{0} ** pk_comp_size;
            compressPublicKey(&pk_comp[0], &self.point);
            return pk_comp;
        }

        pub fn compressPublicKey(out: *u8, point: *const pk_aff_type) void {
            pk_comp_fn(out, point);
        }

        pub fn serialize(self: *const @This()) [pk_ser_size]u8 {
            var pk_out = [_]u8{0} ** pk_ser_size;
            serializePublicKey(&pk_out[0], &self.point);
            return pk_out;
        }

        pub fn serializePublicKey(out: *u8, point: *const pk_aff_type) void {
            pk_ser_fn(out, point);
        }

        pub fn uncompress(pk_comp: []const u8) BLST_ERROR!@This() {
            var pk = @This().default();
            const res = uncompressPublicKey(&pk.point, pk_comp);
            return toBlstError(res) orelse pk;
        }

        pub fn uncompressPublicKey(out: *pk_aff_type, pk_comp: []const u8) c_uint {
            if (pk_comp.len == pk_comp_size and (pk_comp[0] & 0x80) != 0) {
                return pk_uncomp_fn(out, &pk_comp[0]);
            }

            return c.BLST_BAD_ENCODING;
        }

        pub fn deserialize(pk_in: []const u8) BLST_ERROR!@This() {
            var pk = default();
            const res = deserializePublicKey(&pk.point, pk_in);
            return toBlstError(res) orelse pk;
        }

        pub fn deserializePublicKey(out: *pk_aff_type, pk_in: []const u8) c_uint {
            if ((pk_in.len == pk_ser_size and (pk_in[0] & 0x80) == 0) or
                (pk_in.len == pk_comp_size and (pk_in[0] & 0x80) != 0))
            {
                return pk_deser_fn(out, &pk_in[0]);
            }

            return c.BLST_BAD_ENCODING;
        }

        pub fn fromBytes(pk_in: []const u8) BLST_ERROR!@This() {
            return @This().deserialize(pk_in);
        }

        pub fn publicKeyFromBytes(point: *pk_aff_type, pk_in: []const u8) c_uint {
            return deserializePublicKey(point, pk_in);
        }

        pub fn toBytes(self: *const @This()) [pk_comp_size]u8 {
            return self.compress();
        }

        pub fn toPublicKeyBytes(out: *u8, point: *pk_aff_type) void {
            return compressPublicKey(out, point);
        }

        pub fn isEqual(self: *const @This(), other: *const @This()) bool {
            return pk_eq_fn(&self.point, &other.point);
        }

        pub fn isPublicKeyEqual(point: *pk_aff_type, other: *pk_aff_type) bool {
            return pk_eq_fn(point, other);
        }

        // TODO: PartialEq, Serialize, Deserialize?

    };

    // each function has 2 version: 1 for Zig and 1 for C-ABI
    const AggregatePublicKey = struct {
        point: pk_type,

        pub fn default() @This() {
            return .{
                .point = default_agg_pubkey_fn(),
            };
        }

        pub fn defaultAggregatePublicKey() pk_type {
            return default_agg_pubkey_fn();
        }

        pub fn fromPublicKey(pk: *const PublicKey) @This() {
            var agg_pk = @This().default();
            aggregateFromPublicKey(&agg_pk.point, &pk.point);

            return agg_pk;
        }

        pub fn aggregateFromPublicKey(out: *pk_type, pk: *const pk_aff_type) void {
            return pk_from_aff_fn(out, pk);
        }

        pub fn toPublicKey(self: *const @This()) PublicKey {
            var pk = PublicKey.default();
            aggregateToPublicKey(&pk.point, &self.point);
            return pk;
        }

        pub fn aggregateToPublicKey(out: *pk_aff_type, agg_pk: *const pk_type) void {
            return pk_to_aff_fn(out, agg_pk);
        }

        // Aggregate
        pub fn aggregate(pks: []*const PublicKey, pks_validate: bool) BLST_ERROR!@This() {
            if (pks.len == 0) {
                return BLST_ERROR.AGGR_TYPE_MISMATCH;
            }

            // this is unsafe code but we scanned through testTypeAlignment unit test
            const pk_aff_points: []*const pk_aff_type = @ptrCast(pks);
            var agg_pk = @This().default();
            const res = aggregatePublicKeys(&agg_pk.point, pk_aff_points, pks_validate);
            return toBlstError(res) orelse agg_pk;
        }

        pub fn aggregatePublicKeys(out: *pk_type, pks: []*const pk_aff_type, pks_validate: bool) c_uint {
            const len = pks.len;
            if (len == 0) {
                return c.BLST_AGGR_TYPE_MISMATCH;
            }
            if (pks_validate) {
                const res = PublicKey.validatePublicKey(pks[0]);
                if (res != c.BLST_SUCCESS) {
                    return res;
                }
            }

            aggregateFromPublicKey(out, pks[0]);
            for (1..len) |i| {
                if (pks_validate) {
                    const res = PublicKey.validatePublicKey(pks[i]);
                    if (res != c.BLST_SUCCESS) {
                        return res;
                    }
                }

                pk_add_or_dbl_aff_fn(out, out, pks[i]);
            }

            return c.BLST_SUCCESS;
        }

        // cannot deduplicate this function with the below 3 functions because pks may contain different sizes
        pub fn aggregateSerialized(pks: [][]const u8, pks_validate: bool) BLST_ERROR!@This() {
            // TODO - threading
            // rust binding is also not implementing multi-thread anyway
            if (pks.len == 0) {
                return BLST_ERROR.AGGR_TYPE_MISMATCH;
            }
            var pk = try PublicKey.fromBytes(pks[0]);
            if (pks_validate) {
                try pk.validate();
            }
            var agg_pk = @This().fromPublicKey(&pk);
            for (pks[1..]) |s| {
                pk = try PublicKey.fromBytes(s);
                if (pks_validate) {
                    try pk.validate();
                }
                pk_add_or_dbl_aff_fn(&agg_pk.point, &agg_pk.point, &pk.point);
            }

            return agg_pk;
        }

        pub fn aggregateSerializedPublicKeys(out: *pk_type, pks: [][*c]const u8, pk_len: usize, pks_validate: bool) c_uint {
            const pks_len = pks.len;
            if (pks_len <= 0) {
                return c.BLST_AGGR_TYPE_MISMATCH;
            }

            var pk = default_pubkey_fn();
            var res = PublicKey.publicKeyFromBytes(&pk, pks[0][0..pk_len]);
            if (res != c.BLST_SUCCESS) {
                return res;
            }

            if (pks_validate) {
                res = PublicKey.validatePublicKey(&pk);
                if (res != c.BLST_SUCCESS) {
                    return res;
                }
            }

            aggregateFromPublicKey(out, &pk);

            for (1..pks_len) |i| {
                var point = default_pubkey_fn();
                res = PublicKey.publicKeyFromBytes(&point, pks[i][0..pk_len]);
                if (res != c.BLST_SUCCESS) {
                    return res;
                }
                if (pks_validate) {
                    res = PublicKey.validatePublicKey(&point);
                    if (res != c.BLST_SUCCESS) {
                        return res;
                    }
                }
                pk_add_or_dbl_aff_fn(out, out, &point);
            }

            return c.BLST_SUCCESS;
        }

        pub fn addAggregate(self: *@This(), agg_pk: *const @This()) BLST_ERROR!void {
            addAggregatePublicKey(&self.point, &self.point, &agg_pk.point);
        }

        pub fn addAggregatePublicKey(out: *pk_type, agg_pk: *const pk_type) void {
            pk_add_or_dbl_fn(out, out, agg_pk);
        }

        pub fn addPublicKey(self: *@This(), pk: *const PublicKey, pk_validate: bool) BLST_ERROR!void {
            const res = addPublicKeyToAggregate(&self.point, &pk.point, pk_validate);
            if (toBlstError(res)) |err| {
                return err;
            }
        }

        pub fn addPublicKeyToAggregate(out: *pk_type, pk: *const pk_aff_type, pk_validate: bool) c_uint {
            if (pk_validate) {
                const res = PublicKey.validatePublicKey(pk);
                if (res != c.BLST_SUCCESS) {
                    return res;
                }
            }

            pk_add_or_dbl_aff_fn(out, out, pk);
            return c.BLST_SUCCESS;
        }

        pub fn isEqual(self: *const @This(), other: *const @This()) bool {
            return isAggregatePublicKeyEqual(&self.point, &other.point);
        }

        pub fn isAggregatePublicKeyEqual(point: *const pk_type, other: *const pk_type) bool {
            return agg_pk_eq_fn(point, other);
        }
    };

    const SignatureSet = extern struct {
        msg: [*c]const u8,
        pk: *const pk_aff_type,
        sig: *const sig_aff_type,
    };

    const Signature = struct {
        point: sig_aff_type,

        pub fn default() @This() {
            return .{
                .point = default_sig_fn(),
            };
        }

        pub fn defaultSignature() sig_aff_type {
            return default_sig_fn();
        }

        // sig_infcheck, check for infinity, is a way to avoid going
        // into resource-consuming verification. Passing 'false' is
        // always cryptographically safe, but application might want
        // to guard against obviously bogus individual[!] signatures.
        pub fn validate(self: *const @This(), sig_infcheck: bool) BLST_ERROR!void {
            const res = validateSignature(&self.point, sig_infcheck);
            if (toBlstError(res)) |err| {
                return err;
            }
        }

        pub fn validateSignature(point: *const sig_aff_type, sig_infcheck: bool) c_uint {
            if (sig_infcheck and sig_is_inf_fn(point)) {
                return c.BLST_PK_IS_INFINITY;
            }

            if (!sig_in_group_fn(point)) {
                return c.BLST_POINT_NOT_IN_GROUP;
            }

            return c.BLST_SUCCESS;
        }

        pub fn sigValidate(sig_in: []const u8, sig_infcheck: bool) BLST_ERROR!@This() {
            var sig = try @This().fromBytes(sig_in);
            try sig.validate(sig_infcheck);
            return sig;
        }

        pub fn sigValidateC(out: *sig_aff_type, sig_in: []const u8, sig_infcheck: bool) c_uint {
            const res = signatureFromBytes(out, sig_in);
            if (res != c.BLST_SUCCESS) {
                return res;
            }
            return validateSignature(out, sig_infcheck);
        }

        // same to non-std verify in Rust
        pub fn verify(self: *const @This(), sig_groupcheck: bool, msg: []const u8, dst: []const u8, aug: ?[]const u8, pk: *const PublicKey, pk_validate: bool) BLST_ERROR!void {
            const res = verifySignature(&self.point, sig_groupcheck, msg, dst, aug, &pk.point, pk_validate);
            if (toBlstError(res)) |err| {
                return err;
            }
        }

        /// C-ABI version of verify()
        /// - no aug parameter
        pub fn verifySignature(sig: *const sig_aff_type, sig_groupcheck: bool, msg: []const u8, dst: []const u8, aug: ?[]const u8, pk: *const pk_aff_type, pk_validate: bool) c_uint {
            if (sig_groupcheck) {
                const res = validateSignature(sig, false);
                if (res != c.BLST_SUCCESS) {
                    return res;
                }
            }

            if (pk_validate) {
                const res = PublicKey.validatePublicKey(pk);
                if (res != c.BLST_SUCCESS) {
                    return res;
                }
            }

            if (msg.len == 0 or dst.len == 0) {
                return c.BLST_BAD_ENCODING;
            }

            const aug_ptr = if (aug != null and aug.?.len > 0) &aug.?[0] else null;
            const aug_len = if (aug != null) aug.?.len else 0;

            return verify_fn(pk, sig, true, &msg[0], msg.len, &dst[0], dst.len, aug_ptr, aug_len);
        }

        /// same to non-std aggregate_verify in Rust, with extra `pool` parameter
        pub fn aggregateVerify(self: *const @This(), sig_groupcheck: bool, msgs: [][]const u8, dst: []const u8, pks: []const *PublicKey, pks_validate: bool, pool: *MemoryPool) BLST_ERROR!void {
            const n_elems = pks.len;
            if (n_elems == 0 or msgs.len != n_elems) {
                return BLST_ERROR.VERIFY_FAIL;
            }

            const AtomicCounter = std.atomic.Value(usize);
            // donot use AtomicBoolean because we want error code to return
            const AtomicError = std.atomic.Value(c_uint);
            var atomic_counter = AtomicCounter.init(0);
            // 0 = BLST_SUCCESS
            var atomic_valid = AtomicError.init(c.BLST_SUCCESS);
            var wg = std.Thread.WaitGroup{};

            const cpu_count = @max(1, std.Thread.getCpuCount() catch 1);
            const n_workers = @min(cpu_count, n_elems);

            var acc = Pairing.new(pool, hash_or_encode, dst) catch {
                return BLST_ERROR.FAILED_PAIRING;
            };

            defer acc.deinit() catch {};

            for (0..n_workers) |_| {
                spawnTaskWg(&wg, struct {
                    fn run(_msgs: [][]const u8, _dst: []const u8, _pks: []const *PublicKey, _pks_validate: bool, _pool: *MemoryPool, _atomic_counter: *AtomicCounter, _atomic_valid: *AtomicError, _acc: *Pairing) void {
                        var pairing = Pairing.new(_pool, hash_or_encode, _dst) catch {
                            // .release will publish the value to other threads
                            _atomic_valid.store(BLST_FAILED_PAIRING, AtomicOrder.release);
                            return;
                        };
                        defer pairing.deinit() catch {
                            // .release will publish the value to other threads
                            _atomic_valid.store(BLST_FAILED_PAIRING, AtomicOrder.release);
                        };

                        // the most relaxed atomic ordering
                        var local_count: usize = 0;
                        while (_atomic_valid.load(.monotonic) == c.BLST_SUCCESS) {
                            // this uses @atomicRmw internally and returns the previous value
                            // acquired then release which publish value to other thread
                            const counter = _atomic_counter.fetchAdd(1, AtomicOrder.acq_rel);
                            if (counter >= _msgs.len) {
                                break;
                            }
                            pairing.aggregate(&_pks[counter].point, _pks_validate, null, false, _msgs[counter], null) catch {
                                // .release will publish the value to other threads
                                _atomic_valid.store(c.BLST_VERIFY_FAIL, .release);
                                return;
                            };
                            local_count += 1;
                        }

                        if (local_count > 0 and _atomic_valid.load(.monotonic) == c.BLST_SUCCESS) {
                            pairing.commit();
                            _acc.merge(&pairing) catch {
                                // .release will publish the value to other threads
                                _atomic_valid.store(BLST_FAILED_PAIRING, AtomicOrder.release);
                            };
                        }
                    }
                }.run, .{ msgs, dst, pks, pks_validate, pool, &atomic_counter, &atomic_valid, &acc });
            }

            waitAndWork(&wg);
            acc.commit();

            // all threads finished, load atomic_valid once
            const valid = atomic_valid.load(.monotonic);

            if (sig_groupcheck and valid == c.BLST_SUCCESS) {
                try self.validate(false);
            }

            var gtsig = util.default_blst_fp12();
            if (valid == c.BLST_SUCCESS) {
                Pairing.aggregated(&gtsig, &self.point);
            }

            // do finalVerify() once in the main thread
            if (valid == c.BLST_SUCCESS and !acc.finalVerify(&gtsig)) {
                return BLST_ERROR.VERIFY_FAIL;
            }

            if (toBlstError(valid)) |err| {
                return err;
            }
        }

        /// C-ABI version of aggregateVerify()
        /// - extra msg_len parameter, all messages should have the same length
        pub fn aggregateVerifyC(sig: *const sig_aff_type, sig_groupcheck: bool, msgs: [][*c]const u8, msg_len: usize, dst: []const u8, pks: []const *pk_aff_type, pks_validate: bool, pool: *MemoryPool) c_uint {
            const msgs_len = msgs.len;
            const pks_len = pks.len;
            if (msgs_len == 0 or msgs_len != pks_len) {
                return c.BLST_VERIFY_FAIL;
            }

            const AtomicCounter = std.atomic.Value(usize);
            // donot use AtomicBoolean because we want error code to return
            const AtomicError = std.atomic.Value(c_uint);
            var atomic_counter = AtomicCounter.init(0);
            // 0 = BLST_SUCCESS
            var atomic_valid = AtomicError.init(c.BLST_SUCCESS);
            var wg = std.Thread.WaitGroup{};

            const cpu_count = @max(1, std.Thread.getCpuCount() catch 1);
            const n_workers = @min(cpu_count, msgs_len);

            var acc = Pairing.new(pool, hash_or_encode, dst) catch {
                return BLST_FAILED_PAIRING;
            };

            defer acc.deinit() catch {};

            for (0..n_workers) |_| {
                spawnTaskWg(&wg, struct {
                    fn run(_msgs: [][*c]const u8, _msg_len: usize, _dst: []const u8, _pks: []const *pk_aff_type, _pks_validate: bool, _pool: *MemoryPool, _atomic_counter: *AtomicCounter, _atomic_valid: *AtomicError, _acc: *Pairing) void {
                        const _msgs_len = _msgs.len;
                        var pairing = Pairing.new(_pool, hash_or_encode, _dst) catch {
                            // .release will publish the value to other threads
                            _atomic_valid.store(BLST_FAILED_PAIRING, AtomicOrder.release);
                            return;
                        };
                        defer pairing.deinit() catch {
                            // .release will publish the value to other threads
                            _atomic_valid.store(BLST_FAILED_PAIRING, AtomicOrder.release);
                        };

                        // the most relaxed atomic ordering
                        var local_count: usize = 0;
                        while (_atomic_valid.load(.monotonic) == c.BLST_SUCCESS) {
                            // this uses @atomicRmw internally and returns the previous value
                            // acquired then release which publish value to other thread
                            const counter = _atomic_counter.fetchAdd(1, AtomicOrder.acq_rel);
                            if (counter >= _msgs_len) {
                                break;
                            }
                            pairing.aggregate(_pks[counter], _pks_validate, null, false, _msgs[counter][0.._msg_len], null) catch {
                                // .release will publish the value to other threads
                                _atomic_valid.store(c.BLST_VERIFY_FAIL, AtomicOrder.release);
                                return;
                            };
                            local_count += 1;
                        }

                        if (local_count > 0 and _atomic_valid.load(.monotonic) == c.BLST_SUCCESS) {
                            pairing.commit();
                            _acc.merge(&pairing) catch {
                                // .release will publish the value to other threads
                                _atomic_valid.store(BLST_FAILED_PAIRING, AtomicOrder.release);
                            };
                        }
                    }
                }.run, .{ msgs, msg_len, dst, pks, pks_validate, pool, &atomic_counter, &atomic_valid, &acc });
            }

            waitAndWork(&wg);
            acc.commit();

            // all threads finished, load atomic_valid once
            var valid = atomic_valid.load(.monotonic);

            if (sig_groupcheck and valid == c.BLST_SUCCESS) {
                valid = validateSignature(sig, false);
            }

            var gtsig = util.default_blst_fp12();
            if (valid == c.BLST_SUCCESS) {
                Pairing.aggregated(&gtsig, sig);
            }

            // do finalVerify() once in the main thread
            if (valid == c.BLST_SUCCESS and !acc.finalVerify(&gtsig)) {
                return c.BLST_VERIFY_FAIL;
            }

            return valid;
        }

        /// same to fast_aggregate_verify in Rust with extra `pool` parameter
        pub fn fastAggregateVerify(self: *const @This(), sig_groupcheck: bool, msg: []const u8, dst: []const u8, pks: []*const PublicKey, pool: *MemoryPool) BLST_ERROR!void {
            // this is unsafe code but we scanned through testTypeAlignment unit test
            const pk_aff_points: []*const pk_aff_type = @ptrCast(pks);
            const res = fastAggregateVerifyC(&self.point, sig_groupcheck, msg, dst, pk_aff_points, pool);
            const err_res = toBlstError(res);
            if (err_res) |err| {
                return err;
            }
        }

        pub fn fastAggregateVerifyC(sig: *const sig_aff_type, sig_groupcheck: bool, msg: []const u8, dst: []const u8, pks: []*const pk_aff_type, pool: *MemoryPool) c_uint {
            if (msg.len == 0 or dst.len == 0) {
                return c.BLST_BAD_ENCODING;
            }

            var agg_pk = default_agg_pubkey_fn();
            const res = AggregatePublicKey.aggregatePublicKeys(&agg_pk, pks, false);
            if (res != c.BLST_SUCCESS) {
                return res;
            }
            var pk = default_pubkey_fn();
            PublicKey.publicKeyFromAggregate(&pk, &agg_pk);

            var msgs_arr = [_][*c]const u8{&msg[0]};
            var pks_arr = [_]*pk_aff_type{&pk};
            return aggregateVerifyC(sig, sig_groupcheck, msgs_arr[0..], msg.len, dst, pks_arr[0..], false, pool);
        }

        /// same to fast_aggregate_verify_pre_aggregated in Rust with extra `pool` parameter
        /// TODO: make pk as *const PublicKey, then all other functions should make pks as []const *const PublicKey
        pub fn fastAggregateVerifyPreAggregated(self: *const @This(), sig_groupcheck: bool, msg: []const u8, dst: []const u8, pk: *PublicKey, pool: *MemoryPool) BLST_ERROR!void {
            var msgs = [_][]const u8{msg};
            var pks = [_]*PublicKey{pk};
            try self.aggregateVerify(sig_groupcheck, msgs[0..], dst, pks[0..], false, pool);
        }

        /// C-ABI version of fastAggregateVerifyPreAggregated()
        pub fn fastAggregateVerifyPreAggregatedC(sig: *const sig_aff_type, sig_groupcheck: bool, msg: []const u8, dst: []const u8, pk: *pk_aff_type, pool: *MemoryPool) c_uint {
            if (msg.len == 0 or dst.len == 0) {
                return c.BLST_BAD_ENCODING;
            }

            var msgs = [_][*c]const u8{&msg[0]};
            var pks = [_]*pk_aff_type{pk};
            return aggregateVerifyC(sig, sig_groupcheck, msgs[0..], msg.len, dst, pks[0..], false, pool);
        }

        /// https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407
        ///  similar to std verify_multiple_aggregate_signatures in Rust (the multi-threaded version) with:
        /// - `rands` parameter type changed to `[][]const u8` instead of []blst_scalar because mulAndAggregateG1() accepts []const u8 anyway
        /// rand_bits is always 64 in all tests
        pub fn verifyMultipleAggregateSignatures(msgs: [][]const u8, dst: []const u8, pks: []const *PublicKey, pks_validate: bool, sigs: []const *@This(), sigs_groupcheck: bool, rands: [][]const u8, rand_bits: usize, pool: *MemoryPool) BLST_ERROR!void {
            const n_elems = pks.len;
            if (n_elems == 0 or msgs.len != n_elems or sigs.len != n_elems or rands.len != n_elems) {
                return BLST_ERROR.VERIFY_FAIL;
            }

            const AtomicCounter = std.atomic.Value(usize);
            // donot use AtomicBoolean because we want error code to return
            const AtomicError = std.atomic.Value(c_uint);
            var atomic_counter = AtomicCounter.init(0);
            // 0 = BLST_SUCCESS
            var atomic_valid = AtomicError.init(c.BLST_SUCCESS);
            var wg = std.Thread.WaitGroup{};

            const cpu_count = @max(1, std.Thread.getCpuCount() catch 1);
            const n_workers = @min(cpu_count, n_elems);
            const Signature = @This();

            var acc = Pairing.new(pool, hash_or_encode, dst) catch {
                return BLST_ERROR.FAILED_PAIRING;
            };

            defer acc.deinit() catch {};

            for (0..n_workers) |_| {
                spawnTaskWg(&wg, struct {
                    fn run(_msgs: [][]const u8, _dst: []const u8, _pks: []const *PublicKey, _pks_validate: bool, _sigs: []const *Signature, _sigs_groupcheck: bool, _rands: [][]const u8, _rand_bits: usize, _pool: *MemoryPool, _atomic_counter: *AtomicCounter, _atomic_valid: *AtomicError, _acc: *Pairing) void {
                        var pairing = Pairing.new(_pool, hash_or_encode, _dst) catch {
                            // .release will publish the value to other threads
                            _atomic_valid.store(BLST_FAILED_PAIRING, AtomicOrder.release);
                            return;
                        };
                        defer pairing.deinit() catch {
                            // .release will publish the value to other threads
                            _atomic_valid.store(BLST_FAILED_PAIRING, AtomicOrder.release);
                        };

                        // the most relaxed atomic ordering
                        var local_count: usize = 0;
                        while (_atomic_valid.load(.monotonic) == c.BLST_SUCCESS) {
                            // this uses @atomicRmw internally and returns the previous value
                            // acquired then release which publish value to other thread
                            const counter = _atomic_counter.fetchAdd(1, AtomicOrder.acq_rel);
                            if (counter >= _msgs.len) {
                                break;
                            }
                            pairing.mulAndAggregate(&_pks[counter].point, _pks_validate, &_sigs[counter].point, _sigs_groupcheck, &_rands[counter][0], _rand_bits, _msgs[counter], null) catch {
                                // .release will publish the value to other threads
                                _atomic_valid.store(c.BLST_VERIFY_FAIL, .release);
                                return;
                            };
                            local_count += 1;
                        }

                        if (local_count > 0 and _atomic_valid.load(.monotonic) == c.BLST_SUCCESS) {
                            pairing.commit();
                            _acc.merge(&pairing) catch {
                                // .release will publish the value to other threads
                                _atomic_valid.store(BLST_FAILED_PAIRING, AtomicOrder.release);
                            };
                        }
                    }
                }.run, .{ msgs, dst, pks, pks_validate, sigs, sigs_groupcheck, rands, rand_bits, pool, &atomic_counter, &atomic_valid, &acc });
            }

            waitAndWork(&wg);
            acc.commit();

            const valid = atomic_valid.load(.monotonic);
            // do finalVerify() once in the main thread
            if (valid == c.BLST_SUCCESS and !acc.finalVerify(null)) {
                return BLST_ERROR.VERIFY_FAIL;
            }

            if (toBlstError(valid)) |err| {
                return err;
            }
        }

        /// C-ABI version of verifyMultipleAggregateSignatures() with
        /// - extra msg_len parameter, all messages should have the same length
        pub fn verifyMultipleAggregateSignaturesC(sets: []*const SignatureSet, msg_len: usize, dst: []const u8, pks_validate: bool, sigs_groupcheck: bool, rands: [][]const u8, rand_bits: usize, pool: *MemoryPool) c_uint {
            const sets_len = sets.len;
            const rands_len = rands.len;
            if (sets_len == 0 or rands_len != sets_len) {
                return c.BLST_VERIFY_FAIL;
            }

            const AtomicCounter = std.atomic.Value(usize);
            // donot use AtomicBoolean because we want error code to return
            const AtomicError = std.atomic.Value(c_uint);
            var atomic_counter = AtomicCounter.init(0);
            // 0 = BLST_SUCCESS
            var atomic_valid = AtomicError.init(c.BLST_SUCCESS);
            var wg = std.Thread.WaitGroup{};

            const cpu_count = @max(1, std.Thread.getCpuCount() catch 1);
            const n_workers = @min(cpu_count, sets_len);
            var acc = Pairing.new(pool, hash_or_encode, dst) catch {
                return BLST_FAILED_PAIRING;
            };

            defer acc.deinit() catch {};

            for (0..n_workers) |_| {
                spawnTaskWg(&wg, struct {
                    fn run(_sets: []*const SignatureSet, _msg_len: usize, _dst: []const u8, _pks_validate: bool, _sigs_groupcheck: bool, _rands: [][]const u8, _rand_bits: usize, _pool: *MemoryPool, _atomic_counter: *AtomicCounter, _atomic_valid: *AtomicError, _acc: *Pairing) void {
                        var pairing = Pairing.new(_pool, hash_or_encode, _dst) catch {
                            // .release will publish the value to other threads
                            _atomic_valid.store(BLST_FAILED_PAIRING, AtomicOrder.release);
                            return;
                        };

                        defer pairing.deinit() catch {
                            // .release will publish the value to other threads
                            _atomic_valid.store(BLST_FAILED_PAIRING, AtomicOrder.release);
                        };

                        // the most relaxed atomic ordering
                        var local_count: usize = 0;
                        const _sets_len = _sets.len;
                        while (_atomic_valid.load(.monotonic) == c.BLST_SUCCESS) {
                            // this uses @atomicRmw internally and returns the previous value
                            // acquired then release which publish value to other thread
                            const counter = _atomic_counter.fetchAdd(1, AtomicOrder.acq_rel);
                            if (counter >= _sets_len) {
                                break;
                            }
                            const set = _sets[counter];
                            pairing.mulAndAggregate(set.pk, _pks_validate, set.sig, _sigs_groupcheck, &_rands[counter][0], _rand_bits, set.msg[0.._msg_len], null) catch {
                                // .release will publish the value to other threads
                                _atomic_valid.store(c.BLST_VERIFY_FAIL, .release);
                                return;
                            };
                            local_count += 1;
                        }

                        if (local_count > 0 and _atomic_valid.load(.monotonic) == c.BLST_SUCCESS) {
                            pairing.commit();
                            _acc.merge(&pairing) catch {
                                // .release will publish the value to other threads
                                _atomic_valid.store(BLST_FAILED_PAIRING, AtomicOrder.release);
                            };
                        }
                    }
                }.run, .{ sets, msg_len, dst, pks_validate, sigs_groupcheck, rands, rand_bits, pool, &atomic_counter, &atomic_valid, &acc });
            }

            waitAndWork(&wg);
            acc.commit();

            const valid = atomic_valid.load(.monotonic);
            // do finalVerify() once in the main thread
            if (valid == c.BLST_SUCCESS and !acc.finalVerify(null)) {
                return c.BLST_VERIFY_FAIL;
            }

            return valid;
        }

        pub fn fromAggregate(comptime AggregateSignature: type, agg_sig: *const AggregateSignature) @This() {
            var sig_aff = @This().default();
            signatureFromAggregate(&sig_aff.point, &agg_sig.point);
            return sig_aff;
        }

        pub fn signatureFromAggregate(out: *sig_aff_type, agg_sig: *const sig_type) void {
            return sig_to_aff_fn(out, agg_sig);
        }

        pub fn compress(self: *const @This()) [sig_comp_size]u8 {
            var sig_comp = [_]u8{0} ** sig_comp_size;
            compressSignature(&sig_comp[0], &self.point);
            return sig_comp;
        }

        pub fn compressSignature(out: *u8, point: *const sig_aff_type) void {
            sig_comp_fn(out, point);
        }

        pub fn serialize(self: *const @This()) [sig_ser_size]u8 {
            var sig_out = [_]u8{0} ** sig_ser_size;
            serializeSignature(&sig_out[0], &self.point);
            return sig_out;
        }

        pub fn serializeSignature(out: *u8, point: *const sig_aff_type) void {
            sig_ser_fn(out, point);
        }

        pub fn uncompress(sig_comp: []const u8) BLST_ERROR!@This() {
            if (sig_comp.len == 0) {
                return BLST_ERROR.BAD_ENCODING;
            }

            const sig = @This().default();
            const res = uncompressSignature(&sig.point, sig_comp);
            return toBlstError(res) orelse sig;
        }

        pub fn uncompressSignature(out: *sig_aff_type, sig_comp: []const u8) c_uint {
            const len = sig_comp.len;
            if (len == sig_comp_size and (sig_comp[0] & 0x80) != 0) {
                return sig_uncomp_fn(out, &sig_comp[0]);
            }

            return c.BLST_BAD_ENCODING;
        }

        pub fn deserialize(sig_in: []const u8) BLST_ERROR!@This() {
            if (sig_in.len == 0) {
                return BLST_ERROR.BAD_ENCODING;
            }

            var sig = @This().default();

            const res = deserializeSignature(&sig.point, sig_in);

            return toBlstError(res) orelse sig;
        }

        pub fn deserializeSignature(out: *sig_aff_type, sig_in: []const u8) c_uint {
            const len = sig_in.len;
            if (len == 0) {
                return c.BLST_BAD_ENCODING;
            }

            if ((len == sig_ser_size and (sig_in[0] & 0x80) == 0) or
                (len == sig_comp_size and (sig_in[0] & 0x80) != 0))
            {
                return sig_deser_fn(out, &sig_in[0]);
            }

            return c.BLST_BAD_ENCODING;
        }

        pub fn fromBytes(sig_in: []const u8) BLST_ERROR!@This() {
            return @This().deserialize(sig_in);
        }

        pub fn signatureFromBytes(out: *sig_aff_type, sig_in: []const u8) c_uint {
            return deserializeSignature(out, sig_in);
        }

        pub fn toBytes(self: *const @This()) [sig_comp_size]u8 {
            return self.compress();
        }

        pub fn signatureToBytes(out: *u8, point: *sig_aff_type) void {
            return compressSignature(out, point);
        }

        pub fn subgroupCheck(self: *const @This()) bool {
            return signatureSubgroupCheck(&self.point);
        }

        pub fn signatureSubgroupCheck(point: *sig_aff_type) bool {
            return sig_in_group_fn(point);
        }

        pub fn isEqual(self: *const @This(), other: *const @This()) bool {
            return isSignatureEqual(&self.point, &other.point);
        }

        pub fn isSignatureEqual(point: *const sig_aff_type, other: *const sig_aff_type) bool {
            return sig_eq_fn(point, other);
        }
    };

    const AggregateSignature = struct {
        point: sig_type,

        pub fn default() @This() {
            return .{
                .point = default_agg_sig_fn(),
            };
        }

        pub fn defaultAggregateSignature() sig_type {
            return default_agg_sig_fn();
        }

        pub fn validate(self: *const @This()) BLST_ERROR!void {
            const res = subgroupCheckC(&self.point);
            if (!res) {
                return BLST_ERROR.POINT_NOT_IN_GROUP;
            }
        }

        pub fn validateAggregateSignature(point: *const sig_type) c_uint {
            if (!subgroupCheckC(point)) {
                return c.BLST_POINT_NOT_IN_GROUP;
            }

            return c.BLST_SUCCESS;
        }

        pub fn fromSignature(sig: *const Signature) @This() {
            var agg_sig = @This().default();
            sig_from_aff_fn(&agg_sig.point, &sig.point);
            return agg_sig;
        }

        pub fn aggregateFromSignature(out: *sig_type, sig: *const sig_aff_type) void {
            sig_from_aff_fn(out, sig);
        }

        pub fn toSignature(self: *const @This()) Signature {
            var sig = Signature.default();
            sig_to_aff_fn(&sig.point, &self.point);
            return sig;
        }

        pub fn aggregateToSignature(out: *sig_aff_type, agg_sig: *const sig_type) void {
            sig_to_aff_fn(out, agg_sig);
        }

        // Aggregate
        pub fn aggregate(sigs: []*const Signature, sigs_groupcheck: bool) BLST_ERROR!@This() {
            if (sigs.len == 0) {
                return BLST_ERROR.AGGR_TYPE_MISMATCH;
            }

            // this is unsafe code but we scanned through testTypeAlignment unit test
            const sigs_ptr: [*c]*const sig_aff_type = @ptrCast(&sigs[0]);
            var agg_sig = @This().default();
            const res = aggregateSignatures(&agg_sig.point, sigs_ptr[0..sigs.len], sigs_groupcheck);
            return toBlstError(res) orelse agg_sig;
        }

        pub fn aggregateSignatures(out: *sig_type, sigs: []*const sig_aff_type, sigs_groupcheck: bool) c_uint {
            const len = sigs.len;
            if (len == 0) {
                return c.BLST_AGGR_TYPE_MISMATCH;
            }
            if (sigs_groupcheck) {
                // We can't actually judge if input is individual or
                // aggregated signature, so we can't enforce infinity
                // check.
                const res = Signature.validateSignature(sigs[0], false);
                if (res != c.BLST_SUCCESS) {
                    return res;
                }
            }

            aggregateFromSignature(out, sigs[0]);
            for (1..len) |i| {
                if (sigs_groupcheck) {
                    const res = Signature.validateSignature(sigs[i], false);
                    if (res != c.BLST_SUCCESS) {
                        return res;
                    }
                }

                sig_add_or_dbl_aff_fn(out, out, sigs[i]);
            }

            return c.BLST_SUCCESS;
        }

        pub fn aggregateSerialized(sigs: [][]const u8, sigs_groupcheck: bool) BLST_ERROR!@This() {
            // TODO - threading
            if (sigs.len() == 0) {
                return BLST_ERROR.AGGR_TYPE_MISMATCH;
            }

            var sig = if (sigs_groupcheck) Signature.sigValidate(sigs[0], false) else Signature.fromBytes(sigs[0]);

            var agg_sig = @This().fromSignature(&sig);
            for (sigs[1..]) |s| {
                sig = if (sigs_groupcheck) Signature.sigValidate(s, false) else Signature.fromBytes(s);
                sig_add_or_dbl_aff_fn(&agg_sig.point, &agg_sig.point, &sig.point);
            }
            return agg_sig;
        }

        /// C-ABI version of aggregateSerialized
        /// all signatures should have the same len
        pub fn aggregateSerializedC(out: *sig_type, sigs: [][*c]const u8, sig_len: usize, sigs_groupcheck: bool) c_uint {
            const sigs_len = sigs.len;
            if (sigs_len == 0) {
                return c.BLST_AGGR_TYPE_MISMATCH;
            }

            var sig = Signature.default().point;
            var res = Signature.signatureFromBytes(&sig, sigs[0][0..sig_len]);
            if (res != c.BLST_SUCCESS) {
                return res;
            }

            if (sigs_groupcheck) {
                res = Signature.validateSignature(&sig, false);
                if (res != c.BLST_SUCCESS) {
                    return res;
                }
            }

            aggregateFromSignature(out, &sig);

            for (1..sigs_len) |i| {
                var point = Signature.default().point;
                res = Signature.signatureFromBytes(&point, sigs[i][0..sig_len]);
                if (res != c.BLST_SUCCESS) {
                    return res;
                }

                if (sigs_groupcheck) {
                    res = Signature.validateSignature(&point, false);
                    if (res != c.BLST_SUCCESS) {
                        return res;
                    }
                }

                sig_add_or_dbl_aff_fn(out, out, &point);
            }

            return c.BLST_SUCCESS;
        }

        pub fn addAggregate(self: *@This(), agg_sig: *const @This()) void {
            sig_add_or_dbl_fn(&self.point, &self.point, &agg_sig.point);
        }

        pub fn addAggregateC(out: *sig_type, agg_sig: *const sig_type) void {
            sig_add_or_dbl_fn(out, out, agg_sig);
        }

        pub fn addSignature(self: *@This(), sig: *const Signature, sig_groupcheck: bool) BLST_ERROR!void {
            if (sig_groupcheck) {
                try sig.validate(false);
            }
            sig_add_or_dbl_aff_fn(&self.point, &self.point, &sig.point);
        }

        pub fn addSignatureToAggregate(out: *sig_type, sig: *const sig_aff_type, sig_groupcheck: bool) c_uint {
            if (sig_groupcheck) {
                const res = Signature.validateSignature(sig, false);
                if (res != c.BLST_SUCCESS) {
                    return res;
                }
            }

            sig_add_or_dbl_aff_fn(out, out, sig);
            return c.BLST_SUCCESS;
        }

        pub fn subgroupCheck(self: *const @This()) bool {
            return sig_aggr_in_group_fn(&self.point);
        }

        pub fn subgroupCheckC(agg_sig: *const sig_type) bool {
            return sig_aggr_in_group_fn(agg_sig);
        }

        pub fn isEqual(self: *const @This(), other: *const @This()) bool {
            return agg_sig_eq_fn(&self.point, &other.point);
        }

        pub fn isAggregateSignatureEqual(point: *const sig_type, other: *const sig_type) bool {
            return agg_sig_eq_fn(point, other);
        }
    };

    const SecretKey = struct {
        value: c.blst_scalar,

        pub fn default() @This() {
            return .{
                .value = util.default_blst_scalar(),
            };
        }

        pub fn defaultSecretKey() c.blst_scalar {
            return util.default_blst_scalar();
        }

        pub fn keyGen(ikm: []const u8, key_info: ?[]const u8) BLST_ERROR!@This() {
            if (ikm.len < 32) {
                return BLST_ERROR.BAD_ENCODING;
            }

            var sk = @This().default();
            const key_info_ptr = if (key_info != null) &key_info.?[0] else null;
            const key_info_len = if (key_info != null) key_info.?.len else 0;

            c.blst_keygen(&sk.value, &ikm[0], ikm.len, key_info_ptr, key_info_len);
            return sk;
        }

        // cannot use slice for key gen functions because key_info could be null value
        pub fn secretKeyGen(out: *c.blst_scalar, ikm: [*c]const u8, ikm_len: usize, key_info: [*c]const u8, key_info_len: usize) c_uint {
            if (ikm_len < 32) {
                return c.BLST_BAD_ENCODING;
            }

            c.blst_keygen(out, ikm, ikm_len, key_info, key_info_len);
            return c.BLST_SUCCESS;
        }

        pub fn keyGenV3(ikm: []const u8, key_info: ?[]const u8) BLST_ERROR!@This() {
            if (ikm.len < 32) {
                return BLST_ERROR.BAD_ENCODING;
            }

            var sk = @This().default();
            const key_info_ptr = if (key_info != null) &key_info.?[0] else null;
            const key_info_len = if (key_info != null) key_info.?.len else 0;

            c.blst_keygen_v3(&sk.value, &ikm[0], ikm.len, key_info_ptr, key_info_len);
            return sk;
        }

        pub fn secretKeyGenV3(out: *c.blst_scalar, ikm: [*c]const u8, ikm_len: usize, key_info: [*c]const u8, key_info_len: usize) c_uint {
            if (ikm_len < 32) {
                return c.BLST_BAD_ENCODING;
            }

            c.blst_keygen_v3(out, ikm, ikm_len, key_info, key_info_len);
            return c.BLST_SUCCESS;
        }

        pub fn keyGenV45(ikm: []const u8, salt: []const u8, info: ?[]const u8) BLST_ERROR!@This() {
            if (ikm.len < 32) {
                return BLST_ERROR.BAD_ENCODING;
            }

            var sk = @This().default();
            const info_ptr = if (info != null and info.?.len > 0) &info.?[0] else null;
            const info_len = if (info != null) info.?.len else 0;

            c.blst_keygen_v4_5(&sk.value, &ikm[0], ikm.len, &salt[0], salt.len, info_ptr, info_len);
            return sk;
        }

        pub fn secretKeyGenV45(out: *c.blst_scalar, ikm: [*c]const u8, ikm_len: usize, salt: [*c]const u8, salt_len: usize, info: [*c]const u8, info_len: usize) c_uint {
            if (ikm_len < 32) {
                return c.BLST_BAD_ENCODING;
            }

            c.blst_keygen_v4_5(out, ikm, ikm_len, salt, salt_len, info, info_len);
            return c.BLST_SUCCESS;
        }

        pub fn keyGenV5(ikm: []const u8, salt: []const u8, info: ?[]const u8) BLST_ERROR!@This() {
            if (ikm.len < 32) {
                return BLST_ERROR.BAD_ENCODING;
            }

            var sk = @This().default();
            const info_ptr = if (info != null and info.?.len > 0) &info.?[0] else null;
            const info_len = if (info != null) info.?.len else 0;

            c.blst_keygen_v5(&sk.value, &ikm[0], ikm.len, &salt[0], salt.len, info_ptr, info_len);
            return sk;
        }

        pub fn secretKeyGenV5(out: *c.blst_scalar, ikm: [*c]const u8, ikm_len: usize, salt: [*c]const u8, salt_len: usize, info: [*c]const u8, info_len: usize) c_uint {
            if (ikm_len < 32) {
                return c.BLST_BAD_ENCODING;
            }

            c.blst_keygen_v5(out, ikm, ikm_len, salt, salt_len, info, info_len);
            return c.BLST_SUCCESS;
        }

        pub fn deriveMasterEip2333(ikm: []const u8) BLST_ERROR!@This() {
            if (ikm.len < 32) {
                return BLST_ERROR.BAD_ENCODING;
            }

            var sk = @This().default();
            c.blst_derive_master_eip2333(&sk.value, &ikm[0], ikm.len);
            return sk;
        }

        pub fn secretKeyDeriveMasterEip2333(out: *c.blst_scalar, ikm: [*c]const u8, ikm_len: usize) c_uint {
            if (ikm_len < 32) {
                return c.BLST_BAD_ENCODING;
            }

            c.blst_derive_master_eip2333(out, ikm, ikm_len);
            return c.BLST_SUCCESS;
        }

        pub fn deriveChildEip2333(self: *const @This(), child_index: u32) BLST_ERROR!@This() {
            var sk = @This().default();
            c.blst_derive_child_eip2333(&sk.value, &self.value, child_index);
            return sk;
        }

        pub fn secretKeyDeriveChildEip2333(out: *c.blst_scalar, sk: *const c.blst_scalar, child_index: u32) void {
            c.blst_derive_child_eip2333(out, sk, child_index);
        }

        pub fn skToPk(self: *const @This()) PublicKey {
            var pk_aff = PublicKey.default();
            sk_to_pk_fn(null, &pk_aff.point, &self.value);
            return pk_aff;
        }

        pub fn secretKeyToPublicKey(out: *pk_aff_type, sk: *const c.blst_scalar) void {
            sk_to_pk_fn(null, out, sk);
        }

        // Sign
        pub fn sign(self: *const @This(), msg: []const u8, dst: []const u8, aug: ?[]const u8) Signature {
            // TODO - would the user like the serialized/compressed sig as well?
            var sig_aff = Signature.default();
            const aug_ptr = if (aug != null and aug.?.len > 0) &aug.?[0] else null;
            const aug_len = if (aug != null) aug.?.len else 0;
            signC(&sig_aff.point, &self.value, &msg[0], msg.len, &dst[0], dst.len, aug_ptr, aug_len);
            return sig_aff;
        }

        // cannot use slice for aug because it could be null
        // using C pointer for other params too for compatibility
        pub fn signC(out: *sig_aff_type, sk: *const c.blst_scalar, msg: [*c]const u8, msg_len: usize, dst: [*c]const u8, dst_len: usize, aug: [*c]const u8, aug_len: usize) void {
            var q = default_agg_sig_fn();
            hash_or_encode_to_fn(&q, msg, msg_len, dst, dst_len, aug, aug_len);
            sign_fn(null, out, &q, sk);
        }

        // TODO - formally speaking application is entitled to have
        // ultimate control over secret key storage, which means that
        // corresponding serialization/deserialization subroutines
        // should accept reference to where to store the result, as
        // opposite to returning one.

        // serialize
        pub fn serialize(self: *const @This()) [32]u8 {
            var sk_out = [_]u8{0} ** 32;
            c.blst_bendian_from_scalar(&sk_out[0], &self.value);
            return sk_out;
        }

        pub fn serializeSecretKey(out: *u8, sk: *const c.blst_scalar) void {
            c.blst_bendian_from_scalar(out, sk);
        }

        // deserialize
        pub fn deserialize(sk_in: []const u8) BLST_ERROR!@This() {
            var sk = @This().default();
            if (sk_in.len != 32) {
                return BLST_ERROR.BAD_ENCODING;
            }

            const res = deserializeSecretKey(&sk.value, &sk_in[0], sk_in.len);
            return toBlstError(res) orelse sk;
        }

        pub fn deserializeSecretKey(out: *c.blst_scalar, sk_in: [*c]const u8, len: usize) c_uint {
            if (len != 32) {
                return c.BLST_BAD_ENCODING;
            }
            c.blst_scalar_from_bendian(out, sk_in);
            if (!c.blst_sk_check(out)) {
                return c.BLST_BAD_ENCODING;
            }

            return c.BLST_SUCCESS;
        }

        pub fn toBytes(self: *const @This()) [32]u8 {
            return self.serialize();
        }

        pub fn secretKeyToBytes(out: *u8, sk: *const c.blst_scalar) void {
            serializeSecretKey(out, sk);
        }

        pub fn fromBytes(sk_in: []const u8) BLST_ERROR!@This() {
            return @This().deserialize(sk_in);
        }

        pub fn secretKeyFromBytes(out: *c.blst_scalar, sk_in: [*c]const u8, len: usize) c_uint {
            return deserializeSecretKey(out, sk_in, len);
        }
    };

    const PkAndSerializedSig = struct {
        pk: *PublicKey,
        sig: []const u8,
    };

    const PkAndSerializedSigC = extern struct {
        pk: *pk_aff_type,
        sig: [*c]const u8,
        sig_len: usize,
    };

    // for PublicKey and AggregatePublicKey
    const pk_multi_point = @import("./multi_point.zig").createMultiPoint(
        pk_aff_type,
        pk_type,
        default_pubkey_fn,
        default_agg_pubkey_fn,
        agg_pk_eq_fn,
        pk_add_fn,
        pk_multi_scalar_mult_fn,
        pk_scratch_size_of_fn,
        pk_mult_fn,
        pk_generator_fn,
        pk_to_affines_fn,
        pk_add_or_dbl_fn,
    );

    const PkMultiPoint = pk_multi_point.getMultiPoint();

    const sig_multi_point = @import("./multi_point.zig").createMultiPoint(
        sig_aff_type,
        sig_type,
        default_sig_fn,
        default_agg_sig_fn,
        agg_sig_eq_fn,
        sig_add_fn,
        sig_multi_scalar_mult_fn,
        sig_scratch_size_of_fn,
        sig_mult_fn,
        sig_generator_fn,
        sig_to_affines_fn,
        sig_add_or_dbl_fn,
    );

    const SigMultiPoint = sig_multi_point.getMultiPoint();

    // TODO: consume the above struct to work with public data structures

    const CallbackFn = *const fn (result: c_uint) callconv(.C) void;

    return struct {
        pub fn createSecretKey() type {
            return SecretKey;
        }

        pub fn createPublicKey() type {
            return PublicKey;
        }

        pub fn createAggregatePublicKey() type {
            return AggregatePublicKey;
        }

        pub fn createSignature() type {
            return Signature;
        }

        pub fn createAggregateSignature() type {
            return AggregateSignature;
        }

        pub fn getPublicKeyType() type {
            return pk_aff_type;
        }

        pub fn getAggregatePublicKeyType() type {
            return pk_type;
        }

        pub fn getSignatureType() type {
            return sig_aff_type;
        }

        pub fn getAggregateSignatureType() type {
            return sig_type;
        }

        pub fn getSecretKeyType() type {
            return c.blst_scalar;
        }

        pub fn getSignatureSetType() type {
            return SignatureSet;
        }

        pub fn getPkAndSerializedSigType() type {
            // return the C-ABI struct
            return PkAndSerializedSigC;
        }

        pub fn getCallBackFn() type {
            return CallbackFn;
        }

        pub fn getMemoryPoolType() type {
            return MemoryPool;
        }

        pub fn pubkeyFromAggregate(agg_pk: *const AggregatePublicKey) PublicKey {
            var pk_aff = PublicKey.default();
            pk_to_aff_fn(&pk_aff.point, &agg_pk.point);
            return pk_aff;
        }

        /// pk_scratch and sig_scratch are in []u8 to make it friendly to FFI
        pub fn aggregateWithRandomness(sets: []*const PkAndSerializedSig, pool: *MemoryPool, pk_out: *PublicKey, sig_out: *Signature) !void {
            if (sets.len == 0 or sets.len > MAX_SIGNATURE_SETS) {
                return error.InvalidLen;
            }

            var sets_c: [MAX_SIGNATURE_SETS]*const PkAndSerializedSigC = undefined;
            for (0..sets.len) |i| {
                sets_c[i] = &PkAndSerializedSigC{
                    .pk = &sets[i].pk.point,
                    .sig = &sets[i].sig[0],
                    .sig_len = sets[i].sig.len,
                };
            }

            // no callback provided because this function is synchronous
            const res = aggregateWithRandomnessC(sets_c[0..sets.len], pool, &pk_out.point, &sig_out.point, null);
            if (toBlstError(res)) |err| {
                return err;
            }
        }

        /// the same to aggregateWithRandomness with a callback provided
        pub fn asyncAggregateWithRandomness(sets: []*const PkAndSerializedSigC, pool: *MemoryPool, pk_out: *pk_aff_type, sig_out: *sig_aff_type, callback: CallbackFn) c_uint {
            spawnTask(struct {
                fn run(sets_t: []*const PkAndSerializedSigC, memory_pool: *MemoryPool, pk_out_t: *pk_aff_type, sig_out_t: *sig_aff_type, callback_t: CallbackFn) void {
                    _ = aggregateWithRandomnessC(sets_t, memory_pool, pk_out_t, sig_out_t, callback_t);
                }
            }.run, .{ sets, pool, pk_out, sig_out, callback }) catch return util.THREAD_POOL_ERROR;

            return c.BLST_SUCCESS;
        }

        pub fn aggregateWithRandomnessC(sets: []*const PkAndSerializedSigC, pool: *MemoryPool, pk_out: *pk_aff_type, sig_out: *sig_aff_type, callbackFn: ?CallbackFn) c_uint {
            const sets_len = sets.len;
            if (sets_len == 0 or sets_len > MAX_SIGNATURE_SETS) {
                if (callbackFn) |callback| {
                    callback(c.BLST_BAD_ENCODING);
                }
                return c.BLST_BAD_ENCODING;
            }

            const sig_scratch = pool.getSignatureScratch() catch {
                if (callbackFn) |callback| {
                    callback(util.MEMORY_POOL_ERROR);
                }
                return util.MEMORY_POOL_ERROR;
            };

            const pk_scratch = pool.getPublicKeyScratch() catch {
                if (callbackFn) |callback| {
                    callback(util.MEMORY_POOL_ERROR);
                }
                return util.MEMORY_POOL_ERROR;
            };

            defer {
                pool.returnPublicKeyScratch(pk_scratch) catch {};
                pool.returnSignatureScratch(sig_scratch) catch {};
            }

            var pks_refs: [MAX_SIGNATURE_SETS]*const pk_aff_type = undefined;
            var sigs = [_]sig_aff_type{default_sig_fn()} ** MAX_SIGNATURE_SETS;
            var sigs_refs: [MAX_SIGNATURE_SETS]*sig_aff_type = undefined;
            var rands: [32 * MAX_SIGNATURE_SETS]u8 = [_]u8{0} ** (32 * MAX_SIGNATURE_SETS);
            randBytes(rands[0..(32 * sets_len)]);
            var scalars_refs: [MAX_SIGNATURE_SETS]*const u8 = undefined;

            for (0..sets_len) |i| {
                var set = sets[i];
                pks_refs[i] = set.pk;
                sigs_refs[i] = &sigs[i];
                const res = Signature.sigValidateC(sigs_refs[i], set.sig[0..set.sig_len], true);
                if (res != c.BLST_SUCCESS) {
                    if (callbackFn) |callback| {
                        callback(res);
                    }
                    return res;
                }
                scalars_refs[i] = &rands[i * 32];
            }

            const n_bits = 64;

            var mult_pk_res = default_agg_pubkey_fn();
            multPublicKeysC(&mult_pk_res, &pks_refs[0], sets_len, &scalars_refs[0], n_bits, &pk_scratch[0]);
            AggregatePublicKey.aggregateToPublicKey(pk_out, &mult_pk_res);

            var mult_sig_res = default_agg_sig_fn();
            multSignaturesC(&mult_sig_res, @ptrCast(&sigs_refs[0]), sets_len, &scalars_refs[0], n_bits, &sig_scratch[0]);
            AggregateSignature.aggregateToSignature(sig_out, &mult_sig_res);

            if (callbackFn) |callback| {
                callback(c.BLST_SUCCESS);
            }
            return c.BLST_SUCCESS;
        }

        /// Multipoint
        pub fn addPublicKeys(pks: []*const PublicKey) AggregatePublicKey {
            // this is unsafe code but we scanned through testTypeAlignment unit test
            // Rust does the same thing here
            const pk_aff_points: []*const pk_aff_type = @ptrCast(pks);
            var agg_pk = AggregatePublicKey.default();
            PkMultiPoint.add(&agg_pk.point, &pk_aff_points[0], pk_aff_points.len);
            return agg_pk;
        }

        pub fn addPublicKeysC(out: *pk_type, pks: [*c]*const pk_aff_type, pks_len: usize) void {
            PkMultiPoint.add(out, pks, pks_len);
        }

        // scratch param is designed to be reused across multiple calls
        pub fn multPublicKeys(pks: []*const PublicKey, scalars: []*const u8, n_bits: usize, scratch: []u64) AggregatePublicKey {
            // this is unsafe code but we scanned through testTypeAlignment unit test
            // Rust does the same thing here
            const pk_aff_points: []*const pk_aff_type = @ptrCast(pks);
            var agg_pk = AggregatePublicKey.default();
            PkMultiPoint.mult(&agg_pk.point, &pk_aff_points[0], pk_aff_points.len, &scalars[0], n_bits, &scratch[0]);
            return agg_pk;
        }

        pub fn multPublicKeysC(out: *pk_type, pks: [*c]*const pk_aff_type, pks_len: usize, scalars: [*c]*const u8, n_bits: usize, scratch: [*c]u64) void {
            PkMultiPoint.mult(out, pks, pks_len, scalars, n_bits, scratch);
        }

        pub fn addSignatures(sigs: []*const Signature) AggregateSignature {
            // this is unsafe code but we scanned through testTypeAlignment unit test
            // Rust does the same thing here
            const sig_aff_points: []*const sig_aff_type = @ptrCast(sigs);
            var agg_sig = AggregateSignature.default();
            SigMultiPoint.add(&agg_sig.point, &sig_aff_points[0], sig_aff_points.len);
            return agg_sig;
        }

        pub fn addSignaturesC(out: *sig_type, sigs: [*c]*const sig_aff_type, sigs_len: usize) void {
            SigMultiPoint.add(out, sigs, sigs_len);
        }

        // scratch param is designed to be reused across multiple calls
        pub fn multSignatures(sigs: []*const Signature, scalars: []*const u8, n_bits: usize, scratch: []u64) AggregateSignature {
            // this is unsafe code but we scanned through testTypeAlignment unit test
            // Rust does the same thing here
            const sig_aff_points: []*const sig_aff_type = @ptrCast(sigs);
            var agg_sig = AggregateSignature.default();
            SigMultiPoint.mult(&agg_sig.point, &sig_aff_points[0], sig_aff_points.len, &scalars[0], n_bits, &scratch[0]);
            return agg_sig;
        }

        pub fn multSignaturesC(out: *sig_type, sigs: [*c]*const sig_aff_type, sigs_len: usize, scalars: [*c]*const u8, n_bits: usize, scratch: [*c]u64) void {
            SigMultiPoint.mult(out, sigs, sigs_len, scalars, n_bits, scratch);
        }

        /// testing methods for this lib, should not export to consumers
        pub fn testSignNVerify() !void {
            const ikm: [32]u8 = [_]u8{
                0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
                0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
                0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
                0x48, 0x99,
            };
            const sk = try SecretKey.keyGen(ikm[0..], null);
            const pk = sk.skToPk();

            const dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
            const msg = "hello foo";
            // aug is null
            const sig = sk.sign(msg[0..], dst[0..], null);

            // aug is null
            try sig.verify(true, msg[0..], dst[0..], null, &pk, true);
        }

        pub fn testAggregate(comptime is_diff_msg_len: bool) !void {
            const num_msgs = 10;
            const dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

            var rng = std.Random.DefaultPrng.init(12345);
            var sks = [_]SecretKey{SecretKey.default()} ** num_msgs;
            for (0..num_msgs) |i| {
                sks[i] = getRandomKey(&rng);
            }

            var pks: [num_msgs]PublicKey = undefined;
            const pksSlice = pks[0..];
            for (0..num_msgs) |i| {
                pksSlice[i] = sks[i].skToPk();
            }

            var pks_ptr: [num_msgs]*PublicKey = undefined;
            var pks_ptr_rev: [num_msgs]*PublicKey = undefined;
            for (pksSlice, 0..num_msgs) |*pk_ptr, i| {
                pks_ptr[i] = pk_ptr;
                pks_ptr_rev[num_msgs - i - 1] = pk_ptr;
            }

            const pk_comp = pksSlice[0].compress();
            _ = try PublicKey.uncompress(pk_comp[0..]);

            var msgs: [num_msgs][]u8 = undefined;
            // random message len
            // same message length to test aggregateVerifyC
            const same_msg_len = 32;
            const msg_lens: [num_msgs]u64 = comptime if (is_diff_msg_len) .{ 33, 34, 39, 22, 43, 1, 24, 60, 2, 41 } else [_]u64{same_msg_len} ** num_msgs;

            inline for (0..num_msgs) |i| {
                var msg = [_]u8{0} ** msg_lens[i];
                msgs[i] = msg[0..];
                rng.random().bytes(msgs[i]);
            }

            var sigs: [num_msgs]Signature = undefined;
            for (0..num_msgs) |i| {
                sigs[i] = sks[i].sign(msgs[i], dst, null);
            }

            for (0..num_msgs) |i| {
                try sigs[i].verify(true, msgs[i], dst, null, pks_ptr[i], true);
            }

            // Swap message/public key pairs to create bad signature
            for (0..num_msgs) |i| {
                if (sigs[i].verify(true, msgs[num_msgs - i - 1], dst, null, pks_ptr_rev[i], true)) {
                    try std.testing.expect(false);
                } else |err| {
                    try std.testing.expectEqual(BLST_ERROR.VERIFY_FAIL, err);
                }
            }

            var sig_ptrs: [num_msgs]*const Signature = undefined;
            for (sigs[0..], 0..num_msgs) |*sig_ptr, i| {
                sig_ptrs[i] = sig_ptr;
            }
            const agg = try AggregateSignature.aggregate(sig_ptrs[0..], true);
            const agg_sig = agg.toSignature();

            var allocator = std.testing.allocator;
            const memory_pool = try allocator.create(MemoryPool);
            try memory_pool.init(allocator);
            try initializeThreadPool(allocator);
            defer {
                deinitializeThreadPool();
                memory_pool.deinit();
                allocator.destroy(memory_pool);
            }

            // positive test
            var ro_msgs: [num_msgs][]const u8 = undefined;
            for (0..num_msgs) |i| {
                ro_msgs[i] = msgs[i];
            }
            try agg_sig.aggregateVerify(false, ro_msgs[0..], dst, pks_ptr[0..], false, memory_pool);

            // only expect this to pass if all messages are the same length
            // const res = Signature.verifyMultipleAggregateSignaturesC(&sets[0], num_sigs, msg_lens[0], &dst[0], dst.len, false, false, &rands_c[0], rands_c.len, 64, &pairing_buffer[0], pairing_buffer.len);
            if (is_diff_msg_len == false) {
                var msgs_refs: [num_msgs][*c]const u8 = undefined;
                for (msgs[0..], 0..num_msgs) |msg, i| {
                    msgs_refs[i] = &msg[0];
                }
                var pks_refs: [num_msgs]*pk_aff_type = undefined;
                for (pks_ptr[0..], 0..num_msgs) |pk, i| {
                    pks_refs[i] = &pk.point;
                }
                const res = Signature.aggregateVerifyC(&agg_sig.point, false, msgs_refs[0..], same_msg_len, dst, pks_refs[0..], false, memory_pool);
                try std.testing.expect(res == c.BLST_SUCCESS);
            }

            // Swap message/public key pairs to create bad signature
            if (agg_sig.aggregateVerify(false, ro_msgs[0..], dst, pks_ptr_rev[0..], false, memory_pool)) {
                try std.testing.expect(false);
            } else |err| switch (err) {
                BLST_ERROR.VERIFY_FAIL => {},
                else => try std.testing.expect(false),
            }
        }

        pub fn testMultipleAggSigs(comptime is_diff_msg_len: bool) !void {
            var allocator = std.testing.allocator;
            // single pairing_buffer allocation that could be reused multiple times
            const memory_pool = try allocator.create(MemoryPool);
            try memory_pool.init(allocator);
            try initializeThreadPool(allocator);
            defer {
                deinitializeThreadPool();
                memory_pool.deinit();
                allocator.destroy(memory_pool);
            }

            const dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
            const num_pks_per_sig = 10;
            const num_sigs = 10;

            var rng = std.Random.DefaultPrng.init(12345);

            var msgs: [num_sigs][]u8 = undefined;
            var sigs: [num_sigs]Signature = undefined;
            var pks: [num_sigs]PublicKey = undefined;
            var rands: [num_sigs][]u8 = undefined;
            var rands_c: [num_sigs][*c]u8 = undefined;

            // random message len
            // different message length for each signature to test verifyMultipleAggregateSignatures
            // same message length to test verifyMultipleAggregateSignaturesC
            const msg_lens: [num_sigs]u64 = comptime if (is_diff_msg_len) .{ 33, 34, 39, 22, 43, 1, 24, 60, 2, 41 } else [_]u64{32} ** num_sigs;
            const max_len = 64;

            // use inline for to keep scopes of all variable in this function instead of block scope
            inline for (0..num_sigs) |i| {
                var msg = [_]u8{0} ** max_len;
                msgs[i] = msg[0..];
                var rand = [_]u8{0} ** 32;
                rands[i] = rand[0..];
                rands_c[i] = &rand[0];
            }

            for (0..num_sigs) |i| {
                // Create public keys
                var sks_i: [num_pks_per_sig]SecretKey = undefined;
                var pks_i: [num_pks_per_sig]PublicKey = undefined;
                var pks_refs_i: [num_pks_per_sig]*const PublicKey = undefined;
                for (0..num_pks_per_sig) |j| {
                    sks_i[j] = getRandomKey(&rng);
                    pks_i[j] = sks_i[j].skToPk();
                    pks_refs_i[j] = &pks_i[j];
                }

                // Create random message for pks to all sign
                const msg_len = msg_lens[i];
                msgs[i] = msgs[i][0..msg_len];
                rng.random().bytes(msgs[i]);

                // Generate signature for each key pair
                var sigs_i: [num_pks_per_sig]Signature = undefined;
                for (0..num_pks_per_sig) |j| {
                    sigs_i[j] = sks_i[j].sign(msgs[i], dst, null);
                }

                // Test each current single signature
                for (0..num_pks_per_sig) |j| {
                    try sigs_i[j].verify(true, msgs[i], dst, null, pks_refs_i[j], true);
                }

                var sig_refs_i: [num_pks_per_sig]*const Signature = undefined;
                for (sigs_i[0..], 0..num_pks_per_sig) |*sig_ptr, j| {
                    sig_refs_i[j] = sig_ptr;
                }

                const agg_i = try AggregateSignature.aggregate(sig_refs_i[0..], false);

                // Test current aggregate signature
                sigs[i] = agg_i.toSignature();
                try sigs[i].fastAggregateVerify(false, msgs[i], dst, pks_refs_i[0..], memory_pool);

                // negative test
                if (i != 0) {
                    const verify_res = sigs[i - 1].fastAggregateVerify(false, msgs[i], dst, pks_refs_i[0..], memory_pool);
                    if (verify_res) {
                        try std.testing.expect(false);
                    } else |err| {
                        try std.testing.expectEqual(BLST_ERROR.VERIFY_FAIL, err);
                    }
                }

                // aggregate public keys and push into vec
                const pk_i = try AggregatePublicKey.aggregate(pks_refs_i[0..], false);
                pks[i] = pk_i.toPublicKey();

                // Test current aggregate signature with aggregated pks
                try sigs[i].fastAggregateVerifyPreAggregated(false, msgs[i], dst, &pks[i], memory_pool);

                const res = Signature.fastAggregateVerifyPreAggregatedC(&sigs[i].point, false, msgs[i], dst, &pks[i].point, memory_pool);
                try std.testing.expect(res == c.BLST_SUCCESS);

                // negative test
                if (i != 0) {
                    const verify_res = sigs[i - 1].fastAggregateVerifyPreAggregated(false, msgs[i], dst, &pks[i], memory_pool);
                    if (verify_res) {
                        try std.testing.expect(false);
                    } else |err| {
                        try std.testing.expectEqual(BLST_ERROR.VERIFY_FAIL, err);
                    }
                }

                // create random values
                var rand_i = rands[i];
                // Reinterpret the buffer as an array of 4 u64
                const u64_array = std.mem.bytesAsSlice(u64, rand_i[0..]);

                while (u64_array[0] == 0) {
                    // Reject zero as it is used for multiplication.
                    rng.random().bytes(rand_i[0..]);
                }
            }

            var pks_refs: [num_sigs]*PublicKey = undefined;
            for (pks[0..], 0..num_sigs) |*pk, i| {
                pks_refs[i] = pk;
            }

            var msgs_rev: [num_sigs][]const u8 = undefined;
            for (msgs[0..], 0..num_sigs) |msg, i| {
                msgs_rev[num_sigs - i - 1] = msg;
            }

            var sigs_refs: [num_sigs]*Signature = undefined;
            for (sigs[0..], 0..num_sigs) |*sig, i| {
                sigs_refs[i] = sig;
            }

            var pks_rev: [num_sigs]*PublicKey = undefined;
            for (pks_refs[0..], 0..num_sigs) |pk, i| {
                pks_rev[num_sigs - i - 1] = pk;
            }

            var sig_rev_refs: [num_sigs]*Signature = undefined;
            for (sigs_refs[0..], 0..num_sigs) |sig, i| {
                sig_rev_refs[num_sigs - i - 1] = sig;
            }

            try initializeThreadPool(allocator);
            defer {
                deinitializeThreadPool();
            }

            var ro_msgs: [num_sigs][]const u8 = undefined;
            for (0..num_sigs) |i| {
                ro_msgs[i] = msgs[i];
            }

            var ro_rands: [num_sigs][]const u8 = undefined;
            for (0..num_sigs) |i| {
                ro_rands[i] = rands[i];
            }
            try Signature.verifyMultipleAggregateSignatures(ro_msgs[0..], dst, pks_refs[0..], false, sigs_refs[0..], false, ro_rands[0..], 64, memory_pool);
            var sets: [num_sigs]*const SignatureSet = undefined;
            for (0..num_sigs) |i| {
                sets[i] = &.{ .msg = &msgs[i][0], .pk = &pks[i].point, .sig = &sigs[i].point };
            }

            // only expect this to pass if all messages are the same length
            const res = Signature.verifyMultipleAggregateSignaturesC(sets[0..], msg_lens[0], dst, false, false, ro_rands[0..], 64, memory_pool);
            try std.testing.expect(is_diff_msg_len == (res != c.BLST_SUCCESS));

            // negative tests (use reverse msgs, pks, and sigs)
            var verify_res = Signature.verifyMultipleAggregateSignatures(msgs_rev[0..], dst, pks_refs[0..], false, sigs_refs[0..], false, ro_rands[0..], 64, memory_pool);
            if (verify_res) {
                try std.testing.expect(false);
            } else |err| {
                try std.testing.expectEqual(BLST_ERROR.VERIFY_FAIL, err);
            }

            var verify_c_res: c_uint = 0;
            if (!is_diff_msg_len) {
                var sets_msgs_rev: [num_sigs]*const SignatureSet = undefined;
                for (0..num_sigs) |i| {
                    sets_msgs_rev[i] = &.{ .msg = &msgs_rev[i][0], .pk = &pks[i].point, .sig = &sigs[i].point };
                }
                verify_c_res = Signature.verifyMultipleAggregateSignaturesC(sets_msgs_rev[0..], msg_lens[0], dst, false, false, ro_rands[0..], 64, memory_pool);
                try std.testing.expect(verify_c_res != c.BLST_SUCCESS);
            }

            verify_res = Signature.verifyMultipleAggregateSignatures(ro_msgs[0..], dst, pks_rev[0..], false, sigs_refs[0..], false, ro_rands[0..], 64, memory_pool);
            if (verify_res) {
                try std.testing.expect(false);
            } else |err| {
                try std.testing.expectEqual(BLST_ERROR.VERIFY_FAIL, err);
            }

            if (!is_diff_msg_len) {
                var sets_pks_rev: [num_sigs]*const SignatureSet = undefined;
                for (0..num_sigs) |i| {
                    sets_pks_rev[i] = &.{ .msg = &msgs[i][0], .pk = &pks_rev[i].point, .sig = &sigs[i].point };
                }
                verify_c_res = Signature.verifyMultipleAggregateSignaturesC(sets_pks_rev[0..], msg_lens[0], dst, false, false, ro_rands[0..], 64, memory_pool);
                try std.testing.expect(verify_c_res != c.BLST_SUCCESS);
            }

            verify_res = Signature.verifyMultipleAggregateSignatures(ro_msgs[0..], dst, pks_refs[0..], false, sig_rev_refs[0..], false, ro_rands[0..], 64, memory_pool);
            if (verify_res) {
                try std.testing.expect(false);
            } else |err| {
                try std.testing.expectEqual(BLST_ERROR.VERIFY_FAIL, err);
            }

            if (!is_diff_msg_len) {
                var sets_sigs_rev: [num_sigs]*const SignatureSet = undefined;
                for (0..num_sigs) |i| {
                    sets_sigs_rev[i] = &.{ .msg = &msgs[i][0], .pk = &pks[i].point, .sig = &sig_rev_refs[i].point };
                }
                verify_c_res = Signature.verifyMultipleAggregateSignaturesC(sets_sigs_rev[0..], msg_lens[0], dst, false, false, ro_rands[0..], 64, memory_pool);
                try std.testing.expect(verify_c_res != c.BLST_SUCCESS);
            }
        }

        pub fn testSerialization() !void {
            var rng = std.Random.DefaultPrng.init(12345);
            const sk = getRandomKey(&rng);
            const sk2 = getRandomKey(&rng);

            const pk = sk.skToPk();
            const pk_comp = pk.compress();
            const pk_ser = pk.serialize();

            const pk_uncomp = try PublicKey.uncompress(pk_comp[0..]);
            try std.testing.expect(pk_uncomp.isEqual(&pk));

            const pk_deser = try PublicKey.deserialize(pk_ser[0..]);
            try std.testing.expect(pk_deser.isEqual(&pk));

            const pk2 = sk2.skToPk();
            const pk_comp2 = pk2.compress();
            const pk_ser2 = pk2.serialize();

            const pk_uncomp2 = try PublicKey.uncompress(pk_comp2[0..]);
            try std.testing.expect(pk_uncomp2.isEqual(&pk2));

            const pk_deser2 = try PublicKey.deserialize(pk_ser2[0..]);
            try std.testing.expect(pk_deser2.isEqual(&pk2));

            try std.testing.expect(!pk.isEqual(&pk2));
            try std.testing.expect(!pk_uncomp.isEqual(&pk2));
            try std.testing.expect(!pk_deser.isEqual(&pk2));
            try std.testing.expect(!pk_uncomp2.isEqual(&pk));
            try std.testing.expect(!pk_deser2.isEqual(&pk));
        }

        pub fn testSerde() !void {
            var rng = std.Random.DefaultPrng.init(12345);
            const sk = getRandomKey(&rng);
            const pk = sk.skToPk();
            const sig = sk.sign("asdf", "qwer", "zxcv");
            try sig.verify(true, "asdf", "qwer", "zxcv", &pk, true);

            // roundtrip through serde. TODO: do this in Zig
            const pk_ser = pk.serialize();
            const sig_ser = sig.serialize();
            const pk_des = try PublicKey.deserialize(pk_ser[0..]);
            const sig_des = try Signature.deserialize(sig_ser[0..]);

            try std.testing.expect(pk.isEqual(&pk_des));
            try std.testing.expect(sig.isEqual(&sig_des));

            try sig.verify(true, "asdf", "qwer", "zxcv", &pk_des, true);
            try sig_des.verify(true, "asdf", "qwer", "zxcv", &pk, true);

            const sk_ser = sk.serialize();
            const sk_des = try SecretKey.deserialize(sk_ser[0..]);
            const sig2 = sk_des.sign("asdf", "qwer", "zxcv");
            try std.testing.expect(sig.isEqual(&sig2));
        }

        /// additional tests in Zig to make sure our wrapped types point to the same memory as the original types
        /// for example, given a slice of PublicKey, we can pass pointer to the first element to the C function which expect *const pk_aff_type
        pub fn testTypeAlignment() !void {
            // alignOf
            try std.testing.expect(@alignOf(SecretKey) == @alignOf(c.blst_scalar));
            try std.testing.expect(@alignOf(PublicKey) == @alignOf(pk_aff_type));
            try std.testing.expect(@alignOf(AggregatePublicKey) == @alignOf(pk_type));
            try std.testing.expect(@alignOf(Signature) == @alignOf(sig_aff_type));
            try std.testing.expect(@alignOf(AggregateSignature) == @alignOf(sig_type));

            // sizeOf
            try std.testing.expect(@sizeOf(SecretKey) == @sizeOf(c.blst_scalar));
            try std.testing.expect(@sizeOf(PublicKey) == @sizeOf(pk_aff_type));
            try std.testing.expect(@sizeOf(AggregatePublicKey) == @sizeOf(pk_type));
            try std.testing.expect(@sizeOf(Signature) == @sizeOf(sig_aff_type));
            try std.testing.expect(@sizeOf(AggregateSignature) == @sizeOf(sig_type));

            // make sure wrapped structs and C structs point to the same memory so that we can safely use @ptrCast
            var rng = std.Random.DefaultPrng.init(12345);
            const sk = getRandomKey(&rng);
            const pk = sk.skToPk();
            const pk_addr = @intFromPtr(&pk);
            const pk_point_addr = @intFromPtr(&pk.point);
            try std.testing.expect(pk_addr == pk_point_addr);

            const dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
            const msg = "hello foo";
            const sig = sk.sign(msg[0..], dst[0..], null);
            const sig_addr = @intFromPtr(&sig);
            const point_addr = @intFromPtr(&sig.point);
            try std.testing.expect(sig_addr == point_addr);
        }

        /// multi point
        pub fn testAddPubkey() !void {
            try pk_multi_point.testAdd();
        }

        pub fn testMultPubkey() !void {
            try pk_multi_point.testMult();
        }

        pub fn testAddSig() !void {
            try sig_multi_point.testAdd();
        }

        pub fn testMultSig() !void {
            try sig_multi_point.testMult();
        }

        /// this is the same test to Rust's test_multi_point()
        pub fn testMultiPoint() !void {
            const dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
            const num_pks = 10;

            var rng = std.Random.DefaultPrng.init(12345);

            // Create public keys
            var sks = [_]SecretKey{SecretKey.default()} ** num_pks;
            for (0..num_pks) |i| {
                sks[i] = getRandomKey(&rng);
            }

            var pks: [num_pks]PublicKey = undefined;
            for (0..num_pks) |i| {
                pks[i] = sks[i].skToPk();
            }
            var pks_refs: [num_pks]*const PublicKey = undefined;
            for (pks[0..], 0..num_pks) |*pk, i| {
                pks_refs[i] = pk;
            }

            // Create random message for pks to all sign
            // var msg_len = (rng.next() & 0x3F) + 1;
            // random msg_len
            const msg_len = 50;
            var msg: [msg_len]u8 = undefined;
            rng.random().bytes(msg[0..]);

            // Generate signature for each key pair
            var sigs: [num_pks]Signature = undefined;
            for (0..num_pks) |i| {
                sigs[i] = sks[i].sign(msg[0..], dst, null);
            }
            var sigs_refs: [num_pks]*const Signature = undefined;
            for (sigs[0..], 0..num_pks) |*sig, i| {
                sigs_refs[i] = sig;
            }

            // Sanity test each current single signature
            for (0..num_pks) |i| {
                try sigs[i].verify(true, msg[0..], dst, null, pks_refs[i], true);
            }

            // sanity test aggregated signature
            const agg_pk = try AggregatePublicKey.aggregate(pks_refs[0..], false);
            const pk_from_agg = agg_pk.toPublicKey();
            const agg_sig = try AggregateSignature.aggregate(sigs_refs[0..], false);
            const sig_from_agg = agg_sig.toSignature();
            try sig_from_agg.verify(true, msg[0..], dst, null, &pk_from_agg, true);

            // test multi-point aggregation using add
            const added_pk = addPublicKeys(pks_refs[0..]);
            const pk_from_add = added_pk.toPublicKey();
            const added_sig = addSignatures(sigs_refs[0..]);
            const sig_from_add = added_sig.toSignature();
            try sig_from_add.verify(true, msg[0..], dst, null, &pk_from_add, true);

            // test multi-point aggregation using mult
            // n_bytes = 32
            const rands_len = 32 * num_pks;
            var rands: [rands_len]u8 = [_]u8{0} ** rands_len;
            rng.random().bytes(rands[0..]);

            var scalars_refs: [num_pks]*const u8 = undefined;
            for (0..num_pks) |i| {
                scalars_refs[i] = &rands[i * 32];
            }

            const n_bits = 64;

            var allocator = std.testing.allocator;
            const pk_scratch = try allocator.alloc(u64, pk_scratch_size_of_fn(num_pks) / 8);
            defer allocator.free(pk_scratch);
            const sig_scratch = try allocator.alloc(u64, sig_scratch_size_of_fn(num_pks) / 8);
            defer allocator.free(sig_scratch);

            const mult_pk = multPublicKeys(pks_refs[0..], scalars_refs[0..], n_bits, pk_scratch);
            const pk_from_mult = mult_pk.toPublicKey();
            const mult_sig = multSignatures(sigs_refs[0..], scalars_refs[0..], n_bits, sig_scratch);
            const sig_from_mult = mult_sig.toSignature();
            try sig_from_mult.verify(true, msg[0..], dst, null, &pk_from_mult, true);
        }

        /// specific testing in zig, logic is similar to testMultiPoint() with
        /// - no need to generate random
        /// - provide scratch values in []u8 instead of []u64
        pub fn testAggregateWithRandomness() !void {
            const dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
            const num_pks = 10;

            var rng = std.Random.DefaultPrng.init(12345);

            // Create public keys
            var sks = [_]SecretKey{SecretKey.default()} ** num_pks;
            for (0..num_pks) |i| {
                sks[i] = getRandomKey(&rng);
            }

            var pks: [num_pks]PublicKey = undefined;
            for (0..num_pks) |i| {
                pks[i] = sks[i].skToPk();
            }
            var pks_refs: [num_pks]*PublicKey = undefined;
            for (pks[0..], 0..num_pks) |*pk, i| {
                pks_refs[i] = pk;
            }

            // Create random message for pks to all sign
            // var msg_len = (rng.next() & 0x3F) + 1;
            // random msg_len
            const msg_len = 50;
            var msg: [msg_len]u8 = undefined;
            rng.random().bytes(msg[0..]);

            // Generate signature for each key pair
            var sigs: [num_pks]Signature = undefined;
            for (0..num_pks) |i| {
                sigs[i] = sks[i].sign(msg[0..], dst, null);
            }
            var sigs_refs: [num_pks]*Signature = undefined;
            for (sigs[0..], 0..num_pks) |*sig, i| {
                sigs_refs[i] = sig;
            }

            // Sanity test each current single signature
            for (0..num_pks) |i| {
                try sigs[i].verify(true, msg[0..], dst, null, pks_refs[i], true);
            }

            // out params
            var agg_pk = PublicKey.default();
            var agg_sig = Signature.default();

            var set: [num_pks]*const PkAndSerializedSig = undefined;
            var set_c: [num_pks]*const PkAndSerializedSigC = undefined;
            for (0..num_pks) |i| {
                const bytes = sigs[i].serialize();
                var s = PkAndSerializedSig{ .pk = &pks[i], .sig = bytes[0..] };
                set[i] = &s;
                var s_c = PkAndSerializedSigC{ .pk = &pks[i].point, .sig = &bytes[0], .sig_len = bytes.len };
                set_c[i] = &s_c;
            }

            // scratch, allocate once and reuse
            var allocator = std.testing.allocator;
            const memory_pool = try allocator.create(MemoryPool);
            try memory_pool.init(allocator);

            try aggregateWithRandomness(set[0..], memory_pool, &agg_pk, &agg_sig);

            // make sure the thread returns pk_scratch and sig_scratch to the memory pool
            try std.testing.expect(memory_pool.pk_scratch_arr.items.len == 1);
            try std.testing.expect(memory_pool.sig_scratch_arr.items.len == 1);

            try agg_sig.verify(true, msg[0..], dst, null, &agg_pk, true);

            try initializeThreadPool(allocator);
            defer {
                deinitializeThreadPool();
                memory_pool.deinit();
                allocator.destroy(memory_pool);
            }
            var mutex = Mutex{};
            Context.mutex = &mutex;
            var cond = std.Thread.Condition{};
            Context.cond = &cond;
            Context.verify_result = null;

            const call_res = asyncAggregateWithRandomness(set_c[0..num_pks], memory_pool, &agg_pk.point, &agg_sig.point, Context.callback);
            try std.testing.expectEqual(call_res, 0);
            mutex.lock();
            defer mutex.unlock();

            // wait for the callback (triggerred from another thread) to finish
            while (Context.verify_result == null) {
                cond.wait(&mutex);
            }

            try std.testing.expectEqual(0, Context.verify_result);

            // make sure the thread returns pk_scratch and sig_scratch to the memory pool
            try std.testing.expect(memory_pool.pk_scratch_arr.items.len == 1);
            try std.testing.expect(memory_pool.sig_scratch_arr.items.len == 1);

            // make sure the aggregated public key and signature are valid
            try agg_sig.verify(true, msg[0..], dst, null, &agg_pk, true);
        }

        fn getRandomKey(rng: *Xoshiro256) SecretKey {
            var value: [32]u8 = [_]u8{0} ** 32;
            rng.random().bytes(value[0..]);
            const sk = SecretKey.keyGen(value[0..], null) catch {
                @panic("SecretKey.keyGen() failed\n");
            };
            return sk;
        }
    };
}

pub fn randNonZero() u64 {
    var rand = getRandom();
    var res = rand.int(u64);
    while (res == 0) {
        res = rand.int(u64);
    }
    return res;
}

pub fn randBytes(bytes: []u8) void {
    var rand = getRandom();
    rand.random().bytes(bytes);
}

var random: ?std.Random.DefaultPrng = null;

fn getRandom() *std.Random.DefaultPrng {
    if (random == null) {
        const timestamp: u64 = @intCast(std.time.milliTimestamp());
        random = std.Random.DefaultPrng.init(timestamp);
    }
    return &random.?;
}
