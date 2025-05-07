const std = @import("std");

/// Create MultiPoint struct, this follows non-std implementation of Rust binding
/// equivalent to blst/bindings/rust/src/pippenger-no_std.rs
/// IT: input type, for example PublicKey or Signature
/// OT: output type, for example AggregatePublicKey or AggregateSignature
pub fn createMultiPoint(comptime IT: type, comptime OT: type, it_default_fn: anytype, ot_default_fn: anytype, out_eql_fn: anytype, add_fn: anytype, multi_scalar_mult_fn: anytype, scratch_sizeof_fn: anytype, mult_fn: anytype, generator_fn: anytype, to_affines_fn: anytype, add_or_double_fn: anytype) type {
    const MultiPoint = struct {
        /// Skip from([]OT) api
        /// Rust accepts []OT here which make it convenient for test_add
        /// bringing that here makes us deal with allocator
        /// instead of that, it accepts []IT, the conversion of []IT to []OT is done at consumer side
        pub fn add(out: *OT, points: [*c]*const IT, len: usize) void {
            // consumer usually need to convert []IT to []*IT which is not required in Rust
            add_fn(out, points, len);
        }

        /// scratch parameter is designed to be reused here
        pub fn mult(out: *OT, points: [*c]*const IT, points_len: usize, scalars: [*c]*const u8, n_bits: usize, scratch: [*c]u64) void {
            multi_scalar_mult_fn(out, points, points_len, scalars, n_bits, scratch);
        }
    };

    return struct {
        pub fn getMultiPoint() type {
            return MultiPoint;
        }

        pub fn testAdd() !void {
            const n_points = 2000;
            const n_bits = 32;
            const n_bytes = (n_bits + 7) / 8;

            var scalars = [_]u8{0} ** (n_points * n_bytes);

            var rng = std.Random.DefaultPrng.init(12345);
            rng.random().bytes(scalars[0..]);

            var points: [n_points]OT = undefined;
            var naive: OT = ot_default_fn();

            for (0..n_points) |i| {
                mult_fn(&points[i], generator_fn(), &scalars[i * n_bytes], 32);
                add_or_double_fn(&naive, &naive, &points[i]);
            }

            var points_refs: [n_points]*OT = undefined;
            for (points[0..], 0..) |*point, i| {
                points_refs[i] = point;
            }

            // convert []OT to []IT
            var aff_points_refs: [n_points]*IT = undefined;
            var aff_points: [n_points]IT = [_]IT{it_default_fn()} ** n_points;
            for (aff_points[0..], 0..) |*point, i| {
                aff_points_refs[i] = point;
            }

            to_affines_fn(aff_points_refs[0], &points_refs, n_points);
            var add_res = ot_default_fn();
            MultiPoint.add(&add_res, @ptrCast(&aff_points_refs[0]), aff_points_refs.len);
            try std.testing.expect(out_eql_fn(&naive, &add_res));
        }

        pub fn testMult() !void {
            const n_points = 2000;
            const n_bits = 160;
            const n_bytes = (n_bits + 7) / 8;

            var scalars = [_]u8{0} ** (n_points * n_bytes);
            var rng = std.Random.DefaultPrng.init(12345);
            rng.random().bytes(scalars[0..]);

            var scalars_refs: [n_points]*const u8 = undefined;
            for (0..n_points) |i| {
                scalars_refs[i] = &scalars[i * n_bytes];
            }

            var allocator = std.testing.allocator;
            const scratch = try allocator.alloc(u64, scratch_sizeof_fn(n_points) / 8);
            defer allocator.free(scratch);

            var points: [n_points]OT = [_]OT{ot_default_fn()} ** n_points;

            // convert []OT to []IT
            var aff_points_refs: [n_points]*IT = undefined;
            var aff_points: [n_points]IT = [_]IT{it_default_fn()} ** n_points;
            for (aff_points[0..], 0..) |*point, i| {
                aff_points_refs[i] = point;
            }

            var naive = ot_default_fn();
            var points_refs: [n_points]*OT = undefined;

            for (0..n_points) |i| {
                mult_fn(&points[i], generator_fn(), &scalars[i * n_bytes], @min(32, n_bits));
                points_refs[i] = &points[i];
                var t = ot_default_fn();
                mult_fn(&t, &points[i], &scalars[i * n_bytes], n_bits);
                add_or_double_fn(&naive, &naive, &t);

                // TODO: this is not efficient as it contains duplicate works
                to_affines_fn(aff_points_refs[0], &points_refs, (i + 1));
                if (i < 27) {
                    var mult_res = ot_default_fn();
                    MultiPoint.mult(&mult_res, @ptrCast(&aff_points_refs[0]), (i + 1), &scalars_refs[0], n_bits, &scratch[0]);
                    try std.testing.expect(out_eql_fn(&naive, &mult_res));
                }
            }

            for (points[0..], 0..) |*point, i| {
                points_refs[i] = point;
            }

            to_affines_fn(aff_points_refs[0], &points_refs, n_points);

            var mult_res = ot_default_fn();
            MultiPoint.mult(&mult_res, @ptrCast(&aff_points_refs[0]), aff_points_refs.len, &scalars_refs[0], n_bits, &scratch[0]);
            try std.testing.expect(out_eql_fn(&naive, &mult_res));
        }
    };
}
