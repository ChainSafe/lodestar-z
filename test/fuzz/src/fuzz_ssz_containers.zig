// Fuzz target for SSZ container deserialization (fixed and variable).
//
// Input format: [selector_byte] [ssz_data...]
//
// Fixed containers (no allocator needed):
//   0x00 → Fork (16 bytes)
//   0x01 → Checkpoint (40 bytes)
//   0x02 → AttestationData (128 bytes)
//   0x03 → Eth1Data (72 bytes)
//   0x04 → BeaconBlockHeader (112 bytes)
//   0x05 → Validator (121 bytes)
//
// Variable containers (allocator needed):
//   0x06 → Attestation
//   0x07 → IndexedAttestation

const std = @import("std");
const assert = std.debug.assert;
const fuzz_options = @import("fuzz_options");
const consensus_types = @import("consensus_types");
const phase0 = consensus_types.phase0;
const oracle = @import("ssz_oracle.zig");

const selector_count: u32 = 8;
const fuzz_buffer_size: u32 = 64 * 1024 * 1024;

var fuzz_buf: [fuzz_buffer_size]u8 = undefined;

pub export fn zig_fuzz_init() callconv(.c) void {
    // No initialization needed.
    // FixedBufferAllocator is reset per iteration.
}

pub export fn zig_fuzz_test(
    buf: [*]const u8,
    len: usize,
) callconv(.c) void {
    if (len > fuzz_options.max_input_len) return;
    if (len < 1) return;

    var fixed_buffer_allocator =
        std.heap.FixedBufferAllocator.init(&fuzz_buf);
    var tracking = std.testing.FailingAllocator.init(fixed_buffer_allocator.allocator(), .{});
    defer assert(tracking.allocated_bytes == tracking.freed_bytes);
    const allocator = tracking.allocator();

    const selector = buf[0];
    const data = buf[1..len];

    switch (selector % selector_count) {
        // Fixed containers.
        0 => fuzzFixedContainer(phase0.Fork, data),
        1 => fuzzFixedContainer(phase0.Checkpoint, data),
        2 => fuzzFixedContainer(
            phase0.AttestationData,
            data,
        ),
        3 => fuzzFixedContainer(phase0.Eth1Data, data),
        4 => fuzzFixedContainer(
            phase0.BeaconBlockHeader,
            data,
        ),
        5 => fuzzFixedContainer(phase0.Validator, data),
        // Variable containers.
        6 => fuzzVariableContainer(
            phase0.Attestation,
            allocator,
            data,
        ),
        7 => fuzzVariableContainer(
            phase0.IndexedAttestation,
            allocator,
            data,
        ),
        else => unreachable,
    }
}

fn fuzzFixedContainer(
    comptime ContainerT: type,
    data: []const u8,
) void {
    const valid = data.len == ContainerT.fixed_size and
        (ContainerT != phase0.Validator or data[88] <= 1);
    var value: ContainerT.Type = undefined;
    ContainerT.deserializeFromBytes(
        data,
        &value,
    ) catch |err| {
        assert(!valid);
        switch (@as(anyerror, err)) {
            error.InvalidSize, error.invalidBoolean => return,
            else => panicUnexpected("deserializing fixed container", err),
        }
    };
    assert(valid);
    if (ContainerT == phase0.Fork) {
        assert(std.mem.eql(u8, &value.previous_version, data[0..4]));
        assert(std.mem.eql(u8, &value.current_version, data[4..8]));
        assert(value.epoch == oracle.uint(u64, data[8..16]));
    } else if (ContainerT == phase0.Checkpoint) {
        assertCheckpoint(&value, data);
    } else if (ContainerT == phase0.AttestationData) {
        assertAttestationData(&value, data);
    } else if (ContainerT == phase0.Eth1Data) {
        assert(std.mem.eql(u8, &value.deposit_root, data[0..32]));
        assert(value.deposit_count == oracle.uint(u64, data[32..40]));
        assert(std.mem.eql(u8, &value.block_hash, data[40..72]));
    } else if (ContainerT == phase0.BeaconBlockHeader) {
        assert(value.slot == oracle.uint(u64, data[0..8]));
        assert(value.proposer_index == oracle.uint(u64, data[8..16]));
        assert(std.mem.eql(u8, &value.parent_root, data[16..48]));
        assert(std.mem.eql(u8, &value.state_root, data[48..80]));
        assert(std.mem.eql(u8, &value.body_root, data[80..112]));
    } else if (ContainerT == phase0.Validator) {
        assert(std.mem.eql(u8, &value.pubkey, data[0..48]));
        assert(std.mem.eql(u8, &value.withdrawal_credentials, data[48..80]));
        assert(value.effective_balance == oracle.uint(u64, data[80..88]));
        assert(value.slashed == (data[88] == 1));
        assert(value.activation_eligibility_epoch == oracle.uint(u64, data[89..97]));
        assert(value.activation_epoch == oracle.uint(u64, data[97..105]));
        assert(value.exit_epoch == oracle.uint(u64, data[105..113]));
        assert(value.withdrawable_epoch == oracle.uint(u64, data[113..121]));
    } else unreachable;

    // Round-trip invariant.
    var serialized: [ContainerT.fixed_size]u8 = undefined;
    const written = ContainerT.serializeIntoBytes(
        &value,
        &serialized,
    );
    assert(written == ContainerT.fixed_size);
    assert(std.mem.eql(u8, &serialized, data));
}

fn fuzzVariableContainer(
    comptime ContainerT: type,
    allocator: std.mem.Allocator,
    data: []const u8,
) void {
    const valid = validVariableContainer(ContainerT, data);
    var value: ContainerT.Type = ContainerT.default_value;
    defer ContainerT.deinit(allocator, &value);
    ContainerT.deserializeFromBytes(
        allocator,
        data,
        &value,
    ) catch |err| {
        assert(!valid);
        switch (@as(anyerror, err)) {
            error.InvalidSize,
            error.offsetOutOfRange,
            error.UnexpectedRemainder,
            error.gtLimit,
            error.noPaddingBit,
            error.tooLarge,
            => return,
            else => panicUnexpected("deserializing variable container", err),
        }
    };
    assert(valid);
    assertAttestationData(&value.data, data[4..132]);
    assert(std.mem.eql(u8, &value.signature, data[132..228]));
    if (ContainerT == phase0.Attestation) {
        const Bits = ContainerT.getFieldType("aggregation_bits");
        assert(value.aggregation_bits.bit_len == oracle.bitLength(data[228..], Bits.limit).?);
        for (0..value.aggregation_bits.bit_len) |i| {
            const actual = value.aggregation_bits.get(i) catch |err|
                panicUnexpected("reading aggregation bits", err);
            assert(actual == oracle.bit(data[228..], i));
        }
    } else {
        assert(value.attesting_indices.items.len == (data.len - 228) / 8);
        for (value.attesting_indices.items, 0..) |index, i| {
            assert(index == oracle.uint(u64, data[228 + i * 8 ..][0..8]));
        }
    }

    // Round-trip invariant.
    const serialized_size = ContainerT.serializedSize(&value);
    assert(serialized_size == data.len);
    const output = allocator.alloc(
        u8,
        serialized_size,
    ) catch |err| panicUnexpected("allocating container output", err);
    defer allocator.free(output);
    const written = ContainerT.serializeIntoBytes(
        &value,
        output,
    );
    assert(written == serialized_size);
    assert(std.mem.eql(u8, output, data));
}

fn validVariableContainer(comptime ContainerT: type, data: []const u8) bool {
    if (data.len < 228) return false;
    if (oracle.uint(u32, data[0..4]) != 228) return false;
    if (ContainerT == phase0.Attestation) {
        const Bits = ContainerT.getFieldType("aggregation_bits");
        return oracle.bitLength(data[228..], Bits.limit) != null;
    } else {
        const Indices = ContainerT.getFieldType("attesting_indices");
        return (data.len - 228) % 8 == 0 and (data.len - 228) / 8 <= Indices.limit;
    }
}

fn assertCheckpoint(value: *const phase0.Checkpoint.Type, data: []const u8) void {
    assert(data.len == 40);
    assert(value.epoch == oracle.uint(u64, data[0..8]));
    assert(std.mem.eql(u8, &value.root, data[8..40]));
}

fn assertAttestationData(value: *const phase0.AttestationData.Type, data: []const u8) void {
    assert(data.len == 128);
    assert(value.slot == oracle.uint(u64, data[0..8]));
    assert(value.index == oracle.uint(u64, data[8..16]));
    assert(std.mem.eql(u8, &value.beacon_block_root, data[16..48]));
    assertCheckpoint(&value.source, data[48..88]);
    assertCheckpoint(&value.target, data[88..128]);
}

fn panicUnexpected(comptime context: []const u8, err: anyerror) noreturn {
    std.debug.panic("{s}: {s}", .{ context, @errorName(err) });
}

test "container decoder checks field values, boolean validity, and variable offsets" {
    var input: [486]u8 = undefined;
    for (&input, 0..) |*byte, i| byte.* = @truncate(i);
    for ([_]usize{ 16, 40, 128, 72, 112, 121 }, 0..) |size, selector| {
        input[0] = @intCast(selector);
        if (selector == 5) input[89] = 1;
        for ([_]usize{ size - 1, size, size + 1 }) |len| zig_fuzz_test(&input, len + 1);
    }
    input[89] = 2;
    zig_fuzz_test(&input, 122);

    for ([_]u8{ 6, 7 }) |selector| {
        input[0] = selector;
        for ([_]u8{ 0, 227, 228, 229, 255 }) |offset| {
            @memcpy(input[1..5], &[_]u8{ offset, 0, 0, 0 });
            for ([_]usize{ 227, 228, 229, 236, 237 }) |len| {
                zig_fuzz_test(&input, len + 1);
            }
        }
    }
    input[0] = 6;
    @memcpy(input[1..5], &[_]u8{ 228, 0, 0, 0 });
    for ([_]u8{ 0, 1, 2, 128 }) |sentinel| {
        input[485] = sentinel;
        zig_fuzz_test(&input, input.len);
    }
}

test "variable container decoder OOM preserves initialized output ownership" {
    inline for (.{ phase0.Attestation, phase0.IndexedAttestation }) |Container| {
        var data = [_]u8{0} ** 236;
        data[0] = 228;
        data[data.len - 1] = 1;
        var completed = false;
        for (0..2) |fail_index| {
            var tracking = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
            const allocator = tracking.allocator();
            var value = Container.default_value;
            const result = Container.deserializeFromBytes(allocator, &data, &value);
            Container.deinit(allocator, &value);
            try std.testing.expectEqual(tracking.allocated_bytes, tracking.freed_bytes);
            if (tracking.has_induced_failure) {
                try std.testing.expectError(error.OutOfMemory, result);
            } else {
                try result;
                completed = true;
                break;
            }
        }
        try std.testing.expect(completed);
    }
}
