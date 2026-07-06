//! Same-machine comparison against lambdaclass/libssz's differential bench.
//! Replicates `benches/src/fixtures.rs::make_beacon_state` exactly (phase0
//! BeaconState, deterministic contents) so encode/decode/htr numbers are
//! comparable with `cargo bench --bench differential -- beacon_state` run on
//! the same host.
const std = @import("std");
const phase0 = @import("consensus_types").phase0;
const ssz = @import("ssz");
const zbench = @import("zbench");

const BeaconState = phase0.BeaconState;

fn makeBytes32(seed: u64) [32]u8 {
    var b: [32]u8 = undefined;
    for (0..4) |i| {
        std.mem.writeInt(u64, b[i * 8 ..][0..8], seed +% @as(u64, i), .little);
    }
    return b;
}

fn makeValidator(seed: u64) phase0.Validator.Type {
    var pubkey: [48]u8 = undefined;
    for (0..6) |i| {
        std.mem.writeInt(u64, pubkey[i * 8 ..][0..8], seed +% @as(u64, i), .little);
    }
    var wc: [32]u8 = undefined;
    for (0..4) |i| {
        std.mem.writeInt(u64, wc[i * 8 ..][0..8], seed *% 31 +% @as(u64, i), .little);
    }
    return .{
        .pubkey = pubkey,
        .withdrawal_credentials = wc,
        .effective_balance = 32_000_000_000,
        .slashed = seed & 1 == 1,
        .activation_eligibility_epoch = seed,
        .activation_epoch = seed +% 1,
        .exit_epoch = std.math.maxInt(u64),
        .withdrawable_epoch = std.math.maxInt(u64),
    };
}

fn makeHeader(seed: u64) phase0.BeaconBlockHeader.Type {
    var parent_root: [32]u8 = undefined;
    var state_root: [32]u8 = undefined;
    var body_root: [32]u8 = undefined;
    for (0..4) |i| {
        std.mem.writeInt(u64, parent_root[i * 8 ..][0..8], seed +% @as(u64, i), .little);
        std.mem.writeInt(u64, state_root[i * 8 ..][0..8], seed *% 7 +% @as(u64, i), .little);
        std.mem.writeInt(u64, body_root[i * 8 ..][0..8], seed *% 13 +% @as(u64, i), .little);
    }
    return .{
        .slot = seed,
        .proposer_index = seed *% 3,
        .parent_root = parent_root,
        .state_root = state_root,
        .body_root = body_root,
    };
}

fn makeCheckpoint(seed: u64) phase0.Checkpoint.Type {
    var root: [32]u8 = undefined;
    for (0..4) |i| {
        std.mem.writeInt(u64, root[i * 8 ..][0..8], seed *% 17 +% @as(u64, i), .little);
    }
    return .{ .epoch = seed, .root = root };
}

fn makeEth1Data(seed: u64) phase0.Eth1Data.Type {
    var deposit_root: [32]u8 = undefined;
    var block_hash: [32]u8 = undefined;
    for (0..4) |i| {
        std.mem.writeInt(u64, deposit_root[i * 8 ..][0..8], seed *% 11 +% @as(u64, i), .little);
        std.mem.writeInt(u64, block_hash[i * 8 ..][0..8], seed *% 23 +% @as(u64, i), .little);
    }
    return .{ .deposit_root = deposit_root, .deposit_count = seed *% 5, .block_hash = block_hash };
}

fn makeAttestationData(seed: u64) phase0.AttestationData.Type {
    var bbr: [32]u8 = undefined;
    for (0..4) |i| {
        std.mem.writeInt(u64, bbr[i * 8 ..][0..8], seed *% 29 +% @as(u64, i), .little);
    }
    return .{
        .slot = seed,
        .index = seed *% 3,
        .beacon_block_root = bbr,
        .source = makeCheckpoint(seed),
        .target = makeCheckpoint(seed +% 1),
    };
}

fn makePendingAttestation(allocator: std.mem.Allocator, seed: u64) !phase0.PendingAttestation.Type {
    var bl = try ssz.BitList(2048).fromBitLen(allocator, 2048);
    var i: usize = 0;
    while (i < 2048) : (i += 3) {
        try bl.setAssumeCapacity(i, true);
    }
    return .{
        .aggregation_bits = bl,
        .data = makeAttestationData(seed),
        .inclusion_delay = seed +% 1,
        .proposer_index = seed *% 7,
    };
}

fn makeBeaconState(allocator: std.mem.Allocator, n_validators: usize) !*BeaconState.Type {
    const state = try allocator.create(BeaconState.Type);
    state.* = BeaconState.default_value;

    state.genesis_time = 1606824023;
    state.genesis_validators_root = makeBytes32(42);
    state.slot = 1000;
    state.fork = .{
        .previous_version = .{ 0x00, 0x00, 0x00, 0x00 },
        .current_version = .{ 0x01, 0x00, 0x00, 0x00 },
        .epoch = 100,
    };
    state.latest_block_header = makeHeader(999);
    for (0..8192) |i| {
        state.block_roots[i] = makeBytes32(@as(u64, i));
        state.state_roots[i] = makeBytes32(@as(u64, i) + 10000);
    }
    try state.historical_roots.ensureTotalCapacityPrecise(allocator, 16);
    for (0..16) |i| {
        state.historical_roots.appendAssumeCapacity(makeBytes32(@as(u64, i) + 20000));
    }
    state.eth1_data = makeEth1Data(0);
    try state.eth1_data_votes.ensureTotalCapacityPrecise(allocator, 16);
    for (0..16) |i| {
        state.eth1_data_votes.appendAssumeCapacity(makeEth1Data(@as(u64, i)));
    }
    state.eth1_deposit_index = 1000;
    try state.validators.ensureTotalCapacityPrecise(allocator, n_validators);
    try state.balances.ensureTotalCapacityPrecise(allocator, n_validators);
    for (0..n_validators) |i| {
        state.validators.appendAssumeCapacity(makeValidator(@as(u64, i)));
        state.balances.appendAssumeCapacity(32_000_000_000);
    }
    for (0..65536) |i| {
        state.randao_mixes[i] = makeBytes32(@as(u64, i) + 30000);
    }
    // slashings: all zero (default).
    try state.previous_epoch_attestations.ensureTotalCapacityPrecise(allocator, 16);
    try state.current_epoch_attestations.ensureTotalCapacityPrecise(allocator, 16);
    for (0..16) |i| {
        state.previous_epoch_attestations.appendAssumeCapacity(try makePendingAttestation(allocator, @as(u64, i)));
        state.current_epoch_attestations.appendAssumeCapacity(try makePendingAttestation(allocator, @as(u64, i) + 100));
    }
    try state.justification_bits.set(0, true);
    try state.justification_bits.set(1, true);
    state.previous_justified_checkpoint = makeCheckpoint(99);
    state.current_justified_checkpoint = makeCheckpoint(100);
    state.finalized_checkpoint = makeCheckpoint(98);
    return state;
}

const SerializeState = struct {
    state: *BeaconState.Type,
    pub fn run(self: *SerializeState, allocator: std.mem.Allocator) void {
        // Use malloc directly: zbench's passed allocator wraps for tracking.
        _ = allocator;
        const a = std.heap.c_allocator;
        const out = a.alloc(u8, BeaconState.serializedSize(self.state)) catch unreachable;
        defer a.free(out);
        _ = BeaconState.serializeIntoBytes(self.state, out);
    }
};

const SerializeStateNoAlloc = struct {
    state: *BeaconState.Type,
    out: []u8,
    pub fn run(self: *SerializeStateNoAlloc, allocator: std.mem.Allocator) void {
        _ = allocator;
        _ = BeaconState.serializeIntoBytes(self.state, self.out);
    }
};

const DeserializeState = struct {
    bytes: []const u8,
    pub fn run(self: *DeserializeState, allocator: std.mem.Allocator) void {
        _ = allocator;
        const a = std.heap.c_allocator;
        const out = a.create(BeaconState.Type) catch unreachable;
        out.* = BeaconState.default_value;
        BeaconState.deserializeFromBytes(a, self.bytes, out) catch unreachable;
        BeaconState.deinit(a, out);
        a.destroy(out);
    }
};

const DeserializeStateNoAlloc = struct {
    bytes: []const u8,
    out: *BeaconState.Type,
    pub fn run(self: *DeserializeStateNoAlloc, allocator: std.mem.Allocator) void {
        _ = allocator;
        // Lists in `out` retain capacity across runs: warm decode, no big allocs.
        BeaconState.deserializeFromBytes(std.heap.c_allocator, self.bytes, self.out) catch unreachable;
    }
};

const HashStateOneshot = struct {
    state: *BeaconState.Type,
    pub fn run(self: *HashStateOneshot, allocator: std.mem.Allocator) void {
        var out: [32]u8 = undefined;
        BeaconState.hashTreeRoot(allocator, self.state, &out) catch unreachable;
    }
};

pub fn main(init: std.process.Init) !void {
    // c_allocator = macOS system malloc — the same allocator Rust's Vec uses,
    // so alloc-variant numbers compare allocators-equal against libssz's
    // to_ssz()/from_ssz(). page_allocator/smp would re-fault the 150 MB buffer
    // every iteration and benchmark the VM system instead.
    const allocator = std.heap.c_allocator;
    const io = init.io;
    var bench = zbench.Benchmark.init(allocator, .{});
    defer bench.deinit();

    inline for ([_]usize{ 100_000, 1_000_000 }) |n| {
        const state = try makeBeaconState(allocator, n);
        const size = BeaconState.serializedSize(state);
        const buf = try allocator.alloc(u8, size);
        _ = BeaconState.serializeIntoBytes(state, buf);

        const label = std.fmt.comptimePrint("{d}", .{n});
        const serialize = SerializeState{ .state = state };
        try bench.addParam("encode/" ++ label, &serialize, .{});
        const serialize_prealloc = SerializeStateNoAlloc{ .state = state, .out = buf };
        try bench.addParam("encode prealloc/" ++ label, &serialize_prealloc, .{});
        const deserialize = DeserializeState{ .bytes = buf };
        try bench.addParam("decode/" ++ label, &deserialize, .{});
        const warm_out = try allocator.create(BeaconState.Type);
        warm_out.* = BeaconState.default_value;
        BeaconState.deserializeFromBytes(allocator, buf, warm_out) catch unreachable;
        const deserialize_warm = DeserializeStateNoAlloc{ .bytes = buf, .out = warm_out };
        try bench.addParam("decode warm/" ++ label, &deserialize_warm, .{});
        const hash_oneshot = HashStateOneshot{ .state = state };
        try bench.addParam("htr/" ++ label, &hash_oneshot, .{});
    }

    try bench.run(io, std.Io.File.stdout());
}
