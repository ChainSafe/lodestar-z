//! Integration test: connect to Ethereum mainnet discv5 bootnodes.
//!
//! This test:
//! 1. Generates a local keypair
//! 2. Creates our ENR
//! 3. Opens a UDP socket via Linux syscalls (std.net removed in 0.16)
//! 4. Sends a PING to a bootnode via real UDP
//! 5. Handles the WHOAREYOU response (handshake challenge)
//! 6. Completes the handshake and gets a PONG
//! 7. Sends FINDNODE to discover more peers
//! 8. Receives NODES responses
//!
//! Run with: zig build run:discv5-integration-test

const std = @import("std");
const linux = std.os.linux;

const packet = @import("packet.zig");
const session_mod = @import("session.zig");
const messages = @import("messages.zig");
const enr_mod = @import("enr.zig");
const secp = @import("secp256k1.zig");
const rlp = @import("rlp.zig");

const Allocator = std.mem.Allocator;
const Keccak256 = std.crypto.hash.sha3.Keccak256;

// ============================================================
// Raw Linux UDP helpers
// ============================================================

/// sockaddr_in (IPv4)
const SockaddrIn = extern struct {
    family: u16 = linux.AF.INET,
    port: u16 = 0, // big-endian
    addr: u32 = 0, // big-endian
    zero: [8]u8 = [_]u8{0} ** 8,
};

/// timeval for SO_RCVTIMEO
const Timeval = extern struct {
    sec: i64,
    usec: i64,
};

fn htons(x: u16) u16 {
    return (x >> 8) | (x << 8);
}

fn htonl(x: u32) u32 {
    const b0: u32 = x & 0xff;
    const b1: u32 = (x >> 8) & 0xff;
    const b2: u32 = (x >> 16) & 0xff;
    const b3: u32 = (x >> 24) & 0xff;
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
}

fn ipToU32(ip: [4]u8) u32 {
    return htonl((@as(u32, ip[0]) << 24) | (@as(u32, ip[1]) << 16) | (@as(u32, ip[2]) << 8) | @as(u32, ip[3]));
}

fn udpSocket() !i32 {
    const r = linux.syscall3(.socket, linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    const rc: isize = @bitCast(r);
    if (rc < 0) return error.SocketFailed;
    return @intCast(r);
}

fn udpBind(sock: i32) !u16 {
    var sa = SockaddrIn{};
    const bind_rc: isize = @bitCast(linux.syscall3(.bind, @intCast(sock), @intFromPtr(&sa), @sizeOf(SockaddrIn)));
    if (bind_rc != 0) return error.BindFailed;

    // getsockname to find the assigned port
    var sa_len: u32 = @sizeOf(SockaddrIn);
    const gn_rc: isize = @bitCast(linux.syscall3(.getsockname, @intCast(sock), @intFromPtr(&sa), @intFromPtr(&sa_len)));
    if (gn_rc != 0) return error.GetSocknameFailed;
    return htons(sa.port);
}

fn setRecvTimeout(sock: i32, ms: u32) void {
    const tv = Timeval{ .sec = @intCast(ms / 1000), .usec = @intCast((ms % 1000) * 1000) };
    _ = linux.syscall5(.setsockopt, @intCast(sock), linux.SOL.SOCKET, linux.SO.RCVTIMEO, @intFromPtr(&tv), @sizeOf(Timeval));
}

fn udpSend(sock: i32, dest_ip: [4]u8, dest_port: u16, data: []const u8) !void {
    var dest = SockaddrIn{
        .addr = ipToU32(dest_ip),
        .port = htons(dest_port),
    };
    const rc: isize = @bitCast(linux.syscall6(
        .sendto,
        @intCast(sock),
        @intFromPtr(data.ptr),
        data.len,
        0,
        @intFromPtr(&dest),
        @sizeOf(SockaddrIn),
    ));
    if (rc < 0) return error.SendFailed;
}

const RecvResult = struct {
    n: usize,
};

fn udpRecv(sock: i32, buf: []u8) !RecvResult {
    const rc: isize = @bitCast(linux.syscall6(
        .recvfrom,
        @intCast(sock),
        @intFromPtr(buf.ptr),
        buf.len,
        0,
        0, // null src_addr
        0, // null addrlen
    ));
    if (rc < 0) {
        if (rc == -@as(isize, @intFromEnum(linux.E.AGAIN)) or
            rc == -@as(isize, @intFromEnum(linux.E.AGAIN)))
        {
            return error.Timeout;
        }
        return error.RecvFailed;
    }
    return RecvResult{ .n = @intCast(rc) };
}

// ============================================================
// Bootnode ENR strings
// ============================================================

const BOOTNODES = [_]struct { name: []const u8, enr: []const u8 }{
    .{
        .name = "Teku",
        .enr = "enr:-KG4QNTx85fjxABbSq_Rta9wy56nQ1fHK0PewJbGjLm1M4bMGx5-3Qq4ZX2-iFJ0pys_O90sVXNNOxp2E7afBsGsBrgDhGV0aDKQu6TalgMAAAD__________4JpZIJ2NIJpcIQEnfA2iXNlY3AyNTZrMaECGXWQ-rQ2KZKRH1aOW4IlPDBkY4XDphxg9pxKytFCkayDdGNwgiMog3VkcIIjKA",
    },
    .{
        .name = "Prysm",
        .enr = "enr:-Ku4QImhMc1z8yCiNJ1TyUxdcfNucje3BGwEHzodEZUan8PherEo4sF7pPHPSIB1NNuSg5fZy7qFsjmUKs2ea1Whi0EBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQOVphkDqal4QzPMksc5wnpuC3gvSC8AfbFOnZY_On34wIN1ZHCCIyg",
    },
    .{
        .name = "Lighthouse",
        .enr = "enr:-Le4QPUXJS2BTORXxyx2Ia-9ae4YqA_JWX3ssj4E_J-3z1A-HmFGrU8BpvpqhNabayXeOZ2Nq_sbeDgtzMJpLLnXFgAChGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISsaa0Zg2lwNpAkAIkHAAAAAPA8kv_-awoTiXNlY3AyNTZrMaEDHAD2JKYevx89W0CcFJFiskdcEzkH_Wdv9iW42qLK79ODdWRwgiMohHVkcDaCI4I",
    },
};

// ============================================================
// ENR parsing
// ============================================================

fn decodeEnrString(alloc: Allocator, enr_str: []const u8) ![]u8 {
    var s: []const u8 = enr_str;
    if (std.mem.startsWith(u8, s, "enr:")) s = s[4..];
    // Note: do NOT strip the leading "-" — it is a valid base64url character.

    const decoded_len = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(s) catch return error.InvalidEnr;
    const buf = try alloc.alloc(u8, decoded_len);
    errdefer alloc.free(buf);
    std.base64.url_safe_no_pad.Decoder.decode(buf, s) catch return error.InvalidEnr;
    return buf;
}

const BootnodeInfo = struct {
    name: []const u8,
    node_id: [32]u8,
    pubkey: [33]u8,
    ip: [4]u8,
    port: u16,
};

fn parseBootnode(alloc: Allocator, name: []const u8, enr_str: []const u8) !BootnodeInfo {
    const raw = try decodeEnrString(alloc, enr_str);
    defer alloc.free(raw);

    var parsed_enr = try enr_mod.decode(alloc, raw);
    defer parsed_enr.deinit();

    const pubkey = parsed_enr.pubkey orelse return error.NoPubkey;
    const ip = parsed_enr.ip orelse return error.NoIp;
    const port = parsed_enr.udp orelse return error.NoPort;
    const node_id = parsed_enr.nodeId() orelse return error.NoNodeId;

    return BootnodeInfo{
        .name = name,
        .node_id = node_id,
        .pubkey = pubkey,
        .ip = ip,
        .port = port,
    };
}

// ============================================================
// Session state
// ============================================================

const HandshakeState = struct {
    challenge_data: []u8,
    id_nonce: [16]u8,
    enr_seq: u64,
    request_nonce: [12]u8,
    initiator_key: [16]u8,
    recipient_key: [16]u8,
    eph_seckey: [32]u8,
    eph_pubkey: [33]u8,
};

// ============================================================
// Packet helpers
// ============================================================

fn buildHeaderRaw(
    alloc: Allocator,
    flag: u8,
    nonce: *const [12]u8,
    authdata: []const u8,
) ![]u8 {
    const total = packet.STATIC_HEADER_SIZE + authdata.len;
    const buf = try alloc.alloc(u8, total);
    @memcpy(buf[0..6], packet.PROTOCOL_ID);
    std.mem.writeInt(u16, buf[6..8], packet.VERSION, .big);
    buf[8] = flag;
    @memcpy(buf[9..21], nonce);
    std.mem.writeInt(u16, buf[21..23], @intCast(authdata.len), .big);
    @memcpy(buf[packet.STATIC_HEADER_SIZE..], authdata);
    return buf;
}

fn newRng() std.Random.DefaultPrng {
    var seed: u64 = 0;
    // Use getrandom syscall for entropy
    const rc = linux.syscall3(.getrandom, @intFromPtr(&seed), @sizeOf(u64), 0);
    if (@as(isize, @bitCast(rc)) < 0) {
        // Fallback: mix stack address and counter
        var dummy: u8 = 0;
        seed = @intFromPtr(&dummy);
    }
    return std.Random.DefaultPrng.init(seed);
}

/// Send an ordinary PING (with fake key, will trigger WHOAREYOU)
fn sendOrdinaryPing(
    alloc: Allocator,
    sock: i32,
    dest: *const BootnodeInfo,
    local_node_id: *const [32]u8,
    req_id: *const messages.ReqId,
    out_nonce: *[12]u8,
    out_masking_iv: *[16]u8,
) !void {
    var rng = newRng();
    const random = rng.random();

    random.bytes(out_nonce);
    random.bytes(out_masking_iv);

    const ping = messages.Ping{ .req_id = req_id.*, .enr_seq = 0 };
    const ping_bytes = try ping.encode(alloc);
    defer alloc.free(ping_bytes);

    const authdata: []const u8 = local_node_id;

    var fake_key: [16]u8 = undefined;
    random.bytes(&fake_key);

    const header_raw = try buildHeaderRaw(alloc, packet.FLAG_MESSAGE, out_nonce, authdata);
    defer alloc.free(header_raw);

    const ct = try packet.encryptMessage(alloc, &fake_key, out_nonce, ping_bytes, out_masking_iv, header_raw);
    defer alloc.free(ct);

    const pkt = try packet.encode(alloc, out_masking_iv, &dest.node_id, packet.FLAG_MESSAGE, out_nonce, authdata, ct);
    defer alloc.free(pkt);

    try udpSend(sock, dest.ip, dest.port, pkt);
}

/// Parse WHOAREYOU packet
fn parseWhoareyou(
    alloc: Allocator,
    raw: []const u8,
    local_node_id: *const [32]u8,
    request_nonce: *const [12]u8,
) !HandshakeState {
    var parsed = try packet.decode(alloc, raw, local_node_id);
    defer parsed.deinit();

    if (parsed.static_header.flag != packet.FLAG_WHOAREYOU) return error.NotWhoareyou;

    const authdata = parsed.authdata_raw;
    if (authdata.len < 24) return error.InvalidWhoareyou;

    const id_nonce = authdata[0..16].*;
    const enr_seq = std.mem.readInt(u64, authdata[16..24], .big);

    // challenge-data = masking-iv (16) || unmasked-header-raw (static=23 + authdata_size bytes)
    // Per discv5 spec: challenge-data = masking-iv || header-raw (plaintext, not masked wire bytes).
    // packet.decode gives us `masking_iv` and `header_raw` (already decrypted).
    const challenge_data = try alloc.alloc(u8, 16 + parsed.header_raw.len);
    @memcpy(challenge_data[0..16], &parsed.masking_iv);
    @memcpy(challenge_data[16..], parsed.header_raw);

    return HandshakeState{
        .challenge_data = challenge_data,
        .id_nonce = id_nonce,
        .enr_seq = enr_seq,
        .request_nonce = request_nonce.*,
        .initiator_key = undefined,
        .recipient_key = undefined,
        .eph_seckey = undefined,
        .eph_pubkey = undefined,
    };
}

/// Send handshake PING
fn sendHandshakePing(
    alloc: Allocator,
    sock: i32,
    dest: *const BootnodeInfo,
    local_node_id: *const [32]u8,
    local_secret_key: *const [32]u8,
    local_enr_bytes: []const u8,
    hs: *HandshakeState,
    req_id: *const messages.ReqId,
    out_nonce: *[12]u8,
    out_masking_iv: *[16]u8,
) !void {
    var rng = newRng();
    const random = rng.random();

    // Generate ephemeral keypair
    var eph_seckey: [32]u8 = undefined;
    while (true) {
        random.bytes(&eph_seckey);
        hs.eph_pubkey = secp.pubkeyFromSecret(&eph_seckey) catch continue;
        break;
    }
    hs.eph_seckey = eph_seckey;

    // Derive session keys
    const keys = try session_mod.deriveKeys(
        &hs.eph_seckey,
        &dest.pubkey,
        local_node_id,
        &dest.node_id,
        hs.challenge_data,
    );
    hs.initiator_key = keys.initiator_key;
    hs.recipient_key = keys.recipient_key;

    // Compute id-signature
    const id_sig = try session_mod.signIdNonce(
        local_secret_key,
        hs.challenge_data,
        &hs.eph_pubkey,
        &dest.node_id,
    );

    random.bytes(out_nonce);
    random.bytes(out_masking_iv);

    // authdata: src-id(32) | sig-size(1) | eph-key-size(1) | id-sig(64) | eph-pubkey(33) | [enr]
    const include_enr = hs.enr_seq == 0;
    const enr_part: []const u8 = if (include_enr) local_enr_bytes else &[_]u8{};
    const authdata_len = 32 + 1 + 1 + 64 + 33 + enr_part.len;
    const authdata = try alloc.alloc(u8, authdata_len);
    defer alloc.free(authdata);

    @memcpy(authdata[0..32], local_node_id);
    authdata[32] = 64;
    authdata[33] = 33;
    @memcpy(authdata[34..98], &id_sig);
    @memcpy(authdata[98..131], &hs.eph_pubkey);
    if (enr_part.len > 0) @memcpy(authdata[131..], enr_part);

    const ping = messages.Ping{ .req_id = req_id.*, .enr_seq = 1 };
    const ping_bytes = try ping.encode(alloc);
    defer alloc.free(ping_bytes);

    const header_raw = try buildHeaderRaw(alloc, packet.FLAG_HANDSHAKE, out_nonce, authdata);
    defer alloc.free(header_raw);

    const ct = try packet.encryptMessage(alloc, &hs.initiator_key, out_nonce, ping_bytes, out_masking_iv, header_raw);
    defer alloc.free(ct);

    const pkt = try packet.encode(alloc, out_masking_iv, &dest.node_id, packet.FLAG_HANDSHAKE, out_nonce, authdata, ct);
    defer alloc.free(pkt);

    try udpSend(sock, dest.ip, dest.port, pkt);
}

/// Send FINDNODE
fn sendFindnode(
    alloc: Allocator,
    sock: i32,
    dest: *const BootnodeInfo,
    local_node_id: *const [32]u8,
    hs: *const HandshakeState,
    req_id: *const messages.ReqId,
) !void {
    var rng = newRng();
    const random = rng.random();

    var nonce: [12]u8 = undefined;
    var masking_iv: [16]u8 = undefined;
    random.bytes(&nonce);
    random.bytes(&masking_iv);

    const distances = [_]u16{ 256, 255, 254 };
    const fn_msg = messages.FindNode{ .req_id = req_id.*, .distances = &distances };
    const fn_bytes = try fn_msg.encode(alloc);
    defer alloc.free(fn_bytes);

    const authdata: []const u8 = local_node_id;
    const header_raw = try buildHeaderRaw(alloc, packet.FLAG_MESSAGE, &nonce, authdata);
    defer alloc.free(header_raw);

    const ct = try packet.encryptMessage(alloc, &hs.initiator_key, &nonce, fn_bytes, &masking_iv, header_raw);
    defer alloc.free(ct);

    const pkt = try packet.encode(alloc, &masking_iv, &dest.node_id, packet.FLAG_MESSAGE, &nonce, authdata, ct);
    defer alloc.free(pkt);

    try udpSend(sock, dest.ip, dest.port, pkt);
}

// ============================================================
// Main
// ============================================================

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    std.debug.print("\n=== discv5 mainnet bootnode integration test ===\n\n", .{});

    // --- Generate local identity ---
    var rng = newRng();
    const random = rng.random();
    var local_seckey: [32]u8 = undefined;
    var local_pubkey: [33]u8 = undefined;
    while (true) {
        random.bytes(&local_seckey);
        local_pubkey = secp.pubkeyFromSecret(&local_seckey) catch continue;
        break;
    }
    const local_node_id = enr_mod.nodeIdFromCompressedPubkey(&local_pubkey);
    std.debug.print("Local node-id: {s}\n", .{&std.fmt.bytesToHex(local_node_id, .lower)});

    // Build a minimal local ENR
    var enr_builder = enr_mod.Builder.init(alloc, local_seckey, 1);
    const local_enr_bytes = try enr_builder.encode();
    defer alloc.free(local_enr_bytes);

    // --- Open UDP socket ---
    const sock = try udpSocket();
    defer _ = linux.close(sock);

    const local_port = try udpBind(sock);
    std.debug.print("Listening on UDP port {d}\n\n", .{local_port});

    setRecvTimeout(sock, 10_000);

    // --- Try each bootnode ---
    var total_pongs: usize = 0;
    var total_nodes: usize = 0;
    var recv_buf: [1280]u8 = undefined;

    for (BOOTNODES) |bn| {
        std.debug.print("--- Trying bootnode: {s} ---\n", .{bn.name});

        const bootnode = parseBootnode(alloc, bn.name, bn.enr) catch |err| {
            std.debug.print("  Failed to parse ENR: {s}\n", .{@errorName(err)});
            continue;
        };

        std.debug.print("  Node-ID: {s}\n", .{&std.fmt.bytesToHex(bootnode.node_id, .lower)});
        std.debug.print("  Endpoint: {d}.{d}.{d}.{d}:{d}\n", .{
            bootnode.ip[0], bootnode.ip[1], bootnode.ip[2], bootnode.ip[3], bootnode.port,
        });

        // Step 1: Send ordinary PING (triggers WHOAREYOU)
        var ping_nonce: [12]u8 = undefined;
        var ping_masking_iv: [16]u8 = undefined;
        const req_id_1 = messages.ReqId{ .bytes = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 1 }, .len = 4 };
        sendOrdinaryPing(alloc, sock, &bootnode, &local_node_id, &req_id_1, &ping_nonce, &ping_masking_iv) catch |err| {
            std.debug.print("  Send PING failed: {s}\n", .{@errorName(err)});
            continue;
        };
        std.debug.print("  Sent PING (expecting WHOAREYOU)\n", .{});

        // Step 2: Wait for WHOAREYOU
        const r1 = udpRecv(sock, &recv_buf) catch |err| {
            std.debug.print("  Waiting for WHOAREYOU: {s}\n", .{@errorName(err)});
            continue;
        };

        var hs = parseWhoareyou(alloc, recv_buf[0..r1.n], &local_node_id, &ping_nonce) catch |err| {
            std.debug.print("  Failed to parse WHOAREYOU: {s}\n", .{@errorName(err)});
            continue;
        };
        defer alloc.free(hs.challenge_data);

        std.debug.print("  Received WHOAREYOU (enr-seq={d})\n", .{hs.enr_seq});

        // Step 3: Send handshake PING
        var hs_nonce: [12]u8 = undefined;
        var hs_masking_iv: [16]u8 = undefined;
        const req_id_2 = messages.ReqId{ .bytes = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 2 }, .len = 4 };
        sendHandshakePing(alloc, sock, &bootnode, &local_node_id, &local_seckey, local_enr_bytes, &hs, &req_id_2, &hs_nonce, &hs_masking_iv) catch |err| {
            std.debug.print("  Send handshake PING failed: {s}\n", .{@errorName(err)});
            continue;
        };
        std.debug.print("  Sent handshake PING\n", .{});

        // Step 4: Wait for PONG
        const r2 = udpRecv(sock, &recv_buf) catch |err| {
            std.debug.print("  Waiting for PONG: {s}\n", .{@errorName(err)});
            continue;
        };

        var resp_parsed = packet.decode(alloc, recv_buf[0..r2.n], &local_node_id) catch |err| {
            std.debug.print("  Failed to decode response: {s}\n", .{@errorName(err)});
            continue;
        };
        defer resp_parsed.deinit();

        if (resp_parsed.static_header.flag != packet.FLAG_MESSAGE) {
            std.debug.print("  Expected MESSAGE, got flag={d}\n", .{resp_parsed.static_header.flag});
            continue;
        }

        const pt = packet.decryptMessage(
            alloc,
            &hs.recipient_key,
            &resp_parsed.static_header.nonce,
            resp_parsed.message_ciphertext,
            &resp_parsed.masking_iv,
            resp_parsed.header_raw,
        ) catch |err| {
            std.debug.print("  Decryption failed: {s}\n", .{@errorName(err)});
            continue;
        };
        defer alloc.free(pt);

        if (pt.len == 0) {
            std.debug.print("  Empty plaintext\n", .{});
            continue;
        }

        switch (pt[0]) {
            messages.MSG_PONG => {
                const pong = messages.Pong.decode(pt) catch |err| {
                    std.debug.print("  Failed to decode PONG: {s}\n", .{@errorName(err)});
                    continue;
                };
                switch (pong.recipient_ip) {
                    .ip4 => |ip4| std.debug.print(
                        "  ✓ PONG! External IP: {d}.{d}.{d}.{d}:{d}  (bootnode enr-seq={d})\n",
                        .{ ip4[0], ip4[1], ip4[2], ip4[3], pong.recipient_port, pong.enr_seq },
                    ),
                    .ip6 => |ip6| std.debug.print(
                        "  ✓ PONG! External IP: [{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}]:{d}  (bootnode enr-seq={d})\n",
                        .{
                            ip6[0],              ip6[1],       ip6[2],  ip6[3],
                            ip6[4],              ip6[5],       ip6[6],  ip6[7],
                            ip6[8],              ip6[9],       ip6[10], ip6[11],
                            ip6[12],             ip6[13],      ip6[14], ip6[15],
                            pong.recipient_port, pong.enr_seq,
                        },
                    ),
                }
                total_pongs += 1;

                // Step 5: Send FINDNODE
                const req_id_3 = messages.ReqId{ .bytes = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 3 }, .len = 4 };
                sendFindnode(alloc, sock, &bootnode, &local_node_id, &hs, &req_id_3) catch |err| {
                    std.debug.print("  Send FINDNODE failed: {s}\n", .{@errorName(err)});
                    continue;
                };
                std.debug.print("  Sent FINDNODE (distances=[256,255,254])\n", .{});

                // Step 6: Collect NODES responses
                var nodes_received: usize = 0;
                var total_expected: u64 = 1;

                while (nodes_received < total_expected) {
                    const r3 = udpRecv(sock, &recv_buf) catch |err| {
                        std.debug.print("  Waiting for NODES: {s}\n", .{@errorName(err)});
                        break;
                    };

                    var nodes_parsed = packet.decode(alloc, recv_buf[0..r3.n], &local_node_id) catch break;
                    defer nodes_parsed.deinit();

                    if (nodes_parsed.static_header.flag != packet.FLAG_MESSAGE) break;

                    const nodes_pt = packet.decryptMessage(
                        alloc,
                        &hs.recipient_key,
                        &nodes_parsed.static_header.nonce,
                        nodes_parsed.message_ciphertext,
                        &nodes_parsed.masking_iv,
                        nodes_parsed.header_raw,
                    ) catch break;
                    defer alloc.free(nodes_pt);

                    if (nodes_pt.len == 0 or nodes_pt[0] != messages.MSG_NODES) break;

                    // Parse NODES: type(1) | RLP([req-id, total, [enr...]])
                    // Each ENR in the list is an RLP *list* (not bytes), use skipItem
                    var r = rlp.Reader.init(nodes_pt[1..]);
                    var list = r.readList() catch break;
                    _ = list.readBytes() catch break; // req-id
                    total_expected = list.readUint64() catch break;
                    nodes_received += 1;

                    var enr_list = list.readList() catch break;
                    var enr_count: usize = 0;
                    while (!enr_list.atEnd()) {
                        enr_list.skipItem() catch break;
                        enr_count += 1;
                    }
                    total_nodes += enr_count;
                    std.debug.print("  NODES {d}/{d}: {d} ENRs\n", .{ nodes_received, total_expected, enr_count });
                }
            },
            messages.MSG_PING => {
                std.debug.print("  Got PING (unexpected)\n", .{});
            },
            else => {
                std.debug.print("  Unexpected msg type: 0x{x}\n", .{pt[0]});
            },
        }

        std.debug.print("\n", .{});
    }

    // --- Summary ---
    std.debug.print("=== Results ===\n", .{});
    std.debug.print("PONGs received: {d}/3\n", .{total_pongs});
    std.debug.print("Total ENRs discovered: {d}\n", .{total_nodes});
    if (total_pongs > 0) {
        std.debug.print("✓ Integration test PASSED\n", .{});
    } else {
        std.debug.print("✗ Integration test FAILED — no PONGs received\n", .{});
        std.process.exit(1);
    }
}
