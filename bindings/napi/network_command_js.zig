//! Command results for JavaScript: a completed command's record, whose result copies the command's typed store before
//! the exchange that delivers it retires the cell.
const napi = @import("zapi:zapi").napi;
const Value = napi.Value;
const r = @import("network_runtime.zig");
const commands = @import("network_commands.zig");
const projection = @import("network_peer_projection.zig");
const js = @import("network_js.zig");
const Runtime = r.Runtime;

/// A completed command's record: the result its promise resolves with, or the error it rejects with.
pub fn completion(env: napi.Env, runtime: *Runtime, token: commands.Token) !Value {
    const cell = runtime.table.get(token);
    const object = try env.createObject();
    try object.setNamedProperty("family", try env.createStringUtf8("command"));
    try object.setNamedProperty("handle", try js.handle(env, token.index, token.generation));
    try object.setNamedProperty("kind", try env.createStringUtf8(@tagName(cell.input.command)));
    if (cell.failure) |err| {
        try object.setNamedProperty("error", try js.settled(env, js.errorValue(env, @errorName(err))));
    } else try object.setNamedProperty("value", try result(env, runtime, token.index));
    return object;
}

fn result(env: napi.Env, runtime: *Runtime, index: usize) !Value {
    const operation = &runtime.table.cells[index];
    const store = runtime.table.cells[index].store;
    const object = switch (operation.input.command) {
        .getGossipDiagnostics => try @import("network_gossip_diagnostics.zig").copy(env, &runtime.stores.?.gossip_diagnostics[store.?]),
        .getIdentity => try identity(env, &operation.identity),
        .applyIntent, .getPeers, .getDirectPeers, .getRememberedPeers => try env.createObject(),
        .removeDirectPeer => return env.getBoolean(operation.boolean),
        else => return env.getUndefined(),
    };
    try object.setNamedProperty("ownerSequence", try env.createBigintUint64(operation.sequence));
    switch (operation.input.command) {
        .applyIntent => {
            try object.setNamedProperty("changed", try env.getBoolean(operation.boolean));
            try object.setNamedProperty("slot", try env.createBigintUint64(operation.input.slot));
        },
        .getPeers => {
            const peers = try env.createArrayWithLength(operation.count);
            for (runtime.stores.?.snapshots[store.?][0..operation.count], 0..) |*row, i| try peers.setElement(@intCast(i), try projection.state(env, row));
            try object.setNamedProperty("peers", peers);
            try object.setNamedProperty("occupiedCount", try env.createDouble(@floatFromInt(operation.count)));
            try object.setNamedProperty("capacity", try env.createUint32(runtime.peer_capacity));
            const counts = try env.createObject();
            try counts.setNamedProperty("connected", try env.createUint32(operation.counts.connected));
            try counts.setNamedProperty("relevant", try env.createUint32(operation.counts.relevant));
            try counts.setNamedProperty("outboundRelevant", try env.createUint32(operation.counts.outbound_relevant));
            try object.setNamedProperty("counts", counts);
        },
        .getDirectPeers => {
            const identities = try env.createArrayWithLength(operation.count);
            for (runtime.stores.?.direct[store.?][0..operation.count], 0..) |*peer, i| try identities.setElement(@intCast(i), try js.peerIdValue(env, peer));
            try object.setNamedProperty("identities", identities);
        },
        .getRememberedPeers => {
            const page = &runtime.stores.?.remembered[store.?];
            try object.setNamedProperty("genesisValidatorsRoot", try js.bytes(env, &page.genesis_root));
            const peers = try env.createArrayWithLength(operation.count);
            for (page.records[0..operation.count], 0..) |*record, i| {
                const entry = try env.createObject();
                try entry.setNamedProperty("peerId", try js.peerIdValue(env, &record.peer));
                try entry.setNamedProperty("endpoint", try js.endpoint(env, record.address));
                try entry.setNamedProperty("qualifiedAtUnixS", try env.createDouble(@floatFromInt(record.qualified_at_s)));
                try peers.setElement(@intCast(i), entry);
            }
            try object.setNamedProperty("peers", peers);
        },
        else => {},
    }
    return object;
}

/// A runtime identity snapshot, as initialization and getIdentity return it.
pub fn identity(env: napi.Env, value: *const r.Identity) !Value {
    const object = try env.createObject();
    try object.setNamedProperty("peerId", try js.peerIdValue(env, &value.peer));
    try object.setNamedProperty("metadata", try projection.metadata(env, &value.metadata));
    const endpoints = try env.createArrayWithLength(@intFromBool(value.endpoints[0] != null) + @as(u32, @intFromBool(value.endpoints[1] != null)));
    var endpoint_index: u32 = 0;
    for (value.endpoints) |address| if (address) |bound| {
        try endpoints.setElement(endpoint_index, try js.endpoint(env, bound));
        endpoint_index += 1;
    };
    try object.setNamedProperty("localEndpoints", endpoints);
    try object.setNamedProperty("localEndpoint", try js.endpoint(env, value.endpoints[0] orelse value.endpoints[1].?));
    try object.setNamedProperty("localMultiaddr", try js.bytes(env, value.multiaddr[0..value.multiaddr_len]));
    try object.setNamedProperty("localEnr", if (value.enr_len == 0) try env.getNull() else try js.bytes(env, value.enr[0..value.enr_len]));
    return object;
}
