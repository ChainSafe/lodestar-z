const support = @import("../quic/test_support.zig");
const service_mod = @import("../service.zig");
const Engine = @import("../quic/Engine.zig");
const identify = @import("root.zig");

pub fn peerId() !@import("../wire/peer_id.zig").PeerId {
    const key = try @import("../wire/keys.zig").KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{1}));
    return .fromPublicKey(&key.publicKey());
}

pub fn step(pair: *support.Pair, service: *service_mod.Service, server: bool, results: []identify.Handler.Result) usize {
    const engine = if (server) &pair.server else &pair.client;
    var events: [64]Engine.Event = undefined;
    return service.process(engine, pair.events(engine, &events), pair.now, .{ .identify = results }).identify;
}

pub fn serviceOptions(agent: []const u8) !service_mod.Options {
    return .{ .reqresp = .{ .forks = &.{}, .admission = try @import("../reqresp/ReqResp.zig").Options.Admission.defaults(&@import("../reqresp/policy_fixture.zig").config(), 128, 128, 64) }, .gossipsub = .{ .random_seed = 1 }, .identify = .{ .agent = agent, .inbound_max = 1, .outbound_max = 1 } };
}
