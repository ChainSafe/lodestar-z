import assert from "node:assert/strict";
import {createNativeNetworkApplicationRuntime} from "../../src/network.js";
import {applicationConfig, localIntent} from "../utils/network.ts";
const rows = [];
for (const profile of ["small", "beaconNode"]) {
  const config = applicationConfig();
  config.profile = profile;
  if (profile === "beaconNode") config.resources = {
    bridgeBudgetBytes: 16 * 1024 * 1024, connectionCapacity: 256, dialingCapacity: 16,
    handshakingCapacity: 32, maxPeers: 210, minOutbound: 16, nativeBudgetBytes: 256 * 1024 * 1024,
    outboundReserve: 32, peerCapacity: 512, receiveBudgetBytes: 512 * 1024 * 1024, targetPeers: 200,
  };
  const runtime = createNativeNetworkApplicationRuntime(config, () => undefined);
  try {
    await runtime.ready;
    await runtime.applyIntent(localIntent(config), config.initialSlot);
    const before = runtime.diagnostics();
    assert.equal(before.gossip.capacity, profile === "small" ? 64 : 1024);
    assert.equal(before.liveBridgeRequestedBytes, before.bridgeRequestedBytes);
    await runtime.close();
    const after = runtime.diagnostics();
    assert.equal(after.liveBridgeRequestedBytes, after.ownerShellBytes + after.peerLaneBytes);
    assert.equal(after.liveNativeRequestedBytes, 0);
    assert.equal(after.gossip.occupied, 0);
    assert.equal(after.gossip.reservedBytes, 0);
    rows.push({profile, before, after});
  } finally { await runtime.close(); }
}
console.log(JSON.stringify({preset: process.env.LODESTAR_PRESET, rows}, (_, value) => typeof value === "bigint" ? value.toString() : value, 2));
