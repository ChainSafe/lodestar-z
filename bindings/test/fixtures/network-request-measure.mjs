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
  await runtime.ready;
  await runtime.applyIntent(localIntent(config), config.initialSlot);
  const before = runtime.diagnostics();
  await runtime.close();
  const after = runtime.diagnostics();
  assert.equal(after.liveBridgeRequestedBytes, after.ownerShellBytes + after.peerLaneBytes);
  assert.equal(after.requests.reservedBytes, 0);
  rows.push({profile, before, after});
}
console.log(JSON.stringify({preset: process.env.LODESTAR_PRESET ?? "mainnet", rows}, (_, value) => typeof value === "bigint" ? `${value}` : value, 2));

if (process.env.LODESTAR_Z_NETWORK_STOCK_HOST) {
  const {Child} = await import("../../../test/interop/child.mjs");
  const peer = new Child("measure-stock", process.execPath, ["test/interop/request_responder.mjs", process.env.LODESTAR_Z_NETWORK_STOCK_HOST]);
  let runtime;
  try {
    const remote = await peer.command("ready");
    const config = applicationConfig();
    config.resources.bridgeBudgetBytes = 128 * 1024 * 1024;
    runtime = createNativeNetworkApplicationRuntime(config, () => undefined);
    await runtime.ready;
    await runtime.applyIntent(localIntent(config), config.initialSlot);
    const id = Uint8Array.from(Buffer.from(remote.peer, "hex"));
    await runtime.connect(id, [{family: 4, address: Uint8Array.of(127, 0, 0, 1), port: Number(remote.address.split("/")[4])}], 5000n);
    await peer.command("scenario", {scenario: "hold"});
    const held = runtime.request(id, "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy", new Uint8Array(32));
    const heldPull = held.next().catch((error) => error.code);
    const pending = runtime.diagnostics();
    await held.return();
    assert.equal(await heldPull, "NetworkRequestFailed");
    await peer.command("scenario", {scenario: "chunks"});
    const stream = runtime.request(id, "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy", new Uint8Array(64));
    const admitted = runtime.diagnostics();
    const first = stream.next();
    await first;
    const copied = runtime.diagnostics();
    assert.equal(admitted.requests.reservedBytes, 64 + 2 * 10 * 1024 * 1024);
    assert.equal(admitted.requests.inputBytes, 64);
    assert.equal(admitted.requests.sinkBytes, 10 * 1024 * 1024);
    assert.equal(pending.requests.pendingPulls, 1);
    assert.equal(copied.requests.chunksCopied, 1n);
    assert.equal(copied.requests.bytesCopied, 4000n);
    await runtime.close();
    const closed = runtime.diagnostics();
    assert.equal(closed.requests.reservedBytes, 0);
    assert.equal(closed.requests.terminalCells, 1);
    await stream.return();
    const retired = runtime.diagnostics();
    assert.equal(retired.requests.occupied, 0);
    assert.equal(retired.liveBridgeRequestedBytes, retired.ownerShellBytes + retired.peerLaneBytes);
    console.log(JSON.stringify({payload: {admitted, pending, copied, closed, retired}}, (_, value) => typeof value === "bigint" ? `${value}` : value, 2));
  } finally {
    try { await runtime?.close(); } finally { await peer.stop(); }
  }
}
