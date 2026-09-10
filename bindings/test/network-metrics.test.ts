import {setTimeout as delay} from "node:timers/promises";
import {expect, test, vi} from "vitest";
import {createNativeNetworkRuntime} from "../src/network.js";
import {networkConfig} from "./utils/network.js";
import {BLOCKS, incomingPair, takeIncoming} from "./utils/network-incoming.js";

function samples(text: string): Map<string, number> {
  expect(Buffer.byteLength(text)).toBeLessThanOrEqual(512 * 1024);
  expect(text.endsWith("\n")).toBe(true);
  const result = new Map<string, number>();
  const families = new Set<string>();
  for (const line of text.trimEnd().split("\n")) {
    if (line.startsWith("# TYPE ")) {
      const name = line.split(" ")[2];
      expect(families.has(name)).toBe(false);
      families.add(name);
    }
    if (line.startsWith("#")) continue;
    const match = /^([a-zA-Z_:][a-zA-Z_0-9:]*(?:\{[^\n]*\})?) (-?\d+(?:\.\d+)?(?:e[+-]?\d+)?)$/.exec(line);
    expect(match, line).not.toBeNull();
    if (!match) throw Error("Malformed metric");
    expect(result.has(match[1]), match[1]).toBe(false);
    result.set(match[1], Number(match[2]));
  }
  return result;
}

test("metrics are available through startup and remain readable after close", async () => {
  const runtime = createNativeNetworkRuntime(networkConfig(), () => undefined);
  try {
    expect(samples(runtime.getMetrics()).get("libp2p_peers")).toBe(0);
    expect(samples(runtime.getMetrics()).get("lodestar_peer_connection_seconds_count")).toBe(0);
    await runtime.ready;
    await vi.waitFor(() => expect(samples(runtime.getMetrics()).get("lodestar_native_network_running")).toBe(1));
    const metrics = samples(runtime.getMetrics());
    for (const kind of ["subscription", "message", "control", "ihave", "iwant", "graft", "prune", "idontwant"]) {
      expect(metrics.get(`gossipsub_rpc_sent_${kind}_total`)).toBe(0);
    }
    for (const stat of ["avg", "min", "max"]) {
      expect(metrics.get(`gossipsub_score_${stat}`)).toBe(0);
      expect(metrics.get(`gossipsub_score_per_mesh_${stat}{topic="beacon_block"}`)).toBe(0);
      for (const p of ["p1", "p2", "p3", "p3b", "p4"]) {
        expect(metrics.get(`gossipsub_score_weights_${stat}{topic="beacon_block",p="${p}"}`)).toBe(0);
      }
      for (const p of ["p5", "p6", "p7"]) {
        expect(metrics.get(`gossipsub_score_weights_${stat}{topic="",p="${p}"}`)).toBe(0);
      }
    }
    expect(metrics.get('gossipsub_peers_by_score_threshold_count{threshold="mesh"}')).toBe(0);
    expect(metrics.has("gossipsub_score_fn_calls_total")).toBe(true);
    expect(metrics.has("gossipsub_score_fn_runs_total")).toBe(true);
    expect(metrics.has("gossipsub_score_cache_delta_count")).toBe(true);
    for (const penalty of ["graft_backoff", "broken_promise", "message_deficit", "invalid_message"]) {
      expect(metrics.get(`gossipsub_scoring_penalties_total{penalty="${penalty}"}`)).toBe(0);
    }
    expect(
      samples(runtime.getMetrics()).get('lodestar_native_reqresp_request_write_stops_total{method="metadata"}')
    ).toBe(0);
  } finally {
    await runtime.close();
  }
  const closed = runtime.getMetrics();
  expect(samples(closed).get("lodestar_native_network_running")).toBe(0);
  expect(samples(closed).get("libp2p_peers")).toBe(0);
  expect(samples(closed).get("lodestar_peer_connection_seconds_count")).toBe(0);
  expect(samples(closed).get("lodestar_native_quic_connections_active")).toBe(0);
  expect(samples(closed).get("lodestar_native_dial_attempts")).toBe(0);
  expect(runtime.getMetrics()).toBe(closed);
});

test("real request and peer metrics are isolated, cumulative and do not drain requests", async () => {
  const pair = await incomingPair();
  const outgoing = 'beacon_reqresp_outgoing_requests_total{method="beacon_blocks_by_root"}';
  const incoming = 'beacon_reqresp_incoming_requests_total{method="beacon_blocks_by_root"}';
  try {
    const stream = pair.left.request(pair.remote.peerId, BLOCKS, new Uint8Array(32).fill(7));
    const pending = stream.next();
    void pending.catch(() => undefined);
    samples(pair.right.getMetrics());
    const request = await takeIncoming(pair.right);
    await delay(125);
    await request.finish();
    expect(await pending).toEqual({done: true, value: undefined});
    await vi.waitFor(
      () => {
        const left = samples(pair.left.getMetrics());
        const right = samples(pair.right.getMetrics());
        expect(left.get("libp2p_peers")).toBe(1);
        expect(left.get('lodestar_peer_connected_total{direction="outbound",status="open"}')).toBe(1);
        expect(right.get('lodestar_peer_connected_total{direction="inbound",status="open"}')).toBe(1);
        expect(left.get("lodestar_peer_manager_connected_peers_map_size")).toBe(1);
        expect(left.get('lodestar_peers_by_direction_count{direction="outbound"}')).toBe(1);
        expect(right.get('lodestar_peers_by_direction_count{direction="inbound"}')).toBe(1);
        expect(left.get("lodestar_peer_connection_seconds_count")).toBe(1);
        expect(right.get("lodestar_peer_long_lived_attnets_count_count")).toBe(1);
        expect(left.get('lodestar_native_quic_connections_established_total{direction="outbound"}')).toBe(1);
        expect(right.get('lodestar_native_quic_connections_established_total{direction="inbound"}')).toBe(1);
        expect(left.get('lodestar_discovery_dial_time_seconds_count{status="success"}')).toBe(1);
        expect(left.get(outgoing)).toBe(1);
        expect(
          left.get('beacon_reqresp_outgoing_request_roundtrip_time_seconds_count{method="beacon_blocks_by_root"}')
        ).toBe(1);
        expect(
          left.get('beacon_reqresp_outgoing_request_roundtrip_time_seconds_sum{method="beacon_blocks_by_root"}')
        ).toBeGreaterThanOrEqual(0.1);
        expect(
          right.get('beacon_reqresp_incoming_request_handler_time_seconds_count{method="beacon_blocks_by_root"}')
        ).toBe(1);
        expect(left.get("lodestar_native_quic_udp_sent_bytes_total")).toBeGreaterThan(0);
        expect(right.get("lodestar_native_quic_udp_received_bytes_total")).toBeGreaterThan(0);
        expect(left.get(incoming)).toBe(0);
        expect(right.get(incoming)).toBe(1);
        expect(right.get(outgoing)).toBe(0);
      },
      {timeout: 5000}
    );
    for (let i = 0; i < 10; i++) expect(samples(pair.left.getMetrics()).get(outgoing)).toBe(1);
  } finally {
    await Promise.all([pair.left.close(), pair.right.close()]);
  }
  expect(samples(pair.left.getMetrics()).get(outgoing)).toBe(1);
  expect(samples(pair.right.getMetrics()).get(incoming)).toBe(1);
  expect(samples(pair.left.getMetrics()).get("libp2p_peers")).toBe(0);
  expect(samples(pair.left.getMetrics()).get('lodestar_peer_disconnected_total{direction="outbound"}')).toBe(1);
  expect(samples(pair.right.getMetrics()).get('lodestar_peer_disconnected_total{direction="inbound"}')).toBe(1);
  expect(samples(pair.left.getMetrics()).get("lodestar_peer_manager_connected_peers_map_size")).toBe(0);
  expect(samples(pair.left.getMetrics()).get("lodestar_peers_requested_total_to_connect")).toBe(0);
  expect(samples(pair.left.getMetrics()).get('lodestar_discovery_dial_time_seconds_count{status="success"}')).toBe(1);
  expect(samples(pair.left.getMetrics()).get("lodestar_peer_connection_seconds_count")).toBe(0);
}, 20000);
