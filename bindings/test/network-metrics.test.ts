import {setTimeout as delay} from "node:timers/promises";
import {expect, test, vi} from "vitest";
import {applicationConfig, localIntent, startRuntime} from "./utils/network.js";
import {BLOCKS, incomingPair, takeIncoming} from "./utils/network-incoming.js";

function samples(text: string): Map<string, number> {
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
  const config = applicationConfig();
  const runtime = startRuntime(config, () => undefined);
  const capacities = new Map<string, number>();
  try {
    expect(samples(runtime.getMetrics()).get("libp2p_peers")).toBe(0);
    expect(samples(runtime.getMetrics()).get("lodestar_peer_connection_seconds_count")).toBe(0);
    await runtime.identity;
    await runtime.applyIntent(localIntent(config), config.initialSlot);
    await vi.waitFor(() => expect(samples(runtime.getMetrics()).get("lodestar_native_network_running")).toBe(1));
    const metrics = samples(runtime.getMetrics());
    expect(runtime.getMetrics()).toContain("# TYPE lodestar_peers_requested_total_to_connect counter\n");
    expect(metrics.has("lodestar_peer_manager_starved_bool")).toBe(false);
    expect(metrics.has("lodestar_discovery_total_dial_attempts")).toBe(false);
    const published = metrics.get("lodestar_native_network_metrics_updated_timestamp_seconds");
    expect(published).toBeGreaterThan(0);
    await vi.waitFor(
      () => {
        const next = samples(runtime.getMetrics());
        expect(next.get("lodestar_native_network_metrics_updated_timestamp_seconds")).toBeGreaterThan(published ?? 0);
        expect(next.get("gossipsub_heartbeat_duration_seconds_count")).toBeGreaterThan(0);
        expect(next.get("lodestar_native_gossip_maintenance_completed_timestamp_seconds")).toBeGreaterThan(0);
        expect(next.get("lodestar_native_peer_selection_seconds_count")).toBeGreaterThan(0);
        expect(next.get("lodestar_native_network_step_seconds_count")).toBeGreaterThan(0);
      },
      {timeout: 5000}
    );
    expect(metrics.get("lodestar_native_gossip_expired_executing")).toBe(0);
    expect(metrics.get("lodestar_native_gossip_oldest_expired_execution_age_seconds")).toBe(0);
    for (const budget of ["calls", "input", "output", "items", "fields", "work", "copy"]) {
      expect(metrics.get(`lodestar_native_gossip_turns_exhausted_total{budget="${budget}"}`)).toBe(0);
      expect(metrics.get(`lodestar_native_gossip_ready_deferred_total{budget="${budget}"}`)).toBe(0);
    }
    for (const counter of ["read_calls", "write_calls", "write_would_block", "write_zero"]) {
      expect(metrics.get(`lodestar_native_gossip_io_${counter}_total`)).toBe(0);
    }
    expect(metrics.get("lodestar_native_gossip_history_entries_visited_total")).toBe(0);
    for (const phase of ["mesh", "gossip", "retire", "history"]) {
      expect(
        metrics.get(`lodestar_native_gossip_maintenance_work_seconds_count{phase="${phase}"}`)
      ).toBeGreaterThanOrEqual(0);
    }
    for (const stage of ["challenge", "handshake", "packet", "response", "record"]) {
      for (const outcome of ["allowed", "source_limit", "global_limit", "source_capacity"]) {
        expect(metrics.get(`lodestar_native_discovery_admission_total{stage="${stage}",outcome="${outcome}"}`)).toBe(0);
      }
    }
    for (const reason of [
      "server_capacity",
      "peer_capacity",
      "protocol_concurrency",
      "peer_quota",
      "global_quota",
      "identity_capacity",
    ]) {
      expect(metrics.get(`lodestar_native_reqresp_admission_refusals_total{method="status",reason="${reason}"}`)).toBe(
        0
      );
    }
    for (const phase of ["receiving_request", "waiting_host", "writing_response", "withheld", "terminal"]) {
      expect(metrics.get(`lodestar_native_reqresp_inbound_occupied{phase="${phase}"}`)).toBe(0);
    }
    for (const name of [
      "lodestar_native_quic_connections_capacity",
      "lodestar_native_dial_capacity",
      "lodestar_native_gossipsub_connected_capacity",
      "lodestar_native_gossipsub_retained_capacity",
      "lodestar_native_gossipsub_validation_capacity",
      "lodestar_native_gossipsub_delivery_descriptors_capacity",
    ]) {
      const value = metrics.get(name);
      expect(value).toBeGreaterThan(0);
      if (value === undefined) throw Error(`Missing capacity: ${name}`);
      capacities.set(name, value);
    }
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
  const closedSamples = samples(closed);
  expect(closedSamples.get("lodestar_native_gossip_expired_executing")).toBe(0);
  expect(closedSamples.get("lodestar_native_gossip_oldest_expired_execution_age_seconds")).toBe(0);
  for (const [name, value] of capacities) expect(closedSamples.get(name)).toBe(value);
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
  let requestedBeforeClose = 0;
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
      async () => {
        const left = samples(await pair.left.getMetrics());
        const right = samples(pair.right.getMetrics());
        expect(left.get("libp2p_peers")).toBe(1);
        expect(left.get('lodestar_peer_connected_total{direction="outbound",status="open"}')).toBe(1);
        expect(right.get('lodestar_peer_connected_total{direction="inbound",status="open"}')).toBe(1);
        expect(left.get("lodestar_peer_manager_connected_peers_map_size")).toBe(1);
        expect(left.get('lodestar_peers_by_direction_count{direction="outbound"}')).toBe(1);
        expect(right.get('lodestar_peers_by_direction_count{direction="inbound"}')).toBe(1);
        for (const [metrics, direction] of [
          [left, "outbound"],
          [right, "inbound"],
        ] as const) {
          const jointCount = [...metrics]
            .filter(
              ([name]) =>
                name.startsWith("lodestar_native_peers_by_client_direction{") &&
                name.includes(`direction="${direction}"`)
            )
            .reduce((total, [, value]) => total + value, 0);
          expect(jointCount).toBe(1);
        }
        expect(left.get("lodestar_peer_connection_seconds_count")).toBe(1);
        expect(right.get("lodestar_peer_long_lived_attnets_count_count")).toBe(1);
        expect(left.get('lodestar_native_quic_connections_established_total{direction="outbound"}')).toBe(1);
        expect(right.get('lodestar_native_quic_connections_established_total{direction="inbound"}')).toBe(1);
        expect(left.get('lodestar_native_peer_dial_time_seconds_count{status="success"}')).toBe(1);
        expect(left.get('lodestar_native_peer_dial_selections_total{source="manual"}')).toBe(1);
        expect(left.get('lodestar_native_peer_dial_selections_total{source="discovery"}')).toBe(0);
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
    for (let i = 0; i < 10; i++) expect(samples(await pair.left.getMetrics()).get(outgoing)).toBe(1);
    requestedBeforeClose = samples(await pair.left.getMetrics()).get("lodestar_peers_requested_total_to_connect") ?? 0;
  } finally {
    await Promise.all([pair.left.close(), pair.right.close()]);
  }
  expect(samples(await pair.left.getMetrics()).get(outgoing)).toBe(1);
  expect(samples(pair.right.getMetrics()).get(incoming)).toBe(1);
  expect(samples(await pair.left.getMetrics()).get("libp2p_peers")).toBe(0);
  expect(samples(await pair.left.getMetrics()).get('lodestar_peer_disconnected_total{direction="outbound"}')).toBe(1);
  expect(samples(pair.right.getMetrics()).get('lodestar_peer_disconnected_total{direction="inbound"}')).toBe(1);
  expect(samples(await pair.left.getMetrics()).get("lodestar_peer_manager_connected_peers_map_size")).toBe(0);
  expect(samples(await pair.left.getMetrics()).get("lodestar_native_peer_dials_requested")).toBe(0);
  expect(samples(await pair.left.getMetrics()).get("lodestar_peers_requested_total_to_connect")).toBeGreaterThanOrEqual(
    requestedBeforeClose
  );
  expect(
    samples(await pair.left.getMetrics()).get('lodestar_native_peer_dial_time_seconds_count{status="success"}')
  ).toBe(1);
  expect(samples(await pair.left.getMetrics()).get("lodestar_peer_connection_seconds_count")).toBe(0);
}, 20000);
