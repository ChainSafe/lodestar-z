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
    await vi.waitFor(() => expect(samples(runtime.getMetrics()).get("lodestar_network_running_bool")).toBe(1));
    const metrics = samples(runtime.getMetrics());
    expect(metrics.get("gossipsub_validation_capacity_count")).toBe(
      Object.values(config.gossipPolicy.processor).reduce((total, limit) => total + limit.items, 0)
    );
    expect(metrics.has("lodestar_peer_manager_starved_bool")).toBe(false);
    expect(metrics.has("lodestar_discovery_total_dial_attempts")).toBe(false);
    const published = metrics.get("lodestar_network_metrics_updated_timestamp_seconds");
    expect(published).toBeGreaterThan(0);
    await vi.waitFor(
      () => {
        const next = samples(runtime.getMetrics());
        expect(next.get("lodestar_network_metrics_updated_timestamp_seconds")).toBeGreaterThan(published ?? 0);
        expect(next.get("lodestar_network_step_seconds_count")).toBeGreaterThan(0);
      },
      {timeout: 5000}
    );
    expect(metrics.get("lodestar_gossip_validation_expired_executing_count")).toBe(0);
    expect(metrics.get('lodestar_gossip_validation_queue_length{topic="beacon_block"}')).toBe(0);
    for (const reason of [
      "connection_capacity",
      "protocol_concurrency",
      "peer_quota",
      "global_quota",
      "identity_capacity",
    ]) {
      expect(metrics.get(`beacon_reqresp_admission_refusals_total{method="status",reason="${reason}"}`)).toBe(0);
    }
    for (const phase of ["receiving_request", "waiting_start", "waiting_host", "writing_response", "terminal"]) {
      expect(metrics.get(`beacon_reqresp_incoming_count{phase="${phase}"}`)).toBe(0);
    }
    for (const name of [
      "gossipsub_receive_pages_capacity_count",
      "gossipsub_validation_capacity_count",
      "gossipsub_delivery_descriptors_capacity_count",
    ]) {
      const value = metrics.get(name);
      expect(value).toBeGreaterThan(0);
      if (value === undefined) throw Error(`Missing capacity: ${name}`);
      capacities.set(name, value);
    }
    expect(metrics.get("gossipsub_iwant_rcv_dont_have_msgids_total")).toBe(0);
    for (const outcome of ["limited", "queued", "refused"]) {
      expect(metrics.get(`gossipsub_iwant_known_msgids_total{outcome="${outcome}"}`)).toBe(0);
    }
  } finally {
    await runtime.close();
  }
  const closed = runtime.getMetrics();
  const closedSamples = samples(closed);
  expect(closedSamples.get("lodestar_gossip_validation_expired_executing_count")).toBe(0);
  for (const [name, value] of capacities) expect(closedSamples.get(name)).toBe(value);
  expect(samples(closed).get("lodestar_network_running_bool")).toBe(0);
  expect(samples(closed).get("libp2p_peers")).toBe(0);
  expect(samples(closed).get("lodestar_peer_connection_seconds_count")).toBe(0);
  expect(samples(closed).get("lodestar_quic_connection_slots_count")).toBe(0);
  expect(runtime.getMetrics()).toBe(closed);
}, 20000);

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
      async () => {
        const left = samples(await pair.left.getMetrics());
        const right = samples(pair.right.getMetrics());
        expect(left.get("libp2p_peers")).toBe(1);
        expect(left.get('lodestar_peer_connected_total{direction="outbound",status="open"}')).toBe(1);
        expect(right.get('lodestar_peer_connected_total{direction="inbound",status="open"}')).toBe(1);
        expect(left.get('lodestar_peers_by_direction_count{direction="outbound"}')).toBe(1);
        expect(right.get('lodestar_peers_by_direction_count{direction="inbound"}')).toBe(1);
        expect(left.get("lodestar_peer_connection_seconds_count")).toBe(1);
        expect(right.get("lodestar_peer_connection_seconds_count")).toBe(1);
        expect(left.get('lodestar_quic_connections_established_total{direction="outbound"}')).toBe(1);
        expect(right.get('lodestar_quic_connections_established_total{direction="inbound"}')).toBe(1);
        expect(left.get('lodestar_peer_dial_outcomes_total{outcome="connected"}')).toBe(1);
        expect(left.get('lodestar_peer_dial_selections_total{source="manual"}')).toBe(1);
        expect(left.get('lodestar_peer_dial_selections_total{source="discovery"}')).toBe(0);
        expect(left.get(outgoing)).toBe(1);
        for (const stage of ["opened", "closed"]) {
          expect(left.get(`beacon_reqresp_outgoing_${stage}_streams_total{method="beacon_blocks_by_root"}`)).toBe(1);
          expect(right.get(`beacon_reqresp_incoming_${stage}_streams_total{method="beacon_blocks_by_root"}`)).toBe(1);
        }
        expect(left.get("beacon_reqresp_dial_errors_total")).toBe(0);
        expect(left.get("lodestar_peer_long_lived_attnets_count_count")).toBe(1);
        expect(left.get("lodestar_peer_column_group_count_count")).toBe(1);
        expect(
          left.get('beacon_reqresp_outgoing_request_roundtrip_time_seconds_count{method="beacon_blocks_by_root"}')
        ).toBe(1);
        expect(
          left.get('beacon_reqresp_outgoing_request_roundtrip_time_seconds_sum{method="beacon_blocks_by_root"}')
        ).toBeGreaterThanOrEqual(0.1);
        expect(
          right.get('beacon_reqresp_incoming_request_handler_time_seconds_count{method="beacon_blocks_by_root"}')
        ).toBe(1);
        expect(left.get("lodestar_quic_udp_sent_bytes_total")).toBeGreaterThan(0);
        expect(right.get("lodestar_quic_udp_received_bytes_total")).toBeGreaterThan(0);
        expect(left.get(incoming)).toBe(0);
        expect(right.get(incoming)).toBe(1);
        expect(right.get(outgoing)).toBe(0);
        expect(right.get('beacon_reqresp_incoming_requests_error_total{method="beacon_blocks_by_root"}')).toBe(0);
      },
      {timeout: 5000}
    );
    for (let i = 0; i < 10; i++) expect(samples(await pair.left.getMetrics()).get(outgoing)).toBe(1);
    await Promise.all([pair.left.close(), pair.right.close()]);
    expect(samples(await pair.left.getMetrics()).get(outgoing)).toBe(1);
    expect(samples(pair.right.getMetrics()).get(incoming)).toBe(1);
    expect(samples(await pair.left.getMetrics()).get("libp2p_peers")).toBe(0);
    expect(samples(await pair.left.getMetrics()).get('lodestar_peer_dial_outcomes_total{outcome="connected"}')).toBe(1);
    expect(samples(await pair.left.getMetrics()).get("lodestar_peer_connection_seconds_count")).toBe(0);
    expect(samples(await pair.left.getMetrics()).get("lodestar_peer_long_lived_attnets_count_count")).toBe(0);
    expect(
      samples(await pair.left.getMetrics()).get(
        'beacon_reqresp_outgoing_closed_streams_total{method="beacon_blocks_by_root"}'
      )
    ).toBe(1);
  } finally {
    await Promise.all([pair.left.stop(), pair.right.close()]);
  }
}, 20000);

test("incoming error responses use the request error metric exactly once", async () => {
  const pair = await incomingPair();
  const incomingErrors = 'beacon_reqresp_incoming_requests_error_total{method="beacon_blocks_by_root"}';
  const outgoingErrors = 'beacon_reqresp_outgoing_requests_error_total{method="beacon_blocks_by_root"}';
  let expected = 0;
  try {
    for (const status of [2, 3]) {
      const stream = pair.left.request(pair.remote.peerId, BLOCKS, new Uint8Array(32));
      const rejected = expect(stream.next()).rejects.toMatchObject({peerStatus: status, reason: "peer_error"});
      const request = await takeIncoming(pair.right);
      await request.fail(status, new TextEncoder().encode("Unavailable"));
      await rejected;
      expected++;
      await vi.waitFor(
        async () => {
          expect(samples(pair.right.getMetrics()).get(incomingErrors), `response status ${status}`).toBe(expected);
          expect(samples(await pair.left.getMetrics()).get(outgoingErrors), `response status ${status}`).toBe(expected);
        },
        {timeout: 5000}
      );
    }
  } finally {
    await Promise.all([pair.left.stop(), pair.right.close()]);
  }
  expect(samples(pair.right.getMetrics()).get(incomingErrors)).toBe(expected);
}, 20000);
