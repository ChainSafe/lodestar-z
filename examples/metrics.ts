import * as fs from "node:fs";
import http from "node:http";
import { config } from "@lodestar/config/default";
import * as era from "@lodestar/era";
import bindings from "../bindings/src/index.ts";
import { getFirstEraFilePath } from "../bindings/test/eraFiles.ts";

const PORT = 8008;
const PKIX_FILE = "./mainnet.pkix";

const hasPkix = (() => {
  try {
    fs.accessSync(PKIX_FILE);
    return true;
  } catch {
    return false;
  }
})();

if (hasPkix) {
  console.log("Loading pkix cache from disk...");
  bindings.pubkeys.load(PKIX_FILE);
} else {
  console.log("No pkix cache found, ensuring capacity...");
  bindings.pool.ensureCapacity(10_000_000);
  bindings.pubkeys.ensureCapacity(2_000_000);
}

// --- Init metrics (must be before state creation) ---

bindings.metrics.init();
console.log("Metrics initialized.");

// --- Load beacon state from era file ---

console.log("Opening era reader...");
const reader = await era.era.EraReader.open(config, getFirstEraFilePath());

console.log("Reading serialized state...");
const stateBytes = await reader.readSerializedState();

console.log("Creating BeaconStateView...");
const state = bindings.BeaconStateView.createFromBytes(stateBytes);

if (!hasPkix) {
  console.log("Saving pkix cache to disk...");
  bindings.pubkeys.save(PKIX_FILE);
}

console.log(`State loaded at slot ${state.slot}, epoch ${state.epoch}`);

var slot = state.slot;


console.log(`Processing slots: ${state.slot} -> ${state.slot + 1}...`);
console.time("processSlots");
state.processSlots(++slot);
console.timeEnd("processSlots");

// --- Preview scraped metrics ---

const preview = bindings.metrics.scrapeMetrics();
console.log("\n--- Metrics preview (first 2000 chars) ---");
console.log(preview.slice(0, 2000));
console.log("---\n");


console.time("processSlots");
state.processSlots(++slot);
console.timeEnd("processSlots");

const preview2 = bindings.metrics.scrapeMetrics();
console.log("\n--- Metrics preview (first 2000 chars) ---");
console.log(preview2.slice(0, 2000));
console.log("---\n");

// --- Start HTTP metrics server ---

const server = http.createServer((_req, res) => {
  if (_req.url === "/metrics") {
    const metrics = bindings.metrics.scrapeMetrics();
    res.writeHead(200, { "Content-Type": "text/plain; version=0.0.4" });
    res.end(metrics);
  } else if (_req.url === "/slot") {
    console.time("processSlots");
    state.processSlots(++slot);
    console.timeEnd("processSlots");
    res.writeHead(200, { "Content-Type": "text/plain; version=0.0.4" });
    res.end();
  } else {
    res.writeHead(404);
    res.end("Not found. Use /metrics endpoint.\n");
  }
});

server.listen(PORT, () => {
  console.log(`Metrics server listening on http://localhost:${PORT}/metrics`);
  console.log("You can scrape metrics with: curl http://localhost:8008/metrics");
  console.log("Or run Prometheus with: docker run -p 9090:9090 -v $(pwd)/examples/prometheus.yml:/etc/prometheus/prometheus.yml prom/prometheus");
});
