import assert from "node:assert/strict";
import {realpathSync} from "node:fs";
import {createRequire} from "node:module";
import {pathToFileURL} from "node:url";

// Runs inside a consumer: resolves every package export from each declaring manifest, loads them, reports the native
// addons the process loaded, then runs two native network lifecycles through the installed facade. Run it with
// --experimental-import-meta-resolve and --expose-gc.

const MIB = 1024 * 1024;
const RELEASE_ATTEMPTS = 200;
const LIFECYCLE_TIMEOUT_MS = 30_000;
// Lodestar's processor plan for a small validator set, in topic kind order; each byte limit exceeds the kind's
// largest compressed message, as the runtime requires.
const TOPIC_KINDS = [
  ["beacon_block", 8, 24, 8, 32],
  ["beacon_aggregate_and_proof", 2048, 8, 64, 4],
  ["beacon_attestation", 128, 8, 128, 8],
  ["proposer_slashing", 32, 1, 8, 1],
  ["attester_slashing", 32, 4, 8, 4],
  ["voluntary_exit", 128, 1, 8, 1],
  ["sync_committee_contribution_and_proof", 128, 2, 16, 2],
  ["sync_committee", 1024, 2, 32, 2],
  ["light_client_finality_update", 8, 2, 8, 2],
  ["light_client_optimistic_update", 8, 2, 8, 2],
  ["bls_to_execution_change", 128, 1, 8, 1],
  ["blob_sidecar", 256, 8, 32, 8],
  ["data_column_sidecar", 256, 16, 64, 24],
];

function lifecycleConfig() {
  const identitySecretKey = new Uint8Array(32);
  identitySecretKey[31] = 1;
  const topic = {
    firstDeliveryCap: 100,
    firstDeliveryDecay: 0.9,
    firstDeliveryWeight: 1,
    invalidDecay: 0.9,
    invalidWeight: -100,
    meshDeliveryActivationMs: 30000n,
    meshDeliveryCap: 50,
    meshDeliveryDecay: 0.9,
    meshDeliveryStartSlot: 0n,
    meshDeliveryThreshold: 5,
    meshDeliveryWeight: -1,
    meshDeliveryWindowMs: 10n,
    meshFailureDecay: 0.9,
    meshFailureWeight: -1,
    timeInMeshCap: 300,
    timeInMeshQuantumMs: 1000n,
    timeInMeshWeight: 0.03,
    weight: 1,
  };
  return {
    bind: {address: Uint8Array.of(127, 0, 0, 1), family: 4, port: 0},
    discovery: null,
    gossipPolicy: {
      execution: TOPIC_KINDS.map(([, , , items, bytes]) => ({bytes: bytes * MIB, items})),
      gossipFactor: 0.25,
      heartbeatIntervalMs: 1000n,
      idontwantMinDataSize: 16829,
      ipAllowlist: [],
      iwantFollowupMs: 12000n,
      largeFrameTimeoutMs: 30000n,
      opportunisticGraftIntervalMs: 60000n,
      pressureTimeoutMs: 30000n,
      processor: TOPIC_KINDS.map(([, items, bytes]) => ({bytes: bytes * MIB, items})),
      retainedScoreMs: 38400000n,
      score: {
        behaviourDecay: 0.9,
        behaviourThreshold: 6,
        behaviourWeight: -10,
        decayIntervalMs: 12000n,
        decayToZero: 0.01,
        gossipThreshold: -4000,
        graylistThreshold: -16000,
        ipColocationThreshold: 3,
        ipColocationWeight: 0,
        opportunisticGraftThreshold: 5,
        publishThreshold: -8000,
        topicCap: 3200,
        topics: Object.fromEntries(TOPIC_KINDS.map(([kind]) => [kind, {...topic}])),
      },
      seenTtlMs: 384000n,
      txTimeoutMs: 30000n,
      validationTimeoutMs: 30000n,
      validationTombstoneMs: 30000n,
    },
    identify: {agentVersion: "lodestar-z/package-probe", protocolVersion: "eth2/1.0.0"},
    identitySecretKey,
    initialSlot: 100n,
    local: {
      metadata: {attnets: new Uint8Array(8), custodyGroupCount: 1n, sequenceNumber: 1n, syncnets: 0},
      status: {
        earliestAvailableSlot: null,
        finalizedEpoch: 0n,
        finalizedRoot: new Uint8Array(32),
        headRoot: new Uint8Array(32),
        headSlot: 100n,
      },
    },
    logLevel: "off",
    profile: "small",
    resources: {
      bridgeBudgetBytes: 512 * MIB,
      connectionCapacity: 16,
      dialingCapacity: 4,
      handshakingCapacity: 8,
      maxPeers: 12,
      minOutbound: 2,
      nativeBudgetBytes: 512 * MIB,
      outboundReserve: 4,
      peerCapacity: 64,
      receiveBudgetBytes: 64 * MIB,
      targetPeers: 8,
    },
    serveLightClients: false,
  };
}

/** A control-only host: it takes no payload, so the binding only settles commands and close. */
function controlHost() {
  return {
    capacity: () => null,
    checkDependencies: (checks) => checks.map(() => false),
    failed: (error) => {
      throw error;
    },
    logs: () => undefined,
    peers: () => undefined,
    serve: async (request) => request.cancel(),
    validate: async (job) => job.messages.map(() => "ignore"),
  };
}

/** The runtime claim returns when the previous facade is collected, so a second start retries after collection. */
async function startAfterRelease(createNativeNetwork, config) {
  for (let attempt = 0; attempt < RELEASE_ATTEMPTS; attempt++) {
    global.gc();
    await new Promise((resolve) => setTimeout(resolve, 5));
    try {
      return createNativeNetwork(config, controlHost());
    } catch (error) {
      if (!String(error?.message).includes("NetworkAlreadyInitialized")) throw error;
    }
  }
  throw Error("The previous native network runtime was never released");
}

async function lifecycle(createNativeNetwork) {
  assert.equal(typeof global.gc, "function", "the lifecycle smoke needs --expose-gc");
  const cycles = [];
  for (let cycle = 0; cycle < 2; cycle++) {
    const config = lifecycleConfig();
    let network =
      cycle === 0 ? createNativeNetwork(config, controlHost()) : await startAfterRelease(createNativeNetwork, config);
    const identity = await network.getIdentity();
    assert(identity.localEndpoint.port > 0);
    const intent = await network.applyIntent(
      {
        demand: {
          attestationTarget: 1,
          attnets: new Uint8Array(8),
          custodyGroupTargets: new Uint16Array(128),
          groupTargets: new Uint16Array(128),
          syncTarget: 1,
          syncnets: 0,
        },
        subscriptions: [],
        update: {local: config.local},
      },
      config.initialSlot
    );
    assert.equal(intent.slot, config.initialSlot);
    const closed = await network.close();
    assert.deepEqual(closed, {reason: "requested"});
    assert.deepEqual(await network.closed, closed);
    cycles.push({closed: closed.reason, peerId: identity.peerId, port: identity.localEndpoint.port});
    network = null;
  }
  return {cycles};
}

const [parentsJson, specifiersJson, runtimeSpecifier] = process.argv.slice(2);
const parents = JSON.parse(parentsJson);
const specifiers = JSON.parse(specifiersJson);
const result = {exports: {}, loadedAddons: [], resolutions: [], runtime: null};
for (const parent of parents) {
  for (const specifier of specifiers) {
    try {
      result.resolutions.push({parent, resolved: import.meta.resolve(specifier, pathToFileURL(parent)), specifier});
    } catch (error) {
      result.resolutions.push({error: {code: error.code, message: error.message}, parent, specifier});
    }
  }
}
const modules = {};
for (const specifier of specifiers) {
  const resolved = result.resolutions.find((row) => row.specifier === specifier && row.error === undefined)?.resolved;
  if (!resolved) continue;
  modules[specifier] = await import(resolved);
  result.exports[specifier] = Object.keys(modules[specifier]).sort();
}
result.loadedAddons = Object.keys(createRequire(import.meta.url).cache)
  .filter((path) => path.endsWith(".node"))
  .map((path) => realpathSync(path));
if (runtimeSpecifier !== undefined) {
  const createNativeNetwork = modules[runtimeSpecifier]?.createNativeNetwork;
  assert.equal(typeof createNativeNetwork, "function", `${runtimeSpecifier} exports no createNativeNetwork`);
  const timeout = setTimeout(() => {
    throw Error("The native lifecycle smoke timed out");
  }, LIFECYCLE_TIMEOUT_MS);
  result.runtime = await lifecycle(createNativeNetwork);
  clearTimeout(timeout);
}
process.stdout.write(JSON.stringify(result));
