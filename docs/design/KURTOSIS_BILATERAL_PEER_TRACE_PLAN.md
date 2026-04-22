# Kurtosis bilateral peer-trace plan

> For Hermes: use this plan to build a local ephemeral devnet where Lodestar-Z and at least one reference client run side-by-side, then inspect both sides of the connection and churn logs.

Goal: reproduce the post-connect peer churn locally with both-side visibility, so we can see not only how Lodestar-Z reacts to peers, but how the peer reacts to Lodestar-Z.

Architecture:
- Run a fresh ephemeral Kurtosis enclave with 1 Lodestar-Z beacon node plus 1-2 reference beacon nodes.
- Capture logs, metrics, and REST state from both sides.
- Focus on the conversion funnel: discovered -> dialing -> transport connected -> status success -> identify success -> gossip peer -> disconnect/goodbye.

Tech stack:
- Kurtosis CLI + ethpandaops/ethereum-package
- Docker image for Lodestar-Z
- Existing `kurtosis-devnet.yaml` as baseline
- Reference clients: Lodestar-TS and Lighthouse

---

## What we already discovered

1. Local Kurtosis tooling already exists
- File present: `kurtosis-devnet.yaml`
- Kurtosis installed: `1.17.7`
- Docker installed and working
- Kurtosis engine is running locally
- A stale enclave named `lodestar-z-devnet` already exists

2. The current Kurtosis config is not enough to run Zig correctly
- `kurtosis-devnet.yaml` currently sets:
  - `cl_type: lodestar`
  - `cl_image: lodestar-z:local`
- Inspecting the existing service shows ethereum-package injects the Lodestar-TS command line for `cl_type: lodestar`, e.g.:
  - `sh -c exec node ./packages/cli/bin/lodestar beacon ...`
- Our current `Dockerfile` image exposes:
  - entrypoint `lodestar-z`
  - cmd `beacon`
- Therefore the current image/config combination is structurally incompatible.
- Before a fresh bilateral trace run, we need a Kurtosis-compatible shim image or a different package integration path.

This is the key prerequisite. Without fixing it, a new Kurtosis run will not prove anything about Zig peer behavior.

---

## Task 1: Create a Kurtosis-compatible Lodestar-Z image shim

Objective: make ethereum-package able to launch Lodestar-Z while still using `cl_type: lodestar` wiring.

Files:
- Create: `docker/kurtosis/lodestar-wrapper.js`
- Create: `docker/kurtosis/Dockerfile`
- Optional create: `scripts/build-kurtosis-lodestar-z-image.sh`

Approach:
- Build an image that contains:
  - `/usr/local/bin/lodestar-z`
  - Node.js runtime
  - `/packages/cli/bin/lodestar` JS wrapper
- The wrapper should translate the subset of Lodestar-TS CLI flags emitted by ethereum-package into Lodestar-Z flags, then `exec` Lodestar-Z.

Minimum flags the wrapper must understand from the observed command shape:
- `beacon`
- `--logLevel`
- `--port`
- `--discoveryPort`
- `--dataDir`
- `--eth1.providerUrls`
- `--execution.urls`
- `--rest`
- `--rest.address`
- `--rest.port`
- `--nat`
- `--jwt-secret`
- `--enr.ip`
- `--enr.tcp`
- `--enr.udp`
- `--metrics`
- `--metrics.address`
- `--metrics.port`
- `--supernode`
- `--paramsFile`
- `--genesisStateFile`
- `--sync.isSingleNode`
- `--network.allowPublishToZeroPeers`
- ignore or explicitly reject unsupported flags with a loud error

Recommended wrapper behavior:
- log the raw incoming argv before translation
- log the translated Lodestar-Z argv
- fail fast if an unhandled required flag appears

Example wrapper shape:
```js
#!/usr/bin/env node
const {spawn} = require('node:child_process');

const raw = process.argv.slice(2);
if (raw[0] !== 'beacon') {
  console.error('Expected `beacon` subcommand from ethereum-package');
  process.exit(1);
}

const out = ['beacon'];
for (let i = 1; i < raw.length; i++) {
  const arg = raw[i];
  const next = raw[i + 1];

  switch (arg) {
    case '--logLevel': out.push('--logLevel', next); i++; break;
    case '--port': out.push('--p2p-port', next); i++; break;
    case '--discoveryPort': out.push('--discovery-port', next); i++; break;
    case '--dataDir': out.push('--data-dir', next); i++; break;
    case '--execution.urls': out.push('--execution-url', next); i++; break;
    case '--eth1.providerUrls': break; // EL REST is not the Zig execution path
    case '--rest': out.push('--rest'); break;
    case '--rest.address': out.push('--api-address', next); i++; break;
    case '--rest.port': out.push('--api-port', next); i++; break;
    case '--jwt-secret': out.push('--jwt-secret', next); i++; break;
    case '--enr.ip': out.push('--enr.ip', next); i++; break;
    case '--enr.tcp': out.push('--enr.tcp', next); i++; break;
    case '--enr.udp': out.push('--enr.udp', next); i++; break;
    case '--metrics': out.push('--metrics'); break;
    case '--metrics.address': out.push('--metrics-address', next); i++; break;
    case '--metrics.port': out.push('--metrics-port', next); i++; break;
    case '--supernode': out.push('--supernode'); break;
    case '--paramsFile': out.push('--params-file', next); i++; break;
    case '--genesisStateFile': out.push('--checkpoint-state', next); i++; break;
    case '--sync.isSingleNode': out.push('--sync.isSingleNode'); break;
    case '--network.allowPublishToZeroPeers': break;
    case '--nat': out.push('--nat'); break;
    default:
      console.error('Unhandled ethereum-package arg:', arg);
      process.exit(2);
  }
}

console.error('raw argv:', JSON.stringify(raw));
console.error('translated argv:', JSON.stringify(out));
const child = spawn('/usr/local/bin/lodestar-z', out, {stdio: 'inherit'});
child.on('exit', (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  else process.exit(code ?? 1);
});
```

Step 1: write the wrapper.
Step 2: build the image.
Step 3: locally run the wrapper with a copied ethereum-package command line and make sure it starts the Zig binary.

Verification commands:
```bash
node docker/kurtosis/lodestar-wrapper.js beacon --port 9000 --rest --rest.port 5052 --metrics --metrics.port 8008 --sync.isSingleNode

docker build -f docker/kurtosis/Dockerfile -t lodestar-z:kurtosis .

docker run --rm lodestar-z:kurtosis node ./packages/cli/bin/lodestar beacon --help
```

---

## Task 2: Create a fresh ephemeral bilateral-trace Kurtosis config

Objective: define an enclave specifically for peer churn tracing.

Files:
- Create: `kurtosis-peer-churn.yaml`

Suggested participants:
- Participant A: Lodestar-Z shim image + Reth
- Participant B: Lodestar-TS + Reth
- Participant C: Lighthouse + Geth

Design notes:
- keep `seconds_per_slot: 6`
- keep validators low enough for fast startup, e.g. `32` each
- keep `global_log_level: "debug"`
- enable CL and EL port publishing
- name the future enclave explicitly, e.g. `lodestar-z-peer-trace`

The point is not scale first.
The point is observability and bilateral evidence first.

---

## Task 3: Boot a fresh enclave, not the old stale one

Objective: start a reproducible ephemeral environment.

Commands:
```bash
kurtosis enclave rm -f lodestar-z-peer-trace || true
kurtosis run github.com/ethpandaops/ethereum-package \
  --enclave lodestar-z-peer-trace \
  --args-file kurtosis-peer-churn.yaml \
  --image-download missing
```

Verification:
```bash
kurtosis enclave inspect lodestar-z-peer-trace
kurtosis service inspect lodestar-z-peer-trace cl-1-lodestar-reth -o json
```

Important check:
- confirm the Zig participant service command is launching the wrapper path, not raw Lodestar-TS JS from an incompatible image layout.

---

## Task 4: Capture both-side logs for a single peer relationship

Objective: correlate what Zig thinks happened with what the peer thinks happened.

Useful Kurtosis commands:
```bash
kurtosis service logs lodestar-z-peer-trace cl-1-lodestar-reth --match 'dial failed'
kurtosis service logs lodestar-z-peer-trace cl-1-lodestar-reth --regex-match 'identify|gossipsub|status|Goodbye|UnexpectedEof|multistream'

kurtosis service logs lodestar-z-peer-trace cl-2-lodestar-reth --regex-match 'identify|gossipsub|status|Goodbye|UnexpectedEof|multistream'
kurtosis service logs lodestar-z-peer-trace cl-3-lighthouse-geth --regex-match 'identify|gossipsub|status|Goodbye|EOF|disconnect|peer'
```

Also capture metrics from both sides:
```bash
kurtosis service inspect lodestar-z-peer-trace cl-1-lodestar-reth -o json
kurtosis service inspect lodestar-z-peer-trace cl-2-lodestar-reth -o json
kurtosis service inspect lodestar-z-peer-trace cl-3-lighthouse-geth -o json
```
Then query the published REST/metrics ports for:
- peer counts
- gossipsub peer counts
- discovery dials and errors
- req/resp maintenance errors
- block import outcomes

---

## Task 5: Instrument the peer conversion funnel in Lodestar-Z

Objective: stop inferring churn from unrelated counters.

Files:
- Modify: `src/node/p2p_runtime.zig`
- Modify: `src/node/metrics.zig`

Add explicit counters for:
- discovery dial started
- transport connected
- status sent
- status succeeded
- ping succeeded
- metadata succeeded
- identify succeeded
- gossipsub outbound stream opened
- peer entered gossip topic set / mesh
- disconnect before status
- disconnect after status before gossip
- goodbye received after connect with reason

This should let us answer:
- are peers failing before status?
- after status?
- after identify?
- after gossipsub open?
- only when over target and being pruned?

---

## Primary hypotheses this devnet should test

### Hypothesis A
Our eager Zig connect sequence (gossipsub + identify before status) is causing worse retention than Lodestar-TS under marginal QUIC peers.

How to test:
- compare Zig side and TS/Lighthouse side logs around a fresh connection
- see whether the remote peer closes before or during our early stream setup

### Hypothesis B
The real issue is not early stream ordering but low refill aggressiveness under churn.

How to test:
- hold the same peers stable in devnet
- observe whether peer count still collapses with very low dial concurrency
- if not, the refill budget is only a secondary issue

### Hypothesis C
Remote peers are pruning us for peer-selection reasons (`too_many_peers`) independent of our local gossipsub logic.

How to test:
- read the other peer's logs around the same timestamp
- confirm whether they classify us as low-value, irrelevant, redundant, or just overflow

---

## Immediate conclusion before implementation

The next step should indeed be Kurtosis bilateral testing.
But the first actionable blocker is not peer churn itself — it is getting Lodestar-Z launched correctly inside ethereum-package.

Current `kurtosis-devnet.yaml` + current `Dockerfile` is not sufficient because `cl_type: lodestar` makes ethereum-package run Lodestar-TS-style commands that do not match the Zig image contract.

So the shortest path is:
1. build the Lodestar-Z Kurtosis wrapper image
2. create a fresh bilateral trace args file
3. boot a new enclave
4. capture both-side status/identify/gossipsub/goodbye logs
5. only then decide whether the next code change should be sequencing, retry/repair, or refill aggressiveness
