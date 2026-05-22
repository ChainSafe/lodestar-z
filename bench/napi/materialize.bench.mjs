// Microbench: per-call GC cost of factory methods that go through
// zapi's materializeClassInstance (PublicKey.fromBytes, Signature.fromBytes,
// SecretKey.toPublicKey, SecretKey.sign, Signature.aggregate).
//
// Run:
//   node --expose-gc bench/napi/materialize.bench.mjs
//   ITERS=500000 node --expose-gc bench/napi/materialize.bench.mjs   # override iter count
//
// To compare patched vs unpatched zapi: rebuild between runs.
//   zig build build-lib:bindings -Doptimize=ReleaseSafe
//   node --expose-gc bench/napi/materialize.bench.mjs | tee /tmp/patched.txt
//   <revert zapi edits>
//   zig build build-lib:bindings -Doptimize=ReleaseSafe
//   node --expose-gc bench/napi/materialize.bench.mjs | tee /tmp/unpatched.txt
//   diff -u /tmp/unpatched.txt /tmp/patched.txt

import crypto from "node:crypto";
import {PerformanceObserver, performance, constants} from "node:perf_hooks";
import {PublicKey, SecretKey, Signature} from "../../bindings/src/blst.js";

const ITERS = Number(process.env.ITERS ?? 200_000);

const ikm = crypto.randomBytes(32);
const sk = SecretKey.fromKeygen(ikm);
const pk = sk.toPublicKey();
const msg = crypto.randomBytes(32);
const sig = sk.sign(msg);

const pkBytes = pk.toBytes();
const sigBytes = sig.toBytes();

const KIND_NAMES = {
  [constants.NODE_PERFORMANCE_GC_MAJOR]: "major",
  [constants.NODE_PERFORMANCE_GC_MINOR]: "scavenge",
  [constants.NODE_PERFORMANCE_GC_INCREMENTAL]: "incremental",
  [constants.NODE_PERFORMANCE_GC_WEAKCB]: "weakcb",
};

const gc = {scavenge: 0, scavengeMs: 0, major: 0, majorMs: 0, incremental: 0, incrementalMs: 0, weakcb: 0, weakcbMs: 0};
const obs = new PerformanceObserver((list) => {
  for (const e of list.getEntries()) {
    const kind = e.detail?.kind ?? e.kind;
    const name = KIND_NAMES[kind];
    if (!name) continue;
    gc[name]++;
    gc[name + "Ms"] += e.duration;
  }
});
obs.observe({entryTypes: ["gc"]});

function reset() {
  gc.scavenge = 0; gc.scavengeMs = 0;
  gc.major = 0; gc.majorMs = 0;
  gc.incremental = 0; gc.incrementalMs = 0;
  gc.weakcb = 0; gc.weakcbMs = 0;
}

const flush = () => new Promise((r) => setImmediate(r));

async function run(name, fn) {
  // settle before measuring — yield so the observer drains queued events
  global.gc?.();
  global.gc?.();
  await flush();
  reset();
  const t0 = performance.now();
  for (let i = 0; i < ITERS; i++) fn();
  const t1 = performance.now();
  // yield so PerformanceObserver callback fires with the loop's GC events
  await flush();
  global.gc?.();
  await flush();
  const elapsed = t1 - t0;
  const opsPerSec = (ITERS / elapsed) * 1000;
  const scavRatio = (gc.scavengeMs / elapsed) * 100;
  const majorRatio = (gc.majorMs / elapsed) * 100;
  console.log(
    `${name.padEnd(28)} ${ITERS.toLocaleString().padStart(10)} iters  ` +
    `${elapsed.toFixed(1).padStart(8)} ms  ` +
    `${opsPerSec.toFixed(0).padStart(10)} ops/s  ` +
    `scav ${gc.scavenge.toString().padStart(4)}× ${gc.scavengeMs.toFixed(2).padStart(7)}ms (${scavRatio.toFixed(2)}%)  ` +
    `major ${gc.major.toString().padStart(3)}× ${gc.majorMs.toFixed(2).padStart(6)}ms (${majorRatio.toFixed(2)}%)`
  );
}

console.log(`node ${process.version}  iters=${ITERS.toLocaleString()}\n`);

// Warm up everything to JIT-stabilize
for (let i = 0; i < 50_000; i++) {
  PublicKey.fromBytes(pkBytes);
  Signature.fromBytes(sigBytes);
  sk.toPublicKey();
  sk.sign(msg);
}

await run("PublicKey.fromBytes",     () => PublicKey.fromBytes(pkBytes));
await run("Signature.fromBytes",     () => Signature.fromBytes(sigBytes));
await run("SecretKey.toPublicKey",   () => sk.toPublicKey());
await run("SecretKey.sign",          () => sk.sign(msg));

// Aggregate is also a factory — uses a small array each call.
const sigs = [sig, sig, sig, sig];
await run("Signature.aggregate[4]",  () => Signature.aggregate(sigs, false));

// Control: non-factory hot path (returns Uint8Array, no class materialization).
// Used to detect Scavenge churn that is NOT caused by materializeClassInstance.
await run("PublicKey.toBytes (ctrl)", () => pk.toBytes());
