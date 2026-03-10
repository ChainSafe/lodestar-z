/**
 * Benchmark: @chainsafe/blst (Rust) vs zig native-MT vs zig napi-MT
 *
 * Usage:
 *   zig build build-lib:bindings -Doptimize=ReleaseFast
 *   npx benchmark bindings/test/bench-blst-mt.ts --local
 */

import crypto from "node:crypto";
import {createRequire} from "node:module";
import {describe, bench, setBenchOpts} from "@chainsafe/benchmark";

// Zig native-MT implementation (lodestar-z with blst-z ThreadPool)
import * as zig from "../src/blst.js";
import zigBindings from "../src/bindings.js";
const zigNativeMt = {
  aggregatePublicKeys: zigBindings.blst.aggregatePublicKeysMt as typeof zig.aggregatePublicKeys,
  aggregateSignatures: zigBindings.blst.aggregateSignaturesMt as typeof zig.aggregateSignatures,
  verifyMultipleAggregateSignatures: zigBindings.blst.verifyMultipleAggregateSignaturesMt as typeof zig.verifyMultipleAggregateSignatures,
};

// Zig napi-MT implementation (bing/mt-verify — PairingPool at napi layer)
const require = createRequire(import.meta.url);
const zigNapiMtBindings = require("/tmp/lodestar-z-mt-verify/zig-out/lib/bindings.node");
const zigNapiMt = {
  SecretKey: zigNapiMtBindings.blst.SecretKey as typeof zig.SecretKey,
  aggregatePublicKeys: zigNapiMtBindings.blst.aggregatePublicKeys as typeof zig.aggregatePublicKeys,
  aggregateSignatures: zigNapiMtBindings.blst.aggregateSignatures as typeof zig.aggregateSignatures,
  verifyMultipleAggregateSignatures: zigNapiMtBindings.blst.verifyMultipleAggregateSignatures as typeof zig.verifyMultipleAggregateSignatures,
};

// Rust implementation (@chainsafe/blst)
import * as rust from "@chainsafe/blst";

// ── Data generators ────────────────────────────────────────────────────

function generateRustKeyPairs(n: number) {
  const pks: rust.PublicKey[] = [];
  const sks: rust.SecretKey[] = [];
  for (let i = 0; i < n; i++) {
    const sk = rust.SecretKey.fromKeygen(crypto.randomBytes(32));
    sks.push(sk);
    pks.push(sk.toPublicKey());
  }
  return {sks, pks};
}

function generateZigKeyPairs(n: number) {
  const pks: zig.PublicKey[] = [];
  const sks: zig.SecretKey[] = [];
  for (let i = 0; i < n; i++) {
    const sk = zig.SecretKey.fromKeygen(crypto.randomBytes(32));
    sks.push(sk);
    pks.push(sk.toPublicKey());
  }
  return {sks, pks};
}

function generateNapiMtKeyPairs(n: number) {
  const pks: zig.PublicKey[] = [];
  const sks: zig.SecretKey[] = [];
  for (let i = 0; i < n; i++) {
    const sk = zigNapiMt.SecretKey.fromKeygen(crypto.randomBytes(32));
    sks.push(sk);
    pks.push(sk.toPublicKey());
  }
  return {sks, pks};
}

function generateRustSigSets(n: number) {
  const {sks, pks} = generateRustKeyPairs(n);
  const sigs: rust.Signature[] = [];
  const sets: rust.SignatureSet[] = [];
  for (let i = 0; i < n; i++) {
    const msg = crypto.randomBytes(32);
    const sig = sks[i].sign(msg);
    sigs.push(sig);
    sets.push({msg, pk: pks[i], sig});
  }
  return {pks, sigs, sets};
}

function generateZigSigSets(n: number) {
  const {sks, pks} = generateZigKeyPairs(n);
  const sigs: zig.Signature[] = [];
  const sets: Array<{msg: Uint8Array; pk: zig.PublicKey; sig: zig.Signature}> = [];
  for (let i = 0; i < n; i++) {
    const msg = crypto.randomBytes(32);
    const sig = sks[i].sign(msg);
    sigs.push(sig);
    sets.push({msg, pk: pks[i], sig});
  }
  return {pks, sigs, sets};
}

function generateNapiMtSigSets(n: number) {
  const {sks, pks} = generateNapiMtKeyPairs(n);
  const sigs: zig.Signature[] = [];
  const sets: Array<{msg: Uint8Array; pk: zig.PublicKey; sig: zig.Signature}> = [];
  for (let i = 0; i < n; i++) {
    const msg = crypto.randomBytes(32);
    const sig = sks[i].sign(msg);
    sigs.push(sig);
    sets.push({msg, pk: pks[i], sig});
  }
  return {pks, sigs, sets};
}

// ── Benchmarks ─────────────────────────────────────────────────────────

const sizes = [1, 3, 64, 128, 256, 512];

describe("aggregatePublicKeys", () => {
  for (const n of sizes) {
    const rustData = generateRustKeyPairs(n);
    const zigData = generateZigKeyPairs(n);
    const napiMtData = generateNapiMtKeyPairs(n);

    bench({
      id: `rust       aggregatePublicKeys n=${n}`,
      fn: () => {
        rust.aggregatePublicKeys(rustData.pks, false);
      },
    });

    bench({
      id: `zig-native aggregatePublicKeys n=${n}`,
      fn: () => {
        zigNativeMt.aggregatePublicKeys(zigData.pks, false);
      },
    });

    bench({
      id: `zig-napi   aggregatePublicKeys n=${n}`,
      fn: () => {
        zigNapiMt.aggregatePublicKeys(napiMtData.pks, false);
      },
    });
  }
});

describe("aggregateSignatures", () => {
  for (const n of sizes) {
    const rustData = generateRustSigSets(n);
    const zigData = generateZigSigSets(n);
    const napiMtData = generateNapiMtSigSets(n);

    bench({
      id: `rust       aggregateSignatures n=${n}`,
      fn: () => {
        rust.aggregateSignatures(rustData.sigs, false);
      },
    });

    bench({
      id: `zig-native aggregateSignatures n=${n}`,
      fn: () => {
        zigNativeMt.aggregateSignatures(zigData.sigs, false);
      },
    });

    bench({
      id: `zig-napi   aggregateSignatures n=${n}`,
      fn: () => {
        zigNapiMt.aggregateSignatures(napiMtData.sigs, false);
      },
    });
  }
});

describe("verifyMultipleAggregateSignatures", () => {
  for (const n of sizes) {
    const rustData = generateRustSigSets(n);
    const zigData = generateZigSigSets(n);
    const napiMtData = generateNapiMtSigSets(n);

    bench({
      id: `rust       verifyMultipleAggSigs n=${n}`,
      fn: () => {
        rust.verifyMultipleAggregateSignatures(rustData.sets, false, false);
      },
    });

    bench({
      id: `zig-native verifyMultipleAggSigs n=${n}`,
      fn: () => {
        zigNativeMt.verifyMultipleAggregateSignatures(zigData.sets, false, false);
      },
    });

    bench({
      id: `zig-napi   verifyMultipleAggSigs n=${n}`,
      fn: () => {
        zigNapiMt.verifyMultipleAggregateSignatures(napiMtData.sets, false, false);
      },
    });
  }
});
