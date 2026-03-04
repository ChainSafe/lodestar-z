/** biome-ignore-all assist/source/useSortedKeys: benchmarks make more sense in a specific order */
import {bench, describe} from "@chainsafe/benchmark";
import * as blstTS from "@chainsafe/blst";
import * as blstZ from "../src/blst.js";
import {arrayOfIndexes, getSerializedTestSet, getTestSet} from "./utils/index.js";

describe("sanity", () => {
  bench("sanitytest - blstZ", () => {
    blstZ.SecretKey.fromKeygen(new Uint8Array(32));
  });
  bench("sanitytest - blstTS", () => {
    blstTS.SecretKey.fromKeygen(new Uint8Array(32));
  });
});

describe("aggregatePublicKeys", () => {
  for (const count of [1, 8, 32, 128, 256]) {
    bench({
      id: `aggregatePublicKeys blstZ - ${count} keys`,
      beforeEach: () => arrayOfIndexes(0, count - 1).map((i) => getTestSet(i).pk),
      fn: (publicKeys) => {
        blstZ.aggregatePublicKeys(publicKeys);
      },
    });
    bench({
      id: `aggregatePublicKeys blstTS - ${count} keys`,
      beforeEach: () => arrayOfIndexes(0, count - 1).map((i) => blstTS.PublicKey.fromBytes(getSerializedTestSet(i).pk)),
      fn: (publicKeys) => {
        blstTS.aggregatePublicKeys(publicKeys);
      },
    });
  }
});

describe("aggregateSignatures", () => {
  for (const count of [1, 8, 32, 128, 256]) {
    bench({
      id: `aggregateSignatures blstZ - ${count} sigs`,
      beforeEach: () => arrayOfIndexes(0, count - 1).map((i) => getTestSet(i).sig),
      fn: (signatures) => {
        blstZ.aggregateSignatures(signatures);
      },
    });
    bench({
      id: `aggregateSignatures blstTS - ${count} sigs`,
      beforeEach: () =>
        arrayOfIndexes(0, count - 1).map((i) => blstTS.Signature.fromBytes(getSerializedTestSet(i).sig)),
      fn: (signatures) => {
        blstTS.aggregateSignatures(signatures);
      },
    });
  }
});

describe("aggregateVerify", () => {
  for (const count of [1, 8, 32, 128, 256]) {
    bench({
      id: `aggregateVerify blstZ - ${count} sets`,
      beforeEach: () => {
        const sets = arrayOfIndexes(0, count - 1).map((i) => getTestSet(i));
        return {
          messages: sets.map((s) => s.msg),
          publicKeys: sets.map((s) => s.pk),
          signature: blstZ.aggregateSignatures(sets.map((s) => s.sig)),
        };
      },
      fn: ({messages, publicKeys, signature}) => {
        blstZ.aggregateVerify(messages, publicKeys, signature);
      },
    });
    bench({
      id: `aggregateVerify blstTS - ${count} sets`,
      beforeEach: () => {
        const sets = arrayOfIndexes(0, count - 1).map((i) => getSerializedTestSet(i));
        const pks = sets.map((s) => blstTS.PublicKey.fromBytes(s.pk));
        const sigs = sets.map((s) => blstTS.Signature.fromBytes(s.sig));
        return {
          messages: sets.map((s) => s.msg),
          publicKeys: pks,
          signature: blstTS.aggregateSignatures(sigs),
        };
      },
      fn: ({messages, publicKeys, signature}) => {
        blstTS.aggregateVerify(messages, publicKeys, signature);
      },
    });
  }
});

describe("verifyMultipleAggregateSignatures", () => {
  for (const count of [1, 8, 32, 128, 256]) {
    bench({
      id: `verifyMultiAggSig blstZ - ${count} sets`,
      beforeEach: () => arrayOfIndexes(0, count - 1).map((i) => getTestSet(i)),
      fn: (sets) => {
        blstZ.verifyMultipleAggregateSignatures(sets);
      },
    });
    bench({
      id: `verifyMultiAggSig blstTS - ${count} sets`,
      beforeEach: () =>
        arrayOfIndexes(0, count - 1).map((i) => {
          const s = getSerializedTestSet(i);
          return {
            msg: s.msg,
            pk: blstTS.PublicKey.fromBytes(s.pk),
            sig: blstTS.Signature.fromBytes(s.sig),
          };
        }),
      fn: (sets) => {
        blstTS.verifyMultipleAggregateSignatures(sets);
      },
    });
  }
});
