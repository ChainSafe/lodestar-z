//TODO(bing): The ts benchmarks are here really to ensure perf is up to par on the zig side.
// Remove once we are happy
import crypto from "node:crypto";
import {bench, describe} from "@chainsafe/benchmark";
import {
  SecretKey as SecretKeyTS,
  type Signature as SignatureTS,
  aggregatePublicKeys as aggregatePublicKeysTS,
  aggregateSignatures as aggregateSignaturesTS,
  aggregateVerify as aggregateVerifyTS,
  verifyMultipleAggregateSignatures as verifyTS,
} from "@chainsafe/blst";
import {
  SecretKey as SecretKeyZig,
  type Signature as SignatureZig,
  aggregatePublicKeys as aggregatePublicKeysZig,
  aggregateSignatures as aggregateSignaturesZig,
  aggregateVerify as aggregateVerifyZig,
  verifyMultipleAggregateSignatures as verifyZig,
} from "../src/blst.js";

interface SignatureSetZig {
  msg: Uint8Array;
  pk: InstanceType<typeof SecretKeyZig> extends {toPublicKey(): infer P} ? P : never;
  sig: InstanceType<typeof SignatureZig>;
}

interface SignatureSetTS {
  msg: Uint8Array;
  pk: ReturnType<InstanceType<typeof SecretKeyTS>["toPublicKey"]>;
  sig: InstanceType<typeof SignatureTS>;
}

function generateZigSets(count: number): SignatureSetZig[] {
  return Array.from({length: count}, () => {
    const msg = crypto.randomBytes(32);
    const sk = SecretKeyZig.fromKeygen(crypto.randomBytes(32));
    const pk = sk.toPublicKey();
    const sig = sk.sign(msg);
    return {msg, pk, sig};
  });
}

function generateTSSets(count: number): SignatureSetTS[] {
  return Array.from({length: count}, () => {
    const msg = crypto.randomBytes(32);
    const sk = SecretKeyTS.fromKeygen(crypto.randomBytes(32));
    const pk = sk.toPublicKey();
    const sig = sk.sign(msg);
    return {msg, pk, sig};
  });
}

describe("aggregatePublicKeys", () => {
  for (const count of [1, 8, 32, 128, 256]) {
    bench({
      beforeEach: () => generateZigSets(count).map((s) => s.pk),
      fn: (publicKeys) => {
        aggregatePublicKeysZig(publicKeys);
      },
      id: `aggregatePublicKeys lodestar-z  ${count} keys`,
    });

    bench({
      beforeEach: () => generateTSSets(count).map((s) => s.pk),
      fn: (publicKeys) => {
        aggregatePublicKeysTS(publicKeys);
      },
      id: `aggregatePublicKeys @chainsafe/blst  ${count} keys`,
    });
  }
});

describe("aggregateSignatures", () => {
  for (const count of [1, 8, 32, 128, 256]) {
    bench({
      beforeEach: () => generateZigSets(count).map((s) => s.sig),
      fn: (signatures) => {
        aggregateSignaturesZig(signatures);
      },
      id: `aggregateSignatures lodestar-z  ${count} sigs`,
    });

    bench({
      beforeEach: () => generateTSSets(count).map((s) => s.sig),
      fn: (signatures) => {
        aggregateSignaturesTS(signatures);
      },
      id: `aggregateSignatures @chainsafe/blst  ${count} sigs`,
    });
  }
});

describe("aggregateVerify", () => {
  for (const count of [3, 8, 32, 64, 128]) {
    bench({
      beforeEach: () => {
        const sets = generateZigSets(count);
        return {
          messages: sets.map((s) => s.msg),
          publicKeys: sets.map((s) => s.pk),
          signature: aggregateSignaturesZig(sets.map((s) => s.sig)),
        };
      },
      fn: ({messages, publicKeys, signature}) => {
        const isValid = aggregateVerifyZig(messages, publicKeys, signature);
        if (!isValid) throw Error("Invalid");
      },
      id: `aggregateVerify lodestar-z  ${count} sets`,
    });

    bench({
      beforeEach: () => {
        const sets = generateTSSets(count);
        return {
          messages: sets.map((s) => s.msg),
          publicKeys: sets.map((s) => s.pk),
          signature: aggregateSignaturesTS(sets.map((s) => s.sig)),
        };
      },
      fn: ({messages, publicKeys, signature}) => {
        const isValid = aggregateVerifyTS(messages, publicKeys, signature);
        if (!isValid) throw Error("Invalid");
      },
      id: `aggregateVerify @chainsafe/blst  ${count} sets`,
    });
  }
});

describe("verifyMultipleAggregateSignatures", () => {
  for (const count of [3, 8, 32, 64, 128]) {
    bench({
      beforeEach: () => generateZigSets(count),
      fn: (sets) => {
        const isValid = verifyZig(sets);
        if (!isValid) throw Error("Invalid");
      },
      id: `lodestar-z  ${count} sets`,
    });

    bench({
      beforeEach: () => generateTSSets(count),
      fn: (sets) => {
        const isValid = verifyTS(sets);
        if (!isValid) throw Error("Invalid");
      },
      id: `@chainsafe/blst  ${count} sets`,
    });
  }
});
