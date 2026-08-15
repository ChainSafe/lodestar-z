import {beforeEach, describe, expect, it} from "vitest";
import {
  BLS_VERIFIER_EXECUTOR_CONCURRENCY,
  BLS_VERIFIER_MAX_BATCH_SIZE,
  BLS_VERIFIER_MAX_SAME_MESSAGE_BATCH_SIZE,
  BLS_VERIFIER_SET_TYPE,
  type BlsSignatureSet,
  verifySignatureSets,
  verifySignatureSetsAsync,
  verifySignatureSetsSameMessage,
  verifySignatureSetsSameMessageAsync,
} from "../src/bls-verifier.js";
import {SecretKey, aggregateSignatures} from "../src/blst.js";
import {pubkeyCache} from "../src/pubkeys.js";

const keys = Array.from({length: 4}, (_, i) => {
  const ikm = new Uint8Array(32);
  ikm[0] = i + 1;
  return SecretKey.fromKeygen(ikm);
});

function message(value: number): Uint8Array {
  return new Uint8Array(32).fill(value);
}

describe("bls verifier", () => {
  it("reports the native executor concurrency", () => {
    expect(BLS_VERIFIER_EXECUTOR_CONCURRENCY).toBeGreaterThan(0);
  });

  beforeEach(() => {
    pubkeyCache.reset();
    for (const [index, key] of keys.entries()) {
      pubkeyCache.append(index, key.toPublicKey().toBytes());
    }
  });

  it("verifies mixed indexed, aggregate, and raw-pubkey sets", () => {
    const indexedMessage = message(1);
    const aggregateMessage = message(2);
    const singleMessage = message(3);
    const aggregateSignature = aggregateSignatures([keys[1].sign(aggregateMessage), keys[2].sign(aggregateMessage)]);

    const sets: BlsSignatureSet[] = [
      {
        index: 0,
        message: indexedMessage,
        signature: keys[0].sign(indexedMessage).toBytes(),
        type: BLS_VERIFIER_SET_TYPE.indexed,
      },
      {
        indices: Uint32Array.from([1, 2]),
        message: aggregateMessage,
        signature: aggregateSignature.toBytes(),
        type: BLS_VERIFIER_SET_TYPE.aggregate,
      },
      {
        message: singleMessage,
        pubkey: keys[3].toPublicKey().toBytes(),
        signature: keys[3].sign(singleMessage).toBytes(),
        type: BLS_VERIFIER_SET_TYPE.single,
      },
    ];

    expect(verifySignatureSets(sets)).toBe(true);
  });

  it("verifies mixed sets asynchronously", async () => {
    const indexedMessage = message(1);
    const aggregateMessage = message(2);
    const singleMessage = message(3);
    const aggregateSignature = aggregateSignatures([keys[1].sign(aggregateMessage), keys[2].sign(aggregateMessage)]);

    await expect(
      verifySignatureSetsAsync(
        [
          {
            index: 0,
            message: indexedMessage,
            signature: keys[0].sign(indexedMessage).toBytes(),
            type: BLS_VERIFIER_SET_TYPE.indexed,
          },
          {
            indices: Uint32Array.from([1, 2]),
            message: aggregateMessage,
            signature: aggregateSignature.toBytes(),
            type: BLS_VERIFIER_SET_TYPE.aggregate,
          },
          {
            message: singleMessage,
            pubkey: keys[3].toPublicKey().toBytes(),
            signature: keys[3].sign(singleMessage).toBytes(),
            type: BLS_VERIFIER_SET_TYPE.single,
          },
        ],
        true
      )
    ).resolves.toBe(true);
  });

  it("returns false for invalid cryptographic input", () => {
    expect(
      verifySignatureSets([
        {
          index: 0,
          message: message(1),
          signature: new Uint8Array(96),
          type: BLS_VERIFIER_SET_TYPE.indexed,
        },
      ])
    ).toBe(false);
  });

  it("returns asynchronous cryptographic failures and cache errors distinctly", async () => {
    const signingRoot = message(1);
    await expect(
      verifySignatureSetsAsync([
        {
          index: 0,
          message: signingRoot,
          signature: new Uint8Array(96),
          type: BLS_VERIFIER_SET_TYPE.indexed,
        },
      ])
    ).resolves.toBe(false);

    await expect(
      verifySignatureSetsAsync([
        {
          index: keys.length,
          message: signingRoot,
          signature: keys[0].sign(signingRoot).toBytes(),
          type: BLS_VERIFIER_SET_TYPE.indexed,
        },
      ])
    ).rejects.toThrow("PubkeyIndexNotFound");
  });

  it("throws for a missing cached validator index", () => {
    const signingRoot = message(1);
    expect(() =>
      verifySignatureSets([
        {
          index: keys.length,
          message: signingRoot,
          signature: keys[0].sign(signingRoot).toBytes(),
          type: BLS_VERIFIER_SET_TYPE.indexed,
        },
      ])
    ).toThrow("PubkeyIndexNotFound");

    expect(() =>
      verifySignatureSetsSameMessage(
        [{index: keys.length, signature: keys[0].sign(signingRoot).toBytes()}],
        signingRoot
      )
    ).toThrow("PubkeyIndexNotFound");
  });

  it("short-circuits after an invalid cryptographic input", () => {
    const signingRoot = message(1);
    const invalidSet: BlsSignatureSet = {
      index: 0,
      message: signingRoot,
      signature: new Uint8Array(96),
      type: BLS_VERIFIER_SET_TYPE.indexed,
    };
    const missingCacheSet: BlsSignatureSet = {
      index: keys.length,
      message: signingRoot,
      signature: keys[0].sign(signingRoot).toBytes(),
      type: BLS_VERIFIER_SET_TYPE.indexed,
    };

    expect(verifySignatureSets([invalidSet, missingCacheSet])).toBe(false);
    expect(() => verifySignatureSets([missingCacheSet, invalidSet])).toThrow("PubkeyIndexNotFound");
  });

  it("randomly aggregates indexed signatures over the same message", () => {
    const signingRoot = message(4);
    const sets = keys.map((key, index) => ({
      index,
      signature: key.sign(signingRoot).toBytes(),
    }));

    expect(verifySignatureSetsSameMessage(sets, signingRoot)).toEqual([true, true, true, true]);

    sets[1] = {...sets[1], signature: keys[1].sign(message(5)).toBytes()};
    expect(verifySignatureSetsSameMessage(sets, signingRoot)).toEqual([true, false, true, true]);

    sets[1] = {...sets[1], signature: new Uint8Array(96)};
    expect(verifySignatureSetsSameMessage(sets, signingRoot)).toEqual([true, false, true, true]);
  });

  it("randomly aggregates indexed signatures asynchronously", async () => {
    const signingRoot = message(4);
    const sets = keys.map((key, index) => ({
      index,
      signature: key.sign(signingRoot).toBytes(),
    }));

    await expect(verifySignatureSetsSameMessageAsync(sets, signingRoot, true)).resolves.toEqual([
      true,
      true,
      true,
      true,
    ]);

    sets[1] = {...sets[1], signature: keys[1].sign(message(5)).toBytes()};
    await expect(verifySignatureSetsSameMessageAsync(sets, signingRoot)).resolves.toEqual([true, false, true, true]);
  });

  it("snapshots asynchronous input before returning", async () => {
    const signingRoot = message(7);
    const signature = keys[0].sign(signingRoot).toBytes();
    const promise = verifySignatureSetsAsync([
      {
        index: 0,
        message: signingRoot,
        signature,
        type: BLS_VERIFIER_SET_TYPE.indexed,
      },
    ]);

    signingRoot.fill(0);
    signature.fill(0);
    await expect(promise).resolves.toBe(true);
  });

  it("runs concurrent asynchronous roots on the shared BLS executor", async () => {
    const signingRoot = message(8);
    const signature = keys[0].sign(signingRoot).toBytes();
    const jobs = Array.from({length: 32}, () =>
      verifySignatureSetsAsync([
        {
          index: 0,
          message: signingRoot,
          signature,
          type: BLS_VERIFIER_SET_TYPE.indexed,
        },
      ])
    );

    await expect(Promise.all(jobs)).resolves.toEqual(Array.from({length: jobs.length}, () => true));
  });

  it("rejects empty and oversized batches", () => {
    expect(verifySignatureSets([])).toBe(false);
    expect(verifySignatureSetsSameMessage([], message(1))).toEqual([]);

    const signingRoot = message(1);
    const indexedSet = {
      index: 0,
      message: signingRoot,
      signature: keys[0].sign(signingRoot).toBytes(),
      type: BLS_VERIFIER_SET_TYPE.indexed,
    } as const;
    expect(verifySignatureSets(Array.from({length: BLS_VERIFIER_MAX_BATCH_SIZE}, () => indexedSet))).toBe(true);
    expect(() => verifySignatureSets(Array.from({length: BLS_VERIFIER_MAX_BATCH_SIZE + 1}, () => indexedSet))).toThrow(
      "TooManySets"
    );

    const sameMessageSet = {index: 0, signature: indexedSet.signature};
    expect(
      verifySignatureSetsSameMessage(
        Array.from({length: BLS_VERIFIER_MAX_SAME_MESSAGE_BATCH_SIZE}, () => sameMessageSet),
        signingRoot
      )
    ).toEqual(Array.from({length: BLS_VERIFIER_MAX_SAME_MESSAGE_BATCH_SIZE}, () => true));
    expect(() =>
      verifySignatureSetsSameMessage(
        Array.from({length: BLS_VERIFIER_MAX_SAME_MESSAGE_BATCH_SIZE + 1}, () => sameMessageSet),
        signingRoot
      )
    ).toThrow("TooManySets");
  });

  it("rejects invalid numeric indices", () => {
    const signingRoot = message(1);
    const signature = keys[0].sign(signingRoot).toBytes();
    for (const index of [-1, 0.5, 2 ** 32]) {
      expect(() =>
        verifySignatureSets([
          {
            index,
            message: signingRoot,
            signature,
            type: BLS_VERIFIER_SET_TYPE.indexed,
          },
        ])
      ).toThrow("InvalidUint32");
      expect(() => verifySignatureSetsSameMessage([{index, signature}], signingRoot)).toThrow("InvalidUint32");
    }
  });

  it("rejects malformed messages and returns false for invalid raw pubkeys", () => {
    const signingRoot = message(1);
    expect(() =>
      verifySignatureSets([
        {
          index: 0,
          message: new Uint8Array(31),
          signature: keys[0].sign(signingRoot).toBytes(),
          type: BLS_VERIFIER_SET_TYPE.indexed,
        },
      ])
    ).toThrow("InvalidMessageLength");

    expect(() =>
      verifySignatureSetsSameMessage([{index: 0, signature: new Uint8Array(96)}], new Uint8Array(31))
    ).toThrow("InvalidMessageLength");

    expect(
      verifySignatureSets([
        {
          message: signingRoot,
          pubkey: new Uint8Array(48),
          signature: keys[0].sign(signingRoot).toBytes(),
          type: BLS_VERIFIER_SET_TYPE.single,
        },
      ])
    ).toBe(false);
  });
});
