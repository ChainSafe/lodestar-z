import {afterAll, beforeEach, describe, expect, it} from "vitest";
import {SecretKey, aggregateSignatures, verifyIndexedSignatureSets, verifySameMessageSetsByIndex} from "../src/blst.js";
import {pubkeyCache} from "../src/pubkeys.js";

// Deterministic keypairs; indices [0, N) in the process-wide cache.
const keypairs = Array.from({length: 6}, (_, i) => {
  const ikm = new Uint8Array(32);
  ikm[0] = i + 1;
  const sk = SecretKey.fromKeygen(ikm);
  return {pk: sk.toPublicKey(), sk};
});

// A keypair that is never appended to the cache.
const outsider = (() => {
  const ikm = new Uint8Array(32).fill(0xee);
  const sk = SecretKey.fromKeygen(ikm);
  return {pk: sk.toPublicKey(), sk};
})();

const msg = new Uint8Array(32).fill(7);

function sig(i: number, message = msg): Uint8Array {
  return keypairs[i].sk.sign(message).toBytes();
}

function indexedSet(i: number, message = msg) {
  return {index: i, message, signature: sig(i, message), type: "indexed" as const};
}

beforeEach(() => {
  pubkeyCache.reset();
  pubkeyCache.ensureCapacity(2_000);
  for (const [i, {pk}] of keypairs.entries()) {
    pubkeyCache.append(i, pk.toBytes());
  }
});

afterAll(() => pubkeyCache.reset());

describe("verifyIndexedSignatureSets", () => {
  it("verifies a mixed batch of all three set shapes", () => {
    const aggMsg = new Uint8Array(32).fill(8);
    const aggSig = aggregateSignatures([keypairs[1].sk.sign(aggMsg), keypairs[2].sk.sign(aggMsg)]).toBytes();
    const singleMsg = new Uint8Array(32).fill(9);

    const valid = verifyIndexedSignatureSets([
      indexedSet(0),
      {indices: new Uint32Array([1, 2]), message: aggMsg, signature: aggSig, type: "aggregate"},
      {
        message: singleMsg,
        publicKey: outsider.pk.toBytes(),
        signature: outsider.sk.sign(singleMsg).toBytes(),
        type: "single",
      },
    ]);
    expect(valid).toBe(true);
  });

  it("accepts a PublicKey wrapper for single sets", () => {
    const valid = verifyIndexedSignatureSets([
      {message: msg, publicKey: outsider.pk, signature: outsider.sk.sign(msg).toBytes(), type: "single"},
    ]);
    expect(valid).toBe(true);
  });

  it("returns false for semantic failures", () => {
    // Empty batch.
    expect(verifyIndexedSignatureSets([])).toBe(false);
    // Wrong signer.
    expect(verifyIndexedSignatureSets([{index: 0, message: msg, signature: sig(1), type: "indexed"}])).toBe(false);
    // Malformed signature bytes.
    expect(
      verifyIndexedSignatureSets([{index: 0, message: msg, signature: new Uint8Array(96).fill(0xaa), type: "indexed"}])
    ).toBe(false);
    // Invalid raw public key.
    expect(
      verifyIndexedSignatureSets([
        {message: msg, publicKey: new Uint8Array(48).fill(0xaa), signature: sig(0), type: "single"},
      ])
    ).toBe(false);
    // Unknown validator index.
    expect(verifyIndexedSignatureSets([{index: 99, message: msg, signature: sig(0), type: "indexed"}])).toBe(false);
    // Unknown index inside an aggregate.
    expect(
      verifyIndexedSignatureSets([
        {indices: new Uint32Array([1, 99]), message: msg, signature: sig(1), type: "aggregate"},
      ])
    ).toBe(false);
    // Empty aggregate indices.
    expect(
      verifyIndexedSignatureSets([{indices: new Uint32Array([]), message: msg, signature: sig(1), type: "aggregate"}])
    ).toBe(false);
    // Mixed batch with one bad set fails the whole batch.
    expect(
      verifyIndexedSignatureSets([indexedSet(0), {index: 99, message: msg, signature: sig(1), type: "indexed"}])
    ).toBe(false);
  });

  it("throws for caller bugs", () => {
    // Wrong message length.
    expect(() =>
      verifyIndexedSignatureSets([{index: 0, message: new Uint8Array(31), signature: sig(0), type: "indexed"}])
    ).toThrow();
    // Unknown discriminant.
    expect(() =>
      // biome-ignore lint/suspicious/noExplicitAny: intentionally malformed input
      verifyIndexedSignatureSets([{index: 0, message: msg, signature: sig(0), type: "bogus"} as any])
    ).toThrow();
    // indices must be a Uint32Array, not a plain array.
    expect(() =>
      // biome-ignore lint/suspicious/noExplicitAny: intentionally malformed input
      verifyIndexedSignatureSets([{indices: [1, 2] as any, message: msg, signature: sig(1), type: "aggregate"}])
    ).toThrow();
  });

  it("handles duplicate indices in an aggregate", () => {
    const doubled = aggregateSignatures([keypairs[4].sk.sign(msg), keypairs[4].sk.sign(msg)]).toBytes();
    expect(
      verifyIndexedSignatureSets([
        {indices: new Uint32Array([4, 4]), message: msg, signature: doubled, type: "aggregate"},
      ])
    ).toBe(true);
  });
});

describe("verifySameMessageSetsByIndex", () => {
  it("verifies and attributes failures per the fused contract", () => {
    const sets = keypairs.map(({sk}, i) => ({index: i, signature: sk.sign(msg).toBytes()}));
    expect(verifySameMessageSetsByIndex(msg, sets)).toBe(true);

    // One swapped signature fails the fused batch...
    const oneBad = sets.map((set, i) => (i === 2 ? {index: 2, signature: sig(3)} : set));
    expect(verifySameMessageSetsByIndex(msg, oneBad)).toBe(false);
    // ...and the per-set retry (batch of one) attributes it.
    const retries = oneBad.map((set) =>
      verifyIndexedSignatureSets([{index: set.index, message: msg, signature: set.signature, type: "indexed"}])
    );
    expect(retries).toEqual([true, true, false, true, true, true]);

    // Unknown index and empty input return false.
    expect(verifySameMessageSetsByIndex(msg, [{index: 99, signature: sig(0)}])).toBe(false);
    expect(verifySameMessageSetsByIndex(msg, [])).toBe(false);

    // Wrong message length is a caller bug.
    expect(() => verifySameMessageSetsByIndex(new Uint8Array(31), sets.slice(0, 2))).toThrow();
  });
});
