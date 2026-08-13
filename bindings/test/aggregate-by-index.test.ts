import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {SecretKey, aggregateWithRandomness, asyncAggregateWithRandomness, verify} from "../src/blst.js";
import {pubkeyCache} from "../src/pubkeys.js";

const keypairs = Array.from({length: 8}, (_, i) => {
  const ikm = new Uint8Array(32);
  ikm[0] = i + 1;
  const sk = SecretKey.fromKeygen(ikm);
  return {pk: sk.toPublicKey(), sk};
});

const msg = new Uint8Array(32).fill(13);
let base = 0;

beforeAll(() => {
  // Append after any keys other suites left behind; the cache is append-only.
  base = pubkeyCache.size;
  pubkeyCache.ensureCapacity(base + keypairs.length);
  for (const [i, {pk}] of keypairs.entries()) {
    pubkeyCache.append(base + i, pk.toBytes());
  }
});

afterAll(() => pubkeyCache.reset());

describe("asyncAggregateWithRandomness", () => {
  it("produces a verifying aggregate from validator indices", async () => {
    const sets = keypairs.map(({sk}, i) => ({index: base + i, sig: sk.sign(msg).toBytes()}));
    const {pk, sig} = await asyncAggregateWithRandomness(sets);
    expect(verify(msg, pk, sig)).toBe(true);
  });

  it("matches the synchronous by-object variant's verification result", async () => {
    const byIndex = await asyncAggregateWithRandomness(
      keypairs.map(({sk}, i) => ({index: base + i, sig: sk.sign(msg).toBytes()}))
    );
    const byObject = aggregateWithRandomness(keypairs.map(({pk, sk}) => ({pk, sig: sk.sign(msg).toBytes()})));
    // Randomness differs per call, so aggregates differ — but both must verify.
    expect(verify(msg, byIndex.pk, byIndex.sig)).toBe(true);
    expect(verify(msg, byObject.pk, byObject.sig)).toBe(true);
  });

  it("rejects an aggregate containing a wrong signature", async () => {
    const sets = keypairs.map(({sk}, i) => ({index: base + i, sig: sk.sign(msg).toBytes()}));
    sets[3] = {index: base + 3, sig: keypairs[4].sk.sign(msg).toBytes()};
    const {pk, sig} = await asyncAggregateWithRandomness(sets);
    expect(verify(msg, pk, sig)).toBe(false);
  });

  it("throws synchronously for bad input, like the by-object variant", () => {
    // Setup-phase failures throw before a Promise exists.
    expect(() => asyncAggregateWithRandomness([{index: 99_999_999, sig: keypairs[0].sk.sign(msg).toBytes()}])).toThrow(
      "PubkeyIndexNotFound"
    );
    expect(() => asyncAggregateWithRandomness([])).toThrow("EmptyArray");
    expect(() => asyncAggregateWithRandomness([{index: base, sig: new Uint8Array(96).fill(0xaa)}])).toThrow(
      "DeserializationFailed"
    );
  });
});
